/*
 * ZDB Copyright 2017 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#ifndef ZDB_SRC_ANONYMOUS_STORE_H
#define ZDB_SRC_ANONYMOUS_STORE_H

#include <time.h>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <utility>

#include <cachehash/cachehash.h>

#include "delta_handler.h"
#include "macros.h"
#include "record.h"
#include "zdb.h"
#include "zsearch_definitions/search.grpc.pb.h"

namespace zdb {

class AnonymousResult {
  public:
    bool success;
    zsearch::AnonymousDelta delta;

    AnonymousResult();
    AnonymousResult(const AnonymousResult& rhs) = default;
    AnonymousResult(AnonymousResult&& rhs);

    AnonymousResult& operator=(const AnonymousResult& rhs) = default;
    AnonymousResult& operator=(AnonymousResult&& rhs);

    static AnonymousResult failure();
    static AnonymousResult no_change();
};

template <typename key_type>
class AnonymousStore {
  public:
    // Type declarations
    using db_type = DB<key_type, ProtobufRecord<zsearch::AnonymousRecord>>;
    using lock_on_type = typename key_type::lock_on_type;
    using lock_type = typename LockManager<lock_on_type>::Lock;

  private:
    friend class AnonIterator;

    // Member variables
    db_type* m_db;
    lock_type m_lock;
    cachehash* m_cache;
    cachehash* m_ext_cache;

  public:
    using AnonymousRecord = ::zsearch::AnonymousRecord;
    using AnonymousDelta = ::zsearch::AnonymousDelta;
    using ExternalCertificate = ::zsearch::ExternalCertificate;
    using SCT = ::zsearch::SCT;
    using Certificate = ::zsearch::Certificate;

    AnonymousStore() = delete;
    AnonymousStore(const AnonymousStore&) = delete;
    AnonymousStore(AnonymousStore&&);
    AnonymousStore(db_type* db, lock_type lock);
    ~AnonymousStore();

    bool is_open() const { return m_db != nullptr; }

    inline AnonymousRecord get(const key_type& k) { return m_db->get(k).pb(); }
    AnonymousResult put(AnonymousRecord& rec);
    AnonymousResult put_external(ExternalCertificate& ctrm);
    AnonymousResult put_sct(SCT& sct);
    AnonymousResult put_processed_cert(Certificate& c);
    AnonymousResult force_put(const AnonymousRecord& rec);

    inline bool may_exist(const key_type& k) { return m_db->may_exist(k); }

    class AnonIterator {
      public:
        using value_type = std::pair<key_type, zsearch::AnonymousRecord>;

      private:
        using zdb_iterator = typename db_type::iterator;
        friend class AnonymousStore;

        zdb_iterator m_it;
        value_type m_current;

        AnonIterator(zdb_iterator&& it) : m_it(std::move(it)) {
            update_current();
        }

        void update_current() {
            if (m_it.valid()) {
                auto inner = *m_it;
                m_current.first = inner.first;
                m_current.second = inner.second.pb();
            }
        }

      public:
        AnonIterator(const AnonIterator& other) = delete;
        AnonIterator(AnonIterator&& other) = default;

        inline bool operator==(const AnonIterator& other) const {
            return m_it == other.m_it;
        }

        inline bool operator!=(const AnonIterator& other) const {
            return !(other == *this);
        }

        inline value_type operator*() const { return m_current; }

        inline value_type* operator->() { return &m_current; }
        inline AnonIterator& operator++() {
            ++m_it;
            update_current();
            return *this;
        }

        AnonIterator& operator++(int) = delete;

        inline bool valid() const { return m_it.valid(); }
    };

    using iterator = AnonIterator;

    inline iterator find(const key_type& k) const {
        return iterator(m_db->find(k));
    }
    inline iterator seek_start_of_shard(size_t target_shard) {
        return iterator(m_db->seek_start_of_shard(target_shard));
    }

    inline size_t shard_for(const key_type& k) { return m_db->shard_for(k); }

    inline size_t total_shards(void) { return m_db->total_shards(); }

    inline iterator begin() const { return iterator(m_db->begin()); }
    inline iterator end() const { return iterator(m_db->end()); }

    uint64_t regenerate_deltas(DeltaHandler& handler, size_t max_records);

  private:
    AnonymousResult do_put_locked(const key_type& k,
                                  const zsearch::AnonymousRecord& rec);
};

template <typename key_type>
AnonymousStore<key_type>::AnonymousStore(db_type* db, lock_type lock)
        : m_db(db),
          m_lock(std::move(lock)),
          m_cache(nullptr),
          m_ext_cache(nullptr) {
    m_cache = cachehash_init(10 * 1024, nullptr);
    m_ext_cache = cachehash_init(10 * 1024, nullptr);
    cachehash_set_evict_cb(m_cache, nullptr);
    cachehash_set_evict_cb(m_ext_cache, nullptr);
}

template <typename key_type>
AnonymousStore<key_type>::~AnonymousStore() {
    if (m_cache) {
        cachehash_free(m_cache, nullptr);
    }
    if (m_ext_cache) {
        cachehash_free(m_ext_cache, nullptr);
    }
}

template <typename key_type>
AnonymousStore<key_type>::AnonymousStore(AnonymousStore&& other)
        : m_db(other.m_db),
          m_lock(std::move(other.m_lock)),
          m_cache(other.m_cache),
          m_ext_cache(other.m_ext_cache) {
    other.m_cache = nullptr;
    other.m_ext_cache = nullptr;
}

template <typename key_type>
AnonymousResult AnonymousStore<key_type>::put(AnonymousRecord& rec) {
    const key_type k = key_type::from_record(rec);
    const lock_on_type lock_on = k.lock_on();
    auto deferred_unlock = m_lock.lock(lock_on);

    // See if we've cached it and quit early if we have
    const void* ch_key = k.string().data();
    size_t ch_len = k.string().size();
    void* cached_value = cachehash_get(m_cache, ch_key, ch_len);
    if (cached_value != nullptr) {
        return AnonymousResult::no_change();
    }
    // check if this is a certificate. if so, remove the presented chain from
    // the protobuf so that we don't write it to disk. We'll add it back into
    // the delta so that the certificate processing daemon has access to that
    // context
    std::vector<std::string> presented_chain;
    if (rec.has_certificate()) {
        zsearch::Certificate* c = rec.mutable_certificate();
        for (const auto& p : c->presented_chain()) {
            presented_chain.push_back(p);
        }
        c->clear_presented_chain();
    }
    // Not cached, but still could be in the database. Add it to the hash table.
    // The value itself doesn't matter, so just set it to any non-null pointer.
    // Only do this if the put is successful.
    try {
        auto current = m_db->get(k);
        cachehash_put(m_cache, ch_key, ch_len, this);
        // if this is a certificate, indicate that we've seen this in a scan if
        // it hasn't already been set.
        auto pb = current.pb();
        if (pb.has_certificate() && !pb.certificate().seen_in_scan()) {
            pb.mutable_certificate()->set_seen_in_scan(true);
            auto retv = do_put_locked(k, pb);
            auto* c = retv.delta.mutable_record()->mutable_certificate();
            for (const auto& p : presented_chain) {
                c->add_presented_chain(p);
            }
            return retv;
        }
        return AnonymousResult::no_change();
    } catch (std::out_of_range& e) {
        // Do nothing
    } catch (...) {
        log_error("anonstore", "unknown exception thrown by db");
        return AnonymousResult::failure();
    }
    uint32_t now = (uint32_t) time(NULL);
    rec.set_added_at(now);
    rec.set_updated_at(now);
    if (rec.has_certificate()) {
        rec.mutable_certificate()->set_seen_in_scan(true);
        rec.mutable_certificate()->set_source(zsearch::CERTIFICATE_SOURCE_SCAN);
    }
    auto retv = do_put_locked(k, rec);
    // Add it to the cachehash on success
    if (retv.success) {
        cachehash_put(m_cache, ch_key, ch_len, this);
    }
    if (retv.delta.record().has_certificate()) {
        // now that record is written to disk, add presented chain back into
        // the delta so that the certificate processing daemon has access to it
        auto* c = retv.delta.mutable_record()->mutable_certificate();
        for (auto const& p : presented_chain) {
            c->add_presented_chain(p);
        }
    }
    return retv;
}

static zsearch::CTServerStatus* get_ctss(int index, zsearch::CTStatus* cts) {
    switch (index) {
        case zsearch::CT_SERVER_CENSYS_PRODUCTION:
            return cts->mutable_censys();
        case zsearch::CT_SERVER_CENSYS_DEVELOPMENT:
            return cts->mutable_censys_dev();
        case zsearch::CT_SERVER_GOOGLE_AVIATOR:
            return cts->mutable_google_aviator();
        case zsearch::CT_SERVER_GOOGLE_DAEDALUS:
            return cts->mutable_google_daedalus();
        case zsearch::CT_SERVER_GOOGLE_PILOT:
            return cts->mutable_google_pilot();
        case zsearch::CT_SERVER_GOOGLE_ICARUS:
            return cts->mutable_google_icarus();
        case zsearch::CT_SERVER_GOOGLE_SKYDIVER:
            return cts->mutable_google_skydiver();
        case zsearch::CT_SERVER_GOOGLE_ROCKETEER:
            return cts->mutable_google_rocketeer();
        case zsearch::CT_SERVER_GOOGLE_SUBMARINER:
            return cts->mutable_google_submariner();
        case zsearch::CT_SERVER_GOOGLE_TESTTUBE:
            return cts->mutable_google_testtube();
        case zsearch::CT_SERVER_DIGICERT_CT1:
            return cts->mutable_digicert_ct1();
        case zsearch::CT_SERVER_DIGICERT_CT2:
            return cts->mutable_digicert_ct2();
        case zsearch::CT_SERVER_IZENPE_COM_CT:
            return cts->mutable_izenpe_com_ct();
        case zsearch::CT_SERVER_IZENPE_EUS_CT:
            return cts->mutable_izenpe_eus_ct();
        case zsearch::CT_SERVER_SYMANTEC_WS_CT:
            return cts->mutable_symantec_ws_ct();
        case zsearch::CT_SERVER_SYMANTEC_WS_VEGA:
            return cts->mutable_symantec_ws_vega();
        case zsearch::CT_SERVER_SYMANTEC_WS_SIRIUS:
            return cts->mutable_symantec_ws_sirius();
        case zsearch::CT_SERVER_WOSIGN_CTLOG:
            return cts->mutable_wosign_ctlog();
        case zsearch::CT_SERVER_WOSIGN_CT:
            return cts->mutable_wosign_ct();
        case zsearch::CT_SERVER_CNNIC_CTSERVER:
            return cts->mutable_cnnic_ctserver();
        case zsearch::CT_SERVER_GDCA_CT:
            return cts->mutable_gdca_ct();
        case zsearch::CT_SERVER_STARTSSL_CT:
            return cts->mutable_startssl_ct();
        case zsearch::CT_SERVER_CERTLY_LOG:
            return cts->mutable_certly_log();
        case zsearch::CT_SERVER_VENAFI_API_CTLOG:
            return cts->mutable_venafi_api_ctlog();
        case zsearch::CT_SERVER_VENAFI_API_CTLOG_GEN2:
            return cts->mutable_venafi_api_ctlog_gen2();
        case zsearch::CT_SERVER_SYMANTEC_WS_DENEB:
            return cts->mutable_symantec_ws_deneb();
        case zsearch::CT_SERVER_NORDU_CT_PLAUSIBLE:
            return cts->mutable_nordu_ct_plausible();
        case zsearch::CT_SERVER_COMODO_DODO:
            return cts->mutable_comodo_dodo();
        case zsearch::CT_SERVER_COMODO_MAMMOTH:
            return cts->mutable_comodo_mammoth();
        case zsearch::CT_SERVER_COMODO_SABRE:
            return cts->mutable_comodo_sabre();
        case zsearch::CT_SERVER_SHECA_CT:
            return cts->mutable_sheca_ct();
        case zsearch::CT_SERVER_GDCA_CTLOG:
            return cts->mutable_gdca_ctlog();
        case zsearch::CT_SERVER_CERTIFICATETRANSPARENCY_CN_CT:
            return cts->mutable_certificatetransparency_cn_ct();
        case zsearch::CT_SERVER_LETSENCRYPT_CT_CLICKY:
            return cts->mutable_letsencrypt_ct_clicky();
    }
    return nullptr;
}

template <typename key_type>
AnonymousResult AnonymousStore<key_type>::put_external(
        ExternalCertificate& ctrm) {
    AnonymousRecord* rec = ctrm.mutable_anonymous_record();
    const key_type k = key_type::from_record(*rec);
    const lock_on_type lock_on = k.lock_on();
    auto deferred_unlock = m_lock.lock(lock_on);
    // If we've already seen this certificate from this particular CT server
    // then don't write it to disk. This is so that we don't push every
    // intermediate certificate to disk. We don't want to do this for
    // all certificate sources (i.e., Mozilla Salesforce) because that data
    // is mutable and we always want to write it to disk. This is OK because
    // there aren't that many certificates in Mozilla Salesforce.
    std::string ch_str = k.string() + std::to_string(ctrm.source());
    if (ctrm.source() == zsearch::CERTIFICATE_SOURCE_CT ||
        ctrm.source() == zsearch::CERTIFICATE_SOURCE_CT_CHAIN) {
        ch_str += "|";
        ch_str += std::to_string(ctrm.ct_server());
    }
    const void* ch_key = ch_str.data();
    size_t ch_len = ch_str.size();
    if (ctrm.source() == zsearch::CERTIFICATE_SOURCE_CT ||
        ctrm.source() == zsearch::CERTIFICATE_SOURCE_CT_CHAIN) {
        void* cached_value = cachehash_get(m_cache, ch_key, ch_len);
        if (cached_value != nullptr) {
            return AnonymousResult::no_change();
        }
    }
    // pull out the presented chain for later
    std::vector<std::string> presented_chain;
    zsearch::Certificate* c = rec->mutable_certificate();
    for (const auto& p : c->presented_chain()) {
        presented_chain.push_back(p);
    }
    c->clear_presented_chain();
    // if the record is already in the database, we want to update that one with
    // new CT data. However, if it's not, then we'll use the new and update that
    // and put it into the database.
    bool preexisting = false;
    try {
        auto existing = m_db->get(k);
        rec->CopyFrom(existing.pb());
        preexisting = true;
    } catch (std::out_of_range& e) {
        // audit records from Mozilla Salesforce do not include parsed, or
        // raw certificate. They only potentially add *additional* metadata
        // to a certificate. if the record isn't already present in Censys
        // then there's nothing to update and we ignore this additional data.
        if (ctrm.source() == zsearch::CERTIFICATE_SOURCE_MOZILLA_SALESFORCE) {
            return AnonymousResult::no_change();
        }
        // do nothing, we'll juse use the record that came in through the queue
    } catch (...) {
        log_error("anonstore",
                  "unknown exception thrown by db in put_external");
        return AnonymousResult::failure();
    }
    // great, we have a record. let's update it with the data from the external
    // source
    uint32_t now = (uint32_t) time(NULL);
    if (!preexisting) {
        rec->set_added_at(now);
    }
    rec->set_updated_at(now);
    if (ctrm.source() == zsearch::CERTIFICATE_SOURCE_CT) {
        // figure out which CT server just sent us the record and update the
        // CTServerStatus accordingly.
        zsearch::CTStatus* cts = rec->mutable_certificate()->mutable_ct();
        zsearch::CTServerStatus* ct_status = get_ctss(ctrm.ct_server(), cts);
        if (!ct_status) {
            log_error("anonstore", "unknown ct_status");
            return AnonymousResult::failure();
        }
        // ok great, we know what to update. let's update.
        ct_status->set_index(ctrm.ct_status().index());
        ct_status->set_ct_timestamp(ctrm.ct_status().ct_timestamp());
        ct_status->set_pull_timestamp(ctrm.ct_status().pull_timestamp());
    } else if (ctrm.source() ==
               zsearch::CERTIFICATE_SOURCE_MOZILLA_SALESFORCE) {
        zsearch::Certificate* cert = rec->mutable_certificate();
        zsearch::CertificateAudit* audit = cert->mutable_audit();
        audit->mutable_mozilla()->CopyFrom(ctrm.nss_status());
    } else if (ctrm.source() == zsearch::CERTIFICATE_SOURCE_RESEARCH ||
               ctrm.source() == zsearch::CERTIFICATE_SOURCE_CT_CHAIN ||
               ctrm.source() == zsearch::CERTIFICATE_SOURCE_RAPID7 ||
               ctrm.source() == zsearch::CERTIFICATE_SOURCE_HUBBLE ||
               ctrm.source() == zsearch::CERTIFICATE_SOURCE_UNKNOWN) {
    } else {
        // unhandled external source
        log_error("anonstore", "unknown external source");
        return AnonymousResult::failure();
    }
    if (!preexisting) {
        rec->mutable_certificate()->set_source(ctrm.source());
    }
    auto retv = do_put_locked(k, *rec);

    if (retv.success &&
        (ctrm.source() == zsearch::CERTIFICATE_SOURCE_CT ||
         ctrm.source() == zsearch::CERTIFICATE_SOURCE_CT_CHAIN)) {
        cachehash_put(m_cache, ch_key, ch_len, this);
    }

    auto* delta_c = retv.delta.mutable_record()->mutable_certificate();
    for (const auto& p : presented_chain) {
        delta_c->add_presented_chain(p);
    }
    return retv;
}

template <typename key_type>
AnonymousResult AnonymousStore<key_type>::put_sct(SCT& sct) {
    const key_type k = key_type::from_string(sct.sha256fp());
    const lock_on_type lock_on = k.lock_on();
    auto deferred_unlock = m_lock.lock(lock_on);

    AnonymousRecord ar;
    try {
        ar.CopyFrom(m_db->get(k).pb());
    } catch (std::out_of_range& e) {
        //  this shouldn't occur because the record originated from zdb
        log_error("anonstore", "out of range get in sct (how?)");
        return AnonymousResult::failure();
    } catch (...) {
        log_error("anonstore", "unknown db exception in put_sct");
        return AnonymousResult::failure();
    }
    auto cert = ar.mutable_certificate();
    zsearch::CTStatus* cts = cert->mutable_ct();
    auto ctss = get_ctss(sct.server(), cts);
    if (!ctss) {
        return AnonymousResult::failure();
    }
    // if we've already processed an SCT for this server, then the next
    // one is almost guaranteed to be a failure. Don't overwrite that
    // success with this new failure
    if (ctss->push_status() == zsearch::CT_PUSH_STATUS_SUCCESS) {
        return AnonymousResult::no_change();
    }
    ctss->set_push_status(sct.status().push_status());
    ctss->set_sct(sct.status().sct());
    ctss->set_push_timestamp(sct.status().push_timestamp());
    ctss->set_push_error(sct.status().push_error());
    return do_put_locked(k, ar);
}

template <typename key_type>
AnonymousResult AnonymousStore<key_type>::put_processed_cert(Certificate& c) {
    const key_type k = key_type::from_string(c.sha256fp());
    const lock_on_type lock_on = k.lock_on();
    auto deferred_unlock = m_lock.lock(lock_on);

    AnonymousRecord ar;
    try {
        ar.CopyFrom(m_db->get(k).pb());
    } catch (std::out_of_range& e) {
        //  this shouldn't occur because the record originated from zdb
        log_error("anonstore", "out of range get in sct (how?)");
        return AnonymousResult::failure();
    } catch (...) {
        log_error("anonstore",
                  "unknown db exception in put_processed_certificate");
        return AnonymousResult::failure();
    }
    auto orig_cert = ar.mutable_certificate();
    // We can't just replace the entire certificate object because we might have
    // received an SCT or other piece of information while this certificate was
    // being post-processed. Only copy over the information that post-processing
    // updates
    orig_cert->set_parsed(c.parsed());
    orig_cert->set_parse_version(c.parse_version());
    orig_cert->set_parse_status(c.parse_status());
    orig_cert->set_parse_error(c.parse_error());
    orig_cert->mutable_zlint()->CopyFrom(c.zlint());
    orig_cert->mutable_validation()->CopyFrom(c.validation());
    orig_cert->set_not_valid_after(c.not_valid_after());
    orig_cert->set_not_valid_before(c.not_valid_before());
    orig_cert->set_is_precert(c.is_precert());
    orig_cert->set_post_processed(c.post_processed());
    orig_cert->set_post_process_timestamp(c.post_process_timestamp());
    orig_cert->mutable_parents()->CopyFrom(c.parents());
    orig_cert->set_expired(c.expired());

    uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    ar.set_updated_at(now);
    return do_put_locked(k, ar);
}

template <typename key_type>
AnonymousResult AnonymousStore<key_type>::force_put(
        const AnonymousRecord& rec) {
    const key_type k = key_type::from_record(rec);
    const lock_on_type lock_on = k.lock_on();
    auto deferred_unlock = m_lock.lock(lock_on);
    return do_put_locked(k, rec);
}

template <typename key_type>
AnonymousResult AnonymousStore<key_type>::do_put_locked(
        const key_type& k,
        const AnonymousRecord& rec) {
    AnonymousResult result;
    auto& delta = result.delta;
    delta.set_delta_scope(zsearch::AnonymousDelta_DeltaScope_SCOPE_NEW);
    delta.set_delta_type(zsearch::AnonymousDelta_DeltaType_DT_UPDATE);
    ProtobufRecord<AnonymousRecord> pbr(rec);
    if (!m_db->put(k, pbr)) {
        log_error("anonstore", "db could not write in do_put_locked");
        return AnonymousResult::failure();
    }
    delta.mutable_record()->CopyFrom(rec);
    result.success = true;
    return result;
}

template <typename key_type>
uint64_t AnonymousStore<key_type>::regenerate_deltas(DeltaHandler& handler,
                                                     size_t max_records) {
    uint64_t count = 0;
    for (auto it = begin(); it.valid(); ++it, ++count) {
        if (max_records && count >= max_records) {
            break;
        }
        if (count > 0 && count % 100000 == 0) {
            log_info("store", "regenerated %llu deltas so far", count);
        }
        auto& rec = it->second;
        AnonymousResult ar;
        ar.success = true;
        auto& delta = ar.delta;
        delta.set_delta_scope(zsearch::AnonymousDelta_DeltaScope_SCOPE_UPDATE);
        delta.set_delta_type(zsearch::AnonymousDelta_DeltaType_DT_UPDATE);
        delta.mutable_record()->Swap(&rec);
        handler.handle_delta(ar);
    }
    return count;
}

}  // namespace zdb

#endif /* ZDB_SRC_ANONYMOUS_STORE_H */
