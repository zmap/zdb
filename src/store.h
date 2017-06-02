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

#ifndef ZDB_SRC_STORE_H
#define ZDB_SRC_STORE_H

#include <algorithm>
#include <atomic>
#include <functional>
#include <iostream>
#include <iterator>
#include <limits>
#include <map>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <arpa/inet.h>

#include "as_data.h"
#include "channel.h"
#include "db.h"
#include "delta_handler.h"
#include "fastjson.h"
#include "location.h"
#include "macros.h"
#include "record.h"
#include "record_lock.h"
#include "utility.h"
#include "zmap/logger.h"
#include "zsearch_definitions/protocols.pb.h"
#include "zsearch_definitions/search.pb.h"

namespace std {

template <>
struct equal_to<::zsearch::ASAtom> {
    using result_type = bool;
    using first_argument_type = ::zsearch::ASAtom;
    using second_argument_type = ::zsearch::ASAtom;

    result_type operator()(const first_argument_type& lhs,
                           const second_argument_type& rhs) const {
        if (!(lhs.asn() == rhs.asn() &&
              lhs.description() == rhs.description() &&
              lhs.rir() == rhs.rir())) {
            return false;
        }
        if (lhs.bgp_prefix() != rhs.bgp_prefix() || lhs.name() != rhs.name() ||
            lhs.country_code() != rhs.country_code() ||
            lhs.organization() != rhs.organization()) {
            return false;
        }
        if (lhs.path_size() != rhs.path_size()) {
            return false;
        }
        for (size_t i = 0; i < lhs.path_size(); ++i) {
            if (lhs.path(i) != rhs.path(i)) {
                return false;
            }
        }
        return true;
    }
};

template <>
struct hash<::zsearch::AnonymousKey> {
    using argument_type = ::zsearch::AnonymousKey;
    using result_type = size_t;

    result_type operator()(const argument_type& k) const {
        size_t hash_value = 0;
        hash_value |= (k.port() & 0x0000FFFFU) << 16;
        hash_value |= (k.protocol() & 0x000000FFU) << 8;
        hash_value |= (k.subprotocol() & 0x000000FFU);
        return hash_value;
    }
};

template <>
struct equal_to<::zsearch::AnonymousKey> {
    using result_type = bool;
    using first_argument_type = ::zsearch::AnonymousKey;
    using second_argument_type = ::zsearch::AnonymousKey;

    static hash<::zsearch::AnonymousKey> h;

    inline bool operator()(const ::zsearch::AnonymousKey& lhs,
                           const ::zsearch::AnonymousKey& rhs) const {
        return h(lhs) == h(rhs);
    }
};

template <>
struct less<::zsearch::AnonymousKey> {
    using result_type = bool;
    using first_argument_type = ::zsearch::AnonymousKey;
    using second_argument_type = ::zsearch::AnonymousKey;

    static hash<::zsearch::AnonymousKey> h;

    inline bool operator()(const ::zsearch::AnonymousKey& lhs,
                           const ::zsearch::AnonymousKey& rhs) const {
        return h(lhs) < h(rhs);
    }
};

}  // namespace std

namespace zdb {

class StoreResult {
  public:
    bool success;
    zsearch::Delta delta;

    StoreResult();
    StoreResult(const StoreResult& rhs) = default;
    StoreResult(StoreResult&& rhs);

    StoreResult& operator=(const StoreResult& rhs) = default;
    StoreResult& operator=(StoreResult&& rhs);

    static StoreResult from_key(const IPv4Key& key);
    static StoreResult from_key(const DomainKey& key);

    static StoreResult failure();
    static StoreResult no_change();
};

struct PruneConfiguration {
    using min_scan_map = std::map<zsearch::AnonymousKey, uint32_t>;

    min_scan_map min_scan_ids;
};

struct PruneCheck {
    bool should_prune;
    zsearch::AnonymousKey anon_key;

    PruneCheck();
    PruneCheck(const PruneCheck& rhs) = default;
    PruneCheck(PruneCheck&& rhs);

    PruneCheck& operator=(const PruneCheck& rhs) = default;
    PruneCheck& operator=(PruneCheck&& rhs);

    static PruneCheck no_prune();
};

class PruneStatistics {
  public:
    bool success;
    size_t records_pruned;
    size_t records_read;
    std::map<zsearch::AnonymousKey, size_t> pruned_per_key;

    PruneStatistics() : success(false), records_pruned(0), records_read(0) {}
    PruneStatistics(const PruneStatistics&) = default;
    PruneStatistics(PruneStatistics&&) = default;

    void merge(const PruneStatistics& other);
};

struct DumpConfiguration {
    using min_scan_map = PruneConfiguration::min_scan_map;

    size_t max_queue_size;
    size_t max_records;

    min_scan_map min_scan_ids;
    std::vector<std::unique_ptr<DeltaHandler>> prune_handlers;
};

class DumpStatistics {
  public:
    bool success;
    size_t records_dumped;
    size_t hosts_dumped;
    PruneStatistics prune_stats;

    DumpStatistics() : success(false), records_dumped(0), hosts_dumped(0) {}
    DumpStatistics(const DumpStatistics&) = default;
    DumpStatistics(DumpStatistics&&) = default;
};

template <typename key_type>
class Store {
  public:
    using db_type = DB<key_type, ProtobufRecord<zsearch::Record>>;
    using lock_on_type = typename key_type::lock_on_type;
    using lock_type = typename LockManager<lock_on_type>::Lock;

  private:
    db_type* m_db;
    lock_type m_lock;

    ASTree::Handle m_as_handle;
    GeoIP* m_public_location;
    GeoIP* m_restricted_location;

    friend class StoreIterator;
    friend class HostIterator;

  public:
    Store() = delete;
    Store(const Store&) = delete;
    Store(Store&&);
    Store(db_type* db,
          lock_type lock,
          ASTree::Handle as_handle,
          GeoIP* public_location,
          GeoIP* restricted_location);

    bool is_open() const { return m_db != nullptr; }

    inline zsearch::Record get(const key_type& key) {
        return m_db->get(key).pb();
    }
    StoreResult put(zsearch::Record value);
    StoreResult del(const key_type& key);

    inline bool empty() const { return m_db->empty(); }
    bool delete_all();

    class StoreIterator {
      public:
        using value_type = std::pair<key_type, zsearch::Record>;

      private:
        using zdb_iterator =
                typename DB<key_type,
                            ProtobufRecord<zsearch::Record>>::iterator;

        zdb_iterator m_it;
        value_type m_value;

        friend class Store;

        StoreIterator(zdb_iterator&& it) : m_it(std::move(it)) {}

      public:
        StoreIterator(const StoreIterator& other) = delete;
        StoreIterator(StoreIterator&& other) : m_it(std::move(other.m_it)) {}

        bool operator==(const StoreIterator& other) const {
            return m_it == other.m_it;
        }

        bool operator!=(const StoreIterator& other) const {
            return !(*this == other);
        }

        value_type operator*() const {
            zsearch::Record zr;
            auto cur = *m_it;
            zr.Clear();
            zr.Swap(&cur.second.pb());
            return std::make_pair(cur.first, zr);
        }

        value_type* operator->() {
            zsearch::Record zr;
            auto cur = *m_it;
            zr.Clear();
            zr.Swap(&cur.second.pb());
            m_value = std::make_pair(cur.first, zr);
            return &m_value;
        }

        StoreIterator& operator++() {
            ++m_it;
            return *this;
        }

        StoreIterator operator++(int) = delete;

        // Returns true if the underlying RocksDB iterator is valid
        inline bool valid() const { return m_it.valid(); }

        friend void swap(StoreIterator&& first, StoreIterator&& second) {
            std::swap(first.m_it, second.m_it);
        }
    };

    using iterator = StoreIterator;

    class HostIterator {
      public:
        using value_type = std::pair<key_type, std::vector<zsearch::Record>>;

      private:
        iterator m_it;
        value_type m_value;
        bool m_valid;

        friend class Store;

        void update_current() {
            if (!m_it.valid()) {
                m_valid = false;
                return;
            }
            m_value.second.clear();
            auto current_record = *m_it;
            auto current_subkey = current_record.first.zero_subkey();
            for (; m_it.valid(); ++m_it) {
                auto this_record = *m_it;
                if (!(this_record.first.zero_subkey() == current_subkey)) {
                    break;
                }
                m_value.second.emplace_back(std::move(this_record.second));
            }
            m_value.first = current_subkey;
        }

        HostIterator(iterator&& it) : m_it(std::move(it)) {
            m_valid = true;
            if (!m_it.valid()) {
                m_valid = false;
            }
            update_current();
        }

      public:
        HostIterator(const HostIterator& other) = delete;
        HostIterator(HostIterator&& other) : m_it(std::move(other.m_it)) {
            m_valid = other.m_valid;
        }

        bool operator==(const HostIterator& other) const {
            return m_value.first == other.m_value.first;
        }

        bool operator!=(const HostIterator& other) const {
            return !(*this == other);
        }

        const value_type& operator*() const { return m_value; }

        value_type& operator*() { return m_value; }

        const value_type* operator->() const { return &m_value; }

        value_type* operator->() { return &m_value; }

        HostIterator& operator++() {
            update_current();
            return *this;
        }

        HostIterator operator++(int) = delete;

        inline bool valid() const { return m_valid; }

        friend void swap(HostIterator&& first, HostIterator&& second) {
            std::swap(first.m_it, second.m_it);
            std::swap(first.m_valid, second.m_valid);
        }
    };

    using host_iterator = HostIterator;

    inline iterator begin() const { return StoreIterator(m_db->begin()); }
    inline iterator end() const { return StoreIterator(m_db->end()); }
    inline iterator upper_bound(key_type k) const {
        return StoreIterator(m_db->upper_bound(k));
    }
    iterator find_subkey() { return StoreIterator(m_db->end()); }

    inline host_iterator host_begin() const { return HostIterator(begin()); }
    inline host_iterator host_upper_bound(key_type k) const {
        return HostIterator(upper_bound(k));
    }

    StoreResult host_delta(const key_type& k) const;

    using min_scan_map = PruneConfiguration::min_scan_map;

    PruneStatistics prune(const min_scan_map& min_scan_ids,
                          DeltaHandler& handler);
    DumpStatistics dump_to_json(std::ostream& output_file,
                                const DumpConfiguration& dump_config);
    uint64_t regenerate_deltas(key_type start,
                               key_type stop,
                               DeltaHandler& handler);
    ReturnStatus update_locations(key_type start,
                                  key_type stop,
                                  DeltaHandler& handler);

  private:
    static PruneCheck should_prune(const zsearch::Record& record,
                                   const min_scan_map& min_scan_ids);
    static bool dump_host(std::ostream& out_stream,
                          Json::FastWriter& json_writer,
                          std::vector<zsearch::Record> records);
};

template <typename key_type>
Store<key_type>::Store(db_type* db,
                       lock_type lock,
                       ASTree::Handle as_handle,
                       GeoIP* public_location,
                       GeoIP* restricted_location)
        : m_db(db),
          m_lock(std::move(lock)),
          m_as_handle(std::move(as_handle)),
          m_public_location(public_location),
          m_restricted_location(restricted_location) {}

template <typename key_type>
Store<key_type>::Store(Store&& other)
        : m_db(other.m_db),
          m_lock(std::move(other.m_lock)),
          m_as_handle(std::move(other.m_as_handle)),
          m_public_location(other.m_public_location),
          m_restricted_location(other.m_restricted_location) {}

template <typename key_type>
StoreResult Store<key_type>::put(zsearch::Record value) {
    // Determine the key
    auto key = key_type::from_record(value);
    auto zero_subkey = key.zero_subkey();
    auto lock_on = key.lock_on();

    // Variables to keep track of as we iterate.
    std::set<std::string> merged_tags;
    std::map<std::string, std::string> merged_metadata;

    bool seen_subkey = false;
    uint64_t max_version = 0;

    StoreResult result = StoreResult::from_key(key);
    zsearch::Delta& delta = result.delta;
    delta.set_delta_type(zsearch::DT_UPDATE);

    // Lock
    auto deferred_unlock = m_lock.lock(lock_on);

    // Find records with the same subkey and merge tags and metadata. This also
    // let's us know if this IP had seen before.
    for (auto it = m_db->upper_bound_prefix_seek(zero_subkey); it.valid();
         ++it) {
        auto current_key = it->first;
        auto current_zero_subkey = current_key.zero_subkey();
        if (!(current_zero_subkey == zero_subkey)) {
            break;
        }

        seen_subkey = true;
        zsearch::Record& current_record = it->second.pb();
        uint64_t version = current_record.version();
        if (version > max_version) {
            max_version = version;
        }
        if (current_key == key) {
            // Only check protocol atoms
            if (current_record.data_oneof_case() !=
                zsearch::Record::DataOneofCase::kAtom) {
                continue;
            }
            // Check if SHA256 match to avoid a delta
            if (value.sha256fp() == current_record.sha256fp()) {
                // The record isn't going to change, but we need to update the
                // scan_id
                value.set_version(current_record.version());
                if (!m_db->put(key, value)) {
                    log_error("store", "could not put replacement record");
                    return StoreResult::failure();
                }
                return StoreResult::no_change();
            }
            continue;
        }
        auto next_record = delta.add_records();
        next_record->Swap(&current_record);
    }

    uint64_t this_version = max_version + 1;
    value.set_version(this_version);

    auto b = m_db->make_batch(zero_subkey);
    if (!b.put(key, value)) {
        log_error("store", "could not add atom to batch");
        return StoreResult::failure();
    }

    // If this is a new host, create the non-scan records, but only for IP
    // keys (hack)
    // XXX: hack, this should be a template parameter or something
    if (!seen_subkey) {
        // create two location records, one private, and one public
        zsearch::Record public_location;
        public_location.set_ip(value.ip());
        public_location.set_domain(value.domain());
        public_location.set_port(0);
        public_location.set_protocol(zsearch::PROTO_SYSTEM);
        public_location.set_subprotocol(zsearch::SUBPROTO_SYS_PUBLIC_LOCATION);
        m_public_location->populate_atom(
                public_location.mutable_public_location(), value.ip());
        public_location.set_version(this_version);
        if (!b.put(key_type::from_record(public_location), public_location)) {
            log_error("store", "could not add public location atom to batch");
            return StoreResult::failure();
        }
        auto delta_public_location = delta.add_records();
        delta_public_location->Swap(&public_location);

        zsearch::Record private_location;
        private_location.set_ip(value.ip());
        private_location.set_domain(value.domain());
        private_location.set_port(0);
        private_location.set_protocol(zsearch::PROTO_SYSTEM);
        private_location.set_subprotocol(
                zsearch::SUBPROTO_SYS_RESTRICTED_LOCATION);
        m_restricted_location->populate_atom(
                private_location.mutable_private_location(), value.ip());
        private_location.set_version(this_version);
        if (!b.put(key_type::from_record(private_location), private_location)) {
            log_error("store", "could not add private location atom to batch");
            return StoreResult::failure();
        }
        auto delta_private_location = delta.add_records();
        delta_private_location->Swap(&private_location);

        // Create an AS atom
        auto as_result = m_as_handle[ntohl(value.ip())];
        if (as_result.found) {
            zsearch::Record as_record;
            as_record.set_ip(value.ip());
            as_record.set_domain(value.domain());
            as_record.set_port(0);
            as_record.set_protocol(zsearch::PROTO_SYSTEM);
            as_record.set_subprotocol(zsearch::SUBPROTO_SYS_AS);
            as_record.mutable_as_atom()->Swap(&as_result.as_atom);
            as_record.set_version(this_version);
            if (!b.put(key_type::from_record(as_record), as_record)) {
                log_error("store", "could not add AS atom to batch");
                return StoreResult::failure();
            }
            auto delta_as_record = delta.add_records();
            delta_as_record->Swap(&as_record);
        }
    }

    if (!m_db->write_batch(b)) {
        log_error("store", "could not write batch");
        return StoreResult::failure();
    }

    // Finish up
    auto this_record = delta.add_records();
    this_record->Swap(&value);
    delta.set_version(this_version);
    result.success = true;
    return result;
}

template <typename key_type>
StoreResult Store<key_type>::del(const key_type& key) {
    auto zero_subkey = key.zero_subkey();
    auto b = m_db->make_batch(zero_subkey);
    if (!b.del(key)) {
        return StoreResult::failure();
    }

    // Lock
    auto deferred_unlock = m_lock.lock(key.lock_on());

    if (!m_db->may_exist(key)) {
        return StoreResult::no_change();
    }
    ProtobufRecord<zsearch::Record> old;
    try {
        old = m_db->get(key);
    } catch (std::out_of_range& e) {
        return StoreResult::no_change();
    } catch (...) {
        return StoreResult::failure();
    }

    StoreResult result = StoreResult::from_key(key);
    zsearch::Delta& delta = result.delta;
    delta.set_delta_type(zsearch::DT_DELETE);
    uint64_t max_version = old.pb().version();

    for (auto it = m_db->upper_bound_prefix_seek(zero_subkey); it.valid();
         ++it) {
        const auto& current_key = it->first;
        if (!(current_key.zero_subkey() == zero_subkey)) {
            break;
        }
        if (current_key == key) {
            continue;
        }
        auto& current_record = it->second.pb();
        auto version = current_record.version();
        if (version > max_version) {
            max_version = version;
        }
        auto next_record = delta.add_records();
        next_record->Swap(&current_record);
    }
    uint64_t this_version = max_version + 1;
    zsearch::Record dummy = key.make_record();
    dummy.set_port(0);
    dummy.set_protocol(zsearch::Protocol::PROTO_SYSTEM);
    dummy.set_subprotocol(zsearch::Subprotocol::SUBPROTO_SYS_VERSION);
    dummy.set_version(this_version);
    delta.set_version(this_version);
    if (!b.put(key_type::from_record(dummy), dummy)) {
        return StoreResult::failure();
    }
    result.delta.add_records()->Swap(&dummy);

    if (!m_db->write_batch(b)) {
        return StoreResult::failure();
    }

    result.success = true;
    return result;
}

template <typename key_type>
bool Store<key_type>::delete_all() {
    return m_db->delete_all();
}

template <typename key_type>
StoreResult Store<key_type>::host_delta(const key_type& k) const {
    StoreResult ret;
    key_type zk = k.zero_subkey();
    auto it = host_upper_bound(zk);
    // Check if we found anything
    if (!it.valid()) {
        return ret;
    }
    // Check to make sure the key matches
    if (!(it->first.zero_subkey() == zk)) {
        return ret;
    }

    // Make a delta
    k.set_delta(ret.delta);
    ret.delta.set_delta_type(zsearch::DT_NO_CHANGE);
    ret.delta.set_version(get_largest_version(it->second));
    for (zsearch::Record& rec : it->second) {
        zsearch::Record* next = ret.delta.add_records();
        next->Swap(&rec);
    }
    return ret;
}

template <typename key_type>
PruneStatistics Store<key_type>::prune(const min_scan_map& min_scan_ids,
                                       DeltaHandler& handler) {
    PruneStatistics stats;
    for (auto it = m_db->begin(); it.valid(); ++it) {
        ++stats.records_read;
        const auto& current_pair = *it;
        const auto& current_key = current_pair.first;
        const auto& current_record = current_pair.second.pb();

        // Build the current anonymous key
        zsearch::AnonymousKey current_anon_key;
        current_anon_key.set_port(current_record.port());
        current_anon_key.set_protocol(current_record.protocol());
        current_anon_key.set_subprotocol(current_record.subprotocol());

        // Never prune the magic version subprotocol
        if (current_anon_key.subprotocol() == zsearch::SUBPROTO_SYS_VERSION) {
            continue;
        }

        // Check to see if we're pruning this protocol
        auto min_it = min_scan_ids.find(current_anon_key);
        if (min_it == min_scan_ids.end()) {
            continue;
        }

        // We're pruning the protocol, so check to see if we prune this record
        uint32_t current_scan_id = current_record.scanid();
        if (current_scan_id < min_it->second) {
            StoreResult result = del(current_key);
            handler.handle_delta(result);
            ++stats.records_pruned;
            stats.pruned_per_key[current_anon_key] += 1;
        }
    }
    stats.success = true;
    return stats;
}

template <typename key_type>
DumpStatistics Store<key_type>::dump_to_json(
        std::ostream& output_file,
        const DumpConfiguration& dump_config) {
    DumpStatistics stats;

    if (dump_config.prune_handlers.empty()) {
        log_error("store", "could not dump, no handlers specified");
        return stats;
    }

    if (dump_config.min_scan_ids.empty()) {
        log_info("store",
                 "no min_scan_ids received during dump, prune will not occur");
    } else {
        log_info("store", "received min_scan_ids during dump, will also prune");
    }

    auto it = m_db->rr_begin();
    if (!it.valid()) {
        // Database is empty
        log_error("store", "could not dump, empty database");
        return stats;
    }

    // We're using two thread-safe queues: to_process contains vectors of
    // seralized records for a single host. These get turned into a JSON string
    // and added to the to_write queue, which are then written to the output
    // file
    Channel<std::vector<std::string>> to_process;
    Channel<std::string> to_write;
    WaitGroup process_group;

    // Start up the output writing thread, which reads from to_write and write
    // to the output_file
    std::thread output_thread([&to_write, &output_file]() {
        for (auto it = to_write.range(); it.valid(); ++it) {
            if (it->size() > 0) {
                output_file << *it;
            }
        }
        output_file.flush();
    });
    std::vector<std::thread> processing_threads;
    std::vector<PruneStatistics> all_prune_stats;
    all_prune_stats.resize(dump_config.prune_handlers.size());
    process_group.add(dump_config.prune_handlers.size());
    for (size_t i = 0; i < dump_config.prune_handlers.size(); ++i) {
        processing_threads.emplace_back(
                [&](size_t thread_id) {
                    Json::FastWriter json_writer;
                    json_writer.omitEndingLineFeed();
                    PruneStatistics& prune_stats = all_prune_stats[thread_id];
                    for (auto it = to_process.range(); it.valid(); ++it) {
                        auto& serialized_records = *it;
                        if (serialized_records.size() == 0) {
                            continue;
                        }

                        // Allocate containers for this host
                        std::vector<zsearch::Record> records;
                        records.reserve(serialized_records.size());
                        assert(records.size() == 0);

                        // Deserialize all the records and save to a vector
                        std::for_each(
                                serialized_records.begin(),
                                serialized_records.end(),
                                [&](const std::string& s) {
                                    // Deserialize
                                    zsearch::Record record;
                                    bool ok = record.ParseFromString(s);
                                    if (!ok) {
                                        log_error(
                                                "store",
                                                "unable to deserialize record");
                                        return;
                                    }

                                    // Prune here
                                    PruneCheck pc =
                                            Store<key_type>::should_prune(
                                                    record,
                                                    dump_config.min_scan_ids);
                                    if (pc.should_prune) {
                                        auto delta = this->del(
                                                key_type::from_record(record));
                                        dump_config.prune_handlers[thread_id]
                                                ->handle_delta(delta);
                                        ++prune_stats.records_pruned;
                                        prune_stats
                                                .pruned_per_key[pc.anon_key] +=
                                                1;
                                        return;
                                    }

                                    // Didn't prune, add it to the list of
                                    // deserialized records
                                    records.emplace_back();
                                    records.back().Swap(&record);
                                });

                        // Check if we got records to dump
                        if (records.size() == 0) {
                            continue;
                        }

                        // Only do AS data for IPv4 records
                        if (records.front().domain().size() == 0 &&
                            records.front().ip() != 0) {
                            // Find AS data
                            auto as_record_it = std::find_if(
                                    records.begin(), records.end(),
                                    [](const zsearch::Record& r) {
                                        if (r.data_oneof_case() !=
                                            zsearch::Record::DataOneofCase::
                                                    kAsAtom) {
                                            return false;
                                        }
                                        return r.port() == 0 &&
                                               r.protocol() ==
                                                       zsearch::PROTO_SYSTEM &&
                                               r.subprotocol() ==
                                                       zsearch::SUBPROTO_SYS_AS;
                                    });

                            std::equal_to<zsearch::ASAtom> equal_atom;
                            if (as_record_it != records.end()) {
                                // If we found AS data, update and write it
                                auto& as_record = *as_record_it;
                                auto as_res = this->m_as_handle[ntohl(
                                        as_record.ip())];
                                if (as_res.found &&
                                    !(equal_atom(as_record.as_atom(),
                                                 as_res.as_atom))) {
                                    as_record.mutable_as_atom()->Swap(
                                            &as_res.as_atom);
                                }
                                this->put(as_record);
                            } else {
                                // If we didn't find AS data, make a record
                                auto as_res = this->m_as_handle[ntohl(
                                        records.front().ip())];
                                if (as_res.found) {
                                    zsearch::Record as_record;
                                    as_record.set_ip(records.front().ip());
                                    as_record.set_port(0);
                                    as_record.set_protocol(
                                            zsearch::PROTO_SYSTEM);
                                    as_record.set_subprotocol(
                                            zsearch::SUBPROTO_SYS_AS);
                                    as_record.mutable_as_atom()->Swap(
                                            &as_res.as_atom);
                                    auto delta = this->put(as_record);
                                    dump_config.prune_handlers[thread_id]
                                            ->handle_delta(delta);
                                    records.emplace_back();
                                    records.back().Swap(&as_record);
                                }
                            }
                        }

                        // Make the output stream
                        std::stringstream ss;
                        bool non_empty = Store<key_type>::dump_host(
                                ss, json_writer, std::move(records));
                        if (non_empty) {
                            to_write.send(ss.str());
                        }
                    }
                    prune_stats.success = true;
                    process_group.done();
                },
                i);
    }
    std::vector<std::string> working_records;
    auto working_key = it->first.zero_subkey();
    for (; it.valid(); ++it) {
        if (dump_config.max_records &&
            stats.records_dumped >= dump_config.max_records) {
            break;
        }
        const auto current_key = it->first.zero_subkey();
        if (!(current_key == working_key)) {
            to_process.send(std::move(working_records));
            working_records = std::vector<std::string>{};
            ++stats.hosts_dumped;
            working_key = current_key;
        }
        working_records.push_back(it->second);
        ++stats.records_dumped;
    }
    to_process.send(std::move(working_records));
    ++stats.hosts_dumped;
    log_trace("store", "closing to_process queue");
    to_process.close();
    log_trace("store", "waiting on processing threads");
    process_group.wait();
    log_trace("store", "individually joining each process thread");
    std::for_each(processing_threads.begin(), processing_threads.end(),
                  [](std::thread& t) { t.join(); });
    log_trace("store", "closing to_output queue");
    to_write.close();
    log_trace("store", "merging prune statistics from dump process threads");
    stats.prune_stats.success = true;
    std::for_each(all_prune_stats.begin(), all_prune_stats.end(),
                  [&stats](const PruneStatistics& other) {
                      stats.prune_stats.merge(other);
                  });
    log_trace("store", "joining to output thread");
    output_thread.join();
    log_trace("store", "finishing up dump");
    stats.success = stats.prune_stats.success;
    return stats;
}

template <typename key_type>
uint64_t Store<key_type>::regenerate_deltas(key_type start,
                                            key_type stop,
                                            DeltaHandler& handler) {
    uint64_t count = 0;
    for (auto it = host_upper_bound(start); it.valid(); ++it) {
        if (count > 0 && count % 100000 == 0) {
            log_info("store", "regenerated %llu deltas so far", count);
        }
        if (!(it->first < stop)) {
            log_info("store", "regenerate deltas reached stop key");
            break;
        }
        if (it->second.size() == 0) {
            continue;
        }
        StoreResult sr;
        sr.success = true;
        auto& delta = sr.delta;
        it->first.set_delta(delta);
        uint64_t max_version = 1;
        std::for_each(it->second.begin(), it->second.end(),
                      [&](zsearch::Record r) {
                          if (r.version() > max_version) {
                              max_version = r.version();
                          }
                          auto next = delta.add_records();
                          next->Swap(&r);
                      });
        delta.set_version(max_version);
        delta.set_delta_type(zsearch::DeltaType::DT_UPDATE);
        handler.handle_delta(sr);
        count += 1;
    }
    return count;
}

template <typename key_type>
ReturnStatus Store<key_type>::update_locations(key_type start,
                                               key_type stop,
                                               DeltaHandler& handler) {
    uint64_t count = 0;
    for (auto it = host_upper_bound(start); it.valid(); ++it) {
        if (count > 0 && count % 100000 == 0) {
            log_info("store", "updated %llu IPs so far", count);
        }
        if (!(it->first < stop)) {
            log_info("store", "locations update reached stop key");
            break;
        }
        count++;
        if (it->second.size() == 0) {
            continue;
        }
        const auto& current_key = it->first;
        uint32_t current_ip = current_key.ip;

        // Save the deltas. In the normal case, two deltas will be generated.
        std::vector<StoreResult> deltas;
        deltas.reserve(2);

        // Loop through all the records for this host and update the locations
        // as needed.
        for (const auto& r : it->second) {
            auto data_oneof = r.data_oneof_case();
            if (data_oneof == zsearch::Record::DataOneofCase::kPublicLocation) {
                // XXX: Float comparison
                if (r.public_location().latitude() == 0 &&
                    r.public_location().longitude() == 0) {
                    zsearch::Record public_location;
                    public_location.set_ip(current_ip);
                    public_location.set_port(0);
                    public_location.set_protocol(zsearch::PROTO_SYSTEM);
                    public_location.set_subprotocol(
                            zsearch::SUBPROTO_SYS_PUBLIC_LOCATION);
                    m_public_location->populate_atom(
                            public_location.mutable_public_location(),
                            current_ip);
                    public_location.set_version(0);
                    auto sr = this->put(public_location);
                    if (!sr.success) {
                        return RETURN_FAILURE;
                    }
                    deltas.push_back(std::move(sr));
                }
            } else if (data_oneof ==
                       zsearch::Record::DataOneofCase::kPrivateLocation) {
                // XXX: Float comparison
                if (r.private_location().latitude() == 0 &&
                    r.private_location().longitude() == 0) {
                    zsearch::Record private_location;
                    private_location.set_ip(current_ip);
                    private_location.set_port(0);
                    private_location.set_protocol(zsearch::PROTO_SYSTEM);
                    private_location.set_subprotocol(
                            zsearch::SUBPROTO_SYS_RESTRICTED_LOCATION);
                    m_restricted_location->populate_atom(
                            private_location.mutable_private_location(),
                            current_ip);
                    private_location.set_version(0);
                    auto sr = this->put(private_location);
                    if (!sr.success) {
                        return RETURN_FAILURE;
                    }
                    deltas.push_back(std::move(sr));
                }
            }
        }

// XXX: Ignore deltas
#if 0
        if (!deltas.empty()) {
            handler.handle_delta(deltas.back());
        }
#endif
    }
    return RETURN_SUCCESS;
}

template <typename key_type>
PruneCheck Store<key_type>::should_prune(const zsearch::Record& record,
                                         const min_scan_map& min_scan_ids) {
    if (min_scan_ids.empty()) {
        return PruneCheck::no_prune();
    }

    // Build the current anonymous key
    zsearch::AnonymousKey anon_key;
    anon_key.set_port(record.port());
    anon_key.set_protocol(record.protocol());
    anon_key.set_subprotocol(record.subprotocol());

    // Never prune the magic version subprotocol
    if (anon_key.subprotocol() == zsearch::SUBPROTO_SYS_VERSION) {
        return PruneCheck::no_prune();
    }

    // Check to see if we're pruning this protocol
    auto min_it = min_scan_ids.find(anon_key);
    if (min_it == min_scan_ids.end()) {
        return PruneCheck::no_prune();
    }

    // We're pruning the protocol, so check to see if we prune this record
    uint32_t scan_id = record.scanid();
    if (scan_id < min_it->second) {
        PruneCheck check;
        check.should_prune = true;
        check.anon_key.Swap(&anon_key);
        return check;
    }
    return PruneCheck::no_prune();
}

template <typename key_type>
bool Store<key_type>::dump_host(std::ostream& out_stream,
                                Json::FastWriter& json_writer,
                                std::vector<zsearch::Record> records) {
    // Check if it's empty
    if (records.size() == 0) {
        return false;
    }
    auto ip = records.front().ip();
    auto domain = records.front().domain();
    int alexa_rank = 0;

    // Allocate containers
    std::vector<zsearch::Record> atom_records;
    std::map<std::string, std::string> metadata;
    std::set<std::string> tags;

    // Location stuff
    bool public_location_found = false;
    bool private_location_found = false;
    bool as_data_found = false;
    zsearch::LocationAtom public_location;
    zsearch::LocationAtom private_location;
    zsearch::ASAtom as_data;

    // Reserve memory
    atom_records.reserve(records.size());

    std::for_each(records.begin(), records.end(), [&](zsearch::Record& record) {
        // Skip reserved protocol
        if (record.protocol() == zsearch::PROTO_RESERVED ||
            record.subprotocol() == zsearch::SUBPROTO_RESERVED) {
            return;
        }

        // Merge tags
        auto current_tags = tags_from_record(record);
        std::copy(current_tags.begin(), current_tags.end(),
                  std::inserter(tags, tags.begin()));

        // Merge metadata
        auto current_metadata = metadata_from_record(record);
        std::transform(current_metadata.begin(), current_metadata.end(),
                       std::inserter(metadata, metadata.begin()),
                       [](const zsearch::Metadatum& m) {
                           return std::make_pair(m.key(), m.value());
                       });

        // Check for location
        if (record.protocol() == zsearch::PROTO_SYSTEM) {
            if (record.subprotocol() == zsearch::SUBPROTO_SYS_PUBLIC_LOCATION) {
                public_location.CopyFrom(record.public_location());
                public_location_found = true;
            } else if (record.subprotocol() ==
                       zsearch::SUBPROTO_SYS_RESTRICTED_LOCATION) {
                private_location.CopyFrom(record.private_location());
                private_location_found = true;
            } else if (record.subprotocol() ==
                       zsearch::SUBPROTO_SYS_ALEXA_RANK) {
                alexa_rank = record.alexa_rank();
            } else if (record.subprotocol() == zsearch::SUBPROTO_SYS_AS) {
                as_data_found = true;
                as_data.CopyFrom(record.as_atom());
            }
        } else {
            atom_records.emplace_back();
            atom_records.back().Swap(&record);
        }
    });

    if (atom_records.size() == 0) {
        return false;
    }
    fast_dump_ipv4_host(out_stream, ip, domain, atom_records, metadata, tags,
                        public_location, private_location, as_data,
                        public_location_found, private_location_found,
                        as_data_found, alexa_rank, json_writer);
    return true;
}

}  // namespace zdb

#endif /* ZDB_SRC_STORE_H */
