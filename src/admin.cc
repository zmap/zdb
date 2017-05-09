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

#include "admin.h"

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <vector>
#include <list>
#include <utility>

#include <arpa/inet.h>

#include <base64/base64.h>

#include <grpc/grpc.h>
#include <grpc++/server.h>
#include <grpc++/server_builder.h>
#include <grpc++/server_context.h>
#include <grpc++/security/server_credentials.h>

#include <json/json.h>

#include <stdio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

#include <zmap/logger.h>

#include "anonymous_store.h"
#include "as_data.h"
#include "certificates.h"
#include "configuration.h"
#include "record.h"
#include "utility.h"
#include "record.h"
#include "zmap/logger.h"
#include "search.grpc.pb.h"
#include "store.h"
#include "inbound.h"
#include "protocol_names.h"

#include "fastjson.h"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;

using namespace std;
using namespace zdb;
using namespace zsearch;

namespace {

const std::string kErrorMsgUnopened = "unopened store";

}  // namespace

class AdminServiceImpl final : public zsearch::AdminService::Service {
  private:
    Store<IPv4Key> ipv4_store;
    Store<DomainKey> domain_store;
    AnonymousStore<HashKey> cert_store;

    std::shared_ptr<PruneHandler> certificate_prune_handler;
    std::shared_ptr<PruneHandler> certificates_to_process_prune_handler;
    std::vector<std::shared_ptr<PruneHandler>> ipv4_prune_handler;
    std::vector<std::shared_ptr<PruneHandler>> domain_prune_handler;
    CAStore ca_store;

    ASTree* m_as_tree;

    template <typename StoreType>
    grpc::Status prune(StoreType& store,
                       PruneHandler& handler,
                       const Command* request,
                       CommandReply* response) {
        map<AnonymousKey, uint32_t> min_scan_ids;
        for (MinScanId min_id : request->min_scan_ids()) {
            const auto& key = min_id.key();
            if (key.subprotocol() == zsearch::SUBPROTO_SYS_VERSION) {
                response->set_status(CommandReply::ERROR);
                response->set_error("Cannot prune SUBPROTO_SYS_VERSION");
                return grpc::Status::OK;
            }
            min_scan_ids[key] = min_id.min_scan_id();
            log_info(
                    "admin",
                    "will prune port %u, protocol %u, subprotocol %u to min %u",
                    key.port(), key.protocol(), key.subprotocol(),
                    min_id.min_scan_id());
        }
        auto stats = store.prune(min_scan_ids, handler);
        if (stats.success) {
            response->set_status(CommandReply::SUCCESS);
            log_info("admin", "pruned %llu total records",
                     stats.records_pruned);
            for (const auto& prune_pair : stats.pruned_per_key) {
                const auto& key = prune_pair.first;
                log_info(
                        "admin",
                        "prune %llu records for port %u, protocol %u, subprotocol %u",
                        prune_pair.second, key.port(), key.protocol(),
                        key.subprotocol());
                auto stat = response->add_prune_statistics();
                stat->mutable_key()->CopyFrom(key);
                stat->set_records_pruned(prune_pair.second);
            }
        } else {
            response->set_status(CommandReply::ERROR);
            response->set_error("Unknown prune failure");
        }
        return grpc::Status::OK;
    }

    template <typename store_type>
    grpc::Status dump(
            const Command* request,
            CommandReply* response,
            store_type& store,
            std::vector<std::shared_ptr<PruneHandler>> prune_handlers) {
        log_info("admin", "dumping to file %s", request->filepath().c_str());
        std::ofstream f(request->filepath());
        if (!f) {
            log_error("admin", "could not open dump output file %s",
                      request->filepath().c_str());
            response->set_status(CommandReply::ERROR);
            response->set_error("Could not open output file");
            return grpc::Status::OK;
        }

        // Make the dump config
        DumpConfiguration dump_config;
        dump_config.max_queue_size = 1024;
        dump_config.max_records = request->max_records();
        dump_config.prune_handlers = std::move(prune_handlers);
        log_info("admin", "dump max queue size %llu",
                 dump_config.max_queue_size);
        log_info("admin", "dump using %llu process threads",
                 dump_config.prune_handlers.size());
        log_info("admin", "dump max %llu records", dump_config.max_records);

        auto& min_scan_ids = dump_config.min_scan_ids;
        for (MinScanId min_id : request->min_scan_ids()) {
            const auto& key = min_id.key();
            if (key.subprotocol() == zsearch::SUBPROTO_SYS_VERSION) {
                response->set_status(CommandReply::ERROR);
                response->set_error("Cannot prune SUBPROTO_SYS_VERSION");
                return grpc::Status::OK;
            }
            min_scan_ids[key] = min_id.min_scan_id();
            log_info(
                    "admin",
                    "will prune port %u, protocol %u, subprotocol %u to min %u",
                    key.port(), key.protocol(), key.subprotocol(),
                    min_id.min_scan_id());
        }

        // Assume failure
        response->set_status(CommandReply::ERROR);

        // The store itself does the actual dump
        log_info("admin", "writing store to JSON");
        auto stats = store.dump_to_json(f, dump_config);
        log_info("admin", "writing store to JSON finished");

        log_info("admin", "pruned %llu total records during dump",
                 stats.prune_stats.records_pruned);
        for (const auto& prune_pair : stats.prune_stats.pruned_per_key) {
            const auto& key = prune_pair.first;
            log_info(
                    "admin",
                    "prune %llu records for port %u, protocol %u, subprotocol %u",
                    prune_pair.second, key.port(), key.protocol(),
                    key.subprotocol());
            auto stat = response->add_prune_statistics();
            stat->mutable_key()->CopyFrom(key);
            stat->set_records_pruned(prune_pair.second);
        }

        // Check success
        if (stats.success) {
            response->set_status(CommandReply::SUCCESS);
        } else {
            response->set_error("Store error during dump");
        }

        return grpc::Status::OK;
    }

    // Returns true and populates `result` when the certificate with the given
    // sha256fp is found.
    bool get_certificate_delta(std::string sha256fp, AnonymousResult* result) {
        // Make a HashKey from the query
        HashKey hk;
        hk.hash = sha256fp;

        try {
            // Look up the record
            AnonymousRecord ar = cert_store.get(hk);

            // Put the record into an AnonymousResult
            result->success = true;
            AnonymousDelta& d = result->delta;
            d.set_delta_type(zsearch::AnonymousDelta_DeltaType_DT_UPDATE);
            d.set_delta_scope(zsearch::AnonymousDelta_DeltaScope_SCOPE_UPDATE);
            d.mutable_record()->Swap(&ar);
            return true;

        } catch (std::out_of_range e) {
            return false;
        } catch (std::runtime_error e) {
            log_fatal("admin", "error in .get(): %S", e.what());
        }
        NOTREACHED();
    }

  public:
    AdminServiceImpl(Store<IPv4Key>&& ipv4,
                     Store<DomainKey>&& domain,
                     AnonymousStore<HashKey>&& cert,
                     std::vector<std::shared_ptr<PruneHandler>> ipv4_prune,
                     std::vector<std::shared_ptr<PruneHandler>> domain_prune,
                     std::shared_ptr<PruneHandler> certificate_prune,
                     std::shared_ptr<PruneHandler> certificate_process_prune,
                     ASTree* as_tree)
            : zsearch::AdminService::Service(),
              ipv4_store(std::move(ipv4)),
              domain_store(std::move(domain)),
              cert_store(std::move(cert)),
              ipv4_prune_handler(std::move(ipv4_prune)),
              domain_prune_handler(std::move(domain_prune)),
              certificate_prune_handler(std::move(certificate_prune)),
              certificates_to_process_prune_handler(
                      std::move(certificate_process_prune)),
              m_as_tree(as_tree) {}

    virtual grpc::Status Status(ServerContext* context,
                                const Command* request,
                                CommandReply* response) override {
        response->set_status(CommandReply::SUCCESS);
        return grpc::Status::OK;
    }

    virtual grpc::Status Shutdown(ServerContext* context,
                                  const Command* request,
                                  CommandReply* response) override {
        zdb::server_state = STATE_SHUTDOWN;
        log_info("admin", "shutdown process started");
        response->set_status(CommandReply::SUCCESS);
        return grpc::Status::OK;
    }

    virtual grpc::Status PruneIPv4(ServerContext* context,
                                   const Command* request,
                                   CommandReply* response) override {
        log_info("admin", "starting prune process on ipv4");
        if (!ipv4_store.is_open()) {
            log_error("admin", "ipv4 store not opened");
            response->set_status(CommandReply::ERROR);
            response->set_error(kErrorMsgUnopened);
            return grpc::Status::OK;
        }
        grpc::Status s = prune(ipv4_store, *ipv4_prune_handler.front(), request,
                               response);
        return s;
    }

    virtual grpc::Status PruneDomain(ServerContext* context,
                                     const Command* request,
                                     CommandReply* response) override {
        log_info("admin", "starting prune process on domain");
        if (!domain_store.is_open()) {
            log_error("admin", "domain store not opened");
            response->set_status(CommandReply::ERROR);
            response->set_error(kErrorMsgUnopened);
            return grpc::Status::OK;
        }
        log_info("admin", "locking redis threads, starting prune (domain)");
        zdb::server_state = STATE_LOCK_DOMAIN;
        grpc::Status s = prune(domain_store, *domain_prune_handler.front(),
                               request, response);
        log_info("admin", "unlocking redis threads from domain prune");
        if (zdb::server_state == STATE_LOCK_DOMAIN) {
            zdb::server_state = STATE_OK;
        }
        return s;
    }

    virtual grpc::Status UpdateLocationData(grpc::ServerContext* context,
                                            const Command* request,
                                            CommandReply* response) override {
        log_info("admin", "received location update request");
        auto start_str = make_ip_str(request->start_ip());
        auto stop_str = make_ip_str(request->stop_ip());
        log_info("admin", "location update will start at %s",
                 start_str.c_str());
        log_info("admin", "location update will stop at %s", stop_str.c_str());
        IPv4Key start{request->start_ip(), 0, 0, 0};
        IPv4Key stop{request->stop_ip(), 0, 0, 0};

        if (!ipv4_store.is_open()) {
            log_error("admin", "ipv4 store not opened");
            response->set_status(CommandReply::ERROR);
            response->set_error(kErrorMsgUnopened);
            return grpc::Status::OK;
        }

        if (ipv4_store.update_locations(start, stop,
                                        *ipv4_prune_handler.front()) !=
            RETURN_SUCCESS) {
            log_info("admin", "locations job failed");
            response->set_status(CommandReply::ERROR);
            response->set_error("locations job failed");
        }
        log_info("admin", "successfully updated locations");
        response->set_status(CommandReply::SUCCESS);
        return grpc::Status::OK;
    }

    virtual grpc::Status UpdateASData(grpc::ServerContext* context,
                                      const Command* request,
                                      CommandReply* response) override {
        log_info("admin", "received AS update request");
        // Open the AS data file or fail
        log_info("admin", "will read AS data from file %s",
                 request->filepath().c_str());
        std::ifstream as_file(request->filepath());
        if (!as_file) {
            log_error("admin", "could not open AS data file");
            response->set_status(CommandReply::ERROR);
            response->set_error("could not open file");
            return grpc::Status::OK;
        }
        log_info("admin", "starting AS update process");
        bool update_succeeded = m_as_tree->load_json(as_file);
        log_info("admin", "AS update finished");
        if (update_succeeded) {
            response->set_status(CommandReply::SUCCESS);
            log_info("admin", "AS update successful");
        } else {
            response->set_status(CommandReply::ERROR);
            response->set_error("ASTree::load_json returned false");
            log_error("admin", "AS update failed");
        }
        return grpc::Status::OK;
    }

    bool doesLinkUpToRoot(std::shared_ptr<cert_data> cert,
                          std::unordered_set<string>& seen_before,
                          bool restrict_to_now) {
        const auto& issuer = cert->subject_issuer.issuer;
        if (cert->is_valid) {
            return true;
        } else if (cert->subject_issuer.self_signed) {
            return false;
        } else if (seen_before.count(issuer)) {
            return false;
        }
        auto parents_it = ca_store.by_subject.find(cert->subject_issuer.issuer);
        if (parents_it != ca_store.by_subject.end()) {
            for (auto& parent : parents_it->second) {
                // if we're populating currently_valid, then check that a
                // potential parent is valid today.
                if (restrict_to_now &&
                    !x509_check_time_valid_now(parent->X509_cert.get())) {
                    continue;
                }
                seen_before.insert(issuer);
                if (valid_parent(parent->X509_cert.get(),
                                 cert->X509_cert.get())) {
                    if (doesLinkUpToRoot(parent, seen_before,
                                         restrict_to_now)) {
                        parent->is_valid = true;
                        return true;
                    }
                }
                seen_before.erase(issuer);
            }
        }
        return false;
    }

    std::set<string> find_parents(const CertificateSubjectIssuer& child,
                                  X509* c) {
        // Check if we have anything for this issuer
        auto parent_it = ca_store.by_subject.find(child.issuer);
        if (parent_it == ca_store.by_subject.end()) {
            return std::set<string>();
        }
        std::set<string> ret;
        // Check each parent
        for (const auto& parent : parent_it->second) {
            if (valid_parent(parent->X509_cert.get(), c)) {
                ret.insert(parent->subject_issuer.fingerprint_sha256);
            }
        }
        return ret;
    }

    bool find_valid_chain(const CertificateSubjectIssuer& cert,
                          X509* c,
                          cert_data* entry,
                          bool restrict_to_now) {
        // Iterate over valid parents to see if any link up to root
        // If they do then set the writeback flag
        if (restrict_to_now && !x509_check_time_valid_now(c)) {
            return false;
        }
        auto& parents = ca_store.by_subject[cert.issuer];
        std::unordered_set<std::string> seen_before;
        seen_before.insert(cert.subject);
        for (auto& parent : parents) {
            if (!valid_parent(parent->X509_cert.get(), c)) {
                continue;
            }
            if (restrict_to_now &&
                !x509_check_time_valid_now(parent->X509_cert.get())) {
                continue;
            }
            seen_before.insert(cert.issuer);
            if (parent->is_valid ||
                doesLinkUpToRoot(parent, seen_before, restrict_to_now)) {
                // We have a valid cert!

                // If this certificate is one of the signers we found in the
                // first pass, and is valid, we can short circuit the validation
                // next time.
                if (entry != nullptr) {
                    entry->is_valid = true;
                }
                return true;
            }
            seen_before.erase(cert.issuer);
        }
        return false;
    }

    virtual grpc::Status ValidateCertificates(ServerContext* context,
                                              const Command* request,
                                              CommandReply* response) override {
        log_info("admin", "validate for certificates");
        if (!cert_store.is_open()) {
            log_error("admin", "certificate store not opened");
            response->set_status(CommandReply::ERROR);
            response->set_error(kErrorMsgUnopened);
            return grpc::Status::OK;
        }
        OpenSSL_add_all_algorithms();
        const auto path = request->filepath().c_str();

        // Read root store
        size_t num_root_parsed = 0;
        FILE* fp = fopen(path, "r");
        if (!fp) {
            log_error("admin", "unable to open file: %s", path);
            response->set_status(CommandReply::ERROR);
            response->set_error("could not open PEM file");
            return grpc::Status::OK;
        }
        X509* root_cert = PEM_read_X509(fp, NULL, NULL, NULL);
        if (!root_cert) {
            log_error("admin", "unable to parse certificate in: %s", path);
            response->set_status(CommandReply::ERROR);
            response->set_error("no certificates in PEM file");
            return grpc::Status::OK;
        }
        while (root_cert) {
            string subj = x509_get_subject_string(root_cert);
            auto entry = make_shared<cert_data>();
            entry->is_root = true;
            entry->is_valid = true;
            entry->X509_cert = shared_ptr<X509>(root_cert, &::X509_free);
            entry->subject_issuer = x509_get_subject_issuer(root_cert);
            ca_store.by_subject[entry->subject_issuer.subject].insert(entry);
            ca_store.by_fingerprint[entry->subject_issuer.fingerprint_sha256] =
                    entry;
            num_root_parsed++;
            root_cert = PEM_read_X509(fp, NULL, NULL, NULL);
        }
        log_info("admin", "parsed %llu root certificates", num_root_parsed);
        fclose(fp);

        size_t certs_processed_first = 0;

        // First iteration: populate ca_map and record if cert is root
        for (auto it = cert_store.begin(); it.valid();
             ++it, ++certs_processed_first) {
            if (certs_processed_first && certs_processed_first % 100000 == 0) {
                log_info("admin",
                         "first iteration: processed %llu certificates",
                         certs_processed_first);
            }
            auto& rec = it->second;
#ifdef VALIDATION_DEBUG
            const auto old_cert = rec.certificate();
#endif
            // XXX: The method should probably just do this? Or at least create
            // a unique_ptr.
            shared_ptr<X509> c(certificate_to_x509(rec.certificate()),
                               &::X509_free);
            if (c == nullptr) {
                string cert_hex = hex_encode(rec.certificate().raw());
                log_error("admin", "unable to parse certificate: %s",
                          cert_hex.c_str());
                continue;
            }
            auto subject_issuer = x509_get_subject_issuer(c.get());
            bool is_root = ca_store.check_root(subject_issuer);

            // Write the root certificate back to indicate that it's a root
            if (is_root) {
                rec.mutable_certificate()->set_current_in_nss(true);
                rec.mutable_certificate()->set_was_in_nss(true);
                rec.mutable_certificate()->set_current_valid_nss(true);
                rec.mutable_certificate()->set_valid_nss(true);
                rec.mutable_certificate()->set_was_valid_nss(true);
                rec.mutable_certificate()->set_post_processed(true);
                auto res = cert_store.force_put(rec);
                certificate_prune_handler->handle_pruned(res);
#ifdef VALIDATION_DEBUG
                auto new_cert = res.delta.record().certificate();
                log_info("admin", "action: found a root cert on first pass");
                log_info("admin", "sh256fp:");
                string h = hex_encode(old_cert.sha256fp());
                log_info("admin", h.c_str());
                log_info("admin", "====old record:====");
                log_info("admin", "in_nss:");
                log_info("admin", "%d", old_cert.current_in_nss());
                log_info("admin", "valid_nss:");
                log_info("admin", "%d", old_cert.current_valid_nss());
                log_info("admin", "====new record:====");
                log_info("admin", "in_nss:");
                log_info("admin", "%d", new_cert.current_in_nss());
                log_info("admin", "current_valid_nss:");
                log_info("admin", "%d", new_cert.current_valid_nss());
#endif
                // We already know about roots, so just continue
                continue;
            }
            // We're looking for intermediates, so skip certificates that can't
            // sign. We check this after the root check, because who knows what
            // extensions old root certificates have.
            if (!subject_issuer.can_sign) {
                continue;
            }
            // Self-signed certificates should not be intermediates
            // TODO: Confirm this.
            if (subject_issuer.self_signed) {
                continue;
            }
            // We have a certificate that might be an intermediate. Add it to
            // the "store".
            // TODO: This should probably be a method on CAStore
            auto entry = make_shared<cert_data>();
            entry->subject_issuer = subject_issuer;
            entry->X509_cert = c;
            ca_store.by_fingerprint[subject_issuer.fingerprint_sha256] = entry;
            ca_store.by_subject[subject_issuer.subject].insert(entry);
        }
        // The first iteration has now found every possible intermediate.
        log_info("admin",
                 "finished first iteration: processed %llu certificates",
                 certs_processed_first);
        size_t additional_signer_count =
                ca_store.by_fingerprint.size() - num_root_parsed;
        log_info("admin", "found %llu additional signer certs",
                 additional_signer_count);

        // We're now going to iterate through the database again, and do two
        // things:
        //    1. Validate each certificate using the full set of intermediates
        //    2. Update the parents on every certificate to contain only actual,
        //       _valid_ parents.
        size_t certs_processed_second = 0;
        for (auto it = cert_store.begin(); it.valid();
             ++it, ++certs_processed_second) {
            if (certs_processed_second &&
                certs_processed_second % 100000 == 0) {
                log_info("admin",
                         "second iteration: processed %llu certificates",
                         certs_processed_second);
            }
            auto& rec = it->second;
#ifdef VALIDATION_DEBUG
            const auto old_cert = rec.certificate();
#endif
            // Grab a copy of this certificate as an OpenSSL X509
            shared_ptr<X509> c(certificate_to_x509(rec.certificate()),
                               &::X509_free);
            if (c == nullptr) {
                string hex_cert = hex_encode(rec.certificate().raw());
                log_error("admin", "unable to parse certificate: %s",
                          hex_cert.c_str());
                continue;
            }

            // Extrac the subject, issuer, etc.
            auto subject_issuer = x509_get_subject_issuer(c.get());

            // Check to see if we saw this certificate as an intermediate or a
            // root. If it turns out this is a valid intermediate, we can use
            // this back reference to "short circuit" future validations
            auto entry_it = ca_store.by_fingerprint.find(
                    subject_issuer.fingerprint_sha256);
            bool is_root = false;
            std::shared_ptr<cert_data> entry;
            if (entry_it != ca_store.by_fingerprint.end()) {
                entry = entry_it->second;
                is_root = entry->is_root;
            }

            // Assume we don't need to write back
            bool need_write = false;

            // Handle roots, self-signed, and non-roots differently.
            if (is_root) {
                if (!rec.certificate().post_processed() ||
                    !rec.certificate().current_in_nss() ||
                    !rec.certificate().current_valid_nss()) {
                    // Hypothetically, this shouldn't happen because it should
                    // have been caught in the first iteration. However, it
                    // could have been added to the database since then.
                    need_write = true;
                    rec.mutable_certificate()->set_current_in_nss(true);
                    rec.mutable_certificate()->set_was_in_nss(true);
                    rec.mutable_certificate()->set_current_valid_nss(true);
                    rec.mutable_certificate()->set_valid_nss(true);
                    rec.mutable_certificate()->set_was_valid_nss(true);
#ifdef VALIDATION_DEBUG
                    if (need_write) {
                        log_info("admin", "action: rewrote a root cert");
                    }
#endif
                }
            } else if (subject_issuer.self_signed) {
                // Certs that link to self have no valid chain of trust. This
                // check needs to come after the root certificate check.
                // TODO: Confirm this. See earlier todo about self-signed.
                if (!rec.certificate().post_processed() ||
                    (rec.certificate().current_in_nss() != is_root) ||
                    rec.certificate().current_valid_nss()) {
                    need_write = true;
                    rec.mutable_certificate()->set_current_in_nss(is_root);
                    rec.mutable_certificate()->set_current_valid_nss(false);
                    rec.mutable_certificate()->set_valid_nss(false);
                    rec.mutable_certificate()->set_post_processed(true);
                }
            } else if (ca_store.by_subject.count(subject_issuer.issuer)) {
                // In this case, we're a non-root non-self-signed certificate.
                // We need to do actual validation here.

                // First, we'll update the parents on this certificate to be
                // correct.
                auto new_parents = find_parents(subject_issuer, c.get());
                auto current_parents =
                        set<string>(rec.certificate().parents().begin(),
                                    rec.certificate().parents().end());
                if (current_parents != new_parents) {
                    need_write = true;
                    auto mutable_cert = rec.mutable_certificate();
                    mutable_cert->mutable_parents()->Clear();
                    for_each(new_parents.begin(), new_parents.end(),
                             [&](const string& p) {
                                 mutable_cert->add_parents(p);
                             });
                }

                // Now we'll actually try to find some chain back up.
                bool currently_valid = find_valid_chain(subject_issuer, c.get(),
                                                        entry.get(), true);
                bool was_valid = find_valid_chain(subject_issuer, c.get(),
                                                  entry.get(), false);

                // Make sure our validation matches what we got from the
                // database. If they don't match, we need to write back.
                if (currently_valid != rec.certificate().current_valid_nss()) {
                    need_write = true;
                    rec.mutable_certificate()->set_current_valid_nss(
                            currently_valid);
                    rec.mutable_certificate()->set_valid_nss(currently_valid);
                }
                if (was_valid != rec.certificate().was_valid_nss()) {
                    need_write = true;
                    rec.mutable_certificate()->set_was_valid_nss(was_valid);
                }
                if (!rec.certificate().post_processed()) {
                    need_write = true;
                    rec.mutable_certificate()->set_post_processed(true);
                }
#ifdef VALIDATION_DEBUG
                if (need_write) {
                    log_info("admin", "action: rewrote a non-root cert");
                }
#endif
            }

            // If we modified the certificate,  it needs to be written back.
            if (need_write) {
                auto res = cert_store.force_put(rec);
                certificate_prune_handler->handle_pruned(res);
#ifdef VALIDATION_DEBUG
                auto new_cert = res.delta.record().certificate();
                log_info("admin", "sh256fp:");
                string h = hex_encode(old_cert.sha256fp());
                log_info("admin", h.c_str());
                log_info("admin", "====old record:====");
                log_info("admin", "valid_nss:");
                log_info("admin", "%d", old_cert.valid_nss());
                log_info("admin", "parents:");
                for (int i = 0; i < old_cert.parents_size(); ++i) {
                    string k = hex_encode(old_cert.parents(i));
                    log_info("admin", k.c_str());
                }
                log_info("admin", "====new record:====");
                log_info("admin", "valid_nss:");
                log_info("admin", "%d", new_cert.current_valid_nss());
                log_info("admin", "parents:");
                for (int i = 0; i < new_cert.parents_size(); ++i) {
                    string k = hex_encode(new_cert.parents(i));
                    log_info("admin", k.c_str());
                }
#endif
            }
        }
        log_info("admin",
                 "finished second iteration: processed %llu certificates",
                 certs_processed_second);
        // Print out the sha256 fp of all the valid certs in ca_map, then clean
        // up
        log_info("admin",
                 "List of trusted CA certificates (roots and intermediates):");
        for (const auto& c : ca_store.by_fingerprint) {
            if (c.second->is_valid) {
                string hex_fp = hex_encode(c.first);
                log_info("admin", "%s", hex_fp.c_str());
            }
        }
        ca_store.by_subject.clear();
        ca_store.by_fingerprint.clear();
        response->set_status(CommandReply::SUCCESS);
        log_info("admin", "certificate validation succeeded");
        return grpc::Status::OK;
    }

    virtual grpc::Status FixCertificateSource(ServerContext* context,
                                              const Command* request,
                                              CommandReply* response) override {
        log_info("admin", "certificate source fix started");
        if (!cert_store.is_open()) {
            log_error("admin", "certificate store not opened");
            response->set_status(CommandReply::ERROR);
            response->set_error(kErrorMsgUnopened);
            return grpc::Status::OK;
        }
        size_t max_records = request->max_records();
        size_t check_count = 0;
        size_t fix_count = 0;
        for (auto it = cert_store.begin(); it.valid(); ++it, ++check_count) {
            auto& rec = it->second;
            if (max_records && check_count > max_records) {
                break;
            }
            if (check_count && check_count % 100000 == 0) {
                log_info("admin", "checked %llu certificates, fixed %llu",
                         check_count, fix_count);
            }
            if (rec.certificate().source() ==
                zsearch::CERTIFICATE_SOURCE_RESERVED) {
                // Old default value, set to scan.
                rec.mutable_certificate()->set_source(
                        zsearch::CERTIFICATE_SOURCE_SCAN);
                rec.mutable_certificate()->set_seen_in_scan(true);
                // XXX: Ignore deltas
                auto result = cert_store.force_put(rec);
                ++fix_count;
            }
        }
        return grpc::Status::OK;
    }
    std::string make_port_name(int port) {
        uint16_t p = ntohs(static_cast<uint16_t>(port));
        return "p" + std::to_string(p);
    }

    std::string make_ip_str(uint32_t ip) {
        struct in_addr t;
        t.s_addr = ip;
        const char* temp = inet_ntoa(t);
        return std::string(temp);
    }

    virtual grpc::Status DumpIPv4ToJSON(ServerContext* context,
                                        const Command* request,
                                        CommandReply* response) override {
        log_info("admin", "starting dump of ipv4");
        if (!ipv4_store.is_open()) {
            log_error("admin", "ipv4 store not opened");
            response->set_status(CommandReply::ERROR);
            response->set_error(kErrorMsgUnopened);
            return grpc::Status::OK;
        }
        auto status = dump(request, response, ipv4_store, ipv4_prune_handler);
        log_info("admin", "finished dump of ipv4");
        return status;
    }

    virtual grpc::Status DumpDomainToJSON(ServerContext* context,
                                          const Command* request,
                                          CommandReply* response) override {
        log_info("admin", "starting dump of domain");
        if (!domain_store.is_open()) {
            log_error("admin", "domain store not opened");
            response->set_status(CommandReply::ERROR);
            response->set_error(kErrorMsgUnopened);
            return grpc::Status::OK;
        }
        auto status =
                dump(request, response, domain_store, domain_prune_handler);
        log_info("admin", "finished dump of domain");
        return status;
    }

    void DumpCertificateShardToJSON(size_t shard_id,
                                    std::ofstream& out,
                                    std::mutex& out_mtx,
                                    uint32_t max_records,
                                    std::atomic<std::uint32_t>& count) {
        for (auto it = cert_store.seek_start_of_shard(shard_id);
             it.valid() && cert_store.shard_for(it->first) == shard_id; ++it) {
            if (max_records && ++count > max_records) {
                return;
            }
            std::string serialized =
                    dump_certificate_to_json_string(it->second);
            std::lock_guard<std::mutex> guard(out_mtx);
            out << serialized;
        }
    }

    void DumpCertificateThread(std::queue<size_t>& shards,
                               std::mutex& meta_mtx,
                               std::ofstream& out,
                               std::mutex& out_mtx,
                               uint32_t max_records,
                               std::atomic<std::uint32_t>& count) {
        while (true) {
            size_t target_shard;
            {
                std::lock_guard<std::mutex> guard(meta_mtx);
                if (shards.empty()) {
                    return;
                }
                target_shard = shards.front();
                shards.pop();
            }
            DumpCertificateShardToJSON(target_shard, out, out_mtx, max_records,
                                       count);
        }
    }

    virtual grpc::Status DumpCertificatesToJSON(
            ServerContext* context,
            const Command* request,
            CommandReply* response) override {
        log_info("admin", "starting dump process for certificates");
        if (!cert_store.is_open()) {
            log_error("admin", "certificate store not opened");
            response->set_status(CommandReply::ERROR);
            response->set_error(kErrorMsgUnopened);
            return grpc::Status::OK;
        }
        std::ofstream f;
        f.open(request->filepath());
        if (!f) {
            log_error("admin", "could not open dump file for certificates");
            response->set_status(CommandReply::ERROR);
            response->set_error("could not open output file");
            return grpc::Status::OK;
        }
        uint32_t num_threads = 4;
        if (request->threads() != 0) {
            num_threads = request->threads();
        }
        log_debug("admin", "will dump certificates using %u threads",
                  num_threads);
        uint32_t max_records = request->max_records();
        std::atomic<std::uint32_t> count;
        count = 0;
        log_debug("admin", "max certificates to dump: %u", max_records);
        // create thread pool that will process shards in parallel
        std::queue<size_t> shards;
        for (size_t i = 0; i < cert_store.total_shards(); i++) {
            shards.push(i);
        }
        std::mutex meta_mtx;
        std::mutex out_mtx;
        std::vector<std::thread> threads;
        for (uint32_t i = 0; i < num_threads; i++) {
            threads.emplace_back(std::thread(
                    &AdminServiceImpl::DumpCertificateThread, this,
                    std::ref(shards), std::ref(meta_mtx), std::ref(f),
                    std::ref(out_mtx), max_records, std::ref(count)));
        }
        for (auto& t : threads) {
            t.join();
        }
        f.close();
        response->set_status(CommandReply::SUCCESS);
        log_info("admin", "certificate dump succeeded");
        return grpc::Status::OK;
    }

    virtual grpc::Status RegenerateIPv4Deltas(ServerContext* context,
                                              const Command* request,
                                              CommandReply* response) override {
        log_info("admin", "starting delta regeneration for IPv4");
        if (!ipv4_store.is_open()) {
            log_error("admin", "ipv4 store not opened");
            response->set_status(CommandReply::ERROR);
            response->set_error(kErrorMsgUnopened);
            return grpc::Status::OK;
        }
        auto start_str = make_ip_str(request->start_ip());
        auto stop_str = make_ip_str(request->stop_ip());
        log_info("admin", "delta regeneration will start at %s",
                 start_str.c_str());
        log_info("admin", "delta regeneration will stop at %s",
                 stop_str.c_str());
        IPv4Key start{request->start_ip(), 0, 0, 0};
        IPv4Key stop{request->stop_ip(), 0, 0, 0};
        uint64_t count = ipv4_store.regenerate_deltas(
                start, stop, *ipv4_prune_handler.front());
        log_info("admin", "generated %llu deltas", count);
        response->set_status(CommandReply::SUCCESS);
        return grpc::Status::OK;
    }

    virtual grpc::Status RegenerateDomainDeltas(
            ServerContext* context,
            const Command* request,
            CommandReply* response) override {
        log_info("admin", "starting delta regeneration for domain");
        if (!domain_store.is_open()) {
            log_error("admin", "domain store not opened");
            response->set_status(CommandReply::ERROR);
            response->set_error(kErrorMsgUnopened);
            return grpc::Status::OK;
        }
        DomainKey start("", 0, 0, 0);
        DomainKey stop("\x7F", 65535, 255, 255);
        uint64_t count = domain_store.regenerate_deltas(
                start, stop, *domain_prune_handler.front());
        log_info("admin", "generated %llu deltas", count);
        response->set_status(CommandReply::SUCCESS);
        return grpc::Status::OK;
    }

    virtual grpc::Status RegenerateCertificateDeltas(
            ServerContext* context,
            const Command* request,
            CommandReply* response) override {
        log_info("admin", "starting delta regeneration for certificates");
        uint64_t count =
                cert_store.regenerate_deltas(*certificate_prune_handler);
        log_info("admin", "generated %llu deltas", count);
        return grpc::Status::OK;
    }

    virtual grpc::Status RegenerateSingleCertificateDelta(
            ServerContext* context,
            const AnonymousQuery* request,
            CommandReply* response) override {
        std::string hex_fp = hex_encode(request->sha256fp());
        log_info("admin", "delta regeneration for %s", hex_fp.c_str());

        AnonymousResult result;
        bool found = get_certificate_delta(request->sha256fp(), &result);
        if (found) {
            certificate_prune_handler->handle_pruned(result);
            response->set_status(response->SUCCESS);
        } else {
            response->set_status(response->NO_RECORD);
            response->set_error("no matching record");
        }
        return grpc::Status::OK;
    }

    virtual grpc::Status ReprocessCertificates(
            ServerContext* context,
            const Command* request,
            CommandReply* response) override {
        log_info("admin",
                 "starting to queue all certificates for reprocessing");
        uint64_t count = cert_store.regenerate_deltas(
                *certificates_to_process_prune_handler);
        log_info("admin", "generated %llu deltas", count);
        return grpc::Status::OK;
    }

    virtual grpc::Status ReprocessSingleCertificate(
            ServerContext* context,
            const AnonymousQuery* request,
            CommandReply* response) override {
        std::string hex_fp = hex_encode(request->sha256fp());
        log_info("admin", "delta regeneration for %s", hex_fp.c_str());

        AnonymousResult result;
        bool found = get_certificate_delta(request->sha256fp(), &result);
        if (found) {
            certificates_to_process_prune_handler->handle_pruned(result);
            response->set_status(response->SUCCESS);
        } else {
            response->set_status(response->NO_RECORD);
            response->set_error("no matching record");
        }
        return grpc::Status::OK;
    }

    virtual grpc::Status Ping(ServerContext* context,
                              const Command* request,
                              CommandReply* response) override {
        return grpc::Status::OK;
    }
};

std::unique_ptr<zdb::AdminServer> zdb::make_admin_server(
        uint16_t port,
        StoreContext* store_ctx,
        KafkaContext* kafka_ctx) {
    std::string listen =
            std::string("0.0.0.0") + std::string(":") + std::to_string(port);
    std::string server_address(listen);
    grpc::ServerBuilder builder;

    Store<IPv4Key> ipv4 = store_ctx->make_ipv4_store(0);
    Store<DomainKey> domain = store_ctx->make_domain_store(0);
    AnonymousStore<HashKey> certificate = store_ctx->make_certificate_store(0);

    shared_ptr<PruneHandler> certificate_prune_handler;
    {
        auto raw_ptr =
                new KafkaTopicPruneHandler(kafka_ctx->certificate_deltas());
        certificate_prune_handler.reset(raw_ptr);
    }

    shared_ptr<PruneHandler> certificates_to_process_prune_handler;
    {
        auto raw_ptr = new KafkaTopicPruneHandler(
                kafka_ctx->certificates_to_process());
        certificates_to_process_prune_handler.reset(raw_ptr);
    }

    vector<shared_ptr<PruneHandler>> ipv4_prune_handler(12, nullptr);
    vector<shared_ptr<PruneHandler>> domain_prune_handler(12, nullptr);

    std::for_each(ipv4_prune_handler.begin(), ipv4_prune_handler.end(),
                  [&](shared_ptr<PruneHandler>& p) {
                      auto kafka_handler = make_shared<KafkaTopicPruneHandler>(
                              kafka_ctx->ipv4_deltas());
                      auto group_handler = new GroupingPruneHandler();
                      group_handler->set_underlying_handler(kafka_handler);
                      p.reset(group_handler);
                  });

    std::for_each(domain_prune_handler.begin(), domain_prune_handler.end(),
                  [&](shared_ptr<PruneHandler>& p) {
                      auto kafka_handler = make_shared<KafkaTopicPruneHandler>(
                              kafka_ctx->domain_deltas());
                      auto group_handler = new GroupingPruneHandler(
                              GroupingPruneHandler::GROUP_DOMAIN);
                      group_handler->set_underlying_handler(kafka_handler);
                      p.reset(group_handler);
                  });

    unique_ptr<AdminServiceImpl> service(new AdminServiceImpl(
            std::move(ipv4), std::move(domain), std::move(certificate),
            std::move(ipv4_prune_handler), domain_prune_handler,
            certificate_prune_handler, certificates_to_process_prune_handler,
            store_ctx->as_tree()));

    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    builder.RegisterService(service.get());
    std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
    std::unique_ptr<AdminServer> ret(new AdminServer);
    ret->impl = std::move(service);
    ret->server = std::move(server);
    return ret;
}
