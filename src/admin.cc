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
#include <cstdio>
#include <fstream>
#include <iostream>
#include <list>
#include <map>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <arpa/inet.h>

#include <base64/base64.h>

#include <grpc++/security/server_credentials.h>
#include <grpc++/server.h>
#include <grpc++/server_builder.h>
#include <grpc++/server_context.h>
#include <grpc/grpc.h>

#include <json/json.h>

#include <zmap/logger.h>

#include "anonymous_store.h"
#include "as_data.h"
#include "certificates.h"
#include "configuration.h"
#include "delta_handler.h"
#include "grouping_delta_handler.h"
#include "inbound.h"
#include "kafka_topic_delta_handler.h"
#include "protocol_names.h"
#include "record.h"
#include "search.grpc.pb.h"
#include "store.h"
#include "util/strings.h"
#include "utility.h"
#include "zdb.h"
#include "zmap/logger.h"

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

    DeltaContext* m_delta_ctx;

    ASTree* m_as_tree;

    template <typename store_type>
    grpc::Status dump(
            const Command* request,
            CommandReply* response,
            store_type& store,
            std::vector<std::unique_ptr<DeltaHandler>> prune_handlers) {
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
                     DeltaContext* delta_ctx,
                     ASTree* as_tree)
            : zsearch::AdminService::Service(),
              ipv4_store(std::move(ipv4)),
              domain_store(std::move(domain)),
              cert_store(std::move(cert)),
              m_delta_ctx(delta_ctx),
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
        log_error("admin", "received deprecated PruneIPv4 call");
        return grpc::Status(grpc::StatusCode::UNIMPLEMENTED,
                            "deprecated, use DumpIPv4ToJSON instead");
    }

    virtual grpc::Status PruneDomain(ServerContext* context,
                                     const Command* request,
                                     CommandReply* response) override {
        log_error("admin", "received deprecated PruneDomain call");
        return grpc::Status(grpc::StatusCode::UNIMPLEMENTED,
                            "deprecated, use DumpDomainToJSON instead");
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

        std::unique_ptr<DeltaHandler> ipv4_prune_handler =
                m_delta_ctx->new_ipv4_delta_handler();
        if (ipv4_store.update_locations(start, stop, *ipv4_prune_handler) !=
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

    virtual grpc::Status ValidateCertificates(ServerContext* context,
                                              const Command* request,
                                              CommandReply* response) override {
        log_error("admin", "deprecated call to ValidateCertificates");
        return grpc::Status(grpc::StatusCode::UNIMPLEMENTED, "deprecated");
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
        std::vector<std::unique_ptr<DeltaHandler>> ipv4_delta_handlers;
        for (size_t i = 0; i < 12; ++i) {
            ipv4_delta_handlers.push_back(
                    m_delta_ctx->new_ipv4_delta_handler());
        }
        auto status = dump(request, response, ipv4_store,
                           std::move(ipv4_delta_handlers));
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
        std::vector<std::unique_ptr<DeltaHandler>> domain_delta_handlers;
        for (size_t i = 0; i < 12; ++i) {
            domain_delta_handlers.push_back(
                    m_delta_ctx->new_domain_delta_handler());
        }
        auto status = dump(request, response, domain_store,
                           std::move(domain_delta_handlers));
        log_info("admin", "finished dump of domain");
        return status;
    }

    void DumpCertificateShardToJSON(size_t shard_id,
                                    const HashKey& start,
                                    bool has_stop,
                                    const HashKey& stop,
                                    std::ofstream& out,
                                    std::mutex& out_mtx,
                                    uint32_t max_records,
                                    std::atomic<std::uint32_t>& count) {
        std::unique_ptr<DeltaHandler> delta_handler =
                m_delta_ctx->new_certificate_delta_handler();
        std::unique_ptr<DeltaHandler> to_process_handler =
                m_delta_ctx->new_certificates_to_process_delta_handler();
        std::time_t now = std::time(nullptr);

        const Sharder<HashKey>& sharder = cert_store.sharder();
        size_t start_shard = sharder.shard_for(start);
        size_t stop_shard =
                has_stop ? sharder.shard_for(stop) : sharder.total_shards() - 1;
        std::function<bool(const HashKey&)> continue_iterating = nullptr;
        if (shard_id == stop_shard && has_stop) {
            continue_iterating = [&](const HashKey& k) { return k < stop; };
        } else {
            continue_iterating = [&](const HashKey& k) {
                return sharder.shard_for(k) == shard_id;
            };
        }

        AnonymousStore<HashKey>::iterator it;
        if (shard_id == start_shard) {
            it = cert_store.upper_bound(start);
        } else {
            it = cert_store.seek_start_of_shard(shard_id);
        }

        for (; it.valid() && continue_iterating(it->first); ++it) {
            if (max_records && ++count > max_records) {
                return;
            }
            // Only update expiration if `not_valid_before` and
            // `not_valid_after` are actually set.
            if (it->second.certificate().not_valid_before() &&
                it->second.certificate().not_valid_after()) {
                bool expired =
                        !certificate_valid_at(it->second.certificate(), now);
                // Only write back if the value of expired changed.
                if (expired != it->second.certificate().expired()) {
                    it->second.mutable_certificate()->set_expired(expired);
                    DeltaHandler* out = nullptr;
                    if (expired) {
                        // Common case: certificate is now expired. Update
                        // the root store status, and send the certificate
                        // to the delta queue.
                        expire_status(it->second.mutable_certificate()
                                              ->mutable_validation()
                                              ->mutable_nss());
                        expire_status(it->second.mutable_certificate()
                                              ->mutable_validation()
                                              ->mutable_microsoft());
                        expire_status(it->second.mutable_certificate()
                                              ->mutable_validation()
                                              ->mutable_apple());
                        expire_status(it->second.mutable_certificate()
                                              ->mutable_validation()
                                              ->mutable_google_ct_primary());
                        out = delta_handler.get();
                    } else {
                        // Uncommon case: certificate is no longer expired.
                        // Send it back to the certificate daemon.
                        out = to_process_handler.get();
                    }
                    AnonymousResult res = cert_store.force_put(it->second);
                    assert(out);
                    out->handle_delta(res);
                }
            }
            std::string serialized =
                    dump_certificate_to_json_string(it->second);
            std::lock_guard<std::mutex> guard(out_mtx);
            out << serialized;
        }
    }

    void DumpCertificateThread(Channel<size_t>* shards_to_process,
                               const HashKey& start,
                               bool has_stop,
                               const HashKey& stop,
                               std::ofstream& out,
                               std::mutex& out_mtx,
                               uint32_t max_records,
                               std::atomic<uint32_t>& count) {
        for (auto it = shards_to_process->range(); it.valid(); ++it) {
            size_t shard_id = *it;
            DumpCertificateShardToJSON(shard_id, start, has_stop, stop, out,
                                       out_mtx, max_records, count);
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
        uint32_t num_threads = 24;
        if (request->threads() != 0) {
            num_threads = request->threads();
        }
        log_debug("admin", "will dump certificates using %u threads",
                  num_threads);
        uint32_t max_records = request->max_records();
        uint32_t start_prefix = request->start_ip();
        uint32_t end_prefix = request->stop_ip();
        bool has_stop = end_prefix > 0;

        if (has_stop && end_prefix < start_prefix) {
            log_error("admin", "end_prefix (%u) < start_prefix (%u)",
                      end_prefix, start_prefix);
            return grpc::Status::OK;
        }
        HashKey start =
                HashKey::zero_pad_prefix(start_prefix, HashKey::SHA256_LEN);
        HashKey stop =
                HashKey::zero_pad_prefix(end_prefix, HashKey::SHA256_LEN);
        std::string start_hex = util::Strings::hex_encode(start.hash);
        log_info("admin", "start: %s", start_hex.c_str());
        if (has_stop) {
            std::string stop_hex = util::Strings::hex_encode(stop.hash);
            log_info("admin", "stop: %s", stop_hex.c_str());
        }

        Channel<size_t> shards_to_process;

        std::atomic<uint32_t> count(0);
        log_debug("admin", "max certificates to dump: %u", max_records);

        std::mutex out_mtx;
        std::vector<std::thread> threads;
        for (uint32_t i = 0; i < num_threads; i++) {
            threads.emplace_back(std::thread(
                    &AdminServiceImpl::DumpCertificateThread, this,
                    &shards_to_process, start, has_stop, stop, std::ref(f),
                    std::ref(out_mtx), max_records, std::ref(count)));
        }

        size_t start_shard = cert_store.sharder().shard_for(start);
        size_t stop_shard = cert_store.sharder().total_shards() - 1;
        if (has_stop) {
          stop_shard = cert_store.sharder().shard_for(stop);
        }
        for (size_t shard_id = start_shard; shard_id <= stop_shard; ++shard_id) {
          size_t to_send = shard_id;
          shards_to_process.send(std::move(to_send));
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
        std::unique_ptr<DeltaHandler> ipv4_delta_handler =
                m_delta_ctx->new_ipv4_delta_handler();
        uint64_t count =
                ipv4_store.regenerate_deltas(start, stop, *ipv4_delta_handler);
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
        std::unique_ptr<DeltaHandler> domain_delta_handler =
                m_delta_ctx->new_domain_delta_handler();
        uint64_t count = domain_store.regenerate_deltas(start, stop,
                                                        *domain_delta_handler);
        log_info("admin", "generated %llu deltas", count);
        response->set_status(CommandReply::SUCCESS);
        return grpc::Status::OK;
    }

    virtual grpc::Status RegenerateCertificateDeltas(
            ServerContext* context,
            const Command* request,
            CommandReply* response) override {
        log_info("admin", "starting delta regeneration for certificates");
        size_t max_records = request->max_records();
        if (max_records) {
            log_info("admin", "will only regenerate max %llu certificates",
                     max_records);
        }
        std::unique_ptr<DeltaHandler> cert_delta_handler =
                m_delta_ctx->new_certificate_delta_handler();
        uint64_t count =
                cert_store.regenerate_deltas(*cert_delta_handler, max_records);
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
            std::unique_ptr<DeltaHandler> cert_delta_handler =
                    m_delta_ctx->new_certificate_delta_handler();
            cert_delta_handler->handle_delta(result);
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
        size_t max_records = request->max_records();
        if (max_records) {
            log_info("admin", "will only reprocess max %llu certificates",
                     max_records);
        }
        std::unique_ptr<DeltaHandler> to_process_handler =
                m_delta_ctx->new_certificates_to_process_delta_handler();
        uint64_t count =
                cert_store.regenerate_deltas(*to_process_handler, max_records);
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
            std::unique_ptr<DeltaHandler> to_process_handler =
                    m_delta_ctx->new_certificates_to_process_delta_handler();
            to_process_handler->handle_delta(result);
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
        DeltaContext* delta_ctx) {
    std::string listen =
            std::string("0.0.0.0") + std::string(":") + std::to_string(port);
    std::string server_address(listen);
    grpc::ServerBuilder builder;

    Store<IPv4Key> ipv4 = store_ctx->make_ipv4_store(0);
    Store<DomainKey> domain = store_ctx->make_domain_store(0);
    AnonymousStore<HashKey> certificate = store_ctx->make_certificate_store(0);

    unique_ptr<AdminServiceImpl> service(new AdminServiceImpl(
            std::move(ipv4), std::move(domain), std::move(certificate),
            delta_ctx, store_ctx->as_tree()));

    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    builder.RegisterService(service.get());
    std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
    std::unique_ptr<AdminServer> ret(new AdminServer);
    ret->impl = std::move(service);
    ret->server = std::move(server);
    return ret;
}
