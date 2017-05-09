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

#include "query.h"

#include <cstdint>

#include <grpc/grpc.h>
#include <grpc++/server.h>
#include <grpc++/server_builder.h>
#include <grpc++/server_context.h>

#include <zmap/logger.h>

#include "zsearch_definitions/search.grpc.pb.h"

#include "anonymous_store.h"
#include "configuration.h"
#include "inbound.h"
#include "record.h"
#include "store.h"
#include "utility.h"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;

using namespace zdb;
using namespace zsearch;

namespace {

const std::string kErrorMsgUnopened = "unopened store";

}  // namespace

class QueryServiceImpl final : public zsearch::QueryService::Service {
  private:
    Store<IPv4Key> ipv4_store;
    Store<DomainKey> domain_store;
    AnonymousStore<HashKey> cert_store;

  public:
    QueryServiceImpl(Store<IPv4Key>&& ipv4,
                     Store<DomainKey>&& domain,
                     AnonymousStore<HashKey>&& cert)
            : zsearch::QueryService::Service(),
              ipv4_store(std::move(ipv4)),
              domain_store(std::move(domain)),
              cert_store(std::move(cert)) {}

    virtual grpc::Status GetHostIPv4Record(
            grpc::ServerContext* context,
            const zsearch::HostQuery* request,
            zsearch::HostQueryResponse* response) override {
        if (!ipv4_store.is_open()) {
            log_error("admin", "ipv4 store not opened");
            response->set_status(HostQueryResponse::ERROR);
            return grpc::Status::OK;
        }
        IPv4Key k((uint32_t) request->ip(), (uint16_t) request->port(),
                  (uint16_t) request->protocol(),
                  (uint16_t) request->subprotocol());
        response->set_ip(request->ip());
        response->set_port(request->port());
        response->set_protocol(request->protocol());
        response->set_subprotocol(request->subprotocol());
        try {
            Record r = ipv4_store.get(k);
            response->set_status(response->SUCCESS);
            response->mutable_record()->MergeFrom(r);
        } catch (std::out_of_range e) {
            response->set_status(response->NO_RECORD);
        } catch (std::runtime_error e) {
            response->set_status(response->ERROR);
            response->set_error(e.what());
        }
        return grpc::Status::OK;
    }

    virtual grpc::Status DelHostIPv4Record(grpc::ServerContext* context,
                                           const zsearch::HostQuery* request,
                                           zsearch::Delta* response) override {
        if (!ipv4_store.is_open()) {
            log_error("admin", "ipv4 store not opened");
            return grpc::Status(grpc::UNAVAILABLE, "ipv4 store not opened");
        }
        IPv4Key k((uint32_t) request->ip(), (uint16_t) request->port(),
                  (uint16_t) request->protocol(),
                  (uint16_t) request->subprotocol());
        StoreResult sr = ipv4_store.del(k);
        response->MergeFrom(sr.delta);
        return grpc::Status::OK;
    }

    virtual grpc::Status PutHostIPv4Record(grpc::ServerContext* context,
                                           const zsearch::Record* request,
                                           zsearch::Delta* response) override {
        if (!ipv4_store.is_open()) {
            log_error("admin", "ipv4 store not opened");
            return grpc::Status(grpc::UNAVAILABLE, "ipv4 store not opened");
        }
        StoreResult sr = ipv4_store.put(*request);
        response->MergeFrom(sr.delta);
        return grpc::Status::OK;
    }

    virtual grpc::Status GetAllIPv4Records(
            grpc::ServerContext* context,
            const zsearch::HostQuery* request,
            zsearch::HostQueryResponse* response) override {
        if (!ipv4_store.is_open()) {
            log_error("admin", "ipv4 store not opened");
            response->set_status(HostQueryResponse::ERROR);
            return grpc::Status::OK;
        }
        response->set_status(response->SUCCESS);
        for (auto rec : ipv4_store) {
            response->add_records()->CopyFrom(rec.second);
        }
        return grpc::Status::OK;
    }

    virtual grpc::Status GetHostIPv4Delta(grpc::ServerContext* context,
                                          const zsearch::HostQuery* request,
                                          zsearch::Delta* response) override {
        if (!ipv4_store.is_open()) {
            log_error("admin", "ipv4 store not opened");
            return grpc::Status(grpc::UNAVAILABLE, "ipv4 store not opened");
        }
        IPv4Key k;
        k.ip = request->ip();
        StoreResult ret = ipv4_store.host_delta(k);
        response->Swap(&ret.delta);
        return grpc::Status::OK;
    }

    virtual grpc::Status GetHostDomainRecord(
            grpc::ServerContext* context,
            const zsearch::HostQuery* request,
            zsearch::HostQueryResponse* response) override {
        if (!domain_store.is_open()) {
            log_error("admin", "domain store not opened");
            response->set_status(HostQueryResponse::ERROR);
            return grpc::Status::OK;
        }
        DomainKey k(request->domain(), (uint16_t) request->port(),
                    (uint16_t) request->protocol(),
                    (uint16_t) request->subprotocol());
        response->set_domain(request->domain());
        response->set_port(request->port());
        response->set_protocol(request->protocol());
        response->set_subprotocol(request->subprotocol());
        try {
            Record r = domain_store.get(k);
            response->set_status(response->SUCCESS);
            response->mutable_record()->MergeFrom(r);
        } catch (std::out_of_range e) {
            response->set_status(response->NO_RECORD);
        } catch (std::runtime_error e) {
            response->set_status(response->ERROR);
            response->set_error(e.what());
        }
        return grpc::Status::OK;
    }

    virtual grpc::Status DelHostDomainRecord(
            grpc::ServerContext* context,
            const zsearch::HostQuery* request,
            zsearch::Delta* response) override {
        if (!domain_store.is_open()) {
            log_error("admin", "domain store not opened");
            return grpc::Status(grpc::UNAVAILABLE, "domain store not opened");
        }
        DomainKey k(request->domain(), (uint16_t) request->port(),
                    (uint16_t) request->protocol(),
                    (uint16_t) request->subprotocol());
        StoreResult sr = domain_store.del(k);
        response->MergeFrom(sr.delta);
        return grpc::Status::OK;
    }

    virtual grpc::Status PutHostDomainRecord(
            grpc::ServerContext* context,
            const zsearch::Record* request,
            zsearch::Delta* response) override {
        if (!domain_store.is_open()) {
            log_error("admin", "domain store not opened");
            return grpc::Status(grpc::UNAVAILABLE, "domain store not opened");
        }
        StoreResult sr = domain_store.put(*request);
        response->MergeFrom(sr.delta);
        return grpc::Status::OK;
    }

    virtual grpc::Status GetAllDomainRecords(
            grpc::ServerContext* context,
            const zsearch::HostQuery* request,
            zsearch::HostQueryResponse* response) override {
        if (!domain_store.is_open()) {
            log_error("admin", "domain store not opened");
            response->set_status(HostQueryResponse::ERROR);
            response->set_error(kErrorMsgUnopened);
            return grpc::Status::OK;
        }
        uint32_t max_records = request->max_records();
        log_debug("admin", "dumping all (max %u) domain records", max_records);
        uint32_t count = 0;
        for (auto rec : domain_store) {
            response->add_records()->CopyFrom(rec.second);
            if (max_records && count++ > max_records) {
                break;
            }
        }
        log_debug("admin", "domain dump finished");
        response->set_status(response->SUCCESS);
        return grpc::Status::OK;
    }

    virtual grpc::Status GetHostDomainDelta(grpc::ServerContext* context,
                                            const zsearch::HostQuery* request,
                                            zsearch::Delta* response) override {
        if (!domain_store.is_open()) {
            log_error("admin", "domain store not opened");
            return grpc::Status(grpc::UNAVAILABLE, "domain store not opened");
        }
        DomainKey k;
        k.domain = request->domain();
        StoreResult ret = domain_store.host_delta(k);
        response->Swap(&ret.delta);
        return grpc::Status::OK;
    }

    grpc::Status GetFromHashKeyAnonStore(AnonymousStore<HashKey>& s,
                                         ServerContext* context,
                                         const AnonymousQuery* request,
                                         AnonymousQueryResponse* response) {
        // create HashKey object in order to do a search
        HashKey hk;
        hk.hash = request->sha256fp();

        response->set_sha256fp(request->sha256fp());
        try {
            AnonymousRecord ar = s.get(hk);
            response->set_status(response->SUCCESS);
            response->mutable_record()->MergeFrom(ar);
        } catch (std::out_of_range e) {
            response->set_status(response->NO_RECORD);
        } catch (std::runtime_error e) {
            response->set_status(response->ERROR);
            response->set_error(e.what());
        }
        return grpc::Status::OK;
    }

    virtual ::grpc::Status GetCertificate(
            ::grpc::ServerContext* context,
            const ::zsearch::AnonymousQuery* request,
            ::zsearch::AnonymousQueryResponse* response) override {
        if (!cert_store.is_open()) {
            log_error("admin", "certificate store not opened");
            response->set_status(AnonymousQueryResponse::ERROR);
            response->set_error(kErrorMsgUnopened);
            return grpc::Status::OK;
        }
        return GetFromHashKeyAnonStore(cert_store, context, request, response);
    }

    virtual ::grpc::Status UpsertCertificate(
            ::grpc::ServerContext* context,
            const ::zsearch::AnonymousRecord* request,
            ::zsearch::AnonymousDelta* response) override {
        if (!cert_store.is_open()) {
            log_error("admin", "certificate store not opened");
            return grpc::Status(grpc::UNAVAILABLE,
                                "certificate store not opened");
        }
        AnonymousRecord anonrec;
        anonrec.CopyFrom(*request);
        AnonymousResult sr = cert_store.put(anonrec);
        response->MergeFrom(sr.delta);
        return grpc::Status::OK;
    }

    virtual ::grpc::Status UpsertRawCertificate(
            ::grpc::ServerContext* context,
            const ::zsearch::AnonymousRecord* request,
            ::zsearch::AnonymousDelta* response) override {
        if (!cert_store.is_open()) {
            log_error("admin", "certificate store not opened");
            return grpc::Status(grpc::UNAVAILABLE,
                                "certificate store not opened");
        }
        AnonymousResult sr = cert_store.force_put(*request);
        response->MergeFrom(sr.delta);
        return grpc::Status::OK;
    }

    virtual grpc::Status GetCryptographicKey(
            grpc::ServerContext* context,
            const zsearch::AnonymousQuery* request,
            zsearch::AnonymousQueryResponse* response) override {
        response->set_error("unimplemented");
        return grpc::Status::OK;
    }
};

std::unique_ptr<QueryServer> zdb::make_query_server(uint16_t port,
                                                    StoreContext* store_ctx) {
    std::string listen =
            std::string("0.0.0.0") + std::string(":") + std::to_string(port);
    std::string server_address(listen);
    grpc::ServerBuilder builder;

    Store<IPv4Key> ipv4 = store_ctx->make_ipv4_store(1);
    Store<DomainKey> domain = store_ctx->make_domain_store(1);
    AnonymousStore<HashKey> certificate = store_ctx->make_certificate_store(1);

    std::unique_ptr<QueryServiceImpl> service(new QueryServiceImpl(
            std::move(ipv4), std::move(domain), std::move(certificate)));

    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    builder.RegisterService(service.get());
    std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
    std::unique_ptr<QueryServer> ret(new QueryServer);
    ret->impl = std::move(service);
    ret->server = std::move(server);
    return ret;
}
