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

#include "context.h"

#include <algorithm>
#include <iomanip>
#include <memory>
#include <sstream>
#include <string>

#include <rocksdb/db.h>

#include <zmap/logger.h>

#include "delta_handler.h"
#include "grouping_delta_handler.h"
#include "kafka_topic_delta_handler.h"
#include "rocks_util.h"
#include "util/file.h"

namespace zdb {

namespace {

rocksdb::DB* open_rocks(const rocksdb::Options& opt, const std::string& path) {
    rocksdb::DB* db;
    auto status = rocksdb::DB::Open(opt, path, &db);
    if (!status.ok()) {
        log_error("rocksdb", "could not open %s", path.c_str());
        std::string error_message = status.ToString();
        log_error("rocksdb", "%s", error_message.c_str());
        return nullptr;
    }
    return db;
}

std::unique_ptr<KafkaConsumerConnection> connect_inbound(
        const std::string& brokers,
        const std::string& topic) {
    std::string client_id = topic + "_consumer";
    std::unique_ptr<KafkaConsumerConnection> consumer(
            new KafkaConsumerConnection);

    consumer->connect(brokers, topic, client_id);
    return consumer;
}

std::unique_ptr<KafkaProducerConnection> connect_outbound(
        const std::string& brokers,
        const std::string& topic) {
    std::string client_id = topic + "_outbound";
    std::unique_ptr<KafkaProducerConnection> producer(
            new KafkaProducerConnection);

    producer->connect(brokers, topic, client_id);
    return producer;
}

std::unique_ptr<KafkaConsumerConnection> connect_inbound_if(
        bool enabled,
        const std::string& brokers,
        const std::string& topic) {
    if (enabled) {
        return connect_inbound(brokers, topic);
    }
    return nullptr;
}

std::unique_ptr<KafkaProducerConnection> connect_outbound_if(
        bool enabled,
        const std::string& brokers,
        const std::string& topic) {
    if (enabled) {
        return connect_outbound(brokers, topic);
    }
    return nullptr;
}

}  // namespace

LocationContext::LocationContext(const std::string& public_path,
                                 const std::string& restricted_path) {
    m_public.open(public_path);
    m_restricted.open(restricted_path);
}

bool LocationContext::is_open() const {
    return m_public.is_open() && m_restricted.is_open();
}

RocksContext::RocksContext(const std::string& path)
        : m_path(path), m_env(nullptr) {}

RocksSingleContext::RocksSingleContext(const std::string& path)
        : RocksContext(path) {}

bool RocksSingleContext::open() {
    if (is_open()) {
        return true;
    }
    if (shared_options() == nullptr) {
        log_error("rocks_context", "cannot open rocksdb with null options");
        return false;
    }
    m_db.reset(open_rocks(*shared_options(), path()));
    if (m_db == nullptr) {
        return false;
    }
    return true;
}

bool RocksSingleContext::repair() {
    if (is_open()) {
        return true;
    }
    rocksdb::Status repair_status =
            rocksdb::RepairDB(path(), *shared_options());
    if (!repair_status.ok()) {
        std::string err_string = repair_status.ToString();
        log_error("rocksdb", "could not repair %s: %s", path().c_str(),
                  err_string.c_str());
        return false;
    } else {
        log_info("rocksdb", "repaired %s", path().c_str());
    }
    return true;
}

bool RocksSingleContext::compact() {
    if (!m_db) {
        log_error("rocksdb", "database is not open");
    }
    rocksdb::Status compact_status = m_db->CompactRange(nullptr, nullptr);
    if (!compact_status.ok()) {
        std::string err_string = compact_status.ToString();
        log_fatal("rocksdb", "could not compact %s: %s", path().c_str(),
                  err_string.c_str());
    } else {
        log_info("rocksdb", "compacted %s", path().c_str());
    }
    return false;
}

RocksShardedContext::RocksShardedContext(const std::string& base_path,
                                         size_t num_shards)
        : RocksContext(base_path) {
    m_shards.resize(num_shards);
    for (size_t i = 0; i < m_shards.size(); ++i) {
        // Build the path to this shard. Make sure the shard number is encoded
        // as a three digit decimal number.
        std::stringstream ss;
        ss << std::hex;
        ss << path() << "/" << std::setfill('0')
           << std::setw(2 * sizeof(size_t)) << i;
        std::string shard_path = ss.str();

        // Build the RocksContext
        m_shards[i] = std::unique_ptr<RocksSingleContext>(
                new RocksSingleContext(shard_path));
        m_shards[i]->set_options(m_opt);
    }
}

void RocksShardedContext::set_options(std::shared_ptr<rocksdb::Options> opt) {
    std::for_each(m_shards.begin(), m_shards.end(),
                  [&opt](std::unique_ptr<RocksSingleContext>& rctx) {
                      rctx->set_options(opt);
                  });
    RocksContext::set_options(std::move(opt));
}

bool RocksShardedContext::open() {
    if (is_open()) {
        return true;
    }
    util::Directory::mkdir(path());
    bool failed = false;
    for (size_t i = 0; i < m_shards.size(); ++i) {
        // Open each shard
        if (!m_shards[i]->open()) {
            failed = true;
        }
    }
    m_is_open = !failed;
    return m_is_open;
}

bool RocksShardedContext::repair() {
    for (size_t i = 0; i < m_shards.size(); ++i) {
        assert(m_shards[i]);
        if (!m_shards[i]->repair()) {
            log_error("rocksdb", "could not repair %s", m_shards[i]->path().c_str());
            return false;
        }
    }
    return true;
}

bool RocksShardedContext::compact() {
    for (size_t i = 0; i < m_shards.size(); ++i) {
        if (!m_shards[i]->compact()) {
            return false;
        }
    }
    return true;
}

std::vector<rocksdb::DB*> RocksShardedContext::raw_db_ptr() {
    std::vector<rocksdb::DB*> out;
    if (!m_is_open) {
        return out;
    }
    out.resize(m_shards.size());
    for (size_t i = 0; i < m_shards.size(); ++i) {
        out[i] = m_shards[i]->raw_db_ptr();
    }
    return out;
}

void RocksShardedContext::close() {
    size_t count = m_shards.size();
    m_shards.clear();
    m_shards.resize(count);
    m_is_open = false;
}

DBContext::DBContext(std::unique_ptr<RocksShardedContext> ipv4_rctx,
                     std::unique_ptr<RocksSingleContext> domain_rctx,
                     std::unique_ptr<RocksShardedContext> certificate_rctx)
        : m_ipv4_rctx(std::move(ipv4_rctx)),
          m_domain_rctx(std::move(domain_rctx)),
          m_certificate_rctx(std::move(certificate_rctx)) {
}

bool DBContext::open_all() {
    if (m_ipv4_rctx && !m_ipv4_rctx->open()) {
        log_error("context", "could not open ipv4 rocksdb");
        return false;
    }
    if (m_domain_rctx && !m_domain_rctx->open()) {
        log_error("context", "could not open domain rocksdb");
        return false;
    }
    if (m_certificate_rctx && !m_certificate_rctx->open()) {
        log_error("context", "could not open certificate rocksdb");
        return false;
    }
    m_ipv4 = db_from_context<IPv4Key, ProtobufRecord<zsearch::Record>>(
            m_ipv4_rctx.get());
    m_domain = db_from_context<DomainKey, ProtobufRecord<zsearch::Record>>(
            m_domain_rctx.get());
    m_certificate =
            db_from_context<HashKey, ProtobufRecord<zsearch::AnonymousRecord>>(
                    m_certificate_rctx.get());
    return true;
}

bool DBContext::repair() {
    if (m_ipv4_rctx && !m_ipv4_rctx->is_open()) {
        log_info("context", "repairing ipv4");
        if (!m_ipv4_rctx->repair()) {
            return false;
        }
    }
    if (m_domain_rctx && !m_domain_rctx->is_open()) {
        log_info("context", "repairing domain");
        if (!m_domain_rctx->repair()) {
            return false;
        }
    }
    if (m_certificate_rctx && !m_certificate_rctx->is_open()) {
        log_info("context", "repairing certificate");
        if (!m_certificate_rctx->repair()) {
            return false;
        }
    }
    return true;
}

LockContext::LockContext(size_t ipv4_threads,
                         size_t domain_threads,
                         size_t certificate_threads)
        : ipv4(ipv4_threads, IPv4Key::reserved().lock_on()),
          domain(domain_threads, DomainKey::reserved().lock_on()),
          certificate(certificate_threads, HashKey::reserved().lock_on()) {}

StoreContext::StoreContext(std::unique_ptr<DBContext> db_ctx,
                           std::unique_ptr<LockContext> lock_ctx,
                           std::unique_ptr<LocationContext> location_ctx,
                           std::unique_ptr<ASTree> as_tree)
        : m_db_ctx(std::move(db_ctx)),
          m_lock_ctx(std::move(lock_ctx)),
          m_location_ctx(std::move(location_ctx)),
          m_as_tree(std::move(as_tree)) {}

Store<IPv4Key> StoreContext::make_ipv4_store(size_t tid) {
    auto lock = m_lock_ctx->ipv4.make_lock(tid);
    return Store<IPv4Key>(m_db_ctx->ipv4(), std::move(lock),
                          m_as_tree->get_handle(),
                          m_location_ctx->public_location(),
                          m_location_ctx->restricted_location());
}

Store<DomainKey> StoreContext::make_domain_store(size_t tid) {
    auto lock = m_lock_ctx->domain.make_lock(tid);
    return Store<DomainKey>(m_db_ctx->domain(), std::move(lock),
                            m_as_tree->get_handle(),
                            m_location_ctx->public_location(),
                            m_location_ctx->restricted_location());
}

AnonymousStore<HashKey> StoreContext::make_certificate_store(size_t tid) {
    auto lock = m_lock_ctx->certificate.make_lock(tid);
    return AnonymousStore<HashKey>(m_db_ctx->certificate(), std::move(lock));
}

KafkaContext::KafkaContext(const std::string& brokers) : m_brokers(brokers) {}

void KafkaContext::connect_enabled(const EnableMap& enabled) {
    m_ipv4 = connect_inbound_if(enabled.ipv4, m_brokers, kIPv4InboundName);
    m_domain =
            connect_inbound_if(enabled.domain, m_brokers, kDomainInboundName);
    m_certificate = connect_inbound_if(enabled.certificate, m_brokers,
                                       kCertificateInboundName);
    m_external_cert = connect_inbound_if(enabled.external_cert, m_brokers,
                                         kExternalCertificateInboundName);
    m_sct = connect_inbound_if(enabled.sct, m_brokers, kSCTInboundName);
    m_processed_cert = connect_inbound_if(enabled.processed_cert, m_brokers,
                                          kProcessedCertificateInboundName);

    m_ipv4_deltas = connect_outbound_if(!!m_ipv4, m_brokers, kIPv4OutboundName);
    m_domain_deltas =
            connect_outbound_if(!!m_domain, m_brokers, kDomainOutboundName);
    m_certificates_to_process =
            connect_outbound_if(!!m_certificate || !!m_external_cert, m_brokers,
                                kCertificateOutboundName);
    m_certificate_deltas =
            connect_outbound_if(!!m_certificate || !!m_external_cert ||
                                        !!m_sct || !!m_processed_cert,
                                m_brokers, kProcessedCertificateOutboundName);
}

DeltaContext::DeltaContext(KafkaContext* kafka_ctx) : m_kafka_ctx(kafka_ctx) {}

std::unique_ptr<DeltaHandler> DeltaContext::new_ipv4_delta_handler() {
    std::unique_ptr<DeltaHandler> kafka_handler(
            new KafkaTopicDeltaHandler(m_kafka_ctx->ipv4_deltas()));
    std::unique_ptr<DeltaHandler> handler(
            new GroupingDeltaHandler(GroupingDeltaHandler::GROUP_IP));
    GroupingDeltaHandler* grouping_handler =
            reinterpret_cast<GroupingDeltaHandler*>(handler.get());
    grouping_handler->set_underlying_handler(std::move(kafka_handler));
    return handler;
}

std::unique_ptr<DeltaHandler> DeltaContext::new_domain_delta_handler() {
    std::unique_ptr<DeltaHandler> kafka_handler(
            new KafkaTopicDeltaHandler(m_kafka_ctx->domain_deltas()));
    std::unique_ptr<DeltaHandler> handler(
            new GroupingDeltaHandler(GroupingDeltaHandler::GROUP_DOMAIN));
    GroupingDeltaHandler* grouping_handler =
            reinterpret_cast<GroupingDeltaHandler*>(handler.get());
    grouping_handler->set_underlying_handler(std::move(kafka_handler));
    return handler;
}

std::unique_ptr<DeltaHandler> DeltaContext::new_certificate_delta_handler() {
    return std::unique_ptr<DeltaHandler>(
            new KafkaTopicDeltaHandler(m_kafka_ctx->certificate_deltas()));
}

std::unique_ptr<DeltaHandler>
DeltaContext::new_certificates_to_process_delta_handler() {
    return std::unique_ptr<DeltaHandler>(
            new KafkaTopicDeltaHandler(m_kafka_ctx->certificates_to_process()));
}

std::unique_ptr<DBContext> create_db_context_from_config_values(
        const ConfigValues& config_values) {
    std::unique_ptr<RocksShardedContext> ipv4;
    std::unique_ptr<RocksSingleContext> domain;
    std::unique_ptr<RocksShardedContext> certificate;

    if (config_values.ipv4.should_open()) {
        log_info("context", "creating ipv4 context");
        ipv4.reset(new RocksShardedContext(config_values.ipv4.db_path,
                                           kIPv4ShardCount));
        ipv4->set_options(new_ipv4_rocks_options());
    }
    if (config_values.domain.should_open()) {
        log_info("context", "creating domain context");
        domain.reset(new RocksSingleContext(config_values.domain.db_path));
        domain->set_options(new_domain_rocks_options());
    }
    if (config_values.certificate.should_open() ||
        config_values.external_certificate.should_open() ||
        config_values.sct.should_open() ||
        config_values.processed_cert.should_open()) {
        log_info("context", "creating certificate context");
        certificate.reset(new RocksShardedContext(
                config_values.certificate.db_path, kCertificateShardCount));
        certificate->set_options(new_certificate_rocks_options());
    }
    std::unique_ptr<DBContext> db(new DBContext(
            std::move(ipv4), std::move(domain), std::move(certificate)));
    assert(db);
    return db;
}

std::unique_ptr<LockContext> create_lock_context_from_config_values(
        const ConfigValues& config_values) {
    size_t ipv4_threads = 0;
    if (config_values.ipv4.enabled) {
        ipv4_threads = config_values.ipv4.worker_threads;
    }

    size_t domain_threads = 0;
    if (config_values.domain.enabled) {
        domain_threads = config_values.domain.worker_threads;
    }

    size_t certificate_threads = 0;
    if (config_values.certificate.enabled ||
        config_values.external_certificate.enabled ||
        config_values.sct.enabled || config_values.processed_cert.enabled) {
        certificate_threads =
                config_values.certificate.worker_threads +
                config_values.external_certificate.worker_threads +
                config_values.sct.worker_threads +
                config_values.processed_cert.worker_threads;
    }
    return std::unique_ptr<LockContext>(new LockContext(
            ipv4_threads + 2, domain_threads + 2, certificate_threads + 2));
}

std::unique_ptr<KafkaContext> create_kafka_context_from_config_values(
        const std::string& brokers,
        const ConfigValues& config_values) {
    std::unique_ptr<KafkaContext> ctx(new KafkaContext(brokers));
    KafkaContext::EnableMap enabled;
    enabled.ipv4 = config_values.ipv4.should_open();
    enabled.domain = config_values.domain.should_open();
    enabled.certificate = config_values.certificate.should_open();
    enabled.external_cert = config_values.external_certificate.should_open();
    enabled.sct = config_values.sct.should_open();
    enabled.processed_cert = config_values.processed_cert.should_open();
    ctx->connect_enabled(enabled);
    return ctx;
}

}  // namespace zdb
