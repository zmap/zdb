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

#ifndef ZDB_SRC_CONTEXT_H
#define ZDB_SRC_CONTEXT_H

#include <memory>

#include <rocksdb/cache.h>
#include <rocksdb/env.h>

#include "configuration.h"
#include "db.h"
#include "delta_handler.h"
#include "record.h"
#include "sharded_db.h"
#include "zdb.h"

namespace zsearch {

class Record;
class AnonymousRecord;

}  // namespace zsearch

namespace zdb {

using IPv4DB = DB<IPv4Key, ProtobufRecord<zsearch::Record>>;
using DomainDB = DB<DomainKey, ProtobufRecord<zsearch::Record>>;
using CertificateDB = DB<HashKey, ProtobufRecord<zsearch::AnonymousRecord>>;

using IPv4DBImpl = ShardedDB<IPv4Key, ProtobufRecord<zsearch::Record>>;
using DomainDBImpl = ZDB<DomainKey, ProtobufRecord<zsearch::Record>>;
using CertificateDBImpl =
    ShardedDB<HashKey, ProtobufRecord<zsearch::AnonymousRecord>>;

using IPv4LockManager = LockManager<IPv4Key::lock_on_type>;
using DomainLockManager = LockManager<DomainKey::lock_on_type>;
using CertificateLockManager = LockManager<HashKey::lock_on_type>;

class Context {
 public:
  Context() = default;
  virtual ~Context() = default;

 private:
  DISALLOW_COPY_ASSIGN(Context);
};

class LocationContext : public Context {
 public:
  LocationContext(const std::string& public_path,
                  const std::string& restricted_path);

  GeoIP* public_location() { return &m_public; }
  GeoIP* restricted_location() { return &m_restricted; }

  bool is_open() const;

 private:
  GeoIP m_public;
  GeoIP m_restricted;
};

class RocksContext : public Context {
 public:
  RocksContext(const std::string& path);
  virtual ~RocksContext() = default;

  const std::string& path() const { return m_path; }

  virtual rocksdb::Options* mutable_options() { return m_opt.get(); }
  virtual std::shared_ptr<rocksdb::Options> shared_options() { return m_opt; }
  virtual void set_options(std::shared_ptr<rocksdb::Options> opt) {
    m_opt = std::move(opt);
  }

  virtual bool open() = 0;
  virtual void close() = 0;

  virtual bool is_open() const = 0;

  virtual bool repair() = 0;
  virtual bool compact() = 0;

 private:
  std::string m_path;
  rocksdb::Env* m_env;
  std::shared_ptr<rocksdb::Cache> m_cache;
  std::shared_ptr<rocksdb::Options> m_opt;
};

class RocksSingleContext : public RocksContext {
 public:
  template <typename K, typename V>
  using DBImpl = ZDB<K, V>;

  RocksSingleContext(const std::string& path);
  virtual ~RocksSingleContext() = default;

  bool open() override;
  void close() override { m_db.reset(nullptr); }

  bool is_open() const override { return m_db != nullptr; }

  bool repair() override;
  bool compact() override;

  rocksdb::DB* raw_db_ptr() { return m_db.get(); }

 private:
  // Populated by `open()`
  std::unique_ptr<rocksdb::DB> m_db;

  DISALLOW_COPY_ASSIGN(RocksSingleContext);
};

template <typename K, typename V, typename ContextType>
std::unique_ptr<DB<K, V>> db_from_context(ContextType* ctx) {
  if (!ctx) {
    return nullptr;
  }
  if (!ctx->is_open()) {
    return nullptr;
  }
  using ImplType = typename ContextType::template DBImpl<K, V>;
  return std::unique_ptr<DB<K, V>>(new ImplType(ctx->raw_db_ptr()));
}

class RocksShardedContext : public RocksContext {
 public:
  template <typename K, typename V>
  using DBImpl = ShardedDB<K, V>;

  RocksShardedContext(const std::string& base_path, size_t num_shards);

  virtual void set_options(std::shared_ptr<rocksdb::Options> opt) override;

  // Opens each underlying shard. If any one shard could not be opened,
  // ensures all the other shards are closed and returns false. Returns true
  // when all shards are successfully opened.
  bool open() override;
  void close() override;

  bool is_open() const override { return m_is_open; }

  bool repair() override;
  bool compact() override;

  std::vector<rocksdb::DB*> raw_db_ptr();

 private:
  std::shared_ptr<rocksdb::Options> m_opt;

  std::vector<std::unique_ptr<RocksSingleContext>> m_shards;
  bool m_is_open = false;

  DISALLOW_COPY_ASSIGN(RocksShardedContext);
};

class DBContext : public Context {
 public:
  DBContext(std::unique_ptr<RocksShardedContext> ipv4_rctx,
            std::unique_ptr<RocksShardedContext> domain_rctx,
            std::unique_ptr<RocksShardedContext> certificate_rctx);

  bool open_all();
  bool repair();

  IPv4DB* ipv4() { return m_ipv4.get(); }
  const IPv4DB* ipv4() const { return m_ipv4.get(); }

  DomainDB* domain() { return m_domain.get(); }
  const DomainDB* domain() const { return m_domain.get(); }

  CertificateDB* certificate() { return m_certificate.get(); }
  const CertificateDB* certificate() const { return m_certificate.get(); }

 private:
  std::unique_ptr<RocksShardedContext> m_ipv4_rctx;
  std::unique_ptr<RocksShardedContext> m_domain_rctx;
  std::unique_ptr<RocksShardedContext> m_certificate_rctx;

  std::unique_ptr<IPv4DB> m_ipv4;
  std::unique_ptr<DomainDB> m_domain;
  std::unique_ptr<CertificateDB> m_certificate;

  DISALLOW_COPY_ASSIGN(DBContext);
};

class LockContext : public Context {
 public:
  LockContext(size_t ipv4_threads,
              size_t domain_threads,
              size_t certificate_threads);

  IPv4LockManager ipv4;
  DomainLockManager domain;
  CertificateLockManager certificate;
};

class StoreContext : public Context {
 public:
  StoreContext(std::unique_ptr<DBContext> db_ctx,
               std::unique_ptr<LockContext> lock_ctx,
               std::unique_ptr<LocationContext> location_ctx,
               std::unique_ptr<ASTree> as_tree);

  Store<IPv4Key> make_ipv4_store(size_t tid);
  Store<DomainKey> make_domain_store(size_t tid);
  AnonymousStore<HashKey> make_certificate_store(size_t tid);

  ASTree* as_tree() const { return m_as_tree.get(); }

 private:
  std::unique_ptr<DBContext> m_db_ctx;
  std::unique_ptr<LockContext> m_lock_ctx;
  std::unique_ptr<LocationContext> m_location_ctx;
  std::unique_ptr<ASTree> m_as_tree;
};

class KafkaContext : public Context {
 public:
  struct EnableMap {
    bool ipv4 = false;
    bool domain = false;
    bool certificate = false;
    bool external_cert = false;
    bool sct = false;
    bool processed_cert = false;
  };

  KafkaContext(const std::string& brokers);

  void connect_enabled(const EnableMap& enabled);

  KafkaConsumerConnection* ipv4() { return m_ipv4.get(); }
  KafkaConsumerConnection* domain() { return m_domain.get(); }
  KafkaConsumerConnection* certificate() { return m_certificate.get(); }
  KafkaConsumerConnection* external_cert() { return m_external_cert.get(); }
  KafkaConsumerConnection* sct() { return m_sct.get(); }
  KafkaConsumerConnection* processed_cert() { return m_processed_cert.get(); }

  KafkaProducerConnection* ipv4_deltas() { return m_ipv4_deltas.get(); }
  KafkaProducerConnection* domain_deltas() { return m_domain_deltas.get(); }
  KafkaProducerConnection* certificate_deltas() {
    return m_certificate_deltas.get();
  }
  KafkaProducerConnection* certificates_to_process() {
    return m_certificates_to_process.get();
  }

 private:
  // Consumers
  std::unique_ptr<KafkaConsumerConnection> m_ipv4;
  std::unique_ptr<KafkaConsumerConnection> m_domain;
  std::unique_ptr<KafkaConsumerConnection> m_certificate;
  std::unique_ptr<KafkaConsumerConnection> m_external_cert;
  std::unique_ptr<KafkaConsumerConnection> m_sct;
  std::unique_ptr<KafkaConsumerConnection> m_processed_cert;

  // Producers
  std::unique_ptr<KafkaProducerConnection> m_ipv4_deltas;
  std::unique_ptr<KafkaProducerConnection> m_domain_deltas;
  std::unique_ptr<KafkaProducerConnection> m_certificate_deltas;
  std::unique_ptr<KafkaProducerConnection> m_certificates_to_process;

  std::string m_brokers;

  DISALLOW_COPY_ASSIGN(KafkaContext);
};

class DeltaContext : public Context {
 public:
  DeltaContext(KafkaContext* kafka_ctx);
  virtual ~DeltaContext() = default;

  std::unique_ptr<DeltaHandler> new_ipv4_delta_handler();
  std::unique_ptr<DeltaHandler> new_domain_delta_handler();
  std::unique_ptr<DeltaHandler> new_certificate_delta_handler();
  std::unique_ptr<DeltaHandler> new_certificates_to_process_delta_handler();

 private:
  KafkaContext* m_kafka_ctx;

  DISALLOW_COPY_ASSIGN(DeltaContext);
};

std::unique_ptr<DBContext> create_db_context_from_config_values(
    const ConfigValues& config_values);

std::unique_ptr<LockContext> create_lock_context_from_config_values(
    const ConfigValues& config_values);

std::unique_ptr<KafkaContext> create_kafka_context_from_config_values(
    const std::string& brokers,
    const ConfigValues& config_values);

}  // namespace zdb

#endif /* ZDB_SRC_CONTEXT_H */
