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

#ifndef ZDB_SRC_SHARDED_DB_H
#define ZDB_SRC_SHARDED_DB_H

#include <cassert>
#include <future>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <rocksdb/db.h>

#include "db.h"
#include "macros.h"
#include "record.h"

namespace zdb {

template <typename key_type>
struct shard_for {
  static const size_t total_shards;
  size_t operator()(const key_type&) const;
};

template <>
struct shard_for<IPv4Key> {
  static const size_t total_shards;
  size_t operator()(const IPv4Key& key) const {
    // IP should be in network order
    return key.ip & 0x000000FFU;
  }
};

template <>
struct shard_for<HashKey> {
  static const size_t total_shards;
  size_t operator()(const HashKey& key) const {
    assert(!key.hash.empty());
    uint8_t b = key.hash[0];
    return static_cast<size_t>(b);
  }
};

class ShardedOpener;

template <typename key_type,
          typename record_type,
          typename shard_for_type = zdb::shard_for<key_type>>
class ShardedDB : public DB<key_type, record_type> {
 private:
  // Type redeclarations
  using db_type = DB<key_type, record_type>;
  using value_type = typename db_type::value_type;
  using iterator = typename db_type::iterator;
  using raw_record_iterator = typename db_type::raw_record_iterator;
  using Batch = typename db_type::Batch;

  // Member variables
  std::vector<rocksdb::DB*> m_db_shards;
  shard_for_type m_shard_for;

  rocksdb::WriteOptions m_write_options_default;
  rocksdb::ReadOptions m_read_options_default;
  rocksdb::ReadOptions m_read_options_prefix_seek;

  template <typename deserialized_type>
  class ShardedIteratorImpl
      : public db_type::template DBIteratorImpl<deserialized_type> {
   public:
    using Opener = ShardedOpener;

   private:
    // Type Declarations
    using DBIteratorImpl =
        typename db_type::template DBIteratorImpl<deserialized_type>;
    using value_type = typename DBIteratorImpl::value_type;

    // Friend classes
    friend class ShardedDB;

    // Member variables
    rocksdb::Iterator* m_it;
    rocksdb::ReadOptions m_read_options;
    const std::vector<rocksdb::DB*>& m_db_shards;

    deserialize<deserialized_type> m_deserialize;

    value_type m_value;
    size_t m_current_shard;

    ShardedIteratorImpl(const std::vector<rocksdb::DB*>& db_shards,
                        rocksdb::Iterator* it,
                        const rocksdb::ReadOptions& read_options,
                        size_t current_shard)
        : m_db_shards(db_shards),
          m_it(it),
          m_read_options(read_options),
          m_current_shard(current_shard) {
      update_current();
    }

    void update_current() {
      if (!m_it) {
        return;
      }
      while (!m_it->Valid()) {
        delete m_it;
        m_it = nullptr;
        ++m_current_shard;
        if (m_current_shard >= shard_for_type::total_shards) {
          return;
        }
        m_it = m_db_shards[m_current_shard]->NewIterator(m_read_options);
        m_it->SeekToFirst();
      }
      if (m_it->Valid()) {
        m_value.first = key_type::from_string(m_it->key().ToString());
        m_value.second = m_deserialize(m_it->value().ToString());
      }
    }

   public:
    ShardedIteratorImpl(ShardedIteratorImpl&& other)
        : m_db_shards(other.m_db_shards),
          m_it(other.m_it),
          m_read_options(other.m_read_options) {
      other.m_it = nullptr;
    }

    virtual bool valid() const override { return m_it && m_it->Valid(); }

    virtual void next() override {
      m_it->Next();
      update_current();
    }

    virtual value_type& get() override { return m_value; }

    virtual const value_type& get() const override { return m_value; }

    virtual value_type* get_ptr() override { return &m_value; }

    virtual const value_type* get_ptr() const override { return &m_value; }

    virtual bool operator==(const DBIteratorImpl& other) const override {
      // Make sure the underlying type is the same
      const auto s = dynamic_cast<const ShardedIteratorImpl*>(&other);
      if (s == nullptr) {
        return false;
      }

      // Actually compare equality if the types are the same
      if (valid() ^ s->valid()) {
        return false;
      }

      // Both are valid, or both are invalid. If invalid, they're equal
      if (!valid()) {
        return true;
      }

      // Both must be valid, so compare current keys
      return m_it->key() == s->m_it->key();
    }

    virtual ~ShardedIteratorImpl() {
      if (m_it) {
        delete m_it;
      }
    }
  };

  using iterator_impl = ShardedIteratorImpl<record_type>;
  using raw_record_iterator_impl = ShardedIteratorImpl<std::string>;

 private:
  iterator find(const key_type& k, const rocksdb::ReadOptions& opt) const {
    auto target_shard = m_shard_for(k);
    assert(target_shard < shard_for_type::total_shards);
    auto it = m_db_shards[target_shard]->NewIterator(opt);
    auto kstr = k.string();
    rocksdb::Slice ks(kstr);
    it->Seek(ks);
    // If it's not valid, it's already at the end
    if (!it->Valid()) {
      delete it;
      return end();
    }
    // If the key doesn't match, return end()
    if (it->key() != ks) {
      delete it;
      return end();
    }
    std::unique_ptr<iterator_impl> impl_ptr(
        new iterator_impl(m_db_shards, it, opt, target_shard));
    return iterator(std::move(impl_ptr));
  }

 public:
  ShardedDB(std::vector<rocksdb::DB*> db_shards) : m_db_shards(db_shards) {
    // TODO: Take these in the constructor and have them be configurable in
    // the configuration JSON.

    // Default to total order seek
    m_read_options_default.total_order_seek = true;
    m_read_options_prefix_seek.total_order_seek = false;

    // Async writes
    m_write_options_default.sync = false;

    // Sanity check
    assert(shard_for_type::total_shards == m_db_shards.size());
  }

  // Key-value functions
  virtual record_type get(const key_type& key) const override {
    return record_type::from_string(get_serialized(key));
  }

  virtual bool put(const key_type& key, const record_type& record) override {
    auto target_shard = m_shard_for(key);
    assert(target_shard < shard_for_type::total_shards);
    auto ks = key.string();
    auto rs = record.string();
    rocksdb::Slice key_slice(ks);
    rocksdb::Slice record_slice(rs);
    auto status = m_db_shards[target_shard]->Put(m_write_options_default,
                                                 key_slice, record_slice);
    return status.ok();
  }

  virtual bool del(const key_type& key) override {
    auto target_shard = m_shard_for(key);
    auto ks = key.string();
    rocksdb::Slice key_slice(ks);
    auto status =
        m_db_shards[target_shard]->Delete(m_write_options_default, key_slice);
    return status.ok();
  }

  virtual bool may_exist(const key_type& key) const override {
    auto target_shard = m_shard_for(key);
    auto ks = key.string();
    rocksdb::Slice key_slice(ks);
    std::string s;
    return m_db_shards[target_shard]->KeyMayExist(m_read_options_default,
                                                  key_slice, &s, nullptr);
  }

  virtual std::string get_serialized(const key_type& key) const override {
    auto target_shard = m_shard_for(key);
    assert(target_shard < shard_for_type::total_shards);

    auto ks = key.string();
    rocksdb::Slice key_slice(ks);

    std::string data;
    auto status = m_db_shards[target_shard]->Get(m_read_options_default,
                                                 key_slice, &data);
    if (status.IsNotFound()) {
      std::stringstream ss;
      ss << "Key does not exist: " << ks;
      throw std::out_of_range(std::move(ss.str()));
    }
    if (!status.ok()) {
      throw std::runtime_error(status.ToString());
    }
    return data;
  }

  virtual bool put_serialized(const key_type& key,
                              const std::string& serialized) override {
    return put_serialized(key, serialized.data(), serialized.size());
  }

  virtual bool put_serialized(const key_type& key,
                              const void* data,
                              size_t len) override {
    auto target_shard = m_shard_for(key);
    assert(target_shard < shard_for_type::total_shards);
    auto ks = key.string();
    rocksdb::Slice key_slice(ks);
    rocksdb::Slice record_slice(static_cast<const char*>(data), len);
    auto status = m_db_shards[target_shard]->Put(m_write_options_default,
                                                 key_slice, record_slice);
    return status.ok();
  }

  virtual bool delete_all() override {
    bool success = true;
    for (auto db : m_db_shards) {
      rocksdb::WriteBatch batch;
      auto it = db->NewIterator(m_read_options_default);
      for (it->SeekToFirst(); it->Valid(); it->Next()) {
        batch.Delete(it->key());
      }
      auto status = db->Write(m_write_options_default, &batch);
      if (!status.ok()) {
        success = false;
      }
    }
    return success;
  }

  // Iterator functions
  virtual iterator begin() const override {
    rocksdb::Iterator* it =
        m_db_shards.front()->NewIterator(m_read_options_default);
    it->SeekToFirst();
    std::unique_ptr<iterator_impl> impl_ptr(
        new iterator_impl(m_db_shards, it, m_read_options_default, 0));
    return iterator(std::move(impl_ptr));
  }

  virtual iterator end() const override {
    rocksdb::Iterator* it =
        m_db_shards.back()->NewIterator(m_read_options_default);
    std::unique_ptr<iterator_impl> impl_ptr(new iterator_impl(
        m_db_shards, it, m_read_options_default, m_db_shards.size()));
    return iterator(std::move(impl_ptr));
  }

  virtual iterator find(const key_type& k) const override {
    return find(k, m_read_options_default);
  }

  virtual iterator find_prefix_seek(const key_type& k) const override {
    return find(k, m_read_options_prefix_seek);
  }

  virtual iterator upper_bound(const key_type& k) const override {
    auto target_shard = m_shard_for(k);
    assert(target_shard < shard_for_type::total_shards);
    auto kstr = k.string();
    rocksdb::Slice ks(kstr);
    auto it = m_db_shards[target_shard]->NewIterator(m_read_options_default);
    it->Seek(ks);

    // Check if we found something
    if (it->Valid()) {
      std::unique_ptr<iterator_impl> impl_ptr(new iterator_impl(
          m_db_shards, it, m_read_options_default, target_shard));
      return iterator(std::move(impl_ptr));
    }

    // We didn't find something
    delete it;

    // Find the next valid thing in the database
    for (auto current_shard = target_shard + 1;
         current_shard < shard_for_type::total_shards; ++current_shard) {
      it = m_db_shards[current_shard]->NewIterator(m_read_options_default);
      it->SeekToFirst();
      if (it->Valid()) {
        std::unique_ptr<iterator_impl> impl_ptr(new iterator_impl(
            m_db_shards, it, m_read_options_default, current_shard));
        return iterator(std::move(impl_ptr));
      }
      delete it;
    }
    return end();
  }

  virtual iterator upper_bound_prefix_seek(const key_type& k) const override {
    auto target_shard = m_shard_for(k);
    assert(target_shard < shard_for_type::total_shards);
    auto it =
        m_db_shards[target_shard]->NewIterator(m_read_options_prefix_seek);
    auto kstr = k.string();
    rocksdb::Slice ks(kstr);
    it->Seek(ks);

    // Prefix seek can return invalid iterator / end if there's nothing
    // with the prefix, so if there's no match we don't bother to point to
    // the start of the next non-empty shard
    if (!it->Valid()) {
      delete it;
      return end();
    }
    std::unique_ptr<iterator_impl> impl_ptr(new iterator_impl(
        m_db_shards, it, m_read_options_prefix_seek, target_shard));
    return iterator(std::move(impl_ptr));
  }

  virtual size_t total_shards() const override {
    return shard_for_type::total_shards;
  }

  virtual size_t shard_for(const key_type& k) const override {
    return m_shard_for(k);
  }

  virtual iterator seek_start_of_shard(
      const size_t target_shard) const override {
    assert(target_shard < shard_for_type::total_shards);
    auto it = m_db_shards[target_shard]->NewIterator(m_read_options_default);
    it->SeekToFirst();
    if (it->Valid()) {
      std::unique_ptr<iterator_impl> impl_ptr(new iterator_impl(
          m_db_shards, it, m_read_options_default, target_shard));
      return iterator(std::move(impl_ptr));
    }
    delete it;
    return end();
  }

  virtual raw_record_iterator rr_begin() const override {
    rocksdb::Iterator* it =
        m_db_shards.front()->NewIterator(m_read_options_default);
    it->SeekToFirst();
    std::unique_ptr<raw_record_iterator_impl> impl_ptr(
        new raw_record_iterator_impl(m_db_shards, it, m_read_options_default,
                                     0));
    return raw_record_iterator(std::move(impl_ptr));
  }

  virtual raw_record_iterator rr_end() const override {
    rocksdb::Iterator* it =
        m_db_shards.back()->NewIterator(m_read_options_default);
    std::unique_ptr<raw_record_iterator_impl> impl_ptr(
        new raw_record_iterator_impl(m_db_shards, it, m_read_options_default,
                                     m_db_shards.size()));
    return raw_record_iterator(std::move(impl_ptr));
  }

  // Batch write
  virtual Batch make_batch(const key_type& prefix) const override {
    auto target_shard = m_shard_for(prefix);
    assert(target_shard < shard_for_type::total_shards);
    std::function<bool(const key_type&)> validator = [=](const key_type& k) {
      return this->m_shard_for(k) == target_shard;
    };
    return db_type::make_batch(std::move(validator), m_db_shards[target_shard],
                               m_write_options_default);
  }

  virtual bool empty() const override {
    for (rocksdb::DB* db : m_db_shards) {
      auto it = db->NewIterator(m_read_options_default);
      it->SeekToFirst();
      if (it->Valid()) {
        return false;
      }
    }
    return true;
  }

  // Destructor
  virtual ~ShardedDB() {}

 protected:
};

}  // namespace zdb

#endif /* ZDB_SRC_SHARDED_DB_H */
