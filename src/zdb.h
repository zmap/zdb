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

#ifndef ZDB_SRC_ZDB_H
#define ZDB_SRC_ZDB_H

#include <string>
#include <exception>
#include <memory>
#include <mutex>
#include <sstream>
#include <utility>

#include <rocksdb/comparator.h>
#include <rocksdb/db.h>
#include <rocksdb/env.h>
#include <rocksdb/filter_policy.h>
#include <rocksdb/table.h>
#include <rocksdb/write_batch.h>

#include "db.h"
#include "macros.h"
#include "record_lock.h"

namespace zdb {

template <typename key_type, typename record_type>
class ZDB : public DB<key_type, record_type> {
  private:
    // Type redeclarations
    using db_type = DB<key_type, record_type>;
    using value_type = typename db_type::value_type;
    using iterator = typename db_type::iterator;
    using raw_record_iterator = typename db_type::raw_record_iterator;
    using Batch = typename db_type::Batch;

    rocksdb::DB* m_db;
    rocksdb::WriteOptions m_write_options;
    rocksdb::ReadOptions m_read_options;
    std::string m_db_path;

    // Assignment and copy assignment
    ZDB(const ZDB& rhs) = delete;
    ZDB& operator=(const ZDB& rhs) = delete;
    ZDB(ZDB&& rhs) = delete;

    template <typename deserialized_type>
    class ZDBIteratorImpl
            : public db_type::template DBIteratorImpl<deserialized_type> {
      private:
        // Type Declarations
        using DBIteratorImpl =
                typename db_type::template DBIteratorImpl<deserialized_type>;
        using value_type = typename DBIteratorImpl::value_type;

        // Friend classes
        friend class ZDB;

        // Member variables
        rocksdb::DB* m_db;
        rocksdb::Iterator* m_it;
        rocksdb::ReadOptions m_read_options;

        deserialize<deserialized_type> m_deserialize;
        value_type m_value;

        ZDBIteratorImpl(rocksdb::DB* db,
                        rocksdb::Iterator* it,
                        const rocksdb::ReadOptions read_options)
                : m_db(db), m_it(it), m_read_options(read_options) {
            update_current();
        }

        void update_current() {
            if (m_it && m_it->Valid()) {
                m_value.first = key_type::from_string(m_it->key().ToString());
                m_value.second = m_deserialize(m_it->value().ToString());
            }
        }

      public:
        ZDBIteratorImpl(ZDBIteratorImpl&& other)
                : m_db(other.m_db),
                  m_it(other.m_it),
                  m_read_options(other.m_read_options) {
            other.m_db = nullptr;
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
            const auto s = dynamic_cast<const ZDBIteratorImpl*>(&other);
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

        virtual ~ZDBIteratorImpl() {
            if (m_it) {
                delete m_it;
            }
            m_it = nullptr;
            m_db = nullptr;
        }
    };

    // Iterator implementation types
    using iterator_impl = ZDBIteratorImpl<record_type>;
    using raw_record_iterator_impl = ZDBIteratorImpl<std::string>;

  private:
    // Private internal functions
    virtual iterator find(const key_type& k,
                          const rocksdb::ReadOptions& opt) const {
        auto it = m_db->NewIterator(opt);
        auto ks = k.string();
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
                new iterator_impl(m_db, it, opt));
        return iterator(std::move(impl_ptr));
    }

    virtual iterator upper_bound(const key_type& k,
                                 const rocksdb::ReadOptions& opt) const {
        auto it = m_db->NewIterator(opt);
        auto kstr = k.string();
        rocksdb::Slice ks(kstr);
        it->Seek(ks);
        if (!it->Valid()) {
            delete it;
            return end();
        }
        std::unique_ptr<iterator_impl> impl_ptr(
                new iterator_impl(m_db, it, opt));
        return iterator(std::move(impl_ptr));
    }

  public:
    // Constructors and destructors
    ZDB(rocksdb::DB* db) : m_db(db) {
        // Default to total order seek
        m_read_options.total_order_seek = true;

        // Set the sync options
        m_write_options.sync = false;
    }

    // Key-value functions
    virtual record_type get(const key_type& key) const override {
        return record_type::from_string(get_serialized(key));
    }

    virtual bool put(const key_type& key, const record_type& record) override {
        auto ks = key.string();
        auto rs = record.string();
        rocksdb::Slice serialized_key(ks);
        rocksdb::Slice serialized_record(rs);
        auto status =
                m_db->Put(m_write_options, serialized_key, serialized_record);
        return status.ok();
    }

    virtual bool del(const key_type& key) override {
        auto ks = key.string();
        rocksdb::Slice serialized_key(ks);
        auto status = m_db->Delete(m_write_options, serialized_key);
        return status.ok();
    }

    virtual bool may_exist(const key_type& key) const override {
        auto ks = key.string();
        std::string s;
        rocksdb::Slice serialized_key(ks);
        return m_db->KeyMayExist(m_read_options, serialized_key, &s, nullptr);
    }

    virtual std::string get_serialized(const key_type& key) const override {
        auto ks = key.string();
        rocksdb::Slice dbkey(ks);

        std::string data;
        auto status = m_db->Get(m_read_options, dbkey, &data);
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
        auto ks = key.string();
        rocksdb::Slice serialized_key(ks);
        rocksdb::Slice serialized_record(serialized);
        auto status =
                m_db->Put(m_write_options, serialized_key, serialized_record);
        return status.ok();
    }

    virtual bool put_serialized(const key_type& key,
                                const void* data,
                                size_t len) override {
        auto ks = key.string();
        rocksdb::Slice serialized_key(ks);
        rocksdb::Slice serialized_record(static_cast<const char*>(data), len);
        auto status =
                m_db->Put(m_write_options, serialized_key, serialized_record);
        return status.ok();
    }

    virtual bool delete_all() override {
        rocksdb::WriteBatch batch;
        auto it = m_db->NewIterator(m_read_options);
        for (it->SeekToFirst(); it->Valid(); it->Next()) {
            batch.Delete(it->key());
        }
        auto status = m_db->Write(m_write_options, &batch);
        return status.ok();
    }

    // Iterator functions
    virtual iterator begin() const override {
        rocksdb::Iterator* it = m_db->NewIterator(m_read_options);
        it->SeekToFirst();
        std::unique_ptr<iterator_impl> impl_ptr(
                new iterator_impl(m_db, it, m_read_options));
        return iterator(std::move(impl_ptr));
    }

    virtual iterator seek_start_of_shard(
            const size_t target_shard) const override {
        assert(target_shard == 0);
        return begin();
    }

    virtual iterator end() const override {
        rocksdb::Iterator* it = m_db->NewIterator(m_read_options);
        std::unique_ptr<iterator_impl> impl_ptr(
                new iterator_impl(m_db, it, m_read_options));
        return iterator(std::move(impl_ptr));
    }

    virtual iterator find(const key_type& k) const override {
        return find(k, m_read_options);
    }

    virtual iterator find_prefix_seek(const key_type& k) const override {
        auto prefix_seek_opt = m_read_options;
        prefix_seek_opt.total_order_seek = false;
        return find(k, prefix_seek_opt);
    }

    virtual iterator upper_bound(const key_type& k) const override {
        return upper_bound(k, m_read_options);
    }

    virtual iterator upper_bound_prefix_seek(const key_type& k) const override {
        auto prefix_seek_opt = m_read_options;
        prefix_seek_opt.total_order_seek = false;
        return upper_bound(k, prefix_seek_opt);
    }

    virtual size_t total_shards() const override { return 1; }

    virtual size_t shard_for(const key_type& k) const override { return 0; }

    virtual raw_record_iterator rr_begin() const override {
        rocksdb::Iterator* it = m_db->NewIterator(m_read_options);
        it->SeekToFirst();
        std::unique_ptr<raw_record_iterator_impl> impl_ptr(
                new raw_record_iterator_impl(m_db, it, m_read_options));
        return raw_record_iterator(std::move(impl_ptr));
    }
    virtual raw_record_iterator rr_end() const override {
        rocksdb::Iterator* it = m_db->NewIterator(m_read_options);
        std::unique_ptr<raw_record_iterator_impl> impl_ptr(
                new raw_record_iterator_impl(m_db, it, m_read_options));
        return raw_record_iterator(std::move(impl_ptr));
    }

    virtual Batch make_batch(const key_type& prefix) const override {
        static auto validator = [](const key_type& prefix) { return true; };
        return db_type::make_batch(validator, m_db, m_write_options);
    }

    // Statistics

    virtual bool empty() const override {
        rocksdb::Iterator* it = m_db->NewIterator(m_read_options);
        it->SeekToFirst();

        bool result = false;
        if (!it->Valid()) {
            result = true;
        }
        delete it;

        return result;
    }

    // Destructor
    ~ZDB() {}

  protected:
    virtual bool write_batch(rocksdb::WriteBatch& batch) {
        auto status = m_db->Write(m_write_options, &batch);
        return status.ok();
    }
};

}  // namespace zdb

#endif /* ZDB_SRC_ZDB_H */
