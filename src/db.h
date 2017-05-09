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

#ifndef ZDB_DB_H
#define ZDB_DB_H

#include <functional>
#include <string>
#include <memory>
#include <utility>

#include <rocksdb/db.h>
#include <rocksdb/write_batch.h>

#include "macros.h"
#include "serialize.h"

namespace zdb {

template <typename key_type, typename record_type>
class DB {
  public:
    class Batch {
      private:
        rocksdb::WriteBatch m_batch;
        rocksdb::WriteOptions m_write_options;
        rocksdb::DB* m_db;

        std::function<bool(const key_type&)> m_validate;

        friend class DB;

      protected:
        Batch(std::function<bool(const key_type&)> validate,
              rocksdb::DB* db,
              const rocksdb::WriteOptions& write_options)
                : m_validate(std::move(validate)),
                  m_write_options(write_options),
                  m_db(db) {}

      public:
        inline bool put(const key_type& key, const record_type& value) {
            if (!m_validate(key)) {
                return false;
            }
            m_batch.Put(key.string(), value.string());
            return true;
        }

        inline bool del(const key_type& key) {
            if (!m_validate(key)) {
                return false;
            }
            m_batch.Delete(key.string());
            return true;
        }
    };

  protected:
    template <typename deserialized_type>
    class DBIteratorImpl {
      public:
        using value_type = std::pair<key_type, deserialized_type>;

        virtual bool valid() const = 0;

        virtual void next() = 0;
        virtual value_type& get() = 0;
        virtual const value_type& get() const = 0;
        virtual value_type* get_ptr() = 0;
        virtual const value_type* get_ptr() const = 0;

        virtual bool operator==(const DBIteratorImpl& other) const = 0;
        virtual ~DBIteratorImpl() {}
    };

  private:
    template <typename deserialized_type>
    class DBIterator {
      private:
        using impl_type = DBIteratorImpl<deserialized_type>;
        std::unique_ptr<impl_type> m_impl;

      public:
        using value_type = typename impl_type::value_type;

        DBIterator(std::unique_ptr<impl_type> impl) : m_impl(std::move(impl)) {}

        DBIterator(const DBIterator& other) = delete;
        DBIterator(DBIterator&& other) : m_impl(std::move(other.m_impl)) {
            other.m_impl = nullptr;
        }

        bool operator==(const DBIterator& other) const {
            return *m_impl == *other.m_impl;
        }

        bool operator!=(const DBIterator& other) const {
            return !(*m_impl == *other.m_impl);
        }

        inline const value_type& operator*() const { return m_impl->get(); }

        inline value_type* operator->() { return m_impl->get_ptr(); }

        inline const value_type* operator->() const {
            return m_impl->get_ptr();
        }

        DBIterator& operator++() {
            m_impl->next();
            return *this;
        }

        DBIterator operator++(int) = delete;

        inline bool valid() const { return m_impl->valid(); }

        friend void swap(DBIterator& a, DBIterator& b) {
            using std::swap;
            swap(a.m_impl, b.m_impl);
        }
    };

  public:
    // Type definitions
    using value_type = std::pair<key_type, record_type>;
    using raw_record_value_type = std::pair<key_type, std::string>;

    // Iterator definitions
    using iterator = DBIterator<record_type>;
    using raw_record_iterator = DBIterator<std::string>;

    // Key-value functions
    virtual record_type get(const key_type& key) const = 0;
    virtual bool put(const key_type& key, const record_type& record) = 0;
    virtual bool del(const key_type& key) = 0;

    virtual bool may_exist(const key_type& key) const = 0;

    virtual std::string get_serialized(const key_type& key) const = 0;
    virtual bool put_serialized(const key_type& key,
                                const std::string& serialized) = 0;
    virtual bool put_serialized(const key_type& key,
                                const void* data,
                                size_t len) = 0;

    virtual bool delete_all() = 0;

    // Iterator functions
    virtual iterator begin() const = 0;
    virtual iterator end() const = 0;

    virtual iterator find(const key_type& k) const = 0;
    virtual iterator find_prefix_seek(const key_type& k) const = 0;

    virtual iterator upper_bound(const key_type& k) const = 0;
    virtual iterator upper_bound_prefix_seek(const key_type& k) const = 0;
    virtual iterator seek_start_of_shard(const size_t target_shard) const = 0;

    virtual raw_record_iterator rr_begin() const = 0;
    virtual raw_record_iterator rr_end() const = 0;

    virtual size_t total_shards() const = 0;
    virtual size_t shard_for(const key_type& k) const = 0;

    // Batch write
    virtual Batch make_batch(const key_type& prefix) const = 0;
    inline bool write_batch(Batch& batch) {
        return batch.m_db->Write(batch.m_write_options, &batch.m_batch).ok();
    }

    // Statistics
    virtual bool empty() const = 0;

    virtual ~DB() {}

  protected:
    inline Batch make_batch(std::function<bool(const key_type&)> validator,
                            rocksdb::DB* db,
                            const rocksdb::WriteOptions write_options) const {
        return Batch(std::move(validator), db, write_options);
    }
};

}  // namespace zdb

#endif /* ZDB_DB_H */
