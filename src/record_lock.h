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

#ifndef ZDB_RECORD_LOCK_H
#define ZDB_RECORD_LOCK_H

#include <atomic>
#include <cassert>
#include <vector>

#include <unistd.h>

#include <zmap/logger.h>

#include "defer.h"
#include "macros.h"

namespace zdb {

template <typename T>
class LockManager {
  private:
    std::atomic<bool> locked;
    const size_t num_keys;
    T* m_keys;
    T m_empty;

    bool attempt_update_current(const T& current, size_t thread_id) {
        bool is_locked = false;
        while (!locked.compare_exchange_weak(is_locked, true)) {
            is_locked = false;
        }

        // Check for shit
        bool in_use = false;
        for (size_t i = 0; i < num_keys; ++i) {
            if (m_keys[i] == current) {
                in_use = true;
                break;
            }
        }
        if (!in_use) {
            m_keys[thread_id] = current;
        }

        locked.store(false);
        return in_use;
    }

    void release_current(size_t thread_id) {
        bool is_locked = false;
        while (!locked.compare_exchange_weak(is_locked, true)) {
            is_locked = false;
        }
        m_keys[thread_id] = m_empty;
        locked.store(false);
    }

    Deferred update_current(const T& current, size_t thread_id) {
        while (attempt_update_current(current, thread_id)) {
            usleep(1000);
        }
        return defer(std::mem_fn(&LockManager::release_current),
                     std::ref(*this), thread_id);
    }

    friend class Lock;

  public:
    LockManager(size_t num_threads, const T& empty)
            : num_keys(num_threads), m_empty(empty) {
        m_keys = new T[num_keys];
        for (size_t i = 0; i < num_keys; i++) {
            m_keys[i] = m_empty;
        }
        locked.store(false);
    }

    ~LockManager() { delete[] m_keys; }

    LockManager(const LockManager&) = delete;
    LockManager(LockManager&&) = delete;

    class Lock {
      private:
        LockManager* m_lock_manager;
        size_t m_thread_id;

        friend class LockManager;

        Lock(LockManager* manager, size_t thread_id)
                : m_lock_manager(manager), m_thread_id(thread_id) {}

      public:
        inline Deferred lock(const T& current) {
            return m_lock_manager->update_current(current, m_thread_id);
        }
    };

    Lock make_lock(size_t thread_id) {
        assert(thread_id < num_keys);
        return Lock(this, thread_id);
    }
};

}  // namespace zdb

#endif /* ZDB_RECORD_LOCK_H */
