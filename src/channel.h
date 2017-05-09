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

#ifndef ZDB_SRC_CHANNEL_H
#define ZDB_SRC_CHANNEL_H

#include <atomic>
#include <cassert>
#include <condition_variable>
#include <queue>
#include <mutex>

#include "macros.h"

namespace zdb {

template <typename T>
class Channel {
  private:
    std::queue<T> m_queue;
    mutable std::mutex m_queue_mutex;
    mutable std::condition_variable m_queue_not_full;
    mutable std::condition_variable m_queue_not_empty;
    size_t m_max_size;

    std::atomic<bool> m_closed;

    friend class ChannelIterator;

  public:
    class ChannelIterator {
      public:
        using value_type = T;

      private:
        bool m_valid;
        Channel& m_channel;
        value_type m_value;

        friend class Channel;

        ChannelIterator(Channel& channel) : m_channel(channel), m_valid(true) {
            m_channel.recv(*this);
        }

      public:
        ChannelIterator(const ChannelIterator& other) = delete;
        ChannelIterator(ChannelIterator&& other)
                : m_channel(other.m_channel),
                  m_value(std::move(other.m_value)),
                  m_valid(other.m_valid) {
            other.m_valid = false;
        }

        bool operator==(const ChannelIterator& other) const {
            return this == &other;
        }

        bool operator!=(const ChannelIterator& other) const {
            return !(*this == other);
        }

        const value_type& operator*() const { return m_value; }

        value_type& operator*() { return m_value; }

        value_type* operator->() { return &m_value; }

        const value_type* operator->() const { return &m_value; }

        ChannelIterator& operator++() {
            m_channel.recv(*this);
            return *this;
        }

        ChannelIterator operator++(int) = delete;

        inline bool valid() const { return m_valid; }
    };

    using iterator = ChannelIterator;

    Channel() {
        m_max_size = 1024;
        m_closed.store(false);
    }

    void close() {
        std::lock_guard<std::mutex> lock(m_queue_mutex);
        m_closed.store(true);
        m_queue_not_full.notify_all();
        m_queue_not_empty.notify_all();
    }

    void send(T&& elt) {
        std::unique_lock<std::mutex> lock(m_queue_mutex);
        m_queue_not_full.wait(lock, [&]() {
            return (m_queue.size() < m_max_size) || m_closed;
        });
        std::lock_guard<std::mutex> guard(*lock.release(), std::adopt_lock);
        if (m_closed) {
            throw std::bad_function_call();
        }
        m_queue.push(std::move(elt));
        m_queue_not_empty.notify_one();
    }

    iterator range() {
        ChannelIterator it(*this);
        return it;
    }

  private:
    void recv(ChannelIterator& it) {
        std::unique_lock<std::mutex> lock(m_queue_mutex);
        m_queue_not_empty.wait(
                lock, [&]() { return (m_queue.size() > 0) || m_closed; });
        std::lock_guard<std::mutex> guard(*lock.release(), std::adopt_lock);
        if (m_queue.size() > 0) {
            it.m_value = std::move(m_queue.front());
            m_queue.pop();
            m_queue_not_full.notify_one();
        } else if (m_closed) {
            it.m_valid = false;
        } else {
            assert(false);
        }
    }
};

class WaitGroup {
  private:
    std::atomic_uint_fast64_t m_counter;
    std::mutex m_mutex;
    std::condition_variable m_cv;

  public:
    WaitGroup();
    WaitGroup(const WaitGroup&) = delete;
    WaitGroup(WaitGroup&&) = delete;
    void add(size_t delta);
    void done();
    void wait();
};

}  // namespace zdb

#endif /* ZDB_SRC_CHANNEL_H */
