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

#ifndef ZDB_SRC_DEFER_H
#define ZDB_SRC_DEFER_H

#include <functional>

#include "macros.h"

namespace zdb {

class Deferred {
  private:
    std::function<void()> m_f;

  public:
    typedef void (*VoidFunctionPointer)();

    template <typename F, typename... Args>
    Deferred(F&& func, Args&&... args)
            : m_f(std::bind(std::forward<F>(func),
                            std::forward<Args>(args)...)) {}

    Deferred(std::function<void()> func) : m_f(func) {}

    Deferred(VoidFunctionPointer f) : m_f(std::function<void()>(f)) {}

    Deferred(const Deferred&) = delete;
    Deferred(Deferred&& other) : m_f(other.m_f) { other.m_f = nullptr; }

    ~Deferred() {
        if (m_f) {
            m_f();
            m_f = nullptr;
        }
    }
};

template <typename F, typename... Args>
Deferred defer(F&& func, Args&&... args) {
    return Deferred(std::forward<F>(func), std::forward<Args>(args)...);
}

}  // namespace zdb

#endif /* ZDB_SRC_DEFER_H */
