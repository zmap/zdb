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

#include <type_traits>

#include "certificates.h"

namespace zdb {

bool certificate_valid_at(const zsearch::Certificate& cert, std::time_t now) {
    // Compile-time checks on std::time_t
    static_assert(std::is_integral<time_t>::value, "time not an integer");
    static_assert(std::is_unsigned<time_t>::value ||
                          (sizeof(std::time_t) > sizeof(uint32_t)),
                  "signed 32-bit time value");
    static_assert(sizeof(std::time_t) >= sizeof(uint32_t),
                  "time not wide enough");

    uint32_t not_before = cert.not_valid_before();
    uint32_t not_after = cert.not_valid_after();
    return not_before < now && now < not_after;
}

void expire_status(zsearch::RootStoreStatus* expired) {
    // Update the status to reflect expiration. Expired certificates can't be
    // valid and have no trusted path.
    expired->set_trusted_path(false);
    expired->set_valid(false);
    return;
}

}  // namespace zdb
