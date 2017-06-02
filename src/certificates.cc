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

#include "certificates.h"

namespace zdb {

bool certificate_valid_at(const zsearch::Certificate& cert, std::time_t now) {
    uint32_t not_before = cert.not_valid_before();
    uint32_t not_after = cert.not_valid_after();
    return not_before < now && now < not_after;
}

}  // namespace zdb
