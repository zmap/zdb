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

#ifndef ZDB_SRC_CERT_HASH_H
#define ZDB_SRC_CERT_HASH_H

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

namespace zdb {

namespace cert {

struct SHA256Fingerprint {
    SHA256Fingerprint();
    ~SHA256Fingerprint();
    SHA256Fingerprint(const SHA256Fingerprint& fp);

    SHA256Fingerprint& operator=(const SHA256Fingerprint& fp);

    static const size_t SIZE = 32;
    uint8_t data[SIZE];

    static bool from_hex_string(const std::string& hex, SHA256Fingerprint* out);
};

bool operator<(const SHA256Fingerprint& a, const SHA256Fingerprint& b);
bool operator==(const SHA256Fingerprint& a, const SHA256Fingerprint& b);

}  // namespace cert

}  // namespace zdb

#endif /* ZDB_SRC_CERT_HASH_H */
