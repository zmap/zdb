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

#include "cert/hash.h"

#include <cstring>
#include <iomanip>
#include <sstream>

namespace zdb {

namespace cert {

SHA256Fingerprint::SHA256Fingerprint() = default;
SHA256Fingerprint::~SHA256Fingerprint() = default;

SHA256Fingerprint::SHA256Fingerprint(const SHA256Fingerprint& fp) {
  memcpy(data, fp.data, SIZE);
}

SHA256Fingerprint& SHA256Fingerprint::operator=(const SHA256Fingerprint& fp) {
  memcpy(data, fp.data, SIZE);
  return *this;
}

bool operator<(const SHA256Fingerprint& a, const SHA256Fingerprint& b) {
  return memcmp(a.data, b.data, SHA256Fingerprint::SIZE) < 0;
}

bool operator==(const SHA256Fingerprint& a, const SHA256Fingerprint& b) {
  return memcmp(a.data, b.data, SHA256Fingerprint::SIZE) == 0;
}

// static
bool SHA256Fingerprint::from_hex_string(const std::string& hex,
                                        SHA256Fingerprint* out) {
  if (hex.size() != 2 * SHA256Fingerprint::SIZE) {
    return false;
  }
  for (size_t i = 0; i < SHA256Fingerprint::SIZE; ++i) {
    uint16_t b = 0;
    // Read one nibble at a time
    for (size_t n = 0; n < 2; ++n) {
      size_t idx = 2 * i + n;
      // We need to shift left four bits only for the first nibble.
      if (hex[idx] >= '0' && hex[idx] <= '9') {
        b += (hex[idx] - '0') << (4 * (1 - n));
      } else if (hex[idx] >= 'A' && hex[idx] <= 'F') {
        b += (hex[idx] - 'A' + 0x0A) << (4 * (1 - n));
      } else if (hex[idx] >= 'a' && hex[idx] <= 'f') {
        b += (hex[idx] - 'a' + 0x0A) << (4 * (1 - n));
      } else {
        // Not a valid hex character
        return false;
      }
    }
    out->data[i] = static_cast<uint8_t>(b);
  }
  return true;
}

}  // namespace cert

}  // namespace zdb
