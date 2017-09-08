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

#ifndef ZDB_SRC_UTIL_STRINGS_H
#define ZDB_SRC_UTIL_STRINGS_H

#include <string>

namespace zdb {

namespace util {

class Strings {
 public:
  // Returns s with std::tolower applied to all characters.
  static std::string to_lower(const std::string& s);

  // Returns true if `s` starts with `prefix`. Returns false otherwise.
  static bool has_prefix(const std::string& prefix, const std::string& s);

  // Returns true if `s` ends with `suffix`. Returns false otherwise.
  static bool has_suffix(const std::string& suffix, const std::string& s);

  // Returns a string of random bytes. These bytes might not be printable.
  static std::string random_bytes(size_t n);

  // Encodes `s` to hex.
  static std::string hex_encode(const std::string& s);

  // Decodes `in` from hex. Stores decoded value in `out`. Returns true on
  // success.
  static bool hex_decode(const std::string& in, std::string* out);
};

}  // namespace util

}  // namespace zdb

#endif /* ZDB_SRC_UTIL_STRINGS_H */
