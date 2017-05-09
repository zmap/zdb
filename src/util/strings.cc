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

#include "util/strings.h"

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <sstream>

namespace zdb {

namespace util {

// static
bool Strings::has_prefix(const std::string& prefix, const std::string& s) {
    if (s.size() < prefix.size()) {
        return false;
    }
    if (prefix.empty()) {
        return true;
    }
    int cmp = s.compare(0, prefix.size(), prefix);
    return cmp == 0;
}

// static
bool Strings::has_suffix(const std::string& suffix, const std::string& s) {
    if (s.size() < suffix.size()) {
        return false;
    }
    if (suffix.empty()) {
        return true;
    }
    size_t suffix_len = suffix.size();
    int cmp = s.compare(s.size() - suffix_len, suffix_len, suffix);
    return cmp == 0;
}

// static
std::string Strings::random_bytes(size_t n) {
    std::string out;
    out.resize(n);
    char* buf = const_cast<char*>(out.data());
    std::ifstream urandom("/dev/urandom");
    urandom.read(buf, n);
    return out;
}

// static
std::string Strings::hex_encode(const std::string& s) {
    std::stringstream ss;
    ss << std::hex;

    for_each(s.begin(), s.end(), [&](char c) {
        uint16_t b = static_cast<uint8_t>(c);
        ss << std::setw(2) << std::setfill('0') << b;
    });
    return ss.str();
}

}  // namespace util

}  // namespace zdb
