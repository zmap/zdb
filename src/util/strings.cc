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
#include <cctype>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>

namespace zdb {

namespace util {

// static
std::string Strings::to_lower(const std::string& s) {
  std::string out;
  out.reserve(s.size());
  std::transform(s.cbegin(), s.cend(), std::inserter(out, out.end()),
                 [](const char s) { return std::tolower(s); });
  return out;
}

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

// static
bool Strings::hex_decode(const std::string& in, std::string* out) {
  // A valid hex string must have even length.
  if (in.size() % 2 != 0) {
    return false;
  }
  // Validate input characters
  if (std::string::npos != in.find_first_not_of("0123456789ABCDEFabcdef")) {
    return false;
  }
  size_t expected_bytes = in.size() / 2;
  out->clear();
  out->reserve(expected_bytes);
  for (size_t i = 0; i < expected_bytes; ++i) {
    uint32_t b;
    std::stringstream ss;
    ss << std::hex << in.substr(i * 2, 2);
    if (!ss) {
      return false;
    }
    ss >> b;
    if (!ss) {
      return false;
    }
    out->push_back(static_cast<unsigned char>(b));
  }
  return true;
}

}  // namespace util

}  // namespace zdb
