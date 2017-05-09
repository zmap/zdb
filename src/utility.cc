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

#include "utility.h"

#include <algorithm>
#include <sstream>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <cstdlib>

#include <arpa/inet.h>

#include <zmap/logger.h>

namespace zdb {

static const size_t MAX_IP_STR_SIZE = 3 * 4 + 3 + 2;

std::string make_ip_str(uint32_t ip) {
    char buf[MAX_IP_STR_SIZE];
    memset(buf, 0, MAX_IP_STR_SIZE);
    struct in_addr t;
    t.s_addr = ip;
    const char* dst = inet_ntop(AF_INET, &t, buf, MAX_IP_STR_SIZE);
    if (dst == nullptr) {
        return "";
    }
    auto ret = std::string(buf);
    assert(ret[ret.size() - 1] != '\0');
    return ret;
}

void fatal(const char* logger_name, const char* log_message, ...) {
    log_init(stderr, ZLOG_TRACE, 0, "zdb");
    static const size_t buf_size = 256;
    char buf[buf_size];
    buf[buf_size - 1] = '\0';
    va_list va;
    va_start(va, log_message);
    vsnprintf(buf, buf_size - 1, log_message, va);
    va_end(va);
    log_fatal(logger_name, buf);
}

const google::protobuf::RepeatedPtrField<std::string>& tags_from_record(
        const zsearch::Record& r) {
    switch (r.data_oneof_case()) {
        case zsearch::Record::DataOneofCase::kAtom:
            return r.atom().tags();
        case zsearch::Record::DataOneofCase::kUserdata:
            return r.userdata().public_tags();
        default:
            break;
    }
    static const google::protobuf::RepeatedPtrField<std::string> empty;
    return empty;
}

const google::protobuf::RepeatedPtrField<zsearch::Metadatum>&
metadata_from_record(const zsearch::Record& r) {
    switch (r.data_oneof_case()) {
        case zsearch::Record::DataOneofCase::kAtom:
            return r.atom().metadata();
        case zsearch::Record::DataOneofCase::kUserdata:
            return r.userdata().public_metadata();
        default:
            break;
    }
    static const google::protobuf::RepeatedPtrField<zsearch::Metadatum> empty;
    return empty;
}

std::atomic<int> server_state(0);

std::string hex_encode(const std::string& s) {
    std::stringstream ss;
    ss << std::hex;

    for_each(s.begin(), s.end(), [&](char c) {
        uint16_t b = static_cast<uint8_t>(c);
        ss << std::setw(2) << std::setfill('0') << b;
    });
    return ss.str();
}

uint64_t get_largest_version(const std::vector<zsearch::Record>& records) {
    uint64_t max_version = 0;
    for (const auto& record : records) {
        if (record.version() > max_version) {
            max_version = record.version();
        }
    }
    return max_version;
}

}  // namespace zdzb
