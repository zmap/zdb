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

#ifndef ZDB_UTILITY_H
#define ZDB_UTILITY_H

#include <atomic>
#include <cstdarg>
#include <memory>
#include <string>
#include <utility>

#include "zsearch_definitions/search.pb.h"

#include "macros.h"

#define STATE_OK 0
#define STATE_SHUTDOWN 1
#define STATE_LOCK_IPV4 2
#define STATE_LOCK_DOMAIN 3
#define STATE_LOCK_CERT 4
#define STATE_LOCK_PUBKEY 5

namespace zdb {

extern std::atomic<int> server_state;
void fatal(const char* logger_name, const char* log_message, ...)
    __attribute__((noreturn));

const google::protobuf::RepeatedPtrField<std::string>& tags_from_record(
    const zsearch::Record& r);
const google::protobuf::RepeatedPtrField<zsearch::Metadatum>&
metadata_from_record(const zsearch::Record& r);

std::string make_ip_str(uint32_t ip);

std::string hex_encode(const std::string& s);

uint64_t get_largest_version(const std::vector<zsearch::Record>& records);

enum ReturnStatus {

  RETURN_SUCCESS,
  RETURN_FAILURE

};

}  // namespace zdb

#endif
