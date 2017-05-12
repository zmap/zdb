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

#include "anonymous_store.h"
#include "utility.h"
#include "record.h"
#include <json/json.h>

#include "search.grpc.pb.h"

void fast_dump_ipv4_host(std::ostream& f,
                         uint32_t ip,
                         std::string domain,
                         std::vector<zsearch::Record>& records,
                         std::map<std::string, std::string>& metadata,
                         std::set<std::string>& tags,
                         zsearch::LocationAtom& public_location,
                         zsearch::LocationAtom& private_location,
                         zsearch::ASAtom& as_data,
                         bool public_location_found,
                         bool private_location_found,
                         bool as_data_found,
                         int alexa_rank,
                         Json::FastWriter& fastWriter);

void fast_dump_certificate(std::ostream& f,
                           std::map<std::string, std::string>& metadata,
                           std::set<std::string>& tags,
                           const zsearch::Certificate& certificate);

std::string dump_certificate_to_json_string(zsearch::AnonymousRecord rec);