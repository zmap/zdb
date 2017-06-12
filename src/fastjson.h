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

#include <json/json.h>
#include "anonymous_store.h"
#include "record.h"
#include "utility.h"

#include "../censys-definitions/cpp/certificate.pb.h"
#include "search.grpc.pb.h"

std::set<std::string> build_certificate_tags_from_record(
        const zsearch::AnonymousRecord& rec);

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
                           const zsearch::Certificate& certificate,
                           const std::set<std::string>& tags,
                           uint32_t added_at,
                           uint32_t updated_at);

void fast_dump_certificate_metadata(std::ostream& f,
                                    const zsearch::Certificate& c,
                                    uint32_t added_at,
                                    uint32_t updated_at);

std::string dump_certificate_to_json_string(
        const zsearch::AnonymousRecord& rec);

void fast_dump_repeated_bytes(
        std::ostream& f,
        const google::protobuf::RepeatedPtrField<std::string>& sha256fps);

void fast_dump_path(std::ostream& f, const zsearch::Path& path);

void fast_dump_root_store_status(
        std::ostream& f,
        const zsearch::RootStoreStatus& rootStoreStatus);

void fast_dump_validation(
        std::ostream& f,
        const zsearch::CertificateValidation& certificateValidation);

void fast_dump_utc_unix_timestamp(std::ostream& f, uint32_t unix_time);
