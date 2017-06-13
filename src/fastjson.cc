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

#include <base64/base64.h>
#include <json/json.h>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>

#include "anonymous_store.h"
#include "certificates.h"
#include "inbound.h"
#include "protocol_names.h"
#include "record.h"
#include "search.grpc.pb.h"
#include "store.h"
#include "util/strings.h"
#include "zmap/logger.h"

using namespace zdb;
using namespace zsearch;

void make_tags_string(std::ostream& f, const std::set<std::string>& tags) {
    f << '[';
    bool first = true;
    for (const auto& t : tags) {
        if (first) {
            first = false;
        } else {
            f << ',';
        }
        f << '\"' << t << '\"';
    }
    f << ']';
}

void make_metadata_string(std::ostream& f,
                          const std::map<std::string, std::string>& globals) {
    f << "{";
    bool first = true;
    for (const auto& g : globals) {
        if (first) {
            first = false;
        } else {
            f << ',';
        }
        f << '\"' << g.first << "\":" << '\"' << g.second << '\"';
    }
    f << "}";
}

void fast_dump_ct_server(std::ostream& f, const zsearch::CTServerStatus ctss) {
    f << "{";
    if (ctss.index() > 0) {
        f << "\"index\":" << ctss.index();
        f << ",\"added_to_ct_at\":";
        fast_dump_utc_unix_timestamp(f, ctss.ct_timestamp());
        f << ",\"ct_to_censys_at\":";
        fast_dump_utc_unix_timestamp(f, ctss.pull_timestamp());
        if (ctss.push_timestamp()) {
            f << ",\"censys_to_ct_at\":";
            fast_dump_utc_unix_timestamp(f, ctss.push_timestamp());
        }
    }
    f << "}";
}

void fast_dump_ct(std::ostream& f, const zsearch::CTStatus cts) {
    f << "{";
    f << "\"censys_dev\":";
    fast_dump_ct_server(f, cts.censys_dev());
    f << ",\"censys\":";
    fast_dump_ct_server(f, cts.censys());
    f << ",\"google_aviator\":";
    fast_dump_ct_server(f, cts.google_aviator());
    f << ",\"google_daedalus\":";
    fast_dump_ct_server(f, cts.google_daedalus());
    f << ",\"google_pilot\":";
    fast_dump_ct_server(f, cts.google_pilot());
    f << ",\"google_rocketeer\":";
    fast_dump_ct_server(f, cts.google_rocketeer());
    f << ",\"google_icarus\":";
    fast_dump_ct_server(f, cts.google_icarus());
    f << ",\"google_skydiver\":";
    fast_dump_ct_server(f, cts.google_skydiver());
    f << ",\"google_submariner\":";
    fast_dump_ct_server(f, cts.google_submariner());
    f << ",\"google_testtube\":";
    fast_dump_ct_server(f, cts.google_testtube());
    f << ",\"digicert_ct1\":";
    fast_dump_ct_server(f, cts.digicert_ct1());
    f << ",\"digicert_ct2\":";
    fast_dump_ct_server(f, cts.digicert_ct2());
    f << ",\"izenpe_com_ct\":";
    fast_dump_ct_server(f, cts.izenpe_com_ct());
    f << ",\"izenpe_eus_ct\":";
    fast_dump_ct_server(f, cts.izenpe_eus_ct());
    f << ",\"symantec_ws_ct\":";
    fast_dump_ct_server(f, cts.symantec_ws_ct());
    f << ",\"symantec_ws_vega\":";
    fast_dump_ct_server(f, cts.symantec_ws_vega());
    f << ",\"symantec_ws_deneb\":";
    fast_dump_ct_server(f, cts.symantec_ws_deneb());
    f << ",\"symantec_ws_sirius\":";
    fast_dump_ct_server(f, cts.symantec_ws_sirius());
    f << ",\"wosign_ctlog\":";
    fast_dump_ct_server(f, cts.wosign_ctlog());
    f << ",\"cnnic_ctserver\":";
    fast_dump_ct_server(f, cts.cnnic_ctserver());
    f << ",\"gdca_ct\":";
    fast_dump_ct_server(f, cts.gdca_ct());
    f << ",\"startssl_ct\":";
    fast_dump_ct_server(f, cts.startssl_ct());
    f << ",\"venafi_api_ctlog\":";
    fast_dump_ct_server(f, cts.venafi_api_ctlog());
    f << ",\"venafi_api_ctlog_gen2\":";
    fast_dump_ct_server(f, cts.venafi_api_ctlog_gen2());
    f << ",\"nordu_ct_plausible\":";
    fast_dump_ct_server(f, cts.nordu_ct_plausible());
    f << ",\"comodo_dodo\":";
    fast_dump_ct_server(f, cts.comodo_dodo());
    f << ",\"comodo_mammoth\":";
    fast_dump_ct_server(f, cts.comodo_mammoth());
    f << ",\"comodo_sabre\":";
    fast_dump_ct_server(f, cts.comodo_sabre());
    f << ",\"gdca_ctlog\":";
    fast_dump_ct_server(f, cts.gdca_ctlog());
    f << ",\"sheca_ct\":";
    fast_dump_ct_server(f, cts.sheca_ct());
    f << ",\"certificatetransparency_cn_ct\":";
    fast_dump_ct_server(f, cts.certificatetransparency_cn_ct());
    f << ",\"letsencrypt_ct_clicky\":";
    fast_dump_ct_server(f, cts.letsencrypt_ct_clicky());

    f << "}";
}

void fast_dump_repeated_bytes(
        std::ostream& f,
        const google::protobuf::RepeatedPtrField<std::string>& sha256fps) {
    f << "[";
    bool first = true;
    for (const auto& p : sha256fps) {
        if (first) {
            first = false;
        } else {
            f << ",";
        }
        f << "\"" << util::Strings::hex_encode(p) << "\"";
    }
    f << "]";
    return;
}

void fast_dump_path(std::ostream& f, const zsearch::Path& path) {
    return fast_dump_repeated_bytes(f, path.sha256fp());
}

void fast_dump_root_store_status(
        std::ostream& f,
        const zsearch::RootStoreStatus& rootStoreStatus) {
    f << "{";
    f << "\"valid\":" << (rootStoreStatus.valid() ? "true" : "false");
    f << ",\"was_valid\":" << (rootStoreStatus.was_valid() ? "true" : "false");
    f << ",\"trusted_path\":"
      << (rootStoreStatus.trusted_path() ? "true" : "false");
    f << ",\"had_trusted_path\":"
      << (rootStoreStatus.had_trusted_path() ? "true" : "false");
    f << ",\"blacklisted\":"
      << (rootStoreStatus.blacklisted() ? "true" : "false");
    f << ",\"whitelisted\":"
      << (rootStoreStatus.whitelisted() ? "true" : "false");
    f << ",\"type\":"
      << "\"" << translate_certificate_type(rootStoreStatus.type()) << "\"";
    if (rootStoreStatus.trusted_paths_size() > 0) {
        f << ",\"paths\":[";
        bool first = true;
        for (auto& p : rootStoreStatus.trusted_paths()) {
            if (first) {
                first = false;
            } else {
                f << ',';
            }
            f << "{\"path\":";
            fast_dump_path(f, p);
            f << '}';
        }
        f << "]";
    }
    f << ",\"in_revocation_set\":"
      << (rootStoreStatus.in_revocation_set() ? "true" : "false");
    if (rootStoreStatus.parents_size() > 0) {
        f << ",\"parents\":";
        fast_dump_repeated_bytes(f, rootStoreStatus.parents());
    }
    f << "}";
}

void fast_dump_validation(
        std::ostream& f,
        const zsearch::CertificateValidation& certificateValidation) {
    f << "{";
    f << "\"nss\":";
    fast_dump_root_store_status(f, certificateValidation.nss());
    f << ",\"microsoft\":";
    fast_dump_root_store_status(f, certificateValidation.microsoft());
    f << ",\"apple\":";
    fast_dump_root_store_status(f, certificateValidation.apple());
    f << ",\"google_ct_primary\":";
    fast_dump_root_store_status(f, certificateValidation.google_ct_primary());
#if 0
    f << ",\"java\":";
    fast_dump_root_store_status(f, certificateValidation.java());
    f << ",\"android\":";
    fast_dump_root_store_status(f, certificateValidation.android());
#endif
    f << "}";
}

void fast_dump_utc_unix_timestamp(std::ostream& f, uint32_t unix_time) {
    std::time_t t = static_cast<std::time_t>(unix_time);
    char buf[1024];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", std::gmtime(&t));
    f << "\"" << buf << "\"";
}

void fast_dump_certificate_metadata(std::ostream& f,
                                    const zsearch::Certificate& c,
                                    uint32_t added_at,
                                    uint32_t updated_at) {
    f << "{";
    f << "\"updated_at\":";
    fast_dump_utc_unix_timestamp(f, updated_at);
    f << ",\"added_at\":";
    fast_dump_utc_unix_timestamp(f, added_at);
    f << ",\"post_processed\":" << (c.post_processed() ? "true" : "false");
    f << ",\"seen_in_scan\":" << (c.seen_in_scan() ? "true" : "false");
    f << ",\"source\":" << '"' << translate_certificate_source(c.source())
      << '"';
    if (c.post_processed()) {
        if (c.post_process_timestamp()) {
            f << ",\"post_processed_at\":";
            fast_dump_utc_unix_timestamp(f, c.post_process_timestamp());
        }
        f << ",\"parse_version\":" << std::to_string(c.parse_version());
        if (!c.parse_error().empty()) {
            f << ",\"parse_error\":" << '"' << c.parse_error() << '"';
        }
        f << ",\"parse_status\":" << '"'
          << translate_certificate_parse_status(c.parse_status()) << '"';
    }
    f << "}";
}

void fast_dump_certificate(std::ostream& f,
                           const zsearch::Certificate& certificate,
                           const std::set<std::string>& tags,
                           uint32_t added_at,
                           uint32_t updated_at) {
    f << "{";
    f << "\"raw\":\"" << base64_encode(certificate.raw()) << "\"";
    if (certificate.parse_status() == CERTIFICATE_PARSE_STATUS_SUCCESS ||
        (certificate.parse_status() == CERTIFICATE_PARSE_STATUS_RESERVED &&
         certificate.parsed() != "")) {
        f << ",\"parsed\":" << certificate.parsed();
    }
    f << ",\"metadata\":";
    fast_dump_certificate_metadata(f, certificate, added_at, updated_at);

    if (tags.size() > 0) {
        f << ",\"tags\":";
        make_tags_string(f, tags);
    }

    if (certificate.post_process_timestamp() > 0) {
        // Dump validation
        f << ",\"validation\":";
        fast_dump_validation(f, certificate.validation());
    }

    if (certificate.parents_size() > 0) {
        f << ",\"parents\":";
        fast_dump_repeated_bytes(f, certificate.parents());
    }

    f << ",\"ct\":";
    fast_dump_ct(f, certificate.ct());

    f << ",\"precert\":" << (certificate.is_precert() ? "true" : "false");

    f << "}" << std::endl;
}

std::set<std::string> build_certificate_tags_from_record(
        const zsearch::AnonymousRecord& rec) {
    std::set<std::string> tags;
    // Tags from the record, on the off chance any are defined.
    for (const auto& t : rec.tags()) {
        tags.insert(t);
    }
    for (const auto& p : rec.userdata().public_tags()) {
        tags.insert(p);
    }

    // Add "standardized" tags based on values set in the certificate.

    // CT
    const zsearch::Certificate& c = rec.certificate();
    if (c.is_precert()) {
        tags.insert("precert");
    }
    if (certificate_has_ct_info(c)) {
        tags.insert("ct");
    }
    if (certificate_has_google_ct(c)) {
        tags.insert("google-ct");
    }

    // Validation
    if (c.post_processed()) {
        if (certificate_has_valid_set(c)) {
            tags.insert("valid");
        }
        if (certificate_has_was_valid_set(c)) {
            tags.insert("valid");
        }
        certificate_add_types_to_set(c, &tags);
    }

    // Audit
    if (certificate_has_ccadb(c)) {
        tags.insert("ccadb");
    }

    // Parseability
    if (c.post_processed() && c.parsed().empty()) {
        tags.insert("unparseable");
    }

    // TODO: Add validation level (DV, OV, EV, etc.). This is currently only
    // accessible by parsing "parsed".

    // TODO: Add self-signed vs untrusted. Self-signed is currently only
    // accessible by parsing "parsed".

    // Expiration
    if (c.not_valid_before() && c.not_valid_after()) {
        if (c.expired()) {
            tags.insert("expired");
        } else {
            tags.insert("unexpired");
        }
    }
    return tags;
}

std::string dump_certificate_to_json_string(
        const zsearch::AnonymousRecord& rec) {
    // Build tags from the record.
    std::set<std::string> tags = build_certificate_tags_from_record(rec);

    // Write metadata, tags, and the certificate to JSON.
    std::ostringstream f;
    fast_dump_certificate(f, rec.certificate(), tags, rec.added_at(),
                          rec.updated_at());
    return f.str();
}

void dump_proto_with_timestamp(std::ostream& f,
                               std::string data,
                               uint32_t timestamp) {
    // remove closing } and dump
    data.pop_back();
    f << data;
    // if no data, then don't need to add a comma
    if (data != "{") {
        f << ", ";
    }
    f << "\"timestamp\":";
    fast_dump_utc_unix_timestamp(f, timestamp);
    f << "}";
}

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
                         Json::FastWriter& fastWriter) {
    auto has_protocol_atom = std::find_if(records.begin(), records.end(),
                                          [](const zsearch::Record& r) {
                                              switch (r.data_oneof_case()) {
                                                  case zsearch::Record::kAtom:
                                                      return true;
                                                  default:
                                                      break;
                                              }
                                              return false;
                                          });
    if (has_protocol_atom == records.end()) {
        return;
    }

    std::string ipstr = make_ip_str(ip);
    f << "{\"ip\":\"" << ipstr << "\",";
    f << "\"ipint\":" << ntohl(ip) << ",";
    if (!domain.empty()) {
        f << "\"domain\":\"" << domain << "\",";
    }
    if (alexa_rank > 0) {
        f << "\"alexa_rank\":" << alexa_rank << ",";
    }

    int lastport = -1;
    int lastproto = -1;
    int lastsubproto = -1;

    for (zsearch::Record& r : records) {
        // create new port clause
        if (r.port() != lastport) {
            if (lastport >= 0) {  // if there was a previous port, must close
                f << "}},";
            }
            f << "\"p" << ntohs((uint16_t) r.port())
              << "\":{";     // great we're in a new port clause
            lastproto = -1;  // mark this as the first protocol in the series
            lastsubproto = -1;
        }
        if (r.protocol() != lastproto) {
            if (lastproto >= 0) {  // if there was a previous proto, must close
                f << "},";
            }
            // great now we can add a new protocol
            f << "\"" << get_proto_name(r.protocol()) << "\":{";
            lastsubproto = -1;
        }
        // ok now we're in a protocol. woo. add a subprotocol. If there was
        // a previous subprotocol in this protocol, we must add a comma,
        if (lastsubproto >= 0) {
            f << ",";
        }
        // we've taken care of anything before. now we can add the subproto
        f << "\"" << get_subproto_name(r.protocol(), r.subprotocol()) << "\":";
        dump_proto_with_timestamp(f, r.atom().data(), r.timestamp());

        lastport = r.port();
        lastproto = r.protocol();
        lastsubproto = r.subprotocol();
    }
    // we need to close both proto and subproto
    f << "}}";
    // records done. add metadata and tags
    if (metadata.size() > 0) {
        f << ",\"metadata\":";
        make_metadata_string(f, metadata);
    }
    if (tags.size() > 0) {
        f << ",\"tags\":";
        make_tags_string(f, tags);
    }
    if (public_location_found && public_location.latitude() &&
        public_location.longitude()) {
        f << ",\"location\":";
        auto public_location_json = Json::Value(Json::objectValue);
        public_location_json["continent"] = public_location.continent();
        public_location_json["country"] = public_location.country();
        public_location_json["country_code"] = public_location.country_code();
        public_location_json["city"] = public_location.city();
        public_location_json["postal_code"] = public_location.postal_code();
        public_location_json["timezone"] = public_location.timezone();
        public_location_json["province"] = public_location.province();
        public_location_json["latitude"] = public_location.latitude();
        public_location_json["longitude"] = public_location.longitude();
        public_location_json["registered_country"] =
                public_location.registered_country();
        public_location_json["registered_country_code"] =
                public_location.registered_country_code();
        f << fastWriter.write(public_location_json);
    }
    // if (private_location_found) {
    //    f << ",\"__restricted_location\":";
    //    auto private_location_json = Json::Value(Json::objectValue);
    //    private_location_json["continent"] = private_location.continent();
    //    private_location_json["country"] = private_location.country();
    //    private_location_json["country_code"] =
    //    private_location.country_code();
    //    private_location_json["city"] = private_location.city();
    //    private_location_json["postal_code"] = private_location.postal_code();
    //    private_location_json["timezone"] = private_location.timezone();
    //    private_location_json["province"] = private_location.province();
    //    private_location_json["latitude"] = private_location.latitude();
    //    private_location_json["longitude"] = private_location.longitude();
    //    private_location_json["registered_country"] =
    //    private_location.registered_country();
    //    private_location_json["registered_country_code"] =
    //    private_location.registered_country_code();
    //    f << fastWriter.write(private_location_json);
    //}

    if (as_data_found) {
        f << ",\"autonomous_system\":";
        auto as_json = Json::Value(Json::objectValue);
        as_json["asn"] = as_data.asn();
        as_json["description"] = as_data.description();
        as_json["path"] = Json::Value(Json::arrayValue);
        for (const auto& path_elt : as_data.path()) {
            as_json["path"].append(path_elt);
        }
        // as_json["rir"] =
        as_json["routed_prefix"] = as_data.bgp_prefix();
        as_json["name"] = as_data.name();
        as_json["country_code"] = as_data.country_code();
        as_json["organization"] = as_data.organization();
        f << fastWriter.write(as_json);
    }
    // close IP address
    f << "}\n";
}
