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

#include "as_data.h"

#include <atomic>
#include <cassert>
#include <iostream>
#include <list>
#include <string>

#include <json/json.h>

#include <zmap/logger.h>

using namespace std;

namespace zdb {

namespace {
const ASTree::Lookup kLookupFailure{};
const uint32_t kMaskSingleHost(0xFFFFFFFFU);

void ASData_free(ASData* as_data) {
  iptree_destroy(as_data->iptree);
  delete as_data;
}

}  // namespace

ASTree::ASTree() = default;

bool ASTree::load_json(std::ifstream& as_stream) {
  std::shared_ptr<ASData> new_data = load_json_impl(as_stream);
  if (new_data == nullptr) {
    return false;
  }
  std::atomic_store(&m_as_data, new_data);
  return true;
}

size_t ASTree::size() const {
  std::shared_ptr<ASData> as_data = std::atomic_load(&m_as_data);
  if (as_data == nullptr) {
    return 0;
  }
  return as_data->atoms.size();
}

ASTree::Lookup::Lookup(Lookup&& other)
    : found(other.found), exact(other.exact) {
  as_atom.Swap(&other.as_atom);
}

// static
const ASTree::Lookup& ASTree::Lookup::failure() {
  return kLookupFailure;
}

ASTree::Handle::Handle(std::shared_ptr<ASData>* as_data_ptr)
    : m_as_data_ptr(as_data_ptr) {}

ASTree::Lookup ASTree::Handle::operator[](uint32_t ip) const {
  if (m_as_data_ptr == nullptr) {
    return Lookup::failure();
  }
  std::shared_ptr<ASData> as_data = std::atomic_load(m_as_data_ptr);
  if (as_data == nullptr) {
    return Lookup::failure();
  }
  assert(as_data->iptree);
  auto* closest_match = iptree_lookup_best(as_data->iptree, ip);
  if (closest_match == nullptr) {
    return Lookup::failure();
  }
  char* raw_data_ptr = closest_match->data;
  assert(raw_data_ptr);
  zsearch::ASAtom* as_atom = reinterpret_cast<zsearch::ASAtom*>(raw_data_ptr);
  Lookup ret;
  ret.found = true;
  ret.exact = (closest_match->mask == kMaskSingleHost);
  ret.as_atom = *as_atom;
  return ret;
}

ASTree::Lookup ASTree::Handle::operator[](const std::string& ip) const {
  uint32_t ip_int, mask;
  if (iptree_parse_cidr(ip.c_str(), &ip_int, &mask) != EXIT_SUCCESS) {
    return Lookup::failure();
  }
  if (m_as_data_ptr == nullptr) {
    return Lookup::failure();
  }
  std::shared_ptr<ASData> as_data = std::atomic_load(m_as_data_ptr);
  if (as_data == nullptr) {
    return Lookup::failure();
  }
  assert(as_data->iptree);
  const auto* closest_match = iptree_lookup_best(as_data->iptree, ip_int);
  if (closest_match == nullptr) {
    return Lookup::failure();
  }
  char* raw_data_ptr = closest_match->data;
  assert(raw_data_ptr);
  const zsearch::ASAtom* as_atom =
      reinterpret_cast<const zsearch::ASAtom*>(raw_data_ptr);
  Lookup ret;
  ret.found = true;
  ret.as_atom = *as_atom;
  if (closest_match->mask == mask && closest_match->prefix == (ip_int & mask)) {
    ret.exact = true;
  }
  return ret;
}

ASTree::Handle ASTree::get_handle() {
  Handle h(&m_as_data);
  return h;
}

std::shared_ptr<ASData> ASTree::load_json_impl(std::ifstream& as_stream) {
  if (!as_stream) {
    log_error("ASTree", "as_stream empty");
    return nullptr;
  }

  std::shared_ptr<ASData> new_as_data(new ASData, &ASData_free);
  new_as_data->iptree = iptree_create();
  while (as_stream) {
    std::string line;
    std::getline(as_stream, line);

    // Skip empty lines (or newline at end of file)
    if (line.size() == 0) {
      continue;
    }

    Json::Value as_document;
    Json::Reader reader;
    if (!reader.parse(line, as_document)) {
      log_error("ASTree", "could not parse json: %s", line.c_str());
      return nullptr;
    }
    new_as_data->atoms.emplace_back();
    zsearch::ASAtom& as_atom = new_as_data->atoms.back();
    as_atom.set_asn(as_document["asn"].asUInt());
    as_atom.set_description(as_document["description"].asString());
    as_atom.set_bgp_prefix(as_document["bgp_prefix"].asString());
    if (as_document["name"].asString() != "") {
      as_atom.set_name(as_document["name"].asString());
    }
    if (as_document["country_code"].asString() != "") {
      as_atom.set_country_code(as_document["country_code"].asString());
    }
    if (as_document["organization"].asString() != "") {
      as_atom.set_organization(as_document["organization"].asString());
    }
    if (as_document["rir"].asString() != "") {
      zsearch::RegionalRegistrar rir;
      RegionalRegistrar_Parse(as_document["rir"].asString().substr(4), &rir);
      as_atom.set_rir(rir);
    }
    for (Json::ArrayIndex i = 0; i < as_document["path"].size(); ++i) {
      as_atom.add_path(as_document["path"][i].asUInt());
    }
    iptree_insert_str(new_as_data->iptree,
                      as_document["bgp_prefix"].asCString(),
                      reinterpret_cast<char*>(&as_atom));
  }
  return new_as_data;
}

}  // namespace zdb
