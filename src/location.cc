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

#include <arpa/inet.h>
#include <maxminddb.h>

#include "location.h"
#include "utility.h"
#include "zmap/logger.h"
#include "zsearch_definitions/search.pb.h"

namespace zdb {

GeoIP::GeoIP() = default;

GeoIP::GeoIP(const std::string& path) : GeoIP() {
  open(path);
}

GeoIP::~GeoIP() {
  if (m_open) {
    MMDB_close(&m_db);
  }
}

bool GeoIP::open(const std::string& path) {
  int status = MMDB_open(path.c_str(), MMDB_MODE_MMAP, &m_db);
  m_open = (status == MMDB_SUCCESS);
  if (!m_open) {
    log_error("location", "unable to open location data at %s", path.c_str());
  }
  return m_open;
}

bool GeoIP::populate_atom(zsearch::LocationAtom* atom, uint32_t ip) const {
  // look up prev_key in MMDB
  int gai_error, mmdb_error;
  std::string ip_str = make_ip_str(ip);
  MMDB_lookup_result_s result =
      MMDB_lookup_string(&m_db, ip_str.c_str(), &gai_error, &mmdb_error);
  if (gai_error) {
    log_error("location", "error from getaddrinfo");
  }
  if (mmdb_error != MMDB_SUCCESS) {
    log_warn("location", "MMDB error %d", mmdb_error);
    atom->Clear();
    return false;
  }
  if (!result.found_entry) {
    atom->Clear();
    return false;
  }

  MMDB_entry_data_s entry_data;
  int status =
      MMDB_get_value(&result.entry, &entry_data, "city", "names", "en", NULL);
  if (status == MMDB_SUCCESS && entry_data.has_data) {
    atom->set_city(std::string(entry_data.utf8_string, entry_data.data_size));
  }

  status = MMDB_get_value(&result.entry, &entry_data, "continent", "names",
                          "en", NULL);
  if (status == MMDB_SUCCESS && entry_data.has_data) {
    atom->set_continent(
        std::string(entry_data.utf8_string, entry_data.data_size));
  }

  status = MMDB_get_value(&result.entry, &entry_data, "country", "names", "en",
                          NULL);
  if (status == MMDB_SUCCESS && entry_data.has_data) {
    atom->set_country(
        std::string(entry_data.utf8_string, entry_data.data_size));
  }

  status =
      MMDB_get_value(&result.entry, &entry_data, "country", "iso_code", NULL);
  if (status == MMDB_SUCCESS && entry_data.has_data) {
    atom->set_country_code(
        std::string(entry_data.utf8_string, entry_data.data_size));
  }

  status =
      MMDB_get_value(&result.entry, &entry_data, "city", "names", "en", NULL);
  if (status == MMDB_SUCCESS && entry_data.has_data) {
    atom->set_city(std::string(entry_data.utf8_string, entry_data.data_size));
  }

  status = MMDB_get_value(&result.entry, &entry_data, "postal", "code", NULL);
  if (status == MMDB_SUCCESS && entry_data.has_data) {
    atom->set_postal_code(
        std::string(entry_data.utf8_string, entry_data.data_size));
  }

  status =
      MMDB_get_value(&result.entry, &entry_data, "location", "time_zone", NULL);
  if (status == MMDB_SUCCESS && entry_data.has_data) {
    atom->set_timezone(
        std::string(entry_data.utf8_string, entry_data.data_size));
  }

  status = MMDB_get_value(&result.entry, &entry_data, "subdivisions", "0",
                          "names", "en", NULL);
  if (status == MMDB_SUCCESS && entry_data.has_data) {
    atom->set_province(
        std::string(entry_data.utf8_string, entry_data.data_size));
  }

  status =
      MMDB_get_value(&result.entry, &entry_data, "location", "latitude", NULL);
  if (status == MMDB_SUCCESS && entry_data.has_data) {
    atom->set_latitude(entry_data.double_value);
  }

  status =
      MMDB_get_value(&result.entry, &entry_data, "location", "longitude", NULL);
  if (status == MMDB_SUCCESS && entry_data.has_data) {
    atom->set_longitude(entry_data.double_value);
  }

  status = MMDB_get_value(&result.entry, &entry_data, "registered_country",
                          "names", "en", NULL);
  if (status == MMDB_SUCCESS && entry_data.has_data) {
    atom->set_registered_country(
        std::string(entry_data.utf8_string, entry_data.data_size));
  }

  status = MMDB_get_value(&result.entry, &entry_data, "registered_country",
                          "iso_code", NULL);
  if (status == MMDB_SUCCESS && entry_data.has_data) {
    atom->set_registered_country_code(
        std::string(entry_data.utf8_string, entry_data.data_size));
  }
  return true;
}

}  // namespace zdb
