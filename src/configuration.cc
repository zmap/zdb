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

#include "configuration.h"

#include <cassert>
#include <iomanip>
#include <set>
#include <sstream>

#include <gflags/gflags.h>

#include <zmap/logger.h>

namespace zdb {

const char* QUEUES_KEY = "queues";
const char* DELTA_QUEUE_KEY = "delta_redis_queue";
const char* DB_PATH_KEY = "db_path";
const char* WORKER_THREADS_KEY = "threads";
const char* BLOCK_CACHE_SIZE_KEY = "block_cache_size";
const char* ENABLED_KEY = "enabled";

namespace {

bool config_read_optional_boolean(const Json::Value& subconfig,
                                  const std::string& key,
                                  bool* out) {
  const Json::Value& obj = subconfig[key];
  if (obj.isNull()) {
    return true;
  }
  if (!obj.isBool()) {
    log_error("config", "not a bool at key %s", key.c_str());
    return false;
  }
  *out = obj.asBool();
  return true;
}

bool config_read_string(const Json::Value& subconfig,
                        const std::string& key,
                        std::string* out) {
  const Json::Value& obj = subconfig[key];
  if (!obj.isString()) {
    log_error("config", "not a string at key %s", key.c_str());
    return false;
  }
  *out = obj.asString();
  return true;
}

bool config_read_size_t(const Json::Value& subconfig,
                        const std::string& key,
                        size_t* out) {
  const Json::Value& obj = subconfig[key];
  if (!obj.isUInt()) {
    log_error("config", "not an unsigned int at key %s", key.c_str());
    return false;
  }
  *out = obj.asUInt64();
  return true;
}

bool config_read_object(const Json::Value& subconfig,
                        const std::string& key,
                        Json::Value* out) {
  const Json::Value& obj = subconfig[key];
  if (!obj.isObject()) {
    log_error("config", "non-oject at key %s", key.c_str());
    return false;
  }
  *out = obj;
  return true;
}

bool config_read_basic_database(const Json::Value& subconfig,
                                const std::string& key,
                                ConfigValues::BasicDatabase* out) {
  Json::Value c;
  if (!config_read_object(subconfig, key, &c)) {
    return false;
  }
  if (!config_read_string(c, DB_PATH_KEY, &out->db_path)) {
    log_error("config", "could not read %s for %s", DB_PATH_KEY, key.c_str());
    return false;
  }
  if (!config_read_size_t(c, WORKER_THREADS_KEY, &out->worker_threads)) {
    log_error("config", "could not read %s for %s", WORKER_THREADS_KEY,
              key.c_str());
    return false;
  }
  out->enabled = true;
  if (!config_read_optional_boolean(c, ENABLED_KEY, &out->enabled)) {
    log_error("config", "could not read %s for %s", ENABLED_KEY, key.c_str());
    return false;
  }
  return true;
}

bool config_read_inbound_source(const Json::Value& subconfig,
                                const std::string& key,
                                ConfigValues::InboundSource* out) {
  Json::Value c;
  if (!config_read_object(subconfig, key, &c)) {
    return false;
  }
  if (!config_read_size_t(c, WORKER_THREADS_KEY, &out->worker_threads)) {
    log_error("config", "could not read %s for %s", WORKER_THREADS_KEY,
              key.c_str());
    return false;
  }
  out->enabled = true;
  if (!config_read_optional_boolean(c, ENABLED_KEY, &out->enabled)) {
    log_error("config", "could not read %s for %s", ENABLED_KEY, key.c_str());
    return false;
  }
  return true;
}

}  // namespace

bool load_json_from_file(const std::string& filepath, Json::Value* out) {
  std::ifstream config_file(filepath, std::ifstream::binary);
  if (!config_file) {
    return false;
  }
  try {
    config_file >> *out;
  } catch (Json::Exception& e) {
    log_error("json", "%s", e.what());
    return false;
  }
  return true;
}

// static
bool ConfigValues::from_json(const Json::Value& config, ConfigValues* out) {
  Json::Value queue_config;
  if (!config_read_object(config, QUEUES_KEY, &queue_config)) {
    return false;
  }

  // Read the databases
  if (!config_read_basic_database(queue_config, "ipv4", &out->ipv4)) {
    return false;
  }
  if (!config_read_basic_database(queue_config, "domain", &out->domain)) {
    return false;
  }
  if (!config_read_basic_database(queue_config, "certificate",
                                  &out->certificate)) {
    return false;
  }
  if (!config_read_basic_database(queue_config, "pubkey", &out->pubkey)) {
    return false;
  }

  // Read the extra inbound sources
  if (!config_read_inbound_source(queue_config, "external_certificate",
                                  &out->external_certificate)) {
    return false;
  }
  if (!config_read_inbound_source(queue_config, "sct", &out->sct)) {
    return false;
  }
  if (!config_read_inbound_source(queue_config, "processed_certs",
                                  &out->processed_cert)) {
    return false;
  }

  return true;
}

}  // namespace zdb
