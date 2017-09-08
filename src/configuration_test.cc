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
#include "macros.h"

#include <fstream>

#include <gtest/gtest.h>

#include <json/json.h>

namespace zdb {

namespace {

const std::string kTestConfigPrefix = "src/test/data/config/";

bool load_config_file(const std::string& filename, Json::Value* out_json) {
  std::string filepath = kTestConfigPrefix + filename;
  return load_json_from_file(filepath, out_json);
}

}  // namespace

TEST(ConfigurationValuesTest, ValidConfigurationLoads) {
  Json::Value j;
  bool load_ok = load_config_file("valid.json", &j);
  ASSERT_TRUE(load_ok);
  ConfigValues c;
  bool config_ok = ConfigValues::from_json(j, &c);
  EXPECT_TRUE(config_ok);
  EXPECT_EQ(1U, c.ipv4.worker_threads);
  EXPECT_EQ(2U, c.domain.worker_threads);
  EXPECT_EQ(3U, c.certificate.worker_threads);
  EXPECT_EQ(4U, c.pubkey.worker_threads);
  EXPECT_EQ(5U, c.external_certificate.worker_threads);
  EXPECT_EQ(6U, c.sct.worker_threads);

  EXPECT_EQ("ipv4", c.ipv4.db_path);
  EXPECT_EQ("domain", c.domain.db_path);
  EXPECT_EQ("certificate", c.certificate.db_path);
  EXPECT_EQ("pubkey", c.pubkey.db_path);

  EXPECT_TRUE(c.ipv4.enabled);
  EXPECT_TRUE(c.domain.enabled);
  EXPECT_TRUE(c.certificate.enabled);
  EXPECT_FALSE(c.pubkey.enabled);
  EXPECT_TRUE(c.external_certificate.enabled);
  EXPECT_FALSE(c.sct.enabled);
}

}  // namespace zdb
