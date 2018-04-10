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

#ifndef ZDB_SRC_CONFIGURATION_H
#define ZDB_SRC_CONFIGURATION_H

#include <memory>
#include <string>

#include <json/json.h>

#include <rocksdb/cache.h>
#include <rocksdb/env.h>

#include "anonymous_store.h"
#include "as_data.h"
#include "db.h"
#include "kafka_connection.h"
#include "macros.h"
#include "record.h"
#include "sharded_db.h"
#include "store.h"
#include "zdb.h"

namespace zdb {

const size_t kIPv4ShardCount = 256;
const size_t kCertificateShardCount = 256;

const std::string kIPv4InboundName = "ipv4";
const std::string kDomainInboundName = "domain";
const std::string kCertificateInboundName = "certificate";
const std::string kPubkeyInboundName = "pubkey";

const std::string kExternalCertificateInboundName = "ct_to_zdb";
const std::string kSCTInboundName = "scts";
const std::string kProcessedCertificateInboundName = "processed_certs";

const std::string kIPv4OutboundName = "ipv4_deltas";
const std::string kDomainOutboundName = "domain_deltas";
const std::string kCertificateOutboundName = "certificates_to_process";
const std::string kPubkeyOutboundName = "pubkey_deltas";
const std::string kProcessedCertificateOutboundName = "certificate_deltas";

// Reads a single JSON object as the contents of |filepath|, and loads the
// values in to |out|. Returns true if successful and false otherwise. The
// contents of |out| are unspecified when the function returns false.
bool load_json_from_file(const std::string& filepath, Json::Value* out);

struct ConfigValues {
  struct BasicDatabase {
    std::string db_path;
    size_t worker_threads = 0;
    bool enabled = true;

    bool should_open() const { return enabled && worker_threads > 0; }
  };

  struct InboundSource {
    size_t worker_threads = 0;
    bool enabled = true;

    bool should_open() const { return enabled && worker_threads > 0; }
  };

  BasicDatabase ipv4;
  BasicDatabase domain;
  BasicDatabase certificate;
  BasicDatabase pubkey;

  InboundSource external_certificate;
  InboundSource sct;
  InboundSource processed_cert;

  static bool from_json(const Json::Value& config, ConfigValues* out);
};

}  // namespace zdb

#endif /* ZDB_SRC_CONFIGURATION_H */
