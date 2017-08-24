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

#include "ipv4_sharder.h"

namespace zdb {

size_t IPv4Sharder::total_shards() const {
    return kTotalShards;
}

size_t IPv4Sharder::shard_for(const IPv4Key& k) const {
    // IP should be in network order
    return k.ip & kMask;
}

IPv4Key IPv4Sharder::first_of(size_t shard_id) const {
    assert(shard_id < kTotalShards);
    uint32_t b = static_cast<uint8_t>(shard_id);
    return IPv4Key(b, 0, 0, 0);
}

}  // namespace zdb
