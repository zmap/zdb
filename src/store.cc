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

#include "store.h"

using namespace zdb;
using namespace std;

std::hash<::zsearch::AnonymousKey> std::equal_to<::zsearch::AnonymousKey>::h;
std::hash<::zsearch::AnonymousKey> std::less<::zsearch::AnonymousKey>::h;

StoreResult::StoreResult() : success(false) {}

StoreResult::StoreResult(StoreResult&& rhs) {
  success = rhs.success;
  delta.Swap(&rhs.delta);
}

StoreResult& StoreResult::operator=(StoreResult&& rhs) {
  success = rhs.success;
  delta.Swap(&rhs.delta);
  return *this;
}

StoreResult StoreResult::failure() {
  StoreResult out;
  return out;
}

StoreResult StoreResult::no_change() {
  StoreResult out;
  out.success = true;
  out.delta.set_delta_type(zsearch::DT_NO_CHANGE);
  out.delta.set_version(0);
  return out;
}

StoreResult StoreResult::from_key(const zdb::IPv4Key& key) {
  StoreResult out;
  out.delta.set_ip(key.ip);
  return out;
}

StoreResult StoreResult::from_key(const zdb::DomainKey& key) {
  StoreResult out;
  out.delta.set_domain(key.domain);
  return out;
}

PruneCheck::PruneCheck() : should_prune(false) {}

PruneCheck::PruneCheck(PruneCheck&& rhs) {
  should_prune = rhs.should_prune;
  anon_key.Swap(&rhs.anon_key);
}

PruneCheck& PruneCheck::operator=(PruneCheck&& rhs) {
  should_prune = rhs.should_prune;
  anon_key.Swap(&rhs.anon_key);
  return *this;
}

PruneCheck PruneCheck::no_prune() {
  PruneCheck ret;
  return ret;
}

void PruneStatistics::merge(const zdb::PruneStatistics& other) {
  if (!other.success) {
    success = false;
  }
  records_pruned += other.records_pruned;
  records_read += other.records_read;
  std::for_each(other.pruned_per_key.begin(), other.pruned_per_key.end(),
                [this](const std::pair<zsearch::AnonymousKey, size_t>& proto) {
                  pruned_per_key[proto.first] += proto.second;
                });
}
