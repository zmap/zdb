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

#ifndef ZDB_SRC_SHARDER_H
#define ZDB_SRC_SHARDER_H

#include <string>

namespace zdb {

template <typename key_type>
class Sharder {
  public:
    virtual size_t total_shards() const = 0;
    virtual size_t shard_for(const key_type& k) const = 0;
    virtual key_type first_of(size_t shard_id) const = 0;
};

template <typename key_type>
class OneSharder : public Sharder<key_type> {
  public:
    virtual size_t total_shards() const override { return 1; }
    virtual size_t shard_for(const key_type& k) const override { return 0; }
};

}  // namespace zdb

#endif /* ZDB_SRC_SHARDER_H */
