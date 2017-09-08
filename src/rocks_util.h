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

#ifndef ZDB_SRC_ROCKS_UTILS_H
#define ZDB_SRC_ROCKS_UTILS_H

#include <memory>

#include <rocksdb/cache.h>
#include <rocksdb/options.h>

#include "util/file.h"

namespace zdb {

std::shared_ptr<rocksdb::Options> new_rocks_options(
    rocksdb::Env* env,
    std::shared_ptr<rocksdb::Cache> cache);

std::shared_ptr<rocksdb::Options> new_ipv4_rocks_options();

std::shared_ptr<rocksdb::Options> new_domain_rocks_options();

std::shared_ptr<rocksdb::Options> new_certificate_rocks_options();

// Returns true if the contents of `path` match the expected contents of a
// rocksdb folder with no extra data. We expect files in a rocksdb folder to be
// the following:
//   - *.log
//   - *.sst
//   - CURRENT
//   - IDENTITY
//   - LOCK
//   - LOG
//   - LOG.old.*
//   - MANIFEST-*
//
// There may also be a directory called lost/, which only contains *.sst
// files.
bool is_rocks_database_folder(const std::string& path);

bool rm_if_rocks_database_folder(const std::string& path, bool* did_delete);

}  // namespace zdb

#endif /* ZDB_SRC_ROCKS_UTILS_H */
