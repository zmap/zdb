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

#include "rocks_util.h"

#include <memory>

#include <rocksdb/cache.h>
#include <rocksdb/comparator.h>
#include <rocksdb/db.h>
#include <rocksdb/env.h>
#include <rocksdb/filter_policy.h>
#include <rocksdb/options.h>
#include <rocksdb/table.h>

#include "record.h"
#include "util/file.h"
#include "util/strings.h"

namespace zdb {

using util::Directory;
using util::DirectoryEntry;
using util::FileType;
using util::Strings;

namespace {

const size_t kDefaultCacheSize = 1024 * 1024 * 1024;

bool is_rocks_file(const DirectoryEntry& entry) {
  if (entry.file_type != FileType::FILE) {
    return false;
  }

  const std::string& name = entry.name;
  if (name == "CURRENT" || name == "IDENTITY" || name == "LOCK" ||
      name == "LOG") {
    return true;
  }
  if (Strings::has_suffix(".log", name)) {
    return true;
  }
  if (Strings::has_suffix(".sst", name)) {
    return true;
  }
  if (Strings::has_prefix("LOG.old.", name)) {
    return true;
  }
  if (Strings::has_prefix("MANIFEST-", name)) {
    return true;
  }
  return false;
}

bool is_lost_folder(const DirectoryEntry& entry) {
  if (entry.file_type != FileType::DIRECTORY) {
    return false;
  }
  if (entry.name != "lost") {
    return false;
  }
  Directory d;
  if (!d.open(entry.name)) {
    return false;
  }
  std::vector<DirectoryEntry> subentries = d.entries();
  for (const auto& subentry : subentries) {
    if (subentry.file_type != FileType::FILE) {
      return false;
    }
    if (!Strings::has_suffix(".sst", subentry.name)) {
      return false;
    }
  }
  return true;
}

bool delete_rocks_folder(const std::string& path) {
  Directory d;
  if (!d.open(path)) {
    return false;
  }
  std::vector<DirectoryEntry> entries = d.entries();
  for (const auto& e : entries) {
    if (is_rocks_file(e)) {
      if (!d.rm(e)) {
        return false;
      }
    }
  }
  return d.rmdir();
}

}  // namespace

std::shared_ptr<rocksdb::Options> new_rocks_options(
    rocksdb::Env* env,
    std::shared_ptr<rocksdb::Cache> cache) {
  // Allocate the options
  std::shared_ptr<rocksdb::Options> opt(new rocksdb::Options);

  // Based on Github wiki page for total ordered SSD storage
  opt->env = env;
  opt->compaction_style = rocksdb::kCompactionStyleUniversal;
  opt->write_buffer_size = 67108864;  // 64MB
  opt->max_write_buffer_number = 3;
  opt->target_file_size_base = 67108864;  // 64MB
  opt->level0_file_num_compaction_trigger = 4;
  opt->level0_slowdown_writes_trigger = 8;
  opt->level0_stop_writes_trigger = 12;
  opt->num_levels = 4;
  opt->max_open_files = -1;
  opt->allow_os_buffer = true;

  // We use universal compaction style with all databases
  opt->OptimizeUniversalStyleCompaction();

  opt->create_if_missing = true;
  opt->comparator = rocksdb::BytewiseComparator();

  // Giant bloom filter FTW
  rocksdb::BlockBasedTableOptions table_options;
  auto filter_policy = rocksdb::NewBloomFilterPolicy(10, false);
  table_options.filter_policy.reset(filter_policy);
  table_options.block_cache = cache;
  auto table_factory = rocksdb::NewBlockBasedTableFactory(table_options);
  opt->table_factory.reset(table_factory);

  return opt;
}

std::shared_ptr<rocksdb::Options> new_ipv4_rocks_options() {
  rocksdb::Env* default_env = rocksdb::Env::Default();
  std::shared_ptr<rocksdb::Cache> cache =
      rocksdb::NewLRUCache(kDefaultCacheSize);
  std::shared_ptr<rocksdb::Options> opt = new_rocks_options(default_env, cache);
  opt->max_background_compactions = 1;
  opt->max_background_flushes = 1;
  opt->prefix_extractor = IPv4Key::prefix_extractor();
  return opt;
}

std::shared_ptr<rocksdb::Options> new_domain_rocks_options() {
  rocksdb::Env* default_env = rocksdb::Env::Default();
  std::shared_ptr<rocksdb::Cache> cache =
      rocksdb::NewLRUCache(kDefaultCacheSize);
  std::shared_ptr<rocksdb::Options> opt = new_rocks_options(default_env, cache);
  opt->prefix_extractor = DomainKey::prefix_extractor();
  opt->max_background_compactions = 11;
  opt->max_background_flushes = 1;
  return opt;
}

std::shared_ptr<rocksdb::Options> new_certificate_rocks_options() {
  rocksdb::Env* default_env = rocksdb::Env::Default();
  std::shared_ptr<rocksdb::Cache> cache =
      rocksdb::NewLRUCache(kDefaultCacheSize);
  std::shared_ptr<rocksdb::Options> opt = new_rocks_options(default_env, cache);
  opt->max_background_compactions = 11;  // XXX: This could be 23?
  opt->max_background_flushes = 1;
  opt->compaction_options_universal.max_size_amplification_percent = 50;
  return opt;
}

bool is_rocks_database_folder(const std::string& path) {
  Directory d;
  if (!d.open(path)) {
    return false;
  }
  std::vector<DirectoryEntry> entries = d.entries();
  for (const auto& e : entries) {
    switch (e.file_type) {
      case FileType::FILE:
        if (is_rocks_file(e)) {
          continue;
        }
        return false;
      default:
        return false;
    }
  }
  return true;
}

bool rm_if_rocks_database_folder(const std::string& path, bool* did_delete) {
  if (!is_rocks_database_folder(path)) {
    *did_delete = false;
    return true;
  }
  *did_delete = true;
  return delete_rocks_folder(path);
}

}  // namespace zdb
