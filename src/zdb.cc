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

#include "zdb.h"

#include <cstdlib>
#include <sstream>

#include <rocksdb/db.h>

using namespace zdb;

bool erase_db_at_path(const std::string& path) {
#if 0
    // Check if it's actually a database
    rocksdb::DB* db = nullptr;
    rocksdb::Options options;
    options.create_if_missing = false;
    rocksdb::Status status = rocksdb::DB::Open(options, path, &db);
    
    // If it wasn't a database, it's already deleted!
    if (status.IsNotFound()) {
        return true;
    }
    
    // Couldn't open for some other reason, fail. Database is likely in use.
    if (!status.ok()) {
        return false;
    }
    delete db;
    
    // Actually found a database, delete it's directory
    std::stringstream ss;
    ss << "rm -rf " << path;
    int success = system(ss.str().c_str());
    if (success == 0) {
        return true;
    }
#endif

  return false;
}