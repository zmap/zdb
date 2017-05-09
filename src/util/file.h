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

#ifndef ZDB_SRC_UTIL_FILE_H
#define ZDB_SRC_UTIL_FILE_H

#include <cstdio>
#include <string>
#include <vector>

#include <dirent.h>

namespace zdb {

namespace util {

enum class FileType {
    UNKNOWN,
    FILE,
    DIRECTORY,
};

struct DirectoryEntry {
    DirectoryEntry() = default;
    DirectoryEntry(const std::string& name_, FileType file_type_);
    DirectoryEntry(const DirectoryEntry&) = default;

    std::string name;
    FileType file_type = FileType::UNKNOWN;

    bool operator==(const DirectoryEntry& other) const;
};

class Directory {
  public:
    Directory();
    bool open(const std::string& path);
    std::vector<DirectoryEntry> entries();

    bool rm(const DirectoryEntry& d);
    bool rmdir();

    const std::string& path() const { return m_path; }

    static const int MODE_755;
    static bool mkdir(const std::string& path, int mode = MODE_755);
    static bool exists(const std::string& path);

    ~Directory();

  private:
    DIR* m_dir = nullptr;
    std::string m_path;
};

}  // namespace util

}  // namespace zdb

#endif /* ZDB_SRC_UTIL_FILE_H */
