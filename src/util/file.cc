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

#include "util/file.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "defer.h"
#include "macros.h"

namespace zdb {

namespace util {

DirectoryEntry::DirectoryEntry(const std::string& name_, FileType file_type_)
    : name(name_), file_type(file_type_) {}

bool DirectoryEntry::operator==(const DirectoryEntry& other) const {
  return name == other.name && file_type == other.file_type;
}

Directory::Directory() = default;

bool Directory::open(const std::string& path) {
  // If we already have an open directory, don't open another.
  if (m_dir) {
    return false;
  }

  m_dir = opendir(path.c_str());
  if (m_dir) {
    m_path = path;
    return true;
  }
  return false;
}

std::vector<DirectoryEntry> Directory::entries() {
  // If we haven't opened a directory, return an empty vector.
  if (m_dir == nullptr) {
    return std::vector<DirectoryEntry>();
  }

  // Reset the directory pointer when done
  long start = telldir(m_dir);
  auto reset_dirp =
      defer([](DIR* d, long idx) { seekdir(d, idx); }, m_dir, start);

  // Iterate over every file in the directory using `readdir()`, and record
  // the results in `out`.
  struct dirent* de;
  std::vector<DirectoryEntry> out;
  while ((de = readdir(m_dir)) != nullptr) {
    DirectoryEntry entry;
#ifdef OS_MAC
    entry.name = std::string(de->d_name, de->d_namlen);
#else
    entry.name = std::string(de->d_name);
#endif

    // Ignore "." and ".." entries
    if (entry.name == "." || entry.name == "..") {
      continue;
    }

    std::string full_path = m_path + "/" + entry.name;

    struct stat path_stat;
    lstat(full_path.c_str(), &path_stat);
    if (S_ISREG(path_stat.st_mode)) {
      entry.file_type = FileType::FILE;
    } else if (S_ISDIR(path_stat.st_mode)) {
      entry.file_type = FileType::DIRECTORY;
    } else {
      entry.file_type = FileType::UNKNOWN;
    }

    // Add the entry to the output list
    out.push_back(entry);
  }
  return out;
}

bool Directory::rm(const DirectoryEntry& e) {
  if (e.file_type != FileType::FILE) {
    return false;
  }
  std::string full_path = m_path + "/" + e.name;
  int res = unlink(full_path.c_str());
  return res == 0;
}

bool Directory::rmdir() {
  if (m_dir) {
    closedir(m_dir);
    m_dir = nullptr;
  }
  int res = ::rmdir(m_path.c_str());
  return res == 0;
}

// static
const int Directory::MODE_755 = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;

// static
bool Directory::mkdir(const std::string& path, int mode) {
  int res = ::mkdir(path.c_str(), mode);
  return res == 0;
}

Directory::~Directory() {
  if (m_dir) {
    closedir(m_dir);
    m_dir = nullptr;
  }
}

}  // namespace util

}  // namespace zdb
