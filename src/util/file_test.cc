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

#include <fstream>
#include <iostream>
#include <map>

#include <gtest/gtest.h>

#include "util/strings.h"

namespace zdb {

namespace util {

namespace {

const std::string kDirectoryTestPath = "./src/test/data/util/file";

std::string random_test_directory() {
    std::string leaf = Strings::hex_encode(Strings::random_bytes(4));
    return "/tmp/" + leaf;
}

}  // namespace

TEST(DirectoryTest, Open) {
    {
        Directory d;
        EXPECT_TRUE(d.open("."));
    }
    {
        Directory d;
        EXPECT_FALSE(d.open("./notadirectory"));
    }
    {
        Directory d;
        EXPECT_TRUE(d.open("."));
    }
    {
        Directory d;
        EXPECT_TRUE(d.open("/"));
    }
    {
        Directory d;
        EXPECT_TRUE(d.open(kDirectoryTestPath));
    }
}

TEST(DirectoryTest, UnopenedEntriesIsEmpty) {
    Directory d;
    auto unopened_entries = d.entries();
    EXPECT_TRUE(unopened_entries.empty());

    ASSERT_TRUE(d.open("."));
    auto opened_entries = d.entries();
    EXPECT_FALSE(opened_entries.empty());
}

// TODO: Fix clang formatting rule for this.
static const size_t kDirectoryEntryTestDataLength = 5;
static const DirectoryEntry kDirectoryEntryTestData[] = {
        {"a", FileType::FILE},
        {"b", FileType::FILE},
        {"c", FileType::FILE},
        {"d", FileType::DIRECTORY},
        {"l", FileType::UNKNOWN}};

TEST(DirectoryTest, EntriesListIsCorrect) {
    Directory d;
    ASSERT_TRUE(d.open("./src/test/data/util/file"));
    std::vector<DirectoryEntry> entries = d.entries();

    // Populate the set of expected entries by name.
    std::map<std::string, DirectoryEntry> expected_entries_by_name;
    for (size_t i = 0; i < kDirectoryEntryTestDataLength; ++i) {
        expected_entries_by_name[kDirectoryEntryTestData[i].name] =
                kDirectoryEntryTestData[i];
    }

    // Compare the entry list to the expected list.
    EXPECT_EQ(expected_entries_by_name.size(), entries.size());
    for (const DirectoryEntry& entry : entries) {
        const DirectoryEntry& expected = expected_entries_by_name[entry.name];
        EXPECT_EQ(expected, entry);
    }
}

TEST(DirectoryTest, CreateAndRemoveDirectory) {
    std::string test_path = random_test_directory();
    EXPECT_TRUE(Directory::mkdir(test_path));
    Directory d;
    ASSERT_TRUE(d.open(test_path));
    ASSERT_TRUE(d.entries().empty());
    {
        std::string p = test_path + "/empty_file";
        std::fstream empty_file;
        empty_file.open(p, std::ios::out);
        empty_file.close();
    }
    std::vector<DirectoryEntry> entries = d.entries();
    ASSERT_EQ(1, entries.size());
    ASSERT_TRUE(d.rm(entries.front()));
    EXPECT_TRUE(d.rmdir());
}

TEST(DirectoryTest, RemoveNonEmptyDirectoryFails) {
    Directory d;
    ASSERT_TRUE(d.open(kDirectoryTestPath));
    EXPECT_FALSE(d.rmdir());
}

}  // namespace util

}  // namespace zdb
