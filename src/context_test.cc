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

#include "context.h"

#include <memory>
#include <string>

#include <gtest/gtest.h>

#include "rocks_util.h"
#include "util/file.h"
#include "util/strings.h"

namespace zdb {

namespace {

const std::string kRocksContextTestPathBase = "/tmp/rocks_test";
const size_t kTestShardCount = 256;

std::string get_random_rocks_path() {
    std::string leaf =
            util::Strings::hex_encode(util::Strings::random_bytes(4));
    return kRocksContextTestPathBase + leaf;
}

}  // namespace

TEST(RocksContextTest, SetOptions) {
    RocksSingleContext rctx(kRocksContextTestPathBase);
    EXPECT_EQ(kRocksContextTestPathBase, rctx.path());
    EXPECT_EQ(nullptr, rctx.mutable_options());
    EXPECT_EQ(nullptr, rctx.shared_options());

    // Allocate and set a `rocksdb::Options` object, and confirm that `rctx`
    // points back at it.
    std::shared_ptr<rocksdb::Options> opt =
            std::make_shared<rocksdb::Options>();
    ASSERT_TRUE(opt != nullptr);
    rctx.set_options(opt);
    ASSERT_NE(nullptr, rctx.shared_options());
    EXPECT_EQ(opt.get(), rctx.mutable_options());
}

TEST(RocksSingleContextTest, OpenAndClose) {
    std::string path = get_random_rocks_path();
    RocksSingleContext rctx(path);
    EXPECT_EQ(path, rctx.path());
    std::shared_ptr<rocksdb::Options> opt =
            std::make_shared<rocksdb::Options>();
    opt->create_if_missing = true;
    rctx.set_options(opt);
    ASSERT_TRUE(rctx.open());
    EXPECT_NE(nullptr, rctx.raw_db_ptr());
    util::Directory d;
    ASSERT_TRUE(d.open(path));
    EXPECT_FALSE(d.entries().empty());
    rctx.close();
    bool did_delete = false;
    EXPECT_TRUE(rm_if_rocks_database_folder(path, &did_delete));
    EXPECT_TRUE(did_delete);
}

TEST(RocksShardedContextTest, OpenAndClose) {
    std::string path = get_random_rocks_path();
    RocksShardedContext rctx(path, kTestShardCount);
    std::shared_ptr<rocksdb::Options> opt =
            std::make_shared<rocksdb::Options>();
    opt->create_if_missing = true;
    rctx.set_options(opt);
    ASSERT_TRUE(rctx.open());
    EXPECT_FALSE(rctx.raw_db_ptr().empty());
    util::Directory d;
    EXPECT_TRUE(d.open(path));
    std::vector<util::DirectoryEntry> entries = d.entries();
    EXPECT_EQ(kTestShardCount, entries.size());
    for (const auto& e : entries) {
        EXPECT_EQ(2 * sizeof(size_t), e.name.size());
        std::string full_path = path + "/" + e.name;
        bool did_delete = false;
        EXPECT_TRUE(rm_if_rocks_database_folder(full_path, &did_delete));
        EXPECT_TRUE(did_delete);
    }
    EXPECT_TRUE(d.rmdir());
}

}  // namespace zdb
