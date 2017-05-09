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

#include "as_data.h"

#include <gtest/gtest.h>
#include <fstream>

#include "macros.h"

using namespace zdb;
using namespace std;

namespace zdb {

namespace {

const std::string kASPrefix = "./src/test/data/as";
const std::string kValidPath = kASPrefix + "/valid_ases.json";
const std::string kAlsoValidPath = kASPrefix + "/also_valid_ases.json";
const std::string kMissingPath = kASPrefix + "/not-real-file.json";

TEST(ASTreeTest, LoadJSON) {
    {
        ASTree tree_missing;
        std::ifstream as_stream(kMissingPath);
        EXPECT_FALSE(tree_missing.load_json(as_stream));
        EXPECT_EQ(0U, tree_missing.size());
    }
    {
        ASTree tree_valid;
        std::ifstream as_stream(kValidPath);
        EXPECT_TRUE(tree_valid.load_json(as_stream));
        EXPECT_EQ(10U, tree_valid.size());
    }
}

TEST(ASTreeTest, ReloadJSON) {
    ASTree tree;
    ASTree::Handle h = tree.get_handle();

    std::ifstream first(kValidPath);
    EXPECT_TRUE(tree.load_json(first));
    EXPECT_EQ(10U, tree.size());

    ASTree::Lookup missing = h["97.90.0.0/19"];
    EXPECT_FALSE(missing.found);
    EXPECT_FALSE(missing.exact);

    std::ifstream second(kAlsoValidPath);
    EXPECT_TRUE(tree.load_json(second));
    EXPECT_EQ(10U, tree.size());

    ASTree::Lookup added = h["97.90.0.0/19"];
    EXPECT_TRUE(added.found);
    EXPECT_TRUE(added.exact);
    EXPECT_EQ("97.90.0.0/19", added.as_atom.bgp_prefix());
}

TEST(ASTreeTest, HandleLookup) {
    ASTree tree;
    ASTree::Handle h = tree.get_handle();

    std::ifstream as_stream(kValidPath);
    ASSERT_TRUE(tree.load_json(as_stream));

    ASTree::Lookup missing = h["1.2.3.4"];
    EXPECT_FALSE(missing.found);
    EXPECT_FALSE(missing.exact);

    ASTree::Lookup inner = h["91.242.136.1"];
    EXPECT_TRUE(inner.found);
    EXPECT_FALSE(inner.exact);
    EXPECT_EQ("91.242.136.0/24", inner.as_atom.bgp_prefix());

    ASTree::Lookup outer = h["91.242.137.1"];
    EXPECT_EQ("91.242.136.0/22", outer.as_atom.bgp_prefix());
    EXPECT_TRUE(inner.found);
    EXPECT_FALSE(inner.exact);

    ASTree::Lookup cidr = h["185.60.25.0/24"];
    EXPECT_TRUE(cidr.found);
    EXPECT_TRUE(cidr.exact);
    EXPECT_EQ("185.60.25.0/24", cidr.as_atom.bgp_prefix());
}

}  // namespace

}  // namespace zdb
