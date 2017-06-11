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

#include <gtest/gtest.h>
#include <iostream>
#include <json/json.h>

#include "fastjson.h"
#include "util/strings.h"
#include "zsearch_definitions/certificate.pb.h"

namespace zdb {

namespace {

const std::string kTestHexSHA256Fp =
        "98ea6e4f216f2fb4b69fff9b3a44842c38686ca685f3f55dc48c5d3fb1107be4";

}  // namespace

TEST(FastDumpPath, ValidJSON) {
    std::string b;
    ASSERT_TRUE(util::Strings::hex_decode(kTestHexSHA256Fp, &b));

    zsearch::Path p;
    p.add_sha256fp(b);

    std::ostringstream f;
    fast_dump_path(f, p);

    Json::Value root;
    Json::Reader reader;
    bool ok = reader.parse(f.str().c_str(), root);
    ASSERT_TRUE(ok);
    EXPECT_FALSE(root.isNull());
    EXPECT_TRUE(root.isArray());
    EXPECT_EQ(1, root.size());
    Json::Value first = root.get(Json::ArrayIndex(0), Json::nullValue);
    EXPECT_FALSE(first.isNull());
    EXPECT_TRUE(first.isString());
    EXPECT_EQ(kTestHexSHA256Fp, first.asString());
}

TEST(FastDumpRootStoreStatus, ValidJSONEmptyTrustedPathEmptyParents) {
    zsearch::RootStoreStatus rss;

    std::ostringstream f;
    fast_dump_root_store_status(f, rss);

    Json::Value root;
    Json::Reader reader;
    bool ok = reader.parse(f.str().c_str(), root);
    ASSERT_TRUE(ok);
    EXPECT_FALSE(root.isNull());
    EXPECT_TRUE(root.isObject());
    EXPECT_FALSE(root.isMember("parents"));
    EXPECT_FALSE(root.isMember("trusted_paths"));
}

TEST(FastDumpRootStoreStatus, ValidJSONTrustedPathEmptyParents) {
    zsearch::RootStoreStatus rss;

    // Add an unset path.
    rss.add_trusted_paths();

    std::ostringstream f;
    fast_dump_root_store_status(f, rss);

    Json::Value root;
    Json::Reader reader;
    bool ok = reader.parse(f.str().c_str(), root);
    ASSERT_TRUE(ok);
    EXPECT_FALSE(root.isNull());
    EXPECT_TRUE(root.isObject());
    EXPECT_FALSE(root.isMember("parents"));
    EXPECT_FALSE(root.isMember("trusted_paths"));
}

TEST(FastDumpRootStoreStatus, ValidJSONEmptyTrustedPathParents) {
    zsearch::RootStoreStatus rss;
    std::string b;
    ASSERT_TRUE(util::Strings::hex_decode(kTestHexSHA256Fp, &b));
    rss.add_parents(b);

    std::ostringstream f;
    fast_dump_root_store_status(f, rss);

    Json::Value root;
    Json::Reader reader;
    bool ok = reader.parse(f.str().c_str(), root);
    ASSERT_TRUE(ok);
    EXPECT_FALSE(root.isNull());
    EXPECT_TRUE(root.isObject());
    EXPECT_TRUE(root.isMember("parents"));
    EXPECT_FALSE(root.isMember("trusted_paths"));
}

TEST(FastDumpValidation, ValidJSON) {
    zsearch::CertificateValidation cv;

    std::ostringstream f;
    fast_dump_validation(f, cv);

    Json::Value root;
    Json::Reader reader;
    bool ok = reader.parse(f.str().c_str(), root);
    EXPECT_TRUE(ok);
}

TEST(FastDumpTime, CorrectTimezone) {
    uint32_t t = 946684800; // 2000-01-01T00:00:00+00:00
    std::ostringstream f;
    fast_dump_utc_unix_timestamp(f, t);
    EXPECT_EQ("\"2000-01-01 00:00:00\"", f.str());
}

TEST(BuildCertificateTags, Empty) {
    zsearch::AnonymousRecord rec;
    std::set<std::string> tags = build_certificate_tags_from_record(rec);
    for (const auto& k : tags) {
        std::cerr << k << std::endl;
    }
    EXPECT_EQ(0, tags.size());
}

}  // namespace zdb
