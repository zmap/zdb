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
#include <json/json.h>
#include <iostream>

#include "certificates.h"
#include "fastjson.h"
#include "util/strings.h"
#include "zsearch_definitions/certificate.pb.h"

namespace zdb {

namespace {

const std::string kTestHexSHA256Fp =
        "98ea6e4f216f2fb4b69fff9b3a44842c38686ca685f3f55dc48c5d3fb1107be4";

const std::string kParents[] = {
        "731d3d9cfaa061487a1d71445a42f67df0afca2a6c2d2f98ff7b3ce112b1f568",
        "25847d668eb4f04fdd40b12b6b0740c567da7d024308eb6c2c96fe41d9de218d",
};
const size_t kParentsLen = 2;

const std::string kPathA[] = {
        "9f5c853220c6e2015390a38cd0cba8b3a5caac6344b9c9223ec3d2612a846d3d",
        "731d3d9cfaa061487a1d71445a42f67df0afca2a6c2d2f98ff7b3ce112b1f568",
        "96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6",
};
const size_t kPathALen = 3;

const std::string kPathB[] = {
        "9f5c853220c6e2015390a38cd0cba8b3a5caac6344b9c9223ec3d2612a846d3d",
        "25847d668eb4f04fdd40b12b6b0740c567da7d024308eb6c2c96fe41d9de218d",
        "0687260331a72403d909f105e69bcf0d32e1bd2493ffc6d9206d11bcd6770739",
};
const size_t kPathBLen = 3;

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

TEST(FastDumpRootStoreStatus, ValidJSON) {
    // TODO: If we add more tests to fast_dump_root_store_status, parts of this
    // test should be extracted out to a function. It's already very copy-paste
    // heavy.
    zsearch::RootStoreStatus rss;
    rss.set_valid(true);
    rss.set_was_valid(true);
    rss.set_trusted_path(true);
    rss.set_had_trusted_path(true);
    rss.set_blacklisted(false);
    rss.set_whitelisted(false);
    rss.set_type(zsearch::CERTIFICATE_TYPE_LEAF);
    zsearch::Path* path_a = rss.add_trusted_paths();
    for (size_t i = 0; i < kPathALen; ++i) {
        std::string b;
        ASSERT_TRUE(util::Strings::hex_decode(kPathA[i], &b));
        path_a->add_sha256fp(b);
    }
    zsearch::Path* path_b = rss.add_trusted_paths();
    for (size_t i = 0; i < kPathBLen; ++i) {
        std::string b;
        ASSERT_TRUE(util::Strings::hex_decode(kPathB[i], &b));
        path_b->add_sha256fp(b);
    }
    rss.set_in_revocation_set(false);
    for (size_t i = 0; i < kParentsLen; ++i) {
        std::string b;
        ASSERT_TRUE(util::Strings::hex_decode(kParents[i], &b));
        rss.add_parents(b);
    }

    std::ostringstream f;
    fast_dump_root_store_status(f, rss);

    Json::Value root;
    Json::Reader reader;
    bool ok = reader.parse(f.str().c_str(), root);
    ASSERT_TRUE(ok);
    EXPECT_EQ(rss.valid(), root["valid"].asBool());
    EXPECT_EQ(rss.was_valid(), root["was_valid"].asBool());
    EXPECT_EQ(rss.trusted_path(), root["trusted_path"].asBool());
    EXPECT_EQ(rss.had_trusted_path(), root["had_trusted_path"].asBool());
    EXPECT_EQ(rss.blacklisted(), root["blacklisted"].asBool());
    EXPECT_EQ(rss.whitelisted(), root["whitelisted"].asBool());
    EXPECT_EQ(translate_certificate_type(rss.type()), root["type"].asString());

    const Json::Value& paths = root["paths"];
    ASSERT_TRUE(paths.isArray());
    ASSERT_EQ(2, paths.size());
    const Json::Value& json_path_a =
            paths[static_cast<Json::ArrayIndex>(0)]["path"];
    ASSERT_TRUE(json_path_a.isArray());
    ASSERT_EQ(kPathALen, json_path_a.size());
    for (size_t i = 0; i < kPathALen; ++i) {
        Json::ArrayIndex idx = static_cast<Json::ArrayIndex>(i);
        EXPECT_EQ(kPathA[i], json_path_a[idx].asString());
    }
    const Json::Value& json_path_b =
            paths[static_cast<Json::ArrayIndex>(1)]["path"];
    ASSERT_TRUE(json_path_b.isArray());
    ASSERT_EQ(kPathBLen, json_path_b.size());
    for (size_t i = 0; i < kPathBLen; ++i) {
        Json::ArrayIndex idx = static_cast<Json::ArrayIndex>(i);
        EXPECT_EQ(kPathB[i], json_path_b[idx].asString());
    }

    const Json::Value& json_parents = root["parents"];
    ASSERT_TRUE(json_parents.isArray());
    ASSERT_EQ(kParentsLen, json_parents.size());
    for (size_t i = 0; i < kParentsLen; ++i) {
        Json::ArrayIndex idx = static_cast<Json::ArrayIndex>(i);
        EXPECT_EQ(kParents[idx], json_parents[idx].asString());
    }
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

TEST(FastDumpCertificateMetadata, ValidJSON) {
    uint32_t added_at = 725760000;            // 1992-12-31T00:00:00+00:00
    uint32_t updated_at = 1497190560;         // 2017-06-11T14:16:00+00:00
    uint32_t post_processed_at = 1497190530;  // 2017-06-11:14:15:30+00:00

    zsearch::Certificate c;
    c.set_post_processed(true);
    c.set_post_process_timestamp(post_processed_at);
    c.set_seen_in_scan(false);
    c.set_source(zsearch::CERTIFICATE_SOURCE_RESEARCH);
    c.set_parse_version(12);
    c.set_parse_error("a string with a \" in it");
    c.set_parse_status(zsearch::CERTIFICATE_PARSE_STATUS_NOT_PARSED);

    std::ostringstream f;
    Json::FastWriter writer;
    writer.omitEndingLineFeed();
    fast_dump_certificate_metadata(f, writer, c, added_at, updated_at);

    Json::Value root;
    Json::Reader reader;
    bool ok = reader.parse(f.str().c_str(), root);
    ASSERT_TRUE(ok);
    EXPECT_EQ("1992-12-31 00:00:00", root["added_at"].asString());
    EXPECT_EQ("2017-06-11 14:16:00", root["updated_at"].asString());
    EXPECT_EQ(c.post_processed(), root["post_processed"].asBool());
    EXPECT_EQ("2017-06-11 14:15:30", root["post_processed_at"].asString());
    EXPECT_EQ(c.seen_in_scan(), root["seen_in_scan"].asBool());
    EXPECT_EQ(translate_certificate_source(c.source()),
              root["source"].asString());
    EXPECT_EQ(c.parse_version(), root["parse_version"].asUInt());
    EXPECT_EQ(c.parse_error(), root["parse_error"].asString());
    EXPECT_EQ(translate_certificate_parse_status(c.parse_status()),
              root["parse_status"].asString());
}

TEST(FastDumpZLint, EmptyLints) {
    zsearch::ZLint zlint;

    std::ostringstream f;
    fast_dump_zlint(f, zlint);

    Json::Value root;
    Json::Reader reader;
    bool ok = reader.parse(f.str().c_str(), root);
    ASSERT_TRUE(ok);
    EXPECT_FALSE(root.isMember("lints"));
}

TEST(FastDumpZLint, ValidJSON) {
    zsearch::ZLint zlint;
    zlint.mutable_lints()
            ->mutable_e_basic_constraints_not_critical()
            ->set_result(zsearch::LINT_RESULT_ERROR);
    zlint.mutable_lints()->mutable_e_ian_bare_wildcard()->set_result(
            zsearch::LINT_RESULT_FATAL);
    zlint.mutable_lints()->mutable_w_multiple_issuer_rdn()->set_result(
            zsearch::LINT_RESULT_PASS);

    std::ostringstream f;
    fast_dump_zlint(f, zlint);

    Json::Value root;
    Json::Reader reader;
    bool ok = reader.parse(f.str().c_str(), root);
    ASSERT_TRUE(ok);

    EXPECT_EQ(zlint.version(), root["version"].asUInt());

    EXPECT_FALSE(root.isMember("infos_present"));
    EXPECT_EQ(zlint.notices_present(), root["notices_present"].asBool());
    EXPECT_EQ(zlint.warnings_present(), root["warnings_present"].asBool());
    EXPECT_EQ(zlint.errors_present(), root["errors_present"].asBool());
    EXPECT_EQ(zlint.fatals_present(), root["fatals_present"].asBool());

    const Json::Value& lints = root["lints"];
    ASSERT_TRUE(lints.isObject());
    EXPECT_EQ(3, lints.size());

    std::set<std::string> known_lint_status;
    for (int i = zsearch::LintResultStatus_MIN;
         i <= zsearch::LintResultStatus_MAX; ++i) {
        std::string s = translate_zlint_lint_result_status(i);
        known_lint_status.insert(s);
    }

    for (const Json::Value& lint : lints) {
        ASSERT_TRUE(lint.isString());
        EXPECT_NE("reserved", lint.asString());
        EXPECT_EQ(1, known_lint_status.count(lint.asString()));
    }

    EXPECT_EQ(translate_zlint_lint_result_status(zsearch::LINT_RESULT_ERROR),
              lints["e_basic_constraints_not_critical"].asString());
    EXPECT_EQ(translate_zlint_lint_result_status(zsearch::LINT_RESULT_FATAL),
              lints["e_ian_bare_wildcard"].asString());
    EXPECT_EQ(translate_zlint_lint_result_status(zsearch::LINT_RESULT_PASS),
              lints["w_multiple_issuer_rdn"].asString());
}

TEST(FastDumpTime, CorrectTimezone) {
    uint32_t t = 946684800;  // 2000-01-01T00:00:00+00:00
    std::ostringstream f;
    fast_dump_utc_unix_timestamp(f, t);
    EXPECT_EQ("\"2000-01-01 00:00:00\"", f.str());
}

TEST(BuildCertificateTags, Empty) {
    zsearch::AnonymousRecord rec;
    std::set<std::string> tags = build_certificate_tags_from_record(rec);
    EXPECT_EQ(0, tags.size());
}

TEST(BuildCertificateTags, Expired) {
    zsearch::AnonymousRecord rec;
    rec.mutable_certificate()->set_not_valid_before(1);
    rec.mutable_certificate()->set_not_valid_after(3);
    rec.mutable_certificate()->set_expired(true);
    std::set<std::string> tags = build_certificate_tags_from_record(rec);
    EXPECT_EQ(1, tags.size());
    EXPECT_EQ(1, tags.count("expired"));
}

}  // namespace zdb
