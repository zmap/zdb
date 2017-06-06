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

#include "util/strings.h"

#include <gtest/gtest.h>

namespace zdb {

namespace util {

struct StringsPredicateTestData {
    std::string input;
    bool expected_output;
};

class StringsPredicateTest
        : public testing::Test,
          public testing::WithParamInterface<StringsPredicateTestData> {};

class HasPrefixTest : public StringsPredicateTest {};

static const StringsPredicateTestData kHasPrefixLogDotOldTests[] = {
        {"", false},
        {"000095.log", false},
        {"CURRENT", false},
        {"IDENTITY", false},
        {"LOCK", false},
        {"LOG", false},
        {"LOG.old.1474217253159832", true},
        {"LOG.old.1474332524634350", true},
        {"LOG.old.1474395031238242", true},
        {"LOG.old.1474423656566745", true},
        {"LOG.old.1474477163364935", true},
        {"LOG.old.1474735078057861", true},
        {"LOG.old.1474740209641587", true},
        {"LOG.old.1475053345049320", true},
        {"LOG.old.1475053345051402", true},
        {"LOG.old.1475093388089829", true},
        {"LOG.old.1475095597456472", true},
        {"LOG.old.1475096487317580", true},
        {"LOG.old.1475098471872845", true},
        {"LOG.old.1475116366970944", true},
        {"LOG.old.1475116839049297", true},
        {"LOG.old.1475159782296425", true},
        {"LOG.old.1475333140893825", true},
        {"LOG.old.1475344257371580", true},
        {"LOG.old.1475353579679971", true},
        {"LOG.old.1475503434996257", true},
        {"LOG.old.1475692284017764", true},
        {"LOG.old.1475697111371518", true},
        {"LOG.old.1476201360511901", true},
        {"LOG.old.1476204023916574", true},
        {"LOG.old.1476223961529005", true},
        {"LOG.old.1476300542048593", true},
        {"LOG.old.1476317172095808", true},
        {"LOG.old.1476376319363092", true},
        {"LOG.old.1476462511610127", true},
        {"LOG.old.1476563527377516", true},
        {"LOG.old.1476647715425291", true},
        {"LOG.old.1476667350685774", true},
        {"LOG.old.1476722349439113", true},
        {"LOG.old.1476823878686815", true},
        {"MANIFEST-000094", false}};

TEST_P(HasPrefixTest, HasPrefixLogDotOld) {
    StringsPredicateTestData test = GetParam();
    EXPECT_EQ(test.expected_output,
              Strings::has_prefix("LOG.old.", test.input));
}

INSTANTIATE_TEST_CASE_P(Strings,
                        HasPrefixTest,
                        testing::ValuesIn(kHasPrefixLogDotOldTests));

class HasSuffixTest : public StringsPredicateTest {};

static const StringsPredicateTestData kHasSuffixDotLogTests[] = {
        {".log", true},
        {".log.old", false},
        {"averylongnamefulloflettersandcharacters.log", true},
        {"log", false},
        {"og", false},
        {"g", false},
        {"", false},
        {"l", false},
        {"lo", false}};

TEST_P(HasSuffixTest, HasSuffixDotLog) {
    StringsPredicateTestData test = GetParam();
    EXPECT_EQ(test.expected_output, Strings::has_suffix(".log", test.input));
}

INSTANTIATE_TEST_CASE_P(Strings,
                        HasSuffixTest,
                        testing::ValuesIn(kHasSuffixDotLogTests));

struct HexDecodeTestData {
    std::string input;
    bool expected_result;
    std::string expected_output;
};

class HexDecodeTest : public testing::Test,
                      public testing::WithParamInterface<HexDecodeTestData> {};

static const HexDecodeTestData kHexDecodeTests[] = {
        {"", true, ""},
        {"0", false, ""},
        {"abf", false, ""},
        {"fg", false, ""},
        {"FF", true, "\xFF"},
        {"01020304", true, "\x01\x02\x03\x04"},
        {"a2c1615816029636903a8172775682e8bbb84c6fde8d74b6de1e198f19f95c72",
         true,
         "\xa2\xc1\x61\x58\x16\x02\x96\x36\x90\x3a\x81\x72\x77\x56\x82\xe8\xbb\xb8\x4c\x6f\xde\x8d\x74\xb6\xde\x1e\x19\x8f\x19\xf9\x5c\x72"},
        {"01", true, "\x01"}};

TEST_P(HexDecodeTest, Match) {
    HexDecodeTestData test = GetParam();
    std::string output;
    bool result = Strings::hex_decode(test.input, &output);
    EXPECT_EQ(test.expected_result, result);
    if (test.expected_result) {
        EXPECT_EQ(test.expected_output, output);
    }
}

INSTANTIATE_TEST_CASE_P(Strings,
                        HexDecodeTest,
                        testing::ValuesIn(kHexDecodeTests));

}  // namespace util

}  // namespace zdb
