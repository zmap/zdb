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

#include "certificates.h"
#include "zsearch_definitions/certificate.pb.h"

namespace zdb {

TEST(CertificateValidAt, InRange) {
  zsearch::Certificate c;
  c.set_not_valid_before(1);
  c.set_not_valid_after(3);
  EXPECT_TRUE(certificate_valid_at(c, 2));
}

TEST(CertificateValidAt, Before) {
  zsearch::Certificate c;
  c.set_not_valid_before(2);
  c.set_not_valid_after(4);
  EXPECT_FALSE(certificate_valid_at(c, 1));
}

TEST(CertificateValidAt, After) {
  zsearch::Certificate c;
  c.set_not_valid_before(1);
  c.set_not_valid_after(3);
  EXPECT_FALSE(certificate_valid_at(c, 4));
}

TEST(CertificateValidAt, Unset) {
  zsearch::Certificate c;
  EXPECT_FALSE(certificate_valid_at(c, 0));
  std::time_t now = std::time(nullptr);
  EXPECT_FALSE(certificate_valid_at(c, now));
}

TEST(CertificateValidAt, Now) {
  zsearch::Certificate c;
  std::time_t now = std::time(nullptr);
  c.set_not_valid_before(946684800);  // 2000-01-01T00:00:00+00:00
  c.set_not_valid_after(1893456000);  // 2030-01-01T00:00:00+00:00
  EXPECT_TRUE(certificate_valid_at(c, now));
}

TEST(CertificateHasCTInfo, Empty) {
  zsearch::Certificate c;
  EXPECT_FALSE(certificate_has_ct_info(c));
}

TEST(CertificateHasCTInfo, Last) {
  zsearch::Certificate c;
  c.mutable_ct()->mutable_letsencrypt_ct_clicky()->set_index(1);
  EXPECT_TRUE(certificate_has_ct_info(c));
}

TEST(CertificateHasGoogleCT, Empty) {
  zsearch::Certificate c;
  EXPECT_FALSE(certificate_has_google_ct(c));
}

TEST(CertificateHasGoogleCT, NonGoogle) {
  zsearch::Certificate c;
  c.mutable_ct()->mutable_symantec_ws_sirius()->set_index(1);
  EXPECT_FALSE(certificate_has_google_ct(c));
}

TEST(CertificateHasGoogleCT, HasGoogle) {
  zsearch::Certificate c;
  c.mutable_ct()->mutable_google_skydiver()->set_index(1);
  EXPECT_TRUE(certificate_has_google_ct(c));
}

TEST(CertificateHasValidSet, Empty) {
  zsearch::Certificate c;
  EXPECT_FALSE(certificate_has_valid_set(c));
}

TEST(CertificateHasValidSet, NSSOnly) {
  zsearch::Certificate c;
  c.mutable_validation()->mutable_nss()->set_valid(true);
  EXPECT_TRUE(certificate_has_valid_set(c));
}

TEST(CertificateHasValidSet, SeveralNonNSS) {
  zsearch::Certificate c;
  c.mutable_validation()->mutable_apple()->set_valid(true);
  c.mutable_validation()->mutable_microsoft()->set_valid(true);
  EXPECT_TRUE(certificate_has_valid_set(c));
}

TEST(CertificateHasValidSet, WasValidNotValid) {
  zsearch::Certificate c;
  c.mutable_validation()->mutable_nss()->set_was_valid(true);
  EXPECT_FALSE(certificate_has_valid_set(c));
}

TEST(CertificateHasWasValidSet, Empty) {
  zsearch::Certificate c;
  EXPECT_FALSE(certificate_has_was_valid_set(c));
}

TEST(CertificateHasWasValidSet, NSSOnly) {
  zsearch::Certificate c;
  c.mutable_validation()->mutable_nss()->set_was_valid(true);
  EXPECT_TRUE(certificate_has_was_valid_set(c));
}

TEST(CertificateHasWasValidSet, SeveralNonNSS) {
  zsearch::Certificate c;
  c.mutable_validation()->mutable_apple()->set_was_valid(true);
  c.mutable_validation()->mutable_microsoft()->set_was_valid(true);
  EXPECT_TRUE(certificate_has_was_valid_set(c));
}

TEST(CertificateHasWasValidSet, ValidButNotWasValid) {
  zsearch::Certificate c;
  c.mutable_validation()->mutable_nss()->set_valid(true);
  EXPECT_FALSE(certificate_has_was_valid_set(c));
}

TEST(CertificateAddTypesToSet, Empty) {
  zsearch::Certificate c;
  std::set<std::string> tags;
  certificate_add_types_to_set(c, &tags);
  EXPECT_EQ(0, tags.size());
}

TEST(CertificateAddTypesToSet, NSSOnly) {
  zsearch::Certificate c;
  std::set<std::string> tags;
  c.mutable_validation()->mutable_nss()->set_type(
      zsearch::CERTIFICATE_TYPE_INTERMEDIATE);
  certificate_add_types_to_set(c, &tags);
  EXPECT_EQ(1, tags.size());
  EXPECT_EQ(1, tags.count("intermediate"));
}

TEST(CertificateHasCCADB, Empty) {
  zsearch::Certificate c;
  EXPECT_FALSE(certificate_has_ccadb(c));
}

TEST(CertificateHasCCADB, WasMozillaSalesforce) {
  zsearch::Certificate c;
  c.mutable_audit()->mutable_mozilla()->set_was_in_roots(true);
  EXPECT_TRUE(certificate_has_ccadb(c));
}

TEST(CertificateHasCCADB, InMozillaSalesforceIntermediates) {
  zsearch::Certificate c;
  c.mutable_audit()->mutable_mozilla()->set_current_in_intermediates(true);
  EXPECT_TRUE(certificate_has_ccadb(c));
  c.mutable_audit()->mutable_mozilla()->set_was_in_intermediates(true);
  EXPECT_TRUE(certificate_has_ccadb(c));
}

TEST(CertificateHasCCADB, InMozillaSalesforceRoots) {
  zsearch::Certificate c;
  c.mutable_audit()->mutable_mozilla()->set_current_in_roots(true);
  EXPECT_TRUE(certificate_has_ccadb(c));

  c.Clear();
  c.mutable_audit()->mutable_mozilla()->set_was_in_roots(true);
  EXPECT_TRUE(certificate_has_ccadb(c));
  c.mutable_audit()->mutable_mozilla()->set_current_in_roots(true);
  EXPECT_TRUE(certificate_has_ccadb(c));
}

}  // namespace zdb
