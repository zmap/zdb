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
	c.set_not_valid_before(946684800); // 2000-01-01T00:00:00+00:00
	c.set_not_valid_after(1893456000); // 2030-01-01T00:00:00+00:00
	EXPECT_TRUE(certificate_valid_at(c, now));
}

}  // namespace zdb
