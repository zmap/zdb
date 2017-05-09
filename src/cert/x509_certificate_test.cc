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

#ifndef ZDB_SRC_CERT_X509_CERTIFICATE_TEST_H
#define ZDB_SRC_CERT_X509_CERTIFICATE_TEST_H

#include "x509_certificate.h"

#include <iostream>
#include <memory>
#include <string>

#include <gtest/gtest.h>

#include <openssl/pem.h>
#include <openssl/x509.h>

#include "cert/test_cert_util.h"

namespace zdb {

namespace cert {

namespace {

const std::string kDavidAdrianOrgHashHex =
        "4ce6f5464d355cabbedd60c29d2913f4c07fb3452f1c7bf9e6ce6c60c0917d9a";

std::string get_test_certificate_path(const std::string& cert_name) {
    return "./src/test/data/" + cert_name;
}

}  // namespace

TEST(X509CertificateTest, TestFromX509) {
    std::string cert_path = get_test_certificate_path("davidadrian.org.pem");
    X509* x = load_x509_from_pem(cert_path);
    ASSERT_TRUE(x);
    std::shared_ptr<X509Certificate> c = X509Certificate::from_X509(x);
    ASSERT_NE(nullptr, c);

    std::string subject = c->subject();
    EXPECT_EQ("CN=davidadrian.org", subject);
    std::string issuer = c->issuer();
    EXPECT_EQ("CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US", issuer);

    SHA256Fingerprint fp = c->fingerprint_sha256();
    SHA256Fingerprint expected_fp;
    ASSERT_TRUE(SHA256Fingerprint::from_hex_string(kDavidAdrianOrgHashHex,
                                                   &expected_fp));
    EXPECT_EQ(expected_fp, fp);

    EXPECT_FALSE(c->can_sign());
    EXPECT_FALSE(c->is_self_signed());
    EXPECT_EQ(0, c->parents().size());
};

TEST(X509CertificateTest, TestSelfSignedRoot) {
    std::string cert_path = get_test_certificate_path("isrgrootx1.pem");
    X509* x = load_x509_from_pem(cert_path);
    ASSERT_TRUE(x);
    std::shared_ptr<X509Certificate> c = X509Certificate::from_X509(x);
    ASSERT_NE(nullptr, c);

    std::string subject = c->subject();
    EXPECT_EQ("CN=ISRG Root X1,O=Internet Security Research Group,C=US",
              subject);
    std::string issuer = c->issuer();
    EXPECT_EQ(subject, issuer);

    EXPECT_TRUE(c->can_sign());
    EXPECT_TRUE(c->is_self_signed());
    EXPECT_EQ(0, c->parents().size());
}

TEST(X509CertificateTest, TestIntermediateRoot) {
    std::string cert_path =
            get_test_certificate_path("lets-encrypt-x3-cross-signed.pem");
    X509* x = load_x509_from_pem(cert_path);
    ASSERT_TRUE(x);
    std::shared_ptr<X509Certificate> c = X509Certificate::from_X509(x);
    ASSERT_NE(nullptr, c);

    std::string subject = c->subject();
    EXPECT_EQ("CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US", subject);
    std::string issuer = c->issuer();
    EXPECT_EQ("CN=DST Root CA X3,O=Digital Signature Trust Co.", issuer);

    EXPECT_TRUE(c->can_sign());
    EXPECT_FALSE(c->is_self_signed());
    EXPECT_EQ(0, c->parents().size());
}

}  // namespace cert

}  // namespace zdb

#endif /* ZDB_SRC_CERT_X509_CERTIFICATE_TEST_H */
