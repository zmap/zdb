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

#ifndef ZDB_SRC_CERT_CERT_STORE_TEST_H
#define ZDB_SRC_CERT_CERT_STORE_TEST_H

#include "cert/cert_store.h"
#include "cert/test_cert_util.h"

#include <string>

#include <gtest/gtest.h>

namespace zdb {

namespace cert {

namespace {

const std::string kCertPathPrefix = "./src/test/data/";
const std::string kLERootCertificatePath = kCertPathPrefix + "isrgrootx1.pem";
const std::string kLEIntermediatePath =
    kCertPathPrefix + "lets-encrypt-x3-cross-signed.pem";

const std::string kDavidAdrianOrgHashHex =
    "4ce6f5464d355cabbedd60c29d2913f4c07fb3452f1c7bf9e6ce6c60c0917d9a";
const std::string kDavidAdrianOrgPath = kCertPathPrefix + "davidadrian.org.pem";

const std::string kSelfSignedECDSA256Path =
    kCertPathPrefix + "self-signed-ecdsa-256.pem";

}  // namespace

class CertStoreLetsEncryptTest : public ::testing::Test {
 public:
  void SetUp() {
    std::shared_ptr<X509Certificate> root =
        X509Certificate_from_PEM(kLERootCertificatePath);
    ASSERT_NE(nullptr, root);
    m_store.add_root(root);
    EXPECT_EQ(1, m_store.root_size());

    std::shared_ptr<X509Certificate> intermediate =
        X509Certificate_from_PEM(kLEIntermediatePath);
    ASSERT_NE(nullptr, root);
    m_store.add_intermediate(intermediate);
    EXPECT_EQ(1, m_store.intermediate_size());
  }

 protected:
  CertStore m_store;
};

#if 0
TEST_F(CertStoreLetsEncryptTest, TestValidSingleChain) {
    std::shared_ptr<X509Certificate> leaf =
            X509Certificate_from_PEM(kDavidAdrianOrgPath);
    ASSERT_NE(nullptr, leaf);

    CertificateVerifyResult verify_result = m_store.verify_certificate(leaf);
    EXPECT_EQ(CERT_STATUS_OK, verify_result.cert_status);
    EXPECT_EQ(zsearch::CERTIFICATE_TYPE_LEAF, verify_result.cert_type);
}

TEST_F(CertStoreLetsEncryptTest, TestSelfSigned) {
    std::shared_ptr<X509Certificate> leaf =
            X509Certificate_from_PEM(kSelfSignedECDSA256Path);
    ASSERT_NE(nullptr, leaf);

    CertificateVerifyResult verify_result = m_store.verify_certificate(leaf);
    EXPECT_NE(CERT_STATUS_OK, verify_result.cert_status);
    EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_UNKNOWN_PARENT);
    EXPECT_EQ(zsearch::CERTIFICATE_TYPE_LEAF, verify_result.cert_type);
}

TEST_F(CertStoreLetsEncryptTest, TestIntermediate) {
    std::shared_ptr<X509Certificate> leaf =
            X509Certificate_from_PEM(kLEIntermediatePath);
    ASSERT_NE(nullptr, leaf);

    CertificateVerifyResult verify_result = m_store.verify_certificate(leaf);
    EXPECT_EQ(CERT_STATUS_OK, verify_result.cert_status);
    EXPECT_EQ(zsearch::CERTIFICATE_TYPE_INTERMEDIATE, verify_result.cert_type);
}

TEST_F(CertStoreLetsEncryptTest, TestRoot) {
    std::shared_ptr<X509Certificate> leaf =
            X509Certificate_from_PEM(kLERootCertificatePath);
    ASSERT_NE(nullptr, leaf);

    CertificateVerifyResult verify_result = m_store.verify_certificate(leaf);
    EXPECT_EQ(CERT_STATUS_OK, verify_result.cert_status);
    EXPECT_EQ(zsearch::CERTIFICATE_TYPE_ROOT, verify_result.cert_type);
}
#endif

}  // namespace cert

}  // namespace zdb

#endif /* ZDB_SRC_CERT_CERT_STORE_TEST_H */
