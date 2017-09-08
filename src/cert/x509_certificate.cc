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

#include "cert/x509_certificate.h"

#include "cert/x509_util.h"

#include <openssl/x509v3.h>

namespace zdb {

namespace cert {

X509Certificate::X509Certificate() {}

X509Certificate::~X509Certificate() {
  if (m_x509) {
    X509_free(m_x509);
  }
}

// static
X509* X509Certificate::X509(const X509Certificate& cert) {
  return cert.m_x509;
}

// static
std::shared_ptr<X509Certificate> X509Certificate::from_X509(::X509* x) {
  std::shared_ptr<X509Certificate> cert(new X509Certificate);
  cert->m_x509 = x;

  cert->m_subject = X509_get_subject_string(x);
  cert->m_issuer = X509_get_issuer_string(x);
  cert->m_fingerprint_sha256 = X509_get_fingerprint_sha256(x);
  cert->m_can_sign = (X509_check_ca(x) != 0);
  cert->m_is_self_signed = X509_valid_parent(x, x);
  return cert;
}

// static
std::shared_ptr<X509Certificate> X509Certificate::from_values(
    const std::string& subject,
    const std::string& issuer,
    const SHA256Fingerprint& fingerprint,
    bool can_sign) {
  std::shared_ptr<X509Certificate> cert(new X509Certificate);
  cert->m_x509 = nullptr;

  cert->m_subject = subject;
  cert->m_issuer = issuer;
  cert->m_fingerprint_sha256 = fingerprint;
  cert->m_can_sign = can_sign;
  cert->m_is_self_signed = (subject == issuer);
  return cert;
}

}  // namespace cert

}  // namespace zdb
