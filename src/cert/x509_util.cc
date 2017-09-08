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

#include "cert/x509_util.h"

#include <openssl/x509v3.h>

namespace zdb {

namespace cert {

bool X509_valid_parent(X509* parent, X509* child) {
  if (X509_check_issued(parent, child) == X509_V_OK) {
    EVP_PKEY* parent_key = X509_get_pubkey(parent);
    if (!parent_key) {
      return false;
    }
    int valid_sign = X509_verify(child, parent_key);
    if (valid_sign == 1) {
      EVP_PKEY_free(parent_key);
      return true;
    } else if (valid_sign == 0) {
      EVP_PKEY_free(parent_key);
      return false;
    } else {
      EVP_PKEY_free(parent_key);
      return false;
    }
  }
  return false;
}

X509* certificate_to_x509(const zsearch::Certificate& cert) {
  size_t raw_length = cert.raw().size();
  const unsigned char* data =
      reinterpret_cast<const unsigned char*>(cert.raw().data());
  X509* c = d2i_X509(NULL, &data, raw_length);
  return c;
}

SHA256Fingerprint X509_get_fingerprint_sha256(X509* c) {
  const EVP_MD* digest = EVP_sha256();
  unsigned len;
  SHA256Fingerprint result;

  int rc = X509_digest(c, digest, (unsigned char*) result.data, &len);
  assert(rc != 0);
  assert(len == SHA256Fingerprint::SIZE);
  return result;
}

std::string X509_get_subject_string(X509* c) {
  BIO* subject_bio = BIO_new(BIO_s_mem());
  X509_NAME_print_ex(subject_bio, X509_get_subject_name(c), 0, XN_FLAG_RFC2253);
  BUF_MEM* subject_buf;
  BIO_get_mem_ptr(subject_bio, &subject_buf);
  std::string subject(subject_buf->data, subject_buf->length);
  BIO_free(subject_bio);
  return subject;
}

std::string X509_get_issuer_string(X509* c) {
  BIO* issuer_bio = BIO_new(BIO_s_mem());
  X509_NAME_print_ex(issuer_bio, X509_get_issuer_name(c), 0, XN_FLAG_RFC2253);
  BUF_MEM* issuer_buf;
  BIO_get_mem_ptr(issuer_bio, &issuer_buf);
  std::string issuer(issuer_buf->data, issuer_buf->length);
  BIO_free(issuer_bio);
  return issuer;
}

bool X509_check_time_valid_now(X509* c) {
  time_t ptime = time(NULL);
  int not_before = X509_cmp_time(X509_get_notBefore(c), &ptime);
  int not_after = X509_cmp_time(X509_get_notAfter(c), &ptime);
  // check that results are valid comparison. if not, then reject.
  if (!(not_before && not_after)) {
    return false;
  }
  // not yet valid
  if (not_before > 0) {
    return false;
  }
  // expired
  if (not_after < 0) {
    return false;
  }
  return true;
}

}  // namespace cert

}  // namespace zdb
