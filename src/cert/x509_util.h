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

#ifndef ZDB_SRC_CERT_X509_UTIL_H
#define ZDB_SRC_CERT_X509_UTIL_H

#include <openssl/x509.h>

#include "cert/hash.h"
#include "zsearch_definitions/anonstore.pb.h"

namespace zdb {

namespace cert {

bool X509_valid_parent(X509* parent, X509* child);

X509* certificate_to_X509(const zsearch::Certificate& cert);

SHA256Fingerprint X509_get_fingerprint_sha256(X509* c);

std::string X509_get_subject_string(X509* c);

std::string X509_get_issuer_string(X509* c);

bool X509_check_time_valid_now(X509* c);

}  // namespace cert

}  // namespace zdb

#endif /* ZDB_SRC_CERT_X509_UTIL_H */
