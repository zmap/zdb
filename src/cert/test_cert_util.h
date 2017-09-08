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

#ifndef ZDB_SRC_CERT_TEST_CERT_UTIL_H
#define ZDB_SRC_CERT_TEST_CERT_UTIL_H

#include <memory>
#include <string>

#include <openssl/x509.h>

#include "cert/x509_certificate.h"
#include "defer.h"

namespace zdb {

namespace cert {

::X509* load_x509_from_pem(const std::string& path);

std::shared_ptr<X509Certificate> X509Certificate_from_PEM(
    const std::string& path);

}  // namespace cert

}  // namespace zdb

#endif /* ZDB_SRC_CERT_TEST_CERT_UTIL_H */
