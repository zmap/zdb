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

#include "cert/test_cert_util.h"

#include <openssl/pem.h>
#include <openssl/x509.h>

namespace zdb {

namespace cert {

::X509* load_x509_from_pem(const std::string& path) {
  FILE* fp = fopen(path.c_str(), "r");
  auto deferred_close = defer([fp]() {
    if (fp) {
      fclose(fp);
    }
  });
  if (!fp) {
    return nullptr;
  }
  return PEM_read_X509(fp, NULL, NULL, NULL);
}

std::shared_ptr<X509Certificate> X509Certificate_from_PEM(
    const std::string& path) {
  X509* x = load_x509_from_pem(path);
  if (!x) {
    return nullptr;
  }
  return X509Certificate::from_X509(x);
}

}  // namespace cert

}  // namespace zdb
