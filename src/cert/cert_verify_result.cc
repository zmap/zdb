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

#include "cert/cert_verify_result.h"

namespace zdb {

namespace cert {

bool is_error_status(const CertificateStatus& cert_status) {
  return cert_status & CERT_STATUS_ALL_ERRORS;
}

CertificateVerifyResult::CertificateVerifyResult() = default;
CertificateVerifyResult::CertificateVerifyResult(
    const CertificateVerifyResult&) = default;

}  // namespace cert

}  // namespace zdb
