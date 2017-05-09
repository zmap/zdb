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

#ifndef ZDB_SRC_CERT_CERT_VERIFY_RESULT_H
#define ZDB_SRC_CERT_CERT_VERIFY_RESULT_H

#include "cert/x509_certificate.h"
#include "zsearch_definitions/anonstore.pb.h"

#include <openssl/x509.h>

namespace zdb {

namespace cert {

typedef uint32_t CertificateStatus;

// Valid/trusted; no errors
const uint32_t CERT_STATUS_OK = 0;

// 1 << 4 to 1 << 7 are reserved for errors that cause verification to be
// incomplete.
const uint32_t CERT_STATUS_INTERNAL_ERROR = 1 << 4;

// 1 << 8 to 1 << 15 are reserved for errors that might be ignored.
const uint32_t CERT_STATUS_EXPIRED = 1 << 8;
const uint32_t CERT_STATUS_EXPIRED_CERT_IN_CHAIN = 1 << 9;

// 1 << 16 and higher are reserved for errors.
const uint32_t CERT_STATUS_BLACKLISTED = 1 << 16;
const uint32_t CERT_STATUS_REVOKED = 1 << 17;
const uint32_t CERT_STATUS_UNKNOWN_PARENT = 1 << 18;
const uint32_t CERT_STATUS_UNTRUSTED_CHAIN = 1 << 19;

const uint32_t CERT_STATUS_ALL_ERRORS = 0xFFFF00F0;

bool is_error_status(const CertificateStatus& cert_status);

struct CertificateVerifyResult {
    CertificateVerifyResult();
    CertificateVerifyResult(const CertificateVerifyResult&);

    zsearch::CertificateType cert_type = zsearch::CERTIFICATE_TYPE_RESERVED;
    CertificateStatus cert_status = CERT_STATUS_OK;
};

struct ChainVerifyResult {
    CertificateVerifyResult cert_verify_result;
    CertChain chain;
};

}  // namespace cert

}  // namespace zdb

#endif /* ZDB_SRC_CERT_CERT_VERIFY_RESULT_H */
