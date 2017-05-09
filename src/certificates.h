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

#ifndef ZDB_SRC_CERTIFICATES_H
#define ZDB_SRC_CERTIFICATES_H

#include <algorithm>
#include <memory>
#include <set>
#include <string>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

#include "zsearch_definitions/search.pb.h"

#include "macros.h"

namespace zdb {

struct CertificateSubjectIssuer {
    std::string subject;
    std::string issuer;
    std::string fingerprint_sha256;
    bool can_sign = false;
    bool self_signed = false;
};

struct cert_data {
    CertificateSubjectIssuer subject_issuer;
    std::shared_ptr<X509> X509_cert;
    bool is_valid;
    bool is_root;
};

struct CAStore {
    std::map<std::string, std::shared_ptr<cert_data>> by_fingerprint;
    std::map<std::string, std::set<std::shared_ptr<cert_data>>> by_subject;

    bool check_root(const CertificateSubjectIssuer& subject_issuer) {
        auto it = by_fingerprint.find(subject_issuer.fingerprint_sha256);
        if (it == by_fingerprint.end()) {
            return false;
        }
        return it->second->is_root;
    }
};

bool valid_parent(X509* parent, X509* child);

X509* certificate_to_x509(const zsearch::Certificate& cert);

CertificateSubjectIssuer x509_get_subject_issuer(X509* c);

std::string x509_get_fingerprint_sha256(X509* c);

std::string x509_get_subject_string(X509* c);

std::string x509_get_issuer_string(X509* c);

bool x509_check_time_valid_now(X509* c);

}  // namespace zdb

namespace std {

template <>
struct less<::zdb::CertificateSubjectIssuer> {
    using result_type = bool;
    using first_argument_type = ::zdb::CertificateSubjectIssuer;
    using second_argument_type = first_argument_type;

    bool operator()(const first_argument_type& lhs,
                    const second_argument_type& rhs) const {
        return lhs.fingerprint_sha256 < rhs.fingerprint_sha256;
    }
};

template <>
struct less<::zdb::cert_data> {
    using result_type = bool;
    using first_argument_type = ::zdb::cert_data;
    using second_argument_type = first_argument_type;

    bool operator()(const first_argument_type& lhs,
                    const second_argument_type& rhs) const {
        return lhs.subject_issuer.fingerprint_sha256 <
               rhs.subject_issuer.fingerprint_sha256;
    }
};

}  // namespace std

#endif /* ZDB_SRC_CERTIFICATES_H */
