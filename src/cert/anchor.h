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

#ifndef ZDB_SRC_CERT_ANCHOR_H
#define ZDB_SRC_CERT_ANCHOR_H

#include <memory>
#include <string>

#include "zsearch_definitions/anonstore.pb.h"
#include "cert/x509_certificate.h"

namespace zdb {

namespace cert {

struct Anchor {
    zsearch::CertificateType cert_type = zsearch::CERTIFICATE_TYPE_ROOT;
    bool trusted = false;
    std::shared_ptr<X509Certificate> certificate;
};

}  // namespace cert

}  // namespace zdb

namespace std {

template <>
struct less<::zdb::cert::Anchor> {
    using result_type = bool;
    using first_argument_type = ::zdb::cert::Anchor;
    using second_argument_type = first_argument_type;

    bool operator()(const first_argument_type& lhs,
                    const second_argument_type& rhs) const {
        return lhs.certificate < rhs.certificate;
    }
};

}  // namespace std

#endif /* ZDB_SRC_CERT_ANCHOR_H */
