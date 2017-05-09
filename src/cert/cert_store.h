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

#ifndef ZDB_SRC_CERT_CERT_STORE_H
#define ZDB_SRC_CERT_CERT_STORE_H

#include <map>
#include <memory>
#include <set>
#include <vector>

#include "cert/anchor.h"
#include "cert/cert_verify_result.h"
#include "cert/hash.h"
#include "cert/x509_certificate.h"

namespace zdb {

namespace cert {

class CertPool {
  public:
    CertPool();
    ~CertPool();

    void add_cert(std::shared_ptr<X509Certificate> cert);

    std::shared_ptr<X509Certificate> has_cert(
            const std::shared_ptr<X509Certificate>& cert) const;
    std::shared_ptr<X509Certificate> has_cert(
            const SHA256Fingerprint& fp) const;

    size_t size() const { return m_certs.size(); }

    CertSet with_subject(const std::string& subject) const;

  private:
    CertSet m_certs;
    std::map<std::string, CertSet> m_subjects;
    std::map<SHA256Fingerprint, std::shared_ptr<X509Certificate>>
            m_fingerprints;
};

class CertStore {
  public:
    CertStore();
    virtual ~CertStore();

    void add_root(std::shared_ptr<X509Certificate> cert);
    void add_intermediate(std::shared_ptr<X509Certificate> cert);

    size_t root_size() const { return m_roots.size(); }
    size_t intermediate_size() const { return m_intermediates.size(); }

    CertificateVerifyResult verify_certificate(
            std::shared_ptr<X509Certificate> cert);

  private:
    CertSet find_parents(const std::shared_ptr<X509Certificate>&) const;
    void make_chains(std::shared_ptr<X509Certificate> cert,
                     CertSet* seen_before);

    CertPool m_roots;
    CertPool m_intermediates;
};

}  // namespace cert

}  // namespace zdb

#endif  // ZDB_SRC_CERT_CERT_STORE_H
