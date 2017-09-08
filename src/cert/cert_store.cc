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

#include "cert/cert_store.h"

#include <algorithm>
#include <utility>

#include "cert/x509_certificate.h"
#include "cert/x509_util.h"
#include "zsearch_definitions/anonstore.pb.h"

namespace zdb {

namespace cert {

namespace {

bool does_link_up_to_root() {
  return false;
}

}  // namespace

CertPool::CertPool() = default;
CertPool::~CertPool() {}

void CertPool::add_cert(std::shared_ptr<X509Certificate> cert) {
  if (m_certs.find(cert) != m_certs.end()) {
    return;
  }
  m_certs.insert(cert);

  // Enable lookups by subject
  CertSet& subject_set = m_subjects[cert->subject()];
  subject_set.insert(cert);

  // Enable lookups by fingerprint.
  SHA256Fingerprint fp = cert->fingerprint_sha256();
  m_fingerprints[fp] = cert;
}

std::shared_ptr<X509Certificate> CertPool::has_cert(
    const std::shared_ptr<X509Certificate>& cert) const {
  auto it = m_certs.find(cert);
  if (it != m_certs.end()) {
    return *it;
  }
  return nullptr;
}

std::shared_ptr<X509Certificate> CertPool::has_cert(
    const SHA256Fingerprint& fp) const {
  auto it = m_fingerprints.find(fp);
  if (it != m_fingerprints.end()) {
    return it->second;
  }
  return nullptr;
}

CertSet CertPool::with_subject(const std::string& subject) const {
  auto it = m_subjects.find(subject);
  if (it != m_subjects.end()) {
    return it->second;
  }
  return CertSet();
}

CertStore::CertStore() = default;
CertStore::~CertStore() {}

void CertStore::add_root(std::shared_ptr<X509Certificate> cert) {
  m_roots.add_cert(std::move(cert));
}

void CertStore::add_intermediate(std::shared_ptr<X509Certificate> cert) {
  m_intermediates.add_cert(std::move(cert));
}

CertificateVerifyResult CertStore::verify_certificate(
    std::shared_ptr<X509Certificate> cert) {
  CertificateVerifyResult result;
  cert->clear_parents();

  // Check to make sure we actually have a certificate.
  X509* cx = X509Certificate::X509(*cert);
  if (!cx) {
    result.cert_status |= CERT_STATUS_INTERNAL_ERROR;
    return result;
  }

  // Check if this certificate is expired.
  if (!X509_check_time_valid_now(cx)) {
    result.cert_status |= CERT_STATUS_EXPIRED;
  }

  // Check if we're actually a root certificate. If we are, set certificate
  // type and then exit, since there will be no chains to validate.
  if (m_roots.has_cert(cert)) {
    result.cert_type = zsearch::CERTIFICATE_TYPE_ROOT;
    return result;
  }

  // Recursively make chains on all the parents
  CertSet seen_before;
  make_chains(cert, &seen_before);

  // Check if we're actually an intermediate certificate. If we are set
  // certificate type. We still need to validate, since not all intermediates
  // are trusted: they still have to chain to a certificate in |m_roots|. If
  // we're not an intermediate, then we must be a leaf.
  if (m_intermediates.has_cert(cert)) {
    result.cert_type = zsearch::CERTIFICATE_TYPE_INTERMEDIATE;
  }

  std::vector<ChainVerifyResult> chain_verify_results;
  for (auto it = cert->chains_begin(); it != cert->chains_end(); ++it) {
    chain_verify_results.emplace_back();
    auto& res = chain_verify_results.back();
    res.chain = *it;

    if (res.chain.size() == 0) {
      // Error
      res.cert_verify_result.cert_status |= CERT_STATUS_INTERNAL_ERROR;
      res.cert_verify_result.cert_type = zsearch::CERTIFICATE_TYPE_UNKNOWN;
    }

    if (res.chain.size() == 1) {
      // Simple case: there is no chain
      res.cert_verify_result.cert_status |= CERT_STATUS_UNKNOWN_PARENT;
      res.cert_verify_result.cert_type = zsearch::CERTIFICATE_TYPE_UNKNOWN;
      continue;
    }

    // Go through the chain
    for (auto it = res.chain.begin() + 1; it != res.chain.end(); ++it) {
      X509* x = X509Certificate::X509(**it);
      if (!X509_check_time_valid_now(x)) {
        res.cert_verify_result.cert_status |= CERT_STATUS_EXPIRED_CERT_IN_CHAIN;
      }
    }
  }

  return result;
}

CertSet CertStore::find_parents(
    const std::shared_ptr<X509Certificate>& cert) const {
  X509* cx = X509Certificate::X509(*cert);
  if (!cx) {
    return CertSet();
  }

  // Find all possible one-level parents
  CertSet matching_intermediates = m_intermediates.with_subject(cert->issuer());
  CertSet matching_roots = m_roots.with_subject(cert->issuer());

  CertSet possible_parents;
  std::set_union(matching_intermediates.begin(), matching_intermediates.end(),
                 matching_roots.begin(), matching_roots.end(),
                 std::inserter(possible_parents, possible_parents.begin()));

  // Check to see if any are actually parents
  CertSet parents;
  for (const auto& parent_candidate : possible_parents) {
    X509* px = X509Certificate::X509(*parent_candidate);
    if (!X509_valid_parent(px, cx)) {
      continue;
    }
    parents.insert(parent_candidate);
  }
  return parents;
}

void CertStore::make_chains(std::shared_ptr<X509Certificate> cert,
                            CertSet* seen_before) {
  // If we've already added parents for this certificate, don't do it again.
  if (seen_before->count(cert) != 0) {
    return;
  }
  seen_before->insert(cert);

  // Add all the parents
  CertSet parents = find_parents(cert);
  for (const auto& parent : parents) {
    cert->add_parent(parent);
    make_chains(parent, seen_before);
  }
}

}  // namespace cert

}  // namespace zdb
