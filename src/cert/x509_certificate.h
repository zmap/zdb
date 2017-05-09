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

#ifndef ZDB_SRC_CERT_X509_CERTIFICATE_H
#define ZDB_SRC_CERT_X509_CERTIFICATE_H

#include <memory>
#include <set>
#include <string>
#include <vector>

#include <openssl/x509.h>

#include "cert/hash.h"

namespace zdb {

namespace cert {

class X509Certificate;
using CertSet = std::set<std::shared_ptr<X509Certificate>>;
using CertChain = std::vector<std::shared_ptr<X509Certificate>>;

class X509Certificate {
  public:
    X509Certificate(const X509Certificate&) = delete;
    ~X509Certificate();

    std::string subject() const { return m_subject; }
    std::string issuer() const { return m_issuer; }
    SHA256Fingerprint fingerprint_sha256() const {
        return m_fingerprint_sha256;
    }

    bool can_sign() const { return m_can_sign; }
    bool is_self_signed() const { return m_is_self_signed; }

    void set_parents(const CertSet& parents) { m_parents = parents; }
    void add_parent(std::shared_ptr<X509Certificate> c) {
        m_parents.insert(std::move(c));
    }
    void clear_parents() { m_parents.clear(); }
    const CertSet& parents() const { return m_parents; }

    static ::X509* X509(const X509Certificate& cert);
    static std::shared_ptr<X509Certificate> from_X509(::X509* x509);
    static std::shared_ptr<X509Certificate> from_PEM(const std::string& path);

    static std::shared_ptr<X509Certificate> from_values(
            const std::string& subject,
            const std::string& issuer,
            const SHA256Fingerprint& fingerprint,
            bool can_sign);

    class ChainIterator {
      public:
        using value_type = CertChain;

        ChainIterator() : m_leaf(nullptr) {}
        ChainIterator(const ChainIterator&) = default;
        ChainIterator(ChainIterator&&) = default;

        bool operator==(const ChainIterator& other) const {
            if ((m_leaf == nullptr) != (other.m_leaf == nullptr)) {
                return false;
            }
            if (m_leaf == nullptr && other.m_leaf == nullptr) {
                return true;
            }
            return m_leaf->fingerprint_sha256() ==
                           other.m_leaf->fingerprint_sha256() &&
                   m_stack == other.m_stack && m_chain == other.m_chain;
        }

        bool operator!=(const ChainIterator& other) const {
            return !(other == *this);
        }

        const value_type& operator*() const { return m_chain; }
        const value_type* operator->() const { return &m_chain; }

        ChainIterator& operator++() {
            next();
            return *this;
        }
        ChainIterator& operator++(int) = delete;
        ChainIterator& operator--() = delete;
        ChainIterator& operator--(int) = delete;

      private:
        using parent_iterator =
                std::set<std::shared_ptr<X509Certificate>>::iterator;

        ChainIterator(std::shared_ptr<X509Certificate> cert) : m_leaf(cert) {
            m_stack.push_back(cert);
            auto parent_it = cert->parents().begin();
            if (parent_it == cert->parents().end()) {
                m_leaf = nullptr;
                m_stack.clear();
            } else {
                m_parents.push_back(cert->parents().begin());
                roll_forward();
            }
        }

        void roll_back() {
            while (true) {
                if (m_parents.empty() || m_stack.empty()) {
                    break;
                }
                const auto& current_cert = m_stack.back();
                auto& parent_it = m_parents.back();
                ++parent_it;

                // If we're at the end of this parent iterator, get
                // the iterator for the next lower certificate.
                if (parent_it == current_cert->parents().end()) {
                    m_stack.pop_back();
                    m_parents.pop_back();
                    continue;
                }
                break;
            }
        }

        void roll_forward() {
            while (true) {
                if (m_parents.empty() || m_stack.empty()) {
                    return;
                }
                const auto& current_cert = m_stack.back();
                auto new_parents = current_cert->parents().begin();
                auto new_parents_end = current_cert->parents().end();

                // If there's at least one parent we haven't seen, we keep
                // building the chain from there. Otherwise, we need to do
                // an
                // extra roll_back().
                if (new_parents != new_parents_end) {
                    m_stack.push_back(*new_parents);
                    m_parents.push_back(new_parents);
                } else {
                    break;
                }
            }
        }

        void next() {
            // Invalid call
            if (m_stack.empty() || m_parents.empty()) {
                return;
            }
            const auto& current_cert = m_stack.back();
            m_stack.pop_back();
            m_parents.pop_back();
            roll_back();
            roll_forward();
            m_chain = m_stack;
            if (m_stack.empty() || m_parents.empty()) {
                m_leaf = nullptr;
                m_stack.clear();
                m_parents.clear();
                return;
            }
        }

        std::shared_ptr<X509Certificate> m_leaf;
        std::vector<std::shared_ptr<X509Certificate>> m_stack;
        std::vector<parent_iterator> m_parents;

        CertChain m_chain;
    };

    ChainIterator chains_begin() const { return ChainIterator(); }
    ChainIterator chains_end() const { return ChainIterator(); }

  private:
    X509Certificate();

    std::string m_subject;
    std::string m_issuer;

    SHA256Fingerprint m_fingerprint_sha256;

    bool m_can_sign = false;
    bool m_is_self_signed = false;

    ::X509* m_x509 = nullptr;
    CertSet m_parents;
};

}  // namespace cert

}  // namespace zdb

namespace std {

template <>
struct less<::zdb::cert::X509Certificate> {
    using result_type = bool;
    using first_argument_type = ::zdb::cert::X509Certificate;
    using second_argument_type = first_argument_type;

    bool operator()(const first_argument_type& lhs,
                    const second_argument_type& rhs) const {
        return lhs.fingerprint_sha256() < rhs.fingerprint_sha256();
    }
};

}  // namespace std

#endif /* ZDB_SRC_CERT_X509_CERTIFICATE_H */
