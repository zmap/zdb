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

#include <cassert>
#include <memory>
#include <sstream>

#include <rocksdb/slice.h>
#include <rocksdb/slice_transform.h>

#include "record.h"
#include "utility.h"
#include "search.pb.h"
#include "protocols.pb.h"

using namespace zdb;
using rocksdb::Slice;
using rocksdb::SliceTransform;

IPv4Key::IPv4Key() : ip(0), port(0), proto(0), subproto(0) {}

IPv4Key::IPv4Key(uint32_t ip,
                 uint16_t port,
                 uint8_t protocol,
                 uint8_t subprotocol)
        : ip(ip), port(port), proto(protocol), subproto(subprotocol) {}

void IPv4Key::set_delta(zsearch::Delta& delta) const {
    delta.set_ip(ip);
}

IPv4Key IPv4Key::from_string(const std::string& raw) {
    auto k = reinterpret_cast<const bigendian_key*>(raw.data());
    IPv4Key out{k->ip, k->port, k->proto, k->subproto};
    return out;
}

IPv4Key IPv4Key::from_record(const zsearch::Record& r) {
    IPv4Key out;
    out.ip = r.ip();
    out.port = static_cast<uint16_t>(r.port());
    out.proto = static_cast<uint8_t>(r.protocol());
    out.subproto = static_cast<uint8_t>(r.subprotocol());
    return out;
}

std::shared_ptr<const rocksdb::SliceTransform> IPv4Key::prefix_extractor() {
    auto transform = rocksdb::NewFixedPrefixTransform(4);
    return std::shared_ptr<const rocksdb::SliceTransform>(transform);
}

const IPv4Key& IPv4Key::reserved() {
    static const uint8_t protocol_reserved =
            static_cast<uint8_t>(zsearch::PROTO_RESERVED);
    static const uint8_t subprotocol_reserved =
            static_cast<uint8_t>(zsearch::SUBPROTO_RESERVED);
    static IPv4Key r{0, 0, protocol_reserved, subprotocol_reserved};
    return r;
}

const IPv4Key& IPv4Key::deleted() {
    static const uint8_t protocol_reserved =
            static_cast<uint8_t>(zsearch::PROTO_RESERVED);
    static const uint8_t subprotocol_deleted =
            static_cast<uint8_t>(zsearch::SUBPROTO_DELETED);
    static IPv4Key d{0, 0, protocol_reserved, subprotocol_deleted};
    return d;
}

std::string IPv4Key::string() const {
    bigendian_key k{ip, port, proto, subproto};
    auto c = reinterpret_cast<const char*>(&k);
    return std::string(c, sizeof(bigendian_key));
}

IPv4Key IPv4Key::zero_subkey() const {
    auto out = *this;
    out.port = 0;
    out.subproto = 0;
    out.proto = 0;
    return out;
}

zsearch::Record IPv4Key::make_record() const {
    zsearch::Record out;
    out.set_ip(ip);
    out.set_port(port);
    out.set_protocol(proto);
    out.set_subprotocol(subproto);
    return out;
}

std::string IPv4Key::print() const {
    std::stringstream ss;
    char ip_buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip, ip_buf, INET_ADDRSTRLEN);
    std::string ip_str(ip_buf);
    int pretty_port = ntohs(port);
    int pretty_protocol = static_cast<int>(proto);
    int pretty_subprotocol = static_cast<int>(subproto);
    ss << ip_str << ":" << pretty_port << ":" << pretty_protocol << ":"
       << pretty_subprotocol;
    return ss.str();
}

DomainKey::DomainKey() : port(0), proto(0), subproto(0) {}

DomainKey::DomainKey(const std::string& domain,
                     uint16_t port,
                     uint8_t proto,
                     uint8_t subproto)
        : domain(domain), port(port), proto(proto), subproto(subproto) {}

void DomainKey::set_delta(zsearch::Delta& delta) const {
    delta.set_domain(domain);
}

DomainKey DomainKey::from_string(const std::string& raw) {
    auto start = raw.data();
    auto length = raw.length();
    assert(length >= sizeof(bigendian_domain_key));
    auto domain_length = length - sizeof(bigendian_domain_key);
    auto metadata_start = start + domain_length;
    auto k = reinterpret_cast<const bigendian_domain_key*>(metadata_start);
    std::string domain(start, domain_length);
    DomainKey out{domain, k->port, k->proto, k->subproto};
    return out;
}

DomainKey DomainKey::from_record(const zsearch::Record& r) {
    auto port = static_cast<uint16_t>(r.port());
    auto proto = static_cast<uint8_t>(r.protocol());
    auto subproto = static_cast<uint8_t>(r.subprotocol());
    DomainKey out{r.domain(), port, proto, subproto};
    return out;
}

zsearch::Record DomainKey::make_record() const {
    zsearch::Record out;
    out.set_domain(domain);
    out.set_port(port);
    out.set_protocol(proto);
    out.set_subprotocol(subproto);
    return out;
}

const DomainKey& DomainKey::reserved() {
    static const DomainKey reserved;
    return reserved;
}

const DomainKey& DomainKey::deleted() {
    static const uint8_t protocol_reserved =
            static_cast<uint8_t>(zsearch::PROTO_RESERVED);
    static const uint8_t subprotocol_deleted =
            static_cast<uint8_t>(zsearch::SUBPROTO_DELETED);
    static const DomainKey d{"", 0, protocol_reserved, subprotocol_deleted};
    return d;
}

std::string DomainKey::string() const {
    bigendian_domain_key header{port, proto, subproto};
    auto raw_bytes = reinterpret_cast<const char*>(&header);
    std::stringstream ss;
    ss.write(domain.data(), domain.size());
    ss.write(raw_bytes, sizeof(bigendian_domain_key));
    return ss.str();
}

DomainKey DomainKey::zero_subkey() const {
    DomainKey out = *this;
    out.port = 0;
    out.proto = 0;
    out.subproto = 0;
    return out;
}

class DomainExtractor : public SliceTransform {
    static const size_t SUFFIX_LEN;

    virtual const char* Name() const override { return "DomainExtractor"; }

    virtual Slice Transform(const Slice& src) const override {
        return Slice(src.data(), src.size() - SUFFIX_LEN);
    }

    virtual bool InDomain(const Slice& src) const override {
        return src.size() >= SUFFIX_LEN;
    }

    virtual bool InRange(const Slice& dst) const override { return true; }

    virtual bool SameResultWhenAppended(const Slice& prefix) const override {
        return false;
    }
};

const size_t DomainExtractor::SUFFIX_LEN = 4;

std::shared_ptr<const rocksdb::SliceTransform> DomainKey::prefix_extractor() {
    return std::shared_ptr<rocksdb::SliceTransform>(new DomainExtractor);
}

bool DomainKey::operator==(const DomainKey& rhs) const {
    if (domain != rhs.domain) {
        return false;
    }
    if (port != rhs.port) {
        return false;
    }
    if (proto != rhs.proto) {
        return false;
    }
    if (subproto != rhs.subproto) {
        return false;
    }
    return true;
}

bool DomainKey::operator<(const zdb::DomainKey& rhs) const {
    int comp = domain.compare(rhs.domain);
    if (comp < 0) {
        return true;
    }
    if (comp > 0) {
        return false;
    }
    uint16_t our_port = ntohs(port);
    uint16_t their_port = ntohs(rhs.port);
    if (our_port < their_port) {
        return true;
    }
    if (our_port > their_port) {
        return false;
    }
    if (proto < rhs.proto) {
        return true;
    }
    if (proto > rhs.proto) {
        return false;
    }
    if (subproto < rhs.subproto) {
        return true;
    }
    return false;
}

std::string DomainKey::print() const {
    std::stringstream ss;
    int pretty_port = ntohs(port);
    int pretty_protocol = static_cast<int>(proto);
    int pretty_subprotocol = static_cast<int>(subproto);
    ss << domain << ":" << pretty_port << ":" << pretty_protocol << ":"
       << pretty_subprotocol;
    return ss.str();
}

HashKey HashKey::from_string(const std::string& raw) {
    HashKey out{raw};
    return out;
}

HashKey HashKey::from_string(const std::string&& raw) {
    HashKey out{std::move(raw)};
    return out;
}

HashKey HashKey::from_record(const zsearch::Record& r) {
    HashKey out{r.sha256fp()};
    return out;
}

HashKey HashKey::from_record(const zsearch::AnonymousRecord& record) {
    HashKey out{record.sha256fp()};
    return out;
}

const HashKey& HashKey::reserved() {
    static HashKey r;
    return r;
}

const HashKey& HashKey::deleted() {
    static const std::string sentinal("\0", 1);
    static const HashKey h{sentinal};
    return h;
}

std::string& HashKey::string() {
    return hash;
}

const std::string& HashKey::string() const {
    return hash;
}

HashKey HashKey::zero_subkey() const {
    return *this;
}

std::shared_ptr<const rocksdb::SliceTransform> HashKey::prefix_extractor() {
    return nullptr;
}

bool HashKey::operator==(const HashKey& rhs) const {
    return hash == rhs.hash;
}

std::string HashKey::print() const {
    return hex_encode(hash);
}

StringRecord::StringRecord(StringRecord&& other) {
    m_str = std::move(other.m_str);
}

StringRecord& StringRecord::operator=(StringRecord&& other) {
    if (this != &other) {
        m_str = std::move(other.m_str);
    }
    return *this;
}

std::string StringRecord::string() const {
    return m_str;
}

StringRecord StringRecord::zero_subkey() const {
    return *this;
}

StringRecord StringRecord::from_string(const std::string& raw) {
    StringRecord out;
    out.m_str = raw;
    return out;
}

StringRecord StringRecord::from_string(const std::string&& raw) {
    StringRecord out;
    out.m_str = std::move(raw);
    return out;
}

bool StringRecord::operator==(const StringRecord& rhs) const {
    return m_str == rhs.m_str;
}
