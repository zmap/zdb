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

#ifndef ZDB_SRC_RECORD_H
#define ZDB_SRC_RECORD_H

#include <cstdint>
#include <functional>
#include <string>

#include <arpa/inet.h>

#include <rocksdb/slice_transform.h>

#include "zsearch_definitions/search.pb.h"

#include "macros.h"
#include "serialize.h"

namespace zdb {

class IPv4Key {
 private:
  struct bigendian_key {
    uint32_t ip;
    uint16_t port;
    uint8_t proto;
    uint8_t subproto;
  } __attribute__((packed));

  friend struct ::std::hash<IPv4Key>;

 public:
#pragma pack(push, 1)
  uint32_t ip;
  uint16_t port;
  uint8_t proto;
  uint8_t subproto;
#pragma pack(pop)

  using lock_on_type = uint32_t;

  IPv4Key();
  IPv4Key(uint32_t ip, uint16_t port, uint8_t protocol, uint8_t subprotocol);
  std::string string() const;
  inline uint64_t uint64() const {
    return *reinterpret_cast<const uint64_t*>(&ip);
  }
  IPv4Key zero_subkey() const;
  inline lock_on_type lock_on() const { return ip; }
  zsearch::Record make_record() const;

  void set_delta(zsearch::Delta& delta) const;

  static IPv4Key from_string(const std::string& raw);
  static IPv4Key from_record(const zsearch::Record& record);

  static const IPv4Key& reserved();
  static const IPv4Key& deleted();

  static std::shared_ptr<const rocksdb::SliceTransform> prefix_extractor();

  inline uint64_t uint64_host() const {
    uint64_t ret = 0;
    ret |= ntohl(ip);
    ret <<= 32;
    ret |= static_cast<uint32_t>(ntohs(port)) << 16;
    ret |= static_cast<uint16_t>(proto) << 8;
    ret |= subproto;
    return ret;
  }

  inline bool operator==(const IPv4Key& rhs) const {
    // return (ip == rhs.ip && port == rhs.port && proto == rhs.proto &&
    // subproto == rhs.subproto);
    return uint64() == rhs.uint64();
  }

  inline bool operator<(const IPv4Key& rhs) const {
    return uint64_host() < rhs.uint64_host();
  }

  std::string print() const;
};

class DomainKey {
 private:
  struct bigendian_domain_key {
    uint16_t port;
    uint8_t proto;
    uint8_t subproto;
  };

 public:
  std::string domain;
  uint16_t port;
  uint8_t proto;
  uint8_t subproto;

  using lock_on_type = std::string;

  DomainKey();
  DomainKey(const std::string& domain,
            uint16_t port,
            uint8_t protocol,
            uint8_t subproto);
  std::string string() const;
  DomainKey zero_subkey() const;
  inline lock_on_type lock_on() const { return domain; }
  zsearch::Record make_record() const;

  void set_delta(zsearch::Delta& delta) const;

  static DomainKey from_string(const std::string& raw);
  static DomainKey from_record(const zsearch::Record& record);
  static DomainKey from_delta(const zsearch::Delta& delta);

  static const DomainKey& reserved();
  static const DomainKey& deleted();

  static std::shared_ptr<const rocksdb::SliceTransform> prefix_extractor();

  bool operator==(const DomainKey& rhs) const;
  bool operator<(const DomainKey& rhs) const;

  std::string print() const;
};

class HashKey {
 public:
  std::string hash;

  using lock_on_type = std::string;

  HashKey() = default;
  std::string& string();
  const std::string& string() const;
  HashKey zero_subkey() const;
  inline lock_on_type lock_on() const { return hash; }

  static HashKey from_string(const std::string& raw);
  static HashKey from_string(const std::string&& raw);
  static HashKey from_record(const zsearch::Record& record);
  static HashKey from_record(const zsearch::AnonymousRecord& record);
  static HashKey zero_pad_prefix(uint32_t prefix, size_t length);

  static const HashKey& reserved();
  static const HashKey& deleted();

  static std::shared_ptr<const rocksdb::SliceTransform> prefix_extractor();

  bool operator==(const HashKey& rhs) const;
  bool operator<(const HashKey& rhs) const;

  std::string print() const;

  static const size_t SHA256_LEN;
};

class StringRecord {
 private:
  std::string m_str;

 public:
  StringRecord() = default;
  StringRecord(const StringRecord&) = default;
  StringRecord(StringRecord&& other);
  StringRecord& operator=(StringRecord&& other);

  std::string string() const;
  StringRecord zero_subkey() const;

  static StringRecord from_string(const std::string& raw);
  static StringRecord from_string(const std::string&& raw);

  bool operator==(const StringRecord& rhs) const;
};

template <typename pb_type>
class ProtobufRecord {
 private:
  pb_type m_pb;

 public:
  ProtobufRecord() = default;
  ProtobufRecord(const ProtobufRecord&) = default;
  ProtobufRecord(ProtobufRecord&&);
  ProtobufRecord(const pb_type&);
  ProtobufRecord(pb_type&&);

  ProtobufRecord& operator=(const ProtobufRecord&) = default;
  ProtobufRecord& operator=(ProtobufRecord&&);

  bool operator==(const ProtobufRecord&) const;

  inline pb_type& pb() { return m_pb; }
  inline const pb_type& pb() const { return m_pb; }

  std::string string() const;

  static ProtobufRecord from_string(const std::string& raw);
};

template <typename pb_type>
ProtobufRecord<pb_type>::ProtobufRecord(ProtobufRecord&& other) {
  m_pb.Clear();
  m_pb.Swap(&other.m_pb);
}

template <typename pb_type>
ProtobufRecord<pb_type>::ProtobufRecord(const pb_type& pb) {
  m_pb.CopyFrom(pb);
}

template <typename pb_type>
ProtobufRecord<pb_type>::ProtobufRecord(pb_type&& pb) {
  m_pb.Clear();
  m_pb.Swap(&pb);
}

template <typename pb_type>
ProtobufRecord<pb_type>& ProtobufRecord<pb_type>::operator=(
    ProtobufRecord<pb_type>&& other) {
  if (this != &other) {
    m_pb.Clear();
    m_pb.Swap(&other.m_pb);
  }
  return *this;
}

template <typename pb_type>
ProtobufRecord<pb_type> ProtobufRecord<pb_type>::from_string(
    const std::string& raw) {
  ProtobufRecord<pb_type> out;
  out.m_pb.ParseFromString(raw);
  return std::move(out);
}

template <typename pb_type>
std::string ProtobufRecord<pb_type>::string() const {
  return m_pb.SerializeAsString();
}

template <typename pb_type>
bool ProtobufRecord<pb_type>::operator==(
    const ProtobufRecord<pb_type>& rhs) const {
  return string() == rhs.string();
}

template <typename T>
struct deserialize<ProtobufRecord<T>> {
  using value_type = ProtobufRecord<T>;

  value_type operator()(const std::string& s) const {
    return ProtobufRecord<T>::from_string(s);
  }

  value_type operator()(std::string&& s) const {
    return ProtobufRecord<T>::from_string(std::move(s));
  }
};

template <>
struct deserialize<StringRecord> {
  using value_type = StringRecord;

  value_type operator()(const std::string& s) const {
    return StringRecord::from_string(s);
  }

  value_type operator()(std::string&& s) const {
    return StringRecord::from_string(std::move(s));
  }
};

template <>
struct deserialize<std::string> {
  using value_type = std::string;

  value_type operator()(const std::string& s) const { return s; }

  value_type operator()(std::string&& s) const { return std::move(s); }
};

}  // namespace zdb

namespace std {

template <>
struct hash<::zdb::IPv4Key> {
  using argument_type = zdb::IPv4Key;
  using result_type = size_t;

  result_type operator()(const argument_type& k) const {
    return static_cast<result_type>(k.uint64());
  }
};

template <>
struct hash<::zdb::DomainKey> {
  using argument_type = ::zdb::DomainKey;
  using result_type = size_t;

  result_type operator()(const argument_type& k) const {
    hash<string> h;
    return h(k.domain);
  }
};

template <>
struct hash<::zdb::HashKey> {
  using argument_type = ::zdb::HashKey;
  using result_type = size_t;

  result_type operator()(const argument_type& k) const {
    if (k.hash.length() >= 8) {
      return *reinterpret_cast<const size_t*>(k.hash.data());
    }
    hash<string> h;
    return h(k.hash);
  }
};

}  // namespace std

#endif /* ZDB_SRC_RECORD_H */
