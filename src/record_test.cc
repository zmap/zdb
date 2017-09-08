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

#include "record.h"

#include <arpa/inet.h>

#include <gtest/gtest.h>

#include "zsearch_definitions/search.pb.h"

using namespace std;
using namespace zdb;

namespace {

class IPv4KeyTest : public ::testing::Test {
 protected:
  string ip_ascii;
  uint32_t ip_uint_network;
  uint32_t ip_uint_host;

  string port_ascii;
  uint16_t port_uint_host;
  uint16_t port_uint_network;

  uint8_t proto;
  uint8_t subproto;

  uint64_t expected_serialization;
  string expected_string;

  IPv4Key k;

  virtual void SetUp() {
    // Unpacking a network-order byte as host order gives the
    // network-ordered integer
    //
    // >>> struct.unpack('I', socket.inet_aton('1.2.3.4'))
    // (67305985,)
    //
    // Unpacking a network-order byte as network order gives the
    // host-ordered integer
    // >>> struct.unpack('!I', socket.inet_aton('1.2.3.4'))
    //
    // (16909060,)
    ip_ascii = "1.2.3.4";
    ip_uint_network = 67305985U;
    ip_uint_host = 16909060U;

    // >>> p = 443
    // >>> socket.htons(p)
    // 47873
    port_ascii = "443";
    port_uint_host = 443;
    port_uint_network = 47873;

    proto = 11;
    subproto = 12;

    // Make the expected string. s[0] is the MSB of the ip
    // Memory from lowest to highest address should be:
    //   01 02 03 04 01 BB 0B 0C
    uint8_t raw_bytes[] = {0x01, 0x02, 0x03, 0x04, 0x01, 0xBB, 0x0B, 0x0C};
    char* as_c_str = reinterpret_cast<char*>(raw_bytes);
    expected_string = string(as_c_str, 8);

    // Make a key object to play with
    k.ip = ip_uint_network;
    k.port = port_uint_network;
    k.proto = proto;
    k.subproto = subproto;
  }
};

TEST_F(IPv4KeyTest, SerializetoUint64) {
  uint32_t ip = htonl(0x01020304);
  uint16_t port = htons(0x0506);
  uint8_t proto = 3;
  uint8_t subproto = 8;
  IPv4Key test_key{ip, port, proto, subproto};
  auto as_uint = test_key.uint64();
  EXPECT_EQ(0x0803060504030201LLU, as_uint);
}

TEST_F(IPv4KeyTest, SerializeToString) {
  auto serialized_to_bytes = k.string();
  EXPECT_EQ(8, serialized_to_bytes.length());
  EXPECT_EQ(expected_string, serialized_to_bytes);
}

TEST_F(IPv4KeyTest, FromString) {
  auto output = IPv4Key::from_string(expected_string);
  EXPECT_EQ(k, output);
}

TEST_F(IPv4KeyTest, TestUint64Host) {
  auto uh = k.uint64_host();
  EXPECT_EQ(uh, 0x0102030401BB0B0C);
}

TEST_F(IPv4KeyTest, TestEquality) {
  IPv4Key keys[10];
  uint32_t ip = 0x01020304;
  for (size_t i = 0; i < 10; ++i) {
    IPv4Key k;
    k.ip = ntohl(ip);
    k.port = ntohs(443);
    k.proto = 2;
    k.subproto = 2;
    keys[i] = k;
    EXPECT_EQ(k, keys[i]);
  }
  for (size_t i = 0; i < 10; ++i) {
    IPv4Key k;
    k.ip = ntohl(ip);
    k.port = ntohs(443);
    k.proto = 2;
    k.subproto = 2;
    EXPECT_EQ(k, keys[i]);
  }
}

TEST_F(IPv4KeyTest, TestOperatorLessThan) {
  IPv4Key zero{0, 0, 0, 0};
  IPv4Key not_zero{1, 2, 3, 4};
  IPv4Key almost_zero{0, 1, 2, 3};
  IPv4Key million_host{1078071040U, ntohs(443), 11, 12};
  IPv4Key bigger{0x8e463100U, ntohs(443), 11, 12};
  IPv4Key technically_bigger{0x99453101U, ntohs(443), 11, 12};
  EXPECT_FALSE(zero < zero);
  EXPECT_TRUE(zero < almost_zero);
  EXPECT_TRUE(zero < not_zero);
  EXPECT_FALSE(almost_zero < zero);
  EXPECT_FALSE(almost_zero < almost_zero);
  EXPECT_TRUE(almost_zero < not_zero);
  EXPECT_FALSE(not_zero < zero);
  EXPECT_FALSE(not_zero < almost_zero);
  EXPECT_FALSE(not_zero < not_zero);
  EXPECT_FALSE(million_host < zero);
  EXPECT_TRUE(million_host < bigger);
  EXPECT_FALSE(bigger < million_host);
  EXPECT_FALSE(technically_bigger < bigger);
}

class DomainKeyTest : public ::testing::Test {
 protected:
  DomainKey k;

  string domain;
  string expected_serialization;

  virtual void SetUp() {
    domain = "davidadrian.org";

    k.domain = domain;
    k.port = htons(443);
    k.proto = 2;
    k.subproto = 3;

    // expected serialization
    size_t expected_length = 4 + domain.length();
    uint8_t expected_bytes[] = {0x64, 0x61, 0x76, 0x69, 0x64, 0x61, 0x64,
                                0x72, 0x69, 0x61, 0x6e, 0x2e, 0x6f, 0x72,
                                0x67, 0x01, 0xBB, 0x02, 0x03};
    const char* expected_chars = reinterpret_cast<const char*>(expected_bytes);
    expected_serialization = string(expected_chars, expected_length);
  }
};

TEST_F(DomainKeyTest, SerializeToString) {
  auto output = k.string();
  ASSERT_EQ(expected_serialization.length(), output.length());
  EXPECT_EQ(expected_serialization, output);
}

TEST_F(DomainKeyTest, DeserializeFromString) {
  auto output = DomainKey::from_string(expected_serialization);
  EXPECT_EQ(k, output);
}

TEST(HashKeyTest, ZeroPadPrefix) {
  uint32_t prefix = 0x01020304U;
  HashKey padded = HashKey::zero_pad_prefix(prefix, HashKey::SHA256_LEN);
  ASSERT_EQ(HashKey::SHA256_LEN, padded.hash.size());
  EXPECT_EQ(padded.hash[0], 0x01);
  EXPECT_EQ(padded.hash[1], 0x02);
  EXPECT_EQ(padded.hash[2], 0x03);
  EXPECT_EQ(padded.hash[3], 0x04);
  for (size_t i = 4; i < padded.hash.size(); ++i) {
    EXPECT_EQ(padded.hash[i], '\0');
  }
}

class ProtobufRecordTest : public ::testing::Test {
 protected:
  ProtobufRecord<zsearch::UserdataAtom> pbr;
  zsearch::UserdataAtom zpb;

  const string private_notes;
  const string public_notes;

  ProtobufRecordTest()
      : private_notes("these are my private notes"),
        public_notes("these are my public notes") {}

  virtual void SetUp() {
    zpb.set_private_notes(private_notes);
    zpb.set_public_notes(public_notes);
    pbr = ProtobufRecord<zsearch::UserdataAtom>(zpb);
  }
};

TEST_F(ProtobufRecordTest, SerializeToString) {
  auto serialized = pbr.string();
  auto expected = zpb.SerializeAsString();
  EXPECT_EQ(expected, serialized);
}

TEST_F(ProtobufRecordTest, DeserializeFromString) {
  auto serialized = zpb.SerializeAsString();
  auto deserialized =
      ProtobufRecord<zsearch::UserdataAtom>::from_string(serialized);
  EXPECT_EQ(pbr, deserialized);
}
}  // namespace
