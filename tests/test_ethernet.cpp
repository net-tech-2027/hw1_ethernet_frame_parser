#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <vector>

extern "C" {
#include "ethernet.h"
}

namespace {

using Bytes = std::vector<uint8_t>;

std::uint16_t read_be16(const std::uint8_t *p) {
  return static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[0]) << 8) |
                                    p[1]);
}

eth_mac_t make_mac(std::initializer_list<std::uint8_t> octets) {
  eth_mac_t mac{};
  std::copy(octets.begin(), octets.end(), mac.octets);
  return mac;
}

void append_mac(Bytes &out, const eth_mac_t &mac) {
  out.insert(out.end(), mac.octets, mac.octets + ETH_ADDR_LEN);
}

void append_be16(Bytes &out, std::uint16_t value) {
  out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFF));
  out.push_back(static_cast<std::uint8_t>(value & 0xFF));
}

Bytes make_payload(std::size_t size, std::uint8_t seed = 0) {
  Bytes payload(size);
  for (std::size_t i = 0; i < size; ++i) {
    payload[i] = static_cast<std::uint8_t>(seed + i);
  }
  return payload;
}

std::uint16_t make_tci(std::uint8_t pcp, bool dei, std::uint16_t vid) {
  return static_cast<std::uint16_t>(
      (static_cast<std::uint16_t>(pcp) << ETH_VLAN_PCP_SHIFT) |
      (dei ? ETH_VLAN_DEI_MASK : 0u) | vid);
}

Bytes build_untagged(const eth_mac_t &dst, const eth_mac_t &src,
                     std::uint16_t ether_type, const Bytes &payload) {
  Bytes frame;
  frame.reserve(ETH_HEADER_LEN + payload.size());
  append_mac(frame, dst);
  append_mac(frame, src);
  append_be16(frame, ether_type);
  frame.insert(frame.end(), payload.begin(), payload.end());
  return frame;
}

Bytes build_tagged(const eth_mac_t &dst, const eth_mac_t &src,
                   std::uint16_t tpid, std::uint16_t tci,
                   std::uint16_t ether_type, const Bytes &payload) {
  Bytes frame;
  frame.reserve(ETH_VLAN_HEADER_LEN + payload.size());
  append_mac(frame, dst);
  append_mac(frame, src);
  append_be16(frame, tpid);
  append_be16(frame, tci);
  append_be16(frame, ether_type);
  frame.insert(frame.end(), payload.begin(), payload.end());
  return frame;
}

void expect_mac_eq(const eth_mac_t &actual, const eth_mac_t &expected) {
  for (std::size_t i = 0; i < sizeof(actual.octets); ++i) {
    EXPECT_EQ(actual.octets[i], expected.octets[i]) << "octet " << i;
  }
}

void expect_frame_eq(const eth_frame_t &actual, const eth_frame_t &expected) {
  expect_mac_eq(actual.dst, expected.dst);
  expect_mac_eq(actual.src, expected.src);
  EXPECT_EQ(actual.vlan_present, expected.vlan_present);
  EXPECT_EQ(actual.vlan.tpid, expected.vlan.tpid);
  EXPECT_EQ(actual.vlan.pcp, expected.vlan.pcp);
  EXPECT_EQ(actual.vlan.dei, expected.vlan.dei);
  EXPECT_EQ(actual.vlan.vid, expected.vlan.vid);
  EXPECT_EQ(actual.ether_type, expected.ether_type);
  EXPECT_EQ(actual.length_field, expected.length_field);
  EXPECT_EQ(actual.payload, expected.payload);
  EXPECT_EQ(actual.payload_len, expected.payload_len);
}

eth_frame_t make_sentinel_frame() {
  static const std::uint8_t payload[ETH_MIN_PAYLOAD] = {};
  eth_frame_t frame{};
  frame.dst = make_mac({0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02});
  frame.src = make_mac({0xDE, 0xAD, 0xBE, 0xEF, 0x03, 0x04});
  frame.vlan_present = true;
  frame.vlan.tpid = ETH_TYPE_VLAN;
  frame.vlan.pcp = 5;
  frame.vlan.dei = true;
  frame.vlan.vid = 7;
  frame.ether_type = ETH_TYPE_IPV4;
  frame.length_field = false;
  frame.payload = payload;
  frame.payload_len = sizeof(payload);
  return frame;
}

void expect_parse_rejected(const Bytes &buf) {
  static const std::uint8_t dummy = 0;
  const std::uint8_t *data = buf.empty() ? &dummy : buf.data();

  eth_frame_t frame = make_sentinel_frame();
  const eth_frame_t before = frame;

  EXPECT_EQ(eth_frame_parse(data, buf.size(), &frame), -1)
      << "frame length: " << buf.size();
  expect_frame_eq(frame, before);
}

class EthernetFrameTest : public ::testing::Test {
protected:
  eth_mac_t dst_ = make_mac({0x01, 0x02, 0x03, 0x04, 0x05, 0x06});
  eth_mac_t src_ = make_mac({0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F});
};

// ---------------------------------------------------------------------------
// Разбор: нетэгированный трафик
// ---------------------------------------------------------------------------

TEST_F(EthernetFrameTest, ParsesUntaggedIpv4Frame) {
  const Bytes payload = make_payload(ETH_MIN_PAYLOAD);
  const Bytes buf = build_untagged(dst_, src_, ETH_TYPE_IPV4, payload);
  ASSERT_EQ(buf.size(), static_cast<std::size_t>(ETH_FRAME_MIN_LEN));

  eth_frame_t frame{};
  ASSERT_EQ(eth_frame_parse(buf.data(), buf.size(), &frame), 0);

  expect_mac_eq(frame.dst, dst_);
  expect_mac_eq(frame.src, src_);
  EXPECT_FALSE(frame.vlan_present);
  EXPECT_EQ(frame.vlan.tpid, 0u);
  EXPECT_EQ(frame.vlan.pcp, 0u);
  EXPECT_FALSE(frame.vlan.dei);
  EXPECT_EQ(frame.vlan.vid, 0u);
  EXPECT_EQ(frame.ether_type, ETH_TYPE_IPV4);
  EXPECT_FALSE(frame.length_field);
  EXPECT_EQ(frame.payload, buf.data() + ETH_HEADER_LEN);
  ASSERT_EQ(frame.payload_len, payload.size());
  EXPECT_EQ(0, std::memcmp(frame.payload, payload.data(), payload.size()));
}

TEST_F(EthernetFrameTest, ParsesUntaggedArpFrame) {
  const Bytes payload = make_payload(ETH_MIN_PAYLOAD, 0x40);
  const Bytes buf = build_untagged(dst_, src_, ETH_TYPE_ARP, payload);

  eth_frame_t frame{};
  ASSERT_EQ(eth_frame_parse(buf.data(), buf.size(), &frame), 0);

  EXPECT_FALSE(frame.vlan_present);
  EXPECT_EQ(frame.ether_type, ETH_TYPE_ARP);
  EXPECT_FALSE(frame.length_field);
  EXPECT_EQ(frame.payload_len, payload.size());
  EXPECT_EQ(frame.payload, buf.data() + ETH_HEADER_LEN);
}

TEST_F(EthernetFrameTest, MarksIeee8023LengthField) {
  const Bytes payload = make_payload(ETH_MIN_PAYLOAD);
  const Bytes buf = build_untagged(
      dst_, src_, static_cast<std::uint16_t>(ETH_MIN_PAYLOAD), payload);

  eth_frame_t frame{};
  ASSERT_EQ(eth_frame_parse(buf.data(), buf.size(), &frame), 0);

  EXPECT_FALSE(frame.vlan_present);
  EXPECT_TRUE(frame.length_field);
  EXPECT_EQ(frame.ether_type, ETH_MIN_PAYLOAD);
  EXPECT_EQ(frame.payload_len, payload.size());
}

// ---------------------------------------------------------------------------
// Разбор: тегированный трафик IEEE 802.1Q
// ---------------------------------------------------------------------------

TEST_F(EthernetFrameTest, ParsesTaggedVlanFrame) {
  const Bytes payload = make_payload(ETH_MIN_PAYLOAD);
  const std::uint8_t pcp = 5;
  const bool dei = true;
  const std::uint16_t vid = 100;
  const Bytes buf =
      build_tagged(dst_, src_, ETH_TYPE_VLAN, make_tci(pcp, dei, vid),
                   ETH_TYPE_IPV4, payload);
  ASSERT_EQ(buf.size(), static_cast<std::size_t>(ETH_VLAN_FRAME_MIN_LEN));

  eth_frame_t frame{};
  ASSERT_EQ(eth_frame_parse(buf.data(), buf.size(), &frame), 0);

  expect_mac_eq(frame.dst, dst_);
  expect_mac_eq(frame.src, src_);
  EXPECT_TRUE(frame.vlan_present);
  EXPECT_EQ(frame.vlan.tpid, ETH_TYPE_VLAN);
  EXPECT_EQ(frame.vlan.pcp, pcp);
  EXPECT_TRUE(frame.vlan.dei);
  EXPECT_EQ(frame.vlan.vid, vid);
  EXPECT_EQ(frame.ether_type, ETH_TYPE_IPV4);
  EXPECT_FALSE(frame.length_field);
  EXPECT_EQ(frame.payload, buf.data() + ETH_VLAN_HEADER_LEN);
  ASSERT_EQ(frame.payload_len, payload.size());
  EXPECT_EQ(0, std::memcmp(frame.payload, payload.data(), payload.size()));
}

TEST_F(EthernetFrameTest, DecodesEveryPcpAndVidBoundaries) {
  const Bytes payload = make_payload(ETH_MIN_PAYLOAD);

  for (std::uint8_t pcp = 0; pcp <= ETH_VLAN_PCP_MASK; ++pcp) {
    for (std::uint16_t vid :
         {static_cast<std::uint16_t>(0), static_cast<std::uint16_t>(1),
          static_cast<std::uint16_t>(ETH_VLAN_VID_MASK)}) {
      for (bool dei : {false, true}) {
        const Bytes buf =
            build_tagged(dst_, src_, ETH_TYPE_VLAN, make_tci(pcp, dei, vid),
                         ETH_TYPE_IPV6, payload);

        eth_frame_t frame{};
        ASSERT_EQ(eth_frame_parse(buf.data(), buf.size(), &frame), 0)
            << "pcp=" << static_cast<int>(pcp) << " vid=" << vid
            << " dei=" << dei;
        EXPECT_TRUE(frame.vlan_present);
        EXPECT_EQ(frame.vlan.tpid, ETH_TYPE_VLAN);
        EXPECT_EQ(frame.vlan.pcp, pcp);
        EXPECT_EQ(frame.vlan.dei, dei);
        EXPECT_EQ(frame.vlan.vid, vid);
        EXPECT_EQ(frame.ether_type, ETH_TYPE_IPV6);
      }
    }
  }
}

TEST_F(EthernetFrameTest, AcceptsSingleQinQServiceTag) {
  const Bytes payload = make_payload(ETH_MIN_PAYLOAD);
  const Bytes buf =
      build_tagged(dst_, src_, ETH_TYPE_QINQ, make_tci(2, false, 200),
                   ETH_TYPE_IPV4, payload);

  eth_frame_t frame{};
  ASSERT_EQ(eth_frame_parse(buf.data(), buf.size(), &frame), 0);

  EXPECT_TRUE(frame.vlan_present);
  EXPECT_EQ(frame.vlan.tpid, ETH_TYPE_QINQ);
  EXPECT_EQ(frame.vlan.pcp, 2u);
  EXPECT_FALSE(frame.vlan.dei);
  EXPECT_EQ(frame.vlan.vid, 200u);
  EXPECT_EQ(frame.ether_type, ETH_TYPE_IPV4);
}

TEST_F(EthernetFrameTest, RejectsNestedVlanTags) {
  const Bytes payload = make_payload(ETH_MIN_PAYLOAD);
  const std::uint16_t tci = make_tci(0, false, 1);

  expect_parse_rejected(
      build_tagged(dst_, src_, ETH_TYPE_VLAN, tci, ETH_TYPE_VLAN, payload));
  expect_parse_rejected(
      build_tagged(dst_, src_, ETH_TYPE_QINQ, tci, ETH_TYPE_VLAN, payload));
}

// ---------------------------------------------------------------------------
// Разбор: ошибки длины и аргументов
// ---------------------------------------------------------------------------

TEST_F(EthernetFrameTest, RejectsFramesShorterThanMinimum) {
  expect_parse_rejected(Bytes{});
  expect_parse_rejected(Bytes(1, 0));
  expect_parse_rejected(Bytes(ETH_HEADER_LEN - 1, 0));
  expect_parse_rejected(Bytes(ETH_HEADER_LEN, 0));
  expect_parse_rejected(build_untagged(dst_, src_, ETH_TYPE_IPV4,
                                       make_payload(ETH_MIN_PAYLOAD - 1)));

  Bytes truncated_tag(ETH_VLAN_HEADER_LEN - 1, 0);
  truncated_tag[12] = 0x81;
  truncated_tag[13] = 0x00;
  expect_parse_rejected(truncated_tag);
  expect_parse_rejected(build_tagged(dst_, src_, ETH_TYPE_VLAN,
                                     make_tci(0, false, 0), ETH_TYPE_IPV4,
                                     make_payload(ETH_MIN_PAYLOAD - 1)));
}

TEST_F(EthernetFrameTest, RejectsPayloadLargerThanMtu) {
  const Bytes too_big = make_payload(ETH_MAX_PAYLOAD + 1);

  expect_parse_rejected(build_untagged(dst_, src_, ETH_TYPE_IPV4, too_big));
  expect_parse_rejected(build_tagged(dst_, src_, ETH_TYPE_VLAN,
                                     make_tci(0, false, 0), ETH_TYPE_IPV4,
                                     too_big));
}

TEST_F(EthernetFrameTest, ParseRejectsNullArguments) {
  const Bytes buf =
      build_untagged(dst_, src_, ETH_TYPE_IPV4, make_payload(ETH_MIN_PAYLOAD));
  eth_frame_t frame{};

  EXPECT_EQ(eth_frame_parse(nullptr, buf.size(), &frame), -1);
  EXPECT_EQ(eth_frame_parse(buf.data(), buf.size(), nullptr), -1);
}

// ---------------------------------------------------------------------------
// Сериализация
// ---------------------------------------------------------------------------

TEST_F(EthernetFrameTest, SerializesUntaggedFrameBytes) {
  const Bytes payload = make_payload(ETH_MIN_PAYLOAD, 0x20);
  eth_frame_t frame{};
  frame.dst = dst_;
  frame.src = src_;
  frame.vlan_present = false;
  frame.ether_type = ETH_TYPE_IPV4;
  frame.payload = payload.data();
  frame.payload_len = payload.size();

  Bytes out(ETH_FRAME_MIN_LEN, 0xCC);
  ASSERT_EQ(eth_frame_serialize(&frame, out.data(), out.size()),
            ETH_FRAME_MIN_LEN);

  Bytes expected;
  append_mac(expected, dst_);
  append_mac(expected, src_);
  append_be16(expected, ETH_TYPE_IPV4);
  expected.insert(expected.end(), payload.begin(), payload.end());

  EXPECT_EQ(out, expected);
  EXPECT_EQ(read_be16(out.data() + 12), ETH_TYPE_IPV4);
}

TEST_F(EthernetFrameTest, SerializesTaggedFrameBytes) {
  const Bytes payload = make_payload(ETH_MIN_PAYLOAD, 0x60);
  const std::uint8_t pcp = 3;
  const bool dei = false;
  const std::uint16_t vid = static_cast<std::uint16_t>(ETH_VLAN_VID_MASK);

  eth_frame_t frame{};
  frame.dst = dst_;
  frame.src = src_;
  frame.vlan_present = true;
  frame.vlan.tpid = ETH_TYPE_VLAN;
  frame.vlan.pcp = pcp;
  frame.vlan.dei = dei;
  frame.vlan.vid = vid;
  frame.ether_type = ETH_TYPE_IPV6;
  frame.payload = payload.data();
  frame.payload_len = payload.size();

  Bytes out(ETH_VLAN_FRAME_MIN_LEN, 0xCC);
  ASSERT_EQ(eth_frame_serialize(&frame, out.data(), out.size()),
            ETH_VLAN_FRAME_MIN_LEN);

  Bytes expected;
  append_mac(expected, dst_);
  append_mac(expected, src_);
  append_be16(expected, ETH_TYPE_VLAN);
  append_be16(expected, make_tci(pcp, dei, vid));
  append_be16(expected, ETH_TYPE_IPV6);
  expected.insert(expected.end(), payload.begin(), payload.end());

  EXPECT_EQ(out, expected);
  EXPECT_EQ(read_be16(out.data() + 12), ETH_TYPE_VLAN);
  EXPECT_EQ(read_be16(out.data() + 14), make_tci(pcp, dei, vid));
  EXPECT_EQ(read_be16(out.data() + 16), ETH_TYPE_IPV6);
}

TEST_F(EthernetFrameTest, RoundTripsUntaggedFrame) {
  const Bytes payload = make_payload(ETH_MAX_PAYLOAD, 0x11);

  eth_frame_t in{};
  in.dst = dst_;
  in.src = src_;
  in.vlan_present = false;
  in.ether_type = ETH_TYPE_ARP;
  in.payload = payload.data();
  in.payload_len = payload.size();

  Bytes wire(ETH_FRAME_MAX_LEN);
  ASSERT_EQ(eth_frame_serialize(&in, wire.data(), wire.size()),
            ETH_FRAME_MAX_LEN);

  eth_frame_t out{};
  ASSERT_EQ(eth_frame_parse(wire.data(), wire.size(), &out), 0);

  expect_mac_eq(out.dst, dst_);
  expect_mac_eq(out.src, src_);
  EXPECT_FALSE(out.vlan_present);
  EXPECT_EQ(out.ether_type, ETH_TYPE_ARP);
  EXPECT_EQ(out.payload_len, payload.size());
  EXPECT_EQ(0, std::memcmp(out.payload, payload.data(), payload.size()));
}

TEST_F(EthernetFrameTest, RoundTripsTaggedFrame) {
  const Bytes payload = make_payload(ETH_MAX_PAYLOAD, 0x77);

  eth_frame_t in{};
  in.dst = dst_;
  in.src = src_;
  in.vlan_present = true;
  in.vlan.tpid = ETH_TYPE_QINQ;
  in.vlan.pcp = 7;
  in.vlan.dei = true;
  in.vlan.vid = 4095;
  in.ether_type = ETH_TYPE_IPV6;
  in.payload = payload.data();
  in.payload_len = payload.size();

  Bytes wire(ETH_VLAN_FRAME_MAX_LEN);
  ASSERT_EQ(eth_frame_serialize(&in, wire.data(), wire.size()),
            ETH_VLAN_FRAME_MAX_LEN);

  eth_frame_t out{};
  ASSERT_EQ(eth_frame_parse(wire.data(), wire.size(), &out), 0);

  expect_mac_eq(out.dst, dst_);
  expect_mac_eq(out.src, src_);
  EXPECT_TRUE(out.vlan_present);
  EXPECT_EQ(out.vlan.tpid, ETH_TYPE_QINQ);
  EXPECT_EQ(out.vlan.pcp, 7u);
  EXPECT_TRUE(out.vlan.dei);
  EXPECT_EQ(out.vlan.vid, 4095u);
  EXPECT_EQ(out.ether_type, ETH_TYPE_IPV6);
  EXPECT_EQ(out.payload_len, payload.size());
  EXPECT_EQ(0, std::memcmp(out.payload, payload.data(), payload.size()));
}

TEST_F(EthernetFrameTest, SerializeRejectsTooSmallBuffer) {
  const Bytes payload = make_payload(ETH_MIN_PAYLOAD);

  eth_frame_t frame{};
  frame.dst = dst_;
  frame.src = src_;
  frame.ether_type = ETH_TYPE_IPV4;
  frame.payload = payload.data();
  frame.payload_len = payload.size();

  Bytes out(ETH_FRAME_MIN_LEN, 0xEE);
  EXPECT_EQ(eth_frame_serialize(&frame, out.data(), out.size() - 1), -1);
  for (std::uint8_t byte : out) {
    EXPECT_EQ(byte, 0xEE);
  }

  frame.vlan_present = true;
  frame.vlan.tpid = ETH_TYPE_VLAN;
  frame.vlan.pcp = 0;
  frame.vlan.dei = false;
  frame.vlan.vid = 0;

  Bytes tagged_out(ETH_VLAN_FRAME_MIN_LEN, 0xEE);
  EXPECT_EQ(
      eth_frame_serialize(&frame, tagged_out.data(), tagged_out.size() - 1),
      -1);
  for (std::uint8_t byte : tagged_out) {
    EXPECT_EQ(byte, 0xEE);
  }
}

TEST_F(EthernetFrameTest, SerializeDoesNotWritePastBufferEnd) {
  struct Guarded {
    std::uint8_t bytes[ETH_VLAN_FRAME_MIN_LEN];
    std::uint8_t guard[8];
  };
  Guarded guarded{};
  std::memset(&guarded, 0x3F, sizeof guarded);

  const Bytes payload = make_payload(ETH_MIN_PAYLOAD);
  eth_frame_t frame{};
  frame.dst = dst_;
  frame.src = src_;
  frame.vlan_present = true;
  frame.vlan.tpid = ETH_TYPE_VLAN;
  frame.vlan.pcp = 1;
  frame.vlan.dei = true;
  frame.vlan.vid = 123;
  frame.ether_type = ETH_TYPE_IPV4;
  frame.payload = payload.data();
  frame.payload_len = payload.size();

  ASSERT_EQ(eth_frame_serialize(&frame, guarded.bytes, sizeof guarded.bytes),
            ETH_VLAN_FRAME_MIN_LEN);
  for (std::uint8_t byte : guarded.guard) {
    EXPECT_EQ(byte, 0x3F);
  }
}

TEST_F(EthernetFrameTest, SerializeRejectsNullArguments) {
  const Bytes payload = make_payload(ETH_MIN_PAYLOAD);
  std::array<std::uint8_t, ETH_FRAME_MAX_LEN> out{};

  eth_frame_t frame{};
  frame.dst = dst_;
  frame.src = src_;
  frame.ether_type = ETH_TYPE_IPV4;
  frame.payload = payload.data();
  frame.payload_len = payload.size();

  EXPECT_EQ(eth_frame_serialize(nullptr, out.data(), out.size()), -1);
  EXPECT_EQ(eth_frame_serialize(&frame, nullptr, out.size()), -1);

  frame.payload = nullptr;
  EXPECT_EQ(eth_frame_serialize(&frame, out.data(), out.size()), -1);
}

TEST_F(EthernetFrameTest, SerializeRejectsPayloadOutOfRange) {
  std::array<std::uint8_t, ETH_VLAN_FRAME_MAX_LEN + 8> out{};

  const Bytes too_small = make_payload(ETH_MIN_PAYLOAD - 1);
  eth_frame_t frame{};
  frame.dst = dst_;
  frame.src = src_;
  frame.ether_type = ETH_TYPE_IPV4;
  frame.payload = too_small.data();
  frame.payload_len = too_small.size();
  EXPECT_EQ(eth_frame_serialize(&frame, out.data(), out.size()), -1);

  const Bytes too_big = make_payload(ETH_MAX_PAYLOAD + 1);
  frame.payload = too_big.data();
  frame.payload_len = too_big.size();
  EXPECT_EQ(eth_frame_serialize(&frame, out.data(), out.size()), -1);
}

TEST_F(EthernetFrameTest, SerializeRejectsInvalidVlanFields) {
  const Bytes payload = make_payload(ETH_MIN_PAYLOAD);
  std::array<std::uint8_t, ETH_VLAN_FRAME_MAX_LEN> out{};

  eth_frame_t frame{};
  frame.dst = dst_;
  frame.src = src_;
  frame.vlan_present = true;
  frame.vlan.tpid = ETH_TYPE_VLAN;
  frame.vlan.pcp = 0;
  frame.vlan.dei = false;
  frame.vlan.vid = 0;
  frame.ether_type = ETH_TYPE_IPV4;
  frame.payload = payload.data();
  frame.payload_len = payload.size();

  for (std::uint16_t tpid :
       {static_cast<std::uint16_t>(0x0000), static_cast<std::uint16_t>(0x0800),
        static_cast<std::uint16_t>(0xFFFF)}) {
    frame.vlan.tpid = tpid;
    EXPECT_EQ(eth_frame_serialize(&frame, out.data(), out.size()), -1)
        << "tpid=" << tpid;
  }

  frame.vlan.tpid = ETH_TYPE_VLAN;
  frame.vlan.pcp = ETH_VLAN_PCP_MASK + 1;
  EXPECT_EQ(eth_frame_serialize(&frame, out.data(), out.size()), -1);

  frame.vlan.pcp = 0;
  frame.vlan.vid = static_cast<std::uint16_t>(ETH_VLAN_VID_MASK + 1);
  EXPECT_EQ(eth_frame_serialize(&frame, out.data(), out.size()), -1);
}

} // namespace
