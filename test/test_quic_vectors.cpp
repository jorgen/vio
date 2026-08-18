#include <array>
#include <cstdint>
#include <optional>
#include <ostream>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include <doctest/doctest.h>
#include <vio/crypto.h>
#include <vio/quic/connection_id.h>
#include <vio/quic/packet_number.h>
#include <vio/quic/varint.h>

// Values transcribed from the raw RFC 9000 text (Appendix A), not from a
// summary of it.

namespace
{
std::vector<std::uint8_t> unhex(std::string_view hex)
{
  auto nibble = [](char c) -> int
  {
    if (c >= '0' && c <= '9')
      return c - '0';
    if (c >= 'a' && c <= 'f')
      return c - 'a' + 10;
    return c - 'A' + 10;
  };
  std::vector<std::uint8_t> out;
  out.reserve(hex.size() / 2);
  for (std::size_t i = 0; i + 1 < hex.size(); i += 2)
  {
    out.push_back(static_cast<std::uint8_t>((nibble(hex[i]) << 4) | nibble(hex[i + 1])));
  }
  return out;
}
} // namespace

TEST_SUITE("quic vectors")
{
TEST_CASE("RFC 9000 A.1: variable-length integer decoding")
{
  struct sample_t
  {
    std::string_view hex;
    std::uint64_t value;
    std::size_t size;
  };

  // The last pair is the RFC's own point that a non-minimal encoding is legal
  // to receive: 0x4025 and 0x25 both decode to 37.
  const std::array<sample_t, 5> samples = {sample_t{"c2197c5eff14e88c", 151288809941952652ULL, 8}, sample_t{"9d7f3e7d", 494878333ULL, 4}, sample_t{"7bbd", 15293ULL, 2}, sample_t{"25", 37ULL, 1},
                                           sample_t{"4025", 37ULL, 2}};

  for (const auto &sample : samples)
  {
    const auto bytes = unhex(sample.hex);
    auto decoded = vio::quic::varint_decode(bytes);
    REQUIRE(decoded.has_value());
    CHECK(decoded->value == sample.value);
    CHECK(decoded->size == sample.size);
  }
}

TEST_CASE("varint encoding is minimal and round trips")
{
  struct sample_t
  {
    std::uint64_t value;
    std::string_view hex;
  };

  const std::array<sample_t, 4> samples = {sample_t{151288809941952652ULL, "c2197c5eff14e88c"}, sample_t{494878333ULL, "9d7f3e7d"}, sample_t{15293ULL, "7bbd"}, sample_t{37ULL, "25"}};

  for (const auto &sample : samples)
  {
    std::array<std::uint8_t, 8> out = {};
    const std::size_t written = vio::quic::varint_encode(out, sample.value);
    REQUIRE(written == sample.hex.size() / 2);
    CHECK(vio::crypto::to_hex(std::span<const std::uint8_t>(out.data(), written)) == sample.hex);

    auto decoded = vio::quic::varint_decode(std::span<const std::uint8_t>(out.data(), written));
    REQUIRE(decoded.has_value());
    CHECK(decoded->value == sample.value);
  }

  SUBCASE("boundaries pick the shortest encoding")
  {
    CHECK(vio::quic::varint_size(0) == 1);
    CHECK(vio::quic::varint_size(63) == 1);
    CHECK(vio::quic::varint_size(64) == 2);
    CHECK(vio::quic::varint_size(16383) == 2);
    CHECK(vio::quic::varint_size(16384) == 4);
    CHECK(vio::quic::varint_size(1073741823) == 4);
    CHECK(vio::quic::varint_size(1073741824) == 8);
    CHECK(vio::quic::varint_size(vio::quic::varint_max) == 8);
  }

  SUBCASE("a value beyond 62 bits is refused")
  {
    std::array<std::uint8_t, 8> out = {};
    CHECK(vio::quic::varint_encode(out, vio::quic::varint_max + 1) == 0);
  }

  SUBCASE("a short buffer is refused rather than truncated")
  {
    std::array<std::uint8_t, 1> out = {};
    CHECK(vio::quic::varint_encode(out, 16383) == 0);
  }

  SUBCASE("a truncated input decodes to nothing")
  {
    const auto bytes = unhex("c2197c");
    CHECK_FALSE(vio::quic::varint_decode(bytes).has_value());
    CHECK_FALSE(vio::quic::varint_decode({}).has_value());
  }
}

TEST_CASE("RFC 9000 A.2: packet number encoding length")
{
  // "if an endpoint has received an acknowledgment for packet 0xabe8b3 and is
  // sending a packet with a number of 0xac5c02 ... 16 bits are required."
  CHECK(vio::quic::packet_number_size(0xac5c02, 0xabe8b3) == 2);
  // "sending a packet with a number of 0xace8fe uses the 24-bit encoding"
  CHECK(vio::quic::packet_number_size(0xace8fe, 0xabe8b3) == 3);

  SUBCASE("with nothing acknowledged the whole number must be covered")
  {
    CHECK(vio::quic::packet_number_size(0, std::nullopt) == 1);
    CHECK(vio::quic::packet_number_size(127, std::nullopt) == 1);
    CHECK(vio::quic::packet_number_size(255, std::nullopt) == 2);
  }

  SUBCASE("the wire format caps the encoding at four bytes")
  {
    CHECK(vio::quic::packet_number_size(0xffffffffffULL, std::nullopt) == vio::quic::max_packet_number_size);
  }
}

TEST_CASE("RFC 9000 A.3: packet number decoding")
{
  // "if the highest successfully authenticated packet had a packet number of
  // 0xa82f30ea, then a packet containing a 16-bit value of 0x9b32 will be
  // decoded as 0xa82f9b32."
  CHECK(vio::quic::packet_number_decode(0xa82f30ea, 0x9b32, 16) == 0xa82f9b32);

  SUBCASE("encode then decode is the identity across the window")
  {
    const std::uint64_t largest = 0xa82f30ea;
    for (std::uint64_t offset : {std::uint64_t{1}, std::uint64_t{2}, std::uint64_t{1000}, std::uint64_t{30000}})
    {
      const std::uint64_t full = largest + offset;
      const std::size_t size = vio::quic::packet_number_size(full, largest);
      std::array<std::uint8_t, 4> out = {};
      const std::size_t written = vio::quic::packet_number_encode(out, full, size);
      REQUIRE(written == size);

      std::uint64_t truncated = 0;
      for (std::size_t i = 0; i < written; ++i)
      {
        truncated = (truncated << 8) | out[i];
      }
      CHECK(vio::quic::packet_number_decode(largest, truncated, written * 8) == full);
    }
  }

  SUBCASE("a bit count the wire cannot produce is refused, not shifted")
  {
    // The length comes from an unauthenticated header. A shift of 64 or more
    // is undefined behaviour rather than a big number, so the guard has to be
    // in the function and not in the caller's good intentions.
    CHECK(vio::quic::packet_number_decode(0xa82f30ea, 0x9b32, 0) == 0x9b32);
    CHECK(vio::quic::packet_number_decode(0xa82f30ea, 0x9b32, 33) == 0x9b32);
    CHECK(vio::quic::packet_number_decode(0xa82f30ea, 0x9b32, 64) == 0x9b32);
    CHECK(vio::quic::packet_number_decode(0xa82f30ea, 0x9b32, 4096) == 0x9b32);
  }

  SUBCASE("all four wire lengths round trip")
  {
    for (std::size_t bytes = 1; bytes <= 4; ++bytes)
    {
      CAPTURE(bytes);
      const std::uint64_t largest = 1000;
      const std::uint64_t full = largest + 1;
      std::array<std::uint8_t, 4> out = {};
      REQUIRE(vio::quic::packet_number_encode(out, full, bytes) == bytes);
      std::uint64_t truncated = 0;
      for (std::size_t i = 0; i < bytes; ++i)
      {
        truncated = (truncated << 8) | out[i];
      }
      CHECK(vio::quic::packet_number_decode(largest, truncated, bytes * 8) == full);
    }
  }

  SUBCASE("a wrapped candidate is pulled into the window")
  {
    // Expected is just past a 16-bit boundary, so a small truncated value
    // belongs to the next window rather than the current one.
    CHECK(vio::quic::packet_number_decode(0xffff, 0x0001, 16) == 0x10001);
  }
}

TEST_CASE("connection ids are inline, comparable and hashable")
{
  const auto bytes = unhex("8394c8f03e515708");
  auto id = vio::quic::connection_id_t::from_bytes(bytes);
  REQUIRE(id.has_value());
  CHECK(id->size() == 8);
  CHECK_FALSE(id->empty());
  CHECK(vio::crypto::to_hex(id->bytes()) == "8394c8f03e515708");

  auto same = vio::quic::connection_id_t::from_bytes(bytes);
  REQUIRE(same.has_value());
  CHECK(*id == *same);
  CHECK(std::hash<vio::quic::connection_id_t>{}(*id) == std::hash<vio::quic::connection_id_t>{}(*same));

  SUBCASE("a zero-length id is valid")
  {
    auto zero = vio::quic::connection_id_t::from_bytes({});
    REQUIRE(zero.has_value());
    CHECK(zero->empty());
    CHECK_FALSE(*zero == *id);
  }

  SUBCASE("a prefix is not equal to the longer id")
  {
    auto shorter = vio::quic::connection_id_t::from_bytes(std::span<const std::uint8_t>(bytes.data(), 4));
    REQUIRE(shorter.has_value());
    CHECK_FALSE(*shorter == *id);
  }

  SUBCASE("more than twenty bytes is refused")
  {
    const std::vector<std::uint8_t> too_long(vio::quic::max_connection_id_size + 1, 0xaa);
    CHECK_FALSE(vio::quic::connection_id_t::from_bytes(too_long).has_value());
    const std::vector<std::uint8_t> at_limit(vio::quic::max_connection_id_size, 0xaa);
    CHECK(vio::quic::connection_id_t::from_bytes(at_limit).has_value());
  }
}
}
