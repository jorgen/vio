#include <array>
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <ostream>
#include <span>
#include <string>
#include <vector>
#include <doctest/doctest.h>
#include <vio/crypto.h>
#include <vio/quic/transport_parameters.h>

// RFC 9000 section 18. The interesting part is not the round trip -- it is
// that an absent parameter means its default, and the defaults are not zero.
// Reading a missing ack_delay_exponent as 0 rather than 3 would put every ACK
// delay computed from a peer's frames out by a factor of eight, and nothing
// about the connection would visibly break.

namespace
{
using namespace vio::quic;

std::vector<std::uint8_t> bytes(std::initializer_list<int> values)
{
  std::vector<std::uint8_t> out;
  out.reserve(values.size());
  for (int value : values)
  {
    out.push_back(static_cast<std::uint8_t>(value));
  }
  return out;
}

std::string hex(std::span<const std::uint8_t> data)
{
  return vio::crypto::to_hex(data);
}

connection_id_t make_id(std::initializer_list<int> values)
{
  const auto raw = bytes(values);
  auto id = connection_id_t::from_bytes(raw);
  REQUIRE(id.has_value());
  return *id;
}
} // namespace

TEST_SUITE("quic transport parameters")
{
TEST_CASE("an empty extension decodes to every default")
{
  auto parameters = decode_transport_parameters({});
  REQUIRE(parameters.has_value());
  CHECK(parameters->max_idle_timeout == 0);
  CHECK(parameters->max_udp_payload_size == 65527);
  CHECK(parameters->ack_delay_exponent == 3);
  CHECK(parameters->max_ack_delay == 25);
  CHECK(parameters->active_connection_id_limit == 2);
  CHECK_FALSE(parameters->disable_active_migration);
  CHECK_FALSE(parameters->original_destination_connection_id.has_value());
  CHECK_FALSE(parameters->initial_source_connection_id.has_value());
  CHECK_FALSE(parameters->stateless_reset_token.has_value());
}

TEST_CASE("defaults are not written to the wire")
{
  const transport_parameters_t parameters;
  CHECK(encode_transport_parameters(parameters).empty());
}

TEST_CASE("a full set round trips")
{
  transport_parameters_t original;
  original.original_destination_connection_id = make_id({0x01, 0x02, 0x03, 0x04});
  original.max_idle_timeout = 30000;
  original.stateless_reset_token = std::array<std::uint8_t, 16>{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
  original.max_udp_payload_size = 1452;
  original.initial_max_data = 1048576;
  original.initial_max_stream_data_bidi_local = 262144;
  original.initial_max_stream_data_bidi_remote = 262144;
  original.initial_max_stream_data_uni = 131072;
  original.initial_max_streams_bidi = 100;
  original.initial_max_streams_uni = 3;
  original.ack_delay_exponent = 10;
  original.max_ack_delay = 50;
  original.disable_active_migration = true;
  original.active_connection_id_limit = 4;
  original.initial_source_connection_id = make_id({0xaa, 0xbb, 0xcc});
  original.retry_source_connection_id = make_id({0xdd, 0xee});

  const auto encoded = encode_transport_parameters(original);
  auto decoded = decode_transport_parameters(encoded);
  REQUIRE(decoded.has_value());

  CHECK(decoded->original_destination_connection_id == original.original_destination_connection_id);
  CHECK(decoded->max_idle_timeout == 30000);
  REQUIRE(decoded->stateless_reset_token.has_value());
  CHECK(hex(*decoded->stateless_reset_token) == hex(*original.stateless_reset_token));
  CHECK(decoded->max_udp_payload_size == 1452);
  CHECK(decoded->initial_max_data == 1048576);
  CHECK(decoded->initial_max_stream_data_bidi_local == 262144);
  CHECK(decoded->initial_max_stream_data_bidi_remote == 262144);
  CHECK(decoded->initial_max_stream_data_uni == 131072);
  CHECK(decoded->initial_max_streams_bidi == 100);
  CHECK(decoded->initial_max_streams_uni == 3);
  CHECK(decoded->ack_delay_exponent == 10);
  CHECK(decoded->max_ack_delay == 50);
  CHECK(decoded->disable_active_migration);
  CHECK(decoded->active_connection_id_limit == 4);
  CHECK(decoded->initial_source_connection_id == original.initial_source_connection_id);
  CHECK(decoded->retry_source_connection_id == original.retry_source_connection_id);

  SUBCASE("and encoding the decoded form reproduces the bytes")
  {
    CHECK(hex(encode_transport_parameters(*decoded)) == hex(encoded));
  }
}

TEST_CASE("a zero-length connection id is carried, not confused with absence")
{
  transport_parameters_t original;
  original.initial_source_connection_id = connection_id_t{};
  const auto encoded = encode_transport_parameters(original);
  auto decoded = decode_transport_parameters(encoded);
  REQUIRE(decoded.has_value());
  REQUIRE(decoded->initial_source_connection_id.has_value());
  CHECK(decoded->initial_source_connection_id->empty());
}

TEST_CASE("the wire encoding is the tuple form section 18 describes")
{
  transport_parameters_t parameters;
  parameters.max_idle_timeout = 5;
  const auto encoded = encode_transport_parameters(parameters);
  // id 0x01, length 1, value 5.
  CHECK(hex(encoded) == "010105");

  SUBCASE("a flag parameter is present with a zero length")
  {
    transport_parameters_t flag;
    flag.disable_active_migration = true;
    CHECK(hex(encode_transport_parameters(flag)) == "0c00");
  }

  SUBCASE("a connection id is a length-prefixed byte string")
  {
    transport_parameters_t identity;
    identity.initial_source_connection_id = make_id({0xaa, 0xbb});
    CHECK(hex(encode_transport_parameters(identity)) == "0f02aabb");
  }
}

TEST_CASE("unknown parameters are ignored")
{
  // Section 18.1 reserves ids of the form 31*N+27 precisely so that this is
  // exercised; 27 and 58 are the first two.
  auto input = bytes({0x1b, 0x03, 0xde, 0xad, 0xbe, 0x40, 0x3a, 0x01, 0xff, 0x01, 0x01, 0x07});
  auto decoded = decode_transport_parameters(input);
  REQUIRE(decoded.has_value());
  CHECK(decoded->max_idle_timeout == 7);

  SUBCASE("including one this build has no field for")
  {
    // preferred_address, which is parsed past and dropped.
    auto with_preferred = bytes({0x0d, 0x02, 0xaa, 0xbb, 0x01, 0x01, 0x09});
    auto parsed = decode_transport_parameters(with_preferred);
    REQUIRE(parsed.has_value());
    CHECK(parsed->max_idle_timeout == 9);
  }
}

TEST_CASE("a duplicated parameter is refused")
{
  auto input = bytes({0x01, 0x01, 0x05, 0x01, 0x01, 0x06});
  auto decoded = decode_transport_parameters(input);
  REQUIRE_FALSE(decoded.has_value());
  CHECK(decoded.error() == transport_parameter_error_t::duplicate);

  SUBCASE("even when this build does not recognise it")
  {
    auto unknown = bytes({0x1b, 0x01, 0x05, 0x1b, 0x01, 0x06});
    auto parsed = decode_transport_parameters(unknown);
    REQUIRE_FALSE(parsed.has_value());
    CHECK(parsed.error() == transport_parameter_error_t::duplicate);
  }
}

TEST_CASE("the values section 18.2 calls invalid are refused")
{
  const auto refused = [](std::initializer_list<int> raw)
  {
    const auto input = bytes(raw);
    auto decoded = decode_transport_parameters(input);
    REQUIRE_FALSE(decoded.has_value());
    CHECK(decoded.error() == transport_parameter_error_t::invalid_value);
  };

  SUBCASE("an ack delay exponent above 20")
  {
    refused({0x0a, 0x01, 21});
    // Exactly 20 is fine.
    const auto ok = bytes({0x0a, 0x01, 20});
    auto decoded = decode_transport_parameters(ok);
    REQUIRE(decoded.has_value());
    CHECK(decoded->ack_delay_exponent == 20);
  }

  SUBCASE("a max ack delay of 2^14 or more")
  {
    // 16384 as a four byte varint.
    refused({0x0b, 0x04, 0x80, 0x00, 0x40, 0x00});
    const auto ok = bytes({0x0b, 0x04, 0x80, 0x00, 0x3f, 0xff});
    auto decoded = decode_transport_parameters(ok);
    REQUIRE(decoded.has_value());
    CHECK(decoded->max_ack_delay == 16383);
  }

  SUBCASE("a max UDP payload size below 1200")
  {
    refused({0x03, 0x02, 0x44, 0xaf});
    const auto ok = bytes({0x03, 0x02, 0x44, 0xb0});
    auto decoded = decode_transport_parameters(ok);
    REQUIRE(decoded.has_value());
    CHECK(decoded->max_udp_payload_size == 1200);
  }

  SUBCASE("an active connection id limit below 2")
  {
    refused({0x0e, 0x01, 0x01});
    refused({0x0e, 0x01, 0x00});
    const auto ok = bytes({0x0e, 0x01, 0x02});
    CHECK(decode_transport_parameters(ok).has_value());
  }

  SUBCASE("a stateless reset token that is not sixteen bytes")
  {
    refused({0x02, 0x02, 0xaa, 0xbb});
  }

  SUBCASE("a connection id longer than twenty bytes")
  {
    std::vector<std::uint8_t> input = {0x0f, 0x15};
    input.insert(input.end(), 21, 0xaa);
    auto decoded = decode_transport_parameters(input);
    REQUIRE_FALSE(decoded.has_value());
    CHECK(decoded.error() == transport_parameter_error_t::invalid_value);
  }

  SUBCASE("a stream count above 2^60")
  {
    refused({0x08, 0x08, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01});
  }

  SUBCASE("a flag parameter carrying a value")
  {
    refused({0x0c, 0x01, 0x01});
  }

  SUBCASE("an integer with trailing bytes in its value field")
  {
    // Length says two bytes but the varint inside is one: the value field has
    // to be exactly the integer.
    refused({0x01, 0x02, 0x05, 0x00});
  }
}

TEST_CASE("truncated input is refused rather than read past")
{
  const auto full = bytes({0x01, 0x01, 0x05, 0x0f, 0x02, 0xaa, 0xbb});
  auto complete = decode_transport_parameters(full);
  REQUIRE(complete.has_value());

  for (std::size_t length = 1; length < full.size(); ++length)
  {
    CAPTURE(length);
    const std::vector<std::uint8_t> prefix(full.begin(), full.begin() + static_cast<std::ptrdiff_t>(length));
    auto decoded = decode_transport_parameters(prefix);
    if (!decoded.has_value())
    {
      CHECK(decoded.error() == transport_parameter_error_t::truncated);
    }
    else
    {
      // A prefix that happens to end on a tuple boundary is well formed; it
      // just carries fewer parameters.
      CHECK(length == 3);
    }
  }

  SUBCASE("a length that runs past the end")
  {
    const auto lying = bytes({0x0f, 0x40, 0xaa, 0xbb});
    auto decoded = decode_transport_parameters(lying);
    REQUIRE_FALSE(decoded.has_value());
    CHECK(decoded.error() == transport_parameter_error_t::truncated);
  }
}

TEST_CASE("every single byte corruption is handled without reading past the end")
{
  const auto original = bytes({0x01, 0x01, 0x05, 0x03, 0x02, 0x45, 0xac, 0x0a, 0x01, 0x0a, 0x0f, 0x02, 0xaa, 0xbb, 0x0c, 0x00});
  REQUIRE(decode_transport_parameters(original).has_value());

  for (std::size_t index = 0; index < original.size(); ++index)
  {
    for (int value = 0; value < 256; value += 13)
    {
      CAPTURE(index);
      CAPTURE(value);
      std::vector<std::uint8_t> mutated = original;
      mutated[index] = static_cast<std::uint8_t>(value);
      // Either it parses or it reports why; neither may read out of bounds,
      // which is what the sanitizer builds are here to confirm.
      auto decoded = decode_transport_parameters(mutated);
      if (!decoded.has_value())
      {
        const bool known = decoded.error() == transport_parameter_error_t::truncated || decoded.error() == transport_parameter_error_t::duplicate || decoded.error() == transport_parameter_error_t::invalid_value;
        CHECK(known);
      }
    }
  }
}
}
