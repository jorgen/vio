#include <array>
#include <cstdint>
#include <vector>
#include <doctest/doctest.h>
#include <vio/quic/stateless_reset.h>

// RFC 9000 section 10.3. A stateless reset is the one message an endpoint can
// send about a connection it has completely forgotten, so everything about it
// is shaped by two constraints: it must be unguessable, and it must not be
// distinguishable from ordinary traffic.

namespace
{
using namespace vio::quic;

connection_id_t make_id(std::uint8_t seed)
{
  std::array<std::uint8_t, 8> bytes = {};
  for (std::size_t i = 0; i < bytes.size(); ++i)
  {
    bytes[i] = static_cast<std::uint8_t>(seed + i);
  }
  auto id = connection_id_t::from_bytes(bytes);
  REQUIRE(id.has_value());
  return *id;
}
} // namespace

TEST_SUITE("quic stateless reset")
{
TEST_CASE("a token is recomputable from the key and the connection id")
{
  // Section 10.3.2: this is the property that lets an endpoint answer for a
  // connection it no longer has any state for. A per-connection random token
  // would be lost exactly when it was needed.
  const std::vector<std::uint8_t> secret(32, 0x5a);
  const auto key = stateless_reset_key_t::from_secret(secret);
  const auto again = stateless_reset_key_t::from_secret(secret);

  CHECK(key.token_for(make_id(1)) == again.token_for(make_id(1)));
  CHECK_FALSE(key.token_for(make_id(1)) == key.token_for(make_id(2)));
}

TEST_CASE("different keys give different tokens for the same connection id")
{
  const auto first = stateless_reset_key_t::create();
  const auto second = stateless_reset_key_t::create();
  REQUIRE(first.has_value());
  REQUIRE(second.has_value());
  CHECK_FALSE(first->token_for(make_id(1)) == second->token_for(make_id(1)));
}

TEST_CASE("token comparison rejects the wrong length and every wrong byte")
{
  stateless_reset_token_t token = {};
  for (std::size_t i = 0; i < token.size(); ++i)
  {
    token[i] = static_cast<std::uint8_t>(i);
  }
  CHECK(tokens_equal(token, token));

  for (std::size_t i = 0; i < token.size(); ++i)
  {
    auto altered = token;
    altered[i] ^= 0xff;
    CHECK_FALSE(tokens_equal(token, altered));
  }

  std::vector<std::uint8_t> shorter(token.begin(), token.end() - 1);
  CHECK_FALSE(tokens_equal(token, shorter));
}

TEST_CASE("a reset looks like a short header packet")
{
  stateless_reset_token_t token = {};
  token.fill(0xab);
  std::vector<std::uint8_t> out(1200);

  auto size = build_stateless_reset(out, token, 1200);
  REQUIRE(size.has_value());
  REQUIRE(*size >= minimum_stateless_reset_size);
  // Header form 0, fixed bit 1: anything else is not a 1-RTT packet, and an
  // observer could filter resets out of a flow on sight.
  CHECK((out[0] & 0x80) == 0);
  CHECK((out[0] & 0x40) == 0x40);
  CHECK(std::equal(token.begin(), token.end(), out.begin() + static_cast<std::ptrdiff_t>(*size - token.size())));
}

TEST_CASE("a reset never amplifies")
{
  // Section 10.3: three times or more the size of what arrived would make an
  // endpoint that has lost its state into a reflector.
  stateless_reset_token_t token = {};
  token.fill(0x11);
  std::vector<std::uint8_t> out(1500);

  for (std::size_t received : {22u, 30u, 43u, 44u, 100u, 1200u})
  {
    auto size = build_stateless_reset(out, token, received);
    REQUIRE(size.has_value());
    CHECK(*size < received);
    CHECK(*size * 3 > *size);
  }
}

TEST_CASE("a small packet gets a smaller reset, so two of them cannot loop")
{
  // Section 10.3: answering a packet of 43 bytes or fewer with one byte less
  // means two endpoints that have both lost state shrink each exchange until
  // nothing valid can be sent.
  stateless_reset_token_t token = {};
  token.fill(0x22);
  std::vector<std::uint8_t> out(1500);

  auto size = build_stateless_reset(out, token, 40);
  REQUIRE(size.has_value());
  CHECK(*size == 39);

  // Below the point where a reply could be both valid and smaller, nothing is
  // sent at all.
  auto none = build_stateless_reset(out, token, minimum_stateless_reset_size);
  REQUIRE(none.has_value());
  CHECK(*none == 0);
}

TEST_CASE("a datagram too small to be a packet carries no token")
{
  std::vector<std::uint8_t> datagram(minimum_stateless_reset_size - 1, 0x00);
  CHECK(trailing_token(datagram).empty());

  std::vector<std::uint8_t> big_enough(minimum_stateless_reset_size, 0x00);
  CHECK(trailing_token(big_enough).size() == stateless_reset_token_size);
}
}
