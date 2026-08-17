#include <array>
#include <cstdint>
#include <optional>
#include <ostream>
#include <string_view>
#include <doctest/doctest.h>
#include <vio/quic/frame.h>

// RFC 9000 Table 3 and section 13.3, transcribed from the raw RFC text. The
// table is the contract the sent-packet record is built on, so it is asserted
// row by row rather than spot checked.

namespace
{
using namespace vio::quic;

struct row_t
{
  std::uint64_t type;
  frame_kind_t kind;
  std::string_view pkts; // the Table 3 "Pkts" column
  std::string_view spec; // the Table 3 "Spec" column
  loss_policy_t policy;  // section 13.3
};

// Pkts uses I H 0 1 with '_' for absent, exactly as the RFC prints it.
std::uint8_t mask_of(std::string_view pkts)
{
  std::uint8_t mask = 0;
  if (pkts[0] == 'I')
    mask |= packet_in_initial;
  if (pkts[1] == 'H')
    mask |= packet_in_handshake;
  if (pkts[2] == '0')
    mask |= packet_in_zero_rtt;
  if (pkts[3] == '1')
    mask |= packet_in_one_rtt;
  return mask;
}

constexpr bool has(std::string_view spec, char flag)
{
  return spec.find(flag) != std::string_view::npos;
}
} // namespace

TEST_SUITE("quic frame table")
{
TEST_CASE("RFC 9000 Table 3 and section 13.3, row by row")
{
  const std::array<row_t, 21> rows = {
    row_t{0x00, frame_kind_t::padding, "IH01", "NP", loss_policy_t::discard},
    row_t{0x01, frame_kind_t::ping, "IH01", "", loss_policy_t::discard},
    row_t{0x02, frame_kind_t::ack, "IH_1", "NC", loss_policy_t::discard},
    row_t{0x03, frame_kind_t::ack, "IH_1", "NC", loss_policy_t::discard},
    row_t{0x04, frame_kind_t::reset_stream, "__01", "", loss_policy_t::retransmit},
    row_t{0x05, frame_kind_t::stop_sending, "__01", "", loss_policy_t::retransmit},
    row_t{0x06, frame_kind_t::crypto, "IH_1", "", loss_policy_t::retransmit},
    row_t{0x07, frame_kind_t::new_token, "___1", "", loss_policy_t::retransmit},
    row_t{0x08, frame_kind_t::stream, "__01", "F", loss_policy_t::retransmit},
    row_t{0x0f, frame_kind_t::stream, "__01", "F", loss_policy_t::retransmit},
    row_t{0x10, frame_kind_t::max_data, "__01", "", loss_policy_t::resend_current},
    row_t{0x11, frame_kind_t::max_stream_data, "__01", "", loss_policy_t::resend_current},
    row_t{0x12, frame_kind_t::max_streams, "__01", "", loss_policy_t::resend_current},
    row_t{0x13, frame_kind_t::max_streams, "__01", "", loss_policy_t::resend_current},
    row_t{0x14, frame_kind_t::data_blocked, "__01", "", loss_policy_t::resend_current},
    row_t{0x15, frame_kind_t::stream_data_blocked, "__01", "", loss_policy_t::resend_current},
    row_t{0x16, frame_kind_t::streams_blocked, "__01", "", loss_policy_t::resend_current},
    row_t{0x17, frame_kind_t::streams_blocked, "__01", "", loss_policy_t::resend_current},
    row_t{0x18, frame_kind_t::new_connection_id, "__01", "P", loss_policy_t::retransmit},
    row_t{0x19, frame_kind_t::retire_connection_id, "__01", "", loss_policy_t::retransmit},
    row_t{0x1a, frame_kind_t::path_challenge, "__01", "P", loss_policy_t::discard},
  };

  for (const auto &row : rows)
  {
    CAPTURE(row.type);
    const auto properties = frame_properties(row.type);
    REQUIRE(properties.has_value());
    CHECK(properties->kind == row.kind);
    CHECK(properties->packets == mask_of(row.pkts));
    CHECK(properties->ack_eliciting == !has(row.spec, 'N'));
    CHECK(properties->counts_in_flight == !has(row.spec, 'C'));
    CHECK(properties->probing == has(row.spec, 'P'));
    CHECK(properties->flow_controlled == has(row.spec, 'F'));
    CHECK(properties->loss_policy == row.policy);
  }
}

TEST_CASE("the remaining Table 3 rows, which the ranges do not cover")
{
  SUBCASE("PATH_RESPONSE is 1-RTT only and probing")
  {
    const auto properties = frame_properties(0x1b);
    REQUIRE(properties.has_value());
    CHECK(properties->packets == packet_in_one_rtt);
    CHECK(properties->probing);
    // "Responses to path validation using PATH_RESPONSE frames are sent just
    // once."
    CHECK(properties->loss_policy == loss_policy_t::discard);
  }

  SUBCASE("HANDSHAKE_DONE is 1-RTT only and must be retransmitted")
  {
    const auto properties = frame_properties(0x1e);
    REQUIRE(properties.has_value());
    CHECK(properties->packets == packet_in_one_rtt);
    CHECK(properties->loss_policy == loss_policy_t::retransmit);
  }

  SUBCASE("only the 0x1c form of CONNECTION_CLOSE reaches Initial and Handshake")
  {
    const auto transport_close = frame_properties(0x1c);
    const auto application_close = frame_properties(0x1d);
    REQUIRE(transport_close.has_value());
    REQUIRE(application_close.has_value());
    CHECK(transport_close->packets == packet_in_all);
    CHECK(application_close->packets == packet_in_application);
    CHECK(frame_allowed_in(0x1c, packet_type_t::initial));
    CHECK_FALSE(frame_allowed_in(0x1d, packet_type_t::initial));
    CHECK_FALSE(frame_allowed_in(0x1d, packet_type_t::handshake));
    // "Connection close signals ... are not sent again when packet loss is
    // detected."
    CHECK(transport_close->loss_policy == loss_policy_t::discard);
    CHECK_FALSE(transport_close->ack_eliciting);
  }
}

TEST_CASE("an unknown frame type has no properties")
{
  CHECK_FALSE(frame_properties(0x1f).has_value());
  CHECK_FALSE(frame_properties(0x20).has_value());
  CHECK_FALSE(frame_properties(0x3fffffff).has_value());
  CHECK_FALSE(frame_allowed_in(0x1f, packet_type_t::one_rtt));
}

TEST_CASE("every frame is permitted in a 1-RTT packet")
{
  // "Note that all frames can appear in 1-RTT packets."
  for (std::uint64_t type = 0x00; type <= 0x1e; ++type)
  {
    CAPTURE(type);
    REQUIRE(frame_properties(type).has_value());
    CHECK(frame_allowed_in(type, packet_type_t::one_rtt));
  }
}

TEST_CASE("0-RTT excludes exactly the frames that need the handshake")
{
  // The frames a client cannot send before the handshake completes: those
  // carrying acknowledgements, crypto, or server-issued state.
  CHECK_FALSE(frame_allowed_in(0x02, packet_type_t::zero_rtt));
  CHECK_FALSE(frame_allowed_in(0x03, packet_type_t::zero_rtt));
  CHECK_FALSE(frame_allowed_in(0x06, packet_type_t::zero_rtt));
  CHECK_FALSE(frame_allowed_in(0x07, packet_type_t::zero_rtt));
  CHECK_FALSE(frame_allowed_in(0x1b, packet_type_t::zero_rtt));
  CHECK_FALSE(frame_allowed_in(0x1e, packet_type_t::zero_rtt));

  // RETIRE_CONNECTION_ID is permitted in 0-RTT, which is easy to get wrong
  // because NEW_CONNECTION_ID and PATH_CHALLENGE sit either side of it.
  CHECK(frame_allowed_in(0x19, packet_type_t::zero_rtt));
  CHECK(frame_allowed_in(0x18, packet_type_t::zero_rtt));
  CHECK(frame_allowed_in(0x1a, packet_type_t::zero_rtt));
}

TEST_CASE("a packet of only non-eliciting frames does not elicit an ack")
{
  // The N marking is a property of a packet containing only such frames, so
  // the per-frame flag is what a packet-level fold consumes.
  for (std::uint64_t type : {std::uint64_t{0x00}, std::uint64_t{0x02}, std::uint64_t{0x03}, std::uint64_t{0x1c}, std::uint64_t{0x1d}})
  {
    CAPTURE(type);
    CHECK_FALSE(frame_properties(type)->ack_eliciting);
  }
  CHECK(frame_properties(0x01)->ack_eliciting);
}

TEST_CASE("only ACK stays out of bytes in flight")
{
  // PADDING is marked NP rather than NC, so a padding-only packet is still
  // congestion controlled -- which is what makes anti-amplification padding
  // and MTU probes cost what they actually cost.
  for (std::uint64_t type = 0x00; type <= 0x1e; ++type)
  {
    CAPTURE(type);
    const bool expected = !(type == 0x02 || type == 0x03);
    CHECK(frame_properties(type)->counts_in_flight == expected);
  }
}

TEST_CASE("the probing frames are exactly the four in section 9.1")
{
  // "PATH_CHALLENGE, PATH_RESPONSE, NEW_CONNECTION_ID, and PADDING frames are
  // probing frames, and all other frames are non-probing frames."
  for (std::uint64_t type = 0x00; type <= 0x1e; ++type)
  {
    CAPTURE(type);
    const bool expected = type == 0x00 || type == 0x18 || type == 0x1a || type == 0x1b;
    CHECK(frame_properties(type)->probing == expected);
  }
}
}
