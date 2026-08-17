/*
  Copyright (c) 2025 Jørgen Lind

  Permission is hereby granted, free of charge, to any person obtaining a copy of
  this software and associated documentation files (the "Software"), to deal in
  the Software without restriction, including without limitation the rights to
  use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
  of the Software, and to permit persons to whom the Software is furnished to do
  so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
*/

#pragma once

// RFC 9000 frame taxonomy: which frames may appear in which packets
// (section 12.4, Table 3) and what a sender owes on loss (section 13.3).
//
// This table is deliberately settled before any frame codec exists, because it
// decides the shape of a sent-packet record. RFC 9000 section 13.3 opens with
// "QUIC packets that are determined to be lost are not retransmitted whole.
// The same applies to the frames that are contained within lost packets."
// A sender therefore records what a packet *meant*, not the bytes it held, and
// the three loss policies below are three different kinds of meaning:
//
//   discard         nothing to repair. A lost PING or PADDING carries no
//                   information; a stale ACK would inflate the peer's RTT
//                   sample; PATH_RESPONSE is sent exactly once; connection
//                   close is resent on receipt, never on loss.
//
//   retransmit      the same content again, byte for byte. RESET_STREAM "MUST
//                   NOT change when it is sent again"; NEW_CONNECTION_ID
//                   retransmissions "carry the same sequence number value".
//
//   resend_current  the signal again, carrying today's value rather than the
//                   lost one. MAX_DATA and friends send "an updated value";
//                   the blocked frames "always include the limit that is
//                   causing blocking at the time that they are transmitted",
//                   and only while still blocked.
//
// Storing frame bytes for replay would satisfy the middle case and silently
// corrupt the last one, which is why the distinction is drawn here rather
// than discovered later.

#include <cstddef>
#include <cstdint>
#include <optional>

namespace vio::quic
{
enum class packet_type_t : std::uint8_t
{
  initial,
  handshake,
  zero_rtt,
  one_rtt,
};

inline constexpr std::uint8_t packet_in_initial = 1U << 0;
inline constexpr std::uint8_t packet_in_handshake = 1U << 1;
inline constexpr std::uint8_t packet_in_zero_rtt = 1U << 2;
inline constexpr std::uint8_t packet_in_one_rtt = 1U << 3;
inline constexpr std::uint8_t packet_in_all = packet_in_initial | packet_in_handshake | packet_in_zero_rtt | packet_in_one_rtt;
inline constexpr std::uint8_t packet_in_application = packet_in_zero_rtt | packet_in_one_rtt;

[[nodiscard]] constexpr std::uint8_t packet_type_bit(packet_type_t type)
{
  switch (type)
  {
  case packet_type_t::initial:
    return packet_in_initial;
  case packet_type_t::handshake:
    return packet_in_handshake;
  case packet_type_t::zero_rtt:
    return packet_in_zero_rtt;
  case packet_type_t::one_rtt:
    return packet_in_one_rtt;
  }
  return 0;
}

enum class loss_policy_t : std::uint8_t
{
  discard,
  retransmit,
  resend_current,
};

// The distinct frames. Types that carry flags in the low bits (ACK, STREAM,
// MAX_STREAMS, STREAMS_BLOCKED, CONNECTION_CLOSE) collapse to one entry, with
// the flag bits read separately.
enum class frame_kind_t : std::uint8_t
{
  padding,
  ping,
  ack,
  reset_stream,
  stop_sending,
  crypto,
  new_token,
  stream,
  max_data,
  max_stream_data,
  max_streams,
  data_blocked,
  stream_data_blocked,
  streams_blocked,
  new_connection_id,
  retire_connection_id,
  path_challenge,
  path_response,
  connection_close,
  handshake_done,
};

struct frame_properties_t
{
  frame_kind_t kind = frame_kind_t::padding;
  std::uint8_t packets = 0;
  bool ack_eliciting = false;
  bool counts_in_flight = false;
  bool probing = false;
  bool flow_controlled = false;
  loss_policy_t loss_policy = loss_policy_t::discard;
};

// Returns nothing for a type this version does not define; RFC 9000 section
// 12.4 requires that to be a FRAME_ENCODING_ERROR rather than an ignore.
[[nodiscard]] inline std::optional<frame_properties_t> frame_properties(std::uint64_t type)
{
  using k = frame_kind_t;
  using p = loss_policy_t;

  auto make = [](frame_kind_t kind, std::uint8_t packets, bool ack_eliciting, bool counts_in_flight, bool probing, bool flow_controlled, loss_policy_t policy)
  { return frame_properties_t{.kind = kind, .packets = packets, .ack_eliciting = ack_eliciting, .counts_in_flight = counts_in_flight, .probing = probing, .flow_controlled = flow_controlled, .loss_policy = policy}; };

  switch (type)
  {
  // Marked NP, not NC: a packet of pure PADDING is still bytes on the wire, so
  // it counts toward congestion control, and section 9.1 lists PADDING among
  // the probing frames.
  case 0x00:
    return make(k::padding, packet_in_all, false, true, true, false, p::discard);
  case 0x01:
    return make(k::ping, packet_in_all, true, true, false, false, p::discard);
  case 0x02:
  case 0x03:
    return make(k::ack, packet_in_initial | packet_in_handshake | packet_in_one_rtt, false, false, false, false, p::discard);
  case 0x04:
    return make(k::reset_stream, packet_in_application, true, true, false, false, p::retransmit);
  case 0x05:
    return make(k::stop_sending, packet_in_application, true, true, false, false, p::retransmit);
  case 0x06:
    return make(k::crypto, packet_in_initial | packet_in_handshake | packet_in_one_rtt, true, true, false, false, p::retransmit);
  case 0x07:
    return make(k::new_token, packet_in_one_rtt, true, true, false, false, p::retransmit);
  case 0x08:
  case 0x09:
  case 0x0a:
  case 0x0b:
  case 0x0c:
  case 0x0d:
  case 0x0e:
  case 0x0f:
    return make(k::stream, packet_in_application, true, true, false, true, p::retransmit);
  case 0x10:
    return make(k::max_data, packet_in_application, true, true, false, false, p::resend_current);
  case 0x11:
    return make(k::max_stream_data, packet_in_application, true, true, false, false, p::resend_current);
  case 0x12:
  case 0x13:
    return make(k::max_streams, packet_in_application, true, true, false, false, p::resend_current);
  case 0x14:
    return make(k::data_blocked, packet_in_application, true, true, false, false, p::resend_current);
  case 0x15:
    return make(k::stream_data_blocked, packet_in_application, true, true, false, false, p::resend_current);
  case 0x16:
  case 0x17:
    return make(k::streams_blocked, packet_in_application, true, true, false, false, p::resend_current);
  case 0x18:
    return make(k::new_connection_id, packet_in_application, true, true, true, false, p::retransmit);
  case 0x19:
    return make(k::retire_connection_id, packet_in_application, true, true, false, false, p::retransmit);
  case 0x1a:
    return make(k::path_challenge, packet_in_application, true, true, true, false, p::discard);
  case 0x1b:
    return make(k::path_response, packet_in_one_rtt, true, true, true, false, p::discard);
  // Only the 0x1c form may appear in Initial or Handshake packets: the 0x1d
  // form carries an application error code, which has no meaning before the
  // application keys exist.
  case 0x1c:
    return make(k::connection_close, packet_in_all, false, true, false, false, p::discard);
  case 0x1d:
    return make(k::connection_close, packet_in_application, false, true, false, false, p::discard);
  case 0x1e:
    return make(k::handshake_done, packet_in_one_rtt, true, true, false, false, p::retransmit);
  default:
    return std::nullopt;
  }
}

[[nodiscard]] inline bool frame_allowed_in(std::uint64_t type, packet_type_t packet)
{
  const auto properties = frame_properties(type);
  return properties.has_value() && (properties->packets & packet_type_bit(packet)) != 0;
}
} // namespace vio::quic
