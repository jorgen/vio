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

// RFC 9000 section 19 frames, both directions.
//
// frame_reader_t is a cursor over one packet payload, yielding one frame at a
// time. Nothing is allocated and nothing is copied: variable-length fields
// come back as spans into the caller buffer, so the payload must outlive the
// frames read from it.
//
// Every field is bounds checked against the remaining input before it is read.
// These bytes have been authenticated by the AEAD but are not otherwise
// trusted: a peer is free to encode a length that runs off the end of its own
// packet, and the answer has to be a connection error rather than a read past
// the buffer.
//
// frame_writer_t is the mirror image, appending frames to the payload region
// of a packet under construction. It answers the one question a packetizer
// asks -- does this frame fit in what is left -- without ever leaving a half
// written frame behind.

#include "vio/quic/connection_id.h"
#include "vio/quic/frame.h"
#include "vio/quic/varint.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <optional>
#include <span>

namespace vio::quic
{
// RFC 9000 section 20.1. Only the codes this layer can raise are named.
enum class transport_error_code_t : std::uint64_t
{
  no_error = 0x00,
  frame_encoding_error = 0x07,
  protocol_violation = 0x0a,
};

struct frame_error_t
{
  transport_error_code_t code = transport_error_code_t::frame_encoding_error;
  std::uint64_t frame_type = 0;
  const char *reason = "";
};

inline constexpr std::uint8_t stream_flag_fin = 0x01;
inline constexpr std::uint8_t stream_flag_len = 0x02;
inline constexpr std::uint8_t stream_flag_off = 0x04;
inline constexpr std::size_t stateless_reset_token_size = 16;
inline constexpr std::size_t path_data_size = 8;
inline constexpr std::uint64_t max_stream_count = std::uint64_t{1} << 60;

struct ack_range_t
{
  std::uint64_t gap = 0;
  std::uint64_t length = 0;
};

struct ecn_counts_t
{
  std::uint64_t ect0 = 0;
  std::uint64_t ect1 = 0;
  std::uint64_t ce = 0;
};

struct frame_t
{
  frame_kind_t kind = frame_kind_t::padding;
  std::uint64_t type = 0;

  // A run of PADDING is one frame with a count. A packet is routinely mostly
  // padding, and one frame per byte would make parsing quadratic in it.
  std::uint64_t padding_count = 0;

  std::uint64_t stream_id = 0;
  std::uint64_t offset = 0;
  bool fin = false;

  // STREAM without the LEN bit: the payload runs to the end of the packet,
  // so only the last frame in a packet may carry it.
  bool omit_length = false;

  // Stream data, crypto data, token, or reason phrase, by kind.
  std::span<const std::uint8_t> data;

  std::uint64_t maximum = 0;
  std::uint64_t error_code = 0;
  std::uint64_t final_size = 0;
  std::uint64_t sequence_number = 0;
  std::uint64_t retire_prior_to = 0;
  std::uint64_t triggering_frame_type = 0;
  bool bidirectional = false;

  // CONNECTION_CLOSE 0x1d, whose error code is the application's rather than
  // the transport's.
  bool application_error = false;

  std::uint64_t largest_acknowledged = 0;
  std::uint64_t ack_delay = 0;
  std::uint64_t first_ack_range = 0;
  std::uint64_t ack_range_count = 0;
  // The encoded ACK Range list, left to ack_range_reader_t rather than decoded
  // into storage the caller did not provide.
  std::span<const std::uint8_t> ack_ranges;
  std::optional<ecn_counts_t> ecn;

  connection_id_t connection_id;
  std::span<const std::uint8_t> stateless_reset_token;
  std::span<const std::uint8_t> path_data;
};

class ack_range_reader_t
{
public:
  explicit ack_range_reader_t(std::span<const std::uint8_t> encoded)
    : _input(encoded)
  {
  }

  [[nodiscard]] std::optional<ack_range_t> next()
  {
    if (_position >= _input.size())
    {
      return std::nullopt;
    }
    auto gap = varint_decode(_input.subspan(_position));
    if (!gap.has_value())
    {
      return std::nullopt;
    }
    _position += gap->size;
    auto length = varint_decode(_input.subspan(_position));
    if (!length.has_value())
    {
      return std::nullopt;
    }
    _position += length->size;
    return ack_range_t{.gap = gap->value, .length = length->value};
  }

private:
  std::span<const std::uint8_t> _input;
  std::size_t _position = 0;
};

class frame_reader_t
{
public:
  frame_reader_t(std::span<const std::uint8_t> payload, packet_type_t packet)
    : _input(payload)
    , _packet(packet)
  {
  }

  [[nodiscard]] bool done() const
  {
    return _position >= _input.size();
  }

  [[nodiscard]] std::size_t position() const
  {
    return _position;
  }

  // Nothing once the payload is exhausted.
  [[nodiscard]] std::optional<std::expected<frame_t, frame_error_t>> next()
  {
    if (done())
    {
      return std::nullopt;
    }
    return read_one();
  }

private:
  [[nodiscard]] std::span<const std::uint8_t> remaining() const
  {
    return _input.subspan(_position);
  }

  [[nodiscard]] bool take_varint(std::uint64_t &out)
  {
    auto decoded = varint_decode(remaining());
    if (!decoded.has_value())
    {
      return false;
    }
    _position += decoded->size;
    out = decoded->value;
    return true;
  }

  [[nodiscard]] bool take_bytes(std::size_t count, std::span<const std::uint8_t> &out)
  {
    if (_input.size() - _position < count)
    {
      return false;
    }
    out = _input.subspan(_position, count);
    _position += count;
    return true;
  }

  // A length field is compared against what is left before it is cast to
  // size_t: a 62-bit varint would otherwise truncate on a 32-bit size_t and
  // pass a length check it should have failed.
  [[nodiscard]] bool take_length_prefixed(std::uint64_t length, std::span<const std::uint8_t> &out)
  {
    if (length > _input.size() - _position)
    {
      return false;
    }
    return take_bytes(static_cast<std::size_t>(length), out);
  }

  static std::unexpected<frame_error_t> truncated(std::uint64_t type)
  {
    return std::unexpected(frame_error_t{.code = transport_error_code_t::frame_encoding_error, .frame_type = type, .reason = "frame runs past the end of the packet"});
  }

  static std::unexpected<frame_error_t> invalid(std::uint64_t type, const char *reason, transport_error_code_t code = transport_error_code_t::frame_encoding_error)
  {
    return std::unexpected(frame_error_t{.code = code, .frame_type = type, .reason = reason});
  }

  std::expected<frame_t, frame_error_t> read_one();

  std::span<const std::uint8_t> _input;
  packet_type_t _packet;
  std::size_t _position = 0;
};

inline std::expected<frame_t, frame_error_t> frame_reader_t::read_one()
{
  std::uint64_t type = 0;
  if (!take_varint(type))
  {
    return truncated(0);
  }

  const auto properties = frame_properties(type);
  if (!properties.has_value())
  {
    // Section 12.4: an unknown frame type is a connection error, not
    // something to skip over.
    return invalid(type, "unknown frame type");
  }
  if ((properties->packets & packet_type_bit(_packet)) == 0)
  {
    return invalid(type, "frame is not permitted in this packet type", transport_error_code_t::protocol_violation);
  }

  frame_t frame;
  frame.kind = properties->kind;
  frame.type = type;

  switch (properties->kind)
  {
  case frame_kind_t::padding:
    frame.padding_count = 1;
    while (_position < _input.size() && _input[_position] == 0x00)
    {
      ++_position;
      ++frame.padding_count;
    }
    return frame;

  case frame_kind_t::ping:
  case frame_kind_t::handshake_done:
    return frame;

  case frame_kind_t::ack:
  {
    if (!take_varint(frame.largest_acknowledged) || !take_varint(frame.ack_delay) || !take_varint(frame.ack_range_count) || !take_varint(frame.first_ack_range))
    {
      return truncated(type);
    }
    // Each range costs at least two bytes, so a count larger than half of what
    // remains is a lie. Rejecting it here keeps the loop below bounded by the
    // input rather than by a 62-bit number.
    if (frame.ack_range_count > (_input.size() - _position) / 2)
    {
      return invalid(type, "ACK range count exceeds the bytes available");
    }
    const std::size_t ranges_start = _position;
    for (std::uint64_t i = 0; i < frame.ack_range_count; ++i)
    {
      std::uint64_t gap = 0;
      std::uint64_t length = 0;
      if (!take_varint(gap) || !take_varint(length))
      {
        return truncated(type);
      }
    }
    frame.ack_ranges = _input.subspan(ranges_start, _position - ranges_start);

    if (type == 0x03)
    {
      ecn_counts_t counts;
      if (!take_varint(counts.ect0) || !take_varint(counts.ect1) || !take_varint(counts.ce))
      {
        return truncated(type);
      }
      frame.ecn = counts;
    }
    return frame;
  }

  case frame_kind_t::reset_stream:
    if (!take_varint(frame.stream_id) || !take_varint(frame.error_code) || !take_varint(frame.final_size))
    {
      return truncated(type);
    }
    return frame;

  case frame_kind_t::stop_sending:
    if (!take_varint(frame.stream_id) || !take_varint(frame.error_code))
    {
      return truncated(type);
    }
    return frame;

  case frame_kind_t::crypto:
  {
    std::uint64_t length = 0;
    if (!take_varint(frame.offset) || !take_varint(length))
    {
      return truncated(type);
    }
    if (!take_length_prefixed(length, frame.data))
    {
      return truncated(type);
    }
    // Section 19.6: the largest offset delivered on a stream cannot exceed
    // 2^62-1, and the check has to happen before anything adds the two.
    if (frame.offset > varint_max - length)
    {
      return invalid(type, "CRYPTO offset plus length exceeds 2^62-1");
    }
    return frame;
  }

  case frame_kind_t::new_token:
  {
    std::uint64_t length = 0;
    if (!take_varint(length))
    {
      return truncated(type);
    }
    // Section 19.7: a zero-length token is a FRAME_ENCODING_ERROR.
    if (length == 0)
    {
      return invalid(type, "NEW_TOKEN with an empty token");
    }
    if (!take_length_prefixed(length, frame.data))
    {
      return truncated(type);
    }
    return frame;
  }

  case frame_kind_t::stream:
  {
    const auto flags = static_cast<std::uint8_t>(type & 0x07);
    frame.fin = (flags & stream_flag_fin) != 0;
    if (!take_varint(frame.stream_id))
    {
      return truncated(type);
    }
    if ((flags & stream_flag_off) != 0 && !take_varint(frame.offset))
    {
      return truncated(type);
    }
    if ((flags & stream_flag_len) != 0)
    {
      std::uint64_t length = 0;
      if (!take_varint(length))
      {
        return truncated(type);
      }
      if (!take_length_prefixed(length, frame.data))
      {
        return truncated(type);
      }
    }
    else
    {
      // Without the LEN bit the frame runs to the end of the packet.
      frame.omit_length = true;
      frame.data = remaining();
      _position = _input.size();
    }
    // Section 4.5: a final size above 2^62-1 is a FRAME_ENCODING_ERROR.
    if (frame.offset > varint_max - frame.data.size())
    {
      return invalid(type, "STREAM offset plus length exceeds 2^62-1");
    }
    return frame;
  }

  case frame_kind_t::max_data:
  case frame_kind_t::data_blocked:
    if (!take_varint(frame.maximum))
    {
      return truncated(type);
    }
    return frame;

  case frame_kind_t::max_stream_data:
  case frame_kind_t::stream_data_blocked:
    if (!take_varint(frame.stream_id) || !take_varint(frame.maximum))
    {
      return truncated(type);
    }
    return frame;

  case frame_kind_t::max_streams:
  case frame_kind_t::streams_blocked:
    // The low bit selects the stream type: 0x12 and 0x16 are bidirectional.
    frame.bidirectional = (type & 0x01) == 0;
    if (!take_varint(frame.maximum))
    {
      return truncated(type);
    }
    // Sections 19.11 and 19.14: a count above 2^60 cannot be encoded as a
    // stream ID and is a connection error.
    if (frame.maximum > max_stream_count)
    {
      return invalid(type, "stream count exceeds 2^60");
    }
    return frame;

  case frame_kind_t::new_connection_id:
  {
    if (!take_varint(frame.sequence_number) || !take_varint(frame.retire_prior_to))
    {
      return truncated(type);
    }
    // Section 19.15 names FRAME_ENCODING_ERROR for this, not the
    // PROTOCOL_VIOLATION the rule reads like.
    if (frame.retire_prior_to > frame.sequence_number)
    {
      return invalid(type, "Retire Prior To is greater than Sequence Number");
    }
    std::span<const std::uint8_t> length_byte;
    if (!take_bytes(1, length_byte))
    {
      return truncated(type);
    }
    const std::size_t id_length = length_byte[0];
    if (id_length < 1 || id_length > max_connection_id_size)
    {
      return invalid(type, "connection ID length outside 1..20");
    }
    std::span<const std::uint8_t> id_bytes;
    if (!take_bytes(id_length, id_bytes))
    {
      return truncated(type);
    }
    auto id = connection_id_t::from_bytes(id_bytes);
    if (!id.has_value())
    {
      return truncated(type);
    }
    frame.connection_id = *id;
    if (!take_bytes(stateless_reset_token_size, frame.stateless_reset_token))
    {
      return truncated(type);
    }
    return frame;
  }

  case frame_kind_t::retire_connection_id:
    if (!take_varint(frame.sequence_number))
    {
      return truncated(type);
    }
    return frame;

  case frame_kind_t::path_challenge:
  case frame_kind_t::path_response:
    if (!take_bytes(path_data_size, frame.path_data))
    {
      return truncated(type);
    }
    return frame;

  case frame_kind_t::connection_close:
  {
    frame.application_error = type == 0x1d;
    if (!take_varint(frame.error_code))
    {
      return truncated(type);
    }
    // Only the transport form carries the frame type that triggered it.
    if (type == 0x1c && !take_varint(frame.triggering_frame_type))
    {
      return truncated(type);
    }
    std::uint64_t length = 0;
    if (!take_varint(length))
    {
      return truncated(type);
    }
    if (!take_length_prefixed(length, frame.data))
    {
      return truncated(type);
    }
    return frame;
  }
  }

  return invalid(type, "unhandled frame kind");
}

// The type byte a frame encodes to, derived from the frame fields rather than
// from frame_t::type: the flag bits are meaning, not decoration, and deriving
// them keeps a hand-built frame and a decoded one on the same footing. The
// derivation is minimal, so decoding and re-encoding reproduces the input
// exactly when the input was itself minimal, and shortens it otherwise -- a
// STREAM that spelled out an offset of zero loses the OFF bit it did not
// need.
[[nodiscard]] inline std::uint64_t frame_type_byte(const frame_t &frame)
{
  switch (frame.kind)
  {
  case frame_kind_t::padding:
    return 0x00;
  case frame_kind_t::ping:
    return 0x01;
  case frame_kind_t::ack:
    return frame.ecn.has_value() ? 0x03 : 0x02;
  case frame_kind_t::reset_stream:
    return 0x04;
  case frame_kind_t::stop_sending:
    return 0x05;
  case frame_kind_t::crypto:
    return 0x06;
  case frame_kind_t::new_token:
    return 0x07;
  case frame_kind_t::stream:
  {
    std::uint64_t type = 0x08;
    if (frame.offset != 0)
    {
      type |= stream_flag_off;
    }
    if (!frame.omit_length)
    {
      type |= stream_flag_len;
    }
    if (frame.fin)
    {
      type |= stream_flag_fin;
    }
    return type;
  }
  case frame_kind_t::max_data:
    return 0x10;
  case frame_kind_t::max_stream_data:
    return 0x11;
  case frame_kind_t::max_streams:
    return frame.bidirectional ? 0x12 : 0x13;
  case frame_kind_t::data_blocked:
    return 0x14;
  case frame_kind_t::stream_data_blocked:
    return 0x15;
  case frame_kind_t::streams_blocked:
    return frame.bidirectional ? 0x16 : 0x17;
  case frame_kind_t::new_connection_id:
    return 0x18;
  case frame_kind_t::retire_connection_id:
    return 0x19;
  case frame_kind_t::path_challenge:
    return 0x1a;
  case frame_kind_t::path_response:
    return 0x1b;
  case frame_kind_t::connection_close:
    return frame.application_error ? 0x1d : 0x1c;
  case frame_kind_t::handshake_done:
    return 0x1e;
  }
  return 0x00;
}

// Whether write() can encode this frame at all, independent of how much room
// is left. Every value a frame encodes as a varint has to be inside the
// 62-bit range, and the kinds with their own well-formedness rules are held
// to the same ones the decoder enforces, so a peer never has to reject what
// this library emitted.
[[nodiscard]] inline bool frame_is_encodable(const frame_t &frame)
{
  const auto fits = [](std::uint64_t value) { return value <= varint_max; };

  switch (frame.kind)
  {
  case frame_kind_t::padding:
  case frame_kind_t::ping:
  case frame_kind_t::handshake_done:
    return true;

  case frame_kind_t::ack:
    if (frame.ecn.has_value() && !(fits(frame.ecn->ect0) && fits(frame.ecn->ect1) && fits(frame.ecn->ce)))
    {
      return false;
    }
    return fits(frame.largest_acknowledged) && fits(frame.ack_delay) && fits(frame.ack_range_count) && fits(frame.first_ack_range);

  case frame_kind_t::reset_stream:
    return fits(frame.stream_id) && fits(frame.error_code) && fits(frame.final_size);

  case frame_kind_t::stop_sending:
    return fits(frame.stream_id) && fits(frame.error_code);

  case frame_kind_t::crypto:
    return fits(frame.data.size()) && frame.offset <= varint_max - frame.data.size();

  case frame_kind_t::new_token:
    return !frame.data.empty() && fits(frame.data.size());

  case frame_kind_t::stream:
    return fits(frame.stream_id) && fits(frame.data.size()) && frame.offset <= varint_max - frame.data.size();

  case frame_kind_t::max_data:
  case frame_kind_t::data_blocked:
    return fits(frame.maximum);

  case frame_kind_t::max_stream_data:
  case frame_kind_t::stream_data_blocked:
    return fits(frame.stream_id) && fits(frame.maximum);

  case frame_kind_t::max_streams:
  case frame_kind_t::streams_blocked:
    return frame.maximum <= max_stream_count;

  case frame_kind_t::new_connection_id:
    return fits(frame.sequence_number) && frame.retire_prior_to <= frame.sequence_number && frame.connection_id.size() >= 1 && frame.connection_id.size() <= max_connection_id_size && frame.stateless_reset_token.size() == stateless_reset_token_size;

  case frame_kind_t::retire_connection_id:
    return fits(frame.sequence_number);

  case frame_kind_t::path_challenge:
  case frame_kind_t::path_response:
    return frame.path_data.size() == path_data_size;

  case frame_kind_t::connection_close:
    return fits(frame.error_code) && fits(frame.data.size()) && (frame.application_error || fits(frame.triggering_frame_type));
  }
  return false;
}

// What write() will consume, so a packetizer can decide whether a frame fits
// before attempting it.
[[nodiscard]] inline std::size_t frame_encoded_size(const frame_t &frame)
{
  if (frame.kind == frame_kind_t::padding)
  {
    return static_cast<std::size_t>(frame.padding_count);
  }

  std::size_t size = varint_size(frame_type_byte(frame));
  switch (frame.kind)
  {
  case frame_kind_t::padding:
  case frame_kind_t::ping:
  case frame_kind_t::handshake_done:
    break;
  case frame_kind_t::ack:
    size += varint_size(frame.largest_acknowledged) + varint_size(frame.ack_delay) + varint_size(frame.ack_range_count) + varint_size(frame.first_ack_range) + frame.ack_ranges.size();
    if (frame.ecn.has_value())
    {
      size += varint_size(frame.ecn->ect0) + varint_size(frame.ecn->ect1) + varint_size(frame.ecn->ce);
    }
    break;
  case frame_kind_t::reset_stream:
    size += varint_size(frame.stream_id) + varint_size(frame.error_code) + varint_size(frame.final_size);
    break;
  case frame_kind_t::stop_sending:
    size += varint_size(frame.stream_id) + varint_size(frame.error_code);
    break;
  case frame_kind_t::crypto:
    size += varint_size(frame.offset) + varint_size(frame.data.size()) + frame.data.size();
    break;
  case frame_kind_t::new_token:
    size += varint_size(frame.data.size()) + frame.data.size();
    break;
  case frame_kind_t::stream:
    size += varint_size(frame.stream_id);
    if (frame.offset != 0)
    {
      size += varint_size(frame.offset);
    }
    if (!frame.omit_length)
    {
      size += varint_size(frame.data.size());
    }
    size += frame.data.size();
    break;
  case frame_kind_t::max_data:
  case frame_kind_t::max_streams:
  case frame_kind_t::data_blocked:
  case frame_kind_t::streams_blocked:
    size += varint_size(frame.maximum);
    break;
  case frame_kind_t::max_stream_data:
  case frame_kind_t::stream_data_blocked:
    size += varint_size(frame.stream_id) + varint_size(frame.maximum);
    break;
  case frame_kind_t::new_connection_id:
    size += varint_size(frame.sequence_number) + varint_size(frame.retire_prior_to) + 1 + frame.connection_id.size() + stateless_reset_token_size;
    break;
  case frame_kind_t::retire_connection_id:
    size += varint_size(frame.sequence_number);
    break;
  case frame_kind_t::path_challenge:
  case frame_kind_t::path_response:
    size += path_data_size;
    break;
  case frame_kind_t::connection_close:
    size += varint_size(frame.error_code);
    if (!frame.application_error)
    {
      size += varint_size(frame.triggering_frame_type);
    }
    size += varint_size(frame.data.size()) + frame.data.size();
    break;
  }
  return size;
}

// Builds the ACK Range list that a frame_t carries as an opaque span, so an
// ACK can be assembled without hand-encoding varints at the call site.
class ack_range_writer_t
{
public:
  explicit ack_range_writer_t(std::span<std::uint8_t> out)
    : _out(out)
  {
  }

  [[nodiscard]] bool write(const ack_range_t &range)
  {
    const std::size_t start = _position;
    if (!put_varint(range.gap) || !put_varint(range.length))
    {
      _position = start;
      return false;
    }
    ++_count;
    return true;
  }

  [[nodiscard]] std::uint64_t count() const
  {
    return _count;
  }

  [[nodiscard]] std::span<const std::uint8_t> bytes() const
  {
    return _out.first(_position);
  }

private:
  bool put_varint(std::uint64_t value)
  {
    const std::size_t written = varint_encode(_out.subspan(_position), value);
    _position += written;
    return written != 0;
  }

  std::span<std::uint8_t> _out;
  std::size_t _position = 0;
  std::uint64_t _count = 0;
};

// Appends frames to a caller-owned buffer, typically the payload region of a
// packet under construction.
class frame_writer_t
{
public:
  explicit frame_writer_t(std::span<std::uint8_t> out)
    : _out(out)
  {
  }

  [[nodiscard]] std::size_t written() const
  {
    return _position;
  }

  [[nodiscard]] std::size_t remaining() const
  {
    return _out.size() - _position;
  }

  [[nodiscard]] std::span<const std::uint8_t> bytes() const
  {
    return _out.first(_position);
  }

  // A frame is written whole or not at all, and both conditions for not are
  // settled before a single byte is emitted: the buffer is left byte for byte
  // as it was, so a packetizer can go on to try a smaller frame. False means
  // the frame did not fit or is not encodable, and the two are not
  // distinguished because an unencodable frame is a bug at the call site
  // rather than a condition to recover from; frame_is_encodable tells them
  // apart when that matters.
  [[nodiscard]] bool write(const frame_t &frame)
  {
    if (!frame_is_encodable(frame))
    {
      return false;
    }
    if (frame_encoded_size(frame) > remaining())
    {
      return false;
    }
    const std::size_t start = _position;
    if (!write_body(frame))
    {
      _position = start;
      return false;
    }
    return true;
  }

private:
  bool put_varint(std::uint64_t value)
  {
    const std::size_t written = varint_encode(_out.subspan(_position), value);
    _position += written;
    return written != 0;
  }

  bool put_byte(std::uint8_t value)
  {
    if (remaining() < 1)
    {
      return false;
    }
    _out[_position] = value;
    ++_position;
    return true;
  }

  bool put_bytes(std::span<const std::uint8_t> data)
  {
    if (remaining() < data.size())
    {
      return false;
    }
    // A STREAM or CRYPTO payload is most of a packet, so this is the copy that
    // matters; a byte-at-a-time loop leaves most of the machine idle. Guarded
    // because an empty frame is legal and memcpy from a null pointer is
    // undefined even for zero bytes.
    if (!data.empty())
    {
      std::memcpy(_out.data() + _position, data.data(), data.size());
    }
    _position += data.size();
    return true;
  }

  bool write_body(const frame_t &frame);

  std::span<std::uint8_t> _out;
  std::size_t _position = 0;
};

inline bool frame_writer_t::write_body(const frame_t &frame)
{
  if (frame.kind == frame_kind_t::padding)
  {
    // Compared in 64-bit space rather than through frame_encoded_size, whose
    // size_t result could narrow the count on a 32-bit target.
    if (frame.padding_count > remaining())
    {
      return false;
    }
    for (std::uint64_t i = 0; i < frame.padding_count; ++i)
    {
      if (!put_byte(0x00))
      {
        return false;
      }
    }
    return true;
  }

  if (!put_varint(frame_type_byte(frame)))
  {
    return false;
  }

  switch (frame.kind)
  {
  case frame_kind_t::padding:
  case frame_kind_t::ping:
  case frame_kind_t::handshake_done:
    return true;

  case frame_kind_t::ack:
    if (!put_varint(frame.largest_acknowledged) || !put_varint(frame.ack_delay) || !put_varint(frame.ack_range_count) || !put_varint(frame.first_ack_range) || !put_bytes(frame.ack_ranges))
    {
      return false;
    }
    if (frame.ecn.has_value())
    {
      return put_varint(frame.ecn->ect0) && put_varint(frame.ecn->ect1) && put_varint(frame.ecn->ce);
    }
    return true;

  case frame_kind_t::reset_stream:
    return put_varint(frame.stream_id) && put_varint(frame.error_code) && put_varint(frame.final_size);

  case frame_kind_t::stop_sending:
    return put_varint(frame.stream_id) && put_varint(frame.error_code);

  case frame_kind_t::crypto:
    if (frame.offset > varint_max - frame.data.size())
    {
      return false;
    }
    return put_varint(frame.offset) && put_varint(frame.data.size()) && put_bytes(frame.data);

  case frame_kind_t::new_token:
    if (frame.data.empty())
    {
      return false;
    }
    return put_varint(frame.data.size()) && put_bytes(frame.data);

  case frame_kind_t::stream:
    if (frame.offset > varint_max - frame.data.size())
    {
      return false;
    }
    if (!put_varint(frame.stream_id))
    {
      return false;
    }
    if (frame.offset != 0 && !put_varint(frame.offset))
    {
      return false;
    }
    if (!frame.omit_length && !put_varint(frame.data.size()))
    {
      return false;
    }
    return put_bytes(frame.data);

  case frame_kind_t::max_data:
  case frame_kind_t::data_blocked:
    return put_varint(frame.maximum);

  case frame_kind_t::max_streams:
  case frame_kind_t::streams_blocked:
    if (frame.maximum > max_stream_count)
    {
      return false;
    }
    return put_varint(frame.maximum);

  case frame_kind_t::max_stream_data:
  case frame_kind_t::stream_data_blocked:
    return put_varint(frame.stream_id) && put_varint(frame.maximum);

  case frame_kind_t::new_connection_id:
  {
    if (frame.retire_prior_to > frame.sequence_number)
    {
      return false;
    }
    const std::size_t id_length = frame.connection_id.size();
    if (id_length < 1 || id_length > max_connection_id_size)
    {
      return false;
    }
    if (frame.stateless_reset_token.size() != stateless_reset_token_size)
    {
      return false;
    }
    return put_varint(frame.sequence_number) && put_varint(frame.retire_prior_to) && put_byte(static_cast<std::uint8_t>(id_length)) && put_bytes(frame.connection_id.bytes()) && put_bytes(frame.stateless_reset_token);
  }

  case frame_kind_t::retire_connection_id:
    return put_varint(frame.sequence_number);

  case frame_kind_t::path_challenge:
  case frame_kind_t::path_response:
    if (frame.path_data.size() != path_data_size)
    {
      return false;
    }
    return put_bytes(frame.path_data);

  case frame_kind_t::connection_close:
    if (!put_varint(frame.error_code))
    {
      return false;
    }
    if (!frame.application_error && !put_varint(frame.triggering_frame_type))
    {
      return false;
    }
    return put_varint(frame.data.size()) && put_bytes(frame.data);
  }

  return false;
}
} // namespace vio::quic
