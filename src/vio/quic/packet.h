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

// RFC 9000 section 17 packet headers.
//
// Everything here stops at the packet number. The packet number and the low
// bits of the first byte are covered by header protection (RFC 9001 section
// 5.4), which needs a key and a ciphertext sample, so a reader can only get as
// far as *where* the packet number starts -- not what it says. packet_header_t
// therefore reports offsets, and protection.h finishes the job.
//
// The other thing this layer does not do is decide anything. A header that
// fails to parse is a packet to drop, never a connection error: these bytes
// have not been authenticated yet, so a hostile or merely broken datagram must
// cost a discard and nothing more. That is why the failure type is called
// packet_discard_t and why it carries no transport error code. The rules that
// *are* connection errors -- non-zero reserved bits above all -- can only be
// checked once protection has been removed, and so live with the code that
// removes it.

#include "vio/quic/connection_id.h"
#include "vio/quic/frame.h"
#include "vio/quic/packet_number.h"
#include "vio/quic/varint.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <optional>
#include <span>

namespace vio::quic
{
inline constexpr std::uint32_t quic_version_1 = 0x00000001;
inline constexpr std::uint32_t quic_version_negotiation = 0x00000000;

inline constexpr std::uint8_t header_form_long = 0x80;
inline constexpr std::uint8_t header_fixed_bit = 0x40;
inline constexpr std::uint8_t long_packet_type_mask = 0x30;
inline constexpr std::uint8_t long_reserved_mask = 0x0c;
inline constexpr std::uint8_t short_spin_bit = 0x20;
inline constexpr std::uint8_t short_reserved_mask = 0x18;
inline constexpr std::uint8_t short_key_phase_bit = 0x04;
inline constexpr std::uint8_t packet_number_length_mask = 0x03;

// RFC 9001 section 5.4.2: the sample starts four bytes past the packet number
// -- the field is assumed to be its maximum length, since a receiver does not
// know the real one until the protection is off -- and is sixteen bytes for
// every AEAD this version defines.
inline constexpr std::size_t header_protection_sample_size = 16;
inline constexpr std::size_t header_protection_sample_skip = 4;
inline constexpr std::size_t header_protection_minimum_tail = header_protection_sample_skip + header_protection_sample_size;

// RFC 9001 section 5.8.
inline constexpr std::size_t retry_integrity_tag_size = 16;

// Every AEAD QUIC version 1 defines expands by sixteen bytes.
inline constexpr std::size_t default_aead_expansion = 16;

// The builder reserves a two-byte varint for the Length field, which is what
// any datagram inside a real path MTU needs. A packet longer than this is
// refused rather than silently mis-encoded.
inline constexpr std::uint64_t max_reserved_length_field = 16383;

enum class packet_kind_t : std::uint8_t
{
  initial,
  zero_rtt,
  handshake,
  retry,
  one_rtt,
  version_negotiation,
};

// Which packet types carry frames, and so have a place in the frame table.
// Retry and Version Negotiation carry none.
[[nodiscard]] constexpr std::optional<packet_type_t> frame_packet_type(packet_kind_t kind)
{
  switch (kind)
  {
  case packet_kind_t::initial:
    return packet_type_t::initial;
  case packet_kind_t::zero_rtt:
    return packet_type_t::zero_rtt;
  case packet_kind_t::handshake:
    return packet_type_t::handshake;
  case packet_kind_t::one_rtt:
    return packet_type_t::one_rtt;
  case packet_kind_t::retry:
  case packet_kind_t::version_negotiation:
    break;
  }
  return std::nullopt;
}

[[nodiscard]] constexpr bool is_long_header(packet_kind_t kind)
{
  return kind != packet_kind_t::one_rtt;
}

[[nodiscard]] constexpr std::uint8_t long_packet_type_bits(packet_kind_t kind)
{
  switch (kind)
  {
  case packet_kind_t::initial:
    return 0x00;
  case packet_kind_t::zero_rtt:
    return 0x10;
  case packet_kind_t::handshake:
    return 0x20;
  case packet_kind_t::retry:
    return 0x30;
  case packet_kind_t::one_rtt:
  case packet_kind_t::version_negotiation:
    break;
  }
  return 0x00;
}

// Reasons to drop a datagram, or the remainder of one. None of these is a
// connection error; see the note at the top of this file.
enum class packet_discard_t : std::uint8_t
{
  truncated,
  fixed_bit_clear,
  connection_id_too_long,
  unsupported_version,
  invalid_length,
  sample_too_short,
};

// The fields RFC 8999 declares version independent, which is all a server can
// rely on when the version is one it does not speak. Connection IDs come back
// as spans rather than connection_id_t because another version may use IDs
// longer than the twenty bytes version 1 allows, and a server has to echo them
// into a Version Negotiation packet without being able to store them.
struct invariant_header_t
{
  bool long_header = false;
  std::uint32_t version = 0;
  std::span<const std::uint8_t> destination_id;
  std::span<const std::uint8_t> source_id;
};

[[nodiscard]] inline std::optional<invariant_header_t> parse_invariant_header(std::span<const std::uint8_t> datagram)
{
  if (datagram.empty())
  {
    return std::nullopt;
  }
  invariant_header_t header;
  header.long_header = (datagram[0] & header_form_long) != 0;
  if (!header.long_header)
  {
    // A short header carries no connection ID length; only the recipient, who
    // chose the ID, knows where it ends.
    return header;
  }
  if (datagram.size() < 5)
  {
    return std::nullopt;
  }
  header.version = (static_cast<std::uint32_t>(datagram[1]) << 24) | (static_cast<std::uint32_t>(datagram[2]) << 16) | (static_cast<std::uint32_t>(datagram[3]) << 8) | static_cast<std::uint32_t>(datagram[4]);

  std::size_t position = 5;
  for (auto *field : {&header.destination_id, &header.source_id})
  {
    if (position >= datagram.size())
    {
      return std::nullopt;
    }
    const std::size_t length = datagram[position];
    ++position;
    if (datagram.size() - position < length)
    {
      return std::nullopt;
    }
    *field = datagram.subspan(position, length);
    position += length;
  }
  return header;
}

struct packet_header_t
{
  packet_kind_t kind = packet_kind_t::one_rtt;
  std::uint32_t version = 0;
  connection_id_t destination_id;
  connection_id_t source_id;

  // Initial only. A client that receives one of these with a non-zero length
  // has grounds for a PROTOCOL_VIOLATION, but that is a decision about roles
  // and so is left to the caller.
  std::span<const std::uint8_t> token;

  // Retry only.
  std::span<const std::uint8_t> retry_token;
  std::span<const std::uint8_t> retry_integrity_tag;

  // Version Negotiation only: the raw list, four bytes per version.
  std::span<const std::uint8_t> supported_versions;

  // This packet within the datagram it was read from. A datagram may hold
  // several coalesced packets, so this is not necessarily the whole thing.
  std::span<const std::uint8_t> packet;

  // Where the still-protected packet number starts, relative to packet.
  // Meaningless for Retry and Version Negotiation, which have neither a packet
  // number nor header protection.
  std::size_t packet_number_offset = 0;

  [[nodiscard]] bool has_packet_number() const
  {
    return kind != packet_kind_t::retry && kind != packet_kind_t::version_negotiation;
  }

  // Packet number and payload, both still protected.
  [[nodiscard]] std::span<const std::uint8_t> protected_region() const
  {
    return packet.subspan(packet_number_offset);
  }

  // The ciphertext header protection masks the first byte and the packet
  // number with. The reader has already refused anything too short to hold it.
  [[nodiscard]] std::span<const std::uint8_t> header_protection_sample() const
  {
    return packet.subspan(packet_number_offset + header_protection_sample_skip, header_protection_sample_size);
  }
};

// Walks the packets in one datagram. Coalescing (RFC 9000 section 12.2) lets a
// sender pack several long header packets into a datagram; a short header,
// Retry or Version Negotiation packet runs to the end and so must be last.
//
// local_connection_id_length is the length of the connection IDs this endpoint
// issues, and is the only way to find where a short header ends: the field has
// no length prefix on the wire.
//
// A failure ends the walk. RFC 9000 section 12.2 has a receiver discard the
// rest of a datagram once a packet in it cannot be parsed, so next() returns
// nothing after an error rather than trying to resynchronise on bytes it has
// no reason to trust.
class packet_reader_t
{
public:
  packet_reader_t(std::span<const std::uint8_t> datagram, std::size_t local_connection_id_length)
    : _input(datagram)
    , _local_connection_id_length(local_connection_id_length)
  {
  }

  [[nodiscard]] bool done() const
  {
    return _done || _position >= _input.size();
  }

  [[nodiscard]] std::size_t position() const
  {
    return _position;
  }

  [[nodiscard]] std::optional<std::expected<packet_header_t, packet_discard_t>> next()
  {
    if (done())
    {
      return std::nullopt;
    }
    auto result = read_one();
    if (!result.has_value())
    {
      _done = true;
    }
    return result;
  }

private:
  std::expected<packet_header_t, packet_discard_t> read_one();

  std::span<const std::uint8_t> _input;
  std::size_t _local_connection_id_length = 0;
  std::size_t _position = 0;
  bool _done = false;
};

inline std::expected<packet_header_t, packet_discard_t> packet_reader_t::read_one()
{
  const auto remaining = _input.subspan(_position);
  const std::uint8_t first = remaining[0];

  packet_header_t header;

  if ((first & header_form_long) == 0)
  {
    if ((first & header_fixed_bit) == 0)
    {
      return std::unexpected(packet_discard_t::fixed_bit_clear);
    }
    if (_local_connection_id_length > max_connection_id_size)
    {
      return std::unexpected(packet_discard_t::connection_id_too_long);
    }
    if (remaining.size() < 1 + _local_connection_id_length)
    {
      return std::unexpected(packet_discard_t::truncated);
    }
    auto id = connection_id_t::from_bytes(remaining.subspan(1, _local_connection_id_length));
    if (!id.has_value())
    {
      return std::unexpected(packet_discard_t::connection_id_too_long);
    }
    header.kind = packet_kind_t::one_rtt;
    header.destination_id = *id;
    header.packet_number_offset = 1 + _local_connection_id_length;
    // A short header has no length field: it owns the rest of the datagram.
    header.packet = remaining;
    if (header.packet.size() - header.packet_number_offset < header_protection_minimum_tail)
    {
      return std::unexpected(packet_discard_t::sample_too_short);
    }
    _position = _input.size();
    return header;
  }

  if (remaining.size() < 5)
  {
    return std::unexpected(packet_discard_t::truncated);
  }
  header.version = (static_cast<std::uint32_t>(remaining[1]) << 24) | (static_cast<std::uint32_t>(remaining[2]) << 16) | (static_cast<std::uint32_t>(remaining[3]) << 8) | static_cast<std::uint32_t>(remaining[4]);

  // A Version Negotiation packet is the one long header whose fixed bit means
  // nothing: section 17.2.1 leaves those seven bits to the server.
  const bool version_negotiation = header.version == quic_version_negotiation;

  // The version decides before anything else, because every rule below it is
  // a version 1 rule -- the fixed bit is "not valid packets in this version",
  // and the twenty byte ceiling on connection IDs is written as applying to a
  // version 1 long header. A packet from a version this build does not speak
  // has to come back as unsupported_version and nothing else, or a server
  // cannot tell the difference between a packet to answer with Version
  // Negotiation and one to drop on the floor. Its connection IDs, which may be
  // longer than version 1 permits, are what parse_invariant_header is for.
  if (!version_negotiation && header.version != quic_version_1)
  {
    return std::unexpected(packet_discard_t::unsupported_version);
  }
  if (!version_negotiation && (first & header_fixed_bit) == 0)
  {
    return std::unexpected(packet_discard_t::fixed_bit_clear);
  }

  std::size_t position = 5;
  connection_id_t *ids[] = {&header.destination_id, &header.source_id};
  for (auto *id : ids)
  {
    if (position >= remaining.size())
    {
      return std::unexpected(packet_discard_t::truncated);
    }
    const std::size_t length = remaining[position];
    ++position;
    if (length > max_connection_id_size)
    {
      return std::unexpected(packet_discard_t::connection_id_too_long);
    }
    if (remaining.size() - position < length)
    {
      return std::unexpected(packet_discard_t::truncated);
    }
    auto parsed = connection_id_t::from_bytes(remaining.subspan(position, length));
    if (!parsed.has_value())
    {
      return std::unexpected(packet_discard_t::connection_id_too_long);
    }
    *id = *parsed;
    position += length;
  }

  if (version_negotiation)
  {
    header.kind = packet_kind_t::version_negotiation;
    const std::size_t rest = remaining.size() - position;
    if (rest == 0 || rest % 4 != 0)
    {
      return std::unexpected(packet_discard_t::invalid_length);
    }
    header.supported_versions = remaining.subspan(position, rest);
    header.packet = remaining;
    _position = _input.size();
    return header;
  }

  switch (first & long_packet_type_mask)
  {
  case 0x00:
    header.kind = packet_kind_t::initial;
    break;
  case 0x10:
    header.kind = packet_kind_t::zero_rtt;
    break;
  case 0x20:
    header.kind = packet_kind_t::handshake;
    break;
  default:
    header.kind = packet_kind_t::retry;
    break;
  }

  if (header.kind == packet_kind_t::retry)
  {
    const std::size_t rest = remaining.size() - position;
    if (rest < retry_integrity_tag_size)
    {
      return std::unexpected(packet_discard_t::truncated);
    }
    header.retry_token = remaining.subspan(position, rest - retry_integrity_tag_size);
    header.retry_integrity_tag = remaining.subspan(remaining.size() - retry_integrity_tag_size, retry_integrity_tag_size);
    header.packet = remaining;
    _position = _input.size();
    return header;
  }

  if (header.kind == packet_kind_t::initial)
  {
    auto token_length = varint_decode(remaining.subspan(position));
    if (!token_length.has_value())
    {
      return std::unexpected(packet_discard_t::truncated);
    }
    position += token_length->size;
    if (token_length->value > remaining.size() - position)
    {
      return std::unexpected(packet_discard_t::truncated);
    }
    header.token = remaining.subspan(position, static_cast<std::size_t>(token_length->value));
    position += static_cast<std::size_t>(token_length->value);
  }

  auto length = varint_decode(remaining.subspan(position));
  if (!length.has_value())
  {
    return std::unexpected(packet_discard_t::truncated);
  }
  position += length->size;

  // Compared before the cast: a 62-bit Length would otherwise narrow into
  // something that passes a check it should have failed.
  if (length->value > remaining.size() - position)
  {
    return std::unexpected(packet_discard_t::truncated);
  }
  const std::size_t protected_length = static_cast<std::size_t>(length->value);
  if (protected_length < header_protection_minimum_tail)
  {
    return std::unexpected(packet_discard_t::sample_too_short);
  }

  header.packet_number_offset = position;
  header.packet = remaining.first(position + protected_length);
  _position += header.packet.size();
  return header;
}

struct packet_layout_t
{
  std::size_t packet_number_offset = 0;
  std::size_t packet_number_length = 0;
  // Bytes through the packet number: the associated data the AEAD covers, and
  // where the payload begins.
  std::size_t header_length = 0;
  std::size_t frame_bytes = 0;
  std::size_t packet_length = 0;
};

// Writes a packet header into a caller buffer and, once the frames are in,
// goes back and fills in the Length field.
//
// The order the wire wants and the order a sender knows things in do not
// match: Length covers the packet number and the protected payload, neither of
// which is known when the field is written. Hence begin, then frames, then
// finish. Two bytes are reserved for Length, which section 16 permits -- only
// a frame type has to use the shortest encoding.
class packet_builder_t
{
public:
  explicit packet_builder_t(std::span<std::uint8_t> out)
    : _out(out)
  {
  }

  // Initial, 0-RTT or Handshake. token is written for Initial and ignored
  // otherwise; an Initial with no token writes a zero length.
  [[nodiscard]] bool begin_long(packet_kind_t kind, std::uint32_t version, const connection_id_t &destination, const connection_id_t &source, std::span<const std::uint8_t> token, std::uint64_t packet_number,
                                std::optional<std::uint64_t> largest_acked)
  {
    if (!is_long_header(kind) || kind == packet_kind_t::retry || kind == packet_kind_t::version_negotiation)
    {
      return false;
    }
    const std::size_t number_length = packet_number_size(packet_number, largest_acked);
    const std::size_t token_length_size = kind == packet_kind_t::initial ? varint_size(token.size()) : 0;
    const std::size_t token_size = kind == packet_kind_t::initial ? token.size() : 0;
    const std::size_t needed = 1 + 4 + 1 + destination.size() + 1 + source.size() + token_length_size + token_size + reserved_length_size + number_length;
    if (_out.size() < needed)
    {
      return false;
    }

    std::size_t position = 0;
    _out[position] = static_cast<std::uint8_t>(header_form_long | header_fixed_bit | long_packet_type_bits(kind) | static_cast<std::uint8_t>(number_length - 1));
    ++position;
    _out[position++] = static_cast<std::uint8_t>((version >> 24) & 0xff);
    _out[position++] = static_cast<std::uint8_t>((version >> 16) & 0xff);
    _out[position++] = static_cast<std::uint8_t>((version >> 8) & 0xff);
    _out[position++] = static_cast<std::uint8_t>(version & 0xff);
    position += write_connection_id(position, destination);
    position += write_connection_id(position, source);

    if (kind == packet_kind_t::initial)
    {
      position += varint_encode(_out.subspan(position), token.size());
      if (!token.empty())
      {
        std::memcpy(_out.data() + position, token.data(), token.size());
      }
      position += token.size();
    }

    _length_offset = position;
    _has_length_field = true;
    // Placeholder; finish() overwrites both bytes.
    _out[position++] = 0x40;
    _out[position++] = 0x00;

    return finish_begin(position, packet_number, number_length);
  }

  [[nodiscard]] bool begin_short(const connection_id_t &destination, bool key_phase, bool spin, std::uint64_t packet_number, std::optional<std::uint64_t> largest_acked)
  {
    const std::size_t number_length = packet_number_size(packet_number, largest_acked);
    if (_out.size() < 1 + destination.size() + number_length)
    {
      return false;
    }
    std::uint8_t first = static_cast<std::uint8_t>(header_fixed_bit | static_cast<std::uint8_t>(number_length - 1));
    if (key_phase)
    {
      first |= short_key_phase_bit;
    }
    if (spin)
    {
      first |= short_spin_bit;
    }
    _out[0] = first;
    // No length prefix here: only the endpoint that chose the connection ID
    // knows how long it is, which is why the reader has to be told.
    const auto bytes = destination.bytes();
    for (std::size_t i = 0; i < bytes.size(); ++i)
    {
      _out[1 + i] = bytes[i];
    }
    _has_length_field = false;
    return finish_begin(1 + bytes.size(), packet_number, number_length);
  }

  // Where the frames go.
  [[nodiscard]] std::span<std::uint8_t> payload_buffer()
  {
    return _out.subspan(_header_length);
  }

  // The most frames that will fit once the AEAD has taken its expansion.
  [[nodiscard]] std::size_t maximum_frame_bytes(std::size_t expansion = default_aead_expansion) const
  {
    const std::size_t available = _out.size() - _header_length;
    return available < expansion ? 0 : available - expansion;
  }

  // RFC 9001 section 5.4.2 needs the packet number and protected payload to
  // reach four bytes past the start of a sixteen byte sample, so a small
  // packet has to be padded to get there. This is how much PADDING it takes.
  [[nodiscard]] std::size_t minimum_frame_bytes(std::size_t expansion = default_aead_expansion) const
  {
    const std::size_t tail = _packet_number_length + expansion;
    return tail >= header_protection_minimum_tail ? 0 : header_protection_minimum_tail - tail;
  }

  [[nodiscard]] std::optional<packet_layout_t> finish(std::size_t frame_bytes, std::size_t expansion = default_aead_expansion)
  {
    if (_header_length == 0)
    {
      return std::nullopt;
    }
    if (frame_bytes > maximum_frame_bytes(expansion) || frame_bytes < minimum_frame_bytes(expansion))
    {
      return std::nullopt;
    }

    if (_has_length_field)
    {
      const std::uint64_t length = _packet_number_length + frame_bytes + expansion;
      if (length > max_reserved_length_field)
      {
        return std::nullopt;
      }
      _out[_length_offset] = static_cast<std::uint8_t>(0x40 | ((length >> 8) & 0x3f));
      _out[_length_offset + 1] = static_cast<std::uint8_t>(length & 0xff);
    }

    return packet_layout_t{.packet_number_offset = _packet_number_offset,
                           .packet_number_length = _packet_number_length,
                           .header_length = _header_length,
                           .frame_bytes = frame_bytes,
                           .packet_length = _header_length + frame_bytes + expansion};
  }

private:
  static constexpr std::size_t reserved_length_size = 2;

  std::size_t write_connection_id(std::size_t position, const connection_id_t &id)
  {
    _out[position] = static_cast<std::uint8_t>(id.size());
    const auto bytes = id.bytes();
    // A zero-length connection ID is legal, so this cannot assume a pointer.
    if (!bytes.empty())
    {
      std::memcpy(_out.data() + position + 1, bytes.data(), bytes.size());
    }
    return 1 + bytes.size();
  }

  bool finish_begin(std::size_t position, std::uint64_t packet_number, std::size_t number_length)
  {
    _packet_number_offset = position;
    const std::size_t written = packet_number_encode(_out.subspan(position), packet_number, number_length);
    if (written == 0)
    {
      _header_length = 0;
      return false;
    }
    _packet_number_length = written;
    _header_length = position + written;
    return true;
  }

  std::span<std::uint8_t> _out;
  bool _has_length_field = false;
  std::size_t _length_offset = 0;
  std::size_t _packet_number_offset = 0;
  std::size_t _packet_number_length = 0;
  std::size_t _header_length = 0;
};

// Section 17.2.1. The connection IDs are spans, not connection_id_t, because a
// server answers a version it does not speak and must echo back whatever that
// version put on the wire -- which may be longer than version 1 permits.
// Returns the bytes written, or zero if the buffer is too small or an argument
// is out of range.
[[nodiscard]] inline std::size_t serialize_version_negotiation(std::span<std::uint8_t> out, std::span<const std::uint8_t> destination_id, std::span<const std::uint8_t> source_id, std::span<const std::uint32_t> versions)
{
  if (destination_id.size() > 255 || source_id.size() > 255 || versions.empty())
  {
    return 0;
  }
  const std::size_t needed = 1 + 4 + 1 + destination_id.size() + 1 + source_id.size() + versions.size() * 4;
  if (out.size() < needed)
  {
    return 0;
  }

  std::size_t position = 0;
  // The fixed bit is set only so the packet is not mistaken for another
  // protocol on a multiplexed port; section 17.2.1 says a client ignores it.
  out[position++] = header_form_long | header_fixed_bit;
  out[position++] = 0x00;
  out[position++] = 0x00;
  out[position++] = 0x00;
  out[position++] = 0x00;
  for (auto id : {destination_id, source_id})
  {
    out[position++] = static_cast<std::uint8_t>(id.size());
    for (std::size_t i = 0; i < id.size(); ++i)
    {
      out[position + i] = id[i];
    }
    position += id.size();
  }
  for (std::uint32_t version : versions)
  {
    out[position++] = static_cast<std::uint8_t>((version >> 24) & 0xff);
    out[position++] = static_cast<std::uint8_t>((version >> 16) & 0xff);
    out[position++] = static_cast<std::uint8_t>((version >> 8) & 0xff);
    out[position++] = static_cast<std::uint8_t>(version & 0xff);
  }
  return position;
}

// Section 17.2.5, everything but the integrity tag: computing that needs the
// original destination connection ID and a key, which belongs with the rest of
// the crypto. Returns the bytes written, which is where the tag goes.
[[nodiscard]] inline std::size_t serialize_retry(std::span<std::uint8_t> out, std::uint32_t version, const connection_id_t &destination, const connection_id_t &source, std::span<const std::uint8_t> retry_token)
{
  const std::size_t needed = 1 + 4 + 1 + destination.size() + 1 + source.size() + retry_token.size();
  if (out.size() < needed)
  {
    return 0;
  }

  std::size_t position = 0;
  // The four unused bits are the server's to pick; zero is as good as any.
  out[position++] = header_form_long | header_fixed_bit | long_packet_type_bits(packet_kind_t::retry);
  out[position++] = static_cast<std::uint8_t>((version >> 24) & 0xff);
  out[position++] = static_cast<std::uint8_t>((version >> 16) & 0xff);
  out[position++] = static_cast<std::uint8_t>((version >> 8) & 0xff);
  out[position++] = static_cast<std::uint8_t>(version & 0xff);
  for (const auto *id : {&destination, &source})
  {
    const auto bytes = id->bytes();
    out[position++] = static_cast<std::uint8_t>(bytes.size());
    for (std::size_t i = 0; i < bytes.size(); ++i)
    {
      out[position + i] = bytes[i];
    }
    position += bytes.size();
  }
  for (std::size_t i = 0; i < retry_token.size(); ++i)
  {
    out[position + i] = retry_token[i];
  }
  position += retry_token.size();
  return position;
}
} // namespace vio::quic
