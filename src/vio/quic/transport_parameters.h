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

// The quic_transport_parameters extension (RFC 9000 section 18): a list of
// (id, length, value) tuples that TLS carries and that settle everything the
// transport needs to agree on before it can send anything but a handshake.
//
// Absence means the default, and the defaults are not all zero -- an
// ack_delay_exponent that is missing means 3, not 0, and reading it as 0 would
// make every ACK delay this endpoint computes wrong by a factor of eight. The
// struct is therefore initialised to the defaults rather than zeroed, and
// decoding overwrites only what the peer actually sent.
//
// Unknown parameters are ignored on purpose: section 18.1 reserves a family of
// identifiers whose whole job is to be unrecognised, so a decoder that refused
// them would fail against conforming peers.

#include "vio/quic/connection_id.h"
#include "vio/quic/frame_codec.h"
#include "vio/quic/varint.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <vector>

namespace vio::quic
{
enum class transport_parameter_id_t : std::uint64_t
{
  original_destination_connection_id = 0x00,
  max_idle_timeout = 0x01,
  stateless_reset_token = 0x02,
  max_udp_payload_size = 0x03,
  initial_max_data = 0x04,
  initial_max_stream_data_bidi_local = 0x05,
  initial_max_stream_data_bidi_remote = 0x06,
  initial_max_stream_data_uni = 0x07,
  initial_max_streams_bidi = 0x08,
  initial_max_streams_uni = 0x09,
  ack_delay_exponent = 0x0a,
  max_ack_delay = 0x0b,
  disable_active_migration = 0x0c,
  preferred_address = 0x0d,
  active_connection_id_limit = 0x0e,
  initial_source_connection_id = 0x0f,
  retry_source_connection_id = 0x10,
  // RFC 9221.
  max_datagram_frame_size = 0x20,
};

// Every one of these is spelled out in section 18.2 as what to assume when the
// parameter is absent.
inline constexpr std::uint64_t default_max_udp_payload_size = 65527;
inline constexpr std::uint64_t default_ack_delay_exponent_parameter = 3;
inline constexpr std::uint64_t default_max_ack_delay_milliseconds = 25;
inline constexpr std::uint64_t default_active_connection_id_limit = 2;

// The values section 18.2 calls invalid outright, each of which is a
// TRANSPORT_PARAMETER_ERROR rather than something to clamp.
inline constexpr std::uint64_t max_ack_delay_exponent_value = 20;
inline constexpr std::uint64_t max_ack_delay_limit = std::uint64_t{1} << 14;
inline constexpr std::uint64_t minimum_max_udp_payload_size = 1200;
inline constexpr std::uint64_t minimum_active_connection_id_limit = 2;

struct transport_parameters_t
{
  // Server only: the Destination Connection ID from the client's first
  // Initial, which is how a client detects a tampered handshake.
  std::optional<connection_id_t> original_destination_connection_id;
  std::uint64_t max_idle_timeout = 0;
  std::optional<std::array<std::uint8_t, stateless_reset_token_size>> stateless_reset_token;
  std::uint64_t max_udp_payload_size = default_max_udp_payload_size;
  std::uint64_t initial_max_data = 0;
  std::uint64_t initial_max_stream_data_bidi_local = 0;
  std::uint64_t initial_max_stream_data_bidi_remote = 0;
  std::uint64_t initial_max_stream_data_uni = 0;
  std::uint64_t initial_max_streams_bidi = 0;
  std::uint64_t initial_max_streams_uni = 0;
  std::uint64_t ack_delay_exponent = default_ack_delay_exponent_parameter;
  std::uint64_t max_ack_delay = default_max_ack_delay_milliseconds;
  bool disable_active_migration = false;
  std::uint64_t active_connection_id_limit = default_active_connection_id_limit;
  std::optional<connection_id_t> initial_source_connection_id;
  std::optional<connection_id_t> retry_source_connection_id;

  // RFC 9221 section 3. Zero, the default, means DATAGRAM frames are not
  // supported and receiving one is a PROTOCOL_VIOLATION. Any other value is
  // the largest frame this endpoint will accept, counted as the whole frame
  // including its type and length.
  std::uint64_t max_datagram_frame_size = 0;

  // preferred_address is not produced and is ignored when received: it only
  // matters for server-initiated migration, which this stack does not do.
};

enum class transport_parameter_error_t : std::uint8_t
{
  truncated,
  duplicate,
  invalid_value,
};

[[nodiscard]] inline std::vector<std::uint8_t> encode_transport_parameters(const transport_parameters_t &parameters)
{
  std::vector<std::uint8_t> out;

  const auto put_varint = [&out](std::uint64_t value)
  {
    std::array<std::uint8_t, 8> scratch = {};
    const std::size_t written = varint_encode(scratch, value);
    out.insert(out.end(), scratch.begin(), scratch.begin() + static_cast<std::ptrdiff_t>(written));
  };

  const auto put_bytes = [&](transport_parameter_id_t id, std::span<const std::uint8_t> value)
  {
    put_varint(static_cast<std::uint64_t>(id));
    put_varint(value.size());
    out.insert(out.end(), value.begin(), value.end());
  };

  const auto put_integer = [&](transport_parameter_id_t id, std::uint64_t value)
  {
    put_varint(static_cast<std::uint64_t>(id));
    put_varint(varint_size(value));
    put_varint(value);
  };

  // Only what differs from the default goes on the wire. Sending a parameter
  // whose value is the default is legal but pure overhead in every packet of
  // the handshake.
  if (parameters.original_destination_connection_id.has_value())
  {
    put_bytes(transport_parameter_id_t::original_destination_connection_id, parameters.original_destination_connection_id->bytes());
  }
  if (parameters.max_idle_timeout != 0)
  {
    put_integer(transport_parameter_id_t::max_idle_timeout, parameters.max_idle_timeout);
  }
  if (parameters.stateless_reset_token.has_value())
  {
    put_bytes(transport_parameter_id_t::stateless_reset_token, *parameters.stateless_reset_token);
  }
  if (parameters.max_udp_payload_size != default_max_udp_payload_size)
  {
    put_integer(transport_parameter_id_t::max_udp_payload_size, parameters.max_udp_payload_size);
  }
  if (parameters.initial_max_data != 0)
  {
    put_integer(transport_parameter_id_t::initial_max_data, parameters.initial_max_data);
  }
  if (parameters.initial_max_stream_data_bidi_local != 0)
  {
    put_integer(transport_parameter_id_t::initial_max_stream_data_bidi_local, parameters.initial_max_stream_data_bidi_local);
  }
  if (parameters.initial_max_stream_data_bidi_remote != 0)
  {
    put_integer(transport_parameter_id_t::initial_max_stream_data_bidi_remote, parameters.initial_max_stream_data_bidi_remote);
  }
  if (parameters.initial_max_stream_data_uni != 0)
  {
    put_integer(transport_parameter_id_t::initial_max_stream_data_uni, parameters.initial_max_stream_data_uni);
  }
  if (parameters.initial_max_streams_bidi != 0)
  {
    put_integer(transport_parameter_id_t::initial_max_streams_bidi, parameters.initial_max_streams_bidi);
  }
  if (parameters.initial_max_streams_uni != 0)
  {
    put_integer(transport_parameter_id_t::initial_max_streams_uni, parameters.initial_max_streams_uni);
  }
  if (parameters.ack_delay_exponent != default_ack_delay_exponent_parameter)
  {
    put_integer(transport_parameter_id_t::ack_delay_exponent, parameters.ack_delay_exponent);
  }
  if (parameters.max_ack_delay != default_max_ack_delay_milliseconds)
  {
    put_integer(transport_parameter_id_t::max_ack_delay, parameters.max_ack_delay);
  }
  if (parameters.max_datagram_frame_size != 0)
  {
    put_integer(transport_parameter_id_t::max_datagram_frame_size, parameters.max_datagram_frame_size);
  }
  if (parameters.disable_active_migration)
  {
    // A zero length value: the parameter is a flag, present or not.
    put_bytes(transport_parameter_id_t::disable_active_migration, {});
  }
  if (parameters.active_connection_id_limit != default_active_connection_id_limit)
  {
    put_integer(transport_parameter_id_t::active_connection_id_limit, parameters.active_connection_id_limit);
  }
  if (parameters.initial_source_connection_id.has_value())
  {
    put_bytes(transport_parameter_id_t::initial_source_connection_id, parameters.initial_source_connection_id->bytes());
  }
  if (parameters.retry_source_connection_id.has_value())
  {
    put_bytes(transport_parameter_id_t::retry_source_connection_id, parameters.retry_source_connection_id->bytes());
  }
  return out;
}

[[nodiscard]] inline std::expected<transport_parameters_t, transport_parameter_error_t> decode_transport_parameters(std::span<const std::uint8_t> input)
{
  transport_parameters_t parameters;
  std::vector<std::uint64_t> seen;
  std::size_t position = 0;

  const auto read_varint = [&input, &position](std::uint64_t &out) -> bool
  {
    auto decoded = varint_decode(input.subspan(position));
    if (!decoded.has_value())
    {
      return false;
    }
    position += decoded->size;
    out = decoded->value;
    return true;
  };

  while (position < input.size())
  {
    std::uint64_t id = 0;
    std::uint64_t length = 0;
    if (!read_varint(id) || !read_varint(length))
    {
      return std::unexpected(transport_parameter_error_t::truncated);
    }
    if (length > input.size() - position)
    {
      return std::unexpected(transport_parameter_error_t::truncated);
    }
    const auto value = input.subspan(position, static_cast<std::size_t>(length));
    position += static_cast<std::size_t>(length);

    // Section 18.2: a parameter must not appear twice. Checked against every
    // id, including ones this build does not recognise, because the rule is
    // about the extension being well formed rather than about the semantics.
    if (std::find(seen.begin(), seen.end(), id) != seen.end())
    {
      return std::unexpected(transport_parameter_error_t::duplicate);
    }
    seen.push_back(id);

    const auto as_integer = [&value](std::uint64_t &out) -> bool
    {
      auto decoded = varint_decode(value);
      // The value field must be exactly the integer and nothing else.
      if (!decoded.has_value() || decoded->size != value.size())
      {
        return false;
      }
      out = decoded->value;
      return true;
    };

    const auto as_connection_id = [&value](std::optional<connection_id_t> &out) -> bool
    {
      auto id_value = connection_id_t::from_bytes(value);
      if (!id_value.has_value())
      {
        return false;
      }
      out = *id_value;
      return true;
    };

    switch (static_cast<transport_parameter_id_t>(id))
    {
    case transport_parameter_id_t::original_destination_connection_id:
      if (!as_connection_id(parameters.original_destination_connection_id))
      {
        return std::unexpected(transport_parameter_error_t::invalid_value);
      }
      break;
    case transport_parameter_id_t::max_idle_timeout:
      if (!as_integer(parameters.max_idle_timeout))
      {
        return std::unexpected(transport_parameter_error_t::invalid_value);
      }
      break;
    case transport_parameter_id_t::stateless_reset_token:
    {
      if (value.size() != stateless_reset_token_size)
      {
        return std::unexpected(transport_parameter_error_t::invalid_value);
      }
      std::array<std::uint8_t, stateless_reset_token_size> token = {};
      std::copy(value.begin(), value.end(), token.begin());
      parameters.stateless_reset_token = token;
      break;
    }
    case transport_parameter_id_t::max_udp_payload_size:
      if (!as_integer(parameters.max_udp_payload_size) || parameters.max_udp_payload_size < minimum_max_udp_payload_size)
      {
        return std::unexpected(transport_parameter_error_t::invalid_value);
      }
      break;
    case transport_parameter_id_t::initial_max_data:
      if (!as_integer(parameters.initial_max_data))
      {
        return std::unexpected(transport_parameter_error_t::invalid_value);
      }
      break;
    case transport_parameter_id_t::initial_max_stream_data_bidi_local:
      if (!as_integer(parameters.initial_max_stream_data_bidi_local))
      {
        return std::unexpected(transport_parameter_error_t::invalid_value);
      }
      break;
    case transport_parameter_id_t::initial_max_stream_data_bidi_remote:
      if (!as_integer(parameters.initial_max_stream_data_bidi_remote))
      {
        return std::unexpected(transport_parameter_error_t::invalid_value);
      }
      break;
    case transport_parameter_id_t::initial_max_stream_data_uni:
      if (!as_integer(parameters.initial_max_stream_data_uni))
      {
        return std::unexpected(transport_parameter_error_t::invalid_value);
      }
      break;
    case transport_parameter_id_t::initial_max_streams_bidi:
      if (!as_integer(parameters.initial_max_streams_bidi) || parameters.initial_max_streams_bidi > max_stream_count)
      {
        return std::unexpected(transport_parameter_error_t::invalid_value);
      }
      break;
    case transport_parameter_id_t::initial_max_streams_uni:
      if (!as_integer(parameters.initial_max_streams_uni) || parameters.initial_max_streams_uni > max_stream_count)
      {
        return std::unexpected(transport_parameter_error_t::invalid_value);
      }
      break;
    case transport_parameter_id_t::ack_delay_exponent:
      if (!as_integer(parameters.ack_delay_exponent) || parameters.ack_delay_exponent > max_ack_delay_exponent_value)
      {
        return std::unexpected(transport_parameter_error_t::invalid_value);
      }
      break;
    case transport_parameter_id_t::max_ack_delay:
      if (!as_integer(parameters.max_ack_delay) || parameters.max_ack_delay >= max_ack_delay_limit)
      {
        return std::unexpected(transport_parameter_error_t::invalid_value);
      }
      break;
    case transport_parameter_id_t::max_datagram_frame_size:
      if (!as_integer(parameters.max_datagram_frame_size))
      {
        return std::unexpected(transport_parameter_error_t::invalid_value);
      }
      break;
    case transport_parameter_id_t::disable_active_migration:
      if (!value.empty())
      {
        return std::unexpected(transport_parameter_error_t::invalid_value);
      }
      parameters.disable_active_migration = true;
      break;
    case transport_parameter_id_t::active_connection_id_limit:
      if (!as_integer(parameters.active_connection_id_limit) || parameters.active_connection_id_limit < minimum_active_connection_id_limit)
      {
        return std::unexpected(transport_parameter_error_t::invalid_value);
      }
      break;
    case transport_parameter_id_t::initial_source_connection_id:
      if (!as_connection_id(parameters.initial_source_connection_id))
      {
        return std::unexpected(transport_parameter_error_t::invalid_value);
      }
      break;
    case transport_parameter_id_t::retry_source_connection_id:
      if (!as_connection_id(parameters.retry_source_connection_id))
      {
        return std::unexpected(transport_parameter_error_t::invalid_value);
      }
      break;
    case transport_parameter_id_t::preferred_address:
    default:
      // Section 18.1 reserves a family of identifiers for exactly this: a
      // decoder that refused what it did not recognise would fail against
      // conforming peers.
      break;
    }
  }
  return parameters;
}
} // namespace vio::quic
