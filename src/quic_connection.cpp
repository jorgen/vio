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

#include "vio/quic/connection.h"

#include "vio/crypto.h"
#include "vio/quic/ack_tracker.h"
#include "vio/quic/crypto_stream.h"
#include "vio/quic/frame_codec.h"
#include "vio/quic/packet.h"
#include "vio/quic/protection.h"

#include <algorithm>
#include <array>
#include <utility>

namespace vio::quic
{
namespace
{
constexpr std::size_t space_count = 3;

// The three packet number spaces of section 12.3. Early data has no space of
// its own -- 0-RTT packets share the application space -- and this build has
// no early data at all.
[[nodiscard]] std::size_t space_index(encryption_level_t level)
{
  switch (level)
  {
  case encryption_level_t::initial:
    return 0;
  case encryption_level_t::handshake:
    return 1;
  case encryption_level_t::application:
  case encryption_level_t::early_data:
    break;
  }
  return 2;
}

[[nodiscard]] std::optional<encryption_level_t> level_for(packet_kind_t kind)
{
  switch (kind)
  {
  case packet_kind_t::initial:
    return encryption_level_t::initial;
  case packet_kind_t::handshake:
    return encryption_level_t::handshake;
  case packet_kind_t::one_rtt:
    return encryption_level_t::application;
  case packet_kind_t::zero_rtt:
  case packet_kind_t::retry:
  case packet_kind_t::version_negotiation:
    break;
  }
  return std::nullopt;
}

constexpr encryption_level_t ordered_levels[space_count] = {encryption_level_t::initial, encryption_level_t::handshake, encryption_level_t::application};

// Section 14.1.
constexpr std::size_t minimum_initial_datagram = 1200;

// Scratch for the encoded ACK range list; a range costs at most sixteen bytes
// and the tracker holds a bounded number of them.
constexpr std::size_t ack_range_scratch = 1024;

struct packet_space_t
{
  crypto_stream_t crypto;
  ack_tracker_t acks;
  std::uint64_t next_packet_number = 0;
  std::uint64_t crypto_send_offset = 0;
  packet_protection_t read;
  packet_protection_t write;
  header_protection_t read_header;
  header_protection_t write_header;
  bool have_read = false;
  bool have_write = false;
  bool discarded = false;
};
} // namespace

namespace detail
{
struct connection_impl_t
{
  connection_impl_t(tls_session_t &&session, const connection_config_t &configuration)
    : tls(std::move(session))
    , config(configuration)
  {
  }

  tls_session_t tls;
  connection_config_t config;
  std::array<packet_space_t, space_count> spaces;

  connection_id_t local_connection_id;
  connection_id_t peer_connection_id;
  // What the client put in the Destination Connection ID of its first Initial.
  // Both sides need it: the server derives Initial keys from it and echoes it
  // back as a transport parameter, and the client checks that echo.
  connection_id_t original_destination_id;
  // A client starts with a connection ID it invented for the server, and
  // replaces it with the one the server actually chose (section 7.2). Until
  // that swap the value is somewhere to send, not something the peer said,
  // which is the difference section 7.3 authenticates.
  bool peer_connection_id_confirmed = false;

  connection_state_t state = connection_state_t::handshaking;
  bool handshake_complete = false;
  bool handshake_confirmed = false;
  bool handshake_done_sent = false;

  // Section 8.1. Until the peer address is validated a server may send no more
  // than three times what it has received.
  std::uint64_t bytes_received = 0;
  std::uint64_t bytes_sent = 0;
  bool address_validated = false;

  std::optional<connection_close_t> close_reason;
  bool close_frame_pending = false;

  std::optional<transport_parameters_t> peer_parameters;
};
} // namespace detail

namespace
{
using detail::connection_impl_t;

std::expected<void, error_t> install_keys(packet_space_t &space, const tls_secret_t &secret, bool read)
{
  auto material = derive_key_material(secret.suite, secret.secret);
  if (!material.has_value())
  {
    return std::unexpected(material.error());
  }
  auto &protection = read ? space.read : space.write;
  auto &header = read ? space.read_header : space.write_header;
  if (auto r = protection.init(secret.suite, secret.secret); !r.has_value())
  {
    return std::unexpected(r.error());
  }
  if (auto r = header.init(secret.suite, material->header_protection); !r.has_value())
  {
    return std::unexpected(r.error());
  }
  (read ? space.have_read : space.have_write) = true;
  return {};
}

std::expected<void, error_t> install_initial_keys(connection_impl_t &impl, const connection_id_t &destination)
{
  auto secrets = derive_initial_secrets(destination.bytes());
  if (!secrets.has_value())
  {
    return std::unexpected(secrets.error());
  }
  const bool is_client = impl.config.role == tls_role_t::client;
  const auto &write_secret = is_client ? secrets->client : secrets->server;
  const auto &read_secret = is_client ? secrets->server : secrets->client;

  auto &space = impl.spaces[0];
  const tls_secret_t write{.level = encryption_level_t::initial, .suite = tls_aes_128_gcm_sha256, .secret = write_secret};
  const tls_secret_t read{.level = encryption_level_t::initial, .suite = tls_aes_128_gcm_sha256, .secret = read_secret};
  if (auto r = install_keys(space, write, false); !r.has_value())
  {
    return r;
  }
  return install_keys(space, read, true);
}

void discard_space(packet_space_t &space)
{
  space.discarded = true;
  space.have_read = false;
  space.have_write = false;
}

void begin_close(connection_impl_t &impl, std::uint64_t error_code, std::string_view reason, bool application, bool from_peer)
{
  if (impl.close_reason.has_value())
  {
    return;
  }
  impl.close_reason = connection_close_t{.error_code = error_code, .application = application, .reason = std::string(reason), .from_peer = from_peer};
  if (from_peer)
  {
    impl.state = connection_state_t::closed;
    impl.close_frame_pending = false;
  }
  else
  {
    impl.state = connection_state_t::closing;
    impl.close_frame_pending = true;
  }
}

// Hands TLS whatever the CRYPTO streams have made contiguous, runs the
// handshake as far as it will go, and installs whatever secrets came out.
std::expected<void, error_t> drive_tls(connection_impl_t &impl)
{
  if (impl.close_reason.has_value())
  {
    return {};
  }

  for (auto level : ordered_levels)
  {
    auto &space = impl.spaces[space_index(level)];
    const auto readable = space.crypto.readable();
    if (readable.empty())
    {
      continue;
    }
    if (auto r = impl.tls.provide_handshake_data(level, readable); !r.has_value())
    {
      begin_close(impl, crypto_error_code(0x50), r.error().msg, false, false);
      return {};
    }
    space.crypto.consume(readable.size());
  }

  auto advanced = impl.tls.advance();
  if (!advanced.has_value())
  {
    const auto alert = impl.tls.alert();
    begin_close(impl, alert.has_value() ? crypto_error_code(*alert) : crypto_error_code(0x50), advanced.error().msg, false, false);
    return {};
  }

  for (auto &secret : impl.tls.take_write_secrets())
  {
    auto &space = impl.spaces[space_index(secret.level)];
    if (auto r = install_keys(space, secret, false); !r.has_value())
    {
      return r;
    }
  }
  for (auto &secret : impl.tls.take_read_secrets())
  {
    auto &space = impl.spaces[space_index(secret.level)];
    if (auto r = install_keys(space, secret, true); !r.has_value())
    {
      return r;
    }
  }

  if (*advanced && !impl.handshake_complete)
  {
    impl.handshake_complete = true;

    const auto raw = impl.tls.peer_transport_parameters();
    auto parameters = decode_transport_parameters(raw);
    if (!parameters.has_value())
    {
      begin_close(impl, 0x08, "malformed transport parameters", false, false);
      return {};
    }

    // Section 7.3. The connection IDs the peer says it used must be the ones
    // that actually arrived, which is what makes the handshake authenticate
    // them: an attacker that rewrote a connection ID in flight would be
    // caught here rather than silently taking over the connection.
    if (parameters->initial_source_connection_id.has_value() && impl.peer_connection_id_confirmed && *parameters->initial_source_connection_id != impl.peer_connection_id)
    {
      begin_close(impl, 0x0a, "initial_source_connection_id does not match", false, false);
      return {};
    }
    if (impl.config.role == tls_role_t::client)
    {
      if (!parameters->original_destination_connection_id.has_value() || *parameters->original_destination_connection_id != impl.original_destination_id)
      {
        begin_close(impl, 0x0a, "original_destination_connection_id does not match", false, false);
        return {};
      }
    }

    impl.peer_parameters = *parameters;

    // Section 4.9.2: a server confirms the handshake by completing it. A
    // client waits for HANDSHAKE_DONE.
    if (impl.config.role == tls_role_t::server)
    {
      impl.handshake_confirmed = true;
    }
    if (impl.state == connection_state_t::handshaking)
    {
      impl.state = connection_state_t::connected;
    }
  }
  return {};
}

// Everything a received packet's frames can do to the connection.
std::expected<bool, error_t> process_frames(connection_impl_t &impl, std::span<const std::uint8_t> payload, packet_kind_t kind, tick_t now)
{
  const auto packet_type = frame_packet_type(kind);
  if (!packet_type.has_value())
  {
    return false;
  }

  bool ack_eliciting = false;
  frame_reader_t reader(payload, *packet_type);
  while (auto next = reader.next())
  {
    if (!next->has_value())
    {
      begin_close(impl, static_cast<std::uint64_t>(next->error().code), next->error().reason, false, false);
      return ack_eliciting;
    }
    const auto &frame = next->value();
    const auto properties = frame_properties(frame.type);
    if (properties.has_value() && properties->ack_eliciting)
    {
      ack_eliciting = true;
    }

    switch (frame.kind)
    {
    case frame_kind_t::padding:
    case frame_kind_t::ping:
      break;

    case frame_kind_t::ack:
      // Nothing consumes acknowledgements yet: loss detection and congestion
      // control are not built. The frame is still parsed and validated so a
      // malformed one is caught.
      break;

    case frame_kind_t::crypto:
    {
      auto &space = impl.spaces[space_index(*level_for(kind))];
      const auto inserted = space.crypto.insert(frame.offset, frame.data);
      if (inserted == crypto_insert_t::offset_overflow)
      {
        begin_close(impl, static_cast<std::uint64_t>(transport_error_code_t::frame_encoding_error), "CRYPTO offset out of range", false, false);
        return ack_eliciting;
      }
      if (inserted == crypto_insert_t::buffer_exceeded)
      {
        begin_close(impl, transport_error_crypto_buffer_exceeded, "CRYPTO buffer exceeded", false, false);
        return ack_eliciting;
      }
      break;
    }

    case frame_kind_t::connection_close:
      begin_close(impl, frame.error_code, std::string(reinterpret_cast<const char *>(frame.data.data()), frame.data.size()), frame.application_error, true);
      return ack_eliciting;

    case frame_kind_t::handshake_done:
      if (impl.config.role == tls_role_t::server)
      {
        // Section 19.20: only a server sends this.
        begin_close(impl, transport_error_protocol_violation, "HANDSHAKE_DONE from a client", false, false);
        return ack_eliciting;
      }
      impl.handshake_confirmed = true;
      break;

    default:
      // Streams, flow control and connection ID management are not
      // implemented. Their frames are well formed and are accepted so the
      // packet is still acknowledged, but nothing acts on them.
      break;
    }
  }
  (void)now;
  return ack_eliciting;
}

std::expected<void, error_t> receive_packet(connection_impl_t &impl, const packet_header_t &header, std::span<std::uint8_t> packet, tick_t now)
{
  if (header.kind == packet_kind_t::retry || header.kind == packet_kind_t::version_negotiation || header.kind == packet_kind_t::zero_rtt)
  {
    // Retry and Version Negotiation are not handled yet; 0-RTT is refused by
    // construction. All three are dropped rather than treated as errors.
    return {};
  }

  auto level = level_for(header.kind);
  if (!level.has_value())
  {
    return {};
  }
  auto &space = impl.spaces[space_index(*level)];

  if (header.kind == packet_kind_t::initial && !space.have_read && !space.discarded && impl.config.role == tls_role_t::server)
  {
    // The client chose this connection ID at random; it is the only shared
    // secret the Initial keys have, which is why Initial protection stops
    // off-path spoofing and nothing more.
    impl.original_destination_id = header.destination_id;
    if (auto r = install_initial_keys(impl, header.destination_id); !r.has_value())
    {
      return r;
    }
  }

  if (space.discarded || !space.have_read)
  {
    return {};
  }

  auto opened = unprotect_packet(space.read, space.read_header, packet, header.packet_number_offset, space.acks.largest_received());
  if (!opened.has_value())
  {
    if (is_connection_error(opened.error()))
    {
      begin_close(impl, transport_error_protocol_violation, "reserved bits set", false, false);
    }
    return {};
  }

  if (space.acks.is_duplicate(opened->packet_number))
  {
    return {};
  }

  if (is_long_header(header.kind) && !impl.peer_connection_id_confirmed)
  {
    // Section 7.2: a client takes the server's chosen connection ID from the
    // first packet it can actually read, not the first one that arrives.
    impl.peer_connection_id = header.source_id;
    impl.peer_connection_id_confirmed = true;
  }

  if (header.kind == packet_kind_t::handshake)
  {
    // Section 8.1: a Handshake packet proves the peer processed an Initial,
    // which validates its address. Section 4.9.1: it also means the server
    // will never need Initial keys again.
    impl.address_validated = true;
    if (impl.config.role == tls_role_t::server && !impl.spaces[0].discarded)
    {
      discard_space(impl.spaces[0]);
    }
  }

  auto ack_eliciting = process_frames(impl, opened->payload, header.kind, now);
  if (!ack_eliciting.has_value())
  {
    return std::unexpected(ack_eliciting.error());
  }
  space.acks.on_packet_received(opened->packet_number, *ack_eliciting, now);

  // Keys for the next packet in this same datagram may depend on this one:
  // that is exactly why senders coalesce Initial before Handshake.
  return drive_tls(impl);
}

// Writes the frames for one space into a packet, returning its size or zero
// when there was nothing worth sending.
std::expected<std::size_t, error_t> build_packet(connection_impl_t &impl, encryption_level_t level, std::span<std::uint8_t> out, tick_t now, bool allow_empty_ack)
{
  auto &space = impl.spaces[space_index(level)];
  if (space.discarded || !space.have_write)
  {
    return std::size_t{0};
  }
  auto kind = packet_kind_for(level);
  if (!kind.has_value())
  {
    return std::size_t{0};
  }
  // A short header can only be used once this endpoint knows where to send it.
  if (!impl.peer_connection_id_confirmed && impl.config.role == tls_role_t::server)
  {
    return std::size_t{0};
  }

  const auto crypto_pending = impl.tls.pending_handshake_data(level);
  const bool want_ack = space.acks.has_received() && (space.acks.should_send_ack(now, impl.config.max_ack_delay) || (allow_empty_ack && space.acks.ack_pending()));
  const bool want_handshake_done = level == encryption_level_t::application && impl.config.role == tls_role_t::server && impl.handshake_complete && !impl.handshake_done_sent;
  const bool want_close = impl.close_frame_pending && space.have_write;

  if (crypto_pending.empty() && !want_ack && !want_handshake_done && !want_close)
  {
    return std::size_t{0};
  }

  packet_builder_t builder(out);
  const std::uint64_t packet_number = space.next_packet_number;
  bool begun = false;
  if (*kind == packet_kind_t::one_rtt)
  {
    begun = builder.begin_short(impl.peer_connection_id, false, false, packet_number, std::nullopt);
  }
  else
  {
    begun = builder.begin_long(*kind, quic_version_1, impl.peer_connection_id, impl.local_connection_id, {}, packet_number, std::nullopt);
  }
  if (!begun)
  {
    return std::size_t{0};
  }

  const std::size_t capacity = builder.maximum_frame_bytes();
  if (capacity == 0)
  {
    return std::size_t{0};
  }
  frame_writer_t frames(builder.payload_buffer().first(capacity));

  std::array<std::uint8_t, ack_range_scratch> range_bytes = {};
  bool wrote_ack = false;
  if (want_ack)
  {
    auto ack = space.acks.build_ack(now, static_cast<std::uint32_t>(impl.config.transport_parameters.ack_delay_exponent));
    if (ack.has_value())
    {
      ack_range_writer_t ranges(range_bytes);
      for (const auto &range : ack->ranges)
      {
        if (!ranges.write(range))
        {
          break;
        }
      }
      frame_t frame;
      frame.kind = frame_kind_t::ack;
      frame.largest_acknowledged = ack->largest_acknowledged;
      frame.ack_delay = ack->ack_delay;
      frame.first_ack_range = ack->first_ack_range;
      frame.ack_range_count = ranges.count();
      frame.ack_ranges = ranges.bytes();
      wrote_ack = frames.write(frame);
    }
  }

  if (want_close)
  {
    frame_t frame;
    frame.kind = frame_kind_t::connection_close;
    frame.error_code = impl.close_reason->error_code;
    // Section 10.2.3: the application form has no meaning outside 1-RTT, so a
    // close during the handshake is reported as an internal transport error.
    const bool application_here = impl.close_reason->application && level == encryption_level_t::application;
    frame.application_error = application_here;
    if (!application_here && impl.close_reason->application)
    {
      frame.error_code = transport_error_internal;
    }
    const auto &reason = impl.close_reason->reason;
    frame.data = std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(reason.data()), reason.size());
    if (!frames.write(frame))
    {
      frame.data = {};
      (void)frames.write(frame);
    }
  }

  std::size_t crypto_written = 0;
  if (!crypto_pending.empty() && !want_close)
  {
    const std::size_t available = frames.remaining();
    const std::size_t header_cost = 1 + varint_size(space.crypto_send_offset);
    if (available > header_cost + 1)
    {
      std::size_t amount = std::min(crypto_pending.size(), available);
      while (amount > 0 && header_cost + varint_size(amount) + amount > available)
      {
        --amount;
      }
      if (amount > 0)
      {
        frame_t frame;
        frame.kind = frame_kind_t::crypto;
        frame.offset = space.crypto_send_offset;
        frame.data = crypto_pending.first(amount);
        if (frames.write(frame))
        {
          crypto_written = amount;
        }
      }
    }
  }

  bool wrote_handshake_done = false;
  if (want_handshake_done && !want_close)
  {
    frame_t frame;
    frame.kind = frame_kind_t::handshake_done;
    wrote_handshake_done = frames.write(frame);
  }

  if (frames.written() == 0)
  {
    return std::size_t{0};
  }

  // Section 5.4.2 of RFC 9001: the packet has to be long enough to sample.
  const std::size_t minimum = builder.minimum_frame_bytes();
  if (frames.written() < minimum)
  {
    frame_t padding;
    padding.kind = frame_kind_t::padding;
    padding.padding_count = minimum - frames.written();
    if (!frames.write(padding))
    {
      return std::size_t{0};
    }
  }

  auto layout = builder.finish(frames.written());
  if (!layout.has_value())
  {
    return std::size_t{0};
  }
  auto length = protect_packet(space.write, space.write_header, out, *layout, packet_number);
  if (!length.has_value())
  {
    return std::unexpected(length.error());
  }

  space.next_packet_number = packet_number + 1;
  space.crypto_send_offset += crypto_written;
  if (crypto_written > 0)
  {
    impl.tls.consume_handshake_data(level, crypto_written);
  }
  if (wrote_ack)
  {
    space.acks.on_ack_sent();
  }
  if (wrote_handshake_done)
  {
    impl.handshake_done_sent = true;
  }
  return *length;
}
} // namespace

connection_t::~connection_t() = default;
connection_t::connection_t(connection_t &&) noexcept = default;
connection_t &connection_t::operator=(connection_t &&) noexcept = default;

std::expected<connection_t, error_t> connection_t::create(const tls_context_t &context, const connection_config_t &config, std::string_view server_name)
{
  if (config.local_connection_id_length > max_connection_id_size)
  {
    return std::unexpected(error_t{.code = 1, .msg = "local connection id length exceeds 20 bytes"});
  }
  if (config.max_datagram_size < minimum_initial_datagram)
  {
    return std::unexpected(error_t{.code = 1, .msg = "max datagram size is below the 1200 bytes section 14 requires"});
  }

  std::array<std::uint8_t, max_connection_id_size> scratch = {};
  auto local_bytes = std::span<std::uint8_t>(scratch).first(config.local_connection_id_length);
  if (!local_bytes.empty())
  {
    if (auto r = crypto::random_bytes(local_bytes); !r.has_value())
    {
      return std::unexpected(r.error());
    }
  }
  auto local = connection_id_t::from_bytes(local_bytes);
  if (!local.has_value())
  {
    return std::unexpected(error_t{.code = 1, .msg = "could not build a local connection id"});
  }

  auto session = tls_session_t::create(context, server_name);
  if (!session.has_value())
  {
    return std::unexpected(session.error());
  }

  auto impl = std::make_unique<detail::connection_impl_t>(std::move(*session), config);
  impl->local_connection_id = *local;

  // The transport parameters have to name the connection IDs this endpoint is
  // using before the handshake starts, because TLS carries them in its first
  // flight (section 7.3).
  impl->config.transport_parameters.initial_source_connection_id = impl->local_connection_id;

  if (config.role == tls_role_t::client)
  {
    // The first Destination Connection ID is unguessable so that only an
    // on-path attacker can forge Initial packets: it is the sole input to the
    // Initial key schedule.
    std::array<std::uint8_t, 8> initial_destination = {};
    if (auto r = crypto::random_bytes(initial_destination); !r.has_value())
    {
      return std::unexpected(r.error());
    }
    auto destination = connection_id_t::from_bytes(initial_destination);
    if (!destination.has_value())
    {
      return std::unexpected(error_t{.code = 1, .msg = "could not build the initial destination connection id"});
    }
    impl->original_destination_id = *destination;
    impl->peer_connection_id = *destination;
    if (auto r = install_initial_keys(*impl, *destination); !r.has_value())
    {
      return std::unexpected(r.error());
    }
    if (auto r = impl->tls.set_transport_parameters(encode_transport_parameters(impl->config.transport_parameters)); !r.has_value())
    {
      return std::unexpected(r.error());
    }
    // Produces the ClientHello, so that the first poll_send has something to
    // put in an Initial packet.
    if (auto r = drive_tls(*impl); !r.has_value())
    {
      return std::unexpected(r.error());
    }
  }

  connection_t connection;
  connection._impl = std::move(impl);
  return connection;
}

std::expected<void, error_t> connection_t::receive(std::span<std::uint8_t> datagram, tick_t now)
{
  auto &impl = *_impl;
  if (impl.state == connection_state_t::closed || datagram.empty())
  {
    return {};
  }
  impl.bytes_received += datagram.size();

  // A server has to know the client's connection ID before it can answer, and
  // it only learns it from the first Initial. Setting the transport parameters
  // has to wait for that too.
  if (impl.config.role == tls_role_t::server && !impl.peer_connection_id_confirmed)
  {
    auto invariant = parse_invariant_header(datagram);
    if (invariant.has_value() && invariant->long_header)
    {
      auto source = connection_id_t::from_bytes(invariant->source_id);
      auto destination = connection_id_t::from_bytes(invariant->destination_id);
      if (source.has_value() && destination.has_value())
      {
        impl.peer_connection_id = *source;
        impl.peer_connection_id_confirmed = true;
        auto parameters = impl.config.transport_parameters;
        parameters.original_destination_connection_id = *destination;
        impl.config.transport_parameters = parameters;
        if (auto r = impl.tls.set_transport_parameters(encode_transport_parameters(parameters)); !r.has_value())
        {
          return std::unexpected(r.error());
        }
      }
    }
  }

  packet_reader_t reader(datagram, impl.local_connection_id.size());
  while (auto next = reader.next())
  {
    if (!next->has_value())
    {
      // Section 12.2: once a packet cannot be parsed the rest of the datagram
      // goes with it.
      break;
    }
    const auto header = next->value();
    const auto offset = static_cast<std::size_t>(header.packet.data() - datagram.data());
    if (auto r = receive_packet(impl, header, datagram.subspan(offset, header.packet.size()), now); !r.has_value())
    {
      return r;
    }
    if (impl.state == connection_state_t::closed)
    {
      break;
    }
  }
  return {};
}

std::expected<std::size_t, error_t> connection_t::poll_send(std::span<std::uint8_t> out, tick_t now)
{
  auto &impl = *_impl;
  if (impl.state == connection_state_t::closed)
  {
    return std::size_t{0};
  }

  std::size_t budget = std::min(out.size(), impl.config.max_datagram_size);
  if (impl.config.role == tls_role_t::server && !impl.address_validated)
  {
    // Section 8.1: three times what has arrived, and not a byte more.
    const std::uint64_t allowance = impl.bytes_received * 3;
    if (impl.bytes_sent >= allowance)
    {
      return std::size_t{0};
    }
    const std::uint64_t remaining = allowance - impl.bytes_sent;
    budget = static_cast<std::size_t>(std::min<std::uint64_t>(budget, remaining));
  }
  if (budget == 0)
  {
    return std::size_t{0};
  }

  std::size_t written = 0;
  bool carries_initial = false;
  bool carries_anything = false;

  for (auto level : ordered_levels)
  {
    if (written >= budget)
    {
      break;
    }
    // An ACK on its own is worth a datagram only if nothing else is going out
    // in it; otherwise it rides along.
    auto size = build_packet(impl, level, out.subspan(written, budget - written), now, true);
    if (!size.has_value())
    {
      return std::unexpected(size.error());
    }
    if (*size > 0)
    {
      written += *size;
      carries_anything = true;
      if (level == encryption_level_t::initial)
      {
        carries_initial = true;
      }
    }
  }

  if (!carries_anything)
  {
    return std::size_t{0};
  }

  // Section 14.1: any datagram carrying an Initial is expanded to 1200 bytes.
  // Section 12.2 permits padding it with what looks like an invalid packet,
  // which is what trailing zeroes are, and a receiver discards the remainder
  // of a datagram once a packet fails to parse.
  if (carries_initial && written < minimum_initial_datagram && budget >= minimum_initial_datagram)
  {
    std::fill(out.begin() + static_cast<std::ptrdiff_t>(written), out.begin() + static_cast<std::ptrdiff_t>(minimum_initial_datagram), std::uint8_t{0});
    written = minimum_initial_datagram;
  }

  impl.bytes_sent += written;
  if (impl.close_frame_pending)
  {
    impl.close_frame_pending = false;
    impl.state = connection_state_t::closed;
  }
  // Section 4.9.1: a client is done with Initial keys once it sends anything
  // at the Handshake level.
  if (impl.config.role == tls_role_t::client && impl.spaces[1].have_write && !impl.spaces[0].discarded)
  {
    discard_space(impl.spaces[0]);
  }
  if (impl.handshake_confirmed && !impl.spaces[1].discarded)
  {
    // Section 4.9.2.
    discard_space(impl.spaces[1]);
  }
  return written;
}

std::optional<tick_t> connection_t::next_timeout() const
{
  std::optional<tick_t> earliest;
  for (auto level : ordered_levels)
  {
    const auto &space = _impl->spaces[space_index(level)];
    if (space.discarded)
    {
      continue;
    }
    auto deadline = space.acks.ack_deadline(_impl->config.max_ack_delay);
    if (deadline.has_value() && (!earliest.has_value() || *deadline < *earliest))
    {
      earliest = deadline;
    }
  }
  return earliest;
}

connection_state_t connection_t::state() const
{
  return _impl->state;
}

bool connection_t::handshake_complete() const
{
  return _impl->handshake_complete;
}

bool connection_t::handshake_confirmed() const
{
  return _impl->handshake_confirmed;
}

const connection_id_t &connection_t::local_connection_id() const
{
  return _impl->local_connection_id;
}

const connection_id_t &connection_t::peer_connection_id() const
{
  return _impl->peer_connection_id;
}

std::optional<transport_parameters_t> connection_t::peer_transport_parameters() const
{
  return _impl->peer_parameters;
}

std::string_view connection_t::selected_alpn() const
{
  return _impl->tls.selected_alpn();
}

std::optional<connection_close_t> connection_t::close_reason() const
{
  return _impl->close_reason;
}

void connection_t::close(std::uint64_t error_code, std::string_view reason, bool application)
{
  begin_close(*_impl, error_code, reason, application, false);
}
} // namespace vio::quic
