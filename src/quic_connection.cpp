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
#include "vio/quic/congestion_control.h"
#include "vio/quic/crypto_stream.h"
#include "vio/quic/frame_codec.h"
#include "vio/quic/loss_recovery.h"
#include "vio/quic/packet.h"
#include "vio/quic/protection.h"
#include "vio/quic/retry_token.h"
#include "vio/quic/streams.h"

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

[[nodiscard]] pn_space_t to_pn_space(encryption_level_t level)
{
  switch (level)
  {
  case encryption_level_t::initial:
    return pn_space_t::initial;
  case encryption_level_t::handshake:
    return pn_space_t::handshake;
  case encryption_level_t::application:
  case encryption_level_t::early_data:
    break;
  }
  return pn_space_t::application;
}

// Section 14.1.
constexpr std::size_t minimum_initial_datagram = 1200;

// Scratch for the encoded ACK range list; a range costs at most sixteen bytes
// and the tracker holds a bounded number of them.
constexpr std::size_t ack_range_scratch = 1024;

struct crypto_range_t
{
  std::uint64_t offset = 0;
  std::uint64_t length = 0;
};

// The send side of one level's CRYPTO stream. Everything TLS has produced is
// kept until the handshake is over, because a lost CRYPTO frame is repaired by
// sending the same bytes again (section 13.3) and TLS will not produce them a
// second time. The buffer is bounded by the size of a handshake.
struct crypto_sender_t
{
  std::vector<std::uint8_t> data;
  // How far into the stream has been packetized at least once.
  std::uint64_t sent_offset = 0;
  // Ranges that went out and were then declared lost.
  std::vector<crypto_range_t> retransmit;

  [[nodiscard]] bool has_pending() const
  {
    return !retransmit.empty() || sent_offset < data.size();
  }
};

[[nodiscard]] streams_config_t make_streams_config(const connection_config_t &config)
{
  streams_config_t out;
  out.local_initiator = config.role == tls_role_t::client ? stream_initiator_t::client : stream_initiator_t::server;
  out.initial_max_data = config.transport_parameters.initial_max_data;
  out.initial_max_stream_data_bidi_local = config.transport_parameters.initial_max_stream_data_bidi_local;
  out.initial_max_stream_data_bidi_remote = config.transport_parameters.initial_max_stream_data_bidi_remote;
  out.initial_max_stream_data_uni = config.transport_parameters.initial_max_stream_data_uni;
  out.initial_max_streams_bidi = config.transport_parameters.initial_max_streams_bidi;
  out.initial_max_streams_uni = config.transport_parameters.initial_max_streams_uni;
  return out;
}

struct packet_space_t
{
  crypto_stream_t crypto;
  ack_tracker_t acks;
  crypto_sender_t crypto_send;
  std::uint64_t next_packet_number = 0;
  // Set when a PTO expires here: the next packet must be ack-eliciting even if
  // there is nothing to say.
  bool probe_pending = false;
  packet_protection_t read;
  packet_protection_t write;
  header_protection_t read_header;
  header_protection_t write_header;
  // RFC 9001 section 6.3: the next generation is derived when the current one
  // is installed rather than when a key update is detected. Deriving it on
  // demand would make the time taken to process a packet depend on the Key
  // Phase bit, which is precisely the bit header protection hides.
  packet_protection_t read_next;
  packet_protection_t write_next;
  bool have_next = false;
  // Section 6.5: a packet sent before the update but delayed by the network
  // arrives after it, still protected with the old keys. Discarding the
  // previous generation immediately would drop perfectly good data.
  packet_protection_t read_previous;
  bool have_previous = false;
  // The phase this endpoint is sending in, and expecting to receive in.
  bool key_phase = false;
  // Section 6.1: another update may not begin until a packet from this phase
  // has been acknowledged, or the peer would be left without the keys to read
  // what comes next.
  std::uint64_t first_packet_in_phase = 0;
  bool phase_acknowledged = true;
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
    , congestion(configuration.max_datagram_size)
    , streams(make_streams_config(configuration))
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

  loss_recovery_t recovery;
  congestion_control_t congestion;
  // The token from a Retry, repeated in every subsequent Initial (section
  // 17.2.5.3).
  std::vector<std::uint8_t> retry_token;
  // A client accepts at most one Retry per connection attempt (section
  // 17.2.5.2); a second is an injected packet or a confused server.
  bool retry_handled = false;
  // A server issues at most one, and validates the token that comes back.
  // These are separate: having issued a Retry is exactly the state in which a
  // token is expected, so conflating them means never checking the one thing
  // the Retry was for.
  bool retry_issued = false;
  bool retry_validated = false;
  bool retry_pending = false;
  bool validated_by_retry = false;
  std::vector<std::uint8_t> pending_retry_packet;
  streams_t streams;
  // A window is only extended when the application has actually taken the
  // data; sending MAX_DATA for bytes still sitting in a reassembly buffer
  // would advertise capacity that does not exist.
  bool max_data_pending = false;
  std::uint64_t consumed_since_max_data = 0;
  // Appendix A.8 of RFC 9002: a client considers the server's address
  // validated once it has seen an acknowledgement at the Handshake level.
  bool received_handshake_ack = false;
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

// Section 6.1: the next generation comes from "quic ku" applied to the current
// secret. The header protection key is deliberately not touched -- it is what
// conceals the Key Phase bit, so a key that changed with the phase would have
// to be selected by the thing it hides.
std::expected<void, error_t> derive_next_generation(packet_space_t &space)
{
  if (!space.have_read || !space.have_write || space.have_next)
  {
    return {};
  }
  auto next_read = space.read.next_generation();
  if (!next_read.has_value())
  {
    return std::unexpected(next_read.error());
  }
  auto next_write = space.write.next_generation();
  if (!next_write.has_value())
  {
    return std::unexpected(next_write.error());
  }
  space.read_next = std::move(*next_read);
  space.write_next = std::move(*next_write);
  space.have_next = true;
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

void discard_space(connection_impl_t &impl, encryption_level_t level)
{
  auto &space = impl.spaces[space_index(level)];
  space.discarded = true;
  space.have_read = false;
  space.have_write = false;
  space.probe_pending = false;
  space.crypto_send = crypto_sender_t{};
  impl.recovery.discard_space(to_pn_space(level));
}

[[nodiscard]] recovery_context_t recovery_context(const connection_impl_t &impl)
{
  recovery_context_t context;
  context.handshake_confirmed = impl.handshake_confirmed;
  context.has_handshake_keys = impl.spaces[space_index(encryption_level_t::handshake)].have_write;
  // A server validates the client implicitly by answering it; a client is
  // waiting on the server until something at the Handshake level comes back.
  context.peer_completed_address_validation = impl.config.role == tls_role_t::server || impl.handshake_confirmed || impl.received_handshake_ack;
  context.max_ack_delay = impl.config.max_ack_delay;
  // The peer's exponent, not this endpoint's: it is the peer that encoded the
  // delay being decoded. Section 18.2 says assume 3 until told otherwise.
  context.ack_delay_exponent = impl.peer_parameters.has_value() ? static_cast<std::uint32_t>(impl.peer_parameters->ack_delay_exponent) : static_cast<std::uint32_t>(default_ack_delay_exponent_parameter);
  return context;
}

void queue_crypto_retransmit(packet_space_t &space, std::uint64_t offset, std::uint64_t length)
{
  if (length == 0)
  {
    return;
  }
  for (const auto &pending : space.crypto_send.retransmit)
  {
    if (pending.offset == offset && pending.length == length)
    {
      // A repeated PTO must not enqueue the same bytes again and again.
      return;
    }
  }
  space.crypto_send.retransmit.push_back(crypto_range_t{.offset = offset, .length = length});
}

// Section 13.3: a lost packet is repaired frame by frame, according to what
// each frame meant. The loss policy that decides which repair applies was
// settled in frame.h.
void repair_lost(connection_impl_t &impl, pn_space_t space, const std::vector<sent_packet_t> &lost)
{
  for (const auto &packet : lost)
  {
    for (const auto &frame : packet.frames)
    {
      switch (frame.kind)
      {
      case frame_kind_t::crypto:
        // Retransmit: the same bytes, at the same offset.
        queue_crypto_retransmit(impl.spaces[static_cast<std::size_t>(space)], frame.offset, frame.length);
        break;
      case frame_kind_t::handshake_done:
        // Also retransmit, and section 13.3 says until acknowledged.
        impl.handshake_done_sent = false;
        break;
      case frame_kind_t::stream:
      {
        // Retransmit: the same bytes at the same offset, exactly as for
        // CRYPTO. The stream may have been reset since, in which case its
        // send half refuses the range.
        if (auto *stream = impl.streams.find(frame.stream_id); stream != nullptr && stream->has_send)
        {
          stream->send.on_range_lost(frame.offset, frame.length);
        }
        break;
      }
      case frame_kind_t::reset_stream:
        if (auto *stream = impl.streams.find(frame.stream_id); stream != nullptr)
        {
          stream->reset_pending = true;
        }
        break;
      case frame_kind_t::max_data:
        // Resend current, not retransmit: the limit that applies now, which
        // is why nothing here replays the bytes that went out.
        impl.max_data_pending = true;
        break;
      default:
        // PING and PADDING carry no information to repair; a stale ACK would
        // do more harm than good. Both are discard.
        break;
      }
    }
  }
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

  // Only the application space ever updates keys; Initial and Handshake are
  // discarded long before it could matter.
  auto &application = impl.spaces[space_index(encryption_level_t::application)];
  if (auto r = derive_next_generation(application); !r.has_value())
  {
    return r;
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
    impl.streams.apply_peer_parameters(*parameters);

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
    {
      const auto space = to_pn_space(*level_for(kind));
      auto outcome = impl.recovery.on_ack_received(space, frame, now, recovery_context(impl));
      if (outcome.malformed)
      {
        begin_close(impl, static_cast<std::uint64_t>(transport_error_code_t::frame_encoding_error), "malformed ACK ranges", false, false);
        return ack_eliciting;
      }
      if (outcome.acknowledged_unsent)
      {
        // Section 13.1: a peer claiming to have received something that was
        // never sent is not confused, it is lying.
        begin_close(impl, transport_error_protocol_violation, "acknowledgement for a packet that was never sent", false, false);
        return ack_eliciting;
      }
      if (kind == packet_kind_t::handshake)
      {
        impl.received_handshake_ack = true;
      }
      auto &application_space = impl.spaces[space_index(encryption_level_t::application)];
      for (const auto &acked : outcome.acknowledged)
      {
        if (space == pn_space_t::application && acked.packet_number >= application_space.first_packet_in_phase)
        {
          application_space.phase_acknowledged = true;
        }
        impl.congestion.on_packet_acked(acked);
        for (const auto &sent : acked.frames)
        {
          if (sent.kind != frame_kind_t::stream)
          {
            continue;
          }
          if (auto *stream = impl.streams.find(sent.stream_id); stream != nullptr && stream->has_send)
          {
            stream->send.on_range_acknowledged(sent.offset, sent.length);
          }
        }
      }
      impl.congestion.on_packets_lost(outcome.lost, now, impl.recovery.rtt(), impl.config.max_ack_delay, impl.recovery.first_rtt_sample());
      repair_lost(impl, space, outcome.lost);
      break;
    }

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

    case frame_kind_t::stream:
    {
      const auto error = impl.streams.receive_stream_frame(frame.stream_id, frame.offset, frame.data, frame.fin);
      if (error != streams_error_t::none)
      {
        begin_close(impl, streams_error_code(error), "stream error", false, false);
        return ack_eliciting;
      }
      break;
    }

    case frame_kind_t::reset_stream:
    {
      const auto error = impl.streams.receive_reset_stream(frame.stream_id, frame.error_code, frame.final_size);
      if (error != streams_error_t::none)
      {
        begin_close(impl, streams_error_code(error), "stream reset error", false, false);
        return ack_eliciting;
      }
      break;
    }

    case frame_kind_t::stop_sending:
    {
      const auto error = impl.streams.receive_stop_sending(frame.stream_id, frame.error_code);
      if (error != streams_error_t::none)
      {
        begin_close(impl, streams_error_code(error), "stop sending error", false, false);
        return ack_eliciting;
      }
      break;
    }

    case frame_kind_t::max_data:
      impl.streams.set_peer_max_data(frame.maximum);
      break;

    case frame_kind_t::max_stream_data:
    {
      const auto error = impl.streams.receive_max_stream_data(frame.stream_id, frame.maximum);
      if (error != streams_error_t::none)
      {
        begin_close(impl, streams_error_code(error), "max stream data error", false, false);
        return ack_eliciting;
      }
      break;
    }

    case frame_kind_t::max_streams:
      impl.streams.set_peer_max_streams(frame.bidirectional ? stream_direction_t::bidirectional : stream_direction_t::unidirectional, frame.maximum);
      break;

    case frame_kind_t::data_blocked:
    case frame_kind_t::stream_data_blocked:
    case frame_kind_t::streams_blocked:
      // The peer is telling us it wants a bigger limit. Nothing is owed in
      // reply beyond what the window update policy already does.
      break;

    default:
      // NEW_CONNECTION_ID, RETIRE_CONNECTION_ID, PATH_CHALLENGE,
      // PATH_RESPONSE and NEW_TOKEN are parsed and acknowledged but not acted
      // on: migration, connection ID rotation and Retry are not built.
      break;
    }
  }
  return ack_eliciting;
}

// Section 6.1 and 6.2: one step to the next generation. The header protection
// key is deliberately untouched.
std::expected<void, error_t> advance_key_phase(packet_space_t &space, bool move_write)
{
  if (!space.have_next)
  {
    return {};
  }
  space.read_previous = std::move(space.read);
  space.have_previous = true;
  space.read = std::move(space.read_next);
  if (move_write)
  {
    space.write = std::move(space.write_next);
  }
  space.have_next = false;
  space.key_phase = !space.key_phase;
  space.first_packet_in_phase = space.next_packet_number;
  space.phase_acknowledged = false;
  return derive_next_generation(space);
}

// Section 17.2.5.2. Every condition here is a discard rather than an error:
// a Retry is unprotected apart from its integrity tag, so anyone on the path
// can inject one, and reacting to a bad one would hand them the connection.
std::expected<void, error_t> receive_retry(connection_impl_t &impl, const packet_header_t &header)
{
  if (impl.config.role != tls_role_t::client)
  {
    return {};
  }
  if (impl.retry_handled || impl.handshake_complete)
  {
    // At most one per connection attempt, and none once the handshake has
    // moved on.
    return {};
  }
  if (header.retry_token.empty())
  {
    return {};
  }
  if (header.source_id == impl.original_destination_id)
  {
    // A server that echoed back the connection ID the client invented has
    // proved nothing; section 17.2.5.1 forbids it.
    return {};
  }
  if (!verify_retry_integrity(impl.original_destination_id.bytes(), header.packet))
  {
    // Section 5.8 of RFC 9001: the tag is what proves the sender saw the
    // client's Initial. Without it this is an injected packet.
    return {};
  }

  impl.retry_token.assign(header.retry_token.begin(), header.retry_token.end());
  impl.retry_handled = true;
  impl.validated_by_retry = true;

  // Section 17.2.5.3: the client adopts the server's connection ID, and the
  // Initial keys follow it because they are derived from it.
  impl.peer_connection_id = header.source_id;
  impl.peer_connection_id_confirmed = true;
  if (auto r = install_initial_keys(impl, header.source_id); !r.has_value())
  {
    return r;
  }

  // The same handshake message goes again, from the start, under the new
  // keys. Packet numbers are deliberately not reset -- section 17.2.5.3.
  auto &initial = impl.spaces[space_index(encryption_level_t::initial)];
  initial.crypto_send.sent_offset = 0;
  initial.crypto_send.retransmit.clear();
  initial.probe_pending = false;
  impl.recovery.discard_space(pn_space_t::initial);
  return {};
}

std::expected<void, error_t> receive_packet(connection_impl_t &impl, const packet_header_t &header, std::span<std::uint8_t> packet, tick_t now)
{
  if (header.kind == packet_kind_t::retry)
  {
    return receive_retry(impl, header);
  }
  if (header.kind == packet_kind_t::version_negotiation || header.kind == packet_kind_t::zero_rtt)
  {
    // Version Negotiation is not handled yet; 0-RTT is refused by
    // construction. Both are dropped rather than treated as errors.
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

  if (header.kind == packet_kind_t::initial && impl.config.role == tls_role_t::server && impl.config.retry_key != nullptr && !impl.retry_validated)
  {
    if (header.token.empty())
    {
      // Section 8.1.2: no token, so nothing has proved this address is real.
      // Answering with a Retry costs the client a round trip and costs anyone
      // spoofing a source address the ability to make this server work for
      // them. No handshake state is built until the token comes back.
      if (!impl.retry_issued)
      {
        impl.retry_pending = true;
        impl.retry_issued = true;
        // Section 5.2 of RFC 9001: Initial keys follow the Destination
        // Connection ID, and after a Retry that is the one this server just
        // told the client to use. Keeping the keys derived from the ID the
        // client invented would leave the server unable to read its own Retry
        // being answered. Packet numbers are deliberately left alone: section
        // 17.2.5.3 forbids the client resetting them, so the acknowledgement
        // state stays valid across the Retry.
        if (auto r = install_initial_keys(impl, impl.local_connection_id); !r.has_value())
        {
          return r;
        }
      }
      return {};
    }

    auto original = impl.config.retry_key->validate(header.token, impl.config.peer_address, now);
    if (!original.has_value())
    {
      // Forged, expired, or presented from a different address. A packet that
      // cannot be accounted for is dropped, not argued with.
      return {};
    }
    impl.retry_validated = true;
    // Section 8.1.4: the connection ID the client first chose comes back out
    // of the token, and the handshake requires it to be echoed to the client
    // so the client can confirm the Retry was genuine.
    impl.original_destination_id = *original;
    impl.validated_by_retry = true;
    impl.address_validated = true;
    auto parameters = impl.config.transport_parameters;
    parameters.original_destination_connection_id = *original;
    parameters.retry_source_connection_id = impl.local_connection_id;
    impl.config.transport_parameters = parameters;
    if (auto r = impl.tls.set_transport_parameters(encode_transport_parameters(parameters)); !r.has_value())
    {
      return std::unexpected(r.error());
    }
  }

  if (space.discarded || !space.have_read)
  {
    return {};
  }

  // The two halves are split here rather than using unprotect_packet, because
  // which key generation applies is only knowable once the header is unmasked,
  // and the Key Phase bit that says so is itself under header protection.
  auto unmasked = space.read_header.remove(packet, header.packet_number_offset);
  if (!unmasked.has_value())
  {
    if (is_connection_error(unmasked.error()))
    {
      begin_close(impl, transport_error_protocol_violation, "reserved bits set", false, false);
    }
    return {};
  }

  const bool phase_changed = header.kind == packet_kind_t::one_rtt && unmasked->key_phase != space.key_phase;
  bool peer_updated = false;

  // Decryption is in place, and an AEAD that rejects a tag is under no
  // obligation to leave the buffer as it found it. Any attempt that might be
  // followed by another therefore needs the ciphertext kept: without this the
  // second attempt authenticates whatever the first left behind, and a key
  // update simply never completes.
  const std::size_t payload_offset = header.packet_number_offset + unmasked->packet_number_length;
  std::vector<std::uint8_t> ciphertext;
  if (phase_changed && payload_offset <= packet.size())
  {
    ciphertext.assign(packet.begin() + static_cast<std::ptrdiff_t>(payload_offset), packet.end());
  }
  const auto restore = [&]()
  {
    std::copy(ciphertext.begin(), ciphertext.end(), packet.begin() + static_cast<std::ptrdiff_t>(payload_offset));
  };

  auto opened = space.read.decrypt(packet, header.packet_number_offset, *unmasked, space.acks.largest_received());
  if (phase_changed && !opened.has_value())
  {
    // A differing Key Phase bit means one of two things, and which one is not
    // knowable without trying: the peer has moved on, or this is a packet from
    // before the last update that the network delayed. Both generations are
    // already derived, so neither costs a key schedule here -- section 6.3
    // warns that deriving on demand leaks when updates happen.
    if (space.have_next && impl.handshake_confirmed)
    {
      restore();
      opened = space.read_next.decrypt(packet, header.packet_number_offset, *unmasked, space.acks.largest_received());
      peer_updated = opened.has_value();
    }
    if (!opened.has_value() && space.have_previous)
    {
      restore();
      opened = space.read_previous.decrypt(packet, header.packet_number_offset, *unmasked, space.acks.largest_received());
    }
  }

  if (!opened.has_value())
  {
    if (is_connection_error(opened.error()))
    {
      begin_close(impl, transport_error_protocol_violation, "reserved bits set", false, false);
    }
    return {};
  }

  if (peer_updated)
  {
    // Section 6.2: the packet opened under the next generation, so the peer
    // really did update. Sending keys move with it, and must do so before the
    // acknowledgement goes out -- that acknowledgement is what tells the peer
    // the update completed.
    if (auto r = advance_key_phase(space, true); !r.has_value())
    {
      return r;
    }
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
      discard_space(impl, encryption_level_t::initial);
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

// Section 17.2.5.1. The Destination Connection ID is the one the client used
// as its source, and the Source Connection ID is this server's own -- which is
// what the client will address from then on.
std::expected<std::size_t, error_t> build_retry(connection_impl_t &impl, std::span<std::uint8_t> out, tick_t now)
{
  if (impl.config.retry_key == nullptr)
  {
    return std::size_t{0};
  }
  auto token = impl.config.retry_key->issue(impl.original_destination_id, impl.config.peer_address, now);
  if (!token.has_value())
  {
    return std::unexpected(token.error());
  }

  const std::size_t head = serialize_retry(out, quic_version_1, impl.peer_connection_id, impl.local_connection_id, *token);
  if (head == 0 || out.size() < head + retry_integrity_tag_size)
  {
    return std::size_t{0};
  }
  auto tag = retry_integrity_tag(impl.original_destination_id.bytes(), out.first(head));
  if (!tag.has_value())
  {
    return std::unexpected(tag.error());
  }
  std::copy(tag->begin(), tag->end(), out.begin() + static_cast<std::ptrdiff_t>(head));
  return head + retry_integrity_tag_size;
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

  // Whatever TLS has produced becomes ours to keep: it will not produce it
  // again, and a lost CRYPTO frame is repaired by resending the same bytes.
  if (const auto produced = impl.tls.pending_handshake_data(level); !produced.empty())
  {
    space.crypto_send.data.insert(space.crypto_send.data.end(), produced.begin(), produced.end());
    impl.tls.consume_handshake_data(level, produced.size());
  }

  const bool want_crypto = space.crypto_send.has_pending();
  const bool want_ack = space.acks.has_received() && (space.acks.should_send_ack(now, impl.config.max_ack_delay) || (allow_empty_ack && space.acks.ack_pending()));
  const bool want_handshake_done = level == encryption_level_t::application && impl.config.role == tls_role_t::server && impl.handshake_complete && !impl.handshake_done_sent;
  const bool want_close = impl.close_frame_pending && space.have_write;
  const bool want_probe = space.probe_pending;

  bool want_streams = false;
  if (level == encryption_level_t::application && !want_close)
  {
    want_streams = impl.max_data_pending;
    for (auto &entry : impl.streams.all())
    {
      auto &stream = entry.second;
      if (stream.reset_pending || (stream.has_send && stream.send.has_pending()) || stream.pending_max_stream_data || stream.stop_sending_pending.has_value())
      {
        want_streams = true;
        break;
      }
    }
  }

  if (!want_crypto && !want_ack && !want_handshake_done && !want_close && !want_probe && !want_streams)
  {
    return std::size_t{0};
  }

  packet_builder_t builder(out);
  const std::uint64_t packet_number = space.next_packet_number;
  bool begun = false;
  if (*kind == packet_kind_t::one_rtt)
  {
    begun = builder.begin_short(impl.peer_connection_id, space.key_phase, false, packet_number, std::nullopt);
  }
  else
  {
    const auto token = *kind == packet_kind_t::initial ? std::span<const std::uint8_t>(impl.retry_token) : std::span<const std::uint8_t>{};
    begun = builder.begin_long(*kind, quic_version_1, impl.peer_connection_id, impl.local_connection_id, token, packet_number, std::nullopt);
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

  std::vector<sent_frame_t> record;
  std::size_t crypto_written = 0;
  std::uint64_t crypto_offset = 0;
  bool crypto_from_retransmit = false;
  if (want_crypto && !want_close)
  {
    // Section 13.3: retransmissions go before new data.
    if (!space.crypto_send.retransmit.empty())
    {
      crypto_offset = space.crypto_send.retransmit.front().offset;
      crypto_from_retransmit = true;
    }
    else
    {
      crypto_offset = space.crypto_send.sent_offset;
    }
    const std::uint64_t span_end = crypto_from_retransmit ? crypto_offset + space.crypto_send.retransmit.front().length : space.crypto_send.data.size();

    const std::size_t available = frames.remaining();
    const std::size_t header_cost = 1 + varint_size(crypto_offset);
    if (available > header_cost + 1 && span_end > crypto_offset)
    {
      std::size_t amount = static_cast<std::size_t>(std::min<std::uint64_t>(span_end - crypto_offset, available));
      while (amount > 0 && header_cost + varint_size(amount) + amount > available)
      {
        --amount;
      }
      if (amount > 0)
      {
        frame_t frame;
        frame.kind = frame_kind_t::crypto;
        frame.offset = crypto_offset;
        frame.data = std::span<const std::uint8_t>(space.crypto_send.data).subspan(static_cast<std::size_t>(crypto_offset), amount);
        if (frames.write(frame))
        {
          crypto_written = amount;
          record.push_back(sent_frame_t{.kind = frame_kind_t::crypto, .offset = crypto_offset, .length = amount});
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
    if (wrote_handshake_done)
    {
      record.push_back(sent_frame_t{.kind = frame_kind_t::handshake_done});
    }
  }

  std::size_t stream_bytes_written = 0;
  if (want_streams)
  {
    // Section 4.1: a window update says what this endpoint is now willing to
    // receive in total, so it is recomputed at send time rather than queued
    // with a stale number.
    if (impl.max_data_pending)
    {
      frame_t frame;
      frame.kind = frame_kind_t::max_data;
      frame.maximum = impl.streams.local_max_data();
      if (frames.write(frame))
      {
        impl.max_data_pending = false;
        record.push_back(sent_frame_t{.kind = frame_kind_t::max_data});
      }
    }

    for (auto &entry : impl.streams.all())
    {
      auto &stream = entry.second;

      if (stream.pending_max_stream_data && stream.has_receive)
      {
        frame_t frame;
        frame.kind = frame_kind_t::max_stream_data;
        frame.stream_id = stream.id;
        frame.maximum = stream.receive.max_data();
        if (frames.write(frame))
        {
          stream.pending_max_stream_data = false;
          record.push_back(sent_frame_t{.kind = frame_kind_t::max_stream_data, .stream_id = stream.id});
        }
      }

      if (stream.stop_sending_pending.has_value() && stream.has_receive)
      {
        frame_t frame;
        frame.kind = frame_kind_t::stop_sending;
        frame.stream_id = stream.id;
        frame.error_code = *stream.stop_sending_pending;
        if (frames.write(frame))
        {
          stream.stop_sending_pending.reset();
          record.push_back(sent_frame_t{.kind = frame_kind_t::stop_sending, .stream_id = stream.id});
        }
      }

      if (stream.reset_pending && stream.has_send)
      {
        frame_t frame;
        frame.kind = frame_kind_t::reset_stream;
        frame.stream_id = stream.id;
        frame.error_code = stream.send.reset_error().value_or(0);
        frame.final_size = stream.send.final_size();
        if (frames.write(frame))
        {
          stream.reset_pending = false;
          record.push_back(sent_frame_t{.kind = frame_kind_t::reset_stream, .stream_id = stream.id});
        }
        continue;
      }

      if (!stream.has_send || !stream.send.has_pending())
      {
        continue;
      }

      // A STREAM frame costs its type byte, the id, the offset and the
      // length; leave room for all four before deciding how much data fits.
      const std::size_t available = frames.remaining();
      const std::size_t overhead = 1 + varint_size(stream.id) + varint_size(stream.send.sent_offset()) + 2;
      if (available <= overhead)
      {
        continue;
      }
      auto chunk = stream.send.next_chunk(available - overhead, impl.streams.connection_send_window());
      if (!chunk.has_value())
      {
        continue;
      }

      frame_t frame;
      frame.kind = frame_kind_t::stream;
      frame.stream_id = stream.id;
      frame.offset = chunk->offset;
      frame.data = chunk->data;
      frame.fin = chunk->fin;
      if (!frames.write(frame))
      {
        continue;
      }
      record.push_back(sent_frame_t{.kind = frame_kind_t::stream, .offset = chunk->offset, .length = chunk->data.size(), .stream_id = stream.id});
      stream.send.on_chunk_sent(*chunk);
      if (!chunk->retransmit)
      {
        // Only new data consumes connection-level credit; a retransmission
        // was charged when it first went out.
        stream_bytes_written += chunk->data.size();
      }
    }
  }

  // A probe has to elicit an acknowledgement; if nothing else in this packet
  // will, a PING is the cheapest thing that does.
  bool wrote_ping = false;
  if (want_probe && !want_close && crypto_written == 0 && !wrote_handshake_done && stream_bytes_written == 0)
  {
    frame_t frame;
    frame.kind = frame_kind_t::ping;
    wrote_ping = frames.write(frame);
    if (wrote_ping)
    {
      record.push_back(sent_frame_t{.kind = frame_kind_t::ping});
    }
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
  if (crypto_written > 0)
  {
    if (crypto_from_retransmit)
    {
      auto &front = space.crypto_send.retransmit.front();
      front.offset += crypto_written;
      front.length -= crypto_written;
      if (front.length == 0)
      {
        space.crypto_send.retransmit.erase(space.crypto_send.retransmit.begin());
      }
    }
    else
    {
      space.crypto_send.sent_offset += crypto_written;
    }
  }
  if (wrote_ack)
  {
    space.acks.on_ack_sent();
  }
  if (wrote_handshake_done)
  {
    impl.handshake_done_sent = true;
  }
  space.probe_pending = false;
  impl.streams.on_data_sent(stream_bytes_written);

  // Section 2 of RFC 9002: ACK, PADDING and CONNECTION_CLOSE neither elicit an
  // acknowledgement nor count against the congestion window, so a packet
  // carrying only those is not tracked for loss.
  sent_packet_t sent;
  sent.packet_number = packet_number;
  sent.time_sent = now;
  sent.ack_eliciting = crypto_written > 0 || wrote_handshake_done || wrote_ping || !record.empty();
  sent.in_flight = sent.ack_eliciting;
  sent.size = *length;
  sent.frames = std::move(record);
  impl.recovery.on_packet_sent(to_pn_space(level), std::move(sent));
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

  // A timer that has come due is handled before anything new is built, so a
  // probe or a repair goes out in this datagram rather than the next one.
  const auto context = recovery_context(impl);
  if (auto deadline = impl.recovery.loss_detection_timer(now, context); deadline.has_value() && now >= *deadline)
  {
    auto expiry = impl.recovery.on_loss_detection_timeout(now, context);
    if (expiry.loss_space.has_value())
    {
      impl.congestion.on_packets_lost(expiry.lost, now, impl.recovery.rtt(), impl.config.max_ack_delay, impl.recovery.first_rtt_sample());
      repair_lost(impl, *expiry.loss_space, expiry.lost);
    }
    if (expiry.probe_space.has_value())
    {
      for (auto level : ordered_levels)
      {
        if (to_pn_space(level) != *expiry.probe_space)
        {
          continue;
        }
        auto &space = impl.spaces[space_index(level)];
        space.probe_pending = true;
        // Section 6.2.4: a probe should carry data. During a handshake a bare
        // PING would elicit an acknowledgement while telling the peer nothing
        // it is waiting for, so anything still outstanding goes again.
        for (const auto &frame : impl.recovery.unacknowledged_frames(*expiry.probe_space))
        {
          if (frame.kind == frame_kind_t::crypto)
          {
            queue_crypto_retransmit(space, frame.offset, frame.length);
          }
        }
      }
    }
  }

  // Section 7.5: a probe is never blocked by the controller, and neither is a
  // CONNECTION_CLOSE -- both have to get out for the connection to make any
  // progress at all. Everything else waits for the window.
  bool probing = impl.close_frame_pending;
  for (auto level : ordered_levels)
  {
    probing = probing || impl.spaces[space_index(level)].probe_pending;
  }
  if (!probing && impl.recovery.bytes_in_flight() >= impl.congestion.window())
  {
    return std::size_t{0};
  }

  if (impl.retry_pending)
  {
    // A Retry is its own datagram: it carries no packet number, cannot be
    // acknowledged, and nothing may be coalesced after it.
    auto written = build_retry(impl, out, now);
    if (!written.has_value())
    {
      return std::unexpected(written.error());
    }
    if (*written > 0)
    {
      impl.retry_pending = false;
      impl.bytes_sent += *written;
    }
    return written;
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
    discard_space(impl, encryption_level_t::initial);
  }
  if (impl.handshake_confirmed && !impl.spaces[1].discarded)
  {
    // Section 4.9.2.
    discard_space(impl, encryption_level_t::handshake);
  }
  return written;
}

std::optional<tick_t> connection_t::next_timeout(tick_t now) const
{
  std::optional<tick_t> earliest;
  const auto consider = [&earliest](std::optional<tick_t> candidate)
  {
    if (candidate.has_value() && (!earliest.has_value() || *candidate < *earliest))
    {
      earliest = candidate;
    }
  };

  for (auto level : ordered_levels)
  {
    const auto &space = _impl->spaces[space_index(level)];
    if (space.discarded)
    {
      continue;
    }
    consider(space.acks.ack_deadline(_impl->config.max_ack_delay));
  }
  // Whichever comes first: an acknowledgement this endpoint owes, or the loss
  // detection timer telling it something of its own has gone missing.
  consider(_impl->recovery.loss_detection_timer(now, recovery_context(*_impl)));
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

bool connection_t::address_validated_by_retry() const
{
  return _impl->validated_by_retry;
}

bool connection_t::initiate_key_update()
{
  auto &space = _impl->spaces[space_index(encryption_level_t::application)];
  if (!_impl->handshake_confirmed || space.discarded || !space.have_next || !space.phase_acknowledged)
  {
    return false;
  }
  return advance_key_phase(space, true).has_value();
}

bool connection_t::key_phase() const
{
  return _impl->spaces[space_index(encryption_level_t::application)].key_phase;
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

std::optional<std::uint64_t> connection_t::open_stream(stream_direction_t direction)
{
  return _impl->streams.open(direction);
}

std::size_t connection_t::write_stream(std::uint64_t id, std::span<const std::uint8_t> data, bool fin)
{
  auto *stream = _impl->streams.find(id);
  if (stream == nullptr || !stream->has_send)
  {
    return 0;
  }
  if (!stream->send.write(data, fin))
  {
    return 0;
  }
  return data.size();
}

std::span<const std::uint8_t> connection_t::readable_stream(std::uint64_t id)
{
  auto *stream = _impl->streams.find(id);
  if (stream == nullptr || !stream->has_receive)
  {
    return {};
  }
  return stream->receive.readable();
}

void connection_t::consume_stream(std::uint64_t id, std::size_t bytes)
{
  auto *stream = _impl->streams.find(id);
  if (stream == nullptr || !stream->has_receive)
  {
    return;
  }
  const auto before = stream->receive.read_offset();
  stream->receive.consume(bytes);
  const auto taken = stream->receive.read_offset() - before;
  if (taken == 0)
  {
    return;
  }

  // Section 4.1: the peer may send more once this endpoint has actually taken
  // the data. Updating on every byte would spend a frame per read, so the
  // window is extended once it has been half consumed -- early enough that the
  // peer never stalls waiting for credit.
  stream->consumed_since_update += taken;
  const auto stream_window = stream->receive.max_data() - stream->receive.read_offset();
  if (stream->consumed_since_update * 2 >= stream_window + stream->consumed_since_update)
  {
    stream->receive.set_max_data(stream->receive.read_offset() + _impl->config.transport_parameters.initial_max_stream_data_bidi_local);
    stream->consumed_since_update = 0;
    stream->pending_max_stream_data = true;
  }

  _impl->consumed_since_max_data += taken;
  const auto connection_window = _impl->streams.local_max_data() - _impl->streams.data_received();
  if (_impl->consumed_since_max_data * 2 >= connection_window + _impl->consumed_since_max_data)
  {
    _impl->streams.set_local_max_data(_impl->streams.local_max_data() + _impl->consumed_since_max_data);
    _impl->consumed_since_max_data = 0;
    _impl->max_data_pending = true;
  }
}

std::vector<std::uint64_t> connection_t::readable_streams()
{
  std::vector<std::uint64_t> out;
  for (auto &entry : _impl->streams.all())
  {
    if (entry.second.has_receive && !entry.second.receive.readable().empty())
    {
      out.push_back(entry.first);
    }
  }
  return out;
}

bool connection_t::stream_receive_finished(std::uint64_t id)
{
  auto *stream = _impl->streams.find(id);
  if (stream == nullptr || !stream->has_receive)
  {
    return false;
  }
  const auto state = stream->receive.state();
  return state == receive_state_t::data_received || state == receive_state_t::data_read || state == receive_state_t::reset_received || state == receive_state_t::reset_read;
}

bool connection_t::stream_send_finished(std::uint64_t id)
{
  auto *stream = _impl->streams.find(id);
  if (stream == nullptr || !stream->has_send)
  {
    return false;
  }
  const auto state = stream->send.state();
  return state == send_state_t::data_received || state == send_state_t::reset_sent || state == send_state_t::reset_received;
}

void connection_t::reset_stream(std::uint64_t id, std::uint64_t error_code)
{
  auto *stream = _impl->streams.find(id);
  if (stream == nullptr || !stream->has_send)
  {
    return;
  }
  stream->send.reset(error_code);
  stream->reset_pending = true;
}

void connection_t::stop_sending(std::uint64_t id, std::uint64_t error_code)
{
  auto *stream = _impl->streams.find(id);
  if (stream == nullptr || !stream->has_receive)
  {
    return;
  }
  stream->stop_sending_pending = error_code;
}
} // namespace vio::quic
