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
#include "vio/quic/connection_id_manager.h"
#include "vio/quic/path.h"
#include "vio/quic/stateless_reset.h"
#include "vio/quic/protection.h"
#include "vio/quic/retry_token.h"
#include "vio/quic/streams.h"

#include <algorithm>
#include <array>
#include <deque>
#include <utility>

namespace vio::quic
{
namespace
{
// Section 6.2.4 of RFC 9002 permits two.
constexpr std::uint8_t probes_per_timeout = 2;
} // namespace

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
  // How many ack-eliciting packets a expired PTO still owes this space. Section
  // 6.2.4 allows two, and two is what is sent: a probe is the only thing moving
  // on a connection that has gone quiet, so losing the single packet that was
  // meant to restart it costs another whole backoff interval -- and the
  // intervals double. On a path dropping 30% of packets that is the difference
  // between a handshake finishing and a handshake taking tens of seconds.
  std::uint8_t probes_pending = 0;
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
  // Section 13.4.2.1: the counts arrive per packet number space, so they are
  // checked per space.
  ecn_validator_t ecn;
  bool have_next = false;
  // Section 6.5: a packet sent before the update but delayed by the network
  // arrives after it, still protected with the old keys. Discarding the
  // previous generation immediately would drop perfectly good data.
  packet_protection_t read_previous;
  bool have_previous = false;
  // Section 6.6: how many packets have been protected under the current key.
  std::uint64_t packets_encrypted = 0;
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
    , congestion(configuration.max_datagram_size, configuration.congestion_algorithm)
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

  // The version in use. A server adopts whatever its endpoint agreed to accept
  // from the client's first Initial; everything version specific -- the Initial
  // salt, the key labels, the long header type codes, the Retry tag -- follows
  // from it rather than being assumed.
  std::uint32_t version = quic_version_1;

  // Section 14.3. Every datagram this connection sends is bounded by what this
  // has validated, which starts at the size every path must carry and grows by
  // probing.
  mtu_discovery_t mtu;

  // How fast the path is delivering, measured rather than inferred from the
  // window. Section 14.3's probing and section 7's window both benefit from
  // being told where the operating point is instead of searching for it.
  delivery_rate_estimator_t delivery;
  std::uint64_t last_delivery_rate = 0;

  std::optional<transport_parameters_t> peer_parameters;

  loss_recovery_t recovery;
  congestion_control_t congestion;
  pacer_t pacer;
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
  // Section 4.1: a DATA_BLOCKED is owed. Recorded with the limit that caused
  // it so the same number is not reported twice; a frame per blocked attempt
  // would be a flood, and the peer learns nothing new from the second one.
  bool data_blocked_pending = false;
  bool data_blocked_reported = false;
  std::uint64_t data_blocked_at = 0;
  // Section 4.6: credit to return to the peer for streams it opened and this
  // endpoint has finished with.
  std::array<bool, 2> max_streams_pending = {};
  // Appendix A.8 of RFC 9002: a client considers the server's address
  // validated once it has seen an acknowledgement at the Handshake level.
  bool received_handshake_ack = false;
  // Section 6.6: forgery attempts, counted across every key for the life of
  // the connection.
  std::uint64_t packets_failed_authentication = 0;
  // How many packets have been authenticated and acted on, which is what
  // section 10.1 means by a packet received and processed.
  std::uint64_t packets_processed = 0;
  // Section 17.2.5.2: once an Initial has been processed from the server, a
  // Retry is too late to be genuine.
  bool received_server_initial = false;
  // Set when a read may have finished a stream, cleared by the sweep that
  // returns the credit.
  bool reap_wanted = false;
  // Section 9. Where packets are being sent, and the highest-numbered
  // non-probing packet that put them there -- reordering must not drag the
  // connection back to an address the peer has already left.
  std::vector<std::uint8_t> peer_address;
  std::unique_ptr<qlog_writer_t> qlog;
  // Recovery events discovered while a packet_received event is still open.
  // They describe the packet but are not part of it, so they wait for it to
  // close rather than nesting inside its frame list.
  std::vector<std::uint64_t> qlog_pending_lost;
  bool qlog_metrics_pending = false;
  bool peer_address_known = false;
  std::uint64_t highest_non_probing = 0;
  bool have_non_probing = false;
  std::uint64_t migrations = 0;
  // Section 10.3: the token the peer named in its transport parameters, which
  // covers the connection ID it chose during the handshake. Tokens for the
  // rest arrive in NEW_CONNECTION_ID frames and live in remote_ids.
  std::optional<stateless_reset_token_t> peer_initial_reset_token;
  // Section 13.4: what this endpoint believes its datagrams are being marked
  // with. Marking happens on the socket, which the connection does not own, so
  // this is what its owner was asked to apply -- and what each sent packet
  // records, so the peer's counts can be checked against something real.
  // Cleared when validation fails, which is how the owner learns to stop.
  ecn_codepoint_t ecn_sending = ecn_codepoint_t::not_ect;
  // Section 8.1.3. A server issues one after the handshake; a client keeps
  // whatever arrives for the application to store.
  std::vector<std::uint8_t> new_token_pending;

  // RFC 9221. Unreliable by construction: a queued datagram that does not fit
  // the packet being built waits, and one that is lost is simply gone.
  std::deque<std::vector<std::uint8_t>> datagrams_pending;
  std::deque<std::vector<std::uint8_t>> datagrams_received;
  bool new_token_issued = false;
  std::vector<std::uint8_t> received_new_token;
  bool reset_by_peer = false;
  // Section 6.2: the server answered with a version list this build cannot
  // satisfy, so the attempt is over.
  bool version_negotiation_failed = false;
  // Section 5.1. Two pools: what this endpoint issued and must keep accepting,
  // and what the peer issued and this endpoint may spend.
  local_connection_ids_t local_ids;
  remote_connection_ids_t remote_ids;
  // Issued but not yet put in a NEW_CONNECTION_ID frame, or put in one that
  // was lost -- section 13.3 has them retransmitted with the same sequence
  // number, so the entry is what is queued rather than the intent to issue.
  std::vector<connection_id_entry_t> new_ids_pending;
  // Section 8.2. The validator drives probes this endpoint sends; the queue
  // holds echoes it owes.
  path_validator_t path;
  path_response_queue_t path_responses;
  // Section 10.1. Zero disables it.
  std::chrono::nanoseconds idle_timeout{};
  tick_t last_activity;
  bool activity_seen = false;
  // Section 10.1 also restarts the timer on sending an ack-eliciting packet,
  // but only the first since the last one received -- otherwise an endpoint
  // that keeps talking to a peer that has vanished would never time out.
  bool idle_since_last_receive = false;
};
} // namespace detail

namespace
{
using detail::connection_impl_t;

std::expected<void, error_t> install_keys(packet_space_t &space, const tls_secret_t &secret, bool read, std::uint32_t version)
{
  auto material = derive_key_material(secret.suite, secret.secret, version);
  if (!material.has_value())
  {
    return std::unexpected(material.error());
  }
  auto &protection = read ? space.read : space.write;
  auto &header = read ? space.read_header : space.write_header;
  if (auto r = protection.init(secret.suite, secret.secret, version); !r.has_value())
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
  auto secrets = derive_initial_secrets(destination.bytes(), impl.version);
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
  if (auto r = install_keys(space, write, false, impl.version); !r.has_value())
  {
    return r;
  }
  return install_keys(space, read, true, impl.version);
}

void discard_space(connection_impl_t &impl, encryption_level_t level)
{
  auto &space = impl.spaces[space_index(level)];
  space.discarded = true;
  space.have_read = false;
  space.have_write = false;
  space.probes_pending = 0;
  space.crypto_send = crypto_sender_t{};
  impl.recovery.discard_space(to_pn_space(level));
}

// Section 9.3: a non-probing packet from an address this connection is not
// already talking to means the peer has moved. The response is fixed by the
// spec and every part of it matters:
//
//   Send to the new address, but treat it as unproven. Until path validation
//   succeeds the anti-amplification limit of section 8 applies again, because
//   a spoofed source address would otherwise turn this endpoint into a
//   reflector aimed at the address in the packet (section 9.3.1).
//
//   Reset congestion control and the RTT estimate (section 9.4). What was
//   learned describes the old path, and using it on a new one is how a
//   migration becomes a burst of loss.
//
//   Move to a connection ID the old path never carried (section 9.5), or an
//   observer of both paths can trivially link them.
// Section 8.1.3: a token meant for a later connection is worth little if it
// expires in the seconds a Retry token lives for.
inline constexpr std::chrono::nanoseconds new_token_lifetime = std::chrono::hours(24);

// Section 8.2.4: three times the larger of the current PTO and a PTO computed
// from the initial RTT, because a new path may be slower than the one in use
// and the estimate in hand describes the old one.
[[nodiscard]] std::chrono::nanoseconds path_abandon_timeout(const connection_impl_t &impl)
{
  const auto current = impl.recovery.rtt().pto_base() + impl.config.max_ack_delay;
  const auto fresh = initial_rtt + (std::max)(initial_rtt / 2 * 4, loss_granularity) + impl.config.max_ack_delay;
  return (std::max)(current, fresh) * 3;
}

// Section 10.3.1: only tokens for connection IDs this endpoint has actually
// used, and never retired ones. A token for an id that was never sent to
// cannot have provoked a reset, and checking it would widen the window in
// which a guessed token lands.
[[nodiscard]] bool matches_peer_reset_token(const connection_impl_t &impl, std::span<const std::uint8_t> trailing)
{
  if (impl.peer_initial_reset_token.has_value() && tokens_equal(trailing, *impl.peer_initial_reset_token))
  {
    return true;
  }
  for (const auto &entry : impl.remote_ids.active())
  {
    if (entry.used && entry.has_token && tokens_equal(trailing, entry.token))
    {
      return true;
    }
  }
  return false;
}

// Section 14.4: an MTU probe is the largest thing on the path by construction,
// so losing one says something about the size and not about congestion. Loss
// recovery has already taken it out of the bytes in flight; what must not
// happen is the window shrinking for it.
void report_loss(connection_impl_t &impl, pn_space_t space, const std::vector<sent_packet_t> &lost, tick_t now)
{
  std::vector<sent_packet_t> congested;
  bool probe_lost = false;
  for (const auto &packet : lost)
  {
    // Numbered per space, so only the space a probe was sent in can recognise
    // one.
    if (space == pn_space_t::application && impl.mtu.is_probe(packet.packet_number))
    {
      probe_lost = true;
      impl.mtu.on_lost(packet.packet_number);
      continue;
    }
    congested.push_back(packet);
  }
  impl.congestion.on_packets_lost(probe_lost ? congested : lost, now, impl.recovery.rtt(), impl.config.max_ack_delay, impl.recovery.first_rtt_sample());
}

// Whether anything waiting to go out is the kind of thing pacing exists to
// spread. Section 7.7 of RFC 9002 asks that packets carrying only ACK frames
// not be paced -- delaying an acknowledgement slows the peer's recovery, and an
// ACK is not what bursts a path.
[[nodiscard]] bool wants_paced_content(const connection_impl_t &impl)
{
  if (impl.close_frame_pending)
  {
    return false;
  }
  for (const auto &space : impl.spaces)
  {
    if (space.discarded)
    {
      continue;
    }
    if (space.crypto_send.has_pending() || space.probes_pending > 0)
    {
      return true;
    }
  }
  return !impl.streams.sendable().empty();
}

// Section 4.1 and 4.6. A sender that stops because the peer's limit ran out
// says so; a sender that stops because it has nothing to send says nothing.
// The distinction matters because the peer is the only one who can unblock the
// first case, and it cannot know it needs to unless it is told.
void note_blocked(connection_impl_t &impl, stream_t &stream)
{
  if (stream.send.blocked_by_stream_limit())
  {
    const auto limit = stream.send.stream_limit();
    if (!stream.data_blocked_reported || stream.data_blocked_at != limit)
    {
      stream.data_blocked_pending = true;
      stream.data_blocked_reported = true;
      stream.data_blocked_at = limit;
      impl.streams.mark_sendable(stream);
    }
    return;
  }
  if (stream.send.blocked_by_connection_limit(impl.streams.connection_send_window()))
  {
    const auto limit = impl.streams.peer_max_data();
    if (!impl.data_blocked_reported || impl.data_blocked_at != limit)
    {
      impl.data_blocked_pending = true;
      impl.data_blocked_reported = true;
      impl.data_blocked_at = limit;
    }
  }
}

// The qlog frame_type names are the RFC's frame names in lower case, which is
// what qvis matches on.
[[nodiscard]] std::string_view qlog_frame_name(frame_kind_t kind)
{
  switch (kind)
  {
  case frame_kind_t::padding:
    return "padding";
  case frame_kind_t::ping:
    return "ping";
  case frame_kind_t::ack:
    return "ack";
  case frame_kind_t::reset_stream:
    return "reset_stream";
  case frame_kind_t::stop_sending:
    return "stop_sending";
  case frame_kind_t::crypto:
    return "crypto";
  case frame_kind_t::new_token:
    return "new_token";
  case frame_kind_t::stream:
    return "stream";
  case frame_kind_t::max_data:
    return "max_data";
  case frame_kind_t::max_stream_data:
    return "max_stream_data";
  case frame_kind_t::max_streams:
    return "max_streams";
  case frame_kind_t::data_blocked:
    return "data_blocked";
  case frame_kind_t::stream_data_blocked:
    return "stream_data_blocked";
  case frame_kind_t::streams_blocked:
    return "streams_blocked";
  case frame_kind_t::new_connection_id:
    return "new_connection_id";
  case frame_kind_t::retire_connection_id:
    return "retire_connection_id";
  case frame_kind_t::path_challenge:
    return "path_challenge";
  case frame_kind_t::path_response:
    return "path_response";
  case frame_kind_t::connection_close:
    return "connection_close";
  case frame_kind_t::handshake_done:
    return "handshake_done";
  }
  return "unknown";
}

[[nodiscard]] std::string_view qlog_packet_name(packet_kind_t kind)
{
  switch (kind)
  {
  case packet_kind_t::initial:
    return "initial";
  case packet_kind_t::zero_rtt:
    return "0RTT";
  case packet_kind_t::handshake:
    return "handshake";
  case packet_kind_t::retry:
    return "retry";
  case packet_kind_t::one_rtt:
    return "1RTT";
  case packet_kind_t::version_negotiation:
    return "version_negotiation";
  }
  return "unknown";
}

[[nodiscard]] packet_kind_t packet_kind_for_level(encryption_level_t level)
{
  switch (level)
  {
  case encryption_level_t::initial:
    return packet_kind_t::initial;
  case encryption_level_t::handshake:
    return packet_kind_t::handshake;
  default:
    return packet_kind_t::one_rtt;
  }
}

// What the recovery and congestion state looked like after whatever just
// happened. qvis draws its congestion graph from these, so one goes out after
// every acknowledgement and every loss rather than on a timer.
void qlog_lost(connection_impl_t &impl, const std::vector<sent_packet_t> &lost, tick_t now)
{
  if (impl.qlog == nullptr)
  {
    return;
  }
  for (const auto &packet : lost)
  {
    impl.qlog->begin_event(now, "recovery", "packet_lost");
    impl.qlog->begin_object("header");
    impl.qlog->field_number("packet_number", packet.packet_number);
    impl.qlog->field_number("packet_size", packet.size);
    impl.qlog->end_object();
    impl.qlog->end_event();
  }
}

// Whatever the frames of a just-closed packet turned up.
void qlog_drain_pending(connection_impl_t &impl, tick_t now)
{
  if (impl.qlog == nullptr)
  {
    return;
  }
  for (const auto number : impl.qlog_pending_lost)
  {
    impl.qlog->begin_event(now, "recovery", "packet_lost");
    impl.qlog->begin_object("header");
    impl.qlog->field_number("packet_number", number);
    impl.qlog->end_object();
    impl.qlog->end_event();
  }
  impl.qlog_pending_lost.clear();
}

void qlog_metrics(connection_impl_t &impl, tick_t now)
{
  if (impl.qlog == nullptr)
  {
    return;
  }
  impl.qlog->begin_event(now, "recovery", "metrics_updated");
  impl.qlog->field_number("cwnd", impl.congestion.window());
  impl.qlog->field_number("bytes_in_flight", impl.recovery.bytes_in_flight());
  const auto smoothed = std::chrono::duration_cast<std::chrono::microseconds>(impl.recovery.rtt().smoothed()).count();
  const auto latest = std::chrono::duration_cast<std::chrono::microseconds>(impl.recovery.rtt().latest()).count();
  if (smoothed > 0)
  {
    impl.qlog->field_number("smoothed_rtt", static_cast<std::uint64_t>(smoothed));
  }
  if (latest > 0)
  {
    impl.qlog->field_number("latest_rtt", static_cast<std::uint64_t>(latest));
  }
  impl.qlog->end_event();
}

void migrate_to(connection_impl_t &impl, std::span<const std::uint8_t> address, std::uint64_t packet_number, std::size_t datagram_size, tick_t now)
{
  impl.peer_address.assign(address.begin(), address.end());
  impl.highest_non_probing = packet_number;
  impl.have_non_probing = true;
  ++impl.migrations;

  // Section 8: the limit is per path, so what the old one earned does not
  // carry over. Only this datagram has arrived here so far.
  impl.address_validated = false;
  impl.bytes_received = datagram_size;
  impl.bytes_sent = 0;

  // Section 9.4.
  impl.congestion.reset();
  impl.recovery.reset_rtt();
  impl.pacer.reset();

  // Section 9.5. If the peer has supplied no spare, the connection keeps the
  // one it has: a linkable connection is better than an unusable one, and the
  // peer is the one that failed to supply the id.
  if (impl.remote_ids.has_unused() && impl.remote_ids.switch_to_unused())
  {
    if (const auto *chosen = impl.remote_ids.current(); chosen != nullptr)
    {
      impl.peer_connection_id = *chosen;
    }
  }

  // Section 9.3: validation of the new address starts now, and any attempt
  // against the old one is abandoned.
  impl.path.reset();
  impl.path.begin(now, path_abandon_timeout(impl));
}

// Section 10.1: floored at three times the current PTO, so a peer advertising
// a very small value cannot make the connection unusable before loss recovery
// has had a chance to work.
[[nodiscard]] std::optional<tick_t> idle_deadline(const connection_impl_t &impl)
{
  if (impl.idle_timeout == std::chrono::nanoseconds::zero() || !impl.activity_seen)
  {
    return std::nullopt;
  }
  const auto pto = impl.recovery.rtt().pto_base() + impl.config.max_ack_delay;
  const auto period = (std::max)(impl.idle_timeout, pto * 3);
  return impl.last_activity + period;
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
// Section 13.3: a lost NEW_CONNECTION_ID goes again carrying the same sequence
// number, so what is requeued is the entry rather than a fresh ID. If the peer
// retired it in the meantime there is nothing left to say.
void requeue_new_connection_id(connection_impl_t &impl, std::uint64_t sequence)
{
  const auto *entry = impl.local_ids.find(sequence);
  if (entry == nullptr)
  {
    return;
  }
  const auto queued = std::any_of(impl.new_ids_pending.begin(), impl.new_ids_pending.end(), [sequence](const connection_id_entry_t &pending) { return pending.sequence == sequence; });
  if (!queued)
  {
    impl.new_ids_pending.push_back(*entry);
  }
}

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
          impl.streams.mark_sendable(*stream);
        }
        break;
      }
      case frame_kind_t::reset_stream:
        if (auto *stream = impl.streams.find(frame.stream_id); stream != nullptr)
        {
          stream->reset_pending = true;
          impl.streams.mark_sendable(*stream);
        }
        break;
      case frame_kind_t::max_data:
        // Resend current, not retransmit: the limit that applies now, which
        // is why nothing here replays the bytes that went out.
        impl.max_data_pending = true;
        break;
      case frame_kind_t::max_streams:
        impl.max_streams_pending[0] = true;
        impl.max_streams_pending[1] = true;
        break;
      case frame_kind_t::data_blocked:
        // Section 13.3: sent again if lost, but only while still blocked and
        // carrying the limit in force then. Forgetting that it was reported is
        // enough -- the next attempt to send re-derives both.
        impl.data_blocked_reported = false;
        break;

      case frame_kind_t::stream_data_blocked:
        if (auto *stream = impl.streams.find(frame.stream_id); stream != nullptr)
        {
          stream->data_blocked_reported = false;
        }
        break;

      case frame_kind_t::streams_blocked:
        impl.streams.forget_streams_blocked();
        break;

      case frame_kind_t::new_token:
        // Section 13.3: retransmitted if lost. The same token goes again --
        // section 8.1.3 asks that every NEW_TOKEN be unique except when
        // repairing exactly this.
        impl.new_token_issued = false;
        break;

      case frame_kind_t::new_connection_id:
        requeue_new_connection_id(impl, frame.sequence);
        break;

      case frame_kind_t::retire_connection_id:
        impl.remote_ids.requeue_retire(frame.sequence);
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
  // Section 10.2 permits answering a CONNECTION_CLOSE with one, and declining
  // to costs the peer real time: it stays in the closing state until three
  // probe timeouts have passed, and a probe timeout carries max_ack_delay --
  // 25ms by default, so most of a tenth of a second on every connection that
  // ends. One frame ends it at once. The guard above runs this once per
  // connection and the send path clears the flag after a single packet, so
  // there is no exchange of closes.
  impl.state = connection_state_t::closing;
  impl.close_frame_pending = true;
}

// Hands TLS whatever the CRYPTO streams have made contiguous, runs the
// handshake as far as it will go, and installs whatever secrets came out.
std::expected<void, error_t> drive_tls(connection_impl_t &impl)
{
  if (impl.close_reason.has_value())
  {
    return {};
  }

  bool provided = false;
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
    provided = true;
  }

  // Once the handshake is done, TLS has nothing to say unless CRYPTO data
  // arrives -- a session ticket, say. Asking it anyway put an SSL call on the
  // path of every packet for the life of the connection.
  if (impl.handshake_complete && !provided)
  {
    return {};
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
    if (auto r = install_keys(space, secret, false, impl.version); !r.has_value())
    {
      return r;
    }
  }
  for (auto &secret : impl.tls.take_read_secrets())
  {
    auto &space = impl.spaces[space_index(secret.level)];
    if (auto r = install_keys(space, secret, true, impl.version); !r.has_value())
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
    impl.mtu.limit(static_cast<std::size_t>(parameters->max_udp_payload_size));
    impl.streams.apply_peer_parameters(*parameters);
    // Section 10.3: the token covering the connection ID the peer chose during
    // the handshake. Only a server sends one.
    impl.peer_initial_reset_token = parameters->stateless_reset_token;

    // Section 10.1: the effective timeout is the smaller of the two advertised
    // values, or the sole one when only a single endpoint asks for a limit.
    // Zero on both sides means the connection never expires on its own.
    const auto local = impl.config.transport_parameters.max_idle_timeout;
    const auto remote = parameters->max_idle_timeout;
    std::uint64_t effective = 0;
    if (local != 0 && remote != 0)
    {
      effective = (std::min)(local, remote);
    }
    else
    {
      effective = local != 0 ? local : remote;
    }
    impl.idle_timeout = std::chrono::milliseconds(static_cast<std::int64_t>(effective));

    // Section 4.9.2: a server confirms the handshake by completing it. A
    // client waits for HANDSHAKE_DONE.
    if (impl.config.role == tls_role_t::server)
    {
      impl.handshake_confirmed = true;
      impl.mtu.enable();
    }
    if (impl.state == connection_state_t::handshaking)
    {
      impl.state = connection_state_t::connected;
    }
  }
  return {};
}

// Section 8.1.3: hand the client something it can present next time, so the
// next connection to this server need not spend a round trip on a Retry. Only
// once the handshake is confirmed -- before that the address has not been
// proven and the token would be a gift to whoever spoofed it.
std::expected<void, error_t> issue_new_token(connection_impl_t &impl, tick_t now)
{
  if (impl.config.role != tls_role_t::server || impl.new_token_issued || !impl.handshake_confirmed)
  {
    return {};
  }
  if (impl.config.retry_key == nullptr || impl.config.peer_host_address.empty())
  {
    return {};
  }
  auto token = impl.config.retry_key->issue_new_token(impl.config.peer_host_address, now);
  if (!token.has_value())
  {
    return std::unexpected(token.error());
  }
  impl.new_token_pending = std::move(*token);
  impl.new_token_issued = true;
  return {};
}

// Section 5.1.1: keep the peer stocked up to the limit it advertised, so that
// it can rotate on migration without first having to ask. Issuing beyond the
// limit is forbidden, and issuing nothing quietly prevents the peer from
// migrating at all.
std::expected<void, error_t> replenish_connection_ids(connection_impl_t &impl)
{
  if (!impl.peer_parameters.has_value() || !impl.handshake_complete)
  {
    return {};
  }
  const auto limit = impl.peer_parameters->active_connection_id_limit;
  while (impl.local_ids.can_issue(limit))
  {
    std::array<std::uint8_t, max_connection_id_size> bytes = {};
    auto chosen = std::span<std::uint8_t>(bytes).first(impl.config.local_connection_id_length);
    if (auto r = crypto::random_bytes(chosen); !r.has_value())
    {
      return std::unexpected(r.error());
    }
    auto id = connection_id_t::from_bytes(chosen);
    if (!id.has_value())
    {
      return std::unexpected(error_t{.code = 1, .msg = "could not build a connection id"});
    }
    stateless_reset_token_t token = {};
    if (impl.config.stateless_reset_key != nullptr)
    {
      token = impl.config.stateless_reset_key->token_for(*id);
    }
    else if (auto r = crypto::random_bytes(token); !r.has_value())
    {
      return std::unexpected(r.error());
    }
    impl.new_ids_pending.push_back(impl.local_ids.add(*id, token));
  }
  return {};
}

[[nodiscard]] std::uint64_t cid_error_code(cid_error_t error)
{
  switch (error)
  {
  case cid_error_t::frame_encoding:
    return static_cast<std::uint64_t>(transport_error_code_t::frame_encoding_error);
  case cid_error_t::limit_exceeded:
    return static_cast<std::uint64_t>(transport_error_code_t::connection_id_limit_error);
  case cid_error_t::protocol_violation:
  case cid_error_t::none:
    break;
  }
  return transport_error_protocol_violation;
}

// Section 13.4.2.1. Everything reported is checked against what was actually
// sent before any of it is acted on, because acting on it means letting the
// peer influence this endpoint's sending rate.
void apply_ecn_feedback(connection_impl_t &impl, packet_space_t &space, const frame_t &frame, const ack_outcome_t &outcome, tick_t now)
{
  if (!space.ecn.enabled())
  {
    return;
  }

  ecn_ack_report_t report;
  report.advanced_largest_acked = outcome.advanced_largest_acked;
  if (frame.ecn.has_value())
  {
    report.reported = ecn_counts_totals_t{.ect0 = frame.ecn->ect0, .ect1 = frame.ecn->ect1, .ce = frame.ecn->ce};
  }

  bool have_latest = false;
  tick_t latest;
  for (const auto &acked : outcome.acknowledged)
  {
    if (acked.ecn == ecn_codepoint_t::ect0)
    {
      ++report.newly_acked_ect0;
    }
    else if (acked.ecn == ecn_codepoint_t::ect1)
    {
      ++report.newly_acked_ect1;
    }
    if (!have_latest || acked.time_sent > latest)
    {
      latest = acked.time_sent;
      have_latest = true;
    }
  }

  const auto result = space.ecn.on_ack(report);
  if (result.outcome == ecn_outcome_t::failed)
  {
    // Section 13.4.2: the path does not carry the field honestly. Marking
    // stops for the whole connection -- the codepoint is a property of the
    // path, not of one packet number space.
    impl.ecn_sending = ecn_codepoint_t::not_ect;
    for (auto &other : impl.spaces)
    {
      other.ecn.disable();
    }
    return;
  }
  if (result.ce_increase > 0 && have_latest)
  {
    impl.congestion.on_congestion_event(latest, now);
  }
}

// Everything a received packet's frames can do to the connection.
std::expected<bool, error_t> process_frames(connection_impl_t &impl, std::span<const std::uint8_t> payload, packet_kind_t kind, tick_t now, const connection_id_t &destination, bool &non_probing)
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
    if (impl.qlog != nullptr)
    {
      impl.qlog->begin_object();
      impl.qlog->field_string("frame_type", qlog_frame_name(frame.kind));
      if (frame.kind == frame_kind_t::stream)
      {
        impl.qlog->field_number("stream_id", frame.stream_id);
        impl.qlog->field_number("offset", frame.offset);
        impl.qlog->field_number("length", frame.data.size());
        impl.qlog->field_bool("fin", frame.fin);
      }
      else if (frame.kind == frame_kind_t::crypto)
      {
        impl.qlog->field_number("offset", frame.offset);
        impl.qlog->field_number("length", frame.data.size());
      }
      else if (frame.kind == frame_kind_t::ack)
      {
        impl.qlog->field_number("ack_delay", frame.ack_delay);
        // The ranges are what a reader of a trace is actually after -- which
        // packets this acknowledges, not just the highest. qvis draws its
        // acknowledgement coverage straight from these.
        impl.qlog->begin_array("acked_ranges");
        std::uint64_t largest = frame.largest_acknowledged;
        bool ranges_valid = frame.largest_acknowledged >= frame.first_ack_range;
        if (ranges_valid)
        {
          std::uint64_t smallest = frame.largest_acknowledged - frame.first_ack_range;
          impl.qlog->begin_array();
          impl.qlog->field_element(smallest);
          impl.qlog->field_element(largest);
          impl.qlog->end_array();
          ack_range_reader_t ranges(frame.ack_ranges);
          for (std::uint64_t seen = 0; seen < frame.ack_range_count; ++seen)
          {
            auto range = ranges.next();
            if (!range.has_value() || smallest < range->gap + 2)
            {
              break;
            }
            largest = smallest - range->gap - 2;
            if (largest < range->length)
            {
              break;
            }
            smallest = largest - range->length;
            impl.qlog->begin_array();
            impl.qlog->field_element(smallest);
            impl.qlog->field_element(largest);
            impl.qlog->end_array();
          }
        }
        impl.qlog->end_array();
        if (frame.ecn.has_value())
        {
          impl.qlog->field_number("ect0", frame.ecn->ect0);
          impl.qlog->field_number("ect1", frame.ecn->ect1);
          impl.qlog->field_number("ce", frame.ecn->ce);
        }
      }
      else if (frame.kind == frame_kind_t::max_data || frame.kind == frame_kind_t::max_stream_data || frame.kind == frame_kind_t::max_streams)
      {
        impl.qlog->field_number("maximum", frame.maximum);
      }
      else if (frame.kind == frame_kind_t::new_connection_id || frame.kind == frame_kind_t::retire_connection_id)
      {
        impl.qlog->field_number("sequence_number", frame.sequence_number);
        impl.qlog->field_number("retire_prior_to", frame.retire_prior_to);
      }
      else if (frame.kind == frame_kind_t::connection_close)
      {
        impl.qlog->field_number("error_code", frame.error_code);
        impl.qlog->field_string("error_space", frame.application_error ? "application" : "transport");
      }
      impl.qlog->end_object();
    }
    const auto properties = frame_properties(frame.type);
    if (properties.has_value() && properties->ack_eliciting)
    {
      ack_eliciting = true;
    }
    // Section 9.1: PATH_CHALLENGE, PATH_RESPONSE, NEW_CONNECTION_ID and
    // PADDING are probing frames, and a packet of nothing else says nothing
    // about where the peer has moved to -- it is exactly what an attacker
    // replaying a captured packet from another address would produce.
    if (properties.has_value() && !properties->probing)
    {
      non_probing = true;
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
        if (space == pn_space_t::application)
        {
          impl.mtu.on_acked(acked.packet_number);
        }
        if (acked.in_flight)
        {
          impl.delivery.on_packet_acked(acked.delivery, acked.time_sent, acked.size, now, acked.packet_number);
        }
        impl.congestion.on_packet_acked(acked, now, impl.recovery.rtt().smoothed());
        if (space == pn_space_t::application)
        {
          impl.congestion.on_ack_round_progress(acked.packet_number);
        }
        for (const auto &sent : acked.frames)
        {
          if (sent.kind != frame_kind_t::stream)
          {
            continue;
          }
          if (auto *stream = impl.streams.find(sent.stream_id); stream != nullptr && stream->has_send)
          {
            stream->send.on_range_acknowledged(sent.offset, sent.length);
            // Section 4.6: this is the other way a stream finishes, and the
            // one nothing else notices. A stream the application has already
            // read to the end is still live until the peer acknowledges what
            // was sent back on it, and that acknowledgement arrives here --
            // long after the last read. Without a scan from this side, credit
            // for such a stream is never returned, and a peer that has spent
            // its allowance waits for a MAX_STREAMS that waits on a request it
            // cannot send.
            if (stream->send.state() == send_state_t::data_received)
            {
              impl.reap_wanted = true;
            }
          }
        }
      }
      // One rate for the whole batch, not one per packet: the interval a rate
      // is measured over spans the acknowledgements, so it is only complete
      // once they have all been counted. A sample shorter than a round trip is
      // refused inside -- it would be measuring a burst arriving, not a path.
      if (auto rate = impl.delivery.take(impl.recovery.rtt().minimum()); rate.has_value())
      {
        impl.last_delivery_rate = rate->rate;
      }

      // Section 13.4.2.1, and section 7 of RFC 9002: a rise in the
      // congestion-experienced count is a router saying it is close to
      // dropping, and is treated exactly as loss would be -- except that
      // nothing was actually lost, which is the whole point of ECN. It is only
      // believed once the counts have been checked against the codepoints this
      // endpoint applied to the packets being acknowledged.
      apply_ecn_feedback(impl, impl.spaces[static_cast<std::size_t>(space)], frame, outcome, now);

      if (impl.qlog != nullptr)
      {
        for (const auto &packet : outcome.lost)
        {
          impl.qlog_pending_lost.push_back(packet.packet_number);
        }
        impl.qlog_metrics_pending = true;
      }
      if (space == pn_space_t::application && outcome.rtt_updated)
      {
        impl.congestion.on_rtt_sample(impl.recovery.rtt().latest());
      }
      report_loss(impl, space, outcome.lost, now);
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

    case frame_kind_t::datagram:
      // RFC 9221 section 3: receiving one when none was offered, or one larger
      // than was offered, is a protocol violation rather than something to
      // ignore -- the peer is using an extension this endpoint did not agree to.
      if (impl.config.transport_parameters.max_datagram_frame_size == 0)
      {
        begin_close(impl, transport_error_protocol_violation, "DATAGRAM frame without max_datagram_frame_size", false, false);
        return ack_eliciting;
      }
      if (frame.data.size() > impl.config.transport_parameters.max_datagram_frame_size)
      {
        begin_close(impl, transport_error_protocol_violation, "DATAGRAM frame larger than max_datagram_frame_size", false, false);
        return ack_eliciting;
      }
      impl.datagrams_received.emplace_back(frame.data.begin(), frame.data.end());
      return ack_eliciting;

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
      impl.mtu.enable();
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

    case frame_kind_t::new_connection_id:
    {
      // Section 19.15: an endpoint whose peer sends zero-length destination
      // connection IDs has nothing it could vary, so offering one means the
      // peer has lost track of the connection rather than that it is being
      // helpful.
      if (impl.peer_connection_id.empty())
      {
        begin_close(impl, transport_error_protocol_violation, "NEW_CONNECTION_ID against a zero-length connection id", false, false);
        return ack_eliciting;
      }
      const auto error = impl.remote_ids.on_new(frame.sequence_number, frame.retire_prior_to, frame.connection_id, frame.stateless_reset_token, impl.config.transport_parameters.active_connection_id_limit);
      if (error != cid_error_t::none)
      {
        begin_close(impl, cid_error_code(error), "NEW_CONNECTION_ID rejected", false, false);
        return ack_eliciting;
      }
      // A Retire Prior To can have retired the id this endpoint is addressing
      // packets to, in which case remote_ids has already moved to a live one.
      if (const auto *chosen = impl.remote_ids.current(); chosen != nullptr && !(*chosen == impl.peer_connection_id))
      {
        impl.peer_connection_id = *chosen;
      }
      break;
    }

    case frame_kind_t::retire_connection_id:
    {
      const auto error = impl.local_ids.on_retire(frame.sequence_number, destination);
      if (error != cid_error_t::none)
      {
        begin_close(impl, cid_error_code(error), "RETIRE_CONNECTION_ID rejected", false, false);
        return ack_eliciting;
      }
      break;
    }

    case frame_kind_t::path_challenge:
      // Section 8.2.2: the echo is owed unconditionally, and is the only
      // evidence the peer will get that this endpoint holds this address.
      impl.path_responses.push(frame.path_data);
      break;

    case frame_kind_t::path_response:
      // Section 8.2.3. An echo that matches nothing outstanding is ignored
      // rather than treated as an error -- a stale response and a forged one
      // are indistinguishable, and neither is worth ending a connection over.
      if (impl.path.on_response(frame.path_data))
      {
        // Section 8.2: a matching response is what address validation means.
        // The anti-amplification limit that the migration imposed lifts here,
        // or the connection spends the rest of its life rationed to three
        // times whatever arrives.
        impl.address_validated = true;
      }
      break;

    case frame_kind_t::new_token:
      // Section 19.7: only a server sends these, and a zero-length one is a
      // frame encoding error rather than an empty gift.
      if (impl.config.role != tls_role_t::client)
      {
        begin_close(impl, transport_error_protocol_violation, "NEW_TOKEN from a client", false, false);
        return ack_eliciting;
      }
      if (frame.data.empty())
      {
        begin_close(impl, static_cast<std::uint64_t>(transport_error_code_t::frame_encoding_error), "empty NEW_TOKEN", false, false);
        return ack_eliciting;
      }
      impl.received_new_token.assign(frame.data.begin(), frame.data.end());
      break;

    default:
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
  // Section 6.6: the count is per key, so it starts again with the new one.
  space.packets_encrypted = 0;
  return derive_next_generation(space);
}

// Section 6.2. A Version Negotiation packet carries no authentication of any
// kind -- it cannot, since the whole point is that the two sides share no
// version and therefore no keys. Every condition below exists to keep that
// from being a way for anyone on the path to end a connection:
//
//   Only a client acts on one, and only before anything else has been
//   processed. Once a single genuine packet has arrived, the server has
//   clearly agreed on a version and a later claim otherwise is a forgery.
//
//   A list naming the version already in use is discarded outright, which is
//   what an attacker replaying a captured packet would produce.
//
// Having passed those, a client that speaks only version 1 has nowhere to go,
// so the attempt is abandoned rather than retried.
std::expected<void, error_t> receive_version_negotiation(connection_impl_t &impl, const packet_header_t &header)
{
  if (impl.config.role != tls_role_t::client)
  {
    return {};
  }
  if (impl.packets_processed > 0 || impl.retry_handled || impl.version_negotiation_failed)
  {
    return {};
  }
  if (!(header.destination_id == impl.local_connection_id))
  {
    return {};
  }

  const auto versions = header.supported_versions;
  for (std::size_t offset = 0; offset + 4 <= versions.size(); offset += 4)
  {
    const std::uint32_t version = (static_cast<std::uint32_t>(versions[offset]) << 24) | (static_cast<std::uint32_t>(versions[offset + 1]) << 16) | (static_cast<std::uint32_t>(versions[offset + 2]) << 8) | static_cast<std::uint32_t>(versions[offset + 3]);
    if (version == quic_version_1)
    {
      return {};
    }
  }

  impl.version_negotiation_failed = true;
  impl.state = connection_state_t::closed;
  impl.close_frame_pending = false;
  if (!impl.close_reason.has_value())
  {
    impl.close_reason = connection_close_t{.error_code = transport_error_no_error, .application = false, .reason = "no shared QUIC version", .from_peer = true};
  }
  return {};
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
  if (impl.retry_handled || impl.handshake_complete || impl.received_server_initial)
  {
    // Section 17.2.5.2: at most one per connection attempt, and none once an
    // Initial has been processed from the server -- by then the handshake has
    // started and a Retry could only be an injected attempt to restart it
    // against a different server.
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
  // Section 5.1.1 gives a Retry's connection ID no sequence number, but the
  // pool has to name whatever is actually being sent to, or a later
  // RETIRE_CONNECTION_ID would refer to an ID this endpoint never adopted.
  impl.remote_ids.install_initial(header.source_id);
  if (auto r = install_initial_keys(impl, header.source_id); !r.has_value())
  {
    return r;
  }

  // The same handshake message goes again, from the start, under the new
  // keys. Packet numbers are deliberately not reset -- section 17.2.5.3.
  auto &initial = impl.spaces[space_index(encryption_level_t::initial)];
  initial.crypto_send.sent_offset = 0;
  initial.crypto_send.retransmit.clear();
  initial.probes_pending = 0;
  impl.recovery.discard_space(pn_space_t::initial);
  return {};
}

// What a datagram turned out to say about where the peer is, gathered across
// its coalesced packets and acted on once the whole datagram has been read.
struct migration_signal_t
{
  bool saw_non_probing = false;
  std::uint64_t highest_non_probing = 0;
};

std::expected<void, error_t> receive_packet(connection_impl_t &impl, const packet_header_t &header, std::span<std::uint8_t> packet, tick_t now, migration_signal_t &signal, ecn_codepoint_t ecn)
{
  if (header.kind == packet_kind_t::retry)
  {
    return receive_retry(impl, header);
  }
  if (header.kind == packet_kind_t::version_negotiation)
  {
    return receive_version_negotiation(impl, header);
  }
  if (header.kind == packet_kind_t::zero_rtt)
  {
    // 0-RTT is refused by construction, and dropped rather than an error.
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
    impl.version = header.version;
    if (auto r = install_initial_keys(impl, header.destination_id); !r.has_value())
    {
      return r;
    }
  }

  if (header.kind == packet_kind_t::initial && impl.config.role == tls_role_t::server && impl.config.retry_key != nullptr && !impl.retry_validated)
  {
    // Section 8.1.2: nothing has proved this address is real. Answering with a
    // Retry costs the client a round trip and costs anyone spoofing a source
    // address the ability to make this server work for them. No handshake
    // state is built until the token comes back.
    const auto answer_with_retry = [&]() -> std::expected<void, error_t>
    {
      if (impl.retry_issued)
      {
        return {};
      }
      impl.retry_pending = true;
      impl.retry_issued = true;
      // Section 5.2 of RFC 9001: Initial keys follow the Destination
      // Connection ID, and after a Retry that is the one this server just told
      // the client to use. Keeping the keys derived from the ID the client
      // invented would leave the server unable to read its own Retry being
      // answered. Packet numbers are deliberately left alone: section 17.2.5.3
      // forbids the client resetting them, so the acknowledgement state stays
      // valid across the Retry.
      return install_initial_keys(impl, impl.local_connection_id);
    };

    if (header.token.empty())
    {
      if (auto r = answer_with_retry(); !r.has_value())
      {
        return r;
      }
      return {};
    }

    // Section 8.1.3: a token from a NEW_TOKEN frame is bound to the address
    // without its port and carries no connection ID, so it is tried against
    // that and only accepted as what it says it is. Accepting it as a Retry
    // token would skip the original-connection-ID check that ties a Retry to
    // the exchange it belongs to.
    bool reused_earlier_token = false;
    if (!impl.retry_issued && !impl.config.peer_host_address.empty())
    {
      auto reused = impl.config.retry_key->validate(header.token, impl.config.peer_host_address, now, new_token_lifetime);
      reused_earlier_token = reused.has_value() && reused->kind == address_token_kind_t::new_token;
    }

    if (reused_earlier_token)
    {
      // The address is proven, so no Retry is spent. Nothing else follows from
      // it: unlike a Retry token this one names no connection ID, so the
      // handshake carries no original_destination_connection_id to echo.
      impl.address_validated = true;
      impl.retry_validated = true;
    }
    else
    {
      auto validated = impl.config.retry_key->validate(header.token, impl.config.peer_address, now);
      if (!validated.has_value() || validated->kind != address_token_kind_t::retry)
      {
        // Forged, expired, presented from a different address, or the wrong
        // kind of token entirely. Section 8.1.3 permits discarding the packet,
        // but a client that cached a token which has since expired would then
        // never get in at all -- so it is answered with a Retry, which is both
        // the proof this server wanted and a fresh token for the client.
        if (auto r = answer_with_retry(); !r.has_value())
        {
          return r;
        }
        return {};
      }
      const auto original = std::optional<connection_id_t>(validated->original_destination_id);
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
      return {};
    }
    // Section 6.6: every packet that fails to authenticate is a forgery
    // attempt, and enough of them across the connection means the key can no
    // longer be trusted to reject the next one.
    ++impl.packets_failed_authentication;
    if (impl.packets_failed_authentication > aead_integrity_limit(space.read.suite().aead))
    {
      begin_close(impl, transport_error_aead_limit_reached, "AEAD integrity limit reached", false, false);
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

  if (header.kind == packet_kind_t::initial && impl.config.role == tls_role_t::client)
  {
    impl.received_server_initial = true;
  }

  if (is_long_header(header.kind) && !impl.peer_connection_id_confirmed)
  {
    // Section 7.2: a client takes the server's chosen connection ID from the
    // first packet it can actually read, not the first one that arrives.
    impl.peer_connection_id = header.source_id;
    impl.peer_connection_id_confirmed = true;
    impl.remote_ids.install_initial(impl.peer_connection_id);
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

  bool non_probing = false;
  if (impl.qlog != nullptr)
  {
    impl.qlog->begin_event(now, "transport", "packet_received");
    impl.qlog->field_string("packet_type", qlog_packet_name(header.kind));
    impl.qlog->begin_object("header");
    impl.qlog->field_number("packet_number", opened->packet_number);
    impl.qlog->field_number("packet_size", opened->payload.size());
    impl.qlog->end_object();
    impl.qlog->begin_array("frames");
  }
  auto ack_eliciting = process_frames(impl, opened->payload, header.kind, now, header.destination_id, non_probing);
  if (impl.qlog != nullptr)
  {
    impl.qlog->end_array();
    impl.qlog->end_event();
    qlog_drain_pending(impl, now);
    if (impl.qlog_metrics_pending)
    {
      impl.qlog_metrics_pending = false;
      qlog_metrics(impl, now);
    }
  }
  if (!ack_eliciting.has_value())
  {
    return std::unexpected(ack_eliciting.error());
  }
  // Only 1-RTT packets. Section 9 describes migration for an established
  // connection, and the "highest-numbered" comparison of section 9.3 is only
  // meaningful within one packet number space -- each space numbers from zero,
  // so a Handshake packet number and a 1-RTT packet number are not on the same
  // scale and comparing them decides nothing.
  if (non_probing && header.kind == packet_kind_t::one_rtt && (!signal.saw_non_probing || opened->packet_number > signal.highest_non_probing))
  {
    signal.saw_non_probing = true;
    signal.highest_non_probing = opened->packet_number;
  }
  // Section 13.4.2: only a packet that authenticated is counted. Counting
  // what a forged datagram claimed would let anyone make this endpoint report
  // congestion the network never signalled.
  space.acks.on_packet_received(opened->packet_number, *ack_eliciting, now, ecn);
  ++impl.packets_processed;

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

  const std::size_t head = serialize_retry(out, impl.version, impl.peer_connection_id, impl.local_connection_id, *token);
  if (head == 0 || out.size() < head + retry_integrity_tag_size)
  {
    return std::size_t{0};
  }
  auto tag = retry_integrity_tag(impl.original_destination_id.bytes(), out.first(head), impl.version);
  if (!tag.has_value())
  {
    return std::unexpected(tag.error());
  }
  std::copy(tag->begin(), tag->end(), out.begin() + static_cast<std::ptrdiff_t>(head));
  return head + retry_integrity_tag_size;
}

// Returning stream credit means walking every open stream, so it happens once
// before a packet is built rather than once per read. The credit is only ever
// spent by the MAX_STREAMS frame below, so nothing observes it any sooner, and
// an application draining a thousand streams no longer pays for a thousand
// passes over all of them.
void reap_and_grant(connection_impl_t &impl)
{
  if (!impl.reap_wanted)
  {
    return;
  }
  impl.reap_wanted = false;
  const auto remote_initiator = impl.config.role == tls_role_t::client ? stream_initiator_t::server : stream_initiator_t::client;
  const auto reaped = impl.streams.reap_finished(remote_initiator);
  if (reaped.bidirectional > 0)
  {
    impl.streams.grant_streams(stream_direction_t::bidirectional, reaped.bidirectional);
    impl.max_streams_pending[0] = true;
  }
  if (reaped.unidirectional > 0)
  {
    impl.streams.grant_streams(stream_direction_t::unidirectional, reaped.unidirectional);
    impl.max_streams_pending[1] = true;
  }
}

// Writes the frames for one space into a packet, returning its size or zero
// when there was nothing worth sending.
// expand_to is how large this packet must be for the datagram to reach the
// 1200 bytes section 14.1 requires, or zero when the datagram is already there.
// force_expand says the datagram owes that size for a reason decided before
// this packet -- an Initial ahead of it -- as opposed to one this packet
// discovers for itself by writing a PATH_CHALLENGE or PATH_RESPONSE.
std::expected<std::size_t, error_t> build_packet(connection_impl_t &impl, encryption_level_t level, std::span<std::uint8_t> out, tick_t now, bool allow_empty_ack, std::size_t expand_to = 0, bool force_expand = false, bool mtu_probe = false)
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
  // Section 13.2.1 draws a line the previous reading of this missed. An
  // endpoint MUST acknowledge ack-eliciting Initial and Handshake packets
  // *immediately*, but 1-RTT packets only within its advertised
  // max_ack_delay -- and section 13.2.2 says two ack-eliciting packets is
  // when to stop waiting.
  //
  // Building a packet merely because an acknowledgement was pending collapsed
  // that distinction: every arriving 1-RTT packet drew one back. Twice the
  // packets, and worse, it clocked the sender at one packet per
  // acknowledgement, so a window that could carry a burst never sent one.
  //
  // So the two questions are separated. Whether an acknowledgement is worth a
  // packet of its own, and whether to include one in a packet already being
  // built for other reasons -- which is always worth it, since the frame is
  // small and the packet is going anyway.
  const bool handshake_space = level == encryption_level_t::initial || level == encryption_level_t::handshake;
  const bool ack_owed = space.acks.has_received() && space.acks.ack_pending();
  const bool must_ack = ack_owed && (handshake_space || space.acks.should_send_ack(now, impl.config.max_ack_delay));
  const bool want_ack = allow_empty_ack ? ack_owed : must_ack;
  const bool want_handshake_done = level == encryption_level_t::application && impl.config.role == tls_role_t::server && impl.handshake_complete && !impl.handshake_done_sent;
  const bool want_close = impl.close_frame_pending && space.have_write;
  const bool want_probe = space.probes_pending > 0 || mtu_probe;

  bool want_path = false;
  if (level == encryption_level_t::application && !want_close)
  {
    // Section 8.2.2 forbids delaying a PATH_RESPONSE, so an owed echo is by
    // itself a reason to send.
    want_path = !impl.path_responses.empty() || impl.path.challenge_due(now, impl.recovery.rtt().pto_base() + impl.config.max_ack_delay);
    want_path = want_path || !impl.new_ids_pending.empty() || !impl.remote_ids.pending_retires().empty() || !impl.new_token_pending.empty() || !impl.datagrams_pending.empty();
  }

  bool want_streams = false;
  if (level == encryption_level_t::application && !want_close)
  {
    reap_and_grant(impl);
    want_streams = impl.max_data_pending || impl.max_streams_pending[0] || impl.max_streams_pending[1] || impl.data_blocked_pending || impl.streams.streams_blocked_owed() || impl.streams.has_sendable();
  }

  // Only must_ack justifies a packet by itself; want_ack merely rides along.
  if (!mtu_probe && !want_crypto && !must_ack && !want_handshake_done && !want_close && !want_probe && !want_streams && !want_path)
  {
    return std::size_t{0};
  }

  packet_builder_t builder(out);
  const std::uint64_t packet_number = space.next_packet_number;
  bool begun = false;
  if (*kind == packet_kind_t::one_rtt)
  {
    // RFC 9287 section 3: only after the peer's parameters have been read, and
    // unpredictably rather than always -- a bit that is reliably zero ossifies
    // as readily as one that is reliably one.
    bool clear_quic_bit = false;
    if (impl.peer_parameters.has_value() && impl.peer_parameters->grease_quic_bit)
    {
      std::array<std::uint8_t, 1> coin = {};
      clear_quic_bit = crypto::random_bytes(coin).has_value() && (coin[0] & 1) != 0;
    }
    begun = builder.begin_short(impl.peer_connection_id, space.key_phase, false, packet_number, std::nullopt, clear_quic_bit);
  }
  else
  {
    // Section 8.1.3: a Retry replaces whatever token was being carried, so the
    // Retry token wins when there is one.
    const auto carried = !impl.retry_token.empty() ? std::span<const std::uint8_t>(impl.retry_token) : std::span<const std::uint8_t>(impl.config.address_token);
    const auto token = *kind == packet_kind_t::initial ? carried : std::span<const std::uint8_t>{};
    begun = builder.begin_long(*kind, impl.version, impl.peer_connection_id, impl.local_connection_id, token, packet_number, std::nullopt);
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
      if (ack->ecn.has_value())
      {
        // Section 13.4.2: reporting the totals is what lets the peer react to a
        // router's congestion signal instead of waiting for something to be
        // lost. Only sent once something marked has actually arrived -- an
        // all-zero report would tell a peer its marks were being erased.
        frame.ecn = ecn_counts_t{.ect0 = ack->ecn->ect0, .ect1 = ack->ecn->ect1, .ce = ack->ecn->ce};
      }
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
      std::size_t amount = static_cast<std::size_t>((std::min<std::uint64_t>)(span_end - crypto_offset, available));
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

  if (level == encryption_level_t::application && !want_close)
  {
    // Section 5.1.2: retiring is also a request for a replacement, so these go
    // out before the new IDs below and the peer sees the reason with the need.
    auto retires = impl.remote_ids.pending_retires();
    for (const auto sequence : retires)
    {
      frame_t frame;
      frame.kind = frame_kind_t::retire_connection_id;
      frame.sequence_number = sequence;
      if (!frames.write(frame))
      {
        break;
      }
      impl.remote_ids.clear_pending_retire(sequence);
      record.push_back(sent_frame_t{.kind = frame_kind_t::retire_connection_id, .sequence = sequence});
    }

    if (!impl.new_token_pending.empty())
    {
      frame_t frame;
      frame.kind = frame_kind_t::new_token;
      frame.data = impl.new_token_pending;
      if (frames.write(frame))
      {
        record.push_back(sent_frame_t{.kind = frame_kind_t::new_token});
        impl.new_token_pending.clear();
      }
    }

    while (!impl.datagrams_pending.empty())
    {
      frame_t frame;
      frame.kind = frame_kind_t::datagram;
      frame.data = impl.datagrams_pending.front();
      if (!frames.write(frame))
      {
        // No room in this packet. It keeps its place at the head of the queue
        // rather than being dropped: the application asked for it to go, and
        // the next packet is a better answer than never.
        break;
      }
      record.push_back(sent_frame_t{.kind = frame_kind_t::datagram});
      impl.datagrams_pending.pop_front();
    }

    for (auto it = impl.new_ids_pending.begin(); it != impl.new_ids_pending.end();)
    {
      frame_t frame;
      frame.kind = frame_kind_t::new_connection_id;
      frame.sequence_number = it->sequence;
      // Nothing is being forced out of use: this endpoint issues spares, it
      // does not revoke. Section 19.15 lets Retire Prior To stay at zero.
      frame.retire_prior_to = 0;
      frame.connection_id = it->id;
      frame.stateless_reset_token = it->token;
      if (!frames.write(frame))
      {
        break;
      }
      record.push_back(sent_frame_t{.kind = frame_kind_t::new_connection_id, .sequence = it->sequence});
      it = impl.new_ids_pending.erase(it);
    }
  }

  bool wrote_path_frame = false;
  if (want_path)
  {
    // Section 8.2.2: one echo per challenge, sent once. The loss policy for
    // PATH_RESPONSE is discard, so an entry leaves the queue when it reaches
    // the wire and is not repaired if that packet is lost -- the peer asks
    // again instead.
    while (!impl.path_responses.empty())
    {
      frame_t frame;
      frame.kind = frame_kind_t::path_response;
      frame.path_data = impl.path_responses.front();
      if (!frames.write(frame))
      {
        break;
      }
      impl.path_responses.pop();
      record.push_back(sent_frame_t{.kind = frame_kind_t::path_response});
      wrote_path_frame = true;
    }

    // Section 8.2.1: at most one challenge per packet, and fresh data every
    // time, so that a response can only have come from something this
    // endpoint actually sent.
    if (impl.path.challenge_due(now, impl.recovery.rtt().pto_base() + impl.config.max_ack_delay))
    {
      auto data = impl.path.issue(now, path_abandon_timeout(impl));
      if (!data.has_value())
      {
        return std::unexpected(data.error());
      }
      frame_t frame;
      frame.kind = frame_kind_t::path_challenge;
      frame.path_data = *data;
      if (frames.write(frame))
      {
        record.push_back(sent_frame_t{.kind = frame_kind_t::path_challenge});
        wrote_path_frame = true;
      }
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

    for (const auto direction : {stream_direction_t::bidirectional, stream_direction_t::unidirectional})
    {
      std::uint64_t limit = 0;
      if (!impl.streams.take_streams_blocked(direction, limit))
      {
        continue;
      }
      frame_t frame;
      frame.kind = frame_kind_t::streams_blocked;
      frame.bidirectional = direction == stream_direction_t::bidirectional;
      frame.maximum = limit;
      if (frames.write(frame))
      {
        record.push_back(sent_frame_t{.kind = frame_kind_t::streams_blocked});
      }
      else
      {
        impl.streams.requeue_streams_blocked(direction);
      }
    }

    for (std::size_t i = 0; i < impl.max_streams_pending.size(); ++i)
    {
      if (!impl.max_streams_pending[i])
      {
        continue;
      }
      const auto direction = i == 0 ? stream_direction_t::bidirectional : stream_direction_t::unidirectional;
      frame_t frame;
      frame.kind = frame_kind_t::max_streams;
      frame.bidirectional = direction == stream_direction_t::bidirectional;
      frame.maximum = impl.streams.local_max_streams(direction);
      if (frames.write(frame))
      {
        impl.max_streams_pending[i] = false;
        record.push_back(sent_frame_t{.kind = frame_kind_t::max_streams});
      }
    }

    // The smallest of the frames below: a type byte, a stream id, and one
    // more field. Below this the rest of the list can only be walked for
    // nothing, and with many busy streams that is nearly all of it. Anything
    // skipped this way is still pending, so it goes in the next packet.
    constexpr std::size_t minimum_stream_frame_bytes = 5;

    std::size_t served = 0;
    const auto &sendable = impl.streams.sendable();
    for (; served < sendable.size(); ++served)
    {
      if (frames.remaining() < minimum_stream_frame_bytes)
      {
        break;
      }
      auto *found = impl.streams.find(sendable[served]);
      if (found == nullptr)
      {
        continue;
      }
      auto &stream = *found;

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

      if (stream.data_blocked_pending && stream.has_send)
      {
        frame_t frame;
        frame.kind = frame_kind_t::stream_data_blocked;
        frame.stream_id = stream.id;
        frame.maximum = stream.send.stream_limit();
        if (frames.write(frame))
        {
          stream.data_blocked_pending = false;
          record.push_back(sent_frame_t{.kind = frame_kind_t::stream_data_blocked, .stream_id = stream.id});
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
        // Whether a limit is in the way is settled here, at the one moment
        // this stream is being looked at anyway, and the frame goes into this
        // packet rather than waiting for one the caller has no reason to ask
        // for. Walking every stream up front to find this out was correct and
        // cost a pass over the whole connection per packet.
        note_blocked(impl, stream);
        if (stream.data_blocked_pending && stream.has_send)
        {
          frame_t blocked;
          blocked.kind = frame_kind_t::stream_data_blocked;
          blocked.stream_id = stream.id;
          blocked.maximum = stream.send.stream_limit();
          if (frames.write(blocked))
          {
            stream.data_blocked_pending = false;
            record.push_back(sent_frame_t{.kind = frame_kind_t::stream_data_blocked, .stream_id = stream.id});
          }
        }
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
    impl.streams.rotate_sendable(served);

    if (impl.data_blocked_pending)
    {
      frame_t frame;
      frame.kind = frame_kind_t::data_blocked;
      // Section 13.3: the limit as it stands now, not the one that was in
      // force when the block was noticed. Written after the walk, because the
      // walk is what discovers that the connection window is the obstacle.
      frame.maximum = impl.streams.peer_max_data();
      if (frames.write(frame))
      {
        impl.data_blocked_pending = false;
        record.push_back(sent_frame_t{.kind = frame_kind_t::data_blocked});
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

  // Sections 8.2.1, 8.2.2 and 14.1 all want a datagram of at least 1200 bytes,
  // and the padding that gets it there has to go *inside* the packet whenever
  // this one is a 1-RTT packet. A short header carries no length field, so its
  // payload is defined to run to the end of the datagram: bytes appended after
  // the AEAD sealed it are read back as ciphertext, and the peer discards the
  // packet instead of unpadding it. Only a long header, whose Length bounds the
  // packet, can be followed by filler.
  if (expand_to > 0 && (force_expand || mtu_probe || wrote_path_frame))
  {
    const std::size_t overhead = builder.header_length() + default_aead_expansion;
    if (expand_to > overhead)
    {
      const std::size_t target = (std::min)(expand_to - overhead, capacity);
      if (target > frames.written())
      {
        frame_t padding;
        padding.kind = frame_kind_t::padding;
        padding.padding_count = target - frames.written();
        (void)frames.write(padding);
      }
    }
  }

  auto layout = builder.finish(frames.written());
  if (!layout.has_value())
  {
    return std::size_t{0};
  }
  // Section 6.6: a key that has protected too many packets must not protect
  // another. The connection ends rather than continuing on a key that is no
  // longer doing its job.
  if (space.packets_encrypted >= aead_confidentiality_limit(space.write.suite().aead))
  {
    begin_close(impl, transport_error_aead_limit_reached, "AEAD confidentiality limit reached", false, false);
    return std::size_t{0};
  }

  auto length = protect_packet(space.write, space.write_header, out, *layout, packet_number);
  if (!length.has_value())
  {
    return std::unexpected(length.error());
  }
  ++space.packets_encrypted;

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
  if (space.probes_pending > 0)
  {
    --space.probes_pending;
  }
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
  sent.ecn = impl.ecn_sending;
  if (impl.qlog != nullptr)
  {
    impl.qlog->begin_event(now, "transport", "packet_sent");
    impl.qlog->field_string("packet_type", qlog_packet_name(packet_kind_for_level(level)));
    impl.qlog->begin_object("header");
    impl.qlog->field_number("packet_number", packet_number);
    impl.qlog->field_number("packet_size", *length);
    impl.qlog->end_object();
    impl.qlog->begin_array("frames");
    if (wrote_ack)
    {
      // The ACK is not in the record: section 2 of RFC 9002 leaves it
      // untracked for loss, so nothing retransmits it. It is still the frame
      // the reader of a trace most wants to see.
      impl.qlog->begin_object();
      impl.qlog->field_string("frame_type", "ack");
      impl.qlog->end_object();
    }
    for (const auto &logged : record)
    {
      impl.qlog->begin_object();
      impl.qlog->field_string("frame_type", qlog_frame_name(logged.kind));
      if (logged.kind == frame_kind_t::stream || logged.kind == frame_kind_t::crypto)
      {
        if (logged.kind == frame_kind_t::stream)
        {
          impl.qlog->field_number("stream_id", logged.stream_id);
        }
        impl.qlog->field_number("offset", logged.offset);
        impl.qlog->field_number("length", logged.length);
      }
      else if (logged.kind == frame_kind_t::new_connection_id || logged.kind == frame_kind_t::retire_connection_id)
      {
        impl.qlog->field_number("sequence_number", logged.sequence);
      }
      impl.qlog->end_object();
    }
    impl.qlog->end_array();
    impl.qlog->end_event();
  }
  if (sent.in_flight && to_pn_space(level) == pn_space_t::application)
  {
    impl.congestion.on_packet_sent(packet_number);
  }
  sent.frames = std::move(record);
  if (sent.in_flight)
  {
    sent.delivery = impl.delivery.on_packet_sent(now, impl.recovery.bytes_in_flight() == 0, packet_number);
  }
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
  if (config.datagram_size_ceiling < config.max_datagram_size)
  {
    return std::unexpected(error_t{.code = 1, .msg = "datagram size ceiling is below the size to start from"});
  }

  std::optional<connection_id_t> local = config.local_connection_id_override;
  if (!local.has_value())
  {
    std::array<std::uint8_t, max_connection_id_size> scratch = {};
    auto local_bytes = std::span<std::uint8_t>(scratch).first(config.local_connection_id_length);
    if (!local_bytes.empty())
    {
      if (auto r = crypto::random_bytes(local_bytes); !r.has_value())
      {
        return std::unexpected(r.error());
      }
    }
    local = connection_id_t::from_bytes(local_bytes);
  }
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
  // Section 5.1.1: the ID carried in the long header during the handshake is
  // sequence 0. Its stateless reset token goes out in the transport
  // parameters rather than a frame, which is why it is minted here.
  const auto initial_token = config.stateless_reset_key != nullptr ? config.stateless_reset_key->token_for(impl->local_connection_id) : stateless_reset_token_t{};
  if (config.stateless_reset_key == nullptr)
  {
    stateless_reset_token_t random_token = {};
    if (auto r = crypto::random_bytes(random_token); !r.has_value())
    {
      return std::unexpected(r.error());
    }
    impl->local_ids.install_initial(impl->local_connection_id, random_token);
  }
  else
  {
    impl->local_ids.install_initial(impl->local_connection_id, initial_token);
  }
  impl->ecn_sending = config.ecn;
  impl->mtu.configure(config.max_datagram_size, config.datagram_size_ceiling);

  // Section 10.3: only a server may advertise this. A client's transport
  // parameters are not confidentiality protected, so publishing a token there
  // would hand anyone watching the handshake the means to kill the connection.
  if (config.role == tls_role_t::server && !impl->local_connection_id.empty())
  {
    impl->config.transport_parameters.stateless_reset_token = impl->local_ids.active().front().token;
  }

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
    impl->version = impl->config.version;
    impl->original_destination_id = *destination;
    impl->peer_connection_id = *destination;
    // Not a peer-issued ID yet -- the client invented it. Section 7.2 replaces
    // it with the server's choice, and only that one carries sequence 0.
    impl->remote_ids.install_initial(*destination);
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
  return receive(datagram, now, {}, ecn_codepoint_t::not_ect);
}

std::expected<void, error_t> connection_t::receive(std::span<std::uint8_t> datagram, tick_t now, std::span<const std::uint8_t> peer_address)
{
  return receive(datagram, now, peer_address, ecn_codepoint_t::not_ect);
}

std::expected<void, error_t> connection_t::receive(std::span<std::uint8_t> datagram, tick_t now, std::span<const std::uint8_t> peer_address, ecn_codepoint_t ecn)
{
  auto &impl = *_impl;
  if (impl.state == connection_state_t::closed || datagram.empty())
  {
    return {};
  }
  impl.bytes_received += datagram.size();
  // Section 10.1: the timer restarts on a packet received and processed. The
  // datagram has not been authenticated yet, so this is refined below to only
  // count when something in it actually opened.
  const std::uint64_t processed_before = impl.packets_processed;
  const std::size_t datagram_size = datagram.size();
  migration_signal_t signal;

  // Section 10.3.1 compares the trailing bytes of the datagram *as received*,
  // and this is the only chance to read them: decryption works in place, and a
  // packet that fails to authenticate may already have had plaintext written
  // over it by the time the AEAD rejects the tag. Looking afterwards finds
  // whatever the failed open left behind rather than what the peer sent.
  stateless_reset_token_t arriving_token = {};
  bool arriving_token_present = false;
  if (const auto trailing = trailing_token(datagram); !trailing.empty())
  {
    std::copy(trailing.begin(), trailing.end(), arriving_token.begin());
    arriving_token_present = true;
  }

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
        // Section 5.1.1: the client's handshake connection ID is its sequence 0.
        // Section 7.3 authenticates it later through the transport parameter.
        impl.remote_ids.install_initial(*source);
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

  // Having offered grease_quic_bit, this endpoint has to honour the promise.
  packet_reader_t reader(datagram, impl.local_connection_id.size(), impl.config.transport_parameters.grease_quic_bit);
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
    if (auto r = receive_packet(impl, header, datagram.subspan(offset, header.packet.size()), now, signal, ecn); !r.has_value())
    {
      return r;
    }
    if (impl.state == connection_state_t::closed)
    {
      break;
    }
  }

  if (impl.packets_processed != processed_before)
  {
    impl.last_activity = now;
    impl.activity_seen = true;
    impl.idle_since_last_receive = false;
  }

  // Section 10.3.1: the check is mandatory exactly when nothing in the
  // datagram could be processed, which is what a reset looks like -- it is
  // random bytes under a connection ID this endpoint no longer recognises.
  // Skipping it when a packet did decrypt is permitted and saves the compare
  // on every ordinary datagram.
  if (impl.packets_processed == processed_before && impl.state != connection_state_t::closed)
  {
    if (arriving_token_present && matches_peer_reset_token(impl, arriving_token))
    {
      // Section 10.3.1: enter the draining period and send nothing further.
      // There is nobody left to receive a CONNECTION_CLOSE, which is the whole
      // reason the peer had to resort to this.
      impl.reset_by_peer = true;
      impl.state = connection_state_t::closed;
      impl.close_frame_pending = false;
      if (!impl.close_reason.has_value())
      {
        impl.close_reason = connection_close_t{.error_code = transport_error_no_error, .application = false, .reason = "stateless reset", .from_peer = true};
      }
      return {};
    }
  }

  // Section 9.3. Only now, with the whole datagram read and its packets
  // authenticated, is there anything worth believing about where the peer is.
  if (!peer_address.empty() && signal.saw_non_probing && impl.packets_processed != processed_before)
  {
    const bool same = impl.peer_address_known && impl.peer_address.size() == peer_address.size() && std::equal(impl.peer_address.begin(), impl.peer_address.end(), peer_address.begin());
    if (!impl.peer_address_known)
    {
      impl.peer_address.assign(peer_address.begin(), peer_address.end());
      impl.peer_address_known = true;
      impl.have_non_probing = true;
      impl.highest_non_probing = signal.highest_non_probing;
    }
    else if (same)
    {
      if (!impl.have_non_probing || signal.highest_non_probing > impl.highest_non_probing)
      {
        impl.have_non_probing = true;
        impl.highest_non_probing = signal.highest_non_probing;
      }
    }
    else if (!impl.have_non_probing || signal.highest_non_probing > impl.highest_non_probing)
    {
      // Section 9.3: only the highest-numbered non-probing packet moves the
      // connection, so a packet that took the long way round cannot pull it
      // back to an address the peer has already left.
      migrate_to(impl, peer_address, signal.highest_non_probing, datagram_size, now);
    }
  }
  return {};
}

std::expected<std::size_t, error_t> connection_t::poll_send(std::span<std::uint8_t> out, tick_t now)
{
  auto &impl = *_impl;
  // Section 8.2.4: an attempt that has run out of time is abandoned before
  // anything else decides what to send.
  impl.path.on_timeout(now);
  if (auto r = replenish_connection_ids(impl); !r.has_value())
  {
    return std::unexpected(r.error());
  }
  if (auto r = issue_new_token(impl, now); !r.has_value())
  {
    return std::unexpected(r.error());
  }
  if (auto deadline = idle_deadline(impl); deadline.has_value() && now >= *deadline)
  {
    // Section 10.1: silently closed and the state discarded. No
    // CONNECTION_CLOSE goes out -- there is nobody there to read it, which is
    // the whole reason the timer fired.
    impl.state = connection_state_t::closed;
    impl.close_frame_pending = false;
    return std::size_t{0};
  }
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
      qlog_lost(impl, expiry.lost, now);
      report_loss(impl, *expiry.loss_space, expiry.lost, now);
      repair_lost(impl, *expiry.loss_space, expiry.lost);
      qlog_metrics(impl, now);
    }
    impl.mtu.on_timeout();
    if (expiry.probe_space.has_value())
    {
      for (auto level : ordered_levels)
      {
        if (to_pn_space(level) != *expiry.probe_space)
        {
          continue;
        }
        auto &space = impl.spaces[space_index(level)];
        space.probes_pending = probes_per_timeout;
        // Section 6.2.4: a probe should carry data. During a handshake a bare
        // PING would elicit an acknowledgement while telling the peer nothing
        // it is waiting for, so anything still outstanding goes again.
        impl.recovery.for_each_unacknowledged_frame(*expiry.probe_space,
                                                    [&space](const sent_frame_t &frame)
                                                    {
                                                      if (frame.kind == frame_kind_t::crypto)
                                                      {
                                                        queue_crypto_retransmit(space, frame.offset, frame.length);
                                                      }
                                                    });
      }
    }
  }

  // Section 7.5: a probe is never blocked by the controller, and neither is a
  // CONNECTION_CLOSE -- both have to get out for the connection to make any
  // progress at all. Everything else waits for the window.
  bool probing = impl.close_frame_pending;
  for (auto level : ordered_levels)
  {
    probing = probing || impl.spaces[space_index(level)].probes_pending > 0;
  }
  if (!probing && impl.recovery.bytes_in_flight() >= impl.congestion.window())
  {
    return std::size_t{0};
  }

  // Section 7.7 of RFC 9002: the window says how much may be outstanding, the
  // pacer says how fast it may leave. A probe and a CONNECTION_CLOSE are
  // exempt for the same reason they are exempt from the window -- both exist
  // to get the connection unstuck.
  const bool paceable = impl.config.pacing && !probing && wants_paced_content(impl);
  if (paceable && !impl.pacer.ready(now, impl.congestion.window(), impl.recovery.rtt().smoothed(), impl.mtu.datagram_size()))
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

  // Section 14.3: a probe is a PING padded to the size being tested, in a
  // datagram of its own. It is the only packet allowed past the size already
  // validated, which is what makes it safe -- if the path refuses it, nothing
  // that mattered was in it. It rides the ordinary path from here so that the
  // accounting at the end of this function applies to it like any other
  // datagram.
  impl.mtu.expire(now);
  auto &probe_space = impl.spaces[space_index(encryption_level_t::application)];
  // A probe measures the path rather than using it, so it waits for room the
  // data was not going to use: RFC 8899 section 3 asks that probing not come at
  // the expense of what the connection is actually for. Without this a small or
  // loss-reduced window spends itself on probes instead of on the data waiting
  // behind them.
  // ...and it waits for a path that is not already in trouble. RFC 8899
  // section 5.3: probing while recovering both competes with the retransmission
  // the connection actually needs and answers the wrong question, because a
  // probe lost to congestion says nothing about the size.
  const bool probe_has_room = impl.mtu.wants_probe() && !impl.congestion.recovering() && impl.recovery.bytes_in_flight() + impl.mtu.probe_size() <= impl.congestion.window();
  const bool sending_probe = probe_has_room && !probing && !impl.close_frame_pending && probe_space.write.initialized() && impl.mtu.probe_size() <= out.size();
  const std::uint64_t probe_packet_number = probe_space.next_packet_number;

  std::size_t budget = (std::min)(out.size(), sending_probe ? impl.mtu.probe_size() : impl.mtu.datagram_size());
  if (impl.config.role == tls_role_t::server && !impl.address_validated)
  {
    // Section 8.1: three times what has arrived, and not a byte more.
    const std::uint64_t allowance = impl.bytes_received * 3;
    if (impl.bytes_sent >= allowance)
    {
      return std::size_t{0};
    }
    const std::uint64_t remaining = allowance - impl.bytes_sent;
    budget = static_cast<std::size_t>((std::min<std::uint64_t>)(budget, remaining));
  }
  if (budget == 0)
  {
    return std::size_t{0};
  }

  std::size_t written = 0;
  bool carries_initial = false;
  bool carries_anything = false;
  bool last_packet_short_header = false;

  for (auto level : ordered_levels)
  {
    if (written >= budget)
    {
      break;
    }
    // How big this packet would have to be for the datagram to reach 1200.
    // The levels run in order, so by the time the 1-RTT packet is built,
    // carries_initial already says whether the datagram owes that size.
    const std::size_t expand_to = sending_probe && level == encryption_level_t::application ? budget : (written < minimum_initial_datagram ? minimum_initial_datagram - written : 0);
    // An ACK on its own is worth a datagram only if nothing else is going out
    // in it; otherwise it rides along.
    auto size = build_packet(impl, level, out.subspan(written, budget - written), now, true, expand_to, carries_initial, sending_probe && level == encryption_level_t::application);
    if (!size.has_value())
    {
      return std::unexpected(size.error());
    }
    if (*size > 0)
    {
      written += *size;
      carries_anything = true;
      last_packet_short_header = level == encryption_level_t::application;
      if (level == encryption_level_t::initial)
      {
        carries_initial = true;
      }
    }
  }

  if (!carries_anything)
  {
    // Past the window and past the pacer, and still nothing to put in a packet:
    // it is the application that is the limit here, not the path. A rate
    // measured across this says how fast the sender was fed, so it must not be
    // mistaken for how fast the path can carry.
    impl.delivery.set_app_limited();
    return std::size_t{0};
  }

  // Section 14.1: any datagram carrying an Initial is expanded to 1200 bytes.
  // Section 12.2 permits padding it with what looks like an invalid packet,
  // which is what trailing zeroes are, and a receiver discards the remainder
  // of a datagram once a packet fails to parse.
  //
  // This only works behind a long header. When the datagram ends in a 1-RTT
  // packet the filler had to go inside it, which build_packet has already
  // done -- appending here would land inside the AEAD's idea of the payload
  // and cost the peer the whole packet.
  //
  // Expansion yields to the anti-amplification limit either way, which the
  // budget already carries: padding past what a server may send would make
  // section 14.1 into the amplifier section 8.1 exists to prevent.
  if (carries_initial && !last_packet_short_header && written < minimum_initial_datagram && budget >= minimum_initial_datagram)
  {
    std::fill(out.begin() + static_cast<std::ptrdiff_t>(written), out.begin() + static_cast<std::ptrdiff_t>(minimum_initial_datagram), std::uint8_t{0});
    written = minimum_initial_datagram;
  }

  if (sending_probe)
  {
    impl.mtu.on_probe_sent(probe_packet_number, written, now, impl.recovery.rtt().smoothed());
  }
  impl.bytes_sent += written;
  if (paceable)
  {
    impl.pacer.on_sent(now, written, impl.congestion.window(), impl.recovery.rtt().smoothed());
  }
  if (!impl.idle_since_last_receive && impl.recovery.ack_eliciting_in_flight())
  {
    impl.last_activity = now;
    impl.activity_seen = true;
    impl.idle_since_last_receive = true;
  }
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
  // A probe the path swallowed has to be given up on, and that is a deadline
  // like any other.
  consider(_impl->mtu.probe_deadline());
  // Whichever comes first: an acknowledgement this endpoint owes, or the loss
  // detection timer telling it something of its own has gone missing.
  consider(_impl->recovery.loss_detection_timer(now, recovery_context(*_impl)));
  consider(idle_deadline(*_impl));
  consider(_impl->path.deadline());
  if (_impl->config.pacing && wants_paced_content(*_impl))
  {
    // Section 7.7: when the pacer is what is holding a packet, the caller has
    // to be told when to come back or the connection stalls until some other
    // timer happens to fire.
    consider(_impl->pacer.next_departure(now, _impl->congestion.window(), _impl->recovery.rtt().smoothed(), _impl->mtu.datagram_size()));
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

bool connection_t::address_validated_by_retry() const
{
  return _impl->validated_by_retry;
}

std::span<const std::uint8_t> connection_t::new_token() const
{
  return _impl->received_new_token;
}

ecn_codepoint_t connection_t::ecn_sending() const
{
  return _impl->ecn_sending;
}

bool connection_t::version_negotiation_failed() const
{
  return _impl->version_negotiation_failed;
}

bool connection_t::reset_by_peer() const
{
  return _impl->reset_by_peer;
}

std::uint64_t connection_t::migration_count() const
{
  return _impl->migrations;
}

const connection_id_t &connection_t::original_destination_id() const
{
  return _impl->original_destination_id;
}

std::vector<connection_id_t> connection_t::issued_connection_ids() const
{
  std::vector<connection_id_t> out;
  for (const auto &entry : _impl->local_ids.active())
  {
    out.push_back(entry.id);
  }
  return out;
}

std::size_t connection_t::peer_connection_id_count() const
{
  return _impl->remote_ids.active_count();
}

std::size_t connection_t::issued_connection_id_count() const
{
  return _impl->local_ids.active().size();
}

void connection_t::validate_path(tick_t now)
{
  _impl->path.begin(now, path_abandon_timeout(*_impl));
}

path_state_t connection_t::path_state() const
{
  return _impl->path.state();
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

std::size_t connection_t::datagram_size() const
{
  return _impl->mtu.datagram_size();
}

std::uint64_t connection_t::delivery_rate() const
{
  return _impl->last_delivery_rate;
}

std::uint64_t connection_t::peak_delivery_rate() const
{
  return _impl->delivery.peak();
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

void connection_t::set_qlog(std::unique_ptr<qlog_writer_t> writer)
{
  _impl->qlog = std::move(writer);
}

bool connection_t::tracing() const
{
  return _impl->qlog != nullptr;
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
  _impl->streams.mark_sendable(*stream);
  return data.size();
}

std::size_t connection_t::max_datagram_payload() const
{
  if (!_impl->peer_parameters.has_value())
  {
    return 0;
  }
  const auto offered = _impl->peer_parameters->max_datagram_frame_size;
  if (offered == 0)
  {
    return 0;
  }
  // The peer's limit counts the whole frame. The type byte and the length that
  // precedes the payload come out of it, and the length is a varint sized
  // against the payload -- eight bytes is the largest a varint gets, so
  // reserving that is right whatever the payload turns out to be.
  constexpr std::uint64_t frame_overhead = 1 + 8;
  if (offered <= frame_overhead)
  {
    return 0;
  }
  return static_cast<std::size_t>(offered - frame_overhead);
}

bool connection_t::write_datagram(std::span<const std::uint8_t> data)
{
  const auto room = max_datagram_payload();
  if (room == 0 || data.size() > room)
  {
    return false;
  }
  _impl->datagrams_pending.emplace_back(data.begin(), data.end());
  return true;
}

std::optional<std::vector<std::uint8_t>> connection_t::read_datagram()
{
  if (_impl->datagrams_received.empty())
  {
    return std::nullopt;
  }
  auto front = std::move(_impl->datagrams_received.front());
  _impl->datagrams_received.pop_front();
  return front;
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

  if (taken > 0)
  {
    // Section 4.1: the peer may send more once this endpoint has actually
    // taken the data. Updating on every byte would spend a frame per read, so
    // the window is extended once it has been half consumed -- early enough
    // that the peer never stalls waiting for credit.
    stream->consumed_since_update += taken;
    const auto stream_window = stream->receive.max_data() - stream->receive.read_offset();
    if (stream->consumed_since_update * 2 >= stream_window + stream->consumed_since_update)
    {
      // Section 18.2: which of the three limits applies depends on the stream
      // type. Growing every window by the bidirectional-local figure would
      // give the wrong amount of credit to two of the three kinds.
      const auto &parameters = _impl->config.transport_parameters;
      const auto local_initiator = _impl->config.role == tls_role_t::client ? stream_initiator_t::client : stream_initiator_t::server;
      const std::uint64_t increment = stream_direction(id) == stream_direction_t::unidirectional ? parameters.initial_max_stream_data_uni
                                      : stream_initiator(id) == local_initiator                  ? parameters.initial_max_stream_data_bidi_local
                                                                                                 : parameters.initial_max_stream_data_bidi_remote;
      stream->receive.set_max_data(stream->receive.read_offset() + increment);
      stream->consumed_since_update = 0;
      stream->pending_max_stream_data = true;
      _impl->streams.mark_sendable(*stream);
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

  // Returning stream credit is the same idea as returning data credit: once
  // the application is done with a stream the peer may open another in its
  // place. It is noted whether or not bytes moved, because what finishes a
  // stream is often the read that took its last byte earlier, or a reset with
  // nothing left to take. The scan itself waits until the next packet is
  // built.
  _impl->reap_wanted = true;
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
  std::sort(out.begin(), out.end());
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
  _impl->streams.mark_sendable(*stream);
}

void connection_t::stop_sending(std::uint64_t id, std::uint64_t error_code)
{
  auto *stream = _impl->streams.find(id);
  if (stream == nullptr || !stream->has_receive)
  {
    return;
  }
  stream->stop_sending_pending = error_code;
  _impl->streams.mark_sendable(*stream);
}
} // namespace vio::quic
