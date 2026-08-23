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

// A QUIC connection, sans I/O: datagrams in, datagrams out, time as a
// parameter. It owns no socket and reads no clock, so a whole handshake can be
// run in a test by handing two of these each other's bytes.
//
// The three packet number spaces (RFC 9000 section 12.3) are the organising
// idea. Initial, Handshake and Application each have their own packet numbers,
// their own keys, their own CRYPTO stream and their own ACK state, and nothing
// crosses between them -- an ACK in one says nothing about another, and a
// packet number of 0 appears three times in a normal connection.
//
// Ordering inside a datagram is load-bearing. A server coalesces its Initial
// and Handshake packets into one datagram precisely because processing the
// first yields the keys for the second, so TLS is driven after every packet
// rather than once per datagram.
//
// Loss is expected rather than fatal. Everything TLS produces is kept in a
// per-level send buffer until it is acknowledged, so a lost CRYPTO frame can be
// resent byte for byte; a PTO with no data to send emits a PING to draw one out.
// What each lost frame costs to repair is decided by the loss policy frozen in
// frame.h, not by replaying the bytes that went out.
//
// Still missing before this is a usable transport: congestion control, streams
// and flow control, connection migration, Retry, and key update.

#include "vio/error.h"
#include "vio/quic/connection_id.h"
#include "vio/quic/ecn.h"
#include "vio/quic/path.h"
#include "vio/quic/retry_token.h"
#include "vio/quic/stateless_reset.h"
#include "vio/quic/stream.h"
#include "vio/quic/tls.h"
#include "vio/quic/transport_parameters.h"
#include "vio/tick.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace vio::quic
{
enum class connection_state_t : std::uint8_t
{
  handshaking,
  // The handshake completed. For a server that is when TLS finished; for a
  // client, when the server confirmed it with HANDSHAKE_DONE.
  connected,
  // A CONNECTION_CLOSE is owed to the peer, or has been received.
  closing,
  closed,
};

// RFC 9000 section 20.1, the codes this layer raises.
inline constexpr std::uint64_t transport_error_no_error = 0x00;
inline constexpr std::uint64_t transport_error_internal = 0x01;
inline constexpr std::uint64_t transport_error_protocol_violation = 0x0a;
inline constexpr std::uint64_t transport_error_crypto_buffer_exceeded = 0x0d;
inline constexpr std::uint64_t transport_error_aead_limit_reached = 0x0f;

struct connection_close_t
{
  std::uint64_t error_code = 0;
  bool application = false;
  std::string reason;
  // True when the peer sent it rather than this endpoint.
  bool from_peer = false;
};

struct connection_config_t
{
  tls_role_t role = tls_role_t::server;
  transport_parameters_t transport_parameters;

  // The connection ID this endpoint should answer to, instead of inventing one.
  // A server that answered an earlier Initial with a Retry has already told the
  // client which id to use, and the handshake requires that exact value to come
  // back as retry_source_connection_id -- so a connection built for the second
  // Initial has to adopt it rather than choose afresh.
  std::optional<connection_id_t> local_connection_id_override;

  // Length of the connection IDs this endpoint issues. A short header carries
  // no length field, so this is the only way an incoming 1-RTT packet can be
  // parsed; it cannot change once a connection is running.
  std::size_t local_connection_id_length = 8;

  // The largest datagram this endpoint will send. Section 14 requires at least
  // 1200 for anything carrying an Initial.
  std::size_t max_datagram_size = 1200;

  std::chrono::nanoseconds max_ack_delay = std::chrono::milliseconds(25);

  // Section 13.4. The codepoint the owner of the socket is marking outgoing
  // datagrams with, so that a sent packet records what it went out as and the
  // peer's counts can be checked against it. Leave it at not_ect unless the
  // socket really is marking: claiming ECT(0) without it makes validation
  // fail against an honest peer.
  ecn_codepoint_t ecn = ecn_codepoint_t::not_ect;

  // RFC 9002 section 7.7. Spreads sending over the round trip instead of
  // handing the whole congestion window to the network at once. On by default,
  // because the section requires either this or an explicit burst limit and
  // this is the better of the two.
  //
  // Turn it off when something outside this connection already decides when
  // bytes leave -- a scheduler shared across connections, or a test driving a
  // simulated clock, where pacing measured against a round trip that is being
  // fast-forwarded means nothing.
  bool pacing = true;

  // Server only. When set, the first Initial from an unvalidated client is
  // answered with a Retry rather than a handshake, which costs the client a
  // round trip and costs anyone spoofing a source address the ability to make
  // this server do work on their behalf. The key must outlive the connection;
  // it is what makes an issued token unforgeable.
  const retry_token_key_t *retry_key = nullptr;
  // Section 10.3. Every connection ID this endpoint issues gets a reset token
  // derived from this key, so an endpoint that restarts and reloads the key
  // can still tell a peer to give up on a connection it no longer remembers.
  // Without it the tokens are random, which still works for the peer but is
  // lost the moment this endpoint forgets the connection -- which is exactly
  // when a reset would have been useful.
  const stateless_reset_key_t *stateless_reset_key = nullptr;

  // Opaque bytes identifying the peer's address. Authenticated into the token
  // so one issued to a given address cannot be replayed from another; leaving
  // it empty means the token is bound to nothing, which defeats the point.
  std::vector<std::uint8_t> peer_address;

  // Section 8.1.3: the same address without the port, which is what a
  // NEW_TOKEN token is bound to. The port almost never survives to the next
  // connection, so a token bound to it could never be redeemed.
  std::vector<std::uint8_t> peer_host_address;

  // Client only. A token from a NEW_TOKEN frame on an earlier connection to
  // this server, presented in every Initial so the server can skip the round
  // trip a Retry would cost. Section 8.1.3 forbids reusing a token from a
  // Retry here.
  std::vector<std::uint8_t> address_token;
};

namespace detail
{
struct connection_impl_t;
} // namespace detail

class VIO_EXPORT connection_t
{
public:
  ~connection_t();
  connection_t(connection_t &&) noexcept;
  connection_t &operator=(connection_t &&) noexcept;
  connection_t(const connection_t &) = delete;
  connection_t &operator=(const connection_t &) = delete;

  // server_name is the SNI for a client and is ignored for a server.
  [[nodiscard]] static std::expected<connection_t, error_t> create(const tls_context_t &context, const connection_config_t &config, std::string_view server_name = {});

  // One received UDP datagram. The buffer is modified in place -- header
  // protection is removed and payloads are decrypted where they lie -- so it
  // must be writable and must not be reused until this returns.
  //
  // A malformed or unauthenticated packet is not an error here: it is dropped,
  // because none of it was authenticated. The expected fails only when the
  // connection itself has to end.
  [[nodiscard]] std::expected<void, error_t> receive(std::span<std::uint8_t> datagram, tick_t now);

  // The same, told where the datagram came from. peer_address is opaque here:
  // the connection only ever compares it for equality, so any stable encoding
  // of the peer's address and port will do.
  //
  // Supplying it turns on connection migration (section 9). A non-probing
  // packet from an address the connection is not already using moves it there,
  // subject to path validation. Leaving it empty pins the connection to
  // wherever the caller is sending, which is what a client behind a fixed
  // socket wants.
  [[nodiscard]] std::expected<void, error_t> receive(std::span<std::uint8_t> datagram, tick_t now, std::span<const std::uint8_t> peer_address);

  // Section 8.1.3: a token the server issued for use on a later connection to
  // it, if one arrived. Empty otherwise. An application that keeps this and
  // puts it in connection_config_t::address_token next time saves the round
  // trip a Retry would cost.
  [[nodiscard]] std::span<const std::uint8_t> new_token() const;

  // Section 13.4.2. What this connection is marking with now: not_ect once
  // validation has failed and marking should stop. An endpoint sharing one
  // socket across connections watches this to know when to clear the socket.
  [[nodiscard]] ecn_codepoint_t ecn_sending() const;

  // Section 6.2: whether the attempt ended because the server offered no
  // version this build speaks.
  [[nodiscard]] bool version_negotiation_failed() const;

  // Section 10.3: whether this connection was ended by a stateless reset from
  // the peer, as opposed to a CONNECTION_CLOSE or a timeout.
  [[nodiscard]] bool reset_by_peer() const;

  // How many times the peer has been observed to move. Mostly of interest to
  // a test or a log.
  [[nodiscard]] std::uint64_t migration_count() const;

  // Fills out with the next datagram to send, returning its size. Zero means
  // there is nothing to send right now, which is the normal idle answer.
  [[nodiscard]] std::expected<std::size_t, error_t> poll_send(std::span<std::uint8_t> out, tick_t now);

  // When poll_send should next be called even if nothing else happens: an ACK
  // is owed, or loss detection has something to report. Nothing pending means
  // no deadline.
  [[nodiscard]] std::optional<tick_t> next_timeout(tick_t now) const;

  [[nodiscard]] connection_state_t state() const;
  [[nodiscard]] bool handshake_complete() const;
  [[nodiscard]] bool handshake_confirmed() const;

  [[nodiscard]] const connection_id_t &local_connection_id() const;
  [[nodiscard]] const connection_id_t &peer_connection_id() const;

  [[nodiscard]] std::optional<transport_parameters_t> peer_transport_parameters() const;
  [[nodiscard]] std::string_view selected_alpn() const;
  [[nodiscard]] std::optional<connection_close_t> close_reason() const;

  // Whether this connection went through a Retry, and so whether the peer
  // address was validated before any handshake work was done.
  [[nodiscard]] bool address_validated_by_retry() const;

  // Section 5.1: how many connection IDs each side currently has available.
  // A peer that has run out cannot migrate, since section 9.5 requires it to
  // move to an ID the old path never saw.
  // Section 7.2: the unpredictable value the client put in the Destination
  // Connection ID of its first Initial. A server has to keep answering to it
  // until the client has seen the server's own choice and switched, which is
  // why a demultiplexer routes on it as well as on the issued ids.
  [[nodiscard]] const connection_id_t &original_destination_id() const;

  // Every connection ID this endpoint currently accepts as a destination.
  // A demultiplexer needs all of them, not just the handshake one, or a peer
  // that rotates becomes unreachable.
  [[nodiscard]] std::vector<connection_id_t> issued_connection_ids() const;

  [[nodiscard]] std::size_t peer_connection_id_count() const;
  [[nodiscard]] std::size_t issued_connection_id_count() const;

  // Section 8.2: asks the peer to prove it can receive at the address it is
  // sending from, by echoing unpredictable data. Costs one round trip and
  // succeeds or is abandoned on a timer; the result is readable below rather
  // than reported, because the caller decides what an unusable path means.
  void validate_path(tick_t now);
  [[nodiscard]] path_state_t path_state() const;

  // Moves to the next set of 1-RTT keys. False when it is not permitted yet:
  // section 6.1 forbids it before the handshake is confirmed, and forbids a
  // second update until a packet from the current phase has been acknowledged,
  // because otherwise the peer could be left without the keys to read on.
  [[nodiscard]] bool initiate_key_update();
  [[nodiscard]] bool key_phase() const;

  // Queues a CONNECTION_CLOSE. The frame goes out on the next poll_send.
  void close(std::uint64_t error_code, std::string_view reason, bool application = false);

  // Opens the next stream this endpoint may initiate, or nothing when the
  // peer's limit is reached. Section 4.6 forbids exceeding it, so a caller is
  // told to wait rather than allowed to break the rule.
  [[nodiscard]] std::optional<std::uint64_t> open_stream(stream_direction_t direction);

  // Queues data. Returns how much was accepted, which is everything unless the
  // stream has already been finished or reset -- flow control bounds what goes
  // on the wire, not what may be queued.
  [[nodiscard]] std::size_t write_stream(std::uint64_t id, std::span<const std::uint8_t> data, bool fin = false);

  // Contiguous bytes ready to be read. The span is invalidated by
  // consume_stream and by receive.
  [[nodiscard]] std::span<const std::uint8_t> readable_stream(std::uint64_t id);
  void consume_stream(std::uint64_t id, std::size_t bytes);

  // Ascending by id. The connection does not hold streams in that order, so
  // this sorts; it is a caller-facing convenience rather than anything the
  // send path uses.
  [[nodiscard]] std::vector<std::uint64_t> readable_streams();

  // The two halves finish independently -- that is the whole point of
  // modelling them separately -- so a caller that wants to know whether it can
  // stop reading asks a different question from one that wants to know whether
  // everything it sent arrived.
  [[nodiscard]] bool stream_receive_finished(std::uint64_t id);
  [[nodiscard]] bool stream_send_finished(std::uint64_t id);

  // Abandons the sending half; the peer is told with RESET_STREAM.
  void reset_stream(std::uint64_t id, std::uint64_t error_code);
  // Asks the peer to stop sending on the receiving half.
  void stop_sending(std::uint64_t id, std::uint64_t error_code);

private:
  connection_t() = default;
  std::unique_ptr<detail::connection_impl_t> _impl;
};
} // namespace vio::quic
