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
#include "vio/quic/congestion_control.h"
#include "vio/quic/connection_id.h"
#include "vio/quic/ecn.h"
#include "vio/quic/mtu.h"
#include "vio/quic/path.h"
#include "vio/quic/qlog.h"
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
// Section 20.1: the server is not accepting, and says so rather than letting
// the client wait out a handshake nobody is going to finish. What an endpoint
// whose accept backlog is full answers with.
inline constexpr std::uint64_t transport_error_connection_refused = 0x02;
inline constexpr std::uint64_t transport_error_protocol_violation = 0x0a;
inline constexpr std::uint64_t transport_error_crypto_buffer_exceeded = 0x0d;
inline constexpr std::uint64_t transport_error_aead_limit_reached = 0x0f;

// What a stream's sending half is holding, and why it is not moving.
//
// write_stream accepts whatever it is given and puts it on the wire later, so
// none of this is visible from its return value -- and without it an
// application has no way to meter itself against a peer that has stopped
// reading, and no way to answer "why has my write not left".
struct stream_send_stats_t
{
  // Everything handed to write_stream, whether or not it has been sent.
  std::uint64_t queued = 0;
  // How far the wire has got, and how far the peer has confirmed. The gap
  // between acknowledged and queued is what a sender should bound.
  std::uint64_t sent = 0;
  std::uint64_t acknowledged = 0;
  // The peer's limit for this stream, which is the ceiling `sent` moves under.
  std::uint64_t max_data = 0;
  bool fin_queued = false;
  // The two reasons a stream with data to send sends none. They are different
  // problems: the first is answered by this stream being read, the second by
  // the connection as a whole being read.
  bool blocked_by_stream_limit = false;
  bool blocked_by_connection_limit = false;
};

// What the path is doing. All of it is measured already; none of it was
// reachable, so an application could not report a round trip time, size a
// buffer against the window, or tell a slow path from a lossy one.
struct connection_path_stats_t
{
  std::chrono::nanoseconds smoothed_rtt{0};
  std::chrono::nanoseconds rtt_variation{0};
  std::chrono::nanoseconds min_rtt{0};
  std::size_t bytes_in_flight = 0;
  std::size_t congestion_window = 0;
  std::size_t slow_start_threshold = 0;
  // Whether the window is still doubling. Worth reporting separately because
  // the same window means different things either side of it: in slow start it
  // is a floor being probed upward, and afterwards it is an estimate being
  // defended.
  bool in_slow_start = false;
};

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
  // Which end of the handshake to run. A real input for code building a
  // connection_t directly, which the tests and the benchmark do -- but
  // endpoint_t writes it per connection from the path that built it, so
  // setting it on endpoint_config_t::connection has no effect. It cannot be an
  // endpoint-wide fact any more: one endpoint may hold connections of both
  // roles.
  tls_role_t role = tls_role_t::server;
  // The version a client proposes in its first Initial. A server ignores this
  // and adopts whatever the client asked for, provided the endpoint accepts it.
  std::uint32_t version = quic_version_1;

  // What this endpoint advertises. Initialised to a working set rather than to
  // the struct's own initialisers, which are section 18.2's absent-parameter
  // values and grant no credit at all -- a connection built from those
  // completes its handshake and can then carry nothing, with no error raised
  // anywhere to say why.
  //
  // To change one value, start from what is here rather than from a bare
  // struct: transport_parameters_t{.initial_max_data = x} names one field and
  // silently zeroes the other eight.
  transport_parameters_t transport_parameters = default_transport_parameters();

  // A ticket from an earlier connection to this peer, as handed back by
  // resumption_ticket(). Offering one resumes, and a resumed connection can put
  // application data in its very first flight.
  //
  // It carries the server's transport parameters as well as the TLS session,
  // because section 4.6.1 requires a client sending 0-RTT to keep inside the
  // limits the server gave last time -- there is nothing else to go on before
  // the server has spoken. Those remembered limits are replaced by the real
  // ones the moment the handshake delivers them.
  std::vector<std::uint8_t> resumption_ticket;

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
  // Where the path MTU search starts, and where it stops. Section 14 requires
  // every path to carry the first, so it is also the size a connection retreats
  // to if the path stops carrying what it grew to. The ceiling is bounded again
  // by the peer's max_udp_payload_size, which is a promise about what it will
  // read. Raise it past a 1500 byte link only where the whole path is known to
  // carry more: every size the path refuses costs probes to find out.
  // Which controller runs congestion avoidance. NewReno is the conservative
  // default RFC 9002 describes; CUBIC (RFC 9438) recovers a window a loss took
  // far faster and is what the other implementations ship.
  congestion_algorithm_t congestion_algorithm = congestion_algorithm_t::new_reno;

  std::size_t max_datagram_size = smallest_maximum_datagram_size;
  std::size_t datagram_size_ceiling = common_path_datagram_size;

  std::chrono::nanoseconds max_ack_delay = std::chrono::milliseconds(25);

  // How long a connection may stay unfinished before it is abandoned. The idle
  // timeout of section 10.1 cannot cover this: it is negotiated, so it does not
  // exist until the peer's transport parameters have arrived, and a handshake
  // that never gets that far would otherwise be held forever. A server reached
  // over the open internet needs this, because an Initial costs an attacker one
  // spoofed datagram and costs the server a connection, a TLS session and three
  // key schedules. Zero disables it.
  std::chrono::nanoseconds handshake_timeout = std::chrono::seconds(10);

  // Section 13.4. The codepoint this connection's datagrams go out marked
  // with, recorded on each sent packet so the peer's reported counts can be
  // checked against it. Leave it at not_ect unless whatever owns the socket
  // really is applying it -- claiming ECT(0) without sending it makes
  // validation fail against a peer doing everything right.
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

  // The same, told what ECN codepoint the datagram carried when it arrived.
  // Section 13.4.2: the counts this endpoint reports back are what let the peer
  // react to congestion a router signalled instead of waiting for loss.
  [[nodiscard]] std::expected<void, error_t> receive(std::span<std::uint8_t> datagram, tick_t now, std::span<const std::uint8_t> peer_address, ecn_codepoint_t ecn);

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

  // The same, for a caller that can address a datagram itself.
  //
  // `destination` is cleared and left empty for every datagram belonging to the
  // path the connection is on, which is almost all of them. It is filled in
  // only for a PATH_RESPONSE owed to somewhere else -- a peer probing an address
  // before it migrates there -- which section 8.2.2 requires be answered on the
  // path the challenge arrived by, and which the two-argument form above
  // therefore cannot send at all. A demultiplexer that keeps one peer address
  // per connection has to consult this or the peer's validation times out and
  // it never moves.
  [[nodiscard]] std::expected<std::size_t, error_t> poll_send(std::span<std::uint8_t> out, tick_t now, std::vector<std::uint8_t> *destination);

  // When poll_send should next be called even if nothing else happens: an ACK
  // is owed, or loss detection has something to report. Nothing pending means
  // no deadline.
  [[nodiscard]] std::optional<tick_t> next_timeout(tick_t now) const;

  [[nodiscard]] connection_state_t state() const;
  [[nodiscard]] bool handshake_complete() const;
  [[nodiscard]] bool handshake_confirmed() const;

  // A ticket for resuming this connection later, once the handshake is done
  // and the server has issued one. Empty until then, and on a server always.
  // Keeping it is what makes the next connection to this peer able to send
  // 0-RTT; where it is kept is the caller's decision, so it comes out as bytes.
  [[nodiscard]] std::vector<std::uint8_t> resumption_ticket() const;

  // Whether the data this connection sent before the handshake finished was
  // taken. Meaningful on a client that offered a ticket.
  [[nodiscard]] bool early_data_accepted() const;

  // The server resumed but refused the early data, so nothing sent at 0-RTT
  // arrived. Stream state written early has been rewound and will go out again
  // under 1-RTT keys, which is section 4.6.2's requirement; this reports that
  // it happened rather than asking the caller to do anything about it.
  [[nodiscard]] bool early_data_rejected() const;

  // The datagram size in use, which starts at what section 14 requires of every
  // path and grows to whatever this one turns out to carry.
  [[nodiscard]] std::size_t datagram_size() const;

  // What the path has been measured delivering, in bytes per second: the most
  // recent sample, and the fastest seen. Nothing steers on these yet.
  // Per stream, and for the whole path. Cheap reads of state the transport
  // already keeps; the interesting one is the gap between queued and
  // acknowledged, which is the only measure of how far ahead of the peer a
  // sender has run.
  [[nodiscard]] stream_send_stats_t stream_send_stats(std::uint64_t id);
  [[nodiscard]] connection_path_stats_t path_stats() const;

  [[nodiscard]] std::uint64_t delivery_rate() const;
  [[nodiscard]] std::uint64_t peak_delivery_rate() const;

  [[nodiscard]] const connection_id_t &local_connection_id() const;
  [[nodiscard]] const connection_id_t &peer_connection_id() const;

  [[nodiscard]] std::optional<transport_parameters_t> peer_transport_parameters() const;
  // The subject of the certificate the peer presented, once verified. Empty
  // when the peer presented none, or when it did not verify -- so a non-empty
  // answer is an authenticated identity and nothing else is.
  //
  // A server gets an answer here only if it asked, by setting
  // tls_config_t::peer_verify. Without that it authenticates nobody, which is
  // the ordinary server arrangement and the default.
  [[nodiscard]] std::string peer_certificate_subject() const;

  [[nodiscard]] std::string_view selected_alpn() const;
  // Why this connection ended, or nothing while it is still running.
  //
  // Broader than the frame it is named after: a version negotiation failure, a
  // stateless reset, an idle timeout and an abandoned handshake all end a
  // connection without a CONNECTION_CLOSE ever being sent or received, and all
  // of them record a reason here. Silent on the wire and silent to the
  // application are different things, and this is the only place the second
  // one is answered.
  //
  // from_peer separates the two cases an application usually cares about:
  // whether the far end said something, or whether this end gave up.
  [[nodiscard]] std::optional<connection_close_t> close_reason() const;

  // Whether this connection went through a Retry, and so whether the peer
  // address was validated before any handshake work was done.
  [[nodiscard]] bool address_validated_by_retry() const;

  // Section 5.1: how many connection IDs each side currently has available.
  // A peer that has run out cannot migrate, since section 9.5 requires it to
  // move to an ID the old path never saw.
  // Which end of the handshake this connection ran. Written per connection by
  // whatever built it, so it is the one place the answer lives -- and a
  // demultiplexer needs it, because the two roles are not routable on the same
  // terms. See original_destination_id below.
  [[nodiscard]] tls_role_t role() const;

  // Section 7.2: the unpredictable value the client put in the Destination
  // Connection ID of its first Initial.
  //
  // It means opposite things on the two sides, which is what makes it a
  // routing hazard. On a server it is a value the peer really does address, so
  // a demultiplexer must route on it as well as on the issued ids, until the
  // client has seen the server's own choice and switched. On a client it is
  // the value this endpoint invented to address the PEER, and nothing ever
  // sends it back here -- so routing on it is at best dead weight, and on an
  // endpoint that also answers it is worse: the value travels in plaintext in
  // every Initial, so anyone who has seen one can address it and be routed to
  // a connection that will fail to authenticate them rather than to the
  // accept path.
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

  // Traces this connection to a qlog file. The connection owns the writer, so
  // the trace is closed when the connection is. Nothing is traced without
  // one, and the checks around each event are a null pointer test.
  void set_qlog(std::unique_ptr<qlog_writer_t> writer);
  [[nodiscard]] bool tracing() const;

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
  // RFC 9221. Queues one unreliable datagram, refusing it if the peer offered
  // no room for datagrams or the frame would exceed what it offered. Queued is
  // all it promises: a datagram that is lost is not retransmitted, and one the
  // connection closes on is never sent.
  [[nodiscard]] bool write_datagram(std::span<const std::uint8_t> data);

  // The largest payload write_datagram will take, given what the peer offered.
  // Zero means the peer does not accept datagrams at all.
  [[nodiscard]] std::size_t max_datagram_payload() const;

  // The next datagram that arrived, or nothing. Received datagrams queue in
  // order and are handed over one at a time.
  [[nodiscard]] std::optional<std::vector<std::uint8_t>> read_datagram();

  [[nodiscard]] std::span<const std::uint8_t> readable_stream(std::uint64_t id);
  void consume_stream(std::uint64_t id, std::size_t bytes);

  // Ascending by id. The connection does not hold streams in that order, so
  // this sorts; it is a caller-facing convenience rather than anything the
  // send path uses.
  //
  // Note what it is: streams with unread bytes right now. That is a level, and
  // a level cannot answer "what happened" -- a stream that carried only a
  // zero-length FIN never appears here, nor does one reset before anything was
  // read, nor one whose bytes have all been consumed. The take_* accessors
  // below answer that question instead.
  [[nodiscard]] std::vector<std::uint64_t> readable_streams();

  // Everything that has happened since the last call, drained by reading it.
  //
  // These exist for anything that has to be woken rather than polled: each
  // reports an edge once, so nothing is missed by asking at the wrong moment,
  // and each is emptied by the call. A duplicate id is possible and harmless
  // -- the second look finds nothing to do -- but a missed one is not, which
  // is why they are recorded where the change happens rather than inferred.
  //
  // opened covers both sides; use stream_initiator() on the id to tell a
  // stream the peer opened from one this endpoint did.
  [[nodiscard]] std::vector<std::uint64_t> take_opened_streams();
  // Streams with more to read, or whose receiving half has just ended --
  // including by a reset, and including a FIN that carried no bytes.
  [[nodiscard]] std::vector<std::uint64_t> take_data_arrived();
  // Streams whose sending half may now move: a limit really rose, an
  // acknowledgement freed room, or the peer ended it with STOP_SENDING. A
  // duplicate MAX_DATA does not appear here, because nothing changed.
  [[nodiscard]] std::vector<std::uint64_t> take_send_unblocked();
  // Whether the peer raised how many streams this endpoint may open, which is
  // what open_stream returning nothing is waiting for.
  [[nodiscard]] bool take_stream_credit_opened();

  // The two halves finish independently -- that is the whole point of
  // modelling them separately -- so a caller that wants to know whether it can
  // stop reading asks a different question from one that wants to know whether
  // everything it sent arrived.
  //
  // Note that finished says nothing about how. A stream the peer reset and one
  // it completed both report true here, because both are over; which of the
  // two it was is stream_receive_reset below.
  [[nodiscard]] bool stream_receive_finished(std::uint64_t id);

  // Whether the receiving half ended because the peer gave up on it rather
  // than because it ran out. Cancellation is not an edge case -- it is a user
  // closing a tab, a client abandoning a download, HTTP/3 signalling
  // H3_REQUEST_CANCELLED -- and an application that cannot tell it from a
  // clean end has to infer it from a length it may not know.
  [[nodiscard]] bool stream_receive_reset(std::uint64_t id);

  // The code the peer sent with its RESET_STREAM, and the code it sent with
  // STOP_SENDING. Nothing, when the peer sent neither. These carry whatever
  // the application protocol above puts in them, which is the only place the
  // reason for a cancellation exists.
  [[nodiscard]] std::optional<std::uint64_t> stream_peer_reset_error(std::uint64_t id);
  [[nodiscard]] std::optional<std::uint64_t> stream_peer_stop_sending_error(std::uint64_t id);
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
