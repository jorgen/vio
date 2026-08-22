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

  // Length of the connection IDs this endpoint issues. A short header carries
  // no length field, so this is the only way an incoming 1-RTT packet can be
  // parsed; it cannot change once a connection is running.
  std::size_t local_connection_id_length = 8;

  // The largest datagram this endpoint will send. Section 14 requires at least
  // 1200 for anything carrying an Initial.
  std::size_t max_datagram_size = 1200;

  std::chrono::nanoseconds max_ack_delay = std::chrono::milliseconds(25);
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

  // Queues a CONNECTION_CLOSE. The frame goes out on the next poll_send.
  void close(std::uint64_t error_code, std::string_view reason, bool application = false);

private:
  connection_t() = default;
  std::unique_ptr<detail::connection_impl_t> _impl;
};
} // namespace vio::quic
