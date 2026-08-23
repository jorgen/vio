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

// The socket end of QUIC: one UDP port, many connections.
//
// connection_t is sans-I/O on purpose -- bytes and a clock reading go in,
// bytes come out -- which leaves three jobs that only something owning the
// socket can do, and all three are here.
//
// The first is demultiplexing. A UDP socket is not a connection: every
// datagram has to be matched to one by the Destination Connection ID in its
// header, which is why an endpoint issues connection IDs of a fixed length it
// chooses (section 5.1) -- a short header carries no length field, so the
// length is the only thing that makes the field findable at all.
//
// The second is answering for connections that do not exist. A Version
// Negotiation packet (section 6.1), a Retry (section 8.1.2) and a Stateless
// Reset (section 10.3) are all replies to a datagram that belongs to no
// connection, so none of them can live inside one.
//
// The third is time. connection_t never reads a clock; something has to tell
// it what time it is and call it again when a timer it asked for comes due.

#include "vio/error.h"
#include "vio/event_loop.h"
#include "vio/operation/udp.h"
#include "vio/quic/connection.h"
#include "vio/task.h"
#include "vio/tick.h"

#include <chrono>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace vio::quic
{
struct endpoint_config_t
{
  // The template every accepted or dialled connection is built from. Its
  // connection ID length is what this endpoint will look for in the header of
  // every arriving datagram, so it cannot vary per connection.
  connection_config_t connection;

  // Versions this endpoint speaks, offered in a Version Negotiation packet to
  // a client that asks for something else.
  std::vector<std::uint32_t> supported_versions = {quic_version_1};

  // Section 8.1.2. Present means every new client is sent a Retry before any
  // handshake work is done, which costs an address-spoofing attacker the
  // ability to make this endpoint work on their behalf.
  const retry_token_key_t *retry_key = nullptr;

  // Section 10.3. Also what lets this endpoint answer for connections it has
  // forgotten, so it outlives any one of them.
  const stateless_reset_key_t *stateless_reset_key = nullptr;

  // Section 13.4. Marks outgoing datagrams ECT(0), so routers can report
  // congestion by setting a bit rather than dropping the packet, and the peer's
  // reported counts become something this endpoint can check and act on.
  //
  // Marking is applied to the socket, and the socket is shared by every
  // connection on this endpoint. So when validation fails on one path -- a
  // middlebox clearing the field, a peer not reporting -- marking stops for all
  // of them. That is the conservative direction (ECN off is always safe), but
  // it does mean one bad path costs the others the benefit. Per-datagram
  // marking would need sendmsg with control messages instead of the socket
  // option, and libuv's send path does not offer that.
  bool ecn = false;

  // Zero means no ceiling.
  //
  // A server reachable from the internet should set this, or retry_key, or
  // both. Without either, one Initial packet from a spoofed source address
  // buys a whole connection's worth of state -- a TLS session, key schedules,
  // per-space buffers -- and nothing has proved the address was real. A Retry
  // makes the sender prove it before any of that is built (section 8.1.2); a
  // ceiling bounds the damage when they can.
  std::size_t max_connections = 0;

  // How long a closed connection is kept so that late packets meet a
  // connection rather than a stateless reset. Section 10.2.
  std::chrono::milliseconds draining_period{3000};
};

// Handed to the application when a connection arrives or is dialled. The
// endpoint owns the connection; this is a borrowed view of it, valid until the
// connection closes.
using connection_ready_t = std::function<void(connection_t &)>;

namespace detail
{
struct endpoint_impl_t;
} // namespace detail

class VIO_EXPORT endpoint_t
{
public:
  ~endpoint_t();
  endpoint_t(endpoint_t &&) noexcept;
  endpoint_t &operator=(endpoint_t &&) noexcept;
  endpoint_t(const endpoint_t &) = delete;
  endpoint_t &operator=(const endpoint_t &) = delete;

  [[nodiscard]] static std::expected<endpoint_t, error_t> create(event_loop_t &loop, const tls_context_t &context, const endpoint_config_t &config);

  // Binds the socket. A client may skip this and let the OS choose.
  [[nodiscard]] std::expected<void, error_t> bind(const sockaddr *address);
  [[nodiscard]] std::expected<std::uint16_t, error_t> local_port() const;

  // Called for every connection that completes a handshake, in the order they
  // do. A server uses this to learn about arrivals; a client can use it to
  // learn its dial succeeded.
  void on_connection(connection_ready_t handler);

  // Dials. The returned pointer is owned by the endpoint and stays valid until
  // the connection closes and is reaped.
  [[nodiscard]] std::expected<connection_t *, error_t> connect(const sockaddr *address, std::string_view server_name);

  // Reads until cancelled, routing datagrams and running timers. This is the
  // whole endpoint: nothing else needs to be driven.
  //
  // Shutting down has an order to it. Cancelling stops the read loop, and
  // destroying the endpoint closes its socket -- and the socket must be closed
  // before the event loop is asked to stop, because event_loop_t::stop() runs
  // the loop until nothing is left open. A socket still live at that point is
  // a loop that never returns. The endpoint also has to outlive this
  // coroutine, which holds a reference to it.
  [[nodiscard]] task_t<void> run(cancellation_t *cancel = nullptr);

  // Pushes whatever every connection currently wants to send onto the socket.
  // run() does this after each datagram and on every timer; a caller that has
  // just written to a stream outside the loop can use it to flush without
  // waiting for either.
  std::expected<void, error_t> flush();

  [[nodiscard]] std::size_t connection_count() const;

private:
  endpoint_t() = default;
  std::unique_ptr<detail::endpoint_impl_t> _impl;
};
} // namespace vio::quic
