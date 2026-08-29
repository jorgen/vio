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

// The coroutine face of QUIC: endpoints and connections. Streams and datagrams
// arrive in quic_stream.h next; nothing here names one, because a program that
// only dials and closes should not have to read the stream API to do it.
//
// Everything under vio/quic/ stays as it is. connection_t is a sans-I/O state
// machine and endpoint_t is a demultiplexer over one UDP socket, both driven by
// std::function and by integer ids, and both testable with no socket under
// them. That is the right shape for the inside of a transport and the wrong one
// for an application, which wants to write co_await.
//
// The organising idea is the loop turn. Datagrams that arrived together are
// taken in together by the endpoint's read loop, which marks the connections
// they touched and sends whatever acknowledgements they owe. Then, once, every
// coroutine that has become runnable is resumed and whatever they wrote is
// pushed onto the socket. That second half is the beat, and it runs from a
// handle this endpoint owns.
//
// No user code ever runs on the read loop's stack, and the reason is narrower
// than it first looks. endpoint_impl_t holds its connections as unique_ptr, so
// a dial's push_back does not move the entries a walk is standing on, and the
// walking counter already defers the reap that would free one -- dialling from
// a callback is safe today. What is not safe is what a coroutine may do that a
// callback may not: drop the last quic_endpoint_t, which destroys
// endpoint_impl_t, run()'s own frame, the datagram reader inside it and the
// vector being walked, from a stack several calls deep inside all of them. No
// amount of bracketing helps, because the storage is gone. So the transport's
// hooks only record, and the beat is the one place anything is resumed.
//
// This file is the declaration skeleton: the codes, the configuration, and the
// state the layer keeps. The operations that use it follow.

#include "vio/cancellation.h"
#include "vio/error.h"
#include "vio/event_loop.h"
#include "vio/quic/endpoint.h"
#include "vio/ref_counted_wrapper.h"
#include "vio/task.h"
#include "vio/tick.h"

#include <chrono>
#include <coroutine>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <expected>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <uv.h>

namespace vio
{
// -----------------------------------------------------------------------------
// Error codes
// -----------------------------------------------------------------------------
//
// One hex word for the subsystem, the way ssl_engine.h owns 0x715c00. Nothing
// else in vio uses this block: the only other codes are 0x715c00-02 for TLS,
// 0xca9ce1 for cancellation, and libuv's, which are negative.
//
// 0x9c1c01 to 0x9c1c04 are reserved for quic_stream.h -- stream finished,
// reset, stopped and stale. The hole is left rather than closed so that the
// numbers published here do not move when those arrive.

// The connection ended under this operation with a non-zero code, after its
// handshake had completed. Which side said so, and why, is in the connection's
// close reason; the reason string is also in error_t::msg. A code of zero from
// either side is not this -- that is a clean ending and arrives as success.
inline constexpr int vio_quic_connection_closed = 0x9c1c05;

// Section 10.1: the negotiated idle period elapsed. Distinct from a close
// because nobody said anything, which is the whole reason the timer exists.
inline constexpr int vio_quic_idle_timeout = 0x9c1c06;

// The connection ended before its handshake completed: a certificate that did
// not verify, no ALPN in common, a TLS alert, or the handshake deadline. One
// code for all four, because all four mean the dial produced nothing usable,
// and the close reason separates them.
inline constexpr int vio_quic_handshake_failed = 0x9c1c07;

// Section 10.3: the peer no longer remembers this connection at all.
inline constexpr int vio_quic_stateless_reset = 0x9c1c08;

// Section 6.2: the peer offered no QUIC version this build speaks.
inline constexpr int vio_quic_version_unsupported = 0x9c1c09;

// The endpoint was released, or shut down, while this was suspended. Every
// awaitable an endpoint owns resolves with this before its storage goes, since
// a coroutine that is never resumed is a leaked frame -- and, if it holds a
// handle, an event loop that never returns.
inline constexpr int vio_quic_endpoint_closed = 0x9c1c0a;

// A second concurrent waiter on an operation that has exactly one slot.
//
// Nothing in this file raises it. Accepts and dials are per-call operations, so
// a second concurrent one has nothing to overwrite and simply waits its turn;
// the number is declared because it is published, and because the single reader
// per stream in quic_stream.h is the operation that really does have one slot.
//
// Note what it is not. Asking a dial-only endpoint to accept, or an answer-only
// one to dial, is a configuration mistake rather than a race, and comes back
// with a full sentence -- which is what endpoint_t::connect already answers for
// the mirror case. Spending the one code an application can usefully branch on
// covering both would make it unbranchable.
inline constexpr int vio_quic_busy = 0x9c1c0b;

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

// There is deliberately no separate flow-control type.
// connection_config_t::transport_parameters is already initialised to
// default_transport_parameters() -- 8 MiB across the connection, 2 MiB per
// stream -- so an endpoint configured with nothing carries traffic, and a
// second copy of those numbers here would be a second source of truth for the
// one thing that must have exactly one.
//
// To change one, assign the field rather than brace-initialising the struct:
//
//   quic_config_t config;
//   config.transport.connection.transport_parameters.initial_max_data = 64u << 20;
//
// transport_parameters_t{.initial_max_data = x} names one parameter and
// silently zeroes the other eight, because that struct is also the decoder's
// accumulator and its initialisers are section 18.2's absent-parameter values.
struct quic_config_t
{
  // Everything the transport already has an opinion about: the retry key, the
  // stateless reset key, ECN, segmentation offload, the qlog directory, the
  // connection ceiling, the draining period, and the whole of
  // connection_config_t underneath. Those defaults are good and are left alone.
  vio::quic::endpoint_config_t transport;

  // Connections whose handshake has completed and which nothing has accepted
  // yet. Past this a connection is refused rather than queued, because a client
  // told no can go elsewhere and one told nothing waits out its handshake
  // timeout.
  //
  // Be clear about what it does not bound. The arrival hook fires after the
  // handshake, so a refused connection has already cost a TLS session and three
  // key schedules; endpoint_config_t::max_connections is the earlier and
  // cheaper ceiling, and a server reachable from the internet wants that one
  // and a retry key rather than this.
  std::size_t accept_backlog = 128;
};

// What the path is doing. Nothing steers on these; they are what a progress
// bar, a log line and a bandwidth-delay-product calculation are made of.
//
// Latched as of the ending rather than zeroed once the connection is gone,
// which costs one struct copy per connection: a shutdown log line reading
// "RTT 0" for every connection that has closed is a worse answer than the
// truth.
struct quic_connection_stats_t
{
  std::chrono::nanoseconds smoothed_rtt{};
  std::chrono::nanoseconds rtt_variation{};
  std::chrono::nanoseconds min_rtt{};
  std::size_t congestion_window = 0;
  std::size_t slow_start_threshold = 0;
  std::size_t bytes_in_flight = 0;
  std::size_t datagram_size = 0;
  std::uint64_t delivery_rate = 0;
  std::uint64_t peak_delivery_rate = 0;
  std::uint64_t migrations = 0;
  bool in_slow_start = false;
};

// Everything here is a cheap read of state the transport already keeps, taken
// in one call because it is taken at moments -- the handshake, the ending --
// when the connection_t is about to stop being readable.
[[nodiscard]] inline quic_connection_stats_t quic_read_stats(vio::quic::connection_t &connection)
{
  const auto path = connection.path_stats();
  quic_connection_stats_t out;
  out.smoothed_rtt = path.smoothed_rtt;
  out.rtt_variation = path.rtt_variation;
  out.min_rtt = path.min_rtt;
  out.congestion_window = path.congestion_window;
  out.slow_start_threshold = path.slow_start_threshold;
  out.bytes_in_flight = path.bytes_in_flight;
  out.in_slow_start = path.in_slow_start;
  out.datagram_size = connection.datagram_size();
  out.delivery_rate = connection.delivery_rate();
  out.peak_delivery_rate = connection.peak_delivery_rate();
  out.migrations = connection.migration_count();
  return out;
}

// Which of the codes above an ending deserves.
//
// The transport records an idle timeout and a clean local close identically --
// error code zero, not an application code, not from the peer -- because on the
// wire they are the same nothing. Only this layer knows which of its own calls
// closed a connection, so `closed_locally` is what separates them, and it is
// the argument rather than something read back.
[[nodiscard]] inline int quic_classify_ending(const std::optional<vio::quic::connection_close_t> &reason, bool handshake_reached, bool closed_locally, bool reset_by_peer, bool version_negotiation_failed)
{
  if (reset_by_peer)
  {
    return vio_quic_stateless_reset;
  }
  if (version_negotiation_failed)
  {
    return vio_quic_version_unsupported;
  }
  // Before the handshake completed nothing else is worth distinguishing: every
  // way it can fail means the same thing to a caller holding a dial.
  if (!handshake_reached)
  {
    return vio_quic_handshake_failed;
  }
  if (reason.has_value() && reason->error_code != 0)
  {
    return vio_quic_connection_closed;
  }
  if (closed_locally)
  {
    return 0;
  }
  // A zero code that this endpoint did not send. Either the peer closed
  // cleanly, in which case there is a reason recorded and from_peer is set, or
  // the connection simply went quiet.
  if (reason.has_value() && reason->from_peer)
  {
    return 0;
  }
  return vio_quic_idle_timeout;
}

namespace detail
{
struct quic_endpoint_state_t;
struct quic_connection_state_t;
struct quic_op_t;
struct quic_milestone_state_t;

// A waiter lives inside the awaitable, which lives inside the awaiting
// coroutine's frame. Intrusive rather than a vector of coroutine handles, for
// two reasons that are correctness and not economy: a frame destroyed while
// still suspended unlinks its own node here, where a vector entry would dangle
// and be resumed into freed memory; and a drain resumes one waiter at a time
// re-reading the head, because the first coroutine resumed may destroy the
// second's frame.
struct quic_waiter_t
{
  std::coroutine_handle<> continuation;
  quic_waiter_t *prev = nullptr;
  quic_waiter_t *next = nullptr;
  quic_milestone_state_t *slot = nullptr;
};

// Its own small allocation rather than a member of whatever reached it, so an
// awaitable can hold it outright. A milestone owns no libuv handle, so a
// suspended waiter keeping one alive keeps nothing open -- which is what makes
// this the one place a strong reference is safe, where nothing pointing at the
// endpoint may be.
struct quic_milestone_state_t
{
  bool reached = false;
  std::expected<void, error_t> result;
  quic_waiter_t *waiters = nullptr;
};

// One suspended accept or dial. Heap-allocated per call rather than a slot on
// the endpoint, which is what lets two coroutines accept at once without one
// overwriting the other's continuation.
//
// It borrows its endpoint, nulled the moment the operation resolves or the
// endpoint tears down, so the borrow cannot outlive the storage.
struct quic_op_t
{
  quic_endpoint_state_t *endpoint = nullptr;
  std::coroutine_handle<> continuation;
  ref_ptr_t<quic_connection_state_t> result;
  error_t failure;
  bool resolved = false;
  bool failed = false;
  // The two-hold protocol: the awaitable holds one and the endpoint holds the
  // other, and the last to let go frees it. Without it an operation resolved
  // after its awaitable was abandoned has nobody left to delete it.
  int holds = 0;
  registration_t cancel_registration;
};

struct quic_connection_state_t
{
  quic_connection_state_t(quic_endpoint_state_t *owner, vio::quic::connection_t *from, vio::quic::tls_role_t which)
    : endpoint(owner)
    , transport(from)
    , role(which)
  {
  }
  quic_connection_state_t(const quic_connection_state_t &) = delete;
  quic_connection_state_t &operator=(const quic_connection_state_t &) = delete;

  // Both borrowed, and nulled at two different moments. `transport` goes at the
  // draining latch, because that is the last thing the endpoint says about it:
  // the reap a draining period later frees the connection_t with no
  // notification at all, so a pointer kept past the latch is one nothing will
  // ever tell us to drop -- and the next connection_t may be allocated at the
  // same address. `endpoint` goes when the endpoint tears down.
  //
  // Never strong in either direction. A connection that kept its endpoint alive
  // would keep the UDP socket open, which is uv_loop_close failing and
  // ~event_loop_t aborting on its assert.
  quic_endpoint_state_t *endpoint = nullptr;
  vio::quic::connection_t *transport = nullptr;

  // Latched at registration, because the arrival hook fires for dialled
  // connections too and the sort between the accept queue and the waiting dial
  // needs it before anything else about the connection is known.
  vio::quic::tls_role_t role;

  ref_ptr_t<quic_milestone_state_t> ready;
  ref_ptr_t<quic_milestone_state_t> closed;

  // Latched at the handshake and at the ending respectively, because both are
  // read out of a connection_t the endpoint destroys on its own schedule --
  // selected_alpn() returns a view into that storage, and close_reason() stops
  // existing entirely.
  std::string alpn;
  std::optional<vio::quic::connection_close_t> close_reason;
  quic_connection_stats_t stats;

  // Borrowed: the dial waiting for this connection, nulled when it resolves.
  quic_op_t *pending_dial = nullptr;

  bool handshake_reached = false;
  // Set by every path here that closes: the explicit close, the shutdown, and a
  // cancelled dial. It is the only thing that tells a clean local close from an
  // idle timeout, which the transport records with the same error code, the
  // same application flag and the same from_peer.
  bool closed_locally = false;
  bool severed = false;
  bool queued = false;
  bool dirty = false;
};
} // namespace detail

// The application's handle on an endpoint. Aggregate over a ref_ptr_t with the
// member named handle, exactly as tcp_t and timer_t are.
//
// This is the only strong reference to the endpoint's state that exists, which
// is what makes releasing it a shutdown: no awaitable and no connection holds
// one, so letting the last of these go out of scope really does reach zero and
// run the teardown that resolves everything parked.
struct quic_endpoint_t
{
  ref_ptr_t<detail::quic_endpoint_state_t> handle = ref_ptr_t<detail::quic_endpoint_state_t>::null();
};

// The application's handle on one connection. Holding it past the connection's
// ending is safe and is the point: it keeps answering what it latched, so a
// coroutine that wakes late still learns how its connection ended rather than
// finding a null pointer.
struct quic_connection_t
{
  ref_ptr_t<detail::quic_connection_state_t> handle = ref_ptr_t<detail::quic_connection_state_t>::null();
};

namespace detail
{
struct quic_endpoint_state_t
{
  quic_endpoint_state_t(event_loop_t &owner, vio::quic::endpoint_t &&from, quic_config_t configuration)
    : loop(owner)
    , transport(std::move(from))
    , config(std::move(configuration))
  {
  }
  quic_endpoint_state_t(const quic_endpoint_state_t &) = delete;
  quic_endpoint_state_t &operator=(const quic_endpoint_state_t &) = delete;

  event_loop_t &loop;
  // Declared before driver_stop and driver so that it is destroyed after both:
  // the driver's frame holds an endpoint_impl_t reference and owns the datagram
  // reader, whose poll handle is armed on this socket's descriptor. Teardown
  // does this in order anyway; the declaration order is the second line of
  // defence.
  std::optional<vio::quic::endpoint_t> transport;
  cancellation_t driver_stop;
  std::optional<task_t<void>> driver;
  quic_config_t config;

  reference_counted_t *rc = nullptr;
  uv_prepare_t beat = {};

  bool driver_started = false;
  // Set as the very first act of teardown, before anything is resumed. Every
  // entry point tests this rather than whether the transport is still there,
  // because the transport outlives most of the teardown -- a coroutine resumed
  // to be told the endpoint is going away could otherwise dial and park on an
  // operation nothing will ever resolve.
  bool closing = false;

  // The identity the hooks hand out is a connection_t reference, so this is
  // what turns one back into something with awaiters on it. Erased at the
  // draining latch, which always precedes the reap.
  std::unordered_map<const vio::quic::connection_t *, ref_ptr_t<quic_connection_state_t>> by_connection;
  std::deque<ref_ptr_t<quic_connection_state_t>> accept_queue;

  // Every operation that has not resolved, in the order it was made, which is
  // also the order an arriving connection is handed down. One list rather than
  // a separate accept queue and dial list, because two lists to keep in step is
  // a way to leave an operation in one of them.
  std::vector<quic_op_t *> live_ops;
  // Resolved, waiting for the beat to resume them.
  std::vector<quic_op_t *> ready_ops;

  // What the beat walks. These are different sets and conflating them would
  // flush every connection that merely received a packet, which the read loop
  // has already done.
  std::vector<ref_ptr_t<quic_connection_state_t>> pending;
  std::vector<ref_ptr_t<quic_connection_state_t>> dirty;
  // For a connection refused before it ever had a state: it is not in the
  // registry, so there is nothing to mark, and its CONNECTION_CLOSE needs the
  // all-connections flush to leave.
  bool flush_all = false;

  ref_ptr_t<quic_milestone_state_t> shutdown;
  bool shutdown_active = false;
  std::size_t shutdown_outstanding = 0;
  tick_t shutdown_deadline;
};
} // namespace detail
} // namespace vio
