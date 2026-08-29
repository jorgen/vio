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
#include <utility>
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
  // Explicitly null: ref_ptr_t default-constructs by allocating, and can only
  // do so for a type that is itself default constructible -- which
  // quic_connection_state_t deliberately is not, since a connection state with
  // no endpoint and no transport behind it is not a thing that should exist.
  ref_ptr_t<quic_connection_state_t> result = ref_ptr_t<quic_connection_state_t>::null();
  error_t failure;
  bool resolved = false;
  bool failed = false;
  // The two-hold protocol: the awaitable holds one and the endpoint holds the
  // other, and whichever lets go last frees it.
  //
  // A count rather than the completed/detached pair udp_send_op_t uses, because
  // that pair relies on the second owner being a libuv callback that runs
  // exactly once. Here either owner may let go first -- an operation can be
  // resolved and then abandoned, or abandoned and then resolved -- and a
  // boolean cannot say which of those has already happened.
  int holds = 0;
  registration_t cancel_registration;
};

// Allocated per call rather than kept as a slot on the endpoint, which is what
// lets two coroutines accept at once without one overwriting the other's
// continuation. Two holds from the start: the awaitable about to be returned,
// and whoever is going to resolve it.
[[nodiscard]] inline quic_op_t *quic_op_create(quic_endpoint_state_t *endpoint)
{
  auto *op = new quic_op_t();
  op->endpoint = endpoint;
  op->holds = 2;
  return op;
}

inline void quic_op_release(quic_op_t *op)
{
  if (op == nullptr)
  {
    return;
  }
  --op->holds;
  if (op->holds <= 0)
  {
    delete op;
  }
}

// Records an outcome. The first one wins: a dial that failed for one reason
// must not be reclassified by a later pass, and more than one thing notices an
// ending.
//
// Nothing here resumes anything. Resumption happens on the beat and nowhere
// else, because whatever calls this is standing inside the transport's read
// loop -- and a coroutine resumed from there may drop the last endpoint
// reference and destroy the very storage being walked.
inline void quic_op_finish(quic_op_t &op, ref_ptr_t<quic_connection_state_t> connection)
{
  if (op.resolved)
  {
    return;
  }
  op.result = std::move(connection);
  op.resolved = true;
}

inline void quic_op_finish(quic_op_t &op, error_t failure)
{
  if (op.resolved)
  {
    return;
  }
  op.failure = std::move(failure);
  op.failed = true;
  op.resolved = true;
}

// The endpoint letting go: resumes whatever is parked, then drops its hold.
//
// Nothing may touch the operation after the resume. The resumed coroutine runs
// to its next suspension, and on the way it destroys the awaitable that was
// holding this -- so by the time control comes back, the only remaining hold is
// the one this function is about to drop, and quite possibly neither.
inline void quic_op_dispatch(quic_op_t *op)
{
  if (op == nullptr)
  {
    return;
  }
  const auto continuation = op->continuation;
  op->continuation = {};
  if (continuation)
  {
    continuation.resume();
  }
  quic_op_release(op);
}

// Links a waiter into a slot. Nothing checks for a double link: a waiter node
// lives in exactly one awaitable and an awaitable suspends at most once.
inline void quic_milestone_link(quic_milestone_state_t &into, quic_waiter_t &node, std::coroutine_handle<> handle)
{
  node.continuation = handle;
  node.slot = &into;
  node.prev = nullptr;
  node.next = into.waiters;
  if (node.next != nullptr)
  {
    node.next->prev = &node;
  }
  into.waiters = &node;
}

// Called from the awaitable's destructor, and idempotent because it is also
// called on a node the drain has already taken out.
//
// This is what makes an abandoned await safe. A task_t destroyed while
// suspended frees its frame, and the node lives in that frame -- so a node left
// linked would leave the list pointing into freed storage, and the next drain
// would resume a coroutine that no longer exists.
inline void quic_milestone_unlink(quic_waiter_t &node)
{
  if (node.slot == nullptr)
  {
    return;
  }
  if (node.prev != nullptr)
  {
    node.prev->next = node.next;
  }
  if (node.next != nullptr)
  {
    node.next->prev = node.prev;
  }
  if (node.slot->waiters == &node)
  {
    node.slot->waiters = node.next;
  }
  node.slot = nullptr;
  node.prev = nullptr;
  node.next = nullptr;
  node.continuation = {};
}

// Marks a milestone reached. The first call wins: a connection that ended for
// one reason does not get reclassified by a later one, and more than one thing
// notices an ending.
//
// It deliberately wakes nobody. Whatever calls this is standing inside the
// transport's read loop or its flush, and a coroutine resumed from there may
// drop the last endpoint reference -- destroying the endpoint, the driver's
// frame and the very vector being walked, several calls further down the same
// stack. Latching here and draining on the beat is what keeps that impossible
// rather than merely unlikely.
inline void quic_milestone_reach(quic_milestone_state_t &slot, std::expected<void, error_t> result)
{
  if (slot.reached)
  {
    return;
  }
  slot.reached = true;
  slot.result = std::move(result);
}

// Wakes everything waiting on a milestone that has been reached. Called from
// the beat and nowhere else.
//
// One waiter at a time, re-reading the head each pass rather than walking a
// snapshot: resuming a coroutine can do anything, including destroying another
// coroutine waiting on this same milestone, so the node that was going to be
// next may not exist by the time we reach it.
inline void quic_milestone_drain(quic_milestone_state_t &slot)
{
  if (!slot.reached)
  {
    return;
  }
  while (slot.waiters != nullptr)
  {
    auto *node = slot.waiters;
    const auto continuation = node->continuation;
    // Out of the list before the resume, not after: the resumed coroutine may
    // destroy this node's own frame, and unlinking a freed node writes through
    // dangling pointers.
    quic_milestone_unlink(*node);
    if (continuation)
    {
      continuation.resume();
    }
  }
}

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

// Something that happens once, is reported rather than consumed, and may be
// awaited late, twice, or by several coroutines at once. A handshake
// completing and a connection ending are both this shape; neither is a queue,
// and asking after the fact must answer rather than block for ever.
//
// It is the one thing in this layer that holds a strong reference, and that is
// safe for a specific reason: a milestone owns no libuv handle, so a suspended
// waiter keeping one alive keeps nothing open. Every other awaitable here
// borrows, because holding the endpoint would stop the release that resolves
// it.
//
// The result lives in the shared state rather than in the awaitable, which is
// what makes an await after the fact correct without a second code path: the
// fast path and the resumed path read the same place.
class quic_milestone_t
{
public:
  explicit quic_milestone_t(ref_ptr_t<detail::quic_milestone_state_t> state)
    : _state(std::move(state))
  {
  }

  // Whether it has happened, for a caller that wants to look rather than wait.
  [[nodiscard]] bool reached() const
  {
    return _state.ref_counted() != nullptr && _state->reached;
  }

  struct awaiter_t
  {
    // Declared before the node so that it is destroyed after it. The
    // destructor body below unlinks first in any case, which is what actually
    // makes this safe -- a derived class holding the reference and a base
    // holding the node would destroy them the other way round, and unlink
    // would then write through storage the reference had just freed.
    ref_ptr_t<detail::quic_milestone_state_t> state;
    detail::quic_waiter_t node;

    awaiter_t(const awaiter_t &) = delete;
    awaiter_t &operator=(const awaiter_t &) = delete;

    explicit awaiter_t(ref_ptr_t<detail::quic_milestone_state_t> owner)
      : state(std::move(owner))
    {
    }

    ~awaiter_t()
    {
      detail::quic_milestone_unlink(node);
    }

    // A milestone that has already happened, and one that never can because
    // nothing owns it, both resolve without suspending.
    [[nodiscard]] bool await_ready() const noexcept
    {
      return state.ref_counted() == nullptr || state->reached;
    }

    void await_suspend(std::coroutine_handle<> continuation) noexcept
    {
      detail::quic_milestone_link(state.data(), node, continuation);
    }

    [[nodiscard]] std::expected<void, error_t> await_resume() const noexcept
    {
      if (state.ref_counted() == nullptr)
      {
        return std::unexpected(error_t{.code = vio_quic_endpoint_closed, .msg = "the endpoint was released"});
      }
      return state->result;
    }
  };

  [[nodiscard]] awaiter_t operator co_await() const
  {
    return awaiter_t{_state};
  }

private:
  ref_ptr_t<detail::quic_milestone_state_t> _state;
};

// One accept or one dial. Unlike a milestone this is consumed: it resolves
// once, to the coroutine that asked, and a second call is a second operation.
//
// It borrows its endpoint through the operation rather than holding one, which
// is the rule the whole layer turns on -- an awaitable that kept the endpoint
// alive would prevent the release that is supposed to resolve it, and the loop
// would never close.
//
// The outcome lives in the operation, which both the endpoint and this share.
// That is deliberate and is what makes the two orders equivalent: an operation
// resolved before anyone awaited it and one resolved while a coroutine was
// parked are read from the same place, so there is no second path to get
// wrong. An outcome kept in the awaitable would be invisible to the first case
// and would silently report whatever it was initialised to.
class quic_connection_awaitable_t
{
public:
  explicit quic_connection_awaitable_t(detail::quic_op_t *op)
    : _op(op)
  {
  }

  quic_connection_awaitable_t(const quic_connection_awaitable_t &) = delete;
  quic_connection_awaitable_t &operator=(const quic_connection_awaitable_t &) = delete;

  quic_connection_awaitable_t(quic_connection_awaitable_t &&other) noexcept
    : _op(std::exchange(other._op, nullptr))
  {
  }

  quic_connection_awaitable_t &operator=(quic_connection_awaitable_t &&other) noexcept
  {
    if (this != &other)
    {
      detail::quic_op_release(_op);
      _op = std::exchange(other._op, nullptr);
    }
    return *this;
  }

  ~quic_connection_awaitable_t()
  {
    if (_op == nullptr)
    {
      return;
    }
    // Clearing the continuation is the load-bearing half. This destructor runs
    // on the ordinary path, where it is redundant, and also when the frame it
    // was parked in is destroyed -- and there a continuation left behind is a
    // handle the endpoint would later resume into storage that has gone.
    _op->continuation = {};
    detail::quic_op_release(_op);
  }

  [[nodiscard]] bool await_ready() const noexcept
  {
    return _op == nullptr || _op->resolved;
  }

  void await_suspend(std::coroutine_handle<> continuation) noexcept
  {
    _op->continuation = continuation;
  }

  [[nodiscard]] std::expected<quic_connection_t, error_t> await_resume() noexcept
  {
    if (_op == nullptr)
    {
      return std::unexpected(error_t{.code = vio_quic_endpoint_closed, .msg = "the endpoint was released"});
    }
    if (_op->failed)
    {
      return std::unexpected(_op->failure);
    }
    return quic_connection_t{_op->result};
  }

private:
  detail::quic_op_t *_op = nullptr;
};

namespace detail
{
// -----------------------------------------------------------------------------
// The beat
// -----------------------------------------------------------------------------
//
// Why a prepare handle rather than a check handle. libuv's iteration is
//
//   pending -> idle -> PREPARE -> poll (blocks) -> pending -> CHECK
//     -> closing handles -> update time -> TIMERS
//
// verified in 3rdparty/libuv-v1.51.0/src/unix/core.c. Read it with the wake
// sources marked. A coroutine made runnable by an arriving datagram becomes so
// during poll, and nothing blocks between the check that follows and the
// prepare that opens the next iteration -- so on that path the two phases are
// worth the same and the beat costs no round trip either way.
//
// Timers decide it. They run at the end of the iteration, after check, and the
// endpoint's own ticker fires there -- and it is that tick which flushes every
// connection, latches an idle timeout and fires the gone hook. So a connection
// ending with no traffic on it becomes runnable in the timer phase and nowhere
// else, and prepare is the next callback phase with nothing blocking in
// between, where check is reached only after another poll.
//
// An idle handle is disqualified outright: uv__backend_timeout returns zero
// while any idle handle is active, so an always-started one turns the loop into
// a spin. Neither prepare nor check appears in that function, which is what
// makes arming this permanently and paying one predicate per turn safer than
// arming it conditionally -- and step 3 of this work found that making a
// periodic mechanism in this endpoint conditional produced both a spin and a
// stall.
// Moves an operation from the waiting list to the resumable one, keeping the
// endpoint's hold, which the beat drops after resuming. Nothing here resumes:
// every caller is standing inside the transport's flush.
inline void quic_op_ready(quic_endpoint_state_t &self, quic_op_t *op);

constexpr int quic_beat_max_passes = 4;

[[nodiscard]] inline bool quic_beat_has_work(const quic_endpoint_state_t &self)
{
  return !self.ready_ops.empty() || !self.pending.empty() || !self.dirty.empty() || self.flush_all;
}

inline void quic_mark_pending(quic_endpoint_state_t &self, ref_ptr_t<quic_connection_state_t> state)
{
  if (state->queued)
  {
    return;
  }
  state->queued = true;
  self.pending.push_back(std::move(state));
}

inline void quic_mark_dirty(quic_endpoint_state_t &self, ref_ptr_t<quic_connection_state_t> state)
{
  if (state->dirty)
  {
    return;
  }
  state->dirty = true;
  self.dirty.push_back(std::move(state));
}

inline void quic_drain_connection(ref_ptr_t<quic_connection_state_t> &state)
{
  state->queued = false;
  if (state->ready.ref_counted() != nullptr)
  {
    quic_milestone_drain(state->ready.data());
  }
  if (state->closed.ref_counted() != nullptr)
  {
    quic_milestone_drain(state->closed.data());
  }
}

// Resumes everything that has become runnable.
//
// Every list is taken out of the state before anything is resumed, so a resumed
// coroutine may dial, close a connection, or drop the last handle to one
// without invalidating the walk. The connection entries are held by reference
// rather than by pointer, so an entry the draining latch has already erased
// from the registry is still alive when the beat reaches it.
inline void quic_beat_resume(quic_endpoint_state_t &self)
{
  auto ops = std::exchange(self.ready_ops, {});
  for (auto *op : ops)
  {
    op->endpoint = nullptr;
    // Reset before anything is resumed: the resuming coroutine owns the token
    // and may destroy it.
    op->cancel_registration.reset();
    quic_op_dispatch(op);
  }

  auto pending = std::exchange(self.pending, {});
  for (auto &state : pending)
  {
    quic_drain_connection(state);
  }
}

// Pushes whatever the resumed coroutines wrote onto the socket, in the same
// turn rather than the next one.
inline void quic_beat_flush(quic_endpoint_state_t &self)
{
  if (!self.transport.has_value())
  {
    return;
  }
  if (std::exchange(self.flush_all, false))
  {
    (void)self.transport->flush();
  }
  auto dirty = std::exchange(self.dirty, {});
  for (auto &state : dirty)
  {
    state->dirty = false;
    if (state->transport == nullptr)
    {
      continue; // a tombstone has nothing left to send
    }
    (void)self.transport->flush(*state->transport);
  }
}

inline void quic_beat_cb(uv_prepare_t *handle)
{
  // Borrowed, and deliberately not null-checked: libuv fires no callback for a
  // handle after uv_close, which is the guarantee the borrow rests on. A null
  // test would not even be the right one, because the reference count
  // overwrites this field with its own pointer before closing.
  auto *self = static_cast<quic_endpoint_state_t *>(handle->data);
  if (self->closing)
  {
    return;
  }
  // Bounded: resuming a coroutine can make more work, and an application that
  // always makes more would otherwise starve the loop's I/O inside one
  // callback. Whatever is left waits for the next turn, which the endpoint's
  // own ticker guarantees arrives.
  for (int pass = 0; pass < quic_beat_max_passes && quic_beat_has_work(*self); ++pass)
  {
    quic_beat_resume(*self);
    quic_beat_flush(*self);
  }
}

// -----------------------------------------------------------------------------
// The hooks
// -----------------------------------------------------------------------------
//
// All three fire from inside the transport's flush, which is the one place
// nothing may be resumed. They record and mark; the beat does the rest.

// Fires once per connection, from the transport's flush, when the handshake
// has completed -- for connections this endpoint dialled as well as ones that
// arrived, which is why the role has to be read here rather than assumed.
//
// Registration only, at this step. The sort between a waiting dial and the
// accept queue arrives with the operations that need it.
inline void quic_hook_connection(quic_endpoint_state_t &self, vio::quic::connection_t &connection)
{
  if (self.closing)
  {
    return;
  }
  auto found = self.by_connection.find(&connection);
  if (found == self.by_connection.end())
  {
    auto state = ref_ptr_t<quic_connection_state_t>(&self, &connection, connection.role());
    found = self.by_connection.emplace(&connection, std::move(state)).first;
  }
  auto state = found->second;
  state->handshake_reached = true;
  state->alpn = std::string(connection.selected_alpn());
  if (state->ready.ref_counted() != nullptr)
  {
    quic_milestone_reach(state->ready.data(), {});
  }
  if (state->pending_dial != nullptr)
  {
    auto *op = std::exchange(state->pending_dial, nullptr);
    quic_op_finish(*op, state);
    quic_op_ready(self, op);
  }
  quic_mark_pending(self, state);
}

inline void quic_hook_activity(quic_endpoint_state_t &self, vio::quic::connection_t &connection)
{
  const auto found = self.by_connection.find(&connection);
  if (found == self.by_connection.end())
  {
    return;
  }
  quic_mark_pending(self, found->second);
}

// The tombstone point. Everything an application can still ask after a
// connection has ended is latched here, because the reap a draining period
// later frees the connection_t with no notification at all.
inline void quic_sever(quic_endpoint_state_t &self, ref_ptr_t<quic_connection_state_t> state, const std::expected<void, error_t> &ending)
{
  if (state->severed)
  {
    return;
  }
  state->severed = true;
  if (state->transport != nullptr)
  {
    state->close_reason = state->transport->close_reason();
    state->stats = quic_read_stats(*state->transport);
    if (state->alpn.empty())
    {
      state->alpn = std::string(state->transport->selected_alpn());
    }
  }
  // Nulled here rather than at the reap, which nothing tells us about: a
  // pointer kept past this point is one nothing will ever say to drop, and the
  // next connection_t may be allocated at the same address.
  state->transport = nullptr;

  if (state->ready.ref_counted() != nullptr)
  {
    quic_milestone_reach(state->ready.data(), ending);
  }
  if (state->closed.ref_counted() != nullptr)
  {
    quic_milestone_reach(state->closed.data(), ending);
  }
  if (state->pending_dial != nullptr)
  {
    auto *op = std::exchange(state->pending_dial, nullptr);
    if (ending.has_value())
    {
      quic_op_finish(*op, state);
    }
    else
    {
      quic_op_finish(*op, ending.error());
    }
    quic_op_ready(self, op);
  }
  quic_mark_pending(self, state);
}

inline void quic_hook_gone(quic_endpoint_state_t &self, vio::quic::connection_t &connection)
{
  const auto found = self.by_connection.find(&connection);
  if (found == self.by_connection.end())
  {
    return; // arrived and ended before anything registered it
  }
  auto state = found->second;
  // Erased while the pointer still names this connection.
  self.by_connection.erase(found);

  const int code = quic_classify_ending(connection.close_reason(), state->handshake_reached, state->closed_locally, connection.reset_by_peer(), connection.version_negotiation_failed());
  std::expected<void, error_t> ending;
  if (code != 0)
  {
    const auto reason = connection.close_reason();
    ending = std::unexpected(error_t{.code = code, .msg = reason.has_value() && !reason->reason.empty() ? reason->reason : std::string("the connection ended")});
  }
  quic_sever(self, state, ending);

  if (self.shutdown_active && self.shutdown_outstanding > 0)
  {
    --self.shutdown_outstanding;
  }
}

// -----------------------------------------------------------------------------
// Teardown
// -----------------------------------------------------------------------------
//
// What releasing the last handle does, and the reason nothing else in this
// layer holds a strong reference to the endpoint: this has to be reachable, and
// an awaitable or a connection that kept the endpoint alive would stop it.
inline void quic_teardown(quic_endpoint_state_t &self)
{
  // First, before anything is resumed. Every entry point tests this rather than
  // whether the transport is still there, because the transport outlives most
  // of what follows -- and a coroutine resumed to be told the endpoint is going
  // away could otherwise dial and park on something nothing will ever resolve.
  self.closing = true;

  // The driver's frame holds a reference to the transport and owns the datagram
  // reader. Cancelling finishes both synchronously: cancellation_t runs its
  // callbacks inline, the reader's cancel delivers inline, and a cancelled
  // sleep resumes inline -- so by the time this returns, run() has unwound.
  self.driver_stop.cancel();
  self.driver.reset();

  const error_t released{.code = vio_quic_endpoint_closed, .msg = "the endpoint was released"};

  auto registry = std::exchange(self.by_connection, {});
  for (auto &entry : registry)
  {
    entry.second->endpoint = nullptr;
    quic_sever(self, entry.second, std::unexpected(released));
  }
  self.accept_queue.clear();

  auto live = std::exchange(self.live_ops, {});
  for (auto *op : live)
  {
    quic_op_finish(*op, released);
    self.ready_ops.push_back(op);
  }

  if (self.shutdown.ref_counted() != nullptr)
  {
    quic_milestone_reach(self.shutdown.data(), std::unexpected(released));
  }

  // Everything is latched; now resume. The transport is still alive here, so a
  // resumed coroutine reading a tombstone finds what it latched, and nothing it
  // can call will start new work because closing is already set.
  auto ops = std::exchange(self.ready_ops, {});
  for (auto *op : ops)
  {
    op->endpoint = nullptr;
    op->cancel_registration.reset();
    quic_op_dispatch(op);
  }
  auto pending = std::exchange(self.pending, {});
  for (auto &state : pending)
  {
    quic_drain_connection(state);
  }
  if (self.shutdown.ref_counted() != nullptr)
  {
    quic_milestone_drain(self.shutdown.data());
  }

  self.dirty.clear();
  self.transport.reset();
}
} // namespace detail

// -----------------------------------------------------------------------------
// Creating an endpoint
// -----------------------------------------------------------------------------

// The context decides what the endpoint is for: one built for a server answers,
// one built for a client dials. It must outlive the endpoint, which borrows it.
//
// Nothing is bound and nothing is read yet. libuv makes a UDP socket lazily and
// whoever touches it first fixes its address family, so an endpoint that
// started reading before it knew where it was going would be pinned to IPv4 --
// which is why binding and dialling are the only things that create it.
[[nodiscard]] inline std::expected<quic_endpoint_t, error_t> quic_endpoint_create(event_loop_t &loop, const vio::quic::tls_context_t &context, const quic_config_t &config = {});

// The same, for an endpoint that both answers and dials on one port. Either may
// be null, which is how a dial-only or an answer-only endpoint is expressed.
[[nodiscard]] inline std::expected<quic_endpoint_t, error_t> quic_endpoint_create(event_loop_t &loop, const vio::quic::tls_context_t *server_context, const vio::quic::tls_context_t *client_context, const quic_config_t &config = {});

namespace detail
{
[[nodiscard]] inline std::expected<quic_endpoint_t, error_t> quic_endpoint_build(event_loop_t &loop, std::expected<vio::quic::endpoint_t, error_t> transport, const quic_config_t &config)
{
  if (!transport.has_value())
  {
    return std::unexpected(transport.error());
  }

  quic_endpoint_t endpoint{ref_ptr_t<quic_endpoint_state_t>(loop, std::move(*transport), config)};
  auto *self = &endpoint.handle.data();
  self->rc = endpoint.handle.ref_counted();

  if (const int started = uv_prepare_init(loop.loop(), &self->beat); started < 0)
  {
    return std::unexpected(error_t{.code = started, .msg = uv_strerror(started)});
  }
  // Registered with the reference count so that the close is issued once, when
  // the count reaches zero, on the same terms as the socket. The data pointer
  // is borrowed and not a parked reference, for the reason timer_impl.h gives:
  // a reference held in a registered handle keeps the count above zero forever
  // and the close is never issued at all.
  endpoint.handle.register_handle(&self->beat);
  self->beat.data = self;
  (void)uv_prepare_start(&self->beat, quic_beat_cb);
  // Unreferenced, so that an endpoint nobody is using does not by itself keep
  // the loop alive. An endpoint created and never bound has no descriptor --
  // libuv makes the socket lazily -- so without this the beat would be the only
  // active handle and run() would never return.
  uv_unref(reinterpret_cast<uv_handle_t *>(&self->beat));

  self->transport->on_connection([self](vio::quic::connection_t &connection) { quic_hook_connection(*self, connection); });
  self->transport->on_activity([self](vio::quic::connection_t &connection) { quic_hook_activity(*self, connection); });
  self->transport->on_connection_gone([self](vio::quic::connection_t &connection) { quic_hook_gone(*self, connection); });

  endpoint.handle.on_destroy([self]() { quic_teardown(*self); });
  return endpoint;
}
} // namespace detail

inline std::expected<quic_endpoint_t, error_t> quic_endpoint_create(event_loop_t &loop, const vio::quic::tls_context_t &context, const quic_config_t &config)
{
  auto transport = vio::quic::endpoint_t::create(loop, context, config.transport);
  return detail::quic_endpoint_build(loop, std::move(transport), config);
}

inline std::expected<quic_endpoint_t, error_t> quic_endpoint_create(event_loop_t &loop, const vio::quic::tls_context_t *server_context, const vio::quic::tls_context_t *client_context, const quic_config_t &config)
{
  auto transport = vio::quic::endpoint_t::create(loop, server_context, client_context, config.transport);
  return detail::quic_endpoint_build(loop, std::move(transport), config);
}

namespace detail
{
// Starts the read loop, once. Called by whatever first gives the socket an
// address family -- a bind, or a dial -- and never before, because libuv makes
// the UDP socket lazily and fixes its family on first touch.
inline std::expected<void, error_t> quic_start_driver(quic_endpoint_state_t &self)
{
  if (self.driver_started || self.closing)
  {
    return {};
  }
  self.driver_started = true;
  self.driver.emplace(self.transport->run(&self.driver_stop));
  if (self.driver->done())
  {
    // task_t is eager, so run() has already executed through the reader's
    // creation -- uv_poll_start is synchronous -- down to its first co_await on
    // this very stack. A reader it could not create is reported with a bare
    // co_return, so being done on the first turn is the only signal there is,
    // and without this a bind would report success on an endpoint that will
    // never read a byte.
    self.driver.reset();
    self.driver_started = false;
    return std::unexpected(error_t{.code = -1, .msg = "the endpoint could not start reading its socket"});
  }
  return {};
}
} // namespace detail

// -----------------------------------------------------------------------------
// Binding
// -----------------------------------------------------------------------------

// Binds the socket and starts reading it, in that order, because it is the
// sockaddr that says which address family the socket must have.
//
// A server binds; a client may skip this and let the OS choose a port at its
// first dial, exactly as with udp_bind. Binding a dial-only endpoint is legal
// and not a mistake -- pinning a source port is ordinary client behaviour, and
// refusing it for symmetry with accept would be a trap rather than a check.
[[nodiscard]] inline std::expected<void, error_t> quic_endpoint_bind(quic_endpoint_t &endpoint, const sockaddr *address)
{
  if (endpoint.handle.ref_counted() == nullptr)
  {
    return std::unexpected(error_t{.code = -1, .msg = "the endpoint names nothing"});
  }
  auto &self = endpoint.handle.data();
  if (self.closing)
  {
    return std::unexpected(error_t{.code = vio_quic_endpoint_closed, .msg = "the endpoint was released"});
  }
  if (auto bound = self.transport->bind(address); !bound)
  {
    return bound;
  }
  return detail::quic_start_driver(self);
}

// One socket that answers both IPv6 and IPv4-mapped peers, falling back to
// 0.0.0.0 on a host with no IPv6 -- udp_bind_dual_stack's rule, applied here
// rather than reused, because endpoint_t owns its socket and hands out only
// bind().
//
// Port 0 asks the OS to choose, which is what a test wants; read it back with
// quic_endpoint_local_port.
[[nodiscard]] inline std::expected<void, error_t> quic_endpoint_bind(quic_endpoint_t &endpoint, std::uint16_t port)
{
  sockaddr_in6 any6 = {};
  if (uv_ip6_addr("::", static_cast<int>(port), &any6) == 0)
  {
    if (auto bound = quic_endpoint_bind(endpoint, reinterpret_cast<const sockaddr *>(&any6)); bound.has_value())
    {
      return bound;
    }
  }
  sockaddr_in any4 = {};
  if (const int made = uv_ip4_addr("0.0.0.0", static_cast<int>(port), &any4); made < 0)
  {
    return std::unexpected(error_t{.code = made, .msg = uv_strerror(made)});
  }
  return quic_endpoint_bind(endpoint, reinterpret_cast<const sockaddr *>(&any4));
}

// The port actually in use, which is the only way to learn it after binding to
// zero.
[[nodiscard]] inline std::expected<std::uint16_t, error_t> quic_endpoint_local_port(const quic_endpoint_t &endpoint)
{
  if (endpoint.handle.ref_counted() == nullptr)
  {
    return std::unexpected(error_t{.code = -1, .msg = "the endpoint names nothing"});
  }
  const auto &self = endpoint.handle.data();
  if (!self.transport.has_value())
  {
    return std::unexpected(error_t{.code = vio_quic_endpoint_closed, .msg = "the endpoint was released"});
  }
  return self.transport->local_port();
}

namespace detail
{
inline void quic_op_ready(quic_endpoint_state_t &self, quic_op_t *op)
{
  const auto found = std::find(self.live_ops.begin(), self.live_ops.end(), op);
  if (found == self.live_ops.end())
  {
    return; // already made ready, or never registered
  }
  self.live_ops.erase(found);
  self.ready_ops.push_back(op);
}

// Closes a connection this layer asked to close, which is the only way to tell
// a clean local close from an idle timeout: the transport records both with the
// same error code, the same application flag and the same from_peer.
inline void quic_close_locally(quic_endpoint_state_t &self, ref_ptr_t<quic_connection_state_t> state, std::uint64_t code, std::string_view reason, bool application)
{
  if (state->transport == nullptr)
  {
    return;
  }
  state->closed_locally = true;
  state->transport->close(code, reason, application);
  quic_mark_dirty(self, std::move(state));
}
} // namespace detail

// The awaitable a dial and an accept both return. Two names for one type,
// because "future" is what a thing resolved by an arrival is called elsewhere
// in vio and "awaitable" is what a thing resolved by a request is called, and
// the two operations really are the same shape underneath.
using quic_connect_awaitable_t = quic_connection_awaitable_t;
using quic_accept_future_t = quic_connection_awaitable_t;

// -----------------------------------------------------------------------------
// Dialling
// -----------------------------------------------------------------------------

// Dials, and resolves when the handshake completes or fails. Connected means
// what it means for ssl_client_connect -- the certificate has verified, an ALPN
// has been agreed and the peer's transport parameters have arrived, so a stream
// opened on the result will have credit -- and not that the first Initial has
// been queued.
//
// A ticket kept from an earlier connection to this peer shortens the handshake.
// Read one with quic_connection_resumption_ticket; a ticket that will not parse
// is a full handshake rather than a failure to connect.
//
// Every synchronous failure comes back on the same awaitable, pre-resolved and
// never suspending -- a bad address as the raw libuv code, a dial on an endpoint
// with no client context as a sentence. That is the tcp_connect shape, and it
// means a caller has one place to look rather than two.
[[nodiscard]] inline quic_connect_awaitable_t quic_endpoint_connect(quic_endpoint_t &endpoint, const sockaddr *address, std::string_view server_name, std::span<const std::uint8_t> resumption_ticket = {})
{
  const auto failed = [](error_t reason)
  {
    auto *op = detail::quic_op_create(nullptr);
    detail::quic_op_finish(*op, std::move(reason));
    return quic_connect_awaitable_t{op};
  };

  if (endpoint.handle.ref_counted() == nullptr)
  {
    return failed(error_t{.code = -1, .msg = "the endpoint names nothing"});
  }
  auto &self = endpoint.handle.data();
  if (self.closing)
  {
    return failed(error_t{.code = vio_quic_endpoint_closed, .msg = "the endpoint was released"});
  }

  auto *op = detail::quic_op_create(&self);
  self.live_ops.push_back(op);
  quic_connect_awaitable_t out{op};

  // endpoint_t::connect fixes the socket's address family, so a dial that
  // cannot happen must be refused before it -- otherwise an endpoint built
  // without a client context would be pinned to whatever family the impossible
  // dial named, and a later bind would fail for a reason nothing explains.
  auto dialled = self.transport->connect(address, server_name, resumption_ticket);
  if (!dialled)
  {
    detail::quic_op_finish(*op, dialled.error());
    detail::quic_op_ready(self, op);
    return out;
  }
  auto *connection = self.transport->connection(*dialled);
  if (connection == nullptr)
  {
    detail::quic_op_finish(*op, error_t{.code = -1, .msg = "the dialled connection was gone before it was returned"});
    detail::quic_op_ready(self, op);
    return out;
  }

  // After the dial, never before: the dial is what gave the socket a family,
  // and starting the read loop first would pin it to IPv4.
  if (auto started = detail::quic_start_driver(self); !started)
  {
    connection->close(vio::quic::transport_error_internal, "the endpoint could not start reading", false);
    (void)self.transport->flush(*connection);
    detail::quic_op_finish(*op, started.error());
    detail::quic_op_ready(self, op);
    return out;
  }

  // Registered by pointer, before anything else can look one up. This is what
  // sorts a dial from an arrival: on_connection fires for dialled connections
  // too, and only a registry keyed on connection_t* keeps a peer's own outbound
  // connections out of its accept queue.
  auto entry = ref_ptr_t<detail::quic_connection_state_t>(&self, connection, vio::quic::tls_role_t::client);
  entry->pending_dial = op;
  self.by_connection.emplace(connection, entry);

  // endpoint_t::connect flushes before it returns, so this connection's
  // draining latch -- and with it the gone hook -- may already have fired for a
  // connection nothing had registered yet, in which case it will never fire
  // again. Nothing can drive a fresh dial to closed today; the registration is
  // simply not allowed to assume it precedes the first hook.
  if (connection->state() == vio::quic::connection_state_t::closed)
  {
    detail::quic_sever(self, entry, std::unexpected(error_t{.code = vio_quic_handshake_failed, .msg = "the connection ended before it was dialled"}));
  }
  return out;
}
} // namespace vio
