#include <coroutine>
#include <optional>
#include <doctest/doctest.h>

#include <vio/operation/quic_endpoint.h>

// The coroutine QUIC API, built up in the order its pieces can be tested.
//
// This file starts where the header does: nothing here drives a socket yet, and
// what it checks is that the declarations hold together at all. That is not a
// formality. ref_ptr_t<T> instantiates T's storage in its destructor, so every
// state struct has to be complete before any handle naming it is declared, and
// the handles have to be complete before the operations that return them --
// which makes the physical order of that header load-bearing rather than
// stylistic. A file that compiles is the evidence.

TEST_SUITE("quic coroutine")
{
TEST_CASE("a handle that names nothing is well formed")
{
  using namespace vio;

  // Default construction has to be reachable and has to produce something that
  // can be asked about safely, because that is what every entry point tests
  // before it dereferences: ref_ptr_t::data() dereferences unconditionally, so
  // a null handle reaching one of them is a crash rather than an error.
  quic_endpoint_t endpoint;
  quic_connection_t connection;
  CHECK(endpoint.handle.ref_counted() == nullptr);
  CHECK(connection.handle.ref_counted() == nullptr);

  // And they are movable, since every factory returns one by value.
  quic_endpoint_t moved_endpoint = std::move(endpoint);
  quic_connection_t moved_connection = std::move(connection);
  CHECK(moved_endpoint.handle.ref_counted() == nullptr);
  CHECK(moved_connection.handle.ref_counted() == nullptr);
}

TEST_CASE("the configuration carries working transport parameters")
{
  using namespace vio;

  // The whole point of the defaults landing first: an application that
  // configures nothing gets a connection that can carry data. If this ever
  // reads zero again, every program written against this API completes its
  // handshake and then silently transfers nothing.
  const quic_config_t config;
  const auto &parameters = config.transport.connection.transport_parameters;
  CHECK(parameters.initial_max_data > 0);
  CHECK(parameters.initial_max_stream_data_bidi_remote > 0);
  CHECK(parameters.initial_max_streams_bidi > 0);
  CHECK(config.accept_backlog > 0);
}

// The transport records an idle timeout and a clean local close identically --
// error code zero, not an application code, not from the peer -- so the only
// thing that can separate them is knowing which of this layer's own calls did
// the closing. Getting it backwards reports every deliberate close as a
// timeout, which is the difference between "the peer went away" and "we said
// goodbye" in every log line an application writes.
TEST_CASE("an ending is classified by who ended it")
{
  using namespace vio;
  using vio::quic::connection_close_t;

  const std::optional<connection_close_t> nothing;

  SUBCASE("a close this endpoint made is clean")
  {
    CHECK(quic_classify_ending(nothing, true, true, false, false) == 0);
  }

  SUBCASE("the same silence, not closed by us, is an idle timeout")
  {
    CHECK(quic_classify_ending(nothing, true, false, false, false) == vio_quic_idle_timeout);
  }

  SUBCASE("a peer that closed with a code reports it")
  {
    const std::optional<connection_close_t> refused{connection_close_t{.error_code = 42, .application = true, .reason = "no", .from_peer = true}};
    CHECK(quic_classify_ending(refused, true, false, false, false) == vio_quic_connection_closed);
  }

  SUBCASE("a peer that closed cleanly is not an error")
  {
    const std::optional<connection_close_t> bye{connection_close_t{.error_code = 0, .application = true, .reason = "done", .from_peer = true}};
    CHECK(quic_classify_ending(bye, true, false, false, false) == 0);
  }

  SUBCASE("anything before the handshake completed is a failed handshake")
  {
    // Including a close carrying a code: a caller holding a dial only wants to
    // know it produced nothing usable, and the close reason is still there for
    // whoever needs which of the four ways it failed.
    const std::optional<connection_close_t> alert{connection_close_t{.error_code = 0x178, .application = false, .reason = "bad certificate", .from_peer = true}};
    CHECK(quic_classify_ending(alert, false, false, false, false) == vio_quic_handshake_failed);
    CHECK(quic_classify_ending(nothing, false, false, false, false) == vio_quic_handshake_failed);
  }

  SUBCASE("a stateless reset and a version mismatch outrank everything")
  {
    // Both are read from their own accessors rather than from the close
    // reason, and both can be true while the handshake never completed -- so
    // they are tested before the handshake gate, or a stateless reset would be
    // reported as an ordinary failed dial.
    CHECK(quic_classify_ending(nothing, false, false, true, false) == vio_quic_stateless_reset);
    CHECK(quic_classify_ending(nothing, false, false, false, true) == vio_quic_version_unsupported);
  }
}

// The codes are published, so they are pinned. A renumbering that collided with
// vio's other subsystems -- TLS at 0x715c00 and cancellation at 0xca9ce1 -- or
// with the block reserved for streams would be invisible until an application
// branched on the wrong one.
TEST_CASE("the error codes are distinct and stay where they were published")
{
  using namespace vio;

  CHECK(vio_quic_connection_closed == 0x9c1c05);
  CHECK(vio_quic_idle_timeout == 0x9c1c06);
  CHECK(vio_quic_handshake_failed == 0x9c1c07);
  CHECK(vio_quic_stateless_reset == 0x9c1c08);
  CHECK(vio_quic_version_unsupported == 0x9c1c09);
  CHECK(vio_quic_endpoint_closed == 0x9c1c0a);
  CHECK(vio_quic_busy == 0x9c1c0b);

  // 0x9c1c01 to 0x9c1c04 belong to quic_stream.h and nothing here uses them.
  CHECK(vio_quic_connection_closed > 0x9c1c04);
  // And none of them is any other subsystem's.
  CHECK(vio_quic_connection_closed != vio_cancelled);
  CHECK(vio_quic_endpoint_closed != vio_cancelled);
}
}

// The milestone, with no endpoint under it. Everything below is reachable
// without a socket, a loop or a connection, which is the point of building it
// first: the shapes that go wrong here go wrong the same way when a whole
// transport is stacked on top, and are far harder to see through one.

namespace
{
// A coroutine that waits on a milestone and records what it was told. Takes
// everything by parameter: task_t is eager, so a lambda's captures are gone by
// the time the body first suspends.
vio::detached_task_t await_milestone(vio::quic_milestone_t milestone, bool &woke, bool &failed)
{
  auto outcome = co_await milestone;
  woke = true;
  failed = !outcome.has_value();
}
} // namespace

TEST_SUITE("quic coroutine milestone")
{
TEST_CASE("a milestone reached before anyone waits answers without suspending")
{
  using namespace vio;

  ref_ptr_t<detail::quic_milestone_state_t> slot;
  detail::quic_milestone_reach(slot.data(), {});

  bool woke = false;
  bool failed = true;
  await_milestone(quic_milestone_t{slot}, woke, failed);

  // No suspension, so it is already done by the time the call returns. An
  // await after the fact that parked would be a coroutine nothing will ever
  // resume, which is the shape of every hang in this layer.
  CHECK(woke);
  CHECK_FALSE(failed);
}

TEST_CASE("a waiter is resumed when the milestone is reached")
{
  using namespace vio;

  ref_ptr_t<detail::quic_milestone_state_t> slot;
  bool woke = false;
  bool failed = false;
  await_milestone(quic_milestone_t{slot}, woke, failed);
  CHECK_FALSE(woke);

  detail::quic_milestone_reach(slot.data(), std::unexpected(error_t{.code = vio_quic_idle_timeout, .msg = "idle"}));
  CHECK(woke);
  CHECK(failed);
}

TEST_CASE("every waiter is resumed, and the first reason is the one kept")
{
  using namespace vio;

  ref_ptr_t<detail::quic_milestone_state_t> slot;
  bool first_woke = false;
  bool second_woke = false;
  bool first_failed = false;
  bool second_failed = false;
  await_milestone(quic_milestone_t{slot}, first_woke, first_failed);
  await_milestone(quic_milestone_t{slot}, second_woke, second_failed);

  detail::quic_milestone_reach(slot.data(), std::unexpected(error_t{.code = vio_quic_connection_closed, .msg = "peer closed"}));
  CHECK(first_woke);
  CHECK(second_woke);
  CHECK(first_failed);
  CHECK(second_failed);

  // Reaching it again changes nothing. A connection that ended for one reason
  // must not be reclassified by a later pass over it, and the second call has
  // to be harmless because more than one thing notices an ending.
  detail::quic_milestone_reach(slot.data(), {});
  CHECK(slot->reached);
  CHECK_FALSE(slot->result.has_value());
  CHECK(slot->result.error().code == vio_quic_connection_closed);

  // And a waiter arriving afterwards gets the same answer rather than parking.
  bool late_woke = false;
  bool late_failed = false;
  await_milestone(quic_milestone_t{slot}, late_woke, late_failed);
  CHECK(late_woke);
  CHECK(late_failed);
}

// The case that matters most, and the one a design review will not catch: an
// awaitable destroyed while its node is still linked would leave the list
// pointing into storage that is about to go, and the next reach would resume a
// coroutine that no longer exists.
//
// Tested against the awaiter directly rather than by abandoning a coroutine,
// because vio's task types cannot abandon one: detached_task_t returns an empty
// object and owns no frame at all, and ~task_t destroys a frame only when it is
// already done, so dropping a suspended one leaks it rather than destroying it.
// The unlink is defensive against a frame destroyed by any other means, and
// this is the honest way to exercise it.
TEST_CASE("an awaitable destroyed while linked takes itself out of the list")
{
  using namespace vio;

  ref_ptr_t<detail::quic_milestone_state_t> slot;
  {
    quic_milestone_t::awaiter_t awaiter{slot};
    CHECK_FALSE(awaiter.await_ready());
    awaiter.await_suspend(std::noop_coroutine());
    CHECK(slot->waiters != nullptr);
  }
  CHECK(slot->waiters == nullptr);

  // So reaching it now walks an empty list rather than freed storage.
  detail::quic_milestone_reach(slot.data(), {});
  CHECK(slot->reached);
}

TEST_CASE("unlinking from the middle keeps the list whole")
{
  using namespace vio;

  // The drain always takes the head, but an abandoned awaitable can be
  // anywhere -- so the general case has to hold, not just the head case.
  ref_ptr_t<detail::quic_milestone_state_t> slot;
  detail::quic_waiter_t first;
  detail::quic_waiter_t second;
  detail::quic_waiter_t third;
  detail::quic_milestone_link(slot.data(), first, std::noop_coroutine());
  detail::quic_milestone_link(slot.data(), second, std::noop_coroutine());
  detail::quic_milestone_link(slot.data(), third, std::noop_coroutine());

  // Newest at the head.
  CHECK(slot->waiters == &third);

  detail::quic_milestone_unlink(second);
  CHECK(slot->waiters == &third);
  CHECK(third.next == &first);
  CHECK(first.prev == &third);
  // And the node itself is left inert, so a second unlink is harmless -- which
  // it has to be, because the drain unlinks a node its awaitable will also
  // unlink when it is destroyed.
  CHECK(second.slot == nullptr);
  detail::quic_milestone_unlink(second);
  CHECK(slot->waiters == &third);

  detail::quic_milestone_unlink(third);
  CHECK(slot->waiters == &first);
  detail::quic_milestone_unlink(first);
  CHECK(slot->waiters == nullptr);
}

TEST_CASE("a milestone that names nothing resolves rather than hanging")
{
  using namespace vio;

  // What an accessor returns for a connection this endpoint never had, or one
  // whose state has already gone. Parking on it would be a coroutine with
  // nothing to wake it.
  bool woke = false;
  bool failed = false;
  await_milestone(quic_milestone_t{ref_ptr_t<detail::quic_milestone_state_t>::null()}, woke, failed);
  CHECK(woke);
  CHECK(failed);
}
}

// The per-call operation, still with no endpoint under it. What matters here is
// that an operation and the coroutine awaiting it can let go of each other in
// either order, because both orders really happen: an accept resolves the
// instant a connection is already queued, and a dial can be abandoned while
// still in flight.

namespace
{
// Awaits an operation and records what came back. The connection handle is kept
// so a test can check the operation's result really reached the caller.
vio::detached_task_t await_operation(vio::quic_connection_awaitable_t awaitable, bool &woke, bool &failed, int &code)
{
  auto outcome = co_await std::move(awaitable);
  woke = true;
  failed = !outcome.has_value();
  code = outcome.has_value() ? 0 : outcome.error().code;
}
} // namespace

TEST_SUITE("quic coroutine operation")
{
TEST_CASE("an operation resolved before anyone awaits it does not suspend")
{
  using namespace vio;

  // Settled with a failure, which is the shape of a dial refused before it
  // ever went out.
  auto *op = detail::quic_op_create(nullptr);
  detail::quic_op_finish(*op, error_t{.code = vio_quic_handshake_failed, .msg = "no"});

  bool woke = false;
  bool failed = false;
  int code = 0;
  await_operation(quic_connection_awaitable_t{op}, woke, failed, code);
  CHECK(woke);
  CHECK(failed);

  // The endpoint's hold is still outstanding; dropping it frees the operation.
  detail::quic_op_dispatch(op);
}

TEST_CASE("an operation resolved while a coroutine is parked resumes it")
{
  using namespace vio;

  auto *op = detail::quic_op_create(nullptr);
  bool woke = false;
  bool failed = false;
  int code = 0;
  await_operation(quic_connection_awaitable_t{op}, woke, failed, code);
  CHECK_FALSE(woke);

  detail::quic_op_finish(*op, error_t{.code = vio_quic_idle_timeout, .msg = "idle"});
  CHECK_FALSE(woke);

  // Settling records; the beat resumes. Nothing is woken until something
  // dispatches, because whatever settled it was standing inside the read loop.
  detail::quic_op_dispatch(op);
  CHECK(woke);
  CHECK(failed);
  CHECK(code == vio_quic_idle_timeout);
}

// The first of the two orders that a boolean pair cannot express: abandoned
// while still in flight, and resolved afterwards. The operation has to survive
// the abandonment, because the endpoint still has it, and it must not resume
// the frame that has gone.
TEST_CASE("an operation abandoned before it resolves is not resumed")
{
  using namespace vio;

  auto *op = detail::quic_op_create(nullptr);
  {
    // Destroyed without ever being awaited, which is what an abandoned frame
    // amounts to from the operation's side.
    quic_connection_awaitable_t awaitable{op};
    awaitable.await_suspend(std::noop_coroutine());
    CHECK(op->continuation);
  }
  // The awaitable let go of its hold and, on the way, of the continuation.
  CHECK_FALSE(op->continuation);

  // The endpoint resolving it now touches nothing that has gone.
  detail::quic_op_finish(*op, error_t{.code = vio_quic_endpoint_closed, .msg = "released"});
  detail::quic_op_dispatch(op);
}

// The other order: resolved first, then abandoned. Here the endpoint lets go
// first and the awaitable is last, so the awaitable is what frees it.
TEST_CASE("an operation abandoned after it resolves is freed by whoever is last")
{
  using namespace vio;

  auto *op = detail::quic_op_create(nullptr);
  detail::quic_op_finish(*op, error_t{.code = vio_quic_connection_closed, .msg = "closed"});
  // Nothing parked, so this resumes nothing and only drops the endpoint's hold.
  detail::quic_op_dispatch(op);

  // One hold left. Destroying the awaitable is what frees it, and under a
  // sanitiser a double free or a leak would show up here.
  {
    quic_connection_awaitable_t awaitable{op};
    CHECK(awaitable.await_ready());
  }
}

TEST_CASE("the first outcome is the one reported")
{
  using namespace vio;

  auto *op = detail::quic_op_create(nullptr);
  detail::quic_op_finish(*op, error_t{.code = vio_quic_handshake_failed, .msg = "first"});
  // More than one thing notices an ending, and a dial that failed for one
  // reason must not be reclassified by a later pass over it.
  detail::quic_op_finish(*op, error_t{.code = vio_quic_idle_timeout, .msg = "second"});
  CHECK(op->failure.code == vio_quic_handshake_failed);

  bool woke = false;
  bool failed = false;
  int code = 0;
  await_operation(quic_connection_awaitable_t{op}, woke, failed, code);
  CHECK(code == vio_quic_handshake_failed);
  detail::quic_op_dispatch(op);
}

TEST_CASE("a moved-from awaitable holds nothing")
{
  using namespace vio;

  // Every factory returns one of these by value, so the move has to leave the
  // source inert: two awaitables releasing the same operation is a double free,
  // and it would happen on the ordinary path rather than an exotic one.
  auto *op = detail::quic_op_create(nullptr);
  detail::quic_op_finish(*op, error_t{.code = vio_quic_busy, .msg = "busy"});
  {
    quic_connection_awaitable_t first{op};
    quic_connection_awaitable_t second{std::move(first)};
    CHECK(second.await_ready());
  }
  detail::quic_op_dispatch(op);
}
}
