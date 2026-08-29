#include <chrono>
#include <coroutine>
#include <optional>
#include <doctest/doctest.h>

#include <vio/operation/quic_endpoint.h>
#include <vio/operation/sleep.h>

#include "quic_identity.h"

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
  // Latched but nobody woken: whatever reached it was standing in the read
  // loop, and resuming there is the one thing this layer never does.
  CHECK_FALSE(woke);
  detail::quic_milestone_drain(slot.data());
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
  detail::quic_milestone_drain(slot.data());
  CHECK(first_woke);
  CHECK(second_woke);
  CHECK(first_failed);
  CHECK(second_failed);

  // Reaching it again changes nothing. A connection that ended for one reason
  // must not be reclassified by a later pass over it, and the second call has
  // to be harmless because more than one thing notices an ending.
  detail::quic_milestone_reach(slot.data(), {});
  detail::quic_milestone_drain(slot.data());
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
  detail::quic_milestone_drain(slot.data());
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

TEST_SUITE("quic coroutine endpoint")
{
namespace
{
std::expected<vio::quic::tls_context_t, vio::error_t> make_server_context(const vio_test::identity_t &identity)
{
  vio::quic::tls_config_t config;
  config.role = vio::quic::tls_role_t::server;
  config.certificate_chain_pem = identity.certificate_pem;
  config.private_key_pem = identity.private_key_pem;
  config.alpn = {"test"};
  return vio::quic::tls_context_t::create(config);
}

std::expected<vio::quic::tls_context_t, vio::error_t> make_client_context(const vio_test::identity_t &identity)
{
  vio::quic::tls_config_t config;
  config.role = vio::quic::tls_role_t::client;
  config.ca_certificates_pem = identity.certificate_pem;
  config.alpn = {"test"};
  return vio::quic::tls_context_t::create(config);
}
} // namespace

TEST_CASE("an endpoint that is never bound does not keep the loop running")
{
  using namespace vio;

  // The case uv_unref exists for, and the one that is easy to get wrong in a
  // way no assertion catches: libuv makes the UDP socket lazily, so an endpoint
  // created and never bound owns no descriptor at all. Its beat is therefore
  // the only active handle on the loop, and a referenced prepare handle is
  // enough on its own to make uv_run block for ever -- stop() closes vio's
  // internal handles and nothing else.
  //
  // So this test hanging *is* the failure. There is no assertion that can
  // report it, which is why it is worth writing down rather than assuming.
  const auto identity = vio_test::make_self_signed("localhost");
  const auto context = make_server_context(identity);
  REQUIRE(context.has_value());

  event_loop_t event_loop;
  bool created = false;
  {
    auto endpoint = quic_endpoint_create(event_loop, *context);
    REQUIRE(endpoint.has_value());
    created = endpoint->handle.ref_counted() != nullptr;
    event_loop.stop();
    // Returning at all is the assertion. With the beat referenced, uv_run has
    // an active handle and blocks here for ever.
    event_loop.run();
  } // and only now is the endpoint released, which requests the closes
  // A second run drains them. Every other test in this file releases its
  // endpoint before the loop stops, which is the shape an application should
  // use; this one cannot, because what it is testing is that run() returns
  // while the endpoint is still alive.
  event_loop.run();
  CHECK(created);
}

TEST_CASE("an endpoint released while the loop can still run leaves nothing open")
{
  using namespace vio;

  // The other half of the same rule, from the handle-lifetime section of
  // CLAUDE.md: a vio handle must be released while the loop can still run, or
  // its uv_close is requested and never drained, uv_loop_close fails with EBUSY
  // and the event loop destructor aborts on its assert.
  //
  // Here the endpoint is dropped inside the task, so the close is issued during
  // the run() that is still in progress. If the beat were not registered with
  // the reference count, this would be the assertion that fires.
  const auto identity = vio_test::make_self_signed("localhost");
  const auto context = make_server_context(identity);
  REQUIRE(context.has_value());

  event_loop_t event_loop;
  bool released = false;

  std::optional<task_t<void>> task;
  event_loop.run_in_loop(
    [&]
    {
      task.emplace(
        [](event_loop_t &loop, const vio::quic::tls_context_t &tls, bool &was_released) -> task_t<void>
        {
          {
            auto endpoint = quic_endpoint_create(loop, tls);
            REQUIRE(endpoint.has_value());
            was_released = true;
          } // the last handle goes here, and with it the socket and the beat
          co_await sleep(loop, std::chrono::milliseconds(1));
          loop.stop();
        }(event_loop, *context, released));
    });
  event_loop.run();
  CHECK(released);
}

TEST_CASE("an endpoint can be built to answer, to dial, or to do both")
{
  using namespace vio;

  // A tls_context_t picks TLS_server_method or TLS_client_method at creation
  // and gates tickets and early data on that, so no single one can both answer
  // and dial. Which slots are filled is what decides whether a dial or an
  // arriving Initial is refused, which makes the two-context overload the whole
  // of peer-to-peer support at this layer.
  const auto identity = vio_test::make_self_signed("localhost");
  const auto server_context = make_server_context(identity);
  const auto client_context = make_client_context(identity);
  REQUIRE(server_context.has_value());
  REQUIRE(client_context.has_value());

  event_loop_t event_loop;
  {
    auto answering = quic_endpoint_create(event_loop, &*server_context, nullptr);
    auto dialling = quic_endpoint_create(event_loop, nullptr, &*client_context);
    auto both = quic_endpoint_create(event_loop, &*server_context, &*client_context);
    CHECK(answering.has_value());
    CHECK(dialling.has_value());
    CHECK(both.has_value());

    // The single-context form puts it in the slot its role names, so it is the
    // two-context form with one side left empty rather than a third thing.
    auto shorthand = quic_endpoint_create(event_loop, *server_context);
    CHECK(shorthand.has_value());

    event_loop.stop();
    event_loop.run();
  }
  event_loop.run(); // drains the closes the four releases above requested
}

TEST_CASE("a permanently armed beat still lets the loop sleep")
{
  using namespace vio;

  // The beat is armed for the life of the endpoint and costs one predicate per
  // loop turn. That is deliberate: an idle handle is disqualified outright,
  // because uv__backend_timeout returns zero while one is active and the loop
  // stops sleeping altogether. Neither prepare nor check appears in that
  // function, which is what makes arming this permanently cheaper to reason
  // about than arming it conditionally -- and step 3 of this work found that
  // making a periodic mechanism in this endpoint conditional produced both a
  // spin and a stall.
  //
  // What is checked here is that a timer still ends the sleep with the beat
  // running, which is the observable half of that claim.
  const auto identity = vio_test::make_self_signed("localhost");
  const auto context = make_server_context(identity);
  REQUIRE(context.has_value());

  event_loop_t event_loop;
  std::optional<task_t<void>> task;
  bool slept = false;

  event_loop.run_in_loop(
    [&]
    {
      task.emplace(
        [](event_loop_t &loop, const vio::quic::tls_context_t &tls, bool &did_sleep) -> task_t<void>
        {
          auto endpoint = quic_endpoint_create(loop, tls);
          REQUIRE(endpoint.has_value());
          co_await sleep(loop, std::chrono::milliseconds(20));
          did_sleep = true;
          loop.stop();
        }(event_loop, *context, slept));
    });
  event_loop.run();
  CHECK(slept);
}

TEST_CASE("marking records and draining resumes, and they are separable")
{
  using namespace vio;

  // The invariant the whole layer rests on: the hooks fire from inside the
  // transport's read loop, where a resumed coroutine could drop the last
  // endpoint reference and destroy the vector being walked. So they mark, and
  // the beat resumes.
  //
  // Driven here by hand rather than over a socket, because the point is that
  // marking and resuming are separable at all -- a connection marked pending
  // stays parked until something drains it.
  const auto identity = vio_test::make_self_signed("localhost");
  const auto context = make_server_context(identity);
  REQUIRE(context.has_value());

  event_loop_t event_loop;
  {
    auto endpoint = quic_endpoint_create(event_loop, *context);
    REQUIRE(endpoint.has_value());
    auto &state = endpoint->handle.data();

    auto connection = ref_ptr_t<detail::quic_connection_state_t>(&state, nullptr, vio::quic::tls_role_t::server);
    connection->ready = ref_ptr_t<detail::quic_milestone_state_t>();

    detail::quic_milestone_reach(connection->ready.data(), {});
    detail::quic_mark_pending(state, connection);
    CHECK(state.pending.size() == 1);
    CHECK(connection->queued);

    // Marked twice is queued once: the read loop can touch one connection
    // several times in a turn, and a list with duplicates would drain the same
    // milestone repeatedly.
    detail::quic_mark_pending(state, connection);
    CHECK(state.pending.size() == 1);

    quic_milestone_t ready{connection->ready};
    CHECK(ready.reached());

    // Draining is what the beat does, and it clears the flag so the next turn
    // can mark again.
    detail::quic_beat_resume(state);
    CHECK(state.pending.empty());
    CHECK_FALSE(connection->queued);

    event_loop.stop();
    event_loop.run();
  }
  event_loop.run();
}

TEST_CASE("teardown latches a connection before its transport goes away")
{
  using namespace vio;

  // What makes holding a quic_connection_t past the ending safe. The endpoint
  // frees the connection_t on its own schedule with no notification, so
  // everything an application can still ask has to be copied out at the sever
  // and the pointer nulled there -- a pointer kept past that point is one
  // nothing will ever say to drop, and the next connection_t may land at the
  // same address.
  const auto identity = vio_test::make_self_signed("localhost");
  const auto context = make_server_context(identity);
  REQUIRE(context.has_value());

  event_loop_t event_loop;
  quic_connection_t survivor;
  {
    auto endpoint = quic_endpoint_create(event_loop, *context);
    REQUIRE(endpoint.has_value());
    auto &state = endpoint->handle.data();

    auto connection = ref_ptr_t<detail::quic_connection_state_t>(&state, nullptr, vio::quic::tls_role_t::server);
    connection->closed = ref_ptr_t<detail::quic_milestone_state_t>();
    connection->alpn = "test";
    state.by_connection.emplace(reinterpret_cast<const vio::quic::connection_t *>(0x1), connection);
    survivor.handle = connection;

    event_loop.stop();
    event_loop.run();
  } // the endpoint goes here, and teardown severs everything it still holds
  event_loop.run();

  REQUIRE(survivor.handle.ref_counted() != nullptr);
  CHECK(survivor.handle->severed);
  CHECK(survivor.handle->transport == nullptr);
  CHECK(survivor.handle->endpoint == nullptr);
  CHECK(survivor.handle->alpn == "test");

  quic_milestone_t closed{survivor.handle->closed};
  REQUIRE(closed.reached());
  CHECK_FALSE(survivor.handle->closed->result.has_value());
  CHECK(survivor.handle->closed->result.error().code == vio_quic_endpoint_closed);
}

TEST_CASE("teardown resolves an operation nobody would otherwise resume")
{
  using namespace vio;

  // A coroutine parked on an accept when the last endpoint handle goes is a
  // leaked frame, and if that frame holds a handle it is also an event loop
  // that never returns. Teardown finishes every live operation with
  // vio_quic_endpoint_closed and then resumes them -- latch first, resume
  // second, because a resumed coroutine may destroy the awaitable holding the
  // operation being walked.
  const auto identity = vio_test::make_self_signed("localhost");
  const auto context = make_server_context(identity);
  REQUIRE(context.has_value());

  event_loop_t event_loop;
  {
    auto endpoint = quic_endpoint_create(event_loop, *context);
    REQUIRE(endpoint.has_value());
    auto &state = endpoint->handle.data();

    auto *op = detail::quic_op_create(&state);
    state.live_ops.push_back(op);

    // Two holds: the awaitable standing in for a suspended coroutine, and the
    // endpoint that is going to resolve it.
    CHECK(op->holds == 2);

    event_loop.stop();
    event_loop.run();

    // The endpoint is still alive here, so nothing has torn down yet.
    CHECK_FALSE(op->resolved);

    {
      quic_connection_awaitable_t parked{op};
      auto released = std::move(*endpoint);
    } // both go here: the endpoint tears down, then the awaitable releases

    // Which means the operation was finished, resumed (there was no
    // continuation) and freed by whichever owner was last. Reading it here
    // would be a use-after-free; that it is freed at all is what ASan checks.
  }
  event_loop.run();
}
}

TEST_SUITE("quic coroutine bind")
{
namespace
{
std::expected<vio::quic::tls_context_t, vio::error_t> server_context_for(const vio_test::identity_t &identity)
{
  vio::quic::tls_config_t config;
  config.role = vio::quic::tls_role_t::server;
  config.certificate_chain_pem = identity.certificate_pem;
  config.private_key_pem = identity.private_key_pem;
  config.alpn = {"test"};
  return vio::quic::tls_context_t::create(config);
}

std::expected<vio::quic::tls_context_t, vio::error_t> client_context_for(const vio_test::identity_t &identity)
{
  vio::quic::tls_config_t config;
  config.role = vio::quic::tls_role_t::client;
  config.ca_certificates_pem = identity.certificate_pem;
  config.alpn = {"test"};
  return vio::quic::tls_context_t::create(config);
}
} // namespace

TEST_CASE("binding to zero picks a port and starts the read loop")
{
  using namespace vio;

  // Binding is the moment the socket acquires an address family, which is why
  // the read loop starts here and not at creation: libuv makes the socket
  // lazily and pins its family to whoever touches it first, so an endpoint that
  // started reading before anyone said where would be IPv4 for ever.
  const auto identity = vio_test::make_self_signed("localhost");
  const auto context = server_context_for(identity);
  REQUIRE(context.has_value());

  event_loop_t event_loop;
  std::optional<task_t<void>> task;
  std::uint16_t port = 0;
  bool reading = false;

  event_loop.run_in_loop(
    [&]
    {
      task.emplace(
        [](event_loop_t &loop, const vio::quic::tls_context_t &tls, std::uint16_t &port, bool &reading) -> task_t<void>
        {
          {
            auto endpoint = quic_endpoint_create(loop, tls);
            REQUIRE(endpoint.has_value());

            // Before the bind there is no socket, so there is no port either.
            CHECK(quic_endpoint_local_port(*endpoint).value_or(0) == 0);

            const auto bound = quic_endpoint_bind(*endpoint, std::uint16_t{0});
            REQUIRE(bound.has_value());
            port = quic_endpoint_local_port(*endpoint).value_or(0);
            reading = endpoint->handle->driver_started;
          }
          co_await sleep(loop, std::chrono::milliseconds(1));
          loop.stop();
        }(event_loop, *context, port, reading));
    });
  event_loop.run();

  CHECK(port != 0);
  CHECK(reading);
}

TEST_CASE("a bind that fails does not leave the endpoint reading")
{
  using namespace vio;

  // Binding and starting the read loop are two steps, and the failure has to
  // come out of the first: an endpoint that reported a bind error and then went
  // on to read an unbound socket would be the worst of both.
  //
  // TEST-NET-1, which is not assigned to any interface anywhere, so the failure
  // is the operating system refusing an address it does not have. A second bind
  // on an already-bound port would have been the obvious test and is not a
  // portable one -- Windows lets two UDP sockets share a port unless one asks
  // for exclusive use.
  const auto identity = vio_test::make_self_signed("localhost");
  const auto context = server_context_for(identity);
  REQUIRE(context.has_value());

  event_loop_t event_loop;
  std::optional<task_t<void>> task;
  bool refused = false;
  bool never_read = false;
  bool no_port = false;

  event_loop.run_in_loop(
    [&]
    {
      task.emplace(
        [](event_loop_t &loop, const vio::quic::tls_context_t &tls, bool &refused, bool &never_read, bool &no_port) -> task_t<void>
        {
          {
            auto endpoint = quic_endpoint_create(loop, tls);
            REQUIRE(endpoint.has_value());
            sockaddr_in unassignable = {};
            REQUIRE(uv_ip4_addr("192.0.2.1", 4433, &unassignable) == 0);
            const auto bound = quic_endpoint_bind(*endpoint, reinterpret_cast<const sockaddr *>(&unassignable));
            refused = !bound.has_value();
            never_read = !endpoint->handle->driver_started;
            no_port = quic_endpoint_local_port(*endpoint).value_or(0) == 0;
          }
          co_await sleep(loop, std::chrono::milliseconds(1));
          loop.stop();
        }(event_loop, *context, refused, never_read, no_port));
    });
  event_loop.run();

  CHECK(refused);
  CHECK(never_read);
  CHECK(no_port);
}

TEST_CASE("a dial-only endpoint may still pin a source port")
{
  using namespace vio;

  // Deliberately not symmetric with accept. An endpoint with no server context
  // cannot answer, and asking it to is a configuration mistake worth a
  // sentence -- but pinning a source port is ordinary client behaviour, through
  // a firewall or to keep a NAT mapping, and refusing it for the sake of
  // symmetry would be a trap rather than a check.
  const auto identity = vio_test::make_self_signed("localhost");
  const auto context = client_context_for(identity);
  REQUIRE(context.has_value());

  event_loop_t event_loop;
  std::optional<task_t<void>> task;
  bool bound = false;

  event_loop.run_in_loop(
    [&]
    {
      task.emplace(
        [](event_loop_t &loop, const vio::quic::tls_context_t &tls, bool &bound) -> task_t<void>
        {
          {
            auto endpoint = quic_endpoint_create(loop, nullptr, &tls);
            REQUIRE(endpoint.has_value());
            bound = quic_endpoint_bind(*endpoint, std::uint16_t{0}).has_value() && quic_endpoint_local_port(*endpoint).value_or(0) != 0;
          }
          co_await sleep(loop, std::chrono::milliseconds(1));
          loop.stop();
        }(event_loop, *context, bound));
    });
  event_loop.run();
  CHECK(bound);
}

TEST_CASE("the read loop is started once, however many times bind is called")
{
  using namespace vio;

  // uv_udp_bind refuses a second bind on a bound socket, so the second call
  // never reaches the driver -- but the guard is what makes that a property of
  // this layer rather than a happy accident of libuv's. Two run() frames on one
  // socket would be two readers, two poll handles and two owners of the same
  // datagrams.
  const auto identity = vio_test::make_self_signed("localhost");
  const auto context = server_context_for(identity);
  REQUIRE(context.has_value());

  event_loop_t event_loop;
  std::optional<task_t<void>> task;
  bool one_driver = false;

  event_loop.run_in_loop(
    [&]
    {
      task.emplace(
        [](event_loop_t &loop, const vio::quic::tls_context_t &tls, bool &one_driver) -> task_t<void>
        {
          {
            auto endpoint = quic_endpoint_create(loop, tls);
            REQUIRE(endpoint.has_value());
            REQUIRE(quic_endpoint_bind(*endpoint, std::uint16_t{0}).has_value());
            const auto *first_driver = &*endpoint->handle->driver;

            // Rebinding fails, and the guard means the driver is untouched
            // either way.
            (void)quic_endpoint_bind(*endpoint, std::uint16_t{0});
            REQUIRE(detail::quic_start_driver(endpoint->handle.data()).has_value());
            one_driver = &*endpoint->handle->driver == first_driver;
          }
          co_await sleep(loop, std::chrono::milliseconds(1));
          loop.stop();
        }(event_loop, *context, one_driver));
    });
  event_loop.run();
  CHECK(one_driver);
}

TEST_CASE("binding a released endpoint is refused rather than crashing")
{
  using namespace vio;

  // Every entry point tests `closing` rather than whether the transport is
  // still there, because the transport outlives most of the teardown. A handle
  // that names nothing is the other half of the same check, and it is the one
  // that would be a null dereference: ref_ptr_t::data() does not test.
  quic_endpoint_t nothing;
  const auto bound = quic_endpoint_bind(nothing, std::uint16_t{0});
  REQUIRE_FALSE(bound.has_value());
  CHECK(bound.error().code == -1);
  CHECK_FALSE(quic_endpoint_local_port(nothing).has_value());
}
}
