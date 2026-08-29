#include <chrono>
#include <coroutine>
#include <optional>
#include <doctest/doctest.h>

#include <vio/operation/quic_endpoint.h>
#include <vio/operation/sleep.h>
#include <vio/operation/udp.h>

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
          (void)co_await sleep(loop, std::chrono::milliseconds(1));
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
          (void)co_await sleep(loop, std::chrono::milliseconds(20));
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
  //
  // The operation here has no connection behind it, which is the point: a dial
  // is also resolved by the sever of the connection it registered, so only an
  // operation with nothing to sever exercises the live-op pass. Without it this
  // coroutine parks for ever and the watchdog is what reports it.
  const auto identity = vio_test::make_self_signed("localhost");
  const auto context = make_server_context(identity);
  REQUIRE(context.has_value());

  event_loop_t event_loop;
  std::optional<task_t<void>> task;
  std::optional<task_t<void>> watchdog;
  cancellation_t stop_watchdog;
  bool resolved = false;
  int code = 0;
  bool timed_out = false;

  event_loop.run_in_loop(
    [&]
    {
      watchdog.emplace(
        [](event_loop_t &loop, cancellation_t &cancel, bool &timed_out, const bool &resolved) -> task_t<void>
        {
          (void)co_await sleep(loop, std::chrono::seconds(5), &cancel);
          if (!resolved)
          {
            timed_out = true;
            loop.stop();
          }
        }(event_loop, stop_watchdog, timed_out, resolved));

      task.emplace(
        [](event_loop_t &loop, const vio::quic::tls_context_t &tls, cancellation_t &stop_watchdog, bool &resolved, int &code) -> task_t<void>
        {
          auto endpoint = quic_endpoint_create(loop, tls);
          REQUIRE(endpoint.has_value());

          auto *op = detail::quic_op_create(&endpoint->handle.data());
          endpoint->handle->live_ops.push_back(op);
          quic_connection_awaitable_t parked{op};
          REQUIRE_FALSE(parked.await_ready());

          {
            auto letting_go = std::move(*endpoint);
          }

          const auto result = co_await std::move(parked);
          resolved = true;
          code = result.has_value() ? 0 : result.error().code;
          stop_watchdog.cancel();
          loop.stop();
        }(event_loop, *context, stop_watchdog, resolved, code));
    });
  event_loop.run();

  CHECK_FALSE(timed_out);
  CHECK(resolved);
  CHECK(code == vio_quic_endpoint_closed);
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
          (void)co_await sleep(loop, std::chrono::milliseconds(1));
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
          (void)co_await sleep(loop, std::chrono::milliseconds(1));
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
          (void)co_await sleep(loop, std::chrono::milliseconds(1));
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
          (void)co_await sleep(loop, std::chrono::milliseconds(1));
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

TEST_SUITE("quic coroutine dial")
{
namespace
{
vio::quic::tls_config_t server_tls(const vio_test::identity_t &identity)
{
  vio::quic::tls_config_t config;
  config.role = vio::quic::tls_role_t::server;
  config.certificate_chain_pem = identity.certificate_pem;
  config.private_key_pem = identity.private_key_pem;
  config.alpn = {"test"};
  return config;
}

vio::quic::tls_config_t client_tls(const vio_test::identity_t &identity)
{
  vio::quic::tls_config_t config;
  config.role = vio::quic::tls_role_t::client;
  config.ca_certificates_pem = identity.certificate_pem;
  config.alpn = {"test"};
  return config;
}

sockaddr_in loopback(std::uint16_t port)
{
  sockaddr_in address = {};
  uv_ip4_addr("127.0.0.1", static_cast<int>(port), &address);
  return address;
}
} // namespace

TEST_CASE("a dial resolves when the handshake completes")
{
  using namespace vio;

  // The first thing in this layer that works end to end: two endpoints, one
  // real socket each, and a coroutine that says co_await and gets a connection.
  // Nothing here drives the handshake -- no sleep loop, no flush, no readable
  // sweep. The read loop takes the datagrams in and the beat resumes the dial.
  const auto identity = vio_test::make_self_signed("localhost");
  const auto server_context = vio::quic::tls_context_t::create(server_tls(identity));
  const auto client_context = vio::quic::tls_context_t::create(client_tls(identity));
  REQUIRE(server_context.has_value());
  REQUIRE(client_context.has_value());

  event_loop_t event_loop;
  std::optional<task_t<void>> task;
  bool connected = false;
  std::string alpn;
  bool is_client = false;

  event_loop.run_in_loop(
    [&]
    {
      task.emplace(
        [](event_loop_t &loop, const vio::quic::tls_context_t &server_tls_context, const vio::quic::tls_context_t &client_tls_context, bool &connected, std::string &alpn, bool &is_client) -> task_t<void>
        {
          {
            auto server = quic_endpoint_create(loop, server_tls_context);
            REQUIRE(server.has_value());
            REQUIRE(quic_endpoint_bind(*server, std::uint16_t{0}).has_value());
            const auto port = quic_endpoint_local_port(*server).value_or(0);
            REQUIRE(port != 0);

            auto client = quic_endpoint_create(loop, nullptr, &client_tls_context);
            REQUIRE(client.has_value());

            const auto target = loopback(port);
            auto dialled = co_await quic_endpoint_connect(*client, reinterpret_cast<const sockaddr *>(&target), "localhost");
            connected = dialled.has_value();
            if (dialled)
            {
              alpn = dialled->handle->alpn;
              is_client = dialled->handle->role == vio::quic::tls_role_t::client;
            }
          }
          (void)co_await sleep(loop, std::chrono::milliseconds(1));
          loop.stop();
        }(event_loop, *server_context, *client_context, connected, alpn, is_client));
    });
  event_loop.run();

  CHECK(connected);
  CHECK(alpn == "test");
  CHECK(is_client);
}

TEST_CASE("a dial nobody answers resolves with the handshake failure")
{
  using namespace vio;

  // Test 6. The port is bound by a plain UDP socket that answers nothing, so
  // the Initials are neither refused nor replied to -- which is the case a bare
  // closed port would not produce, since an ICMP unreachable can arrive
  // instantly and would test something else.
  //
  // What ends it is connection_config_t::handshake_timeout, and that timeout
  // exists precisely because the idle timeout of section 10.1 is negotiated and
  // therefore does not exist until the peer's transport parameters arrive.
  const auto identity = vio_test::make_self_signed("localhost");
  const auto client_context = vio::quic::tls_context_t::create(client_tls(identity));
  REQUIRE(client_context.has_value());

  event_loop_t event_loop;
  std::optional<task_t<void>> task;
  bool failed = false;
  int code = 0;

  event_loop.run_in_loop(
    [&]
    {
      task.emplace(
        [](event_loop_t &loop, const vio::quic::tls_context_t &tls, bool &failed, int &code) -> task_t<void>
        {
          {
            // A socket that swallows whatever arrives.
            auto silence = udp_create(loop);
            REQUIRE(silence.has_value());
            sockaddr_in any = {};
            REQUIRE(uv_ip4_addr("127.0.0.1", 0, &any) == 0);
            REQUIRE(udp_bind(*silence, reinterpret_cast<const sockaddr *>(&any)).has_value());
            sockaddr_storage bound = {};
            int length = sizeof(bound);
            REQUIRE(uv_udp_getsockname(silence->get_udp(), reinterpret_cast<sockaddr *>(&bound), &length) == 0);
            const auto port = ntohs(reinterpret_cast<const sockaddr_in *>(&bound)->sin_port);

            quic_config_t config;
            config.transport.connection.handshake_timeout = std::chrono::milliseconds(300);
            auto client = quic_endpoint_create(loop, nullptr, &tls, config);
            REQUIRE(client.has_value());

            const auto target = loopback(port);
            auto dialled = co_await quic_endpoint_connect(*client, reinterpret_cast<const sockaddr *>(&target), "localhost");
            failed = !dialled.has_value();
            if (!dialled)
            {
              code = dialled.error().code;
            }
          }
          (void)co_await sleep(loop, std::chrono::milliseconds(1));
          loop.stop();
        }(event_loop, *client_context, failed, code));
    });
  event_loop.run();

  CHECK(failed);
  CHECK(code == vio_quic_handshake_failed);
}

TEST_CASE("a dial that cannot even be attempted resolves without suspending")
{
  using namespace vio;

  // The tcp_connect shape: every synchronous failure comes back on the same
  // awaitable, pre-resolved. A caller has one place to look rather than a
  // resolve step and then an await.
  //
  // Note what is *not* tested here, because it does not exist: endpoint_t
  // ::connect validates neither the address nor its family, so a garbage
  // sockaddr produces a connection that dials into nowhere and ends on the
  // handshake timeout, not a synchronous error. That is the transport's call
  // and it is left alone; this layer only promises that whatever the transport
  // does refuse comes back here rather than on a second call.
  quic_endpoint_t nothing;
  const auto target = loopback(4433);
  auto dial = quic_endpoint_connect(nothing, reinterpret_cast<const sockaddr *>(&target), "localhost");
  REQUIRE(dial.await_ready());
  const auto result = dial.await_resume();
  REQUIRE_FALSE(result.has_value());
  CHECK(result.error().code == -1);
}

TEST_CASE("a dial on an endpoint with no client context is refused with a sentence")
{
  using namespace vio;

  // Knowable only because there is no setter: which context slots are filled is
  // fixed at create. Refusing here rather than at create is what lets one
  // answer-only endpoint exist without every dial site having to prove it is
  // allowed -- and the refusal has to come before endpoint_t::connect touches
  // the socket, since libuv fixes the address family on first touch and a dial
  // that cannot happen must not pin the endpoint to IPv4.
  const auto identity = vio_test::make_self_signed("localhost");
  const auto server_context = vio::quic::tls_context_t::create(server_tls(identity));
  REQUIRE(server_context.has_value());

  event_loop_t event_loop;
  std::optional<task_t<void>> task;
  bool refused = false;
  bool has_sentence = false;
  bool still_bindable = false;

  event_loop.run_in_loop(
    [&]
    {
      task.emplace(
        [](event_loop_t &loop, const vio::quic::tls_context_t &tls, bool &refused, bool &has_sentence, bool &still_bindable) -> task_t<void>
        {
          {
            auto server = quic_endpoint_create(loop, tls);
            REQUIRE(server.has_value());

            const auto target = loopback(4433);
            auto dial = quic_endpoint_connect(*server, reinterpret_cast<const sockaddr *>(&target), "localhost");
            REQUIRE(dial.await_ready());
            const auto result = dial.await_resume();
            refused = !result.has_value();
            has_sentence = refused && !result.error().msg.empty();

            // And, having been refused, the socket still has no family: a bind
            // can still choose one.
            still_bindable = quic_endpoint_bind(*server, std::uint16_t{0}).has_value();
          }
          (void)co_await sleep(loop, std::chrono::milliseconds(1));
          loop.stop();
        }(event_loop, *server_context, refused, has_sentence, still_bindable));
    });
  event_loop.run();

  CHECK(refused);
  CHECK(has_sentence);
  CHECK(still_bindable);
}

TEST_CASE("an endpoint released mid-dial resolves the dial and closes its loop")
{
  using namespace vio;

  // Test 4, and the falsification of the design sketch this layer started from.
  // Had the awaitable held a strong reference to the endpoint state, the
  // application's release would take the count from two to one, on_destroy
  // would never run, nothing would resolve the dial, and the socket's uv_close
  // would never be issued -- so event_loop.run() would never return and the
  // failure would look like a hang rather than a leak.
  //
  // The watchdog is what turns that hang into a reportable failure.
  const auto identity = vio_test::make_self_signed("localhost");
  const auto client_context = vio::quic::tls_context_t::create(client_tls(identity));
  REQUIRE(client_context.has_value());

  event_loop_t event_loop;
  std::optional<task_t<void>> task;
  std::optional<task_t<void>> watchdog;
  cancellation_t stop_watchdog;
  bool resolved = false;
  int code = 0;
  bool timed_out = false;

  event_loop.run_in_loop(
    [&]
    {
      watchdog.emplace(
        [](event_loop_t &loop, cancellation_t &cancel, bool &timed_out, bool &resolved) -> task_t<void>
        {
          (void)co_await sleep(loop, std::chrono::seconds(5), &cancel);
          if (!resolved)
          {
            timed_out = true;
            loop.stop();
          }
        }(event_loop, stop_watchdog, timed_out, resolved));

      task.emplace(
        [](event_loop_t &loop, const vio::quic::tls_context_t &tls, cancellation_t &stop_watchdog, bool &resolved, int &code) -> task_t<void>
        {
          auto client = quic_endpoint_create(loop, nullptr, &tls);
          REQUIRE(client.has_value());
          // Nothing is listening, and nothing needs to be: the dial parks, and
          // what resolves it is the release below rather than any datagram.
          const auto target = loopback(9);
          auto dial = quic_endpoint_connect(*client, reinterpret_cast<const sockaddr *>(&target), "localhost");
          REQUIRE_FALSE(dial.await_ready());

          // Released while the dial is suspended -- inside the same coroutine,
          // so the awaitable is still alive and still parked.
          {
            auto letting_go = std::move(*client);
          }

          const auto result = co_await std::move(dial);
          resolved = true;
          code = result.has_value() ? 0 : result.error().code;
          stop_watchdog.cancel();
          loop.stop();
        }(event_loop, *client_context, stop_watchdog, resolved, code));
    });
  event_loop.run();

  CHECK_FALSE(timed_out);
  CHECK(resolved);
  CHECK(code == vio_quic_endpoint_closed);
}
}

TEST_SUITE("quic coroutine accept")
{
namespace
{
vio::quic::tls_config_t answering_tls(const vio_test::identity_t &identity)
{
  vio::quic::tls_config_t config;
  config.role = vio::quic::tls_role_t::server;
  config.certificate_chain_pem = identity.certificate_pem;
  config.private_key_pem = identity.private_key_pem;
  config.alpn = {"test"};
  return config;
}

vio::quic::tls_config_t dialling_tls(const vio_test::identity_t &identity)
{
  vio::quic::tls_config_t config;
  config.role = vio::quic::tls_role_t::client;
  config.ca_certificates_pem = identity.certificate_pem;
  config.alpn = {"test"};
  return config;
}

sockaddr_in to_loopback(std::uint16_t port)
{
  sockaddr_in address = {};
  uv_ip4_addr("127.0.0.1", static_cast<int>(port), &address);
  return address;
}
} // namespace

TEST_CASE("an accept and a dial meet")
{
  using namespace vio;

  // The headline. Two endpoints, two coroutines, one handshake, and neither
  // side polls: the server says co_await accept and the client says co_await
  // connect, and the read loop and the beat do the rest.
  const auto identity = vio_test::make_self_signed("localhost");
  const auto server_context = vio::quic::tls_context_t::create(answering_tls(identity));
  const auto client_context = vio::quic::tls_context_t::create(dialling_tls(identity));
  REQUIRE(server_context.has_value());
  REQUIRE(client_context.has_value());

  event_loop_t event_loop;
  std::optional<task_t<void>> task;
  bool accepted = false;
  bool connected = false;
  bool accepted_as_server = false;

  event_loop.run_in_loop(
    [&]
    {
      task.emplace(
        [](event_loop_t &loop, const vio::quic::tls_context_t &answering, const vio::quic::tls_context_t &dialling, bool &accepted, bool &connected, bool &accepted_as_server) -> task_t<void>
        {
          {
            auto server = quic_endpoint_create(loop, answering);
            REQUIRE(server.has_value());
            REQUIRE(quic_endpoint_bind(*server, std::uint16_t{0}).has_value());
            const auto port = quic_endpoint_local_port(*server).value_or(0);
            REQUIRE(port != 0);

            auto accepting = [](quic_endpoint_t &endpoint, bool &accepted, bool &accepted_as_server) -> task_t<void>
            {
              auto arrived = co_await quic_endpoint_accept(endpoint);
              accepted = arrived.has_value();
              if (arrived)
              {
                accepted_as_server = arrived->handle->role == vio::quic::tls_role_t::server;
              }
            }(*server, accepted, accepted_as_server);

            auto client = quic_endpoint_create(loop, nullptr, &dialling);
            REQUIRE(client.has_value());
            const auto target = to_loopback(port);
            auto dialled = co_await quic_endpoint_connect(*client, reinterpret_cast<const sockaddr *>(&target), "localhost");
            connected = dialled.has_value();

            co_await std::move(accepting);
          }
          (void)co_await sleep(loop, std::chrono::milliseconds(1));
          loop.stop();
        }(event_loop, *server_context, *client_context, accepted, connected, accepted_as_server));
    });
  event_loop.run();

  CHECK(connected);
  CHECK(accepted);
  CHECK(accepted_as_server);
}

TEST_CASE("a connection that arrives before anyone accepts is queued, not lost")
{
  using namespace vio;

  // QUIC has no listen call and no backlog to arm: a bound endpoint is already
  // answering Initials, so a handshake can and does complete before any
  // coroutine has asked for one. Queueing is what keeps that from being a
  // dropped connection, and pumping from the accept factory is what makes the
  // queued one resolve without suspending.
  const auto identity = vio_test::make_self_signed("localhost");
  const auto server_context = vio::quic::tls_context_t::create(answering_tls(identity));
  const auto client_context = vio::quic::tls_context_t::create(dialling_tls(identity));
  REQUIRE(server_context.has_value());
  REQUIRE(client_context.has_value());

  event_loop_t event_loop;
  std::optional<task_t<void>> task;
  bool queued = false;
  bool accepted_without_suspending = false;

  event_loop.run_in_loop(
    [&]
    {
      task.emplace(
        [](event_loop_t &loop, const vio::quic::tls_context_t &answering, const vio::quic::tls_context_t &dialling, bool &queued, bool &at_once) -> task_t<void>
        {
          {
            auto server = quic_endpoint_create(loop, answering);
            REQUIRE(server.has_value());
            REQUIRE(quic_endpoint_bind(*server, std::uint16_t{0}).has_value());
            const auto port = quic_endpoint_local_port(*server).value_or(0);

            auto client = quic_endpoint_create(loop, nullptr, &dialling);
            REQUIRE(client.has_value());
            const auto target = to_loopback(port);
            // Nobody is accepting yet, and the dial completes anyway.
            const auto dialled = co_await quic_endpoint_connect(*client, reinterpret_cast<const sockaddr *>(&target), "localhost");
            REQUIRE(dialled.has_value());
            // The two endpoints are independent: the client resolving its dial
            // says nothing about when the server ran its arrival hook. Waiting
            // for it is the point of the test rather than a wrinkle in it --
            // the connection is complete on the server long before anyone here
            // asks for it.
            (void)co_await sleep(loop, std::chrono::milliseconds(50));
            queued = server->handle->accept_queue.size() == 1;

            auto accept = quic_endpoint_accept(*server);
            at_once = accept.await_ready();
            const auto arrived = co_await std::move(accept);
            REQUIRE(arrived.has_value());
          }
          (void)co_await sleep(loop, std::chrono::milliseconds(1));
          loop.stop();
        }(event_loop, *server_context, *client_context, queued, accepted_without_suspending));
    });
  event_loop.run();

  CHECK(queued);
  CHECK(accepted_without_suspending);
}

TEST_CASE("two accepts are both served, oldest first")
{
  using namespace vio;

  // There is no single accept slot and so no busy error: with a per-call
  // operation a second concurrent accept has nothing to overwrite. That
  // deletes four failure modes at once -- a stale re-arm, an overwritten
  // continuation, an abandoned future stranding the slot, and a shared result
  // whose message is moved out on first read.
  const auto identity = vio_test::make_self_signed("localhost");
  const auto server_context = vio::quic::tls_context_t::create(answering_tls(identity));
  const auto client_context = vio::quic::tls_context_t::create(dialling_tls(identity));
  REQUIRE(server_context.has_value());
  REQUIRE(client_context.has_value());

  event_loop_t event_loop;
  std::optional<task_t<void>> task;
  int accepted = 0;
  int order[2] = {0, 0};

  event_loop.run_in_loop(
    [&]
    {
      task.emplace(
        [](event_loop_t &loop, const vio::quic::tls_context_t &answering, const vio::quic::tls_context_t &dialling, int &accepted, int *order) -> task_t<void>
        {
          {
            auto server = quic_endpoint_create(loop, answering);
            REQUIRE(server.has_value());
            REQUIRE(quic_endpoint_bind(*server, std::uint16_t{0}).has_value());
            const auto port = quic_endpoint_local_port(*server).value_or(0);

            auto first = [](quic_endpoint_t &endpoint, int &accepted, int *order) -> task_t<void>
            {
              const auto arrived = co_await quic_endpoint_accept(endpoint);
              if (arrived)
              {
                order[accepted++] = 1;
              }
            }(*server, accepted, order);
            auto second = [](quic_endpoint_t &endpoint, int &accepted, int *order) -> task_t<void>
            {
              const auto arrived = co_await quic_endpoint_accept(endpoint);
              if (arrived)
              {
                order[accepted++] = 2;
              }
            }(*server, accepted, order);

            auto client = quic_endpoint_create(loop, nullptr, &dialling);
            REQUIRE(client.has_value());
            const auto target = to_loopback(port);
            REQUIRE((co_await quic_endpoint_connect(*client, reinterpret_cast<const sockaddr *>(&target), "localhost")).has_value());
            REQUIRE((co_await quic_endpoint_connect(*client, reinterpret_cast<const sockaddr *>(&target), "localhost")).has_value());

            co_await std::move(first);
            co_await std::move(second);
          }
          (void)co_await sleep(loop, std::chrono::milliseconds(1));
          loop.stop();
        }(event_loop, *server_context, *client_context, accepted, order));
    });
  event_loop.run();

  CHECK(accepted == 2);
  CHECK(order[0] == 1);
  CHECK(order[1] == 2);
}

TEST_CASE("an endpoint dialling its own peer does not accept its own dial")
{
  using namespace vio;

  // The peer-to-peer case, and the reason the role is consulted at all.
  // on_connection fires for dialled connections too, so without the registry
  // and the role sort a peer would hand its own outbound connection to its own
  // accept loop -- and then wait for the real one for ever.
  const auto identity = vio_test::make_self_signed("localhost");
  const auto answering = vio::quic::tls_context_t::create(answering_tls(identity));
  const auto dialling = vio::quic::tls_context_t::create(dialling_tls(identity));
  REQUIRE(answering.has_value());
  REQUIRE(dialling.has_value());

  event_loop_t event_loop;
  std::optional<task_t<void>> task;
  bool alice_dialled = false;
  bool bob_accepted = false;
  bool alice_accepted_nothing = true;

  event_loop.run_in_loop(
    [&]
    {
      task.emplace(
        [](event_loop_t &loop, const vio::quic::tls_context_t &answering, const vio::quic::tls_context_t &dialling, bool &alice_dialled, bool &bob_accepted, bool &alice_accepted_nothing) -> task_t<void>
        {
          {
            auto alice = quic_endpoint_create(loop, &answering, &dialling);
            auto bob = quic_endpoint_create(loop, &answering, &dialling);
            REQUIRE(alice.has_value());
            REQUIRE(bob.has_value());
            // Bound to IPv4 explicitly, because both of these dial as well as
            // answer and the dial below names an IPv4 literal. The port-only
            // bind prefers dual-stack IPv6, and a socket that already has a
            // family cannot send to an address in another one.
            const auto any = to_loopback(0);
            REQUIRE(quic_endpoint_bind(*alice, reinterpret_cast<const sockaddr *>(&any)).has_value());
            REQUIRE(quic_endpoint_bind(*bob, reinterpret_cast<const sockaddr *>(&any)).has_value());
            const auto bob_port = quic_endpoint_local_port(*bob).value_or(0);

            auto bob_accepting = [](quic_endpoint_t &endpoint, bool &bob_accepted) -> task_t<void>
            {
              const auto arrived = co_await quic_endpoint_accept(endpoint);
              bob_accepted = arrived.has_value() && arrived->handle->role == vio::quic::tls_role_t::server;
            }(*bob, bob_accepted);

            const auto target = to_loopback(bob_port);
            const auto dialled = co_await quic_endpoint_connect(*alice, reinterpret_cast<const sockaddr *>(&target), "localhost");
            alice_dialled = dialled.has_value();
            co_await std::move(bob_accepting);

            // Alice dialled; her own connection must not be in her queue.
            alice_accepted_nothing = alice->handle->accept_queue.empty();
          }
          (void)co_await sleep(loop, std::chrono::milliseconds(1));
          loop.stop();
        }(event_loop, *answering, *dialling, alice_dialled, bob_accepted, alice_accepted_nothing));
    });
  event_loop.run();

  CHECK(alice_dialled);
  CHECK(bob_accepted);
  CHECK(alice_accepted_nothing);
}

TEST_CASE("a connection dialled behind this layer's back is ignored, not accepted")
{
  using namespace vio;

  // The other half of the sort, and the only branch the role itself decides.
  // Alice's own dial is kept out of her accept queue by the registry -- it was
  // entered there before the hook could fire. A connection dialled straight
  // through the transport has no registry entry, so if the role were not
  // checked it would be indistinguishable from an arrival, and a server would
  // be handed an outbound connection.
  //
  // This is exactly what an application that reaches for the native endpoint
  // can do, which is why the check exists rather than being an assertion that
  // it cannot happen.
  const auto identity = vio_test::make_self_signed("localhost");
  const auto answering = vio::quic::tls_context_t::create(answering_tls(identity));
  const auto dialling = vio::quic::tls_context_t::create(dialling_tls(identity));
  REQUIRE(answering.has_value());
  REQUIRE(dialling.has_value());

  event_loop_t event_loop;
  std::optional<task_t<void>> task;
  bool handshaken = false;
  bool queue_untouched = false;

  event_loop.run_in_loop(
    [&]
    {
      task.emplace(
        [](event_loop_t &loop, const vio::quic::tls_context_t &answering, const vio::quic::tls_context_t &dialling, bool &handshaken, bool &queue_untouched) -> task_t<void>
        {
          {
            auto listener = quic_endpoint_create(loop, answering);
            REQUIRE(listener.has_value());
            const auto any = to_loopback(0);
            REQUIRE(quic_endpoint_bind(*listener, reinterpret_cast<const sockaddr *>(&any)).has_value());
            const auto port = quic_endpoint_local_port(*listener).value_or(0);

            auto peer = quic_endpoint_create(loop, &answering, &dialling);
            REQUIRE(peer.has_value());
            REQUIRE(quic_endpoint_bind(*peer, reinterpret_cast<const sockaddr *>(&any)).has_value());

            // Straight through the transport, so nothing registers it.
            const auto target = to_loopback(port);
            const auto dialled = peer->handle->transport->connect(reinterpret_cast<const sockaddr *>(&target), "localhost");
            REQUIRE(dialled.has_value());

            (void)co_await sleep(loop, std::chrono::milliseconds(200));

            auto *raw = peer->handle->transport->connection(*dialled);
            handshaken = raw != nullptr && raw->handshake_complete();
            queue_untouched = peer->handle->accept_queue.empty() && peer->handle->by_connection.empty();
            if (raw != nullptr)
            {
              raw->close(vio::quic::transport_error_no_error, "done", false);
              (void)peer->handle->transport->flush(*raw);
            }
          }
          (void)co_await sleep(loop, std::chrono::milliseconds(1));
          loop.stop();
        }(event_loop, *answering, *dialling, handshaken, queue_untouched));
    });
  event_loop.run();

  // The handshake really did complete, so the hook really did fire -- which is
  // what makes the empty queue mean something.
  CHECK(handshaken);
  CHECK(queue_untouched);
}

TEST_CASE("an accept past the backlog is refused rather than queued")
{
  using namespace vio;

  // Section 20.1: told no rather than told nothing. The refusal costs the
  // server a CONNECTION_CLOSE it has to flush without a registered connection
  // to hang it on, which is what flush_all is for.
  //
  // Be clear what this bounds and what it does not. The arrival hook fires
  // after the handshake, so a refused connection has already cost a TLS session
  // and three key schedules -- endpoint_config_t::max_connections is the
  // earlier and cheaper ceiling. And because the refusal is decided at that
  // point, the client's own dial has already succeeded: it received
  // HANDSHAKE_DONE and only then the CONNECTION_CLOSE. So what is checked here
  // is the server's side, which is where the decision was made. The client
  // learns of it through quic_connection_closed.
  const auto identity = vio_test::make_self_signed("localhost");
  const auto server_context = vio::quic::tls_context_t::create(answering_tls(identity));
  const auto client_context = vio::quic::tls_context_t::create(dialling_tls(identity));
  REQUIRE(server_context.has_value());
  REQUIRE(client_context.has_value());

  event_loop_t event_loop;
  std::optional<task_t<void>> task;
  bool first_connected = false;
  bool second_refused = false;
  std::size_t queued = 0;

  event_loop.run_in_loop(
    [&]
    {
      task.emplace(
        [](event_loop_t &loop, const vio::quic::tls_context_t &answering, const vio::quic::tls_context_t &dialling, bool &first_connected, bool &second_refused, std::size_t &queued) -> task_t<void>
        {
          {
            quic_config_t config;
            config.accept_backlog = 1;
            auto server = quic_endpoint_create(loop, answering, config);
            REQUIRE(server.has_value());
            REQUIRE(quic_endpoint_bind(*server, std::uint16_t{0}).has_value());
            const auto port = quic_endpoint_local_port(*server).value_or(0);

            auto client = quic_endpoint_create(loop, nullptr, &dialling);
            REQUIRE(client.has_value());
            const auto target = to_loopback(port);

            // Nobody accepts, so the first fills the backlog of one.
            const auto first = co_await quic_endpoint_connect(*client, reinterpret_cast<const sockaddr *>(&target), "localhost");
            first_connected = first.has_value();
            // The two endpoints are independent: the client resolving its dial
            // says nothing about when the server ran its arrival hook.
            (void)co_await sleep(loop, std::chrono::milliseconds(50));
            queued = server->handle->accept_queue.size();

            // The second completes its handshake and is then refused, so it
            // is never registered and never queued.
            const auto second = co_await quic_endpoint_connect(*client, reinterpret_cast<const sockaddr *>(&target), "localhost");
            REQUIRE(second.has_value());
            (void)co_await sleep(loop, std::chrono::milliseconds(50));
            second_refused = server->handle->accept_queue.size() == 1 && server->handle->by_connection.size() == 1;
          }
          (void)co_await sleep(loop, std::chrono::milliseconds(1));
          loop.stop();
        }(event_loop, *server_context, *client_context, first_connected, second_refused, queued));
    });
  event_loop.run();

  CHECK(first_connected);
  CHECK(queued == 1);
  // Still one queued and still one registered: the refused connection was
  // never given a state at all, which is what makes the refusal cheap.
  CHECK(second_refused);
}

TEST_CASE("an accept on an endpoint that cannot answer is refused with a sentence")
{
  using namespace vio;

  // The single most valuable refusal here: it turns an accept loop silently
  // suspended for the life of the process into a message. And the unbound case
  // beside it, which is the same mistake with a different cause -- parking
  // would be indistinguishable from waiting for a peer, and the peer cannot
  // arrive because there is no socket to arrive on.
  const auto identity = vio_test::make_self_signed("localhost");
  const auto server_context = vio::quic::tls_context_t::create(answering_tls(identity));
  const auto client_context = vio::quic::tls_context_t::create(dialling_tls(identity));
  REQUIRE(server_context.has_value());
  REQUIRE(client_context.has_value());

  event_loop_t event_loop;
  std::optional<task_t<void>> task;
  bool dial_only_refused = false;
  bool unbound_refused = false;

  event_loop.run_in_loop(
    [&]
    {
      task.emplace(
        [](event_loop_t &loop, const vio::quic::tls_context_t &answering, const vio::quic::tls_context_t &dialling, bool &dial_only_refused, bool &unbound_refused) -> task_t<void>
        {
          {
            auto dial_only = quic_endpoint_create(loop, nullptr, &dialling);
            REQUIRE(dial_only.has_value());
            auto refused = quic_endpoint_accept(*dial_only);
            REQUIRE(refused.await_ready());
            const auto result = refused.await_resume();
            dial_only_refused = !result.has_value() && !result.error().msg.empty();

            auto unbound = quic_endpoint_create(loop, answering);
            REQUIRE(unbound.has_value());
            auto waiting = quic_endpoint_accept(*unbound);
            REQUIRE(waiting.await_ready());
            unbound_refused = !waiting.await_resume().has_value();
          }
          (void)co_await sleep(loop, std::chrono::milliseconds(1));
          loop.stop();
        }(event_loop, *server_context, *client_context, dial_only_refused, unbound_refused));
    });
  event_loop.run();

  CHECK(dial_only_refused);
  CHECK(unbound_refused);
}
}
