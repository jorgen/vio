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
