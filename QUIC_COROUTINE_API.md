# A coroutine QUIC API for vio

A design proposal. Progress against the eight-step build order at the bottom:

- **Step 1 (transport parameter defaults) — done.** `default_transport_parameters()`, wired
  through `connection_config_t`. All twelve hand-rolled parameter blocks deleted.
- **Step 2 (transport edges and accessors) — done.** Peer reset and STOP_SENDING codes, the
  `take_*` edge drains, a reason on both timeout endings, send-side and path stats, and
  finished local streams reaped.
- **Step 3 (endpoint hardening) — partly done.** `flush(connection_t&)`, `on_connection_gone`
  and the `walking` bracket landed. The deadline-driven timer and the IPv4-pinning fix were
  both tried and reverted with measurements; see the section at the end.
- **Steps 4 to 8 — not started.**

Landed alongside these, outside the build order: peer-to-peer endpoints (two TLS contexts),
mutual TLS, and six verified bug fixes.

> **Revised after the maintainer settled the open questions.** `initial_max_data` is
> 8 MiB (not 1 MiB) and the per-stream windows are 2 MiB (not 256 KiB); the send-side
> high-water marks move with them. `grease_quic_bit` stays off. The callback API stays
> public but no example uses it. The endpoint supports peer-to-peer. See the three
> sections appended at the end of this document, which supersede anything above that
> disagrees with them.


## Thesis

Take design 4's spine — every resumption and every flush happen on one beat per loop turn — but drive that beat from a `uv_prepare_t` the endpoint state owns through `register_handle`, not from `add_about_to_block_listener`, whose removal is posted through the very event pipe `event_loop_t::stop()` closes first (verified: event_loop_impl.h:171 and :190-203). Graft in design 2's load-bearing insight that a stream must be a first-class ref-counted handle that latches its own terminal reason, so `reap_finished` erasing the `stream_t` under a reader stops being a hazard — but keep design 3's "the flow-control window IS the queue", so the API layer holds no second copy of received bytes and the per-connection receive commitment really is `initial_max_data` rather than 25x it. Ownership runs strictly downward (endpoint owns connections owns streams) with borrowed raw back-pointers, exactly as `timer_impl.h` already argues for a handle's `data` field, so a forgotten stream handle can never hold the socket open and `uv_loop_close` can never fail — and every fatal use-after-free the critiques found dies structurally, because with this layering the read loop never calls user code at all: `on_activity` marks dirty, `on_connection` queues, and the beat is the only place a coroutine is resumed. `transport_parameters_t` keeps the RFC 9000 §18.2 absent-parameter semantics its decoder depends on, and the sane values arrive through `connection_config_t::transport_parameters = default_transport_parameters()` plus a `quic_flow_control_t` whose own default member initialisers *are* the policy, so partial override reads correctly and nobody ever has to write a parameter block — which is precisely the user's principle that QUIC should require no more configuration than TCP.

## What a client looks like

```cpp
// examples/quic_echo_client.cpp
//
// Dial, open one stream, say one thing, read the answer, leave. Nothing about
// flow control is configured, nothing drives a run loop, nothing calls flush,
// and nothing sleeps waiting for a teardown.

#include "quic_common.h" // make_self_signed, and the Windows include order

#include <vio/operation/quic_stream.h>
#include <vio/run.h>

#include <optional>
#include <print>
#include <string>

int main()
{
  return vio::run(
    [](vio::event_loop_t &loop) -> vio::task_t<int>
    {
      using namespace vio;

      // The one thing QUIC needs that TCP does not: there is no unencrypted
      // mode to start from. Here the server's own certificate is the client's
      // only trust anchor, because the pair are generated together.
      const auto identity = vio_example::make_self_signed("localhost");

      quic::tls_config_t tls;
      tls.role = quic::tls_role_t::client;
      tls.ca_certificates_pem = identity.certificate_pem;
      // ALPN is not optional in QUIC the way it is in TLS over TCP: a handshake
      // with no protocol in common is refused.
      tls.alpn = {"vio-echo"};
      auto context = quic::tls_context_t::create(tls);
      if (!context)
      {
        std::println(stderr, "tls_context_t::create: {}", context.error().msg);
        co_return 1;
      }

      // No transport parameters anywhere in this program. The defaults grant eight
      // megabytes per connection, 2 MiB per stream, and a hundred streams each
      // way -- which is what this program wants and what it would otherwise
      // have had to spell out.
      auto created = quic_endpoint_create(loop, *context);
      if (!created)
      {
        std::println(stderr, "quic_endpoint_create: {}", created.error().msg);
        co_return 1;
      }
      // Held in an optional so the socket is released at a moment this program
      // chooses -- see the last two statements.
      std::optional<quic_endpoint_t> endpoint(std::move(*created));

      auto target = ip4_addr("127.0.0.1", 4433);
      if (!target)
      {
        std::println(stderr, "ip4_addr: {}", target.error().msg);
        endpoint.reset();
        co_return 1;
      }

      // Resolves when the handshake is done, not when the first Initial is
      // queued: a certificate that did not verify, no ALPN in common, no
      // version in common and the handshake deadline all arrive here as the
      // error. The socket is created by this call, with this address family.
      auto connection = co_await quic_endpoint_connect(*endpoint, reinterpret_cast<const sockaddr *>(&*target), "localhost");
      if (!connection)
      {
        std::println(stderr, "quic_endpoint_connect: {}", connection.error().msg);
        endpoint.reset();
        co_return 1;
      }
      std::println("connected, alpn \"{}\", rtt {}us", quic_connection_alpn(*connection), quic_connection_stats(*connection).smoothed_rtt.count() / 1000);

      // Suspends only if the server granted no stream credit yet, which is not
      // the ordinary case; when credit exists this does not suspend at all.
      auto stream = co_await quic_open_stream(*connection);
      if (!stream)
      {
        std::println(stderr, "quic_open_stream: {}", stream.error().msg);
        endpoint.reset();
        co_return 1;
      }

      const std::string message = "hello over quic";
      // The FIN rides with the bytes it terminates: this is the whole of what
      // the client has to say on this stream, and saying so now means the
      // server never has to guess whether more is coming.
      if (auto written = co_await quic_stream_write_final(*stream, std::as_bytes(std::span(message)).empty() ? std::span<const std::uint8_t>{} : std::span(reinterpret_cast<const std::uint8_t *>(message.data()), message.size()));
          !written)
      {
        std::println(stderr, "quic_stream_write_final: {}", written.error().msg);
        endpoint.reset();
        co_return 1;
      }

      std::string echoed;
      {
        auto created_reader = quic_stream_create_reader(*stream);
        if (!created_reader)
        {
          std::println(stderr, "quic_stream_create_reader: {}", created_reader.error().msg);
          endpoint.reset();
          co_return 1;
        }
        auto reader = std::move(*created_reader);
        for (;;)
        {
          auto chunk = co_await reader;
          if (!chunk)
          {
            if (chunk.error().code == vio_quic_stream_finished)
            {
              break;
            }
            if (chunk.error().code == vio_quic_stream_reset)
            {
              // The 62-bit code the peer chose, which is what an application
              // protocol branches on. Before this API there was no way to tell
              // this ending from the clean one above, let alone read the code.
              std::println(stderr, "server reset the stream with 0x{:x}", quic_stream_peer_reset_error(*stream).value_or(0));
            }
            else
            {
              std::println(stderr, "read ended: {}", chunk.error().msg);
            }
            endpoint.reset();
            co_return 1;
          }
          const auto bytes = quic_bytes(*chunk);
          echoed.append(reinterpret_cast<const char *>(bytes.data()), bytes.size());
        }
      }
      std::println("echoed: \"{}\"", echoed);

      // Tells the peer why rather than leaving it to discover the silence, and
      // waits until the connection has actually ended. Awaiting this is what
      // replaces guessing at a sleep long enough for a flush nobody could
      // observe.
      quic_connection_close(*connection, 0, "done");
      (void)co_await quic_connection_closed(*connection);

      // Releasing the endpoint only *requests* the socket's uv_close; the loop
      // vio::run() is still turning is what completes it. Releasing it after
      // the loop has stopped is the one thing that hangs, and it is the same
      // rule every other vio handle obeys -- `stream` and `connection` need no
      // ordering of their own, because neither keeps the socket alive.
      endpoint.reset();
      co_return echoed == message ? 0 : 1;
    });
}
```

## What a server looks like

```cpp
// examples/quic_echo_server.cpp
//
// One coroutine per connection, one per stream, and a shutdown that is one
// awaited call rather than a sequence of sleeps.
//
// Every helper takes what it needs as a PARAMETER, never as a capture. task_t
// is eager, so a lambda coroutine's closure is already gone by its first
// suspension and a captured reference read after it is a use-after-free. The
// handles are copyable reference counts precisely so that the safe spelling is
// also the short one.

#include "quic_common.h" // make_self_signed

#include <vio/operation/quic_stream.h>
#include <vio/run.h>

#include <optional>
#include <print>
#include <utility>
#include <vector>

namespace
{
using namespace vio;

// Echo one stream until the peer finishes it.
//
// Nothing in here worries about the transport forgetting the stream. Once the
// last byte is read the transport erases its record -- that is how MAX_STREAMS
// credit gets back to the peer -- but this handle names the stream rather than
// pointing at it, and the terminal reason was latched before the reap could
// happen, so the loop below ends normally either way.
task_t<void> echo_stream(quic_stream_t stream)
{
  auto created = quic_stream_create_reader(stream);
  if (!created)
  {
    co_return;
  }
  auto reader = std::move(*created);

  for (;;)
  {
    auto chunk = co_await reader;
    if (!chunk)
    {
      if (chunk.error().code == vio_quic_stream_finished)
      {
        // The peer has said everything it had to say, so this half can end
        // too. The two halves are independent, so nothing did it for us.
        (void)co_await quic_stream_finish(stream);
      }
      else if (chunk.error().code == vio_quic_stream_reset)
      {
        std::println("stream {} reset by peer with 0x{:x}", quic_stream_id(stream), quic_stream_peer_reset_error(stream).value_or(0));
      }
      co_return;
    }

    // Suspends while this stream is over its high-water mark, or the connection
    // over its own, which is the whole of the backpressure: a client that sends
    // faster than it reads slows this loop down instead of growing the process.
    // It fails with vio_quic_stream_stopped if the client sends STOP_SENDING,
    // which is the signal to stop computing an answer nobody will read.
    if (auto written = co_await quic_stream_write(stream, quic_bytes(*chunk)); !written)
    {
      co_return;
    }
  }
}

// Accept streams until the connection ends.
//
// quic_accept_stream reports the *open*, not the bytes, so a stream that
// carried nothing but a FIN and one that was reset before a byte arrived both
// turn up here. Neither is visible through a "who has bytes right now" query,
// which is why an echo server could be written against the old API and a
// request/response server could not.
task_t<void> serve(quic_connection_t connection)
{
  std::vector<task_t<void>> streams;
  for (;;)
  {
    auto stream = co_await quic_accept_stream(connection);
    if (!stream)
    {
      break;
    }
    // Prune the finished ones, or a long-lived connection accumulates a frame
    // per stream it ever served.
    std::erase_if(streams, [](task_t<void> &t) { return t.done(); });
    streams.emplace_back(echo_stream(std::move(*stream)));
  }
  if (const auto reason = quic_connection_close_reason(connection); reason.has_value())
  {
    std::println("connection ended: {} 0x{:x} \"{}\"", reason->from_peer ? "peer" : "local", reason->error_code, reason->reason);
  }
  // Every stream coroutine's pending await was resolved by the same close that
  // ended the accept loop, so each of these is finished or about to be. Joining
  // them is what makes the shutdown below orderly rather than hopeful.
  for (auto &task : streams)
  {
    co_await std::move(task);
  }
}
} // namespace

int main()
{
  return vio::run(
    [](vio::event_loop_t &loop) -> vio::task_t<int>
    {
      using namespace vio;

      const auto identity = vio_example::make_self_signed("localhost");

      quic::tls_config_t tls;
      tls.role = quic::tls_role_t::server;
      tls.certificate_chain_pem = identity.certificate_pem;
      tls.private_key_pem = identity.private_key_pem;
      tls.alpn = {"vio-echo"};
      auto context = quic::tls_context_t::create(tls);
      if (!context)
      {
        std::println(stderr, "tls_context_t::create: {}", context.error().msg);
        co_return 1;
      }

      // The role is not set here: quic_endpoint_create takes it from the
      // context, so there is no second place for it to be stated and disagree.
      //
      // A server reachable from the internet should also set
      // config.transport.retry_key, or transport.max_connections, or both:
      // without either, one spoofed Initial buys a whole connection's worth of
      // state. On loopback this is only here to show where it goes.
      quic_config_t config;
      config.transport.max_connections = 64;

      auto created = quic_endpoint_create(loop, *context, config);
      if (!created)
      {
        std::println(stderr, "quic_endpoint_create: {}", created.error().msg);
        co_return 1;
      }
      std::optional<quic_endpoint_t> endpoint(std::move(*created));

      // Binding is what creates the socket and starts the endpoint driving
      // itself. The address family comes from this call, so nothing was pinned
      // to IPv4 by an endpoint that started before it knew where it was going.
      if (auto bound = quic_endpoint_bind(*endpoint, 4433); !bound)
      {
        std::println(stderr, "quic_endpoint_bind: {}", bound.error().msg);
        endpoint.reset();
        co_return 1;
      }
      std::println("listening on {}", quic_endpoint_local_port(*endpoint).value_or(0));

      // Cancelling this ends the accept loop. Wire it to a signal handler in a
      // real program; this one serves a fixed number so the example terminates.
      cancellation_t stop;
      std::vector<task_t<void>> sessions;
      constexpr std::size_t to_serve = 1;

      while (sessions.size() < to_serve)
      {
        auto connection = co_await quic_endpoint_accept(*endpoint, &stop);
        if (!connection)
        {
          break;
        }
        std::println("accepted from {}", "peer");
        sessions.emplace_back(serve(std::move(*connection)));
      }

      // Closes every live connection, waits for each CONNECTION_CLOSE to reach
      // the socket, and resolves every awaitable this endpoint owns -- so the
      // accept loops and stream reads above return rather than staying
      // suspended, and the frames below can be joined.
      (void)co_await quic_endpoint_shutdown(*endpoint, 0, "shutting down");

      for (auto &session : sessions)
      {
        co_await std::move(session);
      }

      // And only now the socket. This must still happen while the loop can
      // turn, which is vio's one universal rule and the only ordering this
      // program has to know.
      endpoint.reset();
      co_return 0;
    });
}
```

## Transport parameter defaults

DECISION: `transport_parameters_t`'s own default member initialisers do not change. Not one of them. The sane values arrive through `connection_config_t::transport_parameters = default_transport_parameters()` and through `quic_flow_control_t`, whose own initialisers ARE the policy.

WHY THE STRUCT CANNOT CARRY THEM. Verified in the source, not inferred. `decode_transport_parameters` (transport_parameters.h:252) opens with `transport_parameters_t parameters;` and then overwrites only the ids that actually appeared on the wire; `parse_resumption_ticket` (quic_connection.cpp:2972) does the same with a stored block. So those initialisers are RFC 9000 section 18.2's "the peer did not send this" values, and for every credit field that value is zero. Raise `initial_max_data` there and a peer that advertised nothing decodes as having granted a megabyte; this endpoint then sends into a window that does not exist and the peer closes with FLOW_CONTROL_ERROR. A resuming 0-RTT client makes the same mistake a round trip earlier. Independently, `encode_transport_parameters` (transport_parameters.h:172-239) decides "is this the default, skip it" against separate hardcoded RFC constants, so moving the initialisers desynchronises encoder and struct. Two existing tests are the guard rail and both keep passing untouched: `an empty extension decodes to every default` (test_quic_transport_parameters.cpp:50-63) and `defaults are not written to the wire` (:65-69).

THE USER'S PRINCIPLE IS STILL HONOURED, EXACTLY. Nothing that TCP does not make you specify is required here. `quic_endpoint_create(loop, context)` with no config produces a connection that carries data. All twelve hand-rolled parameter blocks in the tree get deleted, and `examples/quic_common.h`'s paragraph explaining that there is no such thing as a sensible default goes with them. The difference from putting them on the struct is invisible at every call site and is the difference between correct and wrong on the wire.

THE EXACT INITIALISERS, on `vio::quic_flow_control_t` (and, as plain assignments, in `vio::quic::default_transport_parameters()`):

  std::chrono::milliseconds max_idle_timeout{30000};
    Zero means a vanished peer is kept for ever. 30 s is what nine of the eleven in-tree blocks already say and what every stack that ships a default converged on.

  std::uint64_t initial_max_data = 8ull * 1024 * 1024;
    The connection-wide receive ceiling, and the real bound on receive memory because this layer keeps no second copy of received bytes. Less than the ~1.6 MiB vio's TLS stack commits per connection with no knob at all, and unlike vio's TCP read queue (an unbounded std::vector) it is a ceiling rather than a hope.

  std::uint64_t initial_max_stream_data_bidi_local = 2ull * 1024 * 1024;
  std::uint64_t initial_max_stream_data_bidi_remote = 2ull * 1024 * 1024;
    Four to one against the connection window on purpose, so one stream cannot be throttled by its own share while the connection still has room, and initial_max_data stays the number that actually bounds memory.

  std::uint64_t initial_max_stream_data_uni = 2ull * 1024 * 1024;
    Non-zero because the zero default has already caught the maintainer twice: test_quic_endpoint.cpp:87-96 and test_quic_connection.cpp:100-106 both leave the uni fields at zero and so cannot use unidirectional streams at all, with nothing reporting why.

  std::uint64_t initial_max_streams_bidi = 100;
  std::uint64_t initial_max_streams_uni = 100;
    A stream index costs nothing until a frame arrives for it -- `ensure_remote` (streams.h:615-625) deliberately materialises only the id that carried one -- and `grant_streams` returns credit as the application finishes, so this is a concurrency limit, not a total.

  std::uint64_t active_connection_id_limit = 4;
    Eight of the nine in-tree blocks that set it picked 4, and it is half the ceiling `decode_transport_parameters` already clamps to. Priced honestly: it is the PEER that loops on our advertised limit in `replenish_connection_ids` (quic_connection.cpp:1198-1230), so vio-to-vio each side now issues four IDs instead of two -- two extra CSPRNG draws, two extra HMACs and two extra `new_ids_pending` allocations per connection, at handshake only. `bench_quic` counts allocations and will see it; it is a fixed handshake cost, not a per-packet one.

  std::chrono::milliseconds max_ack_delay{25};
    Unchanged from the RFC value, but exposed and lowered onto BOTH places that need it: `transport_parameters_t::max_ack_delay` (uint64 ms, transport_parameters.h:117) and `connection_config_t::max_ack_delay` (chrono ns, connection.h:150). Those are two fields with two independent defaults that agree today and that nothing keeps in agreement, so a user who tuned one put a promise on the wire the implementation does not keep.

  std::uint64_t max_datagram_frame_size = 0;
    Stays zero on principle. It is the one credit in QUIC with no bound the transport enforces -- the queue behind it is drained only by `read_datagram()` -- so a non-zero default hands every endpoint a receive queue an application that does not use datagrams will never empty. Zero is also the "not supported" wire signal, so it costs no handshake bytes.

  bool grease_quic_bit = false;
    Off by default. Turning it on changes what vio's traffic looks like to anything filtering on that bit, which is an operational decision rather than a flow-control one. Flagged as an open question because the extension is worth little unless widely on and a reasonable maintainer goes the other way.

Left at their RFC values and not exposed on `quic_flow_control_t` at all: `max_udp_payload_size` (65527; vio reads into its own buffer, so the promise is true and no consumer has ever set it), `ack_delay_exponent` (3; changing it costs wire bytes in every handshake for nothing), `disable_active_migration` (false; it is a prohibition on the PEER, it does not cover NAT rebinding, and migration is not implemented here anyway). Anyone who needs one of those sets it on `config.transport.connection.transport_parameters` after `quic_to_transport_parameters` has run -- `quic_endpoint_create` applies flow control first, so a field flow control does not name survives.

Absent by construction and unreachable from configuration: `original_destination_connection_id`, `initial_source_connection_id`, `retry_source_connection_id`, `stateless_reset_token`. They are filled in per handshake and section 4.6.1 forbids carrying them across a resumption, so a user who can name them is a user who can be silently overridden.

AGGREGATE STATUS. `transport_parameters_t` stays an aggregate -- no user-declared constructors, no bases, no virtuals, no non-public data members -- so `transport_parameters_t{.initial_max_data = X}` still compiles. It is also still a trap, and that is precisely why the sane values live elsewhere: on the wire type that expression looks like a partial override and is a full reset to zero credit for the other eight credit fields. `quic_flow_control_t` is likewise an aggregate whose initialisers are the policy, so `quic_config_t{.flow_control = {.initial_max_data = 64u << 20}}` raises one limit and keeps the rest -- which is the partial override a user actually wants, and it is only correct because that type has no second job.

MEMORY COST, per connection, at the defaults:
  - Receive: `initial_max_data` = 1 MiB. That is the whole receive commitment, because this layer adds no queue of its own -- bytes stay in `receive_stream_t`'s reassembly until an await takes them, and taking them is the call that returns credit.
  - Send: bounded by `quic_connection_write_high_water` = 1 MiB across the connection, with `quic_stream_write_high_water` = 256 KiB per stream inside it. Nothing in QUIC bounds the send side (`send_stream_t::_data` is a std::vector with no limit), which is why these marks had to be invented in this layer.
  - Per-stream objects: roughly 300-400 bytes empty per open stream, so 200 open streams is about 70 KB. Unopened indices cost nothing.
  - Handshake transients: CRYPTO reassembly capped at 64 KiB per level, three levels, released at handshake completion.
  Steady-state ceiling ≈ 2.1 MiB per connection; ≈ 2.1 GiB per 1000 concurrent connections, plus about 190 MiB of handshake churn while they are all handshaking. Size for the ceiling, because that is where an adversarial peer drives it; typical residency is far below it, since the receive half is only full when the application has stopped reading and the send half only when the peer has.

THE ONE PLACE THE DEFAULT IS WRONG, stated rather than hidden: 1 MiB of connection credit caps a single connection at roughly `initial_max_data / round-trip` -- about 84 Mbit/s on a 100 ms path -- and there is no receive-window auto-tuning here to grow past it. Every stack that ships small starting windows has auto-tuning; vio does not, which is why this static number had to be chosen larger than theirs and is still wrong for transatlantic bulk. `examples/quic_bulk_transfer.cpp` already raises it to 8 MiB and will keep doing so, as the one deliberate deviation worth teaching. Auto-tuning is the proper fix and is a separate piece of work.

## Lifetime and teardown

OWNERSHIP RUNS DOWNWARD; EVERY LINK BACK UP IS A BORROWED RAW POINTER.

`quic_endpoint_state_t` owns the `vio::quic::endpoint_t`, a `uv_prepare_t` (the beat), a `timer_t` (loss and idle deadlines), the `task_t<void>` returned by `endpoint_t::run` plus the `cancellation_t` that stops it, the accept queue, and a `ref_ptr_t<quic_connection_state_t>` per live connection. The prepare handle and the timer are registered with the ref count via `register_handle`, so the last release `uv_close`s them and storage is freed only when both close callbacks have fired -- the same discipline `timer_impl.h` already uses, and the reason the beat is a handle this state owns rather than an `add_about_to_block_listener` registration. That matters concretely: `remove_about_to_block_listener` posts through `_run_in_loop` (event_loop_impl.h:171), and `exit_event_loop_cb` closes that pipe and then runs a nested `uv_run` before stopping the prepare (:190-203), so a removal posted during teardown is never delivered while `about_to_block_cb` keeps firing on freed storage. An owned handle has no such window.

`quic_connection_state_t` holds `quic_endpoint_state_t *endpoint` -- borrowed, nulled by the endpoint's `on_destroy` -- plus the `connection_t *` it is keyed on, the latched close reason and ALPN, and a `ref_ptr_t<quic_stream_state_t>` per registered stream. `quic_stream_state_t` holds `quic_connection_state_t *connection`, likewise borrowed, the stream id, the latched terminals and peer codes, and the pending-write FIFO.

The upward links must not be strong, and this is CLAUDE.md's rule stated in pointer terms. If a stream kept its connection alive keeping the endpoint alive, then a user still holding a `quic_stream_t` when `run()` returns is a `uv_close` never issued, `uv_loop_close` failing with EBUSY, and `~event_loop_t` printing every open handle and aborting on its assert. It is the same reason `timer_impl.h` parks a borrowed pointer in `timer->data`. So releasing the last `quic_endpoint_t` always closes the socket, whatever else is held, and there is exactly one rule to remember rather than a graph to reason about.

NO USER CODE EVER RUNS ON A TRANSPORT WALK'S STACK. This is what kills the fatal breaks structurally rather than by care. The API installs `endpoint_t::on_connection` and `on_activity` handlers that only *record*: mark the connection dirty, or push it onto the accept queue. The new `on_connection_gone` hook, fired at the draining latch inside `flush_entry`, likewise only latches the reason and queues the affected awaiters. `reap` never resumes anything. Resumption happens in exactly one place -- the beat -- which runs from the prepare handle, at which point `run()` is suspended at `co_await *reader`, the `touched` vector is out of scope, and `reap`'s iterator does not exist. A user coroutine resumed there may open a stream, close a connection, or drop the last endpoint handle with no walk to corrupt.

THE BEAT HOLDS A REF FOR ITS WHOLE BODY. `about_to_block` takes `ref_ptr_t<quic_endpoint_state_t>` at entry and drops it at exit, exactly as `read_cb` in socket_stream.h does `self->rc->inc()` / `rc->dec(); // final -- may destroy the state`. So a coroutine resumed mid-beat that drops the last user handle cannot free the state under the second half of the beat: the count never reaches zero until the beat returns, and `reference_counted_t::dec()` then runs the destroy sequence cleanly. The beat also collects the connections and streams it intends to touch into local `ref_ptr_t` vectors before resuming anything, so a resumed coroutine may destroy any of them without invalidating the walk.

BEAT ORDER, per loop turn:
  1. Take one `ref_ptr_t` on the endpoint state.
  2. For each dirty connection: drain the transport's new edge lists (streams opened, streams with data or a terminal, streams whose send credit actually rose), latch terminals and peer codes into the stream states, and feed pending writes up to the marks.
  3. Resume, from a local vector: connect and accept waiters, open-stream waiters, readers, writers, milestone waiters. Every registration is `reset()` before its continuation is resumed, because the resuming coroutine owns the `cancellation_t` and may destroy it.
  4. `endpoint_t::flush(connection_t&)` for each dirty connection, then rearm the `timer_t` to the earliest `next_timeout` seen.
  5. Drop the ref.
Step 3 must not need step 2 to have run first for correctness, and it does not: every reader's `await_ready` asks the transport directly, so a reader created by a coroutine resumed in step 3 -- which is the ordinary case for an accepted stream -- sees bytes that are already there and does not suspend. Without that, the first read on every stream would wait for the next beat, and on an otherwise idle connection that is `max_ack_delay`.

libuv runs prepare handles at the top of each iteration, before it blocks in poll. So a batch of datagrams delivered by poll is processed by `run()` (which flushes its own acknowledgements), the iteration completes, and the very next iteration's prepare is the beat -- one iteration, no wall-clock latency, and the reply still rides out before the loop sleeps.

WHAT KEEPS A STREAM SAFE AGAINST THE REAP. Nothing has to, which is the point. `reap_finished` erases a peer stream on the flush right after the application reads it to the end, because that is what returns MAX_STREAMS credit; delaying it to suit a handle would stall the peer. So the handle names the stream and re-looks-up, and the terminal reason is latched -- in the beat, and again in `await_resume` immediately after every `consume_stream`, which covers the case where a read completed synchronously on the user's stack. The latch therefore always precedes the flush that reaps. A handle to a reaped stream reports how it ended and refuses everything else.

REINCARNATION. Section 3.2 lets a peer reopen a stream at an id that was reaped, and `ensure_remote` will happily build a second `stream_t` there because `_remote_bidi_opened` is a high-water mark and not a set. No generation field is needed: the API's per-connection registry is told about every open through the new `take_opened_streams()` list, so an id arriving there for which a state is already registered is by definition a new incarnation. The old state is detached -- terminal pushed, writes failed with `vio_quic_stream_stale`, registry slot replaced -- and the application's old handle can never touch the new stream. Locally opened streams are never reaped today, so their ids never reincarnate.

RELEASING A STREAM HANDLE with a half still open runs the stream state's `on_destroy`: RESET_STREAM on an open sending half, STOP_SENDING plus `consume_stream(id, 0)` on an unfinished receiving half, then mark the connection dirty and rearm the endpoint timer. Silence is not an option -- a peer waiting on a half that is neither finished nor reset waits out the idle timeout -- and the rearm matters, because with the ticker replaced by a deadline-driven `timer_t` an idle connection has no other reason to run. The zero-byte consume is not cosmetic: `receive_stream_t::consume` calls `settle()` unconditionally first (stream.h:311), and `settle()` is the only path from `reset_received` to `reset_read`, which is what `reap_finished` requires before it will return the stream's MAX_STREAMS credit.

TEARDOWN, in `quic_endpoint_state_t::on_destroy`, which runs before the registered handles are closed:
  1. Null every connection state's `endpoint` pointer and every stream state's `connection` pointer, latching each connection's close reason and ALPN into its own state first.
  2. Resolve every suspended awaiter the endpoint owns -- accepts, dials, opens, reads, parked writes, milestones -- with `vio_quic_endpoint_closed`. This is the same thing `tls_server.h`'s `on_destroy` does for its parked listen awaiter, and for the same reason: a server that wrote before the handshake completed must not hang for ever.
  3. `driver_stop.cancel()`. `cancellation_t::cancel()` runs its callbacks inline and `datagram_reader_t::cancel()` resumes the suspended continuation synchronously, so `run()` finishes inside this call and its `task_t` destructor then destroys a frame that is `done()`. The read loop is guaranteed suspended here, because it never calls user code.
  4. `timer_disarm`, and destroy the stored task.
Then the ref count `uv_close`s the prepare handle, the timer and the socket, and frees storage when all three close callbacks have fired.

A SURVIVING HANDLE IS A TOMBSTONE, NOT A DANGLING POINTER. A `quic_connection_t` or `quic_stream_t` held past its owner's teardown is a live ref-counted state whose upward pointer is null: `quic_connection_close_reason`, `quic_connection_alpn` and the latched stream terminals still answer, and every operation returns a pre-resolved failure. Deliberately weaker than the `tcp_t` analogy suggests -- a `tcp_t` owns its socket, a `quic_connection_t` only names something the endpoint reaps on its own schedule -- and it is what lets the reap keep that schedule, which it must, because the reap is also what withdraws connection IDs from routing.

THE EAGER-task_t TRAP is closed by construction rather than documentation: all three handles are copyable `ref_ptr_t` wrappers, so `serve(std::move(*connection))` and `echo_stream(std::move(*stream))` -- state as coroutine parameters -- is strictly shorter to write than the `[&]` form that dangles, and there is not one `std::function` in the public surface to store a closure in.

## Backpressure

SEND SIDE. This is what the transport has nothing of: `connection_t::write_stream` copies onto `send_stream_t::_data`, a `std::vector<std::uint8_t>` with no limit, and returns `data.size()` whether or not a byte can ever leave. With today's zero-credit defaults it returns success for bytes that provably never move.

The replacement is socket_stream.h's producer throttle, measured in QUIC's units. A stream's depth is `send.queued() - send.acknowledged_prefix()` -- bytes the transport is carrying that the peer has not confirmed, both accessors already present and neither reachable from outside. `quic_stream_write` computes that depth, and the connection's total across its streams, and:

  - Under `quic_stream_write_high_water` (256 KiB) and `quic_connection_write_high_water` (1 MiB), the whole write goes to `write_stream` and the awaitable is returned already resolved. `await_ready` is true and the ordinary case costs no suspension.
  - Over either mark, the op records `{span, offset, fin}` and the awaitable is simply not resumed. There is no new API for backpressure; it is a resume that has not happened.

The op holds the caller's span and is fed in pieces by the beat: each pass submits `min(remaining, headroom)` bytes. That is what bounds a write of ANY size to the marks rather than to its own length -- a single `quic_stream_write(stream, four_gigabytes)` never buffers four gigabytes anywhere, it just takes many beats. The caller's buffer stays alive because the caller is suspended in the `co_await`, which is also why the borrowed overload needs no owning twin for correctness. The rvalue overloads exist so a caller need not keep the source itself, and they are honest about buying no copy: `send_stream_t::write` copies into the connection's queue either way.

Waiters are released down to the LOW marks, not the high ones. Resuming at the mark that stopped them produces one wake-up per acknowledgement; the gap is hysteresis, and it is the same two-threshold shape `drain_waiters()` uses.

Writes never reorder. A write issued while an earlier one on the same stream is still parked queues behind it even when there is room, because a stream is a byte stream and two writers cannot both be first. Across streams there is no coordination at all, which is what the multiplexing is for.

Three edges wake a parked writer, and the beat drains from all three: an acknowledgement that moved `acknowledged_prefix`, a MAX_STREAM_DATA that actually raised the stream's limit, and a MAX_DATA that actually raised the connection's. "Actually raised" is load-bearing -- `set_max_data` and `set_peer_max_data` are `std::max` clamps, so a duplicate frame is a no-op and must not wake anyone. A fourth edge is easy to miss and is a hang if it is: STOP_SENDING. `receive_stop_sending` resets the send half, after which nothing is ever acknowledged again, so a writer parked over the mark on a stream the peer has stopped is never woken by any of the three above. It gets its own edge and resolves with `vio_quic_stream_stopped`.

The two-hold discipline is copied verbatim: the op starts at `ref = 2`, one hold for the awaitable (released in its destructor, which nulls the continuation first) and one for the operation, so a synchronous completion cannot free the slot under a not-yet-constructed awaitable and abandoning the awaitable cannot resume a coroutine that is going away.

`quic_stream_flushed` is the separate question and resolves only when `acknowledged_prefix() >= queued()` AND the op FIFO is empty. Without the second condition it would report success on a stream with four megabytes still parked in this layer, which the transport's own counters cannot see -- and a caller deleting a local file on that signal would lose it.

CONNECTION-LEVEL BLOCKING is reported rather than hidden. `quic_stream_stats_t` carries `blocked_by_stream_credit` and `blocked_by_connection_credit` separately, forwarded from `send_stream_t`, because they are different problems with different fixes: one wants a bigger `initial_max_stream_data_*` from the peer, the other a bigger `initial_max_data`. Both predicates exist today and are evaluated at exactly one internal site inside the packet builder.

STREAM-CREATION BACKPRESSURE. `quic_open_stream` suspends when the peer's MAX_STREAMS is exhausted and is woken by the frame that raises it -- `streams_t::open` already sets `_streams_blocked_pending` once per limit, so the wait has a real event behind it. Section 4.6 forbids exceeding the limit, so waiting is the only correct behaviour; the current `std::optional` return simply made every caller write the poll loop.

RECEIVE SIDE. QUIC already has receive backpressure -- it is called flow control -- and the API's job is to use it rather than build a second buffer in front of it.

There is no application-level read queue. `await_resume` copies out of `readable_stream(id)` into a fresh `unique_buf_t` (or straight into the caller's span for `read_into`) and calls `consume_stream` for exactly what it took, which is the call that drives `pending_max_stream_data` and `release_connection_credit`. So not awaiting a reader is not consuming, and not consuming is telling the peer to wait, through the mechanism the protocol has for the purpose. A stream that has been accepted but has no reader yet is never drained at all, so it holds its own credit rather than buffering on the application's behalf.

That is why the memory arithmetic is honest: the per-connection receive commitment is exactly `initial_max_data`, not `initial_max_data` plus a per-stream application queue times the number of streams the peer chose to open. It is also strictly simpler than socket_stream's `ring_buffer_t<..., 10>` plus `disarm_reads`/`read_paused`, and it is available only because QUIC meters its own receive path and TLS-over-TCP does not.

The copy at `await_resume` is unavoidable and is one copy, not two: `readable()` returns a span into a `std::map<uint64_t, std::vector<uint8_t>>` that the ordinary append path reallocates (stream.h:425), so it cannot cross a suspension, and every read here is one. `read_into` saves the allocation, not the copy, and the header says so rather than borrowing tcp's zero-copy name for something that is not.

ACCEPT-SIDE BACKPRESSURE, both levels, needs no configuration to work. An unaccepted stream is never read, so it never reaches `data_read`/`reset_read`, so `reap_finished` never fires for it, so its MAX_STREAMS credit never returns and the peer stops opening more -- bounded by the limit this endpoint already advertised, with nothing dropped. `stream_accept_backlog` is a second, lower ceiling for an application that wants one. `accept_backlog` bounds handshake-complete connections nobody has taken; past it a new connection is refused rather than dropped, because a client told no can go elsewhere and one told nothing waits out its handshake timeout.

DATAGRAMS are deliberately not backpressured. RFC 9221 traffic is chosen over stream traffic to trade reliability for latency, so `quic_connection_write_datagram` refuses rather than queues, and the receive side is a bounded tail drop with a `dropped()` counter -- the `udp_set_recv_queue_limit` / `udp_recv_stats` shape, and the only way to notice a drop that by design tears nothing down.

## Errors and endings

Every ending arrives through one of two channels: a terminal entry in the reader's sequence, or an already-resolved awaitable carrying an `error_t`. There are no side-channel flags to remember to test, and there is no ending reported by the absence of something.

A PEER'S RESET_STREAM. Delivered by the reader as `error_t{.code = vio_quic_stream_reset, ...}`, after every byte the peer had already delivered and this layer had already handed over. The peer's 62-bit code does not fit in `error_t::code` -- `error_t` is `{int, std::string}` and is shared by every subsystem in vio -- so it is read with `quic_stream_peer_reset_error(stream)`, latched on the handle and valid for its life. This needs the internal fix at streams.h:391, where the code is currently `(void)`-discarded; without it a reset can only be reported as EOF, which is wrong. Any write parked on that stream resolves with the same code.

One honest caveat: `receive_stream_t::receive_reset` clears `_chunks` (stream.h:288), so bytes that arrived in the same batch as the reset and had not yet been taken are gone. That is what RESET_STREAM means and the peer chose it, but it is the one place where the ending does not strictly follow every byte the peer ever sent, and the header says so rather than asserting an invariant the transport does not keep.

A PEER'S STOP_SENDING. Not a read event at all -- it ends the SENDING half, and the halves are independent. Every parked and subsequent `quic_stream_write` resolves with `vio_quic_stream_stopped`, and `quic_stream_peer_stop_sending_error(stream)` gives the code. The value is already stored on `stream_t::stop_sending_error` and read by nothing in the library except one unit test, so this needs an accessor and no new state; the transport side is already correct, since `receive_stop_sending` auto-resets the send half and marks the stream sendable.

A CLEAN FIN. `vio_quic_stream_finished` from the reader, once every preceding byte has been handed over; `0` from `read_into`, matching `tcp_reader_t::read_into`'s EOF convention, where a reset is an error and never a zero. That these are two distinct codes is the whole fix for the defect that `stream_receive_finished()` returns true identically for `data_received`, `data_read`, `reset_received` and `reset_read` (quic_connection.cpp:3900-3909). It is the same distinction `vio_tls_clean_shutdown` and `vio_tls_truncated` already draw for TLS, one layer down.

A LOCAL HALF-CLOSE. `quic_stream_finish` is a FIN with no bytes; it resolves when the transport owns it and leaves the receiving half open. Nothing implies anything about the other half, which is why the two are modelled separately.

A LOCAL STOP_SENDING. `quic_stream_stop_sending` ends this endpoint's receiving half at once, resolving a suspended read with `vio_quic_stream_stopped` rather than waiting a round trip for the peer's answering RESET_STREAM -- a peer that ignores STOP_SENDING keeps sending, so waiting for it is not a bounded-time promise. This is also what makes a read abortable from a coroutine that does not own the reader, which the natural decomposition (reader as a local one frame down) otherwise makes impossible.

A CONNECTION ENDING, all five kinds, with the difference between them. `quic_connection_closed(connection)` resolves: a value for a clean ending (error code zero from either side), and otherwise `vio_quic_connection_closed`, `vio_quic_idle_timeout`, `vio_quic_stateless_reset`, `vio_quic_version_unsupported` or `vio_quic_handshake_failed` as appropriate. `quic_connection_close_reason()` gives the full `connection_close_t` -- code, application-or-transport, reason string, `from_peer` -- and keeps answering on a tombstone, because it is copied into the handle's own state. Every awaiter the connection owns, including every stream read and parked write, resolves at the same moment.

This requires the internal fix at quic_connection.cpp:3316-3331, and it is load-bearing rather than cosmetic: the handshake-timeout and idle-timeout paths both set `impl.state = closed; impl.close_frame_pending = false;` and set NO `close_reason`, so `close_reason()` returns nullopt for the two commonest natural endings -- precisely when an application most needs to know why. `begin_close` (:998), stateless reset and version-negotiation failure already set one.

A FAILED DIAL. `quic_endpoint_connect` resolves with the reason, and the causes are distinguishable: no version in common (`version_negotiation_failed()`), a TLS failure (the alert's code and text, which `begin_close` already records for every protocol error), no ALPN in common, the handshake deadline, and a synchronous failure to build the connection at all -- which pre-resolves the awaitable without ever suspending, like every other factory in vio. There is no separate resolve step for a caller to check; a bad address comes back on the same awaitable as the raw libuv code with `uv_strerror`'s message.

`quic_endpoint_connect_early` additionally fails when the ticket does not resume, because a caller that asked for 0-RTT and silently got a full handshake sends its first flight a round trip later than it believes. A rejected-but-resumed early flight is NOT an error and is not reported: the transport repairs those packets at once rather than waiting for loss detection, so the bytes go again under 1-RTT keys. `quic_connection_early_data_accepted()` is where to look if it matters.

THE ENDPOINT GOING AWAY. `vio_quic_endpoint_closed` on everything still suspended, resolved from `on_destroy` before any storage goes. Nothing is ever left parked on an object that is about to be freed -- the failure `tls_server.h`'s `on_destroy` exists to prevent, and which the current QUIC API has no analogue of at all.

A STALE STREAM HANDLE. `vio_quic_stream_stale`, when the id this handle names was reaped and the peer has since reopened it. Section 3.2 makes that legitimate, so the handle is retired rather than being allowed to act on a different stream.

CANCELLATION. The trailing `cancellation_t *cancel = nullptr` on every async entry point, including `quic_stream_read`, with vio's existing split: readers raise `UV_ECANCELED` as an ordinary terminal entry, futures raise `vio_cancelled`, and `is_cancelled()` covers both. Every registration is `reset()` BEFORE its continuation is resumed, because the resuming coroutine owns the token and may destroy it.

API MISUSE gets `vio_quic_busy` and a full sentence in the house style: "A read is already in progress on this stream. Await the outstanding read before starting another." / "Can not create multiple active readers for a stream. Destroy the other reader before making a new one." / "This connection already has an accept loop. Only one coroutine may accept streams on a connection." / "This stream has no receiving half. A unidirectional stream opened by this endpoint can only be written to."

DELIBERATELY NOT AN ERROR: a datagram that fails to authenticate, a packet for an unknown connection ID, a refused MTU probe, a Version Negotiation withheld from an undersized datagram. None of them was ever authenticated or promised, and none should be visible to an application.

## Proposed header: vio/operation/quic_endpoint.h

```cpp
// =============================================================================
// src/vio/operation/quic_endpoint.h  --  namespace vio
//
// The coroutine face of QUIC: endpoints and connections. Streams and datagrams
// are in quic_stream.h, which this header does not include -- a program that
// only dials and closes should not have to parse the stream API to do it.
//
// Everything under vio/quic/ stays exactly as it is. connection_t is a sans-I/O
// state machine and endpoint_t is a demultiplexer over one UDP socket, both
// driven by callbacks and by integer stream ids, and both testable with no
// socket under them. That is the right shape for the inside of a transport and
// the wrong shape for an application, which wants to write co_await and not to
// hold a uint64_t that may name a different stream ten milliseconds from now.
// This header is a layer over those, in namespace vio beside tcp.h and udp.h,
// because that is where a vio application looks for a transport.
//
// The organising idea is the loop turn. Datagrams that arrived together are
// taken in together by the endpoint's read loop, which marks the connections
// they touched and sends whatever acknowledgements they owe. Then, once, before
// the loop blocks again, every coroutine that has become runnable is resumed
// and everything they wrote is pushed onto the socket. That second half is the
// beat, and it runs from a uv_prepare_t this endpoint owns.
//
// Two properties follow, and both are load-bearing:
//
//   - No user code ever runs on the read loop's stack, or inside the endpoint's
//     reap. Both walk raw pointers into a vector the application is invited to
//     mutate, so a coroutine resumed from either could reallocate the container
//     it is being iterated from, or drop the last endpoint handle and free the
//     state underneath the walk. Deferring to the beat makes those unreachable
//     rather than merely unlikely.
//
//   - A reply rides out with the acknowledgement that was going to be sent
//     anyway. libuv runs prepare handles at the top of each iteration, before
//     it blocks in poll, so the beat costs an iteration and no wall-clock
//     latency, and a server answering a burst still produces a burst -- which
//     is what keeps the segmentation offload fed.
//
// There is no run() and no flush() here. An endpoint starts reading the first
// time it is bound or dialled -- not at create(), because libuv makes a UDP
// socket lazily and whoever touches it first fixes its address family, which is
// how an endpoint that started before it knew where it was going ends up unable
// to reach an IPv6 peer. An application that has to remember to flush is an
// application that will forget to.
// =============================================================================

#pragma once

#include "vio/cancellation.h"
#include "vio/error.h"
#include "vio/event_loop.h"
#include "vio/quic/endpoint.h"
#include "vio/ref_counted_wrapper.h"

#include <chrono>
#include <coroutine>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace vio
{

// -----------------------------------------------------------------------------
// Error codes
// -----------------------------------------------------------------------------
//
// One hex word per subsystem, raised next to the code that raises it, the way
// ssl_engine.h owns 0x715c00. Every one of these is something a caller can
// branch on. That matters most for the first two: today
// connection_t::stream_receive_finished() answers true for a clean FIN and for
// a peer that threw the stream away alike, which is the QUIC equivalent of not
// having vio_tls_clean_shutdown and vio_tls_truncated, and an application that
// cannot tell those apart cannot be correct.

// The peer sent everything it meant to and closed its half. QUIC's EOF, and the
// only ending here that is not a failure.
inline constexpr int vio_quic_stream_finished = 0x9c1c01;

// RESET_STREAM: the peer abandoned its sending half. Whatever it had already
// delivered was handed over first; whatever it had not is gone. Its own 62-bit
// application code does not fit in error_t::code, so it is read back with
// quic_stream_peer_reset_error(), which stays valid for the life of the handle.
inline constexpr int vio_quic_stream_reset = 0x9c1c02;

// STOP_SENDING: the peer wants nothing more on this stream, so a write fails
// rather than queueing bytes nobody will read. Also what a local
// quic_stream_stop_sending() reports to this endpoint's own reader, since the
// application has said it wants nothing more either.
inline constexpr int vio_quic_stream_stopped = 0x9c1c03;

// This handle names a stream the transport has finished with and the peer has
// since reopened at the same id. Section 3.2 makes that legitimate -- the
// stream limit is a high-water mark, not a set -- so the old handle is retired
// rather than being allowed to act on the new stream.
inline constexpr int vio_quic_stream_stale = 0x9c1c04;

// The connection ended under this operation. quic_connection_close_reason()
// says who said so and why.
inline constexpr int vio_quic_connection_closed = 0x9c1c05;

// Section 10.1: the negotiated idle period elapsed. Distinct from a close
// because nobody said anything -- there is no error code and no reason string
// from either side, which is the whole reason the timer exists.
inline constexpr int vio_quic_idle_timeout = 0x9c1c06;

// The handshake did not complete: a certificate that did not verify, no ALPN in
// common, or the handshake deadline of connection_config_t::handshake_timeout.
inline constexpr int vio_quic_handshake_failed = 0x9c1c07;

// Section 10.3: the peer no longer remembers this connection at all.
inline constexpr int vio_quic_stateless_reset = 0x9c1c08;

// Section 6.2: the peer offered no version this build speaks.
inline constexpr int vio_quic_version_unsupported = 0x9c1c09;

// The endpoint was released while this was suspended. Every awaitable an
// endpoint owns resolves with this before its storage goes, because a coroutine
// that is never resumed is a leaked frame and, if it holds a handle, an event
// loop that never returns.
inline constexpr int vio_quic_endpoint_closed = 0x9c1c0a;

// API misuse: a second concurrent waiter on an operation that has one slot, or
// a second reader on a stream. Carries a full-sentence message saying what to
// do instead, in the style tcp_create_reader already uses.
inline constexpr int vio_quic_busy = 0x9c1c0b;

// -----------------------------------------------------------------------------
// Flow control
// -----------------------------------------------------------------------------

// The nine numbers that decide whether a connection can carry anything, with
// values that mean it can.
//
// These are deliberately not the default member initialisers of
// vio::quic::transport_parameters_t, and moving them there would be a wire bug
// rather than a style choice. That struct is also the decoder's accumulator:
// decode_transport_parameters() default-constructs one and overwrites only the
// parameters that actually arrived, and parse_resumption_ticket() does the same
// with a stored block. Its initialisers therefore *are* RFC 9000 section 18.2's
// "the peer did not send this" values, and for every credit field that value is
// zero. Give initial_max_data a generous initialiser there and a peer that
// advertised nothing reads as having granted a megabyte; this endpoint then
// sends into a window that does not exist and the peer is entitled to close the
// connection with FLOW_CONTROL_ERROR. A resuming 0-RTT client would make the
// same mistake a round trip earlier, before the server has said anything that
// could correct it.
//
// So the wire type keeps the RFC's meaning, and the policy lives here -- in a
// type whose own initialisers are the policy, which is also what makes
//
//   quic_config_t{.flow_control = {.initial_max_data = 64u << 20}}
//
// raise one limit and leave the other eight alone. The same expression written
// against transport_parameters_t looks like a partial override and is in fact a
// full reset to zero credit for everything it does not name.
//
// The four handshake-owned parameters -- the two connection IDs, the original
// destination ID and the stateless reset token -- are absent on purpose. They
// are filled in per handshake by the connection machinery and section 4.6.1
// forbids carrying them across a resumption, so a user who can name them is a
// user who can be silently overridden.
struct quic_flow_control_t
{
  // Zero, which is what section 18.2 assigns to an absent parameter, means a
  // peer that vanishes is kept for ever. Thirty seconds is what nine of the
  // eleven hand-written parameter blocks in this repository already say and
  // what every other implementation that ships a default arrived at. The
  // negotiated timeout is the smaller of the two sides'.
  std::chrono::milliseconds max_idle_timeout{30000};

  // Unread bytes this endpoint promises to hold across the whole connection.
  // It is the real bound on receive memory, because this layer keeps no second
  // copy: bytes stay in the transport's reassembly until a reader takes them,
  // and taking them is what returns the credit.
  //
  // A megabyte is less than the roughly 1.6 MiB vio's own TLS stack commits per
  // connection with no knob at all, and unlike vio's TCP read queue -- a
  // std::vector with no limit -- it is a ceiling rather than a hope.
  //
  // It is also the throughput ceiling on a long path: a megabyte over a 100 ms
  // round trip is about 84 Mbit/s, and there is no receive-window auto-tuning
  // here to grow past it. A bulk transfer over a fat path raises this and the
  // three below; a request/response service on a short one never touches them.
  std::uint64_t initial_max_data = 8ull * 1024 * 1024;

  // Per stream, deliberately overcommitted four to one against the connection
  // window, so that one stream cannot be throttled by its own share while the
  // connection still has room and initial_max_data stays the number that
  // actually bounds memory.
  std::uint64_t initial_max_stream_data_bidi_local = 2ull * 1024 * 1024;
  std::uint64_t initial_max_stream_data_bidi_remote = 2ull * 1024 * 1024;
  // Non-zero on purpose. The two largest QUIC test files in this repository
  // both leave the unidirectional pair at the RFC value and so cannot use
  // unidirectional streams at all, with nothing anywhere reporting why -- which
  // is exactly the failure a default exists to prevent, caught twice in vio's
  // own suite.
  std::uint64_t initial_max_stream_data_uni = 2ull * 1024 * 1024;

  // How many streams the peer may have open at once. An index costs nothing
  // until a frame arrives for it -- ensure_remote materialises only the id that
  // carried one -- and MAX_STREAMS returns credit as the application finishes
  // with each stream, so this is a concurrency limit and not a total.
  std::uint64_t initial_max_streams_bidi = 100;
  std::uint64_t initial_max_streams_uni = 100;

  // Section 5.1. Spare connection IDs are what let a peer migrate without being
  // linkable across the move. Four rather than the RFC's two because every
  // consumer in this repository picked four, and rather than the eight the
  // decoder already clamps to because each one the peer issues costs it a draw
  // from the CSPRNG and an HMAC.
  std::uint64_t active_connection_id_limit = 4;

  // How long this endpoint may sit on an acknowledgement. Set once here and
  // lowered onto both places that need it: the wire parameter the peer reads,
  // and connection_config_t::max_ack_delay, which loss recovery reads. Those
  // are two fields of two types with two independent defaults that happen to
  // agree, and nothing enforces that they still do -- so a user who tuned one
  // of them put a promise on the wire the implementation does not keep.
  std::chrono::milliseconds max_ack_delay{25};

  // RFC 9221, and the one credit field that stays off. Every other number here
  // bounds a queue the transport itself drains; this one bounds a queue only
  // quic_connection_read_datagram() empties, and an application that does not
  // use datagrams never calls it. Zero is also the wire signal for "not
  // supported", so leaving it costs no handshake bytes.
  std::uint64_t max_datagram_frame_size = 0;

  // RFC 9287. Offering it promises only to accept a cleared QUIC bit; clearing
  // one requires the peer to have offered too, so two conditions hold before
  // anything on the wire changes. Off by default because turning it on changes
  // what vio's traffic looks like to anything filtering on that bit, and that
  // is an operational decision rather than a flow control one. The extension is
  // worth little unless it is widely on, so this is the field here most likely
  // to want flipping.
  bool grease_quic_bit = false;
};

// Lowers the policy onto the wire type, overwriting exactly what it names and
// leaving the rest -- including anything a future RFC adds -- untouched.
// Exposed so that code working directly against connection_config_t can get the
// same numbers rather than a second, drifting set.
[[nodiscard]] vio::quic::transport_parameters_t quic_to_transport_parameters(const quic_flow_control_t &flow_control, vio::quic::transport_parameters_t base = {});

// -----------------------------------------------------------------------------
// Endpoint configuration
// -----------------------------------------------------------------------------

struct quic_config_t
{
  // The only place transport parameters are named. Whatever
  // transport.connection.transport_parameters holds is overwritten from this at
  // create time, because two sources of truth for flow control is a connection
  // that stalls for a reason nothing reports.
  quic_flow_control_t flow_control;

  // Everything the transport already has an opinion about: the retry key, the
  // stateless reset key, ECN, segmentation offload, the qlog directory, the
  // connection ceiling, the draining period, and the whole of
  // connection_config_t underneath -- congestion controller, pacing, handshake
  // timeout, datagram size ceiling. Those defaults are good and are left alone.
  //
  // Two of its fields are written by quic_endpoint_create and whatever is set
  // here is discarded. connection.role is taken from the tls_context_t, which
  // already knows what it was built for, so the role cannot be stated twice and
  // disagree with itself. connection.transport_parameters is taken from
  // flow_control above.
  vio::quic::endpoint_config_t transport;

  // Connections whose handshake has completed and which nothing has accepted
  // yet. Past this a new connection is refused rather than queued, because a
  // client told no can go elsewhere and a client told nothing waits out its
  // handshake timeout. Distinct from transport.max_connections, which bounds
  // connections in total including ones still handshaking.
  std::size_t accept_backlog = 128;

  // Peer-opened streams waiting for quic_connection_accept_stream. The peer's
  // negotiated stream limit already bounds this and is the mechanism that
  // matters -- an unaccepted stream is never read, so it never reaches a
  // terminal state, so it is never reaped, so its MAX_STREAMS credit is never
  // returned and the peer simply stops opening more. This is a second, lower
  // ceiling for an application that wants one; past it a stream is refused with
  // STOP_SENDING, and with RESET_STREAM as well if it has a sending half.
  std::size_t stream_accept_backlog = 64;
  std::uint64_t stream_refused_error = 0;
};

// What vio advertises when the application says nothing, for code below this
// header. connection_config_t::transport_parameters is initialised from it,
// which is the single line that fixes every existing caller of the transport as
// well as every future one -- including the twelve places in this repository
// that hand-roll a parameter block today, no two of them alike.
namespace quic_detail
{
} // namespace quic_detail

// -----------------------------------------------------------------------------
// Handles
// -----------------------------------------------------------------------------

namespace detail
{
struct quic_endpoint_state_t;
struct quic_connection_state_t;
struct quic_stream_state_t;
} // namespace detail

// Aggregate structs over ref_ptr_t, member named `handle`, exactly as tcp_t and
// ssl_server_client_t are. Copying one is a refcount bump, not a duplicate.
//
// The ownership direction is the thing to know, and it is the rule
// timer_impl.h already states about a handle's data field: an endpoint holds
// strong references to its connections and a connection to its streams, and the
// links back up are borrowed raw pointers, nulled when the owner tears down.
// The other way round -- a stream keeping its connection alive keeping the
// endpoint alive -- is a socket whose uv_close is never issued, which is
// uv_loop_close failing with EBUSY and ~event_loop_t aborting on its assert. So
// releasing the last quic_endpoint_t always closes the socket, whatever else is
// still held, and CLAUDE.md's one rule -- release a handle while the loop can
// still run -- applies here unchanged and unextended.
struct quic_endpoint_t
{
  ref_ptr_t<detail::quic_endpoint_state_t> handle;
};

// A connection. Copyable, and cheap enough that passing one by value into a
// coroutine's parameter list is the obvious thing to write -- which matters,
// because task_t is eager, so a lambda coroutine that captured it by reference
// would read a destroyed closure at its first suspension. The safe spelling is
// also the short one.
//
// It names a connection rather than owning it. The endpoint collects a closed
// connection after its draining period, and that schedule must not slip: the
// collection is what withdraws the connection IDs from routing, and a closed
// connection that stayed routable is a bug. A handle held past that point does
// not dangle and does not keep the transport object alive -- it becomes a
// tombstone. quic_connection_close_reason() and quic_connection_alpn() still
// answer, because both are copied into this handle's own state the moment the
// connection ends, and every operation fails with vio_quic_connection_closed.
struct quic_connection_t
{
  ref_ptr_t<detail::quic_connection_state_t> handle;
};

// -----------------------------------------------------------------------------
// Awaitables
// -----------------------------------------------------------------------------
//
// Three shapes, because QUIC needs three and pretending otherwise is where the
// bugs are. Every one of them is returned by value and, on any synchronous
// failure, returned already resolved -- there is no factory in this header that
// returns std::expected<future, error_t>, which is what makes every call site
// read the same:
//
//   auto r = co_await quic_something(...);
//   if (!r) { ... r.error().msg ... }

// One. The tcp_future_t shape: a single operation slot embedded in the owner's
// state, for an operation that is genuinely singular and re-armed by being
// called again. The redundant done-check in await_suspend closes the window
// where the operation completed between await_ready and the suspend, which for
// QUIC is a real window -- an accept whose queue is already non-empty completes
// inside its own factory.
//
// A second concurrent waiter on one of these is refused with vio_quic_busy
// rather than being allowed to overwrite the first one's continuation, which is
// the rule tcp.h states in prose and this header enforces.
template <typename Owner, typename State>
struct quic_future_t
{
  ref_ptr_t<Owner> handle;
  State *state;

  quic_future_t(ref_ptr_t<Owner> owner, State &slot)
    : handle(std::move(owner))
    , state(&slot)
  {
  }
  bool await_ready() noexcept
  {
    return state->done;
  }
  bool await_suspend(std::coroutine_handle<> continuation) noexcept
  {
    if (state->done)
    {
      return false;
    }
    state->continuation = continuation;
    return true;
  }
  auto await_resume() noexcept
  {
    return state->result;
  }
};

// Two. A milestone: something that has either happened or has not, reported
// rather than consumed. It may be awaited late, awaited twice, and awaited by
// several coroutines at once -- a per-connection supervisor watching for the
// end while a stream handler reads is the shape an HTTP/3 GOAWAY wants, and a
// single stored continuation would silently drop all but the last of them. So
// the waiters are a list and every one is resumed. It also tolerates a null
// handle, the way tls_server_client_handshake_future_t does, so awaiting one on
// a handle that was never valid is well defined rather than a dereference.
template <typename Owner, typename Result>
struct quic_milestone_t
{
  ref_ptr_t<Owner> handle;
  Result (*read)(Owner *);
  bool (*reached)(Owner *);

  [[nodiscard]] bool await_ready() const noexcept;
  void await_suspend(std::coroutine_handle<> continuation) noexcept;
  Result await_resume() noexcept;
};

// Three. A per-call operation, heap allocated, released by whichever of the
// awaitable and the transport lets go of it last -- the two-party protocol
// udp_send_op_t already uses. This is what an operation gets when any number of
// them may be in flight at once, which is the case for exactly three things: an
// endpoint dials many peers, a connection has many coroutines wanting to open a
// stream when the peer's limit is reached, and a program writes to many streams
// at once. Giving those the single-slot shape above would make the second
// concurrent caller of each either fail or hang, and for open_stream that is
// precisely the caller the queueing behaviour exists for.
//
// Abandoning one of these before it resolves is safe and cancels nothing that
// has already been handed to the transport: the destructor nulls its
// continuation and drops one hold, and the transport finishes underneath.
class quic_connect_awaitable_t
{
public:
  quic_connect_awaitable_t(quic_connect_awaitable_t &&other) noexcept;
  quic_connect_awaitable_t &operator=(quic_connect_awaitable_t &&other) noexcept;
  quic_connect_awaitable_t(const quic_connect_awaitable_t &) = delete;
  quic_connect_awaitable_t &operator=(const quic_connect_awaitable_t &) = delete;
  ~quic_connect_awaitable_t();

  [[nodiscard]] bool await_ready() const noexcept;
  bool await_suspend(std::coroutine_handle<> continuation) noexcept;
  std::expected<quic_connection_t, error_t> await_resume() noexcept;

private:
  friend struct detail::quic_endpoint_state_t;
  struct op_t;
  explicit quic_connect_awaitable_t(op_t *op);
  op_t *_op = nullptr;
};

namespace detail
{
struct quic_accept_slot_t;
} // namespace detail

using quic_accept_future_t = quic_future_t<detail::quic_endpoint_state_t, detail::quic_accept_slot_t>;

// -----------------------------------------------------------------------------
// Endpoint
// -----------------------------------------------------------------------------

// The role comes from the context, which already knows whether it was built for
// a client or a server, rather than being stated a second time on the config
// with nothing checking that the two agree -- a wart the examples currently
// complain about in a comment.
//
// No socket is opened here. libuv creates a UDP socket lazily and its address
// family is fixed by whoever touches it first, so an endpoint that opened one
// at construction would be pinned to IPv4 before anyone said what they wanted.
// It is opened by the first quic_endpoint_bind or quic_endpoint_connect, each of
// which carries the family in the sockaddr it was given, and the read loop and
// the beat start with it.
[[nodiscard]] std::expected<quic_endpoint_t, error_t> quic_endpoint_create(event_loop_t &loop, const vio::quic::tls_context_t &context, const quic_config_t &config = {});

// A server binds; a client may skip this and let the OS choose a port at its
// first dial, exactly as with udp_bind.
[[nodiscard]] std::expected<void, error_t> quic_endpoint_bind(quic_endpoint_t &endpoint, const sockaddr *address);
[[nodiscard]] std::expected<void, error_t> quic_endpoint_bind(quic_endpoint_t &endpoint, std::uint16_t port);
[[nodiscard]] std::expected<std::uint16_t, error_t> quic_endpoint_local_port(const quic_endpoint_t &endpoint);
[[nodiscard]] std::expected<sockaddr_storage, error_t> quic_endpoint_sockname(const quic_endpoint_t &endpoint);

// Resolves once for each connection that has completed a handshake, in the
// order they complete, and is re-armed by being called again -- the tcp_listen
// contract, and the same reason for it: the endpoint is armed permanently and
// the awaitable is what is one-shot.
//
// It yields the connection directly rather than needing a separate synchronous
// accept, because QUIC has no listen call and no backlog to arm: a bound
// endpoint is already answering Initials, so importing tcp's two-step would be
// ceremony whose mechanism does not exist here.
//
// Only one coroutine may be in an accept loop at a time; a second is refused
// with vio_quic_busy. Connections that complete while nothing is waiting queue,
// bounded by quic_config_t::accept_backlog.
[[nodiscard]] quic_accept_future_t quic_endpoint_accept(quic_endpoint_t &endpoint, cancellation_t *cancel = nullptr);

// Dials, and resolves when the handshake completes or fails. Connected means
// what it means for ssl_client_connect -- the certificate has verified, an ALPN
// has been agreed, and the peer's transport parameters have arrived, so a
// stream opened on the result will have credit -- and not that the first
// Initial has been queued.
//
// A ticket kept from an earlier connection to this peer shortens the handshake
// and, with quic_endpoint_connect_early, lets the first flight carry data. It is
// per dial rather than part of the config because a ticket is about one peer and
// an endpoint dials many, and one that will not parse is a full handshake rather
// than a failure to connect.
[[nodiscard]] quic_connect_awaitable_t quic_endpoint_connect(quic_endpoint_t &endpoint, const sockaddr *address, std::string_view server_name, cancellation_t *cancel = nullptr);
[[nodiscard]] quic_connect_awaitable_t quic_endpoint_connect(quic_endpoint_t &endpoint, const sockaddr *address, std::string_view server_name, std::span<const std::uint8_t> resumption_ticket,
                                                             cancellation_t *cancel = nullptr);

// The 0-RTT dial: resolves as soon as the connection can carry early data,
// which is before the server has said anything. Everything written before
// quic_connection_ready() resolves goes out under early keys, with section
// 4.6's caveat that it is replayable and must therefore be idempotent.
//
// A refusal is not reported and needs no handling: the transport repairs the
// rejected packets at once rather than waiting for loss detection, so the bytes
// go again under 1-RTT keys and the application never learns it happened.
// quic_connection_early_data_accepted() is where to look if it matters. What
// this does fail on is a ticket that will not resume, because a caller that
// asked for early data and silently got a full handshake sends its first flight
// a round trip later than it believes.
[[nodiscard]] quic_connect_awaitable_t quic_endpoint_connect_early(quic_endpoint_t &endpoint, const sockaddr *address, std::string_view server_name, std::span<const std::uint8_t> resumption_ticket,
                                                                   cancellation_t *cancel = nullptr);

// A snapshot of every connection this endpoint currently holds, which is what a
// server needs to shut down: the transport can name its connections and the old
// API could not hand any of them to an application outside a callback.
// Copyable handles, so holding the vector is safe and the connections in it
// behave as tombstones if they end before the caller gets to them.
[[nodiscard]] std::vector<quic_connection_t> quic_endpoint_connections(const quic_endpoint_t &endpoint);
[[nodiscard]] std::size_t quic_endpoint_connection_count(const quic_endpoint_t &endpoint);

// Closes every live connection with this code and reason, stops accepting, and
// resolves every awaitable this endpoint owns -- accepts, dials, opens, reads
// and parked writes -- so that every coroutine suspended on it runs to
// completion and frees its frame. It resolves once each CONNECTION_CLOSE has
// been built into a datagram and handed to the socket, or once close_timeout
// has passed for the ones that could not be.
//
// This is what replaces cancel, sleep 50ms, reset the endpoint, sleep, stop the
// loop. It is not the whole teardown and does not pretend to be: it does not
// close the socket. Releasing the last quic_endpoint_t does that, and that must
// still happen while the loop can turn, which is the same rule every other vio
// handle obeys. Awaiting this first is what makes the release orderly rather
// than abrupt -- without it the peers learn the connection ended from their own
// idle timers.
[[nodiscard]] quic_milestone_t<detail::quic_endpoint_state_t, std::expected<void, error_t>> quic_endpoint_shutdown(quic_endpoint_t &endpoint, std::uint64_t error_code = 0,
                                                                                                                   std::string_view reason = {},
                                                                                                                   std::chrono::milliseconds close_timeout = std::chrono::milliseconds(200));

// Datagrams divided by system calls, which is the only way to tell whether the
// segmentation offloads are doing anything.
[[nodiscard]] vio::quic::endpoint_stats_t quic_endpoint_stats(const quic_endpoint_t &endpoint);

// The transport underneath, for anything this header does not wrap: key update,
// path validation, qlog, the peer's raw transport parameters. Null once the
// endpoint has been released. Do not hold what it returns across a co_await --
// ask again, because the endpoint may run in between and collect what you have.
[[nodiscard]] vio::quic::endpoint_t *quic_endpoint_native(quic_endpoint_t &endpoint);

// -----------------------------------------------------------------------------
// Connection
// -----------------------------------------------------------------------------

// Resolves when the handshake completes, and is safe to await late, twice, or
// not at all. After quic_endpoint_connect it has already happened; after
// quic_endpoint_connect_early it is how a 0-RTT client learns the verdict is in.
[[nodiscard]] quic_milestone_t<detail::quic_connection_state_t, std::expected<void, error_t>> quic_connection_ready(quic_connection_t &connection);

// Resolves when the connection ends, however it ends, and says why. A
// CONNECTION_CLOSE from either side, an idle timeout, a handshake that ran out
// of time, a stateless reset, a version negotiation that found nothing in
// common -- all of them, and the difference between them, which the transport
// today reports for only three of the five. Awaitable late, twice, and by
// several coroutines at once.
//
// Success means a clean ending: error code zero from either side. Anything else
// arrives as the matching vio_quic_* code, with the peer's reason string in the
// message and the full detail in quic_connection_close_reason().
[[nodiscard]] quic_milestone_t<detail::quic_connection_state_t, std::expected<void, error_t>> quic_connection_closed(quic_connection_t &connection);

// Queues a CONNECTION_CLOSE, which goes out on the next beat. Void rather than
// awaitable because the first reason wins: a connection the peer has already
// closed, or that has already timed out, queues nothing, and an awaitable that
// resolved successfully having sent nothing would be a lie. Await
// quic_connection_closed to know it ended, and read the reason to know how.
//
// `application` defaults to true because a caller reaching for this from an
// application is closing for a reason in its own error space; the transport
// codes are for violations this layer raises.
void quic_connection_close(quic_connection_t &connection, std::uint64_t error_code = 0, std::string_view reason = {}, bool application = true);

// Engaged from the moment the connection ends, and stays engaged for the life
// of the handle -- including after the endpoint has collected the connection or
// been released, because the reason is copied into the handle's own state
// rather than read back out of a transport object that may be gone.
[[nodiscard]] std::optional<vio::quic::connection_close_t> quic_connection_close_reason(const quic_connection_t &connection);
[[nodiscard]] bool quic_connection_is_open(const quic_connection_t &connection);

// By value, not a view. connection_t::selected_alpn() returns a string_view
// into transport storage the endpoint may collect at any point the application
// is not looking, and ssl_client_alpn_selected already returns an owning copy
// for exactly that reason. Empty until the handshake completes.
[[nodiscard]] std::string quic_connection_alpn(const quic_connection_t &connection);
[[nodiscard]] std::expected<sockaddr_storage, error_t> quic_connection_peer_address(const quic_connection_t &connection);

// Keep these and hand them to the next dial. The ticket carries the TLS session
// and the server's transport parameters together, because section 4.6.1
// requires a resuming client to stay inside last time's limits and there is
// nothing else to go on before the server has spoken. The token saves the round
// trip a Retry would otherwise cost. Both are empty until the server has issued
// them, and on a server always.
[[nodiscard]] std::vector<std::uint8_t> quic_connection_resumption_ticket(const quic_connection_t &connection);
[[nodiscard]] std::vector<std::uint8_t> quic_connection_new_token(const quic_connection_t &connection);
[[nodiscard]] bool quic_connection_early_data_accepted(const quic_connection_t &connection);

// What the path is doing. Nothing steers on these; they are what a progress
// bar, a log line and a bandwidth-delay-product calculation are made of, and
// smoothed_rtt is what a latency-sensitive application budgets against. Zeroed
// on a tombstone rather than being unavailable, so a shutdown path can log
// without branching.
struct quic_connection_stats_t
{
  std::chrono::nanoseconds smoothed_rtt{};
  std::chrono::nanoseconds rtt_variation{};
  std::chrono::nanoseconds min_rtt{};
  std::size_t congestion_window = 0;
  std::size_t bytes_in_flight = 0;
  std::size_t datagram_size = 0;
  std::uint64_t delivery_rate = 0;
  std::uint64_t peak_delivery_rate = 0;
  std::uint64_t migrations = 0;
  std::size_t open_streams = 0;
  bool in_slow_start = false;
};
[[nodiscard]] quic_connection_stats_t quic_connection_stats(const quic_connection_t &connection);

// The transport connection underneath, for what this header does not wrap. Null
// on a tombstone, and valid only for the stretch of code that asked: do not
// hold it across a co_await, because the endpoint may collect between one
// resumption and the next. Ask again instead -- which is what endpoint.h
// already tells callers about the pointer connect() used to hand back.
[[nodiscard]] vio::quic::connection_t *quic_connection_native(quic_connection_t &connection);

} // namespace vio


// =============================================================================
// src/vio/quic/transport_parameters.h  --  the one addition to the wire type
// =============================================================================
namespace vio::quic
{
// vio's opinion about what a connection should be allowed to carry, as opposed
// to the RFC's statement about what an absent parameter means -- which is what
// transport_parameters_t's own member initialisers are, and must stay.
//
// Two of these differ from section 18.2's values and so appear on every
// handshake's wire from now on, for three bytes each: active_connection_id_limit
// and, once anyone sets it, grease_quic_bit. Everything else that differs is a
// credit field, which was going on the wire anyway because zero credit is not a
// connection anyone can use.
//
// max_datagram_frame_size stays zero. It is the one credit in QUIC with no
// bound the transport enforces, so a non-zero default would hand every endpoint
// a receive queue only an application calling read_datagram() ever empties.
[[nodiscard]] inline transport_parameters_t default_transport_parameters()
{
  transport_parameters_t out;
  out.max_idle_timeout = 30000;
  out.initial_max_data = 1024ull * 1024;
  out.initial_max_stream_data_bidi_local = 256ull * 1024;
  out.initial_max_stream_data_bidi_remote = 256ull * 1024;
  out.initial_max_stream_data_uni = 256ull * 1024;
  out.initial_max_streams_bidi = 100;
  out.initial_max_streams_uni = 100;
  out.active_connection_id_limit = 4;
  return out;
}
} // namespace vio::quic

// ...and in vio/quic/connection.h, connection_config_t's member becomes:
//
//   // Sane by default. Every credit field of transport_parameters_t is zero,
//   // because zero is what section 18.2 says an absent parameter means, and a
//   // connection built from those completes its handshake and then cannot open
//   // a stream or accept a byte with nothing raised anywhere to say why. That
//   // is the correct wire semantic and a useless starting point, so the config
//   // layer -- already where vio's opinions live, next to pacing and
//   // congestion_algorithm -- supplies the working values.
//   transport_parameters_t transport_parameters = default_transport_parameters();
```

## Proposed header: vio/operation/quic_stream.h

```cpp
// =============================================================================
// src/vio/operation/quic_stream.h  --  namespace vio
//
// Streams and unreliable datagrams. quic_endpoint.h has the endpoint and the
// connection, and this header includes it because a stream is reached through
// one.
//
// A QUIC stream is two independent halves that share an identifier, and this
// header models them as two independent halves. Finishing the sending half and
// finding out that the receiving half has ended are different operations, and
// neither implies the other -- which is the whole reason connection_t asks
// stream_receive_finished and stream_send_finished separately, and the reason a
// request/response protocol can say "that is the whole request" without giving
// up the answer.
//
// The handle is reference counted and copyable, and it names a stream rather
// than pointing at one: it holds a reference to its connection's state and the
// stream id, and re-looks-up on every call. That is not caution, it is the only
// thing that works. A peer-initiated stream is erased from the transport on the
// very flush after the application reads it to the end, because erasing it is
// how MAX_STREAMS credit is returned to the peer and delaying that to suit a
// handle would stall the peer's ability to open anything. So nothing here
// caches a stream_t*, a receive_stream_t*, or the span readable_stream()
// returns -- that last one points into a std::vector the next arriving datagram
// reallocates, so it could not cross a suspension even if the stream survived.
//
// What the handle does keep is the part the transport throws away when it
// reaps: the terminal reason, the peer's RESET_STREAM code, the peer's
// STOP_SENDING code, and the pending writes. Those are latched the moment this
// layer observes them -- during the beat, and again immediately after every
// read consumes -- so they are always recorded before the flush that reaps.
// Reading a stream the transport has already forgotten therefore still reports
// how it ended, rather than suspending for ever on a lookup that now misses.
// =============================================================================

#pragma once

#include "vio/cancellation.h"
#include "vio/error.h"
#include "vio/operation/quic_endpoint.h"
#include "vio/owned_payload.h"
#include "vio/quic/connection.h"
#include "vio/ref_counted_wrapper.h"
#include "vio/unique_buf.h"

#include <coroutine>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <type_traits>
#include <vector>

namespace vio
{

// -----------------------------------------------------------------------------
// Backpressure marks
// -----------------------------------------------------------------------------
//
// Transport parameters bound only what a peer may send to this endpoint;
// nothing in QUIC bounds what a local application may pile into a stream.
// connection_t::write_stream copies onto a std::vector with no limit and
// returns data.size() whether or not a byte can ever leave, which is why a
// send-side mark had to be invented here rather than borrowed.
//
// The numbers and the shape are socket_stream.h's, so that a QUIC stream and a
// TLS stream apply the same pressure at the same depth and an application that
// has learned one does not have to learn the other. Constants rather than
// configuration for the reason ssl_config_t has no buffer knob: a vio user
// should not have to have an opinion about this.
//
// The mark is measured in bytes handed to the transport and not yet
// acknowledged, per stream, and there is a second mark for the connection as a
// whole -- without it a peer that opens the negotiated hundred streams decides
// how much this process buffers, which is not a decision a peer should get to
// make.
inline constexpr std::size_t quic_stream_write_high_water = 2ull * 1024 * 1024;
inline constexpr std::size_t quic_stream_write_low_water = 512ull * 1024;
inline constexpr std::size_t quic_connection_write_high_water = 8ull * 1024 * 1024;
inline constexpr std::size_t quic_connection_write_low_water = 2ull * 1024 * 1024;

// -----------------------------------------------------------------------------
// Handle
// -----------------------------------------------------------------------------

struct quic_stream_t
{
  ref_ptr_t<detail::quic_stream_state_t> handle;
};

namespace detail
{
struct quic_open_stream_slot_t;
struct quic_accept_stream_slot_t;
} // namespace detail

using quic_accept_stream_future_t = quic_future_t<detail::quic_connection_state_t, detail::quic_accept_stream_slot_t>;

// Opening a stream is a per-call operation rather than a single slot, because
// the case that makes it worth suspending -- the peer's stream limit is reached
// -- is exactly the case where more than one coroutine is waiting.
class quic_open_stream_awaitable_t
{
public:
  quic_open_stream_awaitable_t(quic_open_stream_awaitable_t &&other) noexcept;
  quic_open_stream_awaitable_t &operator=(quic_open_stream_awaitable_t &&other) noexcept;
  quic_open_stream_awaitable_t(const quic_open_stream_awaitable_t &) = delete;
  quic_open_stream_awaitable_t &operator=(const quic_open_stream_awaitable_t &) = delete;
  ~quic_open_stream_awaitable_t();

  [[nodiscard]] bool await_ready() const noexcept;
  bool await_suspend(std::coroutine_handle<> continuation) noexcept;
  std::expected<quic_stream_t, error_t> await_resume() noexcept;

private:
  friend struct detail::quic_connection_state_t;
  struct op_t;
  explicit quic_open_stream_awaitable_t(op_t *op);
  op_t *_op = nullptr;
};

// -----------------------------------------------------------------------------
// Opening and accepting
// -----------------------------------------------------------------------------

// Opens the next stream this endpoint may initiate, suspending while the peer's
// limit is reached rather than returning nothing and leaving the caller to
// invent a retry loop.
//
// Section 4.6 forbids exceeding the limit, so waiting is the only correct
// behaviour, and the transport already knows the exact moment a MAX_STREAMS
// arrives -- connection_t::open_stream returning std::optional was not a
// simpler API, it was the same wait pushed onto every caller with no event to
// wait on. When credit exists, which is the ordinary case, this resolves inside
// its own factory and nothing suspends.
//
// The suspension is real backpressure and worth understanding: a peer returns
// stream credit as its application finishes with the streams this one opened,
// so a client that opens faster than the server retires is throttled by the
// server. When that is not wanted -- a client that would rather fail a request
// than queue it behind a hundred others -- use quic_try_open_stream.
[[nodiscard]] quic_open_stream_awaitable_t quic_open_stream(quic_connection_t &connection, vio::quic::stream_direction_t direction = vio::quic::stream_direction_t::bidirectional,
                                                            cancellation_t *cancel = nullptr);
[[nodiscard]] std::expected<quic_stream_t, error_t> quic_try_open_stream(quic_connection_t &connection, vio::quic::stream_direction_t direction = vio::quic::stream_direction_t::bidirectional);

// Resolves once per stream the peer opens, in the order their first frames
// arrive, and is re-armed by being called again. One accept loop per connection;
// a second is refused with vio_quic_busy.
//
// This replaces readable_streams(), which could not do the job. That is a list
// of streams with unread bytes right now -- a level, not an edge -- so a stream
// that carried a zero-length FIN, or was reset before anything was read, or
// whose bytes have just been consumed, is invisible through it. A stream is
// reported here exactly once, when its first frame arrives, whether or not it
// ever carries a byte, and its direction and initiator are known before any
// data does -- which is what an HTTP/3 implementation needs, because the first
// varint on a unidirectional stream is its type and the reader for it cannot be
// set up until the stream exists.
//
// One caveat worth knowing rather than discovering: the order is first-frame
// arrival, not open order. Section 3.2 opens every lower-numbered stream of the
// same type implicitly, and the transport deliberately materialises state only
// for the id that actually carried a frame -- otherwise one packet naming a
// high index would force an allocation per implied stream. So reordering on the
// wire is visible here, and a protocol that needs type-before-use reads the
// type itself, which it must do anyway.
[[nodiscard]] quic_accept_stream_future_t quic_accept_stream(quic_connection_t &connection, cancellation_t *cancel = nullptr);

[[nodiscard]] std::uint64_t quic_stream_id(const quic_stream_t &stream);
[[nodiscard]] vio::quic::stream_direction_t quic_stream_direction(const quic_stream_t &stream);
[[nodiscard]] bool quic_stream_is_peer_initiated(const quic_stream_t &stream);

// Which halves this stream has. A unidirectional stream this endpoint opened
// has no receiving half and one the peer opened has no sending half, and the
// transport answers a read on the first with an empty span and a write on the
// second with zero -- neither of which is distinguishable from a slow peer.
// Asking is how a protocol that uses unidirectional streams avoids suspending
// for ever on a half that does not exist; the operations themselves also refuse
// with a full-sentence vio_quic_busy rather than pretending to work.
[[nodiscard]] bool quic_stream_can_read(const quic_stream_t &stream);
[[nodiscard]] bool quic_stream_can_write(const quic_stream_t &stream);

// The connection this stream belongs to, so a coroutine handed nothing but a
// stream can still close, name the peer, or read the round trip time. A null
// handle once the connection's state is gone.
[[nodiscard]] quic_connection_t quic_stream_connection(const quic_stream_t &stream);

// -----------------------------------------------------------------------------
// Writing
// -----------------------------------------------------------------------------

// The write awaitable. Any number may be in flight across different streams;
// several on one stream queue behind each other in issue order, because a
// stream is a byte stream and two writers cannot both be first.
//
// It resolves with void rather than a byte count, and that is a deliberate
// narrowing rather than a lost feature. connection_t::write_stream returns
// data.size() whether or not anything can be sent, and returns zero for five
// different failures as well as for the success of a FIN-only write; a count
// that means all of it or nothing is the only status a caller can act on.
//
// Resolving means the transport owns every byte, not that the peer has them.
// That is the same sense in which write_tcp resolving means libuv took the
// bytes. There is no useful "sent" in QUIC -- a sent packet may be lost and sent
// again, several times -- so the only two honest milestones are "the transport
// owns it" and "the peer acknowledged it", and quic_stream_flushed is the
// second and costs a round trip.
//
// Backpressure is the suspension and nothing else. Under the marks the bytes go
// straight through and the awaitable is already resolved, so the ordinary case
// costs no suspension at all. Over them, the awaitable is simply not resumed
// yet, and the beat feeds the write in pieces as acknowledgements and raised
// limits make room -- which is what bounds a write of any size to the marks
// rather than to its own length. That in turn is why the borrowed overload
// takes a span and needs no owning twin for correctness: either the bytes have
// already been copied into the transport's send queue, or the caller is
// suspended in this co_await and its buffer is alive by construction.
//
// Abandoning the awaitable before it resolves is safe. Its destructor nulls the
// continuation and drops one of the two holds on the operation; the transport
// finishes with whatever it has already taken, and the remainder is dropped,
// which is why abandoning a partly-written stream should be followed by
// quic_stream_reset rather than left to look like a completed write.
class quic_stream_write_awaitable_t
{
public:
  quic_stream_write_awaitable_t(quic_stream_write_awaitable_t &&other) noexcept;
  quic_stream_write_awaitable_t &operator=(quic_stream_write_awaitable_t &&other) noexcept;
  quic_stream_write_awaitable_t(const quic_stream_write_awaitable_t &) = delete;
  quic_stream_write_awaitable_t &operator=(const quic_stream_write_awaitable_t &) = delete;
  ~quic_stream_write_awaitable_t();

  [[nodiscard]] bool await_ready() const noexcept;
  bool await_suspend(std::coroutine_handle<> continuation) noexcept;
  std::expected<void, error_t> await_resume() noexcept;

private:
  friend struct detail::quic_stream_state_t;
  struct op_t;
  explicit quic_stream_write_awaitable_t(op_t *op);
  op_t *_op = nullptr;
};

// Borrowed bytes, kept alive by the caller's suspension.
[[nodiscard]] quic_stream_write_awaitable_t quic_stream_write(quic_stream_t &stream, std::span<const std::uint8_t> data, cancellation_t *cancel = nullptr);

// The same, and then the FIN.
//
// There is a separate function rather than a bool argument, and the reason is
// not taste. A defaulted bool sitting in front of the trailing cancellation_t*
// makes quic_stream_write(stream, data, &cancel) compile, bind the pointer to
// the flag through the standard conversion, half-close the stream and silently
// drop the cancellation -- and every other async entry point in vio puts the
// token immediately after the payload, so that is the call a reader will write
// from memory.
//
// Prefer this to a bare quic_stream_finish after the last write: a FIN that
// rides with the bytes it terminates costs no packet, and it removes the window
// in which the peer has the last chunk and does not yet know it was the last.
[[nodiscard]] quic_stream_write_awaitable_t quic_stream_write_final(quic_stream_t &stream, std::span<const std::uint8_t> data, cancellation_t *cancel = nullptr);

// Owning overloads. Only rvalues bind: ownership must be transferred
// explicitly, which also keeps borrowed views from matching. They exist for a
// caller that would rather not keep the source alive itself -- a buffer built in
// a loop, a response body assembled and handed over -- and not for performance:
// send_stream_t::write copies into the connection's own queue either way, so
// there is no zero-copy path here to claim and none is claimed.
template <typename Bytes>
  requires owned_byte_range<std::remove_cvref_t<Bytes>> && (!std::is_lvalue_reference_v<Bytes>) && (!std::is_const_v<std::remove_reference_t<Bytes>>)
[[nodiscard]] quic_stream_write_awaitable_t quic_stream_write(quic_stream_t &stream, Bytes &&data, cancellation_t *cancel = nullptr);

template <typename Bytes>
  requires owned_byte_range<std::remove_cvref_t<Bytes>> && (!std::is_lvalue_reference_v<Bytes>) && (!std::is_const_v<std::remove_reference_t<Bytes>>)
[[nodiscard]] quic_stream_write_awaitable_t quic_stream_write_final(quic_stream_t &stream, Bytes &&data, cancellation_t *cancel = nullptr);

// Ends the sending half with a FIN and nothing behind it: the half-close
// ssl_client_shutdown performs, and for the same reason. The receiving half
// stays open.
[[nodiscard]] quic_stream_write_awaitable_t quic_stream_finish(quic_stream_t &stream, cancellation_t *cancel = nullptr);

// Resolves when everything written on this stream, FIN included, has been
// acknowledged. Not needed to close cleanly -- the transport retransmits a FIN
// as readily as data -- but it is the only statement about delivery a transport
// can honestly make, and it is what a caller uploading a file before deleting
// the local copy has to have. It waits for the pending writes as well as for
// the transport's own queue, so a write parked behind the high-water mark
// cannot make this resolve early.
[[nodiscard]] quic_milestone_t<detail::quic_stream_state_t, std::expected<void, error_t>> quic_stream_flushed(quic_stream_t &stream, cancellation_t *cancel = nullptr);

// Abandons the sending half; the peer is told with RESET_STREAM and everything
// queued or pending is dropped, resolving each outstanding write with
// vio_quic_stream_reset. Not awaitable, because a reset is a statement and not
// a request. The receiving half is untouched.
void quic_stream_reset(quic_stream_t &stream, std::uint64_t error_code);

// Asks the peer to stop sending, and ends this endpoint's receiving half at
// once: a suspended read resolves immediately with vio_quic_stream_stopped
// rather than waiting a round trip for the peer's answering RESET_STREAM, and
// nothing more is consumed, so the window closes. That is honest -- the
// application has said it wants nothing more -- and it is what makes a read
// cancellable in bounded time from a coroutine that does not own the reader,
// which STOP_SENDING alone cannot promise because a peer that ignores it keeps
// sending.
void quic_stream_stop_sending(quic_stream_t &stream, std::uint64_t error_code);

// The peer's own 62-bit code from a RESET_STREAM or a STOP_SENDING it sent.
// error_t carries an int and a string and is shared across all of vio, so a
// QUIC application error code cannot ride in it: the error says what happened
// and these say what the peer called it, which is what an application protocol
// branches on -- H3_REQUEST_CANCELLED means the request may be retried
// elsewhere and every other code does not. Latched on this handle, so they
// survive the stream being reaped.
[[nodiscard]] std::optional<std::uint64_t> quic_stream_peer_reset_error(const quic_stream_t &stream);
[[nodiscard]] std::optional<std::uint64_t> quic_stream_peer_stop_sending_error(const quic_stream_t &stream);

// The accounting the old API could not report at all. bytes_queued minus
// bytes_acknowledged is the depth the marks are measured against;
// bytes_pending is what this layer is still holding back for them.
// blocked_by_stream_credit and blocked_by_connection_credit are the answer to
// "why did my write not leave", and they are different answers with different
// fixes -- one wants a bigger initial_max_stream_data_* from the peer, the
// other a bigger initial_max_data. Both are computed by send_stream_t today and
// evaluated at exactly one internal site inside the packet builder.
struct quic_stream_stats_t
{
  std::uint64_t bytes_written = 0;      // handed to this API
  std::uint64_t bytes_pending = 0;      // held back by the marks, not yet in the transport
  std::uint64_t bytes_queued = 0;       // handed to the transport
  std::uint64_t bytes_sent = 0;         // on the wire at least once
  std::uint64_t bytes_acknowledged = 0; // the peer has them
  std::uint64_t bytes_read = 0;         // delivered to this application
  std::uint64_t peer_window = 0;        // MAX_STREAM_DATA the peer has granted
  bool blocked_by_stream_credit = false;
  bool blocked_by_connection_credit = false;
  bool fin_sent = false;
  bool fin_acknowledged = false;
};
[[nodiscard]] quic_stream_stats_t quic_stream_stats(const quic_stream_t &stream);

// -----------------------------------------------------------------------------
// Reading
// -----------------------------------------------------------------------------

// One reader per stream, move-only, constructible only through
// quic_stream_create_reader -- the tcp_reader_t shape, with cancel() and
// is_cancelled() and a destructor that undoes exactly what the constructor did.
//
// It reads like tcp_reader_t on purpose, down to the rule that endings are
// ordinary entries rather than flags to test on the side: bytes come back as an
// owned unique_buf_t, and after the last of them comes vio_quic_stream_finished
// for a FIN or vio_quic_stream_reset for a peer that gave up, so a loop that
// reads until it gets an error has by definition seen the bytes first and knows
// which of the two happened.
//
// There is no queue behind it, and that is the important difference from
// socket_stream, which needs a ring buffer because TLS over TCP has no receive
// accounting of its own. QUIC does. Bytes stay in the transport's reassembly
// until an await takes them, and taking them is the call that returns
// MAX_STREAM_DATA credit -- so a reader that is not being awaited stops the peer
// through the mechanism the protocol already has, and the memory a connection
// commits to receiving is exactly initial_max_data with nothing added on top.
//
// One consequence to know: a read yields one contiguous run, which is what
// reassembly can hand over without a gap, and not everything that has arrived.
// A loop, not a single call, is how a message is read.
//
// A second: a RESET_STREAM discards bytes that arrived in the same batch as the
// reset and had not yet been taken. That is what RESET_STREAM means and the
// peer chose it, but it is the one place where the ending does not strictly
// follow every byte the peer ever sent.
class quic_stream_reader_t
{
public:
  quic_stream_reader_t(quic_stream_reader_t &&other) noexcept;
  quic_stream_reader_t &operator=(quic_stream_reader_t &&other) noexcept;
  quic_stream_reader_t(const quic_stream_reader_t &) = delete;
  quic_stream_reader_t &operator=(const quic_stream_reader_t &) = delete;
  ~quic_stream_reader_t();

  // The awaiter holds its own reference to the stream state, so a reader
  // destroyed while a read is suspended does not take the state with it. Its
  // await_ready asks the transport directly rather than a queue this layer
  // keeps, which is also what stops a reader created inside the beat -- the
  // usual case, since that is where an accepted stream is handed over -- from
  // suspending past bytes that have already arrived.
  struct awaiter_t
  {
    ref_ptr_t<detail::quic_stream_state_t> state;
    [[nodiscard]] bool await_ready() const noexcept;
    void await_suspend(std::coroutine_handle<> continuation) noexcept;
    std::expected<unique_buf_t, error_t> await_resume() noexcept;
  };
  [[nodiscard]] awaiter_t operator co_await();

  // Copies the next contiguous run into the caller's buffer and consumes
  // exactly that much, so a caller with its own storage does not pay for a
  // second one and nothing is allocated or freed per read. Zero means the peer
  // finished cleanly, the same EOF convention tcp_reader_t::read_into uses; a
  // reset is an error rather than a zero, which is the distinction a byte count
  // alone could never carry.
  //
  // It is not the true scatter read tcp_reader_t::read_into performs, and
  // naming it the same while quietly copying would be worse than saying so:
  // QUIC decrypts in place in the datagram and reassembles out of order into
  // its own storage, so there is no moment at which the kernel could be handed
  // the caller's buffer. What this saves is the allocation, not the copy.
  struct read_into_awaiter_t
  {
    ref_ptr_t<detail::quic_stream_state_t> state;
    std::span<std::uint8_t> destination;
    [[nodiscard]] bool await_ready() const noexcept;
    void await_suspend(std::coroutine_handle<> continuation) noexcept;
    std::expected<std::size_t, error_t> await_resume() noexcept;
  };
  [[nodiscard]] read_into_awaiter_t read_into(std::span<std::uint8_t> destination);

  // Resolves a suspended read with UV_ECANCELED, delivered the way every other
  // ending is rather than as a flag the awaiter has to remember to test.
  // Idempotent, and it mirrors the destructor's teardown so calling both is
  // safe.
  void cancel();
  [[nodiscard]] bool is_cancelled() const;

private:
  friend std::expected<quic_stream_reader_t, error_t> quic_stream_create_reader(quic_stream_t &stream);
  explicit quic_stream_reader_t(const quic_stream_t &stream);
  ref_ptr_t<detail::quic_stream_state_t> handle;
  bool _is_valid = false;
};

// One reader at a time, refused with a message that says what to do about it in
// the style tcp_create_reader uses. Also refused for a stream with no receiving
// half, and for a connection that has ended.
//
// Until a reader exists nothing is taken out of reassembly, so an accepted
// stream that nobody is reading holds its own credit rather than quietly
// buffering on the application's behalf.
[[nodiscard]] std::expected<quic_stream_reader_t, error_t> quic_stream_create_reader(quic_stream_t &stream);

// The read that takes a cancellation token, which co_await on the reader cannot
// -- the trailing cancellation_t* is vio's whole cancellation story and a read
// that a coroutine one frame up needs to abort has to be able to take one.
[[nodiscard]] quic_stream_reader_t::awaiter_t quic_stream_read(quic_stream_reader_t &reader, cancellation_t *cancel);

// -----------------------------------------------------------------------------
// Unreliable datagrams (RFC 9221)
// -----------------------------------------------------------------------------

// The largest payload quic_connection_write_datagram will take, given what the
// peer offered. Zero means the peer accepts none -- either it did not advertise
// the extension, or this endpoint left quic_flow_control_t::max_datagram_frame_size
// at its default and so never asked. The peer's limit counts the whole frame
// including its type and length, so this does that arithmetic once rather than
// leaving every caller to subtract the header.
[[nodiscard]] std::size_t quic_connection_max_datagram_payload(const quic_connection_t &connection);

// Queues one unreliable datagram, which goes out on the next beat. There is no
// awaitable form and there will not be one: an application reaching for RFC
// 9221 has chosen loss over delay, and a datagram held until there is room is
// exactly the delay it was avoiding. Refused rather than truncated when it does
// not fit, because a datagram is sent whole or not at all, and a lost one is
// never retransmitted -- that rule is what makes this the extension it is.
[[nodiscard]] std::expected<void, error_t> quic_connection_write_datagram(quic_connection_t &connection, std::span<const std::uint8_t> payload);

// Datagrams are the one thing QUIC's flow control does not bound, so the
// receive queue is bounded here instead -- a fixed limit with a tail drop and a
// counter, which is the shape udp_set_recv_queue_limit and udp_recv_stats
// already established. Drops are silent by design, since neither a drop nor a
// slow consumer should tear a connection down, which makes dropped() the only
// way to notice them.
class quic_datagram_reader_t
{
public:
  quic_datagram_reader_t(quic_datagram_reader_t &&other) noexcept;
  quic_datagram_reader_t &operator=(quic_datagram_reader_t &&other) noexcept;
  quic_datagram_reader_t(const quic_datagram_reader_t &) = delete;
  quic_datagram_reader_t &operator=(const quic_datagram_reader_t &) = delete;
  ~quic_datagram_reader_t();

  struct awaiter_t
  {
    ref_ptr_t<detail::quic_connection_state_t> state;
    [[nodiscard]] bool await_ready() const noexcept;
    void await_suspend(std::coroutine_handle<> continuation) noexcept;
    std::expected<std::vector<std::uint8_t>, error_t> await_resume() noexcept;
  };
  [[nodiscard]] awaiter_t operator co_await();

  void cancel();
  [[nodiscard]] bool is_cancelled() const;
  [[nodiscard]] std::uint64_t dropped() const;

private:
  friend std::expected<quic_datagram_reader_t, error_t> quic_connection_create_datagram_reader(quic_connection_t &connection, std::size_t queue_limit);
  explicit quic_datagram_reader_t(const quic_connection_t &connection);
  ref_ptr_t<detail::quic_connection_state_t> handle;
  bool _is_valid = false;
};

[[nodiscard]] std::expected<quic_datagram_reader_t, error_t> quic_connection_create_datagram_reader(quic_connection_t &connection, std::size_t queue_limit = 1024);

// -----------------------------------------------------------------------------
// A convenience that removes a cast from every QUIC program
// -----------------------------------------------------------------------------

// unique_buf_t::buf.base is a char* because libuv's uv_buf_t is, and everything
// in vio::quic speaks in std::uint8_t. Every QUIC example in this repository
// writes the same reinterpret_cast; one function here deletes it from all of
// them.
[[nodiscard]] inline std::span<const std::uint8_t> quic_bytes(const unique_buf_t &buffer)
{
  return {reinterpret_cast<const std::uint8_t *>(buffer.buf.base), buffer.buf.len};
}

} // namespace vio
```

## Internal changes required

### [small] Add `[[nodiscard]] inline transport_parameters_t default_transport_parameters()` after the struct, returning the values in transport_parameter_defaults. Do NOT touch a single default member initialiser on `transport_parameters_t` itself (:105-133), and leave `max_datagram_frame_size` and `grease_quic_bit` at their current values.

**src/vio/quic/transport_parameters.h**

`decode_transport_parameters` (:252) default-constructs one as the RFC 9000 section 18.2 absent-parameter accumulator, `parse_resumption_ticket` (src/quic_connection.cpp:2972) does the same, and `encode_transport_parameters` (:172-239) skips a field by comparing it to a separate hardcoded RFC constant. Raising an initialiser makes a silent peer decode as having granted credit, and this endpoint then overruns its real limit. The two guard-rail tests at test/test_quic_transport_parameters.cpp:50-69 keep passing untouched, which is the check that the layering is right.

### [small] `transport_parameters_t transport_parameters = default_transport_parameters();`

**src/vio/quic/connection.h**

One line, and it fixes both roles and every existing consumer: `accept_connection` (src/quic_endpoint.cpp:531) and `endpoint_t::connect` (:763) each copy `endpoint_config_t::connection` wholesale. It is also the whole of the user's stated principle -- after this, nobody has to specify anything.

### [small] Stop discarding the peer's RESET_STREAM code. Add `std::optional<std::uint64_t> peer_reset_error` to `stream_t` beside the existing `stop_sending_error` (:109), and replace `(void)error_code;` at :391 with an assignment to it.

**src/vio/quic/streams.h**

This is the only place the value exists. Without it a read can report a reset only as EOF, which is wrong, and `stream_receive_finished()` already cannot distinguish the two.

### [medium] Record the edges the coroutine layer wakes on. Add to `streams_t`: `std::vector<std::uint64_t> _opened` pushed at BOTH `_streams[id]` inserts -- `open()` at :353 and `ensure_remote` at :625; `std::vector<std::uint64_t> _data_arrived` pushed from `receive_stream_frame` when bytes were consumed or a FIN settled and from `receive_reset_stream`; `std::vector<std::uint64_t> _send_unblocked` pushed when `set_max_data` (:445) and `receive_stop_sending` (:428) actually change something; `bool _stream_credit_opened` set when `set_peer_max_streams` really raises a limit. Each with a `take_*()` drain, and a stale-entry-is-cheap `bool` hint on `stream_t` in the style of the existing `in_sendable`.

**src/vio/quic/streams.h**

There is no accept edge today at all -- `readable_streams()` is a level, and a peer stream that carried a zero-length FIN, or was reset before any read, or whose bytes have been consumed, never appears in it. `set_max_data` and `set_peer_max_data` are `std::max` clamps, so a duplicate MAX_DATA must not wake a parked writer, which is why these record a real rise rather than an arrival. STOP_SENDING needs its own edge because after `send.reset()` nothing on that stream is ever acknowledged again and a parked writer would otherwise hang for ever.

### [small] Push the stream id onto `_send_unblocked` from the acknowledgement path where a send half advances (around :1465-1480).

**src/quic_connection.cpp**

The send high-water mark is measured against `acknowledged_prefix()`, and an acknowledgement is the commonest thing that frees room. Without this a parked writer on a healthy connection waits for a MAX_DATA that may never come.

### [small] Set a `connection_close_t` on the handshake-timeout path (:3316-3322) and the idle-timeout path (:3323-3331). Both currently set `impl.state = closed; impl.close_frame_pending = false;` and no reason.

**src/quic_connection.cpp**

`close_reason()` returns nullopt for the two commonest natural endings, so a close notification designed around it would be empty exactly when it matters. The idle timeout gets NO_ERROR with `from_peer = false`; the handshake timeout gets an internal code naming the deadline.

### [medium] Add a forwarding accessor block on `connection_t`: `take_opened_streams()`, `take_data_arrived()`, `take_send_unblocked()`, `take_stream_credit_opened()`, `stream_peer_reset_error(id)`, `stream_peer_stop_sending_error(id)`, `stream_receive_reset(id)` (distinguishes reset from FIN, which `stream_receive_finished` cannot), `stream_exists(id)`, `stream_has_receive(id)`/`stream_has_send(id)`, and one `stream_send_stats_t stream_send_stats(id)` returning queued/sent/acknowledged_prefix/max_data/fin_queued/blocked_by_stream_limit/blocked_by_connection_limit in a single call rather than seven.

**src/vio/quic/connection.h and src/quic_connection.cpp**

`connection_impl_t::streams` is private (src/quic_connection.cpp:294) and `connection_t::_impl` has no friends, so none of this is reachable from outside today. `queued() - acknowledged_prefix()` is the outstanding depth the marks are measured against and it has never been reportable; the two blocked predicates are the answer to 'why did my write not leave' and are evaluated at exactly one internal site inside the packet builder.

### [small] Add path observability forwards for `quic_connection_stats_t`: `smoothed_rtt()`, `rtt_variation()`, `min_rtt()` from `loss_recovery_t::rtt()`, `bytes_in_flight()`, `congestion_window()` and `in_slow_start()` from `congestion_control_t`.

**src/vio/quic/connection.h and src/quic_connection.cpp**

All cheap forwards to members that already exist; none is reachable from outside, so a coroutine API cannot report a round trip time or a window at all.

### [small] Bracket `run()`'s `on_activity` dispatch loop and the flush loop that follows it (:1006-1021) with `++impl.walking` / `--impl.walking`.

**src/quic_endpoint.cpp**

`flush()` (:806-812) and the ticker (:865-873) are already bracketed and these two are not, with `reap(impl, now)` immediately after at :1022. Both walk a `std::vector<connection_entry_t *> touched` of raw pointers into unique_ptr-owned entries, so an application handler that calls `flush()` re-enters with `walking == 0`, really erases at :711, and dangles every later pointer. No in-tree handler triggers it today; the new layer installs handlers on both.

### [small] Add `std::expected<void, error_t> flush(connection_t &)` beside the existing all-connections `flush()`.

**src/vio/quic/endpoint.h and src/quic_endpoint.cpp**

The beat runs on a uv_prepare_t, which fires every loop iteration. Flushing every connection there is O(connections) per turn, and each `flush_entry` calls `index_connection`, which calls `issued_connection_ids()` -- a vector returned by value, so a heap allocation per connection per turn. The beat must flush only the connections that ran.

### [medium] Add `void on_connection_gone(std::function<void(connection_t &)>)`, fired from the draining latch in `flush_entry` (:679-686) and from `endpoint_impl_t`'s destructor for anything that never drained. Add `connection_t *` identity keying support by making the hook and the existing `on_connection`/`on_activity` sufficient -- no signature change to either.

**src/vio/quic/endpoint.h and src/quic_endpoint.cpp**

There is no ending notification of any kind today, and it must fire at the DRAINING latch rather than at `reap` -- `reap` runs `draining_period` (3 s) later, so hooking it there would report every peer-side ending three seconds late. Firing at the latch keeps the `connection_t` alive and its `close_reason()`/`reset_by_peer()`/`version_negotiation_failed()` readable. Keying the API's registry on `connection_t*` (stable for the connection's life, since it is a `unique_ptr` in the entry) avoids changing the two existing callback signatures, which the six examples and both interop programs use.

### [medium] Replace the 2 ms `detached_task_t` ticker (:855-877) with a `timer_t` owned by `endpoint_impl_t`, armed to the minimum of `connection_t::next_timeout(now)` across connections and rearmed after every flush.

**src/quic_endpoint.cpp**

`next_timeout` (src/quic_connection.cpp:3551-3587) already covers ack, loss detection, MTU probe, idle, handshake, path and pacer, so the information is computed and public. `timer_t` exists for exactly this (its header names QUIC loss detection as the motivating case), rearms correctly for a deadline already in the past, is registered with the ref count so teardown does one `uv_close`, and holds a reference for the duration of its fire callback. A `detached_task_t` has `suspend_never` as its final suspend and cannot be joined, which is half of why teardown is currently a use-after-free -- and it wakes an idle endpoint 500 times a second.

### [medium] Move the `datagram_reader_t` out of `run()`'s coroutine frame into `endpoint_impl_t`, and remove the `ensure_socket(impl)` call at :830 so `run()` fails if no descriptor exists instead of creating an AF_INET socket.

**src/quic_endpoint.cpp**

`datagram_reader_t::create` requires a descriptor (src/vio/operation/udp_datagram.h:453-459) and libuv creates the UDP socket lazily, so `ensure_socket` with the default AF_INET is what pins an unbound endpoint to IPv4. Both `bind` and `connect` carry the family. Owning the reader in the state is what lets teardown cancel it deterministically -- `cancellation_t::cancel()` runs callbacks inline (src/vio/cancellation.h:122-132), so cancel-then-destroy is well ordered.

### [small] Reap fully-finished locally initiated streams too. `reap_finished` (:534-538) skips any stream whose initiator is not remote, so `_streams` grows a map node per local stream for the life of the connection. Keep the MAX_STREAMS credit accounting remote-only; only the erase changes.

**src/vio/quic/streams.h**

Unbounded growth on a long-lived connection that opens and finishes many streams. Local ids are never reused, so there is no reincarnation hazard on that side, and the coroutine layer's registry is the first thing that can say the application has released a stream. Worth doing while the stream layer is open.

### [large] New files: `src/vio/operation/quic_endpoint.h`, `src/vio/operation/quic_stream.h`, `src/quic_coroutine.cpp`. The three state structs are declared complete in `vio::detail` (ref_ptr_t needs a complete type) and hold only ids, continuations, expected results, registrations, latched terminals and a `connection_t*`; no internal type from streams.h or connection_impl_t appears in either header. The `uv_prepare_t` beat, the per-connection registry, the accept queues and the write FIFOs live here.

**src/vio/operation/quic_endpoint.h, src/vio/operation/quic_stream.h, src/quic_coroutine.cpp**

This is the API itself. It is the single largest item: roughly 1800-2400 lines of implementation, of which the beat, the three awaitable shapes and the stream registry are the substance and the rest is accessor forwarding. Note it must be compiled into the library with VIO_EXPORT on the classes, not header-only: tcp.h and udp.h are entirely inline, but the QUIC classes are already exported because header-only would pull the whole stack into every translation unit.

### [medium] Delete the hand-rolled parameter block from all six examples and both interop programs plus profile_quic and bench_quic (twelve sites, no two identical), delete the paragraph in `examples/quic_common.h` that documents the zero-credit trap, and port the examples to the new API. Keep exactly two deliberate deviations as teaching cases: `quic_datagram.cpp`'s `max_datagram_frame_size` and `quic_close.cpp`'s one-second idle timeout. Add a `done()` accessor to `task_t<T>` so a long-lived accept loop can prune finished children.

**examples/*.cpp, examples/quic_common.h, test/interop_endpoint.cpp, test/interop_server.cpp, test/profile_quic.cpp, test/bench_quic.cpp, src/vio/task.h**

That the blocks can be deleted is the visible proof the defaults landed. The two test files that leave the unidirectional fields at zero (test_quic_endpoint.cpp:87-96, test_quic_connection.cpp:100-106) should keep an explicit block only where a test genuinely needs a non-default value. `task_t::done()` is one line and is needed because the server example otherwise accumulates a frame per stream for the life of the connection.

## Migration

`endpoint_t`, `connection_t`, `connection_handle_t`, `on_connection`, `on_activity`, `run()` and `flush()` all stay exactly as they are, and the coroutine layer is built on top of them rather than replacing them. That is not diplomacy: the sans-I/O transport driven by callbacks and integer ids is the right shape for the inside of a transport, it is what makes a whole handshake testable with no socket under it, and `test_quic_connection.cpp`, `test_quic_endpoint.cpp`, `bench_quic.cpp` and `profile_quic.cpp` are all written directly against it. Nothing in this proposal breaks a single one of them.

The transport gains four public things and loses none: `endpoint_t::flush(connection_t &)`, `endpoint_t::on_connection_gone`, the stream and path accessor block on `connection_t`, and `default_transport_parameters()`. Every existing signature is untouched, which is deliberate -- changing `connection_ready_t` to carry a `connection_handle_t` would have broken all six examples and both interop programs for a convenience the API layer can get by keying on `connection_t*` instead.

WHAT ACTUALLY CHANGES FOR EXISTING CODE, in one line: `connection_config_t::transport_parameters` now defaults to something that works. Any caller that already sets it is unaffected; any caller that did not was already broken.

THE SIX EXAMPLES all move to the new API, and the diff is the argument for the change. Each currently opens with a `parameters()` function and a comment saying there is no such thing as a sensible default here; all of that goes, along with `quic_common.h`'s paragraph explaining the trap. Each then loses its `endpoint.run()` spawn, its `for (...) co_await sleep(loop, 5ms)` handshake wait, its `readable_streams()` sweep, its `flush()` calls, and its cancel-sleep-reset-sleep teardown. `quic_echo.cpp` and `quic_file_server.cpp` become roughly the two programs in this proposal. `quic_bulk_transfer.cpp` keeps one deliberate deviation -- 8 MiB windows, because it is about throughput on a long path and 1 MiB is the wrong number there -- and gains a real backpressure loop instead of its current write-and-hope. `quic_datagram.cpp` keeps `max_datagram_frame_size` and `quic_close.cpp` keeps its one-second idle timeout, each now the single line the example is about rather than one line in a wall of mandatory boilerplate. `quic_zero_rtt.cpp` moves to `quic_endpoint_connect_early` and gets shorter by the whole of its polling.

`interop_endpoint.cpp` and `interop_server.cpp` stay on the low-level API for the moment. They are the only external check on the whole stack -- picoquic in both directions, including 0-RTT through a Retry -- and moving them and the API in one step would leave no way to tell which of the two broke an interop case. They move after the coroutine layer has passed the in-process tests, as a separate change, and that move is worth making because it is also the first real proof the new API can carry a protocol somebody else wrote.

`bench_quic.cpp` and `profile_quic.cpp` stay on the low-level API permanently. `bench_quic` replaces global `operator new` to count allocations and exists to measure per-packet protocol cost with no kernel in the way; putting an event loop and a coroutine layer under it would measure something else. They keep their `generous()` blocks, which are deliberately unrealistic.

ONE COST TO NAME. There will be two ways to drive a QUIC endpoint, and someone will mix them -- installing `on_activity` on an endpoint the coroutine layer also owns, or calling `endpoint_t::flush()` from inside a coroutine the beat resumed. The second is now safe (the `walking` bracket is fixed), the first silently replaces the API layer's own handler and breaks it. The honest mitigation is `quic_endpoint_native()` returning the transport endpoint with a doc comment saying which handlers are spoken for, and a note in CLAUDE.md. Deprecating the callback surface is a decision for after the coroutine layer has proved itself against picoquic, and it is one of the open questions below rather than something to decide now.

## Open questions

- grease_quic_bit: on or off by default? I have set it OFF, on the grounds that turning it on changes what vio's traffic looks like to anything filtering on the QUIC bit, and that is an operational decision rather than a flow-control one. The argument the other way is real and I do not think it is mine to make: RFC 9287 is worth almost nothing unless it is widely on by default, both directions are implemented and interop-tested here, the receive side costs nothing, and two conditions must hold before anything on the wire changes because vio only clears the bit when the peer also offered. It is one line either way.
- initial_max_data: 1 MiB or 8 MiB? 1 MiB caps a single connection at roughly 84 Mbit/s on a 100 ms path and there is no receive-window auto-tuning here to grow past it, so it is right for LAN, datacentre and request/response and wrong for transatlantic bulk. 8 MiB fixes bulk and takes the per-1000-connection receive commitment from about 1 GiB to about 8 GiB. Every stack that ships a small starting window has auto-tuning; vio does not, which is what makes this a real choice rather than a starting point. What is vio's QUIC for first?
- Does the callback surface stay public alongside the coroutine API, or become internal once the coroutine layer has proved itself? Keeping both means two ways to drive an endpoint and a real hazard where someone installs on_activity on an endpoint the coroutine layer already owns. Making the transport internal means test_quic_endpoint.cpp, bench_quic.cpp, profile_quic.cpp and both interop programs need a friend seam or a documented internal header -- and bench_quic in particular should NOT go through an event loop, since it exists to measure protocol cost with no kernel in the way.
- One role per endpoint, or an endpoint that both dials and answers? I have taken the role from tls_context_t, which deletes the wart where it is stated twice and checked nowhere -- but endpoint_impl_t holds a single `const tls_context_t &`, so a peer-to-peer endpoint (or a proxy reusing a port in both directions) is impossible today and stays impossible under this design. Supporting it means two contexts on the endpoint and a role decision per connection, which is a small change made now and a larger one made later.

## Build order

1. Defaults, standalone. Add `default_transport_parameters()` to transport_parameters.h and change `connection_config_t::transport_parameters` to use it. Nothing else. Test: the two existing guard-rail tests in test_quic_transport_parameters.cpp still pass unchanged (they construct a bare `transport_parameters_t`, so they must), plus a new test that a default-constructed `connection_config_t` yields non-zero credit in every field and still encodes `max_datagram_frame_size` as absent. Then delete the `parameters()` function from the six examples and confirm each still runs. This lands alone, is the smallest change with the largest visible effect, and carries no risk to anything else.
2. Transport edges and accessors, sans-I/O. The reset code at streams.h:391; the `_opened`/`_data_arrived`/`_send_unblocked`/`_stream_credit_opened` lists with their `take_*` drains, stamped at BOTH `_streams[id]` inserts; the STOP_SENDING wake edge; the two missing `close_reason` assignments at quic_connection.cpp:3316-3331; the forwarding accessor block on `connection_t`; the path stats forwards; and reaping finished local streams. All of it testable with no socket, in test_quic_streams.cpp and test_quic_connection.cpp: a reset delivers its code, an opened list names a stream that carried only a zero-length FIN, a duplicate MAX_DATA does not appear in `_send_unblocked`, an idle timeout reports a reason, and a connection that opens and finishes a thousand local streams ends with an empty stream map. The tree works and the existing API is strictly better for it.
3. Endpoint hardening, still callback-driven. The `walking` bracket around run()'s two loops; `flush(connection_t&)`; `on_connection_gone` fired at the draining latch; the `timer_t` replacing the 2 ms ticker; the `datagram_reader_t` moved into `endpoint_impl_t`; `run()` no longer calling `ensure_socket`. Test with the existing test_quic_endpoint.cpp plus three new cases: an on_activity handler that calls flush() does not corrupt the walk, an idle endpoint wakes only at its next deadline rather than 500 times a second, and an endpoint that binds to `::` before running reaches an IPv6 peer. Run the interop cases against picoquic here -- this is the last point at which an interop regression can only have come from the transport.
4. The API skeleton: handles, the beat, teardown. The two headers, the three state structs, the `uv_prepare_t` registered through `register_handle`, the callback-duration ref, the registry keyed on `connection_t*`, and `quic_endpoint_create`/`bind`/`connect`/`accept`/`shutdown` plus `quic_connection_ready`/`closed`/`close_reason`/`alpn`/`stats`. No streams at all. Test: a client and a server in one process complete a handshake, exchange nothing, close, and the loop returns; a dial to a wrong certificate fails with `vio_quic_handshake_failed`; an endpoint released mid-dial resolves the dial with `vio_quic_endpoint_closed` and `uv_loop_close` succeeds; two coroutines await `quic_connection_closed` on one connection and both are resumed. That last one is the multi-waiter shape and it should be written before anything depends on it.
5. Streams: open, accept, read, terminals. `quic_open_stream`/`quic_try_open_stream`/`quic_accept_stream`, the stream handle and registry, `quic_stream_create_reader` with `co_await` and `read_into`, the latched terminals and peer codes, `quic_stream_finish`/`reset`/`stop_sending`, and the release policy in the stream state's `on_destroy`. Writes are still synchronous-and-unbounded at this step: `quic_stream_write` submits everything and resolves. Test: the echo pair from this proposal; a clean FIN and a RESET_STREAM produce different codes and the reset carries the peer's number; a stream read to EOF and then reaped still reports its ending; a peer that reopens a reaped id gets a fresh handle and the old one reports `vio_quic_stream_stale`; a dropped handle with an open send half makes the peer see a RESET_STREAM on an otherwise idle connection.
6. Writes and backpressure. The per-call write op with the two-hold protocol, the four marks, feeding in pieces from the beat, the four wake edges including STOP_SENDING, `quic_stream_flushed` gated on both the transport counters and the op FIFO, and `quic_stream_stats`. Test: a 64 MiB write on a stream with a 256 KiB mark never has more than the mark outstanding at any observed point; a peer that stops reading suspends the writer rather than growing the process; STOP_SENDING resolves a parked write instead of hanging it; `quic_stream_flushed` does not resolve while bytes are still parked. Each of these should be confirmed to fail with its mechanism reverted, which is the only thing that makes a regression test worth having.
7. Datagrams and the resumption path. `quic_connection_write_datagram`, `quic_connection_max_datagram_payload`, `quic_datagram_reader_t` with its bounded tail-drop queue and counter, `quic_endpoint_connect_early`, and the ticket and token accessors. Test: `quic_datagram.cpp` ported; a datagram larger than the peer offered is refused rather than truncated; a reader at its limit drops and counts; a vio-to-vio 0-RTT resumption is accepted and a rejected one is repaired without the application noticing.
8. Migrate the examples and the interop programs. All six examples on the new API; `interop_endpoint.cpp` and `interop_server.cpp` moved last and run against picoquic in both directions, including `TESTCASE=zerortt` and the v2 case (`picoquicdemo -v 6b3343cf`). `bench_quic` and `profile_quic` stay on the low-level API deliberately. Anything the interop run turns up at this point is the coroutine layer's, because step 3 already cleared the transport.


---

# Settled: transport parameter revision (8 MiB)

YES — the per-stream windows must rise, by the same factor of eight, to 2 MiB each. This is not a judgement call; leaving them at 256 KiB makes the 8 MiB decision inert for the exact case it was taken for.

THE ARITHMETIC. A single stream's throughput is bounded by min(connection window, stream window) / round trip, because both windows are checked and the smaller binds. At 256 KiB over a 100 ms path that is 256 KiB / 0.1 s = 2.62 MB/s ≈ 21 Mbit/s. The connection window would only become the binding constraint at 32 simultaneous streams — and a bulk transfer is one stream, which is precisely why `examples/quic_bulk_transfer.cpp` exists and why 8 MiB was chosen. Raising the connection window to 8 MiB and leaving the stream window at 256 KiB moves nothing: the same 21 Mbit/s, with a connection window 32x too large to ever be reached.

THE RATIO IS UNCHANGED AT 4:1, AND ITS ORIGINAL JUSTIFICATION SURVIVES VERBATIM. 8 MiB / 4 = 2 MiB. The reason the doc gave for 1 MiB : 256 KiB is still the right reason: four streams can each be individually full before the connection limit binds, so one slow reader cannot starve the rest, and `initial_max_data` stays the single number that bounds memory. Do not invent a new ratio to go with the new magnitude — the ratio was never about the magnitude.

  initial_max_data                       = 8 MiB   (8ull * 1024 * 1024)
  initial_max_stream_data_bidi_local     = 2 MiB
  initial_max_stream_data_bidi_remote    = 2 MiB
  initial_max_stream_data_uni            = 2 MiB
  quic_connection_write_high_water       = 8 MiB   (was 1 MiB)
  quic_stream_write_high_water           = 2 MiB   (was 256 KiB)

Note the tree is already there on the receive side: `default_transport_parameters()` (transport_parameters.h:157-176, an uncommitted working-tree change) already returns exactly 8 MiB and 2 MiB x 3, with a comment that already makes the "a lone stream against a 256 KiB window is about 21 Mbit/s on that same 100 ms path" argument. So this confirms the tree rather than changing it, and what actually needs editing is `quic_flow_control_t` in QUIC_COROUTINE_API.md (:698-780 and :371-402), which still says 1 MiB / 256 KiB, and the client example's comment at ~:51 ("The defaults grant a megabyte per connection, 256 KiB per stream").

OVERCOMMITMENT: RAISING THE PER-STREAM WINDOWS COSTS NOTHING, AND THIS IS THE WHOLE JUSTIFICATION. The per-stream windows are NOT additive with the connection window. At 100 concurrent streams they sum to 200 MiB against an 8 MiB connection window — a 25x overcommitment — and that is correct rather than a leak, because the connection window is checked independently on every arriving byte and binds first. Receive memory is bounded by `initial_max_data` ALONE, because this layer keeps no second copy: bytes sit in `receive_stream_t` reassembly until a reader takes them, and taking them is the call that returns the credit. So raising a per-stream window raises the ceiling on ONE stream's share of a total that has not moved; it does not raise the total by one byte. That is what makes the ratio a free parameter and why the 4:1 can be chosen for fairness rather than for memory.

  ONE CAVEAT WORTH NAMING RATHER THAN DISCOVERING. Reassembly holds FRAGMENTS, and the August 2026 hardening capped fragment counts as well as bytes precisely because flow control bounds the highest offset reached and never the number of runs held to get there. So the fragment cap, not `initial_max_data`, is what bounds the reassembly node count. Raising a per-stream window raises one stream's byte ceiling and does not touch its fragment ceiling, which is the right division and needs no change here.

THE SEND SIDE MUST RISE TOO, AND NEITHER PROPOSAL SAID SO. The send high-water marks are backpressure marks, not wire limits — they bound how much a writer may have outstanding before it parks — but the arithmetic is identical: to keep a 100 ms path full at the 670 Mbit/s the 8 MiB receive window now permits, roughly 8 MiB has to be in flight. A 1 MiB connection mark caps the SENDER at ~84 Mbit/s just as surely as a 1 MiB receive window capped the receiver, and a 256 KiB per-stream mark caps one stream at 21 Mbit/s. Raising only the receive side moves the bottleneck rather than removing it, and the benchmark's bulk shape would then be measuring the send mark. So 8 MiB / 2 MiB there as well.

  BUT THE SEND SIDE IS NOT OVERCOMMITTED. A writer parked at its mark is holding those bytes in `send_stream_t::_data`, which is a real `std::vector` with no limit of its own — that is why the marks had to be invented in this layer at all. So unlike the receive window, the per-stream send marks DO add up until the connection mark stops them, and the connection mark is the real number. Its saving grace is that it is the local application that drives it, not an adversarial peer, so a larger number carries less risk than the same number on the receive side.

REVISED MEMORY COST, per connection, at the defaults:
  - Receive: 8 MiB, the whole receive commitment, because this layer adds no queue of its own.
  - Send:    8 MiB across the connection, with 2 MiB per stream inside it.
  - Per-stream objects: ~300-400 bytes empty per open stream, so 200 open streams is about 70 KB. Unopened indices cost nothing.
  - Handshake transients: CRYPTO reassembly capped at 64 KiB per level, three levels, released at handshake completion — about 190 KiB, and gone before the steady state starts.
  Steady-state ceiling ≈ 16.1 MiB per connection, against the 2.1 MiB the doc costed at 1 MiB.
  Per 1000 concurrent connections ≈ 16 GiB, against 2.1 GiB, plus about 190 MiB of handshake churn while they are all handshaking.

THAT NUMBER IS LARGE ENOUGH THAT IT HAS TO BE STATED, NOT BURIED. Size for the ceiling, because that is where an adversarial peer drives the receive half; typical residency is far below it, since the receive half is only full when the application has stopped reading and the send half only when the peer has. But 16 GiB per thousand connections is the first vio default whose right value depends on the deployment: a bulk transfer over a fat long path wants exactly this, and a server expecting thousands of concurrent connections should lower `initial_max_data` — which is now a one-line partial override on `quic_flow_control_t` precisely because that type has no second job. The doc's honest paragraph about the wrong default inverts rather than disappearing: it used to say "1 MiB is wrong for transatlantic bulk"; it now says "8 MiB is right for bulk and expensive at ten thousand connections, and receive-window auto-tuning is the proper fix and a separate piece of work". Every stack that ships a small starting window has auto-tuning; vio does not, which is what makes this a real choice rather than a starting point.

ONE CONSEQUENCE FOR THE BENCHMARK, already folded into that design: the callback configuration moves off `generous()` (4 GiB) and onto these numbers, so that both socket configurations exercise the flow-control machinery instead of measuring it out of existence. `generous()` stays for the sans-I/O configuration alone, so the numbers CLAUDE.md already records stay comparable.

---

# Settled: peer-to-peer endpoints

SETTLED SHAPE: an endpoint is a UDP socket and holds up to two `tls_context_t`, chosen by a second `create` OVERLOAD (server first, client second) — not by design 1's `quic_tls_t` wrapper struct.

WHY THE OVERLOAD AND NOT THE STRUCT. Design 1's argument for `quic_tls_t` is that two adjacent `const tls_context_t &` can be swapped and that a type which cannot be got wrong beats a runtime message. That argument fails on inspection. (a) The swap IS caught, at create, deterministically, in every build, by comparing each context's `role()` — `tls_context_t::role()` already exists (tls.h:204) and is exactly the discriminator the struct would have used. Create is the earliest moment anything can be checked at all, since the contexts are runtime objects. (b) The struct's own guarantees do not hold: `quic_tls_t` declares `constexpr quic_tls_t() = default;`, which since C++20 is user-declared, so it is NOT an aggregate and `quic_tls_t{.client = &a}` is already ill-formed — the public fields buy nothing while leaving `duplicate_role` bypassable by field assignment. (c) Its deleted-rvalue guard covers only the one-argument constructor; the two-argument one binds an xvalue to either parameter with no deletion, so `quic_endpoint_create(loop, {*dial_ctx, *tls_context_t::create(cfg)}, config)` compiles and dangles — the exact hazard it claims to have made a compile error, in the form it calls the general case. Three deletions were missing. A wrapper type that needs five subtle rules to be right loses to three lines of validation in `create`.

WHAT IT COSTS THE 95% CASE: nothing. `endpoint_t::create(loop, context, config)` and `quic_endpoint_create(loop, *context, config)` keep their exact shapes. All 30 in-tree `endpoint_t::create` call sites (12 examples, 2 bench_quic, 2 interop_endpoint, 1 interop_server, 13 test_quic_endpoint — enumerated, not estimated; design 2's "twenty, verified individually" was wrong by ten and named `profile_quic.cpp`, which does not call it at all) compile and behave identically.

THE ROLE STOPS BEING AN ENDPOINT FACT. Today the endpoint's role is read at exactly one line — `quic_endpoint.cpp:515`, `impl.config.connection.role != tls_role_t::server` — and the context is consumed at exactly two, :547 and :776. That gate becomes `impl.server_context == nullptr`, and `config.role` is WRITTEN per connection at both birth sites (`connect` already does it at :766; `accept_connection` gains the mirror). This deletes a real latent bug: a client endpoint that left `connection.role` at its default `server` passes today's gate, then hands a server-role config to `connection_t::create` on a `TLS_client_method` context — and a client's socket is unconnected, so one spoofed 1200-byte Initial reaches that path. No in-tree caller triggers it because all 30 set the field; the bug exists because the fact is stated twice.

THE MATCHED PAIR IS KEPT, AND FOR ONE REASON. `quic::make_tls_context_pair(tls_config_t)` returns `{server, client}` from one description. Its justification is not convenience, it is the ALPN ORDER hazard, which I verified end to end: `encode_alpn` runs identically in both branches (quic_tls.cpp:706 server, :738 client), and `on_alpn_select` (:477-512) walks the SERVER's own list and takes the first entry the client also offered. So two peers holding the same protocols in DIFFERENT ORDERS complete both handshakes and agree on DIFFERENT protocols depending on which of them dialled. That is silent, it is peer-to-peer-only (it cannot happen when one side only ever dials), and no create-time intersection check catches it. One shared list makes it unrepresentable. The loud case — no overlap at all — is caught separately by an `alpn_wire()` comparison in the two-context `create`, which is worth having as belt-and-braces but is not the mechanism.

FIVE FATAL BREAKS FIXED, ONE CLAIM RETRACTED.

F1 — `on_connection` FIRES FOR DIALLED CONNECTIONS AND THE ACCEPT QUEUE IS BUILT ON IT. `flush_entry` (quic_endpoint.cpp:673-677) fires `on_connection` for every entry whose handshake completes, with no role test, and endpoint.h:173-176 documents that deliberately. The coroutine layer's accept path is that hook (QUIC_COROUTINE_API.md:427), so on a dual-role endpoint every connection it DIALS lands in the accept queue and design 1's own `answer_loop` would call `quic_accept_stream` on the connection `converse` just dialled. FIX: add `[[nodiscard]] tls_role_t connection_t::role() const` returning `_impl->config.role` and branch in the coroutine layer's handler — server-role to the accept queue, client-role to the matching dial op. This is not "stating it twice": there is one storage location (`connection_impl_t::config.role`) and this is its accessor. It pays for itself four times over — F2, F7, the coroutine filter, and the application question "did I dial this?", which also decides whether `quic_connection_resumption_ticket()` can ever be non-empty. Expose it as `quic_connection_role()`, latched into the handle state so it answers on a tombstone. `connection_ready_t`'s signature does NOT change, so the six examples and both interop programs are untouched.

F2 — A CLIENT IS ROUTED BY A CONNECTION ID NO PEER EVER ADDRESSES TO IT. `index_connection` does `route_by(impl, entry, entry.connection->original_destination_id())` at :206 for BOTH roles. For a server that is right and necessary (section 7.2: the client keeps addressing the CID it invented until it sees the server's choice). For a client, `original_destination_id()` is the random 8 bytes IT invented to address the PEER (quic_connection.cpp:3105-3116) — a value the server never sends back, since the server addresses the client's SOURCE connection ID. So the entry is dead weight on a single-role endpoint and a hazard on a dual-role one: that value is in plaintext in every Initial we send, and an inbound Initial carrying it as its DCID matches our own client-role connection, fails AEAD against server-direction read keys, is dropped, and `accept_connection` is never reached. One packet, repeatable, blocks inbound connections from an on-path observer. Self-dial and hairpin NAT hit it without any attacker. FIX: route by ODCID only for server-role entries, and make `route_by` REFUSE rather than overwrite a route another entry holds — `impl.by_id[id] = &entry;` at :189 silently steals it today, and `reap` then erases the winner's route when the loser is collected.

F3 — THE STATELESS-RESET BUDGET IS BURNED BY PACKETS THAT CAN NEVER DRAW A RESET, and design 1's reflector claim is FALSE. `send_stateless_reset` (:354-361) calls `allow_stateless_reset` — which decrements the 64-per-second allowance — BEFORE it parses the header and bails on `invariant->long_header`. An Initial is by definition a long header, so the call at :966 after a refused `accept_connection` sends nothing and never has: a dial-only endpoint is not now and never was a reflector, and design 1's "ONE HARDENING FIX FALLS OUT" fixes a bug that does not exist. What is real is that every refused Initial spends one reset token on silence, so a flood drains the allowance that protects genuine short-header packets. FIX: move the long-header test above `allow_stateless_reset`. Then re-describe design 1's hoist honestly: gating the Retry branch on `server_context != nullptr` stops a dial-only endpoint minting and sealing a token it would never honour, and that is all it does.

F4 — `std::erase_if` ON `std::vector<task_t<void>>` DOES NOT COMPILE, and every accept loop in every proposed example uses it. `task.h:42` and `:174` declare `task_t &operator=(task_t &&) = delete;`, and `std::erase_if` goes through `std::remove_if`, which move-assigns. There is also no `done()`. FIX both, in `task_t<T>` and `task_t<void>`: add `done()`, and add a move assignment that destroys a DONE frame before taking the other's handle — which is exactly what the destructor already does, so the assignment is no worse than destruct-then-construct and makes the container idiom legal everywhere rather than only here. `std::list` was the alternative and is worse: it makes every example reach for a container nothing else in vio uses.

F5 — THE FLAGSHIP EXAMPLE LOSES ITS OWN MESSAGE. `co_await quic_stream_write_final(...)` followed by `quic_connection_close(...)` on the same stack: a write under the high-water mark is returned already resolved (`await_ready` true, QUIC_COROUTINE_API.md:464), so no beat runs between them and the bytes are still only queued in `send_stream_t`. `begin_close` (quic_connection.cpp:998-1015) sets `close_frame_pending` immediately, and the packet builder gates stream output on it (:2284-2288) — no STREAM frame is ever built after that. Both peers print an empty string. FIX in the example: read the peer's answer to EOF before closing, which the request/response shape wants anyway and which the doc's own client example already does for this reason. This is NOT peer-to-peer-specific and needs a documented rule plus a test in step 6.

F6 — THE ANSWERING HALF AUTHENTICATES NOBODY, and this must not be papered over. `tls_context_t::create` calls `SSL_CTX_set_verify` only on the client branch (quic_tls.cpp:720/:735); the server branch (:697-715) loads a chain, a key and an ALPN callback and nothing else, and `tls_config_t` has no client-certificate field at all. So a peer verifies whoever it dials and accepts a connection from anyone. "Peer to peer" invites the opposite assumption. I am NOT adding mutual TLS in this change — it is `tls_config_t::request_client_certificate` plus `SSL_CTX_set_verify(SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT)` on the server branch plus a client presenting a chain, which is its own piece of work — but it is stated in three places: the helper's doc comment, the example's header comment, and CLAUDE.md, and it is named as a prerequisite before anyone calls this authenticated peer-to-peer.

F7 — `max_connections` COUNTS OUTBOUND DIALS. `accept_connection` tests `impl.connections.size() >= impl.config.max_connections` (:518) against the whole vector, which on a dual-role endpoint includes everything it dialled, and `connect()` has no ceiling of its own. endpoint.h:113-120 documents the field purely as a spoofed-Initial defence. A peer with `max_connections = 64` that dials 64 peers silently stops answering — and per F3 the refused peer gets nothing and waits out its handshake timeout. FIX: an `accepted_connections` counter on `endpoint_impl_t`, incremented in `accept_connection` and decremented in `reap` for server-role entries, tested by the gate. Rewrite endpoint.h:113-120 to say the ceiling is on ACCEPTED connections.

FOUR MORE SERIOUS FIXES, ALL SMALL. (i) `local_connection_id_override` is cleared on BOTH paths before the Retry test sets it — design 1 cleared it on the connect path, which is the harmless direction; left on the accept path it makes every accepted connection adopt the same local CID and `route_by`'s last-writer-wins silently unroutes all but the newest. (ii) The Retry override at :531-538 fires on any non-empty token, including a NEW_TOKEN, whose DCID is a fresh client-invented value that section 7.2 lets be 8 to 20 bytes; adopted verbatim as the local CID it never matches the fixed-length slice `find_connection` takes from every short header (:270-275), and the connection dies to a stateless reset the moment 1-RTT starts. `token_proves_address` now returns `std::optional<retry_token_key_t::validated_token_t>` and the override fires only for `address_token_kind_t::retry`. (iii) That same return carries the sealed ODCID, which fixes the qlog pairing: `attach_qlog` on the accept path is currently handed `header.destination_id`, which after a Retry is the CID `send_retry` invented, while the client names its file from its true pre-Retry ODCID — so with `retry_key` set the two traces cannot be loaded together, breaking exactly the promise endpoint.h:83-86 makes. The `.server`/`.client` suffix already keeps a self-dialling peer's two files distinct, which is why the naming survives peer-to-peer otherwise. (iv) `send_version_negotiation` is gated on `server_context != nullptr` for the same reason as the Retry: RFC 9000 section 6.1 is a server behaviour, and answering confirms a live ephemeral port and spends CPU on an unauthenticated packet.

`create` REJECTS: no context at all; a context in the wrong slot (naming the expected order); either `native_handle() == nullptr`, because `role()` answers `server` for a moved-from context (quic_tls.cpp:755-758) and would otherwise file it in the server slot and fail once per connection with no obvious cause; and two contexts whose `alpn_wire()` do not overlap. `make_tls_context_pair` additionally rejects an empty `alpn` — a pair with none registers no `alpn_select_cb` on the server half and calls no `SSL_set_alpn_protos` on the client half (both guarded on `!alpn_wire.empty()`), so it completes handshakes with no ALPN, which RFC 9001 section 8.1 forbids, and the helper is the one place that can catch it.

CALL-TIME, NOT CREATE-TIME: `quic_endpoint_connect` on an endpoint with no client context and `quic_endpoint_accept` on one with no server context return a PRE-RESOLVED awaitable carrying a full-sentence `error_t{.code = 1}` — no new error code, because `code = 1` with a sentence is what every configuration error in this stack already uses and nobody branches on "I built this endpoint wrong". The accept case is the single most valuable line in the change: it converts an accept loop silently suspended for ever into a message, and it is only knowable because there is no setter. The connect check goes ABOVE `ensure_socket`, since libuv fixes the socket's address family on first touch and a dial that cannot happen must not pin the endpoint to IPv4. `quic_endpoint_bind` on a client-only endpoint stays LEGAL — a client pinning a source port is ordinary, and the symmetry is a trap.

NOT AN ERROR AT ALL: an Initial arriving at a dial-only endpoint draws nothing. Nothing was promised to whoever sent it.

VERIFIED AND UNCHANGED, so nobody re-derives it: the stateless reset key is role-blind at the endpoint and correctly role-gated inside the connection (only a server publishes the token in its transport parameters, quic_connection.cpp:3086-3093, section 10.3), so one shared key across both roles is safe; `attach_qlog` already takes `bool server` as a parameter rather than reading the config; `retry_key` reaches only accepted connections, because `connect()` deliberately does not copy it; and symmetric dialling cannot deadlock, because `accept_connection` runs from the read loop and `on_connection` fires from `flush_entry` with nothing waiting on an application accept — accept-side backpressure is a level, not a rendezvous.

## Peer-to-peer code

// =============================================================================
// src/vio/quic/tls.h  --  the matched pair, and the accessor create needs
// =============================================================================
namespace vio::quic
{
class VIO_EXPORT tls_context_t
{
public:
  // ... unchanged ...
  [[nodiscard]] void *native_handle() const;
  [[nodiscard]] tls_role_t role() const;

  // The ALPN list as it goes on the wire, so that an endpoint holding two
  // contexts can refuse a pair with no protocol in common at create rather than
  // at the first handshake -- where the alert says "no application protocol"
  // and not "your two contexts disagree". Empty when none was configured.
  //
  // It does NOT catch the worse case, which is two lists holding the same
  // protocols in different orders; see make_tls_context_pair below for why no
  // check can.
  [[nodiscard]] std::span<const std::uint8_t> alpn_wire() const;
};

// Both halves of one peer's TLS identity. An SSL_CTX is bound to its role at
// construction -- quic_tls.cpp:620 picks TLS_server_method or TLS_client_method
// and never changes its mind, and the role also gates anti-replay (:644),
// the session cache mode (:671), early data (:789) and ticket handling (:807,
// :826) -- so an endpoint that both dials and answers needs one of each. There
// is no way to make one context do both.
//
// Move-only, because tls_context_t is. Keep it alive for as long as the
// endpoints built from it: that is the lifetime rule the single
// `const tls_context_t &` already had.
struct tls_context_pair_t
{
  tls_context_t server;
  tls_context_t client;
};

// One description, two contexts. config.role is IGNORED -- taken by value so
// that the caller's value is visibly overwritten -- and everything else is
// shared, which is the entire point:
//
//   - alpn becomes the same list on both halves, and that matters more than it
//     looks. A server selects with SERVER preference: on_alpn_select walks its
//     own list and takes the first entry the client also offered. So two peers
//     whose lists hold the same protocols in DIFFERENT ORDERS complete both
//     handshakes and agree on DIFFERENT protocols depending on which of them
//     dialled -- silently, and only ever in a peer-to-peer deployment. No
//     create-time intersection check catches that. One shared list makes it
//     unrepresentable, and that is the reason this function exists.
//   - certificate_chain_pem / private_key_pem are read only by the server
//     branch and ca_certificates_pem / verify_peer only by the client branch,
//     so one config carries both without collision. A peer has one identity and
//     presents it whether it dialled or answered.
//   - early_data with no anti_replay register fails HERE rather than at the
//     first 0-RTT ClientHello, because the server half's create refuses it.
//     A peer author who enables 0-RTT is told at pair-creation time that a peer
//     which accepts early data needs a strike register.
//
// An empty alpn is refused. A pair with none registers no alpn_select_cb on the
// server half and calls no SSL_set_alpn_protos on the client half -- both are
// guarded on a non-empty list -- so it would complete handshakes with no ALPN
// at all, which RFC 9001 section 8.1 forbids. This is the one place that can
// catch it.
//
// A peer that needs two distinct identities -- a gateway presenting one
// certificate inward and another outward -- builds two contexts by hand and
// hands them to the same endpoint_t::create overload. This is a convenience
// over that mechanism, never the mechanism. One identity, use the pair; two
// identities, build two contexts.
//
// WHAT THIS DOES NOT GIVE YOU: the server half authenticates nobody.
// tls_context_t::create never calls SSL_CTX_set_verify on the server branch and
// there is no client-certificate support anywhere in this stack, so a mesh
// built from this pair verifies the ANSWERER and never the DIALLER.
// "Peer to peer" invites the opposite assumption. Authenticate the dialler
// above the transport until tls_config_t grows a client-certificate half.
[[nodiscard]] VIO_EXPORT std::expected<tls_context_pair_t, error_t> make_tls_context_pair(tls_config_t config);
} // namespace vio::quic

// -------- src/quic_tls.cpp -- the whole implementation ----------------------
std::span<const std::uint8_t> tls_context_t::alpn_wire() const
{
  return _impl == nullptr ? std::span<const std::uint8_t>{} : std::span<const std::uint8_t>(_impl->alpn_wire);
}

std::expected<tls_context_pair_t, error_t> make_tls_context_pair(tls_config_t config)
{
  if (config.alpn.empty())
  {
    return std::unexpected(error_t{.code = 1, .msg = "a peer's tls contexts need an alpn list: with none, the server half registers no selection callback and the client half offers nothing, and RFC 9001 section 8.1 requires a protocol"});
  }
  config.role = tls_role_t::server;
  auto server = tls_context_t::create(config);
  if (!server.has_value())
  {
    return std::unexpected(server.error());
  }
  config.role = tls_role_t::client;
  auto client = tls_context_t::create(config);
  if (!client.has_value())
  {
    return std::unexpected(client.error());
  }
  return tls_context_pair_t{.server = std::move(*server), .client = std::move(*client)};
}


// =============================================================================
// src/vio/quic/connection.h  --  the one new accessor, and one comment rewrite
// =============================================================================

  // Set by whoever builds the connection. endpoint_t writes it PER CONNECTION
  // -- server for an accepted Initial, client for a dial -- and discards
  // whatever endpoint_config_t::connection held, because an endpoint is a
  // socket and a socket has no role. Setting it on endpoint_config_t::connection
  // therefore has no effect. It remains a real input for code that builds a
  // connection_t directly, which is what the sans-I/O tests, bench_quic and
  // profile_quic do.
  tls_role_t role = tls_role_t::server;

  // ... in the accessor block on connection_t:

  // Which side of the handshake this is. On an endpoint holding both contexts
  // the same connections vector carries connections it dialled and connections
  // it answered, and this is the only thing that tells them apart -- which is
  // also what says whether resumption_ticket() can ever be non-empty, since a
  // server is handed tickets and never presents one.
  //
  // It reports the one stored value config.role, which endpoint_t wrote when it
  // built this connection. There is no second source of truth.
  [[nodiscard]] tls_role_t role() const;   // { return _impl->config.role; }


// =============================================================================
// src/vio/quic/endpoint.h  --  one new declaration, one comment corrected
// =============================================================================

  // Zero means no ceiling.
  //
  // A ceiling on connections this endpoint ACCEPTED. Connections it dialled are
  // not counted: they are a resource the operator controls, and mixing them
  // into a defence against spoofed Initials would let a peer-to-peer node that
  // dialled sixty peers stop answering the sixty-first stranger -- silently,
  // because a refused Initial draws nothing at all.
  std::size_t max_connections = 0;

  // ... on endpoint_t:

  [[nodiscard]] static std::expected<endpoint_t, error_t> create(event_loop_t &loop, const tls_context_t &context, const endpoint_config_t &config);

  // An endpoint that both answers and dials, on one socket: peer to peer, and a
  // proxy reusing a port in both directions.
  //
  // Two contexts rather than a flag because an SSL_CTX is bound to its role at
  // construction. The order is SERVER FIRST, and a pair whose roles are not one
  // of each -- or whose ALPN lists have nothing in common, or either of which is
  // moved-from -- is refused here rather than failing per connection later.
  // quic::make_tls_context_pair() builds a matched pair from one description.
  //
  // endpoint_config_t::connection.role is not read for this decision, or for the
  // single-context overload above. It is written per connection: server in
  // accept_connection, client in connect.
  [[nodiscard]] static std::expected<endpoint_t, error_t> create(event_loop_t &loop, const tls_context_t &server_context, const tls_context_t &client_context, const endpoint_config_t &config);


// =============================================================================
// src/quic_endpoint.cpp  --  the whole transport diff
// =============================================================================

// -------- :131 and :140, two borrowed pointers instead of one reference ------
struct endpoint_impl_t
{
  endpoint_impl_t(event_loop_t &event_loop, const tls_context_t *server_tls, const tls_context_t *client_tls, endpoint_config_t configuration, udp_t socket)
    : loop(event_loop)
    , server_context(server_tls)
    , client_context(client_tls)
    , config(std::move(configuration))
    , udp(std::move(socket))
  {
  }

  event_loop_t &loop;
  // Either may be null; each path checks the one it needs, and the presence of
  // the server one is what makes this endpoint answerable. Borrowed, owned by
  // the caller, required to outlive the endpoint -- the same lifetime the single
  // `const tls_context_t &` had, and the same one retry_key and
  // stateless_reset_key below already have.
  const tls_context_t *server_context;
  const tls_context_t *client_context;
  endpoint_config_t config;
  udp_t udp;
  // Connections this endpoint ANSWERED, which is what max_connections bounds.
  // Cached rather than counted, because the accept gate runs per Initial and
  // the vector holds dialled connections too. Maintained at exactly two places:
  // accept_connection raises it, reap lowers it for a server-role entry.
  std::size_t accepted_connections = 0;
  // ... unchanged ...
};

// -------- :186, a route is never stolen --------------------------------------
void route_by(endpoint_impl_t &impl, connection_entry_t &entry, const connection_id_t &id)
{
  if (id.empty() || std::find(entry.routed.begin(), entry.routed.end(), id) != entry.routed.end())
  {
    return;
  }
  // An id another entry already answers to is not ours to take. Overwriting was
  // silent, and reap then erases by_id for every id in the REAPED entry's list,
  // so collecting the loser deleted the winner's route and the winner started
  // drawing stateless resets. Declining leaves the Initial unaccepted, which is
  // the correct answer to a duplicate destination id.
  if (const auto found = impl.by_id.find(id); found != impl.by_id.end() && found->second != &entry)
  {
    return;
  }
  entry.routed.push_back(id);
  impl.by_id[id] = &entry;
}

// -------- :206, only a server is routed by the id the client invented --------
void index_connection(endpoint_impl_t &impl, connection_entry_t &entry)
{
  const auto issued = entry.connection->issued_connection_ids();
  for (const auto &id : issued)
  {
    route_by(impl, entry, id);
  }

  // Section 7.2, and only for a server: a client goes on addressing the
  // connection ID it invented until it has seen the server's choice and
  // switched, so a server that routed only on what it issued would leave every
  // retransmit of that first Initial unmatched.
  //
  // A CLIENT must not be routed by it. Its original_destination_id() is the
  // eight random bytes IT chose to address the PEER -- the server answers to the
  // client's SOURCE id and never sends this value back -- so the entry is dead
  // weight on a client-only endpoint and a hazard on one that also answers: the
  // value travels in plaintext in every Initial we send, and an inbound Initial
  // carrying it as its destination would match our own client-role connection,
  // fail AEAD against server-direction read keys, be dropped, and never reach
  // accept_connection. One packet, repeatable, and self-dial hits it with no
  // attacker at all.
  const auto &original = entry.connection->original_destination_id();
  if (entry.connection->role() == tls_role_t::server)
  {
    route_by(impl, entry, original);
  }

  const auto still_routed = [&](const connection_id_t &id)
  { return (!original.empty() && id == original) || std::find(issued.begin(), issued.end(), id) != issued.end(); };
  // ... the withdrawal sweep, unchanged ...
}

// -------- :354, the reset budget is not spent on packets that draw none ------
void send_stateless_reset(endpoint_impl_t &impl, std::span<const std::uint8_t> datagram, const sockaddr *address, tick_t now)
{
  if (impl.config.stateless_reset_key == nullptr)
  {
    return;
  }
  // Before the allowance, not after. A long header never draws a reset -- an
  // Initial is one by definition -- and this function is reached for every
  // Initial that accept_connection refuses, so charging the allowance first
  // meant a flood of refused Initials drained the budget that protects genuine
  // short-header packets, while sending nothing.
  const auto invariant = parse_invariant_header(datagram);
  if (!invariant.has_value() || invariant->long_header)
  {
    return;
  }
  const auto length = impl.config.connection.local_connection_id_length;
  if (length == 0 || datagram.size() < 1 + length)
  {
    return;
  }
  if (!allow_stateless_reset(impl, now))
  {
    return;
  }
  // ... the id, the token and the send, unchanged ...
}

// -------- :411, the token's kind and its sealed odcid both matter ------------
// Returns what the token proved, not merely that it proved something. Two
// callers need more than a bool: the Retry branch adopts the destination id
// only for a RETRY token, because a NEW_TOKEN Initial's destination id is a
// fresh value the client invented and section 7.2 lets it be 8 to 20 bytes --
// adopted verbatim as the local connection id it would never match the
// fixed-length slice find_connection takes from a short header, and the
// connection would die to a stateless reset the moment 1-RTT started. And the
// qlog naming needs the ODCID the Retry sealed, because after a Retry the
// arriving header names the id the Retry invented, not the one the client
// first chose.
[[nodiscard]] std::optional<retry_token_key_t::validated_token_t> token_proves_address(const endpoint_impl_t &impl, const packet_header_t &header, const sockaddr *address, tick_t now)
{
  if (header.token.empty())
  {
    return std::nullopt;
  }
  const auto full = address_bytes(address);
  if (!full.empty())
  {
    auto retry = impl.config.retry_key->validate(header.token, full, now);
    if (retry.has_value() && retry->kind == address_token_kind_t::retry)
    {
      return *retry;
    }
  }
  const auto host = host_address_bytes(address);
  if (!host.empty())
  {
    auto reused = impl.config.retry_key->validate(header.token, host, now, new_token_lifetime);
    if (reused.has_value() && reused->kind == address_token_kind_t::new_token)
    {
      return *reused;
    }
  }
  return std::nullopt;
}

// -------- :515, the accept gate and the template hygiene ---------------------
[[nodiscard]] connection_entry_t *accept_connection(endpoint_impl_t &impl, std::span<const std::uint8_t> datagram, const sockaddr *address, const packet_header_t &header,
                                                   const std::optional<retry_token_key_t::validated_token_t> &token, tick_t now)
{
  // Having a server identity is what makes this endpoint answerable. It used to
  // be endpoint_config_t::connection.role, which stated the same fact in a
  // second place with nothing checking the two agreed -- and got it wrong for a
  // client endpoint that left the field at its default, which then built a
  // server-role connection on an SSL_CTX made with TLS_client_method. A client's
  // socket is unconnected and takes whatever reaches its port, so one spoofed
  // Initial reached that path.
  if (impl.server_context == nullptr)
  {
    return nullptr;
  }
  // Accepted connections only. Dialled ones are the operator's business and
  // counting them here would let a peer that dialled its way to the ceiling
  // stop answering strangers.
  if (impl.config.max_connections != 0 && impl.accepted_connections >= impl.config.max_connections)
  {
    return nullptr;
  }
  if (datagram.size() < 1200)
  {
    return nullptr;
  }

  auto config = impl.config.connection;
  // The role is the path's, not the template's.
  config.role = tls_role_t::server;
  // Fields that must not travel from a template both directions now share.
  // A ticket and a token are a client's to present; connection_t::create
  // already ignores a ticket for a server, and a field that is silently ignored
  // is a field somebody reads one day.
  config.resumption_ticket.clear();
  config.address_token.clear();
  // Reset BEFORE the Retry test below, not left to survive. A value set on the
  // template would otherwise make every accepted connection adopt the same
  // local connection id, and route_by's table keys on exactly that.
  config.local_connection_id_override.reset();
  if (token.has_value() && token->kind == address_token_kind_t::retry)
  {
    // This Initial is the answer to a Retry this endpoint sent and kept no
    // record of. Section 7.3 has the handshake echo that exact value back, so
    // the connection has to adopt it rather than invent its own.
    config.local_connection_id_override = header.destination_id;
  }
  config.retry_key = impl.config.retry_key;
  config.stateless_reset_key = impl.config.stateless_reset_key;
  config.peer_address = address_bytes(address);
  config.peer_host_address = host_address_bytes(address);
  config.ecn = impl.config.ecn ? ecn_codepoint_t::ect0 : ecn_codepoint_t::not_ect;

  auto created = connection_t::create(*impl.server_context, config);
  if (!created.has_value())
  {
    return nullptr;
  }

  auto entry = std::make_unique<connection_entry_t>();
  entry->id = impl.next_connection_id++;
  entry->connection = std::make_unique<connection_t>(std::move(*created));
  // Named for the id the CLIENT first chose, which after a Retry is the one
  // sealed in the token and not the one the Retry invented. Getting this wrong
  // meant the two ends of a retried connection wrote differently named traces
  // and could not be loaded together -- which is the whole promise the naming
  // makes.
  attach_qlog(impl, *entry->connection, token.has_value() && token->kind == address_token_kind_t::retry ? token->original_destination_id : header.destination_id, true, now);
  entry->peer_bytes = config.peer_address;
  std::memcpy(&entry->peer, address, address->sa_family == AF_INET6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in));

  auto *raw = entry.get();
  impl.connections.push_back(std::move(entry));
  impl.by_handle[raw->id] = raw;
  ++impl.accepted_connections;
  index_connection(impl, *raw);
  return raw;
}

// -------- :686, reap keeps the accepted count honest -------------------------
    if (entry.connection->role() == tls_role_t::server)
    {
      --impl.accepted_connections;
    }

// -------- :720, create ------------------------------------------------------
namespace
{
std::expected<endpoint_t, error_t> make_endpoint(event_loop_t &loop, const tls_context_t *server_context, const tls_context_t *client_context, const endpoint_config_t &config)
{
  auto socket = udp_create(loop);
  if (!socket.has_value())
  {
    return std::unexpected(socket.error());
  }
  endpoint_t endpoint;
  endpoint._impl = std::make_unique<endpoint_impl_t>(loop, server_context, client_context, config, std::move(*socket));
  return endpoint;
}
} // namespace

std::expected<endpoint_t, error_t> endpoint_t::create(event_loop_t &loop, const tls_context_t &context, const endpoint_config_t &config)
{
  // role() answers `server` for a context with no impl (quic_tls.cpp:755), so a
  // moved-from context would classify as a server one and then fail once per
  // connection with nothing pointing at the cause. Catch it here, once.
  if (context.native_handle() == nullptr)
  {
    return std::unexpected(error_t{.code = 1, .msg = "the tls context is not initialized"});
  }
  const bool answering = context.role() == tls_role_t::server;
  return make_endpoint(loop, answering ? &context : nullptr, answering ? nullptr : &context, config);
}

std::expected<endpoint_t, error_t> endpoint_t::create(event_loop_t &loop, const tls_context_t &server_context, const tls_context_t &client_context, const endpoint_config_t &config)
{
  if (server_context.native_handle() == nullptr || client_context.native_handle() == nullptr)
  {
    return std::unexpected(error_t{.code = 1, .msg = "a tls context is not initialized"});
  }
  if (server_context.role() != tls_role_t::server || client_context.role() != tls_role_t::client)
  {
    return std::unexpected(error_t{.code = 1,
                                   .msg = "this overload takes the server context first and the client context second, and each must have been built with that role. "
                                          "quic::make_tls_context_pair() builds a matched pair from one description."});
  }
  // The loud half of the ALPN hazard. Two hand-built contexts with nothing in
  // common dial out fine and refuse every inbound handshake with a fatal
  // no_application_protocol alert -- which surfaces on the REMOTE node, not on
  // the misconfigured one. The quiet half, two lists holding the same protocols
  // in different orders, no check here can see; make_tls_context_pair is the
  // answer to that one.
  if (!alpn_lists_overlap(server_context.alpn_wire(), client_context.alpn_wire()))
  {
    return std::unexpected(error_t{.code = 1,
                                   .msg = "this endpoint's server and client tls contexts share no alpn protocol, so it would dial successfully and refuse every "
                                          "inbound handshake. quic::make_tls_context_pair() gives both halves one list."});
  }
  return make_endpoint(loop, &server_context, &client_context, config);
}

// -------- :763, dialling ----------------------------------------------------
std::expected<connection_handle_t, error_t> endpoint_t::connect(const sockaddr *address, std::string_view server_name, std::span<const std::uint8_t> resumption_ticket, std::span<const std::uint8_t> address_token)
{
  auto &impl = *_impl;
  // Before ensure_socket: libuv makes the UDP socket lazily and whoever touches
  // it first fixes its address family, so a dial that cannot happen must not be
  // the call that pins this endpoint to IPv4.
  if (impl.client_context == nullptr)
  {
    return std::unexpected(error_t{.code = 1,
                                   .msg = "this endpoint has no client TLS context and cannot dial. Build it from a context whose role is tls_role_t::client, or "
                                          "from a server and a client context together if it must also answer."});
  }
  ensure_socket(impl, address != nullptr ? address->sa_family : AF_INET);
  auto config = impl.config.connection;
  config.role = tls_role_t::client;
  // Server-only, and left on the template it would reach a client connection
  // that has no use for it (connection.h:194, gated by role at
  // quic_connection.cpp:1877).
  config.retry_key = nullptr;
  config.local_connection_id_override.reset();
  config.stateless_reset_key = impl.config.stateless_reset_key;
  config.peer_address = address_bytes(address);
  config.peer_host_address = host_address_bytes(address);
  config.ecn = impl.config.ecn ? ecn_codepoint_t::ect0 : ecn_codepoint_t::not_ect;
  // Unconditional, both of them. A ticket and a NEW_TOKEN are each about ONE
  // peer and an endpoint dials many, so the per-dial argument is authoritative
  // and a value left on the shared template must not leak into every dial --
  // which for a token means one server's identifier replayed at every other
  // peer, and useless besides, since validation binds it to the issuer's
  // address. Nothing in tree sets either field on the template.
  config.resumption_ticket.assign(resumption_ticket.begin(), resumption_ticket.end());
  config.address_token.assign(address_token.begin(), address_token.end());

  auto created = connection_t::create(*impl.client_context, config, server_name);
  // ... unchanged, including attach_qlog from original_destination_id() ...
}

// -------- :920 and :954, an endpoint that cannot answer says nothing ---------
      if (invariant.has_value() && invariant->long_header && !version_supported(impl, invariant->version))
      {
        // Section 6.1 is a server behaviour. A dial-only endpoint answering one
        // confirms a live ephemeral port and spends CPU on an unauthenticated
        // packet for a connection it could never accept.
        if (impl.server_context != nullptr && invariant->version != quic_version_negotiation && bytes.size() >= smallest_maximum_datagram_size)
        {
          send_version_negotiation(impl, *invariant, sender);
        }
        continue;
      }
      const auto initial = peek_initial(impl, bytes);
      if (!initial.has_value())
      {
        send_stateless_reset(impl, bytes, sender, now);
        continue;
      }
      std::optional<retry_token_key_t::validated_token_t> token;
      if (impl.config.retry_key != nullptr)
      {
        token = token_proves_address(impl, *initial, sender, now);
        // Do not mint and seal a Retry token for an Initial this endpoint is
        // about to refuse anyway: it would never honour the token it issued.
        // Note what this is NOT: a dial-only endpoint has never replied to an
        // unsolicited Initial at all, because send_stateless_reset bails on a
        // long header. There is no reflector here and never was.
        if (!token.has_value() && impl.server_context != nullptr)
        {
          send_retry(impl, *initial, sender, now);
          continue;
        }
        if (!token.has_value())
        {
          continue;
        }
      }
      entry = accept_connection(impl, bytes, sender, *initial, token, now);
      if (entry == nullptr)
      {
        send_stateless_reset(impl, bytes, sender, now);
        continue;
      }


// =============================================================================
// src/vio/task.h  --  two additions, and why the assignment is safe
// =============================================================================
  // The frame is destroyed with the task_t that names it, so a container of
  // them is how an accept loop keeps its children alive -- and pruning that
  // container needs both of these. std::erase_if goes through std::remove_if,
  // which move-ASSIGNS, so without the assignment below the idiom does not
  // compile at all.
  //
  // Destroying only a DONE frame is exactly what the destructor already does:
  // this is destruct-then-construct written as one operation, and it is no more
  // able to drop a running frame than dropping the variable was.
  task_t &operator=(task_t &&t) noexcept
  {
    if (this != &t)
    {
      if (_coro && _coro.done())
      {
        _coro.destroy();
      }
      _coro = std::exchange(t._coro, {});
    }
    return *this;
  }

  [[nodiscard]] bool done() const noexcept
  {
    return _coro && _coro.done();
  }


// =============================================================================
// src/vio/operation/quic_endpoint.h  --  the coroutine-layer delta
// =============================================================================

// An endpoint that both answers and dials on one socket: peer to peer, and a
// proxy reusing a port in both directions. One SSL_CTX is bound to its role at
// construction, so this is two contexts rather than a flag, server first.
//
// quic::make_tls_context_pair() builds a matched pair from one tls_config_t, and
// for a peer that is what you want: the ALPN list is then the same object on
// both halves, so no dial can fail for want of a common protocol AND no two
// peers can agree on different protocols depending on which of them dialled --
// which they can when the lists hold the same protocols in different orders,
// because a server selects by its own preference.
//
// A single-context endpoint is not crippled and needs no ceremony: it accepts if
// its context is a server one and dials if it is a client one, and the operation
// it cannot do fails with a sentence rather than suspending for ever.
[[nodiscard]] std::expected<quic_endpoint_t, error_t> quic_endpoint_create(event_loop_t &loop, const vio::quic::tls_context_t &context, const quic_config_t &config = {});
[[nodiscard]] std::expected<quic_endpoint_t, error_t> quic_endpoint_create(event_loop_t &loop, const vio::quic::tls_context_t &server_context, const vio::quic::tls_context_t &client_context,
                                                                           const quic_config_t &config = {});

// Which side of the handshake this connection is.
//
// It exists because quic_endpoint_accept and the accept queue behind it are
// built on endpoint_t::on_connection, which fires for every completed handshake
// whether the endpoint answered it or dialled it -- so the API layer has to sort
// them, and on a two-context endpoint an application walking
// quic_endpoint_connections() has to as well. It is also what says whether
// quic_connection_resumption_ticket() can ever be non-empty: a server is handed
// tickets and never presents one. Latched into the handle's own state, so it
// answers on a tombstone.
[[nodiscard]] vio::quic::tls_role_t quic_connection_role(const quic_connection_t &connection);

// A dial on an endpoint built only to answer, or an accept on one built only to
// dial, resolves IMMEDIATELY with a full sentence rather than suspending. That
// is knowable only because there is no way to add a context after create: if a
// setter is ever added, this check becomes a false negative and the accept loop
// goes back to suspending for ever. It is the single most valuable line here
// after peer-to-peer itself, because an accept loop parked on an endpoint
// nobody can dial is the hardest bug in this area to diagnose.
//
// quic_endpoint_bind on a dial-only endpoint stays LEGAL: a client pinning a
// source port is ordinary, and the symmetry is a trap.


// =============================================================================
// examples/quic_peer.cpp  --  what a peer-to-peer user program looks like
//
// Two peers on one loop. Each binds a port, answers whoever dials it, and dials
// the other -- one socket each, one identity each, and nothing anywhere that
// says which of them is the server. Every helper runs twice, once per peer, and
// not one of them knows which peer it is.
//
// WHAT THIS PROGRAM DOES NOT DEMONSTRATE, and must not be read as: mutual
// authentication. tls_context_t::create calls SSL_CTX_set_verify only on the
// client branch and there is no client-certificate support in this stack, so
// each peer verifies the certificate of whoever it DIALS and accepts a
// connection from anyone. A real mesh authenticates the dialler above the
// transport.
// =============================================================================

#include "quic_common.h" // make_self_signed, and the Windows include order

#include <vio/operation/quic_stream.h>
#include <vio/run.h>

#include <algorithm>
#include <optional>
#include <print>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace
{
using namespace vio;

std::span<const std::uint8_t> bytes_of(const std::string &text)
{
  return {reinterpret_cast<const std::uint8_t *>(text.data()), text.size()};
}

// Read one stream to its FIN and answer on the same stream. Everything is a
// PARAMETER and nothing is a capture: task_t is eager, so a captured reference
// is already dangling at the first suspension.
task_t<void> answer_stream(quic_stream_t stream, std::string name)
{
  auto created = quic_stream_create_reader(stream);
  if (!created)
  {
    co_return;
  }
  auto reader = std::move(*created);

  std::string question;
  for (;;)
  {
    auto chunk = co_await reader;
    if (!chunk)
    {
      break; // vio_quic_stream_finished, or a reset -- either ends the read
    }
    const auto data = quic_bytes(*chunk);
    question.append(reinterpret_cast<const char *>(data.data()), data.size());
  }

  const std::string answer = name + " heard \"" + question + "\"";
  (void)co_await quic_stream_write_final(stream, bytes_of(answer));
}

task_t<void> answer_connection(quic_connection_t connection, std::string name)
{
  std::vector<task_t<void>> streams;
  for (;;)
  {
    auto stream = co_await quic_accept_stream(connection);
    if (!stream)
    {
      break;
    }
    // Needs both of task_t's additions: done(), and a move assignment, because
    // erase_if moves the survivors down.
    std::erase_if(streams, [](task_t<void> &t) { return t.done(); });
    streams.emplace_back(answer_stream(std::move(*stream), name));
  }
  for (auto &stream : streams)
  {
    co_await std::move(stream);
  }
}

// Note what this holds: a quic_endpoint_t by value, which is a strong reference,
// so this coroutine's FRAME keeps the socket open -- and a frame is destroyed
// with its named task_t, not at the co_await that finished it. That is why
// main() joins both of these before it resets either endpoint.
//
// Only connections this endpoint ANSWERED reach here. Ones it dialled never
// enter the accept queue; the API sorts them by quic_connection_role(), which is
// also how a supervisor walking quic_endpoint_connections() would tell them
// apart.
task_t<void> answer_loop(quic_endpoint_t endpoint, std::string name, cancellation_t &stop)
{
  std::vector<task_t<void>> sessions;
  for (;;)
  {
    auto connection = co_await quic_endpoint_accept(endpoint, &stop);
    if (!connection)
    {
      break; // cancelled, or the endpoint went away
    }
    std::erase_if(sessions, [](task_t<void> &t) { return t.done(); });
    sessions.emplace_back(answer_connection(std::move(*connection), name));
  }
  for (auto &session : sessions)
  {
    co_await std::move(session);
  }
}

// Dial, say one thing, READ THE ANSWER TO EOF, then close. The read is not
// decoration and the order is not tidiness: a write under the high-water mark
// resolves without suspending, so no beat has run when the next statement
// executes, and quic_connection_close sets close_frame_pending at once -- after
// which the packet builder emits no STREAM frames at all. Closing here without
// first awaiting something would deliver an empty message to the peer.
task_t<std::string> converse(quic_endpoint_t endpoint, sockaddr_storage target, std::string peer_name, std::string question)
{
  auto connection = co_await quic_endpoint_connect(endpoint, reinterpret_cast<const sockaddr *>(&target), peer_name);
  if (!connection)
  {
    co_return "dial failed: " + connection.error().msg;
  }
  auto stream = co_await quic_open_stream(*connection);
  if (!stream)
  {
    co_return "open failed: " + stream.error().msg;
  }
  if (auto written = co_await quic_stream_write_final(*stream, bytes_of(question)); !written)
  {
    co_return "write failed: " + written.error().msg;
  }

  std::string answer;
  {
    auto created = quic_stream_create_reader(*stream);
    if (!created)
    {
      co_return "reader failed: " + created.error().msg;
    }
    auto reader = std::move(*created);
    for (;;)
    {
      auto chunk = co_await reader;
      if (!chunk)
      {
        break;
      }
      const auto data = quic_bytes(*chunk);
      answer.append(reinterpret_cast<const char *>(data.data()), data.size());
    }
  }

  quic_connection_close(*connection, 0, "done");
  (void)co_await quic_connection_closed(*connection);
  co_return answer;
}
} // namespace

int main()
{
  return vio::run(
    [](vio::event_loop_t &loop) -> vio::task_t<int>
    {
      using namespace vio;

      const auto alice_identity = vio_example::make_self_signed("peer-a");
      const auto bob_identity = vio_example::make_self_signed("peer-b");

      // One description per peer, two contexts out of it. `role` is not set --
      // the pair sets it both ways, which is why no line in this program states
      // a role at all. The peer's certificate is the trust anchor only because
      // the two were generated together; a real mesh names a CA here, and a
      // per-peer trust anchor would need a context per peer.
      auto pair_for = [](const vio_example::identity_t &self, const vio_example::identity_t &other)
      {
        quic::tls_config_t tls;
        tls.certificate_chain_pem = self.certificate_pem;
        tls.private_key_pem = self.private_key_pem;
        tls.ca_certificates_pem = other.certificate_pem;
        tls.alpn = {"vio-peer"};
        return quic::make_tls_context_pair(tls);
      };
      auto alice_tls = pair_for(alice_identity, bob_identity);
      auto bob_tls = pair_for(bob_identity, alice_identity);
      if (!alice_tls || !bob_tls)
      {
        std::println(stderr, "make_tls_context_pair: {}", alice_tls ? bob_tls.error().msg : alice_tls.error().msg);
        co_return 1;
      }

      // The whole of the peer-to-peer change at the call site: two contexts
      // instead of one, server first. No role is stated anywhere -- a dial is a
      // client and an arriving Initial is a server, and there is no third place
      // for that to be written down and disagree.
      auto alice_created = quic_endpoint_create(loop, alice_tls->server, alice_tls->client);
      auto bob_created = quic_endpoint_create(loop, bob_tls->server, bob_tls->client);
      if (!alice_created || !bob_created)
      {
        std::println(stderr, "quic_endpoint_create failed");
        co_return 1;
      }
      std::optional<quic_endpoint_t> alice(std::move(*alice_created));
      std::optional<quic_endpoint_t> bob(std::move(*bob_created));

      // Both bind before either dials: a peer has to be reachable, and each
      // needs the other's port before it can say anything.
      const auto bound = quic_endpoint_bind(*alice, 0) && quic_endpoint_bind(*bob, 0);
      const auto alice_address = bound ? ip4_addr("127.0.0.1", quic_endpoint_local_port(*alice).value_or(0)) : std::unexpected(error_t{.code = 1, .msg = "bind"});
      const auto bob_address = bound ? ip4_addr("127.0.0.1", quic_endpoint_local_port(*bob).value_or(0)) : std::unexpected(error_t{.code = 1, .msg = "bind"});
      if (!alice_address || !bob_address)
      {
        alice.reset();
        bob.reset();
        co_return 1;
      }
      const auto to_storage = [](const auto &address)
      {
        sockaddr_storage out = {};
        std::memcpy(&out, &address, sizeof(address));
        return out;
      };

      std::string bobs_reply;
      std::string alices_reply;
      {
        cancellation_t stop_alice;
        cancellation_t stop_bob;
        auto alice_serving = answer_loop(*alice, "peer-a", stop_alice);
        auto bob_serving = answer_loop(*bob, "peer-b", stop_bob);

        // Both dials are in flight at once, and neither waits for the other
        // side's accept loop to be parked. A handshake completes whether or not
        // anything is accepting -- accept_connection runs from the read loop and
        // the finished connection queues, bounded by accept_backlog -- so
        // symmetric dialling cannot deadlock. That is the property that makes
        // peer-to-peer work at all, and it is worth stating because a reader
        // will go looking for the deadlock.
        //
        // Awaited separately rather than with &&: short-circuiting would leave a
        // coroutine suspended for ever.
        auto alice_to_bob = converse(*alice, to_storage(*bob_address), "peer-b", "hello from peer-a");
        auto bob_to_alice = converse(*bob, to_storage(*alice_address), "peer-a", "hello from peer-b");
        bobs_reply = co_await std::move(alice_to_bob);
        alices_reply = co_await std::move(bob_to_alice);
        std::println("peer-a got: {}", bobs_reply);
        std::println("peer-b got: {}", alices_reply);

        stop_alice.cancel();
        stop_bob.cancel();
        (void)co_await quic_endpoint_shutdown(*alice, 0, "done");
        (void)co_await quic_endpoint_shutdown(*bob, 0, "done");
        // Joining the accept loops FIRST is required, not tidy: each holds a
        // quic_endpoint_t by value, so until they finish the resets below drop a
        // reference rather than the last one, the socket's uv_close is never
        // issued, uv_loop_close fails with EBUSY and ~event_loop_t aborts -- or,
        // worse for a program, run() simply never returns. Peer-to-peer makes
        // that ordering commoner, because there are two accept loops.
        co_await std::move(alice_serving);
        co_await std::move(bob_serving);
      }
      alice.reset();
      bob.reset();

      co_return bobs_reply.starts_with("peer-b heard") && alices_reply.starts_with("peer-a heard") ? 0 : 1;
    });
}

---

# Settled: benchmarking the coroutine API

SETTLED: the (a)/(b)/(c) decomposition is HONEST FOR ALLOCATIONS AND DISHONEST FOR TIME, so the benchmark reports allocations as a difference and time as two adjacent rows it refuses to subtract. Design 3 said the first half and then printed a "C - B" microseconds column anyway; that column is deleted.

WHY THE ALLOCATION SUBTRACTION IS SOUND, and it is worth printing in the header so nobody reconstructs it. The replaced global `operator new` sees only C++ allocations, and both libraries underneath are C allocators: libuv is `uv__malloc` -> `malloc` (no `operator new` anywhere in its sources) and BoringSSL is `OPENSSL_malloc` -> `malloc` INCLUDING its C++ objects, since `bssl::New<T>` (crypto/mem_internal.h:54-60) is `OPENSSL_malloc(sizeof(T))` plus a placement new. So everything the counter sees is vio's own C++, and everything it cannot see — every receive buffer, every handle, every AEAD context — is common-mode between B and C. That blindness is normally a defect; here it is the instrument.

WHY THE TIME SUBTRACTION IS NOT SOUND, and it is not a tolerance problem. B and C do not differ by a layer, they differ by WHEN work happens. The callback benchmark drains inside `on_activity`, which `run()` calls from within the read loop immediately before `flush_entry` (endpoint.h:178-186 says this is the point of the hook), so a reply rides the same flush the arriving batch produced. The coroutine layer marks dirty in `on_activity` and resumes on a `uv_prepare_t` beat (QUIC_COROUTINE_API.md:7); prepare runs before poll, so a coroutine woken by a datagram that arrived in poll writes in the NEXT turn. On a ping-pong that is one extra `epoll_wait`/`GetQueuedCompletionStatus` per exchange, and on bulk it changes the segmentation batch size. A "C - B" microseconds column would put the beat's latency under the word "coroutines" — and a four-line summary block is exactly what gets quoted. Design 3's comparability check makes it worse rather than better: it accepts a 2% packet difference, and on a profile that is 80%+ AES-GCM a 2% packet difference is ~1.6% of total time, which is the same order as the thing being measured. The tolerance is looser than the signal.

SO: B and C are printed as adjacent rows with LOOP TURNS PER OPERATION and datagrams-per-send/read on the same line as first-class columns, and the tool prints no time delta. The reader compares two rows and is told, in the header, what differs between them. The exact-equality packet check survives, but as a red WARNING line on the row, not as a licence to subtract.

WHAT ANSWERS "THE COST OF COROUTINES" IS A NEW SECTION WITH NO QUIC IN IT. The coroutine layer is bound to `event_loop_t` and a `uv_prepare_t`, so it cannot be driven the way `main()` drives two `connection_t` objects with no kernel — every coroutine QUIC number carries loop, socket and scheduler noise that configuration A does not have. That is not a defect to apologise for, it is a reason to measure the machinery separately: N `task_t` chains resumed on a bare `event_loop_t`, plus an already-resolved `co_await`, plus a suspending one, plus a resumption driven through a `uv_prepare_t` beat. ns/op, allocations/op, frame bytes/op. THAT number is the cost of coroutines, it is comparable across machines and across changes, and it is what a maintainer acts on. Sections 3-6 also cost QUIC, and say so.

THE THREE SHAPES, AND THE FOURTH THAT MAKES THE DERIVED LINE HONEST.
  W1 bulk — one stream, sized by TIME (1.5 s) not bytes. Per-byte cost. Design 3's 64 MiB default would run 0.1-0.2 s on loopback, under its own 0.25 s CPU-clock threshold, so its headline CPU column would have printed `--`.
  W2 request/response, 64 in flight — per-operation cost under concurrency, the shape a prism/HTTP-3 author is buying.
  W2' request/response, 1 in flight — same code, `--pipeline 1`.
  W3 ping-pong — one long-lived stream, sequential, no stream open or close in it.
The derived "one stream open + FIN + close" line is W2' MINUS W3, not W2 minus W3. Design 3's W2 − W3 is FATAL: W2 pipelines 64 lanes, so it coalesces 64 STREAM frames into the datagrams W3 spends a full round trip on, and the difference is (stream lifecycle) − (63/64 of a datagram round trip), which comes out NEGATIVE. Design 3 marks only the wall-clock cell `--` and keeps CPU and allocations — but CPU carries exactly the same contaminating term, which is the whole reason CPU was worth measuring. W2' and W3 differ ONLY by the stream lifecycle, in all three columns, and cost one CLI flag rather than a new driver. Pipelined W2 stays as its own row for the concurrency number and is subtracted from nothing.

FLOW CONTROL: THE GUARD IS REVERSED. Design 3 raises C to `generous()`'s 4 GiB so it matches B. That measures the flow-control machinery out of existence — at 4 GiB no MAX_DATA or MAX_STREAM_DATA frame is ever sent, and at the settled 8 MiB it is real per-MiB cost on the bulk shape, which is the shape it was raised for. Instead: B moves to `default_transport_parameters()` (8 MiB / 2 MiB), C stays at `quic_flow_control_t{}`, which lowers to the same, and A keeps `generous()` so the sans-I/O numbers CLAUDE.md quotes stay comparable. The guard becomes `transport_parameters_t`'s defaulted `operator==` over the whole struct minus the four handshake-owned fields, NOT a hand-picked seven-field list — design 3's list already silently missed `active_connection_id_limit` (4 in `quic_flow_control_t`, absent-default 2 in `generous()`), which is two extra CSPRNG draws and two extra HMACs each way. A hand-picked field list is exactly the guard that rots.

TEN MECHANICAL FIXES, ALL OF WHICH ARE THE DIFFERENCE BETWEEN A NUMBER AND A FICTION.
1. The size histogram must not allocate inside `operator new`. Design 3's `++g_sizes[size]` on a `std::map` calls the REPLACED `operator new` from inside itself, on a red-black tree mid-insert — unbounded recursion at best. Fixed open-addressed table, static storage, no allocation, overflow bucket.
2. Eleven `operator new`/`delete` replacements, not one. Aligned new without its matching aligned delete is a runtime mismatch, not a compile error, and design 3's `vio_aligned_malloc`/`vio_aligned_free` exist nowhere in the tree — `_aligned_malloc`/`_aligned_free` on MSVC (NOT interchangeable with `std::free`), `std::aligned_alloc`/`std::free` elsewhere.
3. The frame hook must actually be installed. Design 3 declares `coroutine_frame_hook`, defines `count_frame`, and never assigns one to the other, so the frames column reads 0 in every row.
4. The elision check must test code containing coroutines. Design 3's proposed check runs the sans-I/O bulk loop, which has no `co_await` and no `task_t` in it, so a green result proves nothing. Test a leaf `task_t` awaited N times, with and without the hook. Note the risk is small anyway: `initial_suspend()` is `suspend_never` and tasks are returned by value into containers, so HALO essentially never applies here — but that is the argument to make, not the sans-I/O section.
5. `alloc_window_t` gets a destructor that closes idempotently and an assert that `g_counting` is false on entry. Design 3 ships an RAII type with no destructor and an early-return path that leaves the window open, after which every later row silently counts the next handshake.
6. The 8 KiB `std::array<...,8192> scratch{}` per stream frame is deleted. The `{}` value-initialises 8192 bytes per coroutine frame for a 1-byte message — 320 MB of memset charged only to C at the default counts, and 8 KiB of frame_bytes per stream in the exact column that decides whether a frame pool is worth writing. One scratch per lane, hoisted, passed as a span.
7. `stream_accept_backlog` is raised to 4x the pipeline depth. The default is 64 and design 3's default pipeline is 64, so the server's accept queue sits on the boundary and any lag turns the measurement into a measurement of STOP_SENDING. Assert zero refused streams; a refused stream fails the run.
8. Land the `reap_finished` fix (design step at :1832) before taking any W2 number, or W2's per-stream cost drifts upward within the run — the client's `_streams` map grows a node per LOCAL stream for the connection's life, so 20000 exchanges walk a map 20000 deep against the 64-live steady state a real server has, and a median over repetitions cannot see a monotonic drift. Report first-decile and last-decile per-op cost, whose divergence is the signature.
9. Every early return routes through one teardown tail: `counter.stop(); client.reset(); server.reset(); event_loop.stop();`. Design 3 lists this as risk 7 and then ships the bug in its own sample. Add a watchdog `timer_t` that fails the run with a message, because a parked lane leaks its frame (`task_t`'s destructor only destroys a done frame), the frame holds handle refcounts, the endpoint is never released, and a stall becomes an abort in `~event_loop_t` rather than a diagnosis. A hung benchmark looks like a slow one.
10. A CMake guard: `vio_bench` fails to configure under `VIO_BUILD_SHARED=ON`. On MSVC the executable's `operator new` replacement does not serve `vio.dll`'s CRT and the inline hook gets a second copy in the DLL, so both instrumented columns read near zero with no error. Also record the counting thread id at window open and abort if `note()` sees another — the counted region now contains an event loop, and one comparison per allocation turns a silent race into a message.

FAIRNESS FIX B ALREADY NEEDS: `socket_transfer`'s `for(...) co_await sleep(2ms)` completion probe charges the callback configuration a polling latency the coroutine configuration does not pay. Replaced by a latch signalled from `on_activity` but posted through `run_in_loop` — resuming inline from `on_activity` is precisely the transport-walk hazard the layering exists to close. Also print B's `readable_streams()` call count on its own line: that vector is returned BY VALUE, one heap allocation per call, and it is a real cost of the level-triggered API that the edge-list coroutine layer does not pay — it belongs in B's number but must not be read as coroutines being free.

WHERE IT LIVES: one file, one target, `vio_bench`. The rule is "must never share a binary with the tests", and the reason is doctest plus a replaced `operator new`, not the event loop — `socket_transfer` already stands up a loop and a real socket. Two binaries would mean two runs, two warm-ups, two allocator states and no shared counter, for a benchmark whose entire value is a comparison. Configuration A is UNTOUCHED: the sans-I/O bulk loop and the N-concurrent-streams section stay exactly as they are, because those are the numbers CLAUDE.md quotes and the concurrent-streams one measures the transport's stream container, which no API choice touches.

ORDER: the benchmark lands BEFORE any optimisation. A benchmark written after an optimisation encodes its assumptions and cannot show the regression it was built to catch; the number is the justification for whether the work is worth doing at all (if a request/response costs six allocations and 400 ns against an AEAD bill of 3 us, a frame pool is complexity nobody is paying for); and it gives a quotable before/after pair. The levers it prices, named so the table can be read against them: a size-bucketed freelist on `promise_type::operator new` (a given coroutine's frame is one size, so the hit rate is ~100%), making the write op's allocation conditional on `await_ready()` being false (a write under the mark never parks, so bulk should cost zero ops per write), `read_into` against `co_await reader` (the design claims it "saves the allocation, not the copy" — measure both read shapes in C and the claim is verified or it is not), and pooling `quic_stream_state_t` per connection, which W2's allocations-per-stream measures directly.

DETERMINISM: one warmup run discarded, then five repetitions, median for time. Allocations on a lossless loopback path should be CONSTANT across repetitions; if the spread exceeds one per operation, something retransmitted and the per-operation attribution is a mean rather than a constant — print that as a warning rather than a clean-looking number. CPU cells print `--` below 250 ms per repetition, because `GetProcessTimes` is 15.6 ms granular; prefer `QueryProcessCycleTime` on Windows and keep `GetProcessTimes` as the portable fallback.

DOC EDITS THIS FORCES: QUIC_COROUTINE_API.md:1862 ("bench_quic.cpp and profile_quic.cpp stay on the low-level API permanently... putting an event loop and a coroutine layer under it would measure something else") and the step-8 build-order line both now contradict a settled decision. They are rewritten: the SANS-I/O configuration stays and is the baseline; a coroutine configuration is added beside it, and the sentence they were reaching for is true of the subtraction, not of the measurement.

## Benchmark structure

// =============================================================================
// src/vio/task.h  --  the one library change, and the only honest way to tell a
// coroutine frame from a buffer.
// =============================================================================
namespace vio::detail
{
// Null in every build, called only from a task promise. A coroutine frame
// reaches operator new as an anonymous block of bytes, indistinguishable from a
// unique_buf_t or a std::vector -- and test/bench_quic.cpp exists to price
// coroutines against callbacks, which it cannot do if it cannot tell the two
// apart. One never-taken branch beside a malloc, so it costs nothing; a function
// pointer rather than a macro so that the LIBRARY's own frames are counted too,
// which a bench-only macro cannot do without an ODR violation across the two
// translation units.
inline void (*coroutine_frame_hook)(std::size_t size, bool freed) noexcept = nullptr;
} // namespace vio::detail

// ...on task_t<T>::promise_t, task_t<void>::promise_t and
// detached_task_t::promise_type:
  static void *operator new(std::size_t size)
  {
    if (detail::coroutine_frame_hook != nullptr)
    {
      detail::coroutine_frame_hook(size, false);
    }
    return ::operator new(size);
  }
  static void operator delete(void *p, std::size_t size) noexcept
  {
    if (detail::coroutine_frame_hook != nullptr)
    {
      detail::coroutine_frame_hook(size, true);
    }
    ::operator delete(p, size);
  }


// =============================================================================
// test/CMakeLists.txt  --  the guard that stops the instrument reading zero
// =============================================================================
# A benchmark, not a test: it replaces global operator new to count allocations,
# so it must not share a binary with anything else.
#
# It also cannot work against a shared vio. On MSVC the executable's replacement
# does not serve vio.dll's CRT, and the inline coroutine_frame_hook gets a second
# copy inside the DLL that nothing installs -- so both instrumented columns would
# read near zero with no error anywhere. Fail at configure rather than print a
# clean-looking fiction.
if(VIO_BUILD_SHARED)
    message(STATUS "vio_bench not available: it replaces operator new, which does not reach a shared vio")
else()
    add_executable(vio_bench EXCLUDE_FROM_ALL bench_quic.cpp)
    CmDepTargetLinkLibrary(vio_bench PRIVATE vio BoringSSL::SSL BoringSSL::Crypto)
    target_include_directories(vio_bench PRIVATE ${CMAKE_SOURCE_DIR}/src)
endif()


// =============================================================================
// test/bench_quic.cpp  --  accounting
// =============================================================================
namespace
{
struct alloc_counters_t
{
  std::size_t allocations = 0;
  std::size_t bytes = 0;
  std::size_t frames = 0;      // a SUBSET of allocations, never an addition to it
  std::size_t frame_bytes = 0;
};

alloc_counters_t g_alloc;
bool g_counting = false;
bool g_size_histogram = false;
std::thread::id g_counting_thread;

// A fixed table with static storage, because a std::map here would call the
// REPLACED operator new from inside operator new, on a tree that is mid-insert.
// Open addressing, linear probing, one overflow bucket, and not one allocation.
constexpr std::size_t size_slots = 1024;
std::array<std::pair<std::size_t, std::size_t>, size_slots> g_sizes{};
std::size_t g_sizes_overflow = 0;

void note_size(std::size_t size) noexcept
{
  std::size_t slot = (size * 2654435761u) % size_slots;
  for (std::size_t probe = 0; probe < 32; ++probe)
  {
    auto &cell = g_sizes[(slot + probe) % size_slots];
    if (cell.second == 0 || cell.first == size)
    {
      cell.first = size;
      ++cell.second;
      return;
    }
  }
  ++g_sizes_overflow;
}

void count_frame(std::size_t size, bool freed) noexcept
{
  if (freed || !g_counting)
  {
    return;
  }
  ++g_alloc.frames;
  g_alloc.frame_bytes += size;
}

inline void note(std::size_t size) noexcept
{
  if (!g_counting)
  {
    return;
  }
  // The counted region now contains an event loop, so the single-threadedness
  // these plain std::size_t counters rely on is an assumption rather than a
  // fact. vio's threadpool is reached only through file and DNS operations and
  // neither appears here -- but one comparison per allocation turns a silent
  // data race into a message, which is worth more than the comparison costs.
  if (std::this_thread::get_id() != g_counting_thread)
  {
    std::fprintf(stderr, "allocation from a second thread inside a counted window; the numbers are not trustworthy\n");
    std::abort();
  }
  ++g_alloc.allocations;
  g_alloc.bytes += size;
  if (g_size_histogram)
  {
    note_size(size);
  }
}

// Both endpoints share one process and one loop, so the counters are the sum of
// the two sides -- which is also true of the sans-I/O configuration, so the
// configurations stay comparable.
class alloc_window_t
{
public:
  alloc_window_t()
  {
    // A window left open by an early return would silently count the next
    // handshake, the next certificate parse and the next teardown, and the row
    // after it would still look clean.
    if (g_counting)
    {
      std::fprintf(stderr, "an allocation window was never closed\n");
      std::abort();
    }
    g_alloc = {};
    g_sizes = {};
    g_sizes_overflow = 0;
    g_counting_thread = std::this_thread::get_id();
    g_counting = true;
  }
  ~alloc_window_t()
  {
    close();
  }
  alloc_counters_t close() noexcept
  {
    g_counting = false;
    return g_alloc;
  }
};

// Process-wide, kernel time included: on loopback most of what a datagram costs
// is in the kernel, and charging only user time would flatter the socket-heavy
// configurations. RUSAGE_SELF rather than udp_bench.cpp's RUSAGE_THREAD because
// this program has one thread. QueryProcessCycleTime on Windows because
// GetProcessTimes is 15.6 ms granular and would quantise every short row.
double process_cpu_seconds();
} // namespace

// Eleven in, eleven out. The file used to replace only the scalar new, so an
// over-aligned or array allocation was uncounted -- and replacing an aligned new
// without its matching aligned delete is a runtime mismatch rather than a
// compile error. There is no vio_aligned_malloc in this tree; the Windows CRT
// pair is _aligned_malloc/_aligned_free and its result must NOT be passed to
// std::free.
namespace
{
void *aligned_alloc_shim(std::size_t size, std::size_t alignment)
{
#if defined(_WIN32)
  return _aligned_malloc(size, alignment);
#else
  const std::size_t rounded = (size + alignment - 1) / alignment * alignment;
  return std::aligned_alloc(alignment, rounded);
#endif
}
void aligned_free_shim(void *p) noexcept
{
#if defined(_WIN32)
  _aligned_free(p);
#else
  std::free(p);
#endif
}
} // namespace

void *operator new(std::size_t size) { note(size); void *p = std::malloc(size); if (p == nullptr) { throw std::bad_alloc(); } return p; }
void *operator new[](std::size_t size) { return ::operator new(size); }
void *operator new(std::size_t size, std::align_val_t align) { note(size); void *p = aligned_alloc_shim(size, static_cast<std::size_t>(align)); if (p == nullptr) { throw std::bad_alloc(); } return p; }
void *operator new[](std::size_t size, std::align_val_t align) { return ::operator new(size, align); }
void operator delete(void *p) noexcept { std::free(p); }
void operator delete[](void *p) noexcept { std::free(p); }
void operator delete(void *p, std::size_t) noexcept { std::free(p); }
void operator delete[](void *p, std::size_t) noexcept { std::free(p); }
void operator delete(void *p, std::align_val_t) noexcept { aligned_free_shim(p); }
void operator delete[](void *p, std::align_val_t) noexcept { aligned_free_shim(p); }
void operator delete(void *p, std::size_t, std::align_val_t) noexcept { aligned_free_shim(p); }
void operator delete[](void *p, std::size_t, std::align_val_t) noexcept { aligned_free_shim(p); }


// =============================================================================
// Workloads, samples, and the two guards that decide whether a row may be read
// =============================================================================
namespace
{
enum class shape_t
{
  bulk,             // one stream, sized by time.   op = one datagram
  request_response, // N streams, 1 byte each way.  op = one stream
  ping_pong,        // one stream, N round trips.   op = one round trip
};

struct workload_t
{
  shape_t shape = shape_t::bulk;
  std::chrono::milliseconds bulk_duration{1500}; // by TIME, not bytes: 64 MiB on
                                                 // loopback runs under the CPU
                                                 // clock's own resolution
  std::size_t exchanges = 20000;
  std::size_t pipeline = 64; // 1 for the shape the derived line subtracts
  std::size_t message = 1;
  bool read_into = false;    // coroutine configuration only
  bool offload = true;
};

struct sample_t
{
  double wall_seconds = 0;
  double cpu_seconds = 0;
  std::size_t operations = 0;
  std::size_t bytes = 0;
  std::size_t loop_turns = 0;      // zero for the sans-I/O configuration
  std::size_t readable_streams_calls = 0; // callback configuration only
  std::size_t streams_refused = 0;
  double first_decile_us = 0;      // a rising trend is the reap_finished signature
  double last_decile_us = 0;
  alloc_counters_t alloc;
  vio::quic::endpoint_stats_t out;
  vio::quic::endpoint_stats_t in;
  bool ok = false;
};

// Both configurations must advertise the same windows or the comparison is a
// comparison of receive windows. Compare the WHOLE struct minus the four
// handshake-owned fields, not a hand-picked list: a list is the guard that rots,
// and the obvious seven-field version already misses active_connection_id_limit,
// which differs by two CSPRNG draws and two HMACs each way.
[[nodiscard]] bool same_parameters(vio::quic::transport_parameters_t left, vio::quic::transport_parameters_t right)
{
  const auto blank = [](vio::quic::transport_parameters_t &p)
  {
    p.original_destination_connection_id.reset();
    p.initial_source_connection_id.reset();
    p.retry_source_connection_id.reset();
    p.stateless_reset_token.reset();
  };
  blank(left);
  blank(right);
  return left == right; // transport_parameters_t gains a defaulted operator==
}

// Loop turns, counted by a handle this file owns. Unref'd so it cannot keep the
// loop alive, and closed before stop() -- an open handle when run() returns is
// the abort ~event_loop_t exists to make loud, and uv_loop_close is EBUSY for
// any open handle, ref'd or not.
struct turn_counter_t
{
  uv_check_t check = {};
  std::size_t turns = 0;

  void start(vio::event_loop_t &loop)
  {
    uv_check_init(loop.loop(), &check);
    check.data = this;
    uv_check_start(&check, [](uv_check_t *h) { ++static_cast<turn_counter_t *>(h->data)->turns; });
    uv_unref(reinterpret_cast<uv_handle_t *>(&check));
  }
  void stop()
  {
    uv_check_stop(&check);
    uv_close(reinterpret_cast<uv_handle_t *>(&check), nullptr);
  }
};

// The callback configurations have no natural "finished": socket_transfer today
// sleeps 2 ms in a loop, which charges the callback API a polling latency the
// coroutine API does not pay and would make B look slower than it is. Resuming
// straight from on_activity is not the alternative -- that is the transport's
// own walk, and the hazard the whole layering exists to close. Posting through
// the loop resumes on the next turn, which is what the beat does anyway.
struct done_latch_t
{
  vio::event_loop_t *loop = nullptr;
  std::coroutine_handle<> continuation;
  bool done = false;

  void signal()
  {
    if (done)
    {
      return;
    }
    done = true;
    loop->run_in_loop(
      [this]
      {
        if (continuation)
        {
          auto resume = std::exchange(continuation, {});
          resume.resume();
        }
      });
  }
  [[nodiscard]] bool await_ready() const noexcept { return done; }
  void await_suspend(std::coroutine_handle<> c) noexcept { continuation = c; }
  void await_resume() const noexcept {}
};

// Every early return in a driver goes through this. A driver that returns
// without it leaves two endpoints and a uv_check_t open when run() returns,
// which is either the ~event_loop_t abort or -- worse for a benchmark -- run()
// never returning, and a hung benchmark is indistinguishable from a slow one.
struct teardown_t
{
  vio::event_loop_t *loop = nullptr;
  turn_counter_t *counter = nullptr;
  std::optional<vio::quic_endpoint_t> *first = nullptr;
  std::optional<vio::quic_endpoint_t> *second = nullptr;

  ~teardown_t()
  {
    counter->stop();
    first->reset();
    second->reset();
    loop->stop();
  }
};
} // namespace


// =============================================================================
// Section 2: the coroutine machinery, with no QUIC and no socket under it.
//
// This is the section that answers "what do coroutines cost". Everything in
// sections 3 to 6 also costs a socket, an event loop and AES-GCM, and none of
// them can be driven the way configuration A is driven -- the coroutine layer
// is bound to event_loop_t and a uv_prepare_t beat by construction. Measuring
// the machinery on its own is not a consolation prize for that; it is the only
// number here that is comparable across machines and across changes.
// =============================================================================
namespace
{
struct resolved_awaitable_t
{
  [[nodiscard]] bool await_ready() const noexcept { return true; }
  void await_suspend(std::coroutine_handle<>) const noexcept {}
  void await_resume() const noexcept {}
};

vio::task_t<void> leaf() { co_return; }
vio::task_t<void> chain(int depth)
{
  if (depth > 0)
  {
    co_await chain(depth - 1);
  }
}

void bench_coroutine_machinery(std::size_t iterations)
{
  // Confirms the promise-type operator new did not inhibit heap-allocation
  // elision -- which would mean the instrument is what is being measured. It
  // must be checked against code that CONTAINS coroutines: running the sans-I/O
  // section, which has no co_await in it, proves nothing. The risk is small
  // anyway, since initial_suspend is suspend_never and every task_t here is
  // returned by value into a named variable, so HALO essentially never applies.
  vio::detail::coroutine_frame_hook = nullptr;
  const auto without_hook = measure_task_allocations(iterations);
  vio::detail::coroutine_frame_hook = count_frame;
  const auto with_hook = measure_task_allocations(iterations);
  if (without_hook != with_hook)
  {
    std::printf("  the frame hook changed the allocation count (%zu -> %zu): the instrument is being measured\n", without_hook, with_hook);
  }
  // ... resolved co_await, suspending co_await, leaf task, chain of four, and a
  // resumption driven through a uv_prepare_t on a bare event_loop_t ...
}
} // namespace


// =============================================================================
// Configuration C: the coroutine API. Written the way the API is meant to be
// written -- one coroutine per stream, state as PARAMETERS (task_t is eager, so
// a [&] closure is gone by the first suspension), and no polling anywhere.
// =============================================================================
namespace
{
using namespace vio;

// The scratch buffer is the LANE's, not the frame's. A
// `std::array<std::uint8_t, 8192> scratch{}` inside a per-stream coroutine
// value-initialises eight kilobytes on every frame construction, for a workload
// whose message is one byte -- hundreds of megabytes of memset charged only to
// this configuration, and eight kilobytes per stream in the frame-bytes column
// that is supposed to say whether a frame pool is worth writing.
task_t<void> coro_echo_stream(quic_stream_t stream, std::span<const std::uint8_t> answer, std::span<std::uint8_t> scratch, bool read_into)
{
  auto created = quic_stream_create_reader(stream);
  if (!created)
  {
    co_return;
  }
  auto reader = std::move(*created);
  for (;;)
  {
    if (read_into)
    {
      auto read = co_await reader.read_into(scratch);
      if (!read || *read == 0)
      {
        break;
      }
    }
    else
    {
      auto chunk = co_await reader;
      if (!chunk)
      {
        break;
      }
    }
  }
  (void)co_await quic_stream_write_final(stream, answer);
}

[[nodiscard]] quic_config_t coroutine_config(const workload_t &work)
{
  quic_config_t config;
  // Left at quic_flow_control_t's own defaults -- the settled 8 MiB connection
  // window and 2 MiB per stream. It is the CALLBACK configuration that moves to
  // match, not this one: raising both to generous()'s 4 GiB would mean no
  // MAX_DATA or MAX_STREAM_DATA frame is ever sent, which measures the
  // flow-control machinery out of existence on the one shape it was raised for.
  config.transport.offload = work.offload;
  config.transport.connection.pacing = false;
  // The default backlog is 64 and so is the default pipeline, which puts the
  // server's accept queue exactly on the boundary -- past it a stream is refused
  // with STOP_SENDING, and any accept-loop lag turns this into a measurement of
  // stream refusal.
  config.stream_accept_backlog = work.pipeline * 4;
  return config;
}
} // namespace


// =============================================================================
// Reporting. Two rows, no delta, and the columns that say why.
// =============================================================================
namespace
{
void print_header()
{
  std::printf("vio QUIC benchmark   vio static, counting on one thread\n");
  std::printf("  A  sans-I/O transport      no loop, no socket, no kernel\n");
  std::printf("  B  callback API + socket   drains in on_activity, inside the read loop, BEFORE the flush\n");
  std::printf("  C  coroutine API + socket  drains on the uv_prepare_t beat, one loop turn LATER\n");
  std::printf("\n");
  std::printf("  The counter sees only vio's own C++. libuv allocates through uv__malloc->malloc and\n");
  std::printf("  BoringSSL through OPENSSL_malloc->malloc, bssl::New included, so no receive buffer, no\n");
  std::printf("  handle and no AEAD context is in any number below -- and every one of them is\n");
  std::printf("  common-mode between B and C, which is what makes the allocation columns subtractable.\n");
  std::printf("\n");
  std::printf("  THE TIME COLUMNS ARE NOT SUBTRACTED and no delta is printed. B and C do not differ by\n");
  std::printf("  a layer, they differ by WHEN work happens: B's reply rides the flush its own datagram\n");
  std::printf("  produced, C's rides the next turn's. Read turns/op before reading us/op.\n");
  std::printf("\n");
}

void print_shape_header(const char *title, const char *operation, std::size_t repeats)
{
  std::printf("\n--- %s (op = %s, median of %zu) ---\n", title, operation, repeats);
  std::printf("  %-4s %8s %8s %10s %9s %9s %9s %9s %11s %11s\n", "cfg", "MB/s", "us/op", "cpu us/op", "alloc/op", "frame/op", "frameB/op", "turns/op", "dgrams/send", "dgrams/read");
}

void print_row(const char *label, const sample_t &s)
{
  if (!s.ok)
  {
    std::printf("  %-4s FAILED -- delivered %zu bytes over %zu operations, %zu streams refused\n", label, s.bytes, s.operations, s.streams_refused);
    return;
  }
  const auto ops = static_cast<double>(s.operations == 0 ? 1 : s.operations);
  const double megabytes = static_cast<double>(s.bytes) / (1024.0 * 1024.0);
  char cpu[16];
  // GetProcessTimes is 15.6 ms granular; below a quarter second the cell would
  // be quantisation noise wearing a decimal point.
  if (s.cpu_seconds < 0.25)
  {
    std::snprintf(cpu, sizeof(cpu), "%s", "--");
  }
  else
  {
    std::snprintf(cpu, sizeof(cpu), "%.3f", s.cpu_seconds * 1e6 / ops);
  }
  std::printf("  %-4s %8.1f %8.3f %10s %9.3f %9.3f %9.1f %9.3f %11.2f %11.2f\n", label, s.wall_seconds > 0 ? megabytes / s.wall_seconds : 0.0, s.wall_seconds * 1e6 / ops, cpu,
              static_cast<double>(s.alloc.allocations) / ops, static_cast<double>(s.alloc.frames) / ops, static_cast<double>(s.alloc.frame_bytes) / ops, static_cast<double>(s.loop_turns) / ops,
              s.out.sends > 0 ? static_cast<double>(s.out.datagrams_sent) / static_cast<double>(s.out.sends) : 0.0, s.in.reads > 0 ? static_cast<double>(s.in.datagrams_received) / static_cast<double>(s.in.reads) : 0.0);
  if (s.first_decile_us > 0 && s.last_decile_us > s.first_decile_us * 1.2)
  {
    std::printf("       per-op cost ROSE %.0f%% from the first decile to the last: something is growing under the measurement\n", 100.0 * (s.last_decile_us / s.first_decile_us - 1.0));
  }
}

// Not a delta. A statement about whether the two rows above described the same
// work, printed so a reader knows how much of the difference is not the layer.
void print_comparability(const sample_t &b, const sample_t &c)
{
  const bool identical = b.bytes == c.bytes && b.out.datagrams_sent == c.out.datagrams_sent && b.in.datagrams_received == c.in.datagrams_received;
  std::printf("       B and C moved %llu / %llu datagrams and delivered %zu / %zu bytes%s\n", static_cast<unsigned long long>(b.out.datagrams_sent), static_cast<unsigned long long>(c.out.datagrams_sent), b.bytes, c.bytes,
              identical ? "" : "   -- NOT identical; the allocation columns are still comparable, the time columns less so");
  if (b.readable_streams_calls > 0)
  {
    // B's cost includes a std::vector returned by value per call. That is a real
    // cost of the level-triggered callback API and belongs in B's number -- but
    // it must not be read as the coroutine layer being free, because the edge
    // lists replaced exactly this.
    std::printf("       B called readable_streams() %zu times, one heap vector each\n", b.readable_streams_calls);
  }
}

// From the pipeline-1 request/response shape minus the ping-pong shape. NOT from
// the 64-deep one: that pipelines 64 STREAM frames into the datagrams the
// ping-pong spends a round trip on, so the subtraction is
// (stream lifecycle) - (63/64 of a round trip) and comes out negative -- in the
// CPU column exactly as much as in the wall-clock one, which is why marking only
// the wall-clock cell would not have saved it.
void print_stream_lifecycle(const char *label, const sample_t &sequential, const sample_t &ping_pong)
{
  const auto ops = static_cast<double>(sequential.operations);
  std::printf("  %-4s %11.0f %13.2f %13.2f %15.1f\n", label, (sequential.wall_seconds - ping_pong.wall_seconds * static_cast<double>(sequential.operations) / static_cast<double>(ping_pong.operations)) * 1e9 / ops,
              (static_cast<double>(sequential.alloc.allocations) - static_cast<double>(ping_pong.alloc.allocations)) / ops, (static_cast<double>(sequential.alloc.frames) - static_cast<double>(ping_pong.alloc.frames)) / ops,
              (static_cast<double>(sequential.alloc.frame_bytes) - static_cast<double>(ping_pong.alloc.frame_bytes)) / ops);
}
} // namespace

// =============================================================================
// THE EXACT OUTPUT FORMAT
// =============================================================================
//
// vio QUIC benchmark   vio static, counting on one thread
//   A  sans-I/O transport      no loop, no socket, no kernel
//   B  callback API + socket   drains in on_activity, inside the read loop, BEFORE the flush
//   C  coroutine API + socket  drains on the uv_prepare_t beat, one loop turn LATER
//
//   The counter sees only vio's own C++. libuv allocates through uv__malloc->malloc and
//   BoringSSL through OPENSSL_malloc->malloc, bssl::New included, so no receive buffer, no
//   handle and no AEAD context is in any number below -- and every one of them is
//   common-mode between B and C, which is what makes the allocation columns subtractable.
//
//   THE TIME COLUMNS ARE NOT SUBTRACTED and no delta is printed. B and C do not differ by
//   a layer, they differ by WHEN work happens: B's reply rides the flush its own datagram
//   produced, C's rides the next turn's. Read turns/op before reading us/op.
//
// --- section 1: sans-I/O transport, configuration A (unchanged) ---
// bulk stream transfer                1893.4 MB/s      44032 datagrams   0.02 us/datagram   0.1 allocs/datagram    12 B/datagram
//                                    16777216 bytes delivered
// 512 concurrent streams               412.7 MB/s     108544 datagrams   0.09 us/datagram   1.4 allocs/datagram   184 B/datagram
//
// --- section 2: coroutine machinery, no QUIC, no socket ---
//   operation                            ns/op  alloc/op  frame/op  frameB/op
//   co_await an already-resolved            3.1     0.000     0.000        0.0
//   co_await a suspending awaitable        41.2     0.000     0.000        0.0
//   task_t<void> leaf, awaited             28.6     1.000     1.000       96.0
//   task_t chain, depth 4                 112.4     4.000     4.000      384.0
//   resumption through a uv_prepare_t     860.0     0.000     0.000        0.0
//
// --- one stream, bulk (op = one datagram, median of 5) ---
//   cfg      MB/s    us/op  cpu us/op  alloc/op  frame/op frameB/op  turns/op dgrams/send dgrams/read
//   B       612.3    1.840      1.520     0.310     0.000       0.0     0.004        8.31        6.02
//   C       588.1    1.910      1.575     0.352     0.001      96.0     0.021        8.14        5.97
//   A      1893.4    0.021         --     0.100     0.000       0.0        --          --          --
//        B and C moved 349128 / 349901 datagrams and delivered 918552576 / 918552576 bytes
//        B called readable_streams() 0 times, one heap vector each
//
// --- request/response, 64 in flight (op = one stream, median of 5) ---
//   cfg      MB/s    us/op  cpu us/op  alloc/op  frame/op frameB/op  turns/op dgrams/send dgrams/read
//   B         0.0    3.120      2.410     4.000     0.000       0.0     0.031        4.88        4.12
//   C         0.0    3.740      2.980     7.000     3.000     288.0     0.052        4.71        4.06
//
// --- request/response, 1 in flight (op = one stream, median of 5) ---
//   B         0.0   61.400     11.900     4.000     0.000       0.0     2.010        1.00        1.00
//   C         0.0   63.380     12.640     7.000     3.000     288.0     3.020        1.00        1.00
//
// --- ping-pong on one stream (op = one round trip, median of 5) ---
//   B         0.0   59.980     11.320     0.000     0.000       0.0     2.000        1.00        1.00
//   C         0.0   61.400     11.980     0.000     0.000       0.0     3.000        1.00        1.00
//
// --- derived: one stream open + FIN + close ---
//   From the pipeline-1 request/response minus the ping-pong: same cadence, same depth,
//   differing only by the stream lifecycle. Not derived from the 64-deep shape, whose
//   pipelining makes that subtraction negative in every column.
//   cfg    ns/stream  alloc/stream  frame/stream  frameB/stream
//   B           1420          4.00          0.00            0.0
//   C           1980          7.00          3.00          288.0
//
// --- summary ---
//   A task_t frame costs one allocation of 96 bytes; a chain of four costs four.
//   The coroutine API costs C 3 frames and 3 further allocations per request/response
//     stream over the callback API, and 0.04 allocations per bulk datagram.
//   It also costs one extra loop turn per sequential exchange, which is the beat and
//     not the frames: 2.0 turns/op against 3.0.
//   Nothing here is per-byte: bulk throughput differs by 4%, inside the run-to-run spread.
//
// --- top allocation sizes, C, request/response, 64 in flight (--alloc-sizes) ---
//      96 B x 3.000/op   coroutine frames
//      64 B x 2.000/op   per-call write and read ops
//     312 B x 1.000/op   quic_stream_state_t
//     104 B x 1.000/op   registry node
//   (0 allocations overflowed the size table)
//
// CLI: --shape bulk|rr|pingpong  --config a|b|c|all  --repeats N  --exchanges N
//      --pipeline N  --read-into  --alloc-sizes  --offload on|off
//      and the existing positional stream count for section 1.

---

# Changes and open questions from this round

```
P2P_CHANGES:
[small] Add `alpn_wire()` accessor to `tls_context_t`; add `tls_context_pair_t` and `make_tls_context_pair(tls_config_t)` with the doc comment covering the shared-ALPN reason (server preference means differently ORDERED lists agree on different protocols by direction, which no create-time check catches), the ignored `role`, the refusal of an empty alpn, and the fact that the server half authenticates nobody.
    file: C:/Users/jorge/dev/vio/src/vio/quic/tls.h
[small] Implement `tls_context_t::alpn_wire()` (returns `_impl->alpn_wire`, empty for a null impl) and `make_tls_context_pair` (reject empty alpn, set role server, create, set role client, create). About twenty lines; nothing existing is touched.
    file: C:/Users/jorge/dev/vio/src/quic_tls.cpp
[small] Add the two-context `endpoint_t::create` overload (server first). Rewrite `max_connections`'s comment: it bounds ACCEPTED connections, not the total. Add a paragraph on `connection_ready_t` saying it fires for dialled connections too, so a two-context endpoint must sort by `connection_t::role()`.
    file: C:/Users/jorge/dev/vio/src/vio/quic/endpoint.h
[medium] The whole transport diff. `endpoint_impl_t` holds `server_context`/`client_context` pointers plus an `accepted_connections` counter (:131,:140); `route_by` refuses rather than overwrites a foreign route (:186); `index_connection` routes by ODCID only for server-role entries (:206); `send_stateless_reset` parses and bails on a long header BEFORE spending the allowance (:354); `token_proves_address` returns `optional<validated_token_t>` (:411); `accept_connection` gates on `server_context == nullptr` and on `accepted_connections`, writes `role = server`, clears `resumption_ticket`/`address_token`/`local_connection_id_override`, overrides the CID only for a RETRY token, names the qlog from the token's sealed ODCID, and builds from `*server_context` (:515-:547); `reap` decrements the accepted count; a `make_endpoint` helper plus role/native_handle/ALPN validation in both `create` overloads (:720); `connect` null-checks `client_context` above `ensure_socket`, nulls `retry_key` and `local_connection_id_override`, assigns ticket and token unconditionally, and builds from `*client_context` (:763-:776); `send_version_negotiation` and `send_retry` both gated on `server_context != nullptr` (:920,:954).
    file: C:/Users/jorge/dev/vio/src/quic_endpoint.cpp
[small] Add `[[nodiscard]] tls_role_t role() const;` to `connection_t`. Rewrite the comment on `connection_config_t::role` (:105): written per connection by `endpoint_t`, so setting it on `endpoint_config_t::connection` has no effect; still a real input for code building a `connection_t` directly. Add a defaulted `address_token` parameter to `endpoint_t::connect` (:225).
    file: C:/Users/jorge/dev/vio/src/vio/quic/connection.h
[small] Define `connection_t::role()` returning `_impl->config.role`. Nothing else: the one role gate that matters for a two-context endpoint — only a server publishes its stateless reset token in transport parameters (:3086-3093) — already reads `config.role` and follows the per-path role automatically, as does `replenish_connection_ids` using the reset key for both roles.
    file: C:/Users/jorge/dev/vio/src/quic_connection.cpp
[small] Add `done()` and a move assignment to BOTH `task_t<T>` and `task_t<void>`. The assignment destroys only a done frame before taking the other's handle, which is exactly what the destructor does. Without it `std::erase_if` on a `std::vector<task_t<void>>` — the idiom every accept loop in the design uses — does not compile, because `std::remove_if` move-assigns.
    file: C:/Users/jorge/dev/vio/src/vio/task.h
[small] Add the two-context `quic_endpoint_create` overload and `quic_connection_role()`. Rewrite the `quic_config_t::transport` comment that claims `connection.role` is taken from the context, and the paragraph above `quic_endpoint_create` that says the same: the role comes from the operation. Document that connect on an answer-only endpoint and accept on a dial-only one resolve immediately with a sentence, that this is sound only because there is no setter, and that bind stays legal on either.
    file: C:/Users/jorge/dev/vio/src/vio/operation/quic_endpoint.h
[medium] Forward the two-context create to `endpoint_t::create`; stop writing `transport.connection.role`; in the `on_connection` handler branch on `connection.role()` — server to the accept queue, client to the matching dial op, matched by `connection_t*` — which is the fix for the accept queue swallowing dialled connections; latch the role into `quic_connection_state_t` at registration so `quic_connection_role()` answers on a tombstone; pre-resolve `quic_endpoint_accept`/`quic_endpoint_connect` with a sentence when the matching context is absent; leave `quic_endpoint_bind` unrestricted.
    file: C:/Users/jorge/dev/vio/src/quic_coroutine.cpp
[medium] New peer-to-peer example: two peers, one loop, each binding, answering and dialling, built from one `make_tls_context_pair` each, with a message crossing in both directions. Reads each answer to EOF before closing, which is load-bearing, not decoration. Register with `add_vio_example(quic_peer)`.
    file: C:/Users/jorge/dev/vio/examples/quic_peer.cpp
[medium] Transport cases, each confirmed to fail with its mechanism reverted: two two-context endpoints complete handshakes in both directions at once and `connection_count() == 2` with one connection of each `role()`; a self-dial (endpoint dials its own port) completes both a dialled and an accepted connection, which fails today because the client is routed by its own ODCID; a client-only endpoint sends nothing at all in reply to a 1200-byte Initial and its reset allowance is undiminished; a server-only endpoint's connect fails before any socket exists (assert `local_port()` still reports nothing, which is what proves the check precedes `ensure_socket`); `create` refuses a swapped pair, a moved-from context and a pair with no common ALPN; a two-context endpoint at `max_connections` with N dials still accepts; a retried connection's two qlog files share a name; a NEW_TOKEN Initial does not make the accepted connection adopt a foreign-length CID.
    file: C:/Users/jorge/dev/vio/test/test_quic_endpoint.cpp
[medium] Coroutine cases: `quic_endpoint_connect` on an answer-only endpoint and `quic_endpoint_accept` on a dial-only one both resolve without suspending; on a two-context endpoint a dialled connection never appears in the accept queue and `quic_connection_role()` reports it as a client; the symmetric two-peer exchange from the example runs in-process; a write immediately followed by a close still delivers its bytes (the F5 rule, not peer-to-peer-specific).
    file: C:/Users/jorge/dev/vio/test/test_quic_coroutine.cpp
[small] Delete `config.connection.role = tls_role_t::server` (:255) and `= tls_role_t::client` (:395) — written by the path now. The client at :526 keeps `tls.role = tls_role_t::client`, which is what puts the context in the client slot and is what refuses an inbound Initial. Same deletion at interop_server.cpp:177.
    file: C:/Users/jorge/dev/vio/test/interop_endpoint.cpp
[small] Resolve the fourth open question (:1871) in favour of two contexts and a second create overload; rewrite :297-298, :798-802 and :997-1000, which all assert the role comes from the context; correct :1862 and the step-8 build-order line, which say bench_quic stays on the low-level API permanently and contradict settled question 2. Add `quic_peer.cpp` to the examples section, the accept-queue role filter to the internal-changes list, and `task_t`'s move assignment beside its `done()`.
    file: C:/Users/jorge/dev/vio/QUIC_COROUTINE_API.md
[small] One paragraph under the QUIC section: an endpoint may hold a server context, a client context or both; the presence of the server one is what makes it answerable and the role is written per connection; `make_tls_context_pair` is the matched-pair helper and the shared ALPN list is why; a client is not routed by the CID it invented; and the note that the answering half authenticates nobody until `tls_config_t` grows a client-certificate half.
    file: C:/Users/jorge/dev/vio/CLAUDE.md
BENCH_CHANGES:
[large] The three-configuration comparison. Widen the counter to all eleven operator new/delete overloads with real Windows/POSIX aligned shims, a coroutine-frame subcount driven by a hook that is actually INSTALLED, and an allocation-free open-addressed size histogram (a std::map here reenters operator new from inside itself and is fatal). Add process CPU timing (QueryProcessCycleTime on Windows, getrusage(RUSAGE_SELF) elsewhere), a uv_check_t loop-turn counter, a completion latch posted through run_in_loop to replace socket_transfer's 2 ms polling probe, an alloc_window_t with a destructor and an already-open assert, a single teardown tail every early return routes through, and a watchdog timer that fails a stalled run rather than hanging. Refactor socket_transfer into the callback driver (keeping its offload-on/off section) and leave the sans-I/O bulk and N-concurrent-streams sections untouched as configuration A. Add the coroutine driver with one hoisted scratch per lane (never an 8 KiB value-initialised array per frame), stream_accept_backlog at 4x the pipeline depth, a refused-stream count that fails the run, and first/last-decile per-op cost. Add section 2, the QUIC-free coroutine machinery microbenchmark, including the elision check run against code that actually contains coroutines. Add the four shapes (bulk sized by time; request/response at 64 and at 1; ping-pong), the whole-struct parameter guard, warmup plus five repetitions with a median and an allocation-spread warning, the two-row-no-delta tables, the comparability line, and the derived stream-lifecycle line taken from pipeline-1 minus ping-pong. New CLI: --shape, --config, --repeats, --exchanges, --pipeline, --read-into, --alloc-sizes, --offload; the existing positional stream count stays.
    file: C:/Users/jorge/dev/vio/test/bench_quic.cpp
[small] Add `vio::detail::coroutine_frame_hook`, a null-by-default function pointer, and a static operator new/operator delete pair on task_t<T>, task_t<void> and detached_task_t's promise types that call it before forwarding to the global operator. This is the only seam where a coroutine frame is still distinguishable from a buffer, and a function pointer rather than a macro is what lets the library's own frames be counted without an ODR violation. (done() and the move assignment land with the peer-to-peer change, not this one.)
    file: C:/Users/jorge/dev/vio/src/vio/task.h
[small] Add a defaulted `operator==` to `transport_parameters_t`, so the benchmark's guard compares the whole struct minus the four handshake-owned fields rather than a hand-picked list that silently rots — the obvious seven-field version already misses active_connection_id_limit.
    file: C:/Users/jorge/dev/vio/src/vio/quic/transport_parameters.h
[small] Guard the vio_bench target on `NOT VIO_BUILD_SHARED` with a status message. Under a shared build on MSVC the executable's operator new replacement does not serve vio.dll's CRT and the inline frame hook gets a second, uninstalled copy inside the DLL, so both instrumented columns read near zero with no error anywhere. Update the comment above the target: it is still excluded from the default build and still must not share a binary with the tests, but the reason is doctest plus the replaced operator new, not the absence of an event loop — two of its three configurations now stand up endpoints on a real loopback socket.
    file: C:/Users/jorge/dev/vio/test/CMakeLists.txt
[small] Land the reap_finished fix (`_streams` grows one node per LOCAL stream for the connection's life) before any request/response number is taken, or the per-stream cost drifts upward within a single run against a map that ends 20000 nodes deep, and a median over repetitions cannot see a monotonic drift. Keep the MAX_STREAMS credit accounting remote-only; only the erase changes.
    file: C:/Users/jorge/dev/vio/src/vio/quic/streams.h
[small] Correct the Migration section at :1862, which states that bench_quic.cpp stays on the low-level API permanently and that putting an event loop and a coroutine layer under it 'would measure something else' — that is now the opposite of a settled decision. The sentence it was reaching for is true of the SUBTRACTION, not of the measurement: keep the sans-I/O configuration as the baseline and add a coroutine configuration beside it, never in place of it. Correct the same claim in the step-8 build-order line, and add the benchmark to the build order: the request/response and ping-pong shapes land with step 5 (streams), the bulk numbers with step 6 (writes and marks), and any frame-pool or inline-op optimisation lands after both with its before/after quoted from this table.
    file: C:/Users/jorge/dev/vio/QUIC_COROUTINE_API.md
[small] Extend the bench_quic paragraph: it now measures the sans-I/O transport, the callback API over a socket, the coroutine API over a socket, and the coroutine machinery with no QUIC under it at all — the last being the only number that answers 'what do coroutines cost' without a loop and a kernel in it. Record that allocations are attributed to coroutine frames through task.h's null-by-default promise hook; that libuv and BoringSSL are invisible to the counter (both allocate through malloc; bssl::New is OPENSSL_malloc plus a placement new), which is what makes the allocation subtraction sound rather than approximate; and that the time columns are deliberately never subtracted, because the callback path replies inside the read loop and the coroutine path replies on the next beat, so a delta would be a scheduling difference wearing the word 'coroutines'.
    file: C:/Users/jorge/dev/vio/CLAUDE.md

OPEN QUESTIONS:
- Mutual TLS is a prerequisite before anyone calls this authenticated peer-to-peer, and it is not in this change. The server branch of tls_context_t::create never calls SSL_CTX_set_verify and tls_config_t has no client-certificate field, so a peer verifies whoever it dials and accepts a connection from anyone. Scoping it: tls_config_t::request_client_certificate, SSL_CTX_set_verify(SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT) plus SSL_CTX_set_client_CA_list on the server branch, a certificate_chain_pem/private_key_pem the CLIENT branch also loads, and an accessor for the verified peer identity. Is that a follow-up, or does peer-to-peer wait for it?
- Per-dial trust. ca_certificates_pem is consumed once into the SSL_CTX (quic_tls.cpp:723), so a peer endpoint has exactly one trust configuration for every peer it will ever dial, and the example hides that by hardcoding the single remote certificate as the CA -- a shape that does not survive a third node. A real mesh names a CA. The alternative nobody costed is a context per peer, or quic_endpoint_create taking an identity description and building the contexts itself (which would own them, killing the dangling-pointer risk, and guarantee the two halves agree by construction). That last option is worth weighing precisely because the ban on low-level examples has already weakened the compatibility argument for the current shape.
- Should the callback surface's on_connection be split rather than filtered? Adding connection_t::role() and sorting in the coroutine layer is the minimal fix and changes no existing signature. A second hook -- on_connection firing for accepts only, on_dial_complete for dials -- would make the ambiguity impossible rather than merely sorted, at the cost of a new public hook and an edit to endpoint.h:173-176's deliberately role-blind comment. The minimal fix is what I took; the split is the better shape if the callback surface is going to stay public indefinitely, which is itself an open question in the doc.
- The QUIC-level tie-break for simultaneous open. QUIC has no simultaneous-open collapse: two peers that dial each other get two connections per pair, one dialled and one accepted at each end, and quic_connection_peer_address alone is not enough for both ends to independently agree which one to keep. A mesh needs that rule and it is application-layer, not transport -- but the example demonstrates the two-connections case without saying so, and someone will assume the transport collapsed them.
- How large a max_datagram_frame_size, if peer-to-peer makes datagrams likelier? It stays at zero on principle here (the queue behind it is drained only by an application that reads it), but a peer-to-peer node is exactly the shape that wants unreliable datagrams, and the first person to enable it will want a bound the transport enforces rather than a promise.
- Whether the derived stream-lifecycle line should be dropped entirely if the pipeline-1 request/response and the ping-pong turn out not to differ by only the lifecycle in practice -- their loop-turn counts should be identical, and if they are not, the subtraction is contaminated the same way the 64-deep one was and the line should print '--' rather than a number.
- receive-window auto-tuning. The 8 MiB / 2 MiB decision is a static number chosen large because there is nothing to grow it, and it costs 16 GiB per thousand connections. Auto-tuning is the proper fix, it is what every stack shipping a small starting window has, and it is a separate piece of work that has not been scoped. Until it exists, a server expecting thousands of connections has to know to lower initial_max_data, and nothing tells it so.
```


---

# Step 3: what was reverted, and the measurements

Two of step 3's four items were built, measured, and taken back out. Both are recorded here
because the evidence constrains anything that tries again.

## The deadline-driven timer

The plan was to replace the endpoint's fixed 2 ms ticker with a `timer_t` armed to the earliest
deadline any connection reports, on the grounds that `next_timeout` already computes it. It does
not work, for two independent reasons, and the measurements are the argument.

**It spins.** A closed connection keeps reporting the past deadline that closed it: `poll_send`
returns early once the state is closed and never touches any of them, and the idle or handshake
deadline that usually did the closing is behind us by then. Arming on that answer means arming
for zero and firing again immediately. Measured over a five second run: **2704 fires**, against
the ~2500 the 2 ms tick it replaced would have produced. No saving at all.

Skipping closed connections fixes that -- **2704 fires becomes 8** -- so the idea is sound as far
as it goes.

**But it also stalls.** `next_timeout` reports nothing for a connection that merely has data to
send. The 2 ms tick was flushing unconditionally and thereby papering over that; a timer armed
only on reported deadlines never flushes such a connection at all. Measured: the ECN validation
in `a client and a server reach each other over a UDP socket` went from **12/12 to 4/12**.

There is a third trap for anyone who tries the obvious fix of putting the closed-connection guard
inside `next_timeout` itself rather than in the endpoint: `a datagram size the path refuses is not
adopted` steps its clock *from* `next_timeout`, and the stale past deadline was accidentally
acting as a brake that kept the step at 1 ms. Guarding inside `next_timeout` removes the brake,
the loop jumps to the far-future idle deadline instead, and the test goes **5/5 to 0/5**.

So: making the endpoint deadline-driven requires `next_timeout` to report every reason a flush is
needed, including "I have bytes queued", and to report nothing once the connection is closed.
That is a `connection_t` change, not an endpoint one, and it needs its own regression tests.

Worth knowing: this is **not** a prerequisite for the coroutine API, which drives itself from its
own `uv_prepare_t` beat. It is an efficiency item on the callback transport.

## The IPv4 pinning fix

`run()` calls `ensure_socket`, whose default family is `AF_INET`. It is normally spawned before
the first dial and `task_t` is eager, so it gets there first and pins an unbound endpoint to
IPv4 -- after which a dial to an IPv6 peer has nowhere to go, because a socket's family cannot
change afterwards. The bug is real and is now recorded as a `doctest::should_fail` test in
`test_quic_endpoint.cpp`.

The fix attempted was to stop `run()` creating the socket at all, since only `bind()` and
`connect()` know the family, and have it wait for one instead. That delays the reader by a loop
turn, and that alone was enough: the same ECN test went **12/12 to 4/12**, isolated by measuring
with `ensure_socket` restored (**12/12**).

A real fix has to arm the reader the moment the socket appears rather than after a sleep, which
means a signal from `bind`/`connect` into `run` -- endpoint plumbing that step 3 did not want to
disturb.

## One verified fact for the beat

The coroutine layer must own its own `uv_prepare_t`, registered through the ref count the way
`timer_t` is, and must **not** use `event_loop_t::add_about_to_block_listener`. Removal of a
listener is posted through `_run_in_loop` (`event_loop_impl.h:171`), an event pipe that
`event_loop_t::stop()` closes before draining -- so a listener destroyed during shutdown may
never be removed, and the loop would then call `about_to_block()` on freed storage.


---

# Step 4: two corrections to this document, verified against the source

The step 4 specification work produced three independent designs and three adversarial reviews.
Every design came back "needs-work", and two findings are not opinions about those designs --
they are defects in the sketches **in this document**, confirmed by reading the source. They are
recorded here because anyone implementing step 4 from the headers above will otherwise build
them.

## 1. An awaitable must not hold a strong reference to the endpoint state

The header sketch gives `quic_future_t` a `ref_ptr_t<Owner> handle`, and declares
`quic_accept_future_t = quic_future_t<quic_endpoint_state_t, quic_accept_slot_t>`. Built that
way it deadlocks, by construction:

1. A coroutine suspends on `co_await quic_endpoint_accept(endpoint)`. The awaitable's
   `ref_ptr_t` copy increments the endpoint state's count (`ref_counted_wrapper.h:63-70`).
2. The application drops its last `quic_endpoint_t` -- which is the intended shutdown gesture.
3. `dec()` finds the count is 1 rather than 0, so it never runs the destroy callbacks
   (`ref_counted_impl.h:31-46`).
4. Teardown therefore never runs, so the parked accept is never resolved, so the coroutine never
   resumes, so the reference is never released.
5. The beat and UDP handles stay open, `uv_loop_close` fails, and `~event_loop_t` prints every
   open handle and asserts -- the exact failure mode CLAUDE.md warns about.

The waiter holds the thing whose destruction would release the waiter.

This idiom is copied from `tcp_future_t`, where it is correct: there, the handle is the
operation's owner and dropping it mid-await is not a shutdown path. QUIC differs precisely
because *releasing the endpoint is how an application shuts down*, and that gesture is supposed
to resolve every parked awaitable.

So an awaitable holds a **borrowed** pointer and registers itself in an intrusive waiter list on
the state, so that teardown can walk the list and resolve every waiter; each waiter unlinks
itself when destroyed, so an abandoned `task_t` leaves nothing dangling. Note the ordering trap
that follows: if a derived awaitable holds a `ref_ptr_t` member and the base holds the waiter
node, the member is destroyed **before** the base unlinks, so the state may already be freed when
`unlink()` writes through it.

## 2. The beat's phase is a real trade-off, not an obvious win either way

Verified in `3rdparty/libuv-v1.51.0/src/unix/core.c`, `uv_run`'s iteration is:

    uv__run_pending -> uv__run_idle -> uv__run_prepare -> uv__io_poll
      -> uv__run_pending -> uv__run_check -> uv__run_closing_handles
      -> uv__update_time -> uv__run_timers

Two wake sources matter, and the phases favour opposite ones.

**Datagram-driven work** -- a handshake completing, a stream filling, the ordinary
request/response case -- is marked during `uv__io_poll`, because `run()` is a coroutine parked on
the datagram reader and its continuation is resumed from libuv's UDP receive callback. So the
whole receive batch, `on_activity` and `flush_entry` included, executes on the poll phase's
stack. A **check** handle runs microseconds later in the same iteration. A **prepare** handle
already ran, so that work waits for the next iteration.

**Timer-driven work** -- an idle timeout latched by the endpoint's 2 ms ticker, and anything else
`flush_entry` notices from there -- is marked in `uv__run_timers`, at the *end* of an iteration,
after check has already run. Here it is the other way round: **prepare** picks it up before the
loop next blocks, and **check** picks it up only after the next poll.

Neither delay is unbounded, because the 2 ms ticker caps how long poll may block -- so each phase
costs up to a tick on the case it does not favour. The question is only which case dominates, and
for a QUIC transport whose consumer is an HTTP/3 implementation, it is datagram-driven
request/response by a wide margin. That argues for **check**.

This is worth measuring rather than arguing: it is exactly what the step 7 benchmark's
loop-turns-per-operation column exists to show, and the two can be swapped in one line. Build it
whichever way and let the number decide. What is *not* a trade-off is the ownership question --
an owned handle registered through the ref count, never
`event_loop_t::add_about_to_block_listener`, whose removal is posted through a pipe that `stop()`
closes first (`event_loop_impl.h:171`, `:194-203`).

## 3. The lifetime model, validated by running it

The alternative to the deadlocking sketch was built and run before any of step 4 was written,
because it is the part three designs got wrong and the failure mode is a hang rather than a wrong
answer. The shape that works:

- The state holds an **intrusive doubly-linked list of waiters**. A waiter node lives inside the
  awaitable, not in the state, so parking allocates nothing.
- An awaitable holds a **borrowed** `state *`, never a `ref_ptr_t`. This is the whole point: the
  application handle is the only strong reference, so letting it go out of scope really does
  reach zero.
- `on_destroy` walks the waiter list and resolves every parked coroutine with an error. It takes
  the list into a local first and clears the head before resuming anything, because a resumed
  coroutine may park again and appending to a list being walked does not terminate.
- The awaitable's **destructor unlinks** its node. An abandoned `task_t` frees its frame while
  suspended, so a node left linked would leave the list pointing into freed storage and teardown
  would resume a coroutine that no longer exists.
- Each node carries a `linked` flag rather than inferring linkage from the continuation, because
  the two come apart in the case below.

The measured result: a coroutine parks on an await nothing will ever complete; the application
lets the endpoint handle leave scope, with **no cancel, no sleep and no explicit teardown**; the
coroutine resumes with an error; and `~event_loop_t` reports no open handles. That last part is
the real check -- it is the failure this whole model exists to prevent.

### The case the first attempt got wrong

An await made **after** teardown takes the `await_ready` fast path and never links, so the
teardown broadcast -- which only walks linked waiters -- never reaches it. The first attempt
resolved such an await with whatever `result` had been initialised to, which was a success value:
the caller was told its accept had succeeded on an endpoint that no longer existed. `await_resume`
has to answer for that case itself.

This is worth stating because it is invisible by inspection and it is the shape of a whole class
of bug in this layer: every path that resolves an await has to be reachable from both the
teardown broadcast and the already-torn-down fast path, or one of them silently reports success.


---

# Step 4: the settled specification

Produced by three independent designs and three adversarial reviews; every design came back
"needs-work" and this is the synthesis that answers their findings. Its lifetime model is the
one validated by running it, above -- the two arrived at it independently, which is the main
reason to trust it.

Read with one caveat: the synthesis itself has not been through a review pass. The build order
at the end is deliberately arranged so that each step compiles and is testable on its own, which
is the cheapest way to find out where it is wrong.

## Decision

SETTLED DESIGN — step 4, the skeleton. No streams.

WHERE IT LIVES. One new file, `src/vio/operation/quic_endpoint.h`, header-only and `inline`, namespace `vio`, beside tcp.h and udp.h. Two deviations from the design doc, both deliberate:

- **No `src/quic_coroutine.cpp`.** `ref_ptr_t<Data>`'s destructor instantiates `storage_t`, which needs `Data` complete, so all three state structs must be in the header regardless — the .cpp buys no encapsulation, and it would need `VIO_EXPORT` on some twenty free functions under `VIO_BUILD_SHARED` with `CXX_VISIBILITY_PRESET hidden`. Every other operation layer (tcp.h, udp.h, tls_client.h, timer_impl.h) is header-only. It also means **no CMakeLists change at all**: `src/CMakeLists.txt:155` installs headers by directory glob.
- **`quic_stream.h` is not created in step 4.** It has no content until step 5 and an empty header is not a deliverable; the step-5 change that fills it creates it. Error codes `0x9c1c01`–`0x9c1c04` are reserved by comment in quic_endpoint.h so the published numbers stay put.

One additive line lands in `src/vio/quic/connection.h`: `transport_error_connection_refused = 0x02` in the section-20.1 constant block, which the accept-backlog refusal needs. Nothing else outside the new header changes. In particular `endpoint_t`'s three hook setters are **not** given a claim/refuse protocol — that is a public-signature change to a file outside this step, and the doc's own migration note already settles the mitigation: `quic_endpoint_native()` says in its comment which handlers are spoken for.

THE HANDLES. Two aggregate structs over `ref_ptr_t`, member named `handle`, exactly as `tcp_t` (tcp.h:170) and `timer_t` (timer_impl.h:74). Both default to `ref_ptr_t<T>::null()`, so a handle that names nothing is well defined, and **every entry point tests `handle.ref_counted() == nullptr` before `data()`** — `ref_ptr_t::data()` dereferences unconditionally (ref_counted_wrapper.h:158).

Ownership runs strictly downward: endpoint → connection states. Every link back up is a raw pointer nulled by its owner. That is CLAUDE.md's handle rule in pointer terms and the rule timer_impl.h:91-93 already states about `data`.

THE SHARPEST DECISION: **no awaitable ever holds a strong reference to the endpoint state.** The design doc's `quic_future_t { ref_ptr_t<Owner> handle; }` with `Owner = quic_endpoint_state_t` (QUIC_COROUTINE_API.md:924-928, aliased at :1012) is a guaranteed hang and must not be built. Trace it: a coroutine suspended in `co_await quic_endpoint_accept(e)` holds the state; the application drops its last `quic_endpoint_t`; `dec()` takes the count 2→1 and returns false (ref_counted_impl.h:31-33); `on_destroy` never runs; nothing resolves the accept; the beat, the reader's `uv_poll_t` and the `uv_udp_t` all stay open; `event_loop_t::stop()`'s nested `uv_run(UV_RUN_DEFAULT)` (event_loop_impl.h:197-200) runs until nothing is left open, so **`run()` never returns**. That is the second, non-obvious face of the failure CLAUDE.md already names. `tcp_connect_future_t` gets away with the strong ref because libuv guarantees the `uv_connect_t` callback fires; nothing guarantees an accept ever resolves. The build order's own step-4 test — "an endpoint released mid-dial resolves the dial with `vio_quic_endpoint_closed` and `uv_loop_close` succeeds" — cannot pass with a strong reference.

So there are exactly two awaitable shapes, and neither has an endpoint reference to get wrong:

- **`quic_connection_awaitable_t`** — a heap-allocated `detail::quic_op_t` with the two-hold protocol `udp_send_op_t` already uses. Both `quic_endpoint_accept` and `quic_endpoint_connect` return it (`quic_accept_future_t` and `quic_connect_awaitable_t` are aliases, so both published spellings survive). It borrows `quic_endpoint_state_t *`, nulled the instant the op resolves or the endpoint tears down, so the borrow can never outlive the storage — which closes the residual dangling hole a bare borrowed pointer into a slot would have left. This also **replaces the single accept slot**, and with it the doc's rule that a second concurrent accept is refused with `vio_quic_busy`: with a per-call op there is no slot to overwrite, so concurrent accepts are simply served FIFO. That deviation deletes four separate failure modes at once (a stale re-arm, an overwritten continuation, an abandoned future stranding the slot, and a shared "busy" result whose message is moved out on first read). `vio_quic_busy` stays declared and is raised nowhere in step 4; step 5's single stream reader is the operation that genuinely has one slot.
- **`quic_milestone_t`** — reached-or-not, reported rather than consumed, awaitable late, twice, and by several coroutines at once. It holds one `ref_ptr_t<detail::quic_milestone_state_t>`: a milestone is its own tiny allocation that owns no libuv handle, so holding it is always safe and the ownership question never arises. Three uses, one type: `quic_connection_ready`, `quic_connection_closed`, `quic_endpoint_shutdown`. Its waiters are an **intrusive doubly-linked list of nodes living inside the awaitables**, not a `std::vector<std::coroutine_handle<>>`, for two reasons that are correctness and not economy: an awaiting frame destroyed while suspended unlinks its own node, where a vector entry would dangle; and the drain resumes one waiter at a time re-reading the head, because the first coroutine resumed may destroy the second's frame.

NO USER CODE EVER RUNS ON A TRANSPORT WALK'S STACK, and the reason is narrower than the design doc's. `endpoint_impl_t::connections` is `std::vector<std::unique_ptr<connection_entry_t>>` (quic_endpoint.cpp:158), so a dial's `push_back` reallocates a vector of pointers and the entries themselves do not move — `run()`'s `touched` and `flush_entry`'s `entry` reference are both stable, and the `walking` counter (:150-156) already defers the only thing that frees an entry. Dialling from a handler is genuinely safe today and `test_quic_endpoint.cpp:840` passes for that reason. What is **not** safe, and what the beat exists for, is what a *coroutine* may do that a callback may not: drop the last `quic_endpoint_t`, which destroys `endpoint_impl_t`, `run()`'s own frame, the `datagram_reader_t` inside it and the `touched` vector, from a stack three calls deep inside all of them. No amount of `walking` helps; the storage is gone. So the three hooks **latch and queue and never resume**, and resumption happens in exactly one place.

THE BEAT is a `uv_prepare_t` owned by `quic_endpoint_state_t`, `uv_prepare_init`ed at create, registered with `handle.register_handle(&beat)`, `uv_unref`ed, and started once and never stopped until teardown. `beat.data` is a **borrowed** `quic_endpoint_state_t *`, verbatim `timer_create`'s two lines (timer_impl.h:116-117) and for the reason stated there: a reference parked in a registered handle's data keeps the count above zero forever and the `uv_close` is never issued. Note that `dec()` overwrites `handle->data` with the `reference_counted_t *` before closing (ref_counted_impl.h:58), so a null check in the callback would not even be the right test — libuv fires no callback for a closed handle, which is the guarantee the borrow leans on.

Not `add_about_to_block_listener`: `remove_about_to_block_listener` posts through `_run_in_loop` (event_loop_impl.h:171) and `exit_event_loop_cb` closes that pipe and runs a nested `uv_run` before `uv_prepare_stop` (:194-203), so a removal posted during teardown is never delivered while `about_to_block_cb` keeps firing on freed storage. An owned handle has no such window.

**The `uv_unref` is load-bearing and its reason is not the obvious one.** An endpoint created and never bound has no descriptor at all (libuv makes the UDP socket lazily; `ensure_socket`, quic_endpoint.cpp:268-288), and `uv_prepare_start` calls `uv__handle_start`, which counts a referenced handle in `uv__has_active_handles`. So a ref'd beat on an idle endpoint would be the only active handle and would keep `uv_run` alive by itself. It is a hook, not a reason to keep the loop alive; the reading socket is that.

**Prepare, not check — settled from libuv's own loop order.** See the `seam` field; the short of it is that timers run at the *end* of the iteration and the endpoint's 2 ms ticker is what latches an idle timeout, so prepare is the only hook downstream of every wake source and upstream of the block.

THE CALLBACK-DURATION REF, `rc->inc()` at entry and `rc->dec()` as the last statement, is `socket_stream.h:899/928`'s discipline. Be honest about what it buys here: because the beat is registered with `register_handle`, a `dec()` reaching zero inside the beat would **not** free the storage — `dec()` takes the `closable_handles` branch, issues `uv_close` and returns false (ref_counted_impl.h:52-63), and `destroyer()` runs from the close callback a loop turn later. So this is not a use-after-free guard. What it buys is that the destroy sequence — which resolves awaiters, cancels the driver and destroys `endpoint_impl_t` — runs **after** the beat's walk rather than re-entrantly in the middle of it, which is what makes every "the beat holds locals" argument hold without a case-by-case audit of what teardown has already emptied. It has a direct observable, and the test is written on it rather than on a crash that would not happen.

THE TOMBSTONE POINT IS THE DRAINING LATCH, NOT THE REAP. `reap` (quic_endpoint.cpp:749-774) erases the entry and frees the `connection_t` with no notification; `on_connection_gone`, fired from the draining latch at :730-746, is the last moment anything tells this layer about a connection, and it always precedes the reap because `reap` requires `entry.draining` which is set immediately before the hook. So the registry entry is erased there — while the pointer still names *this* connection — which also closes the address-reuse hazard, since `std::make_unique<connection_t>` may hand the next connection the same address. At that same moment the layer latches `close_reason()` by value, `selected_alpn()` as an owning `std::string`, the path stats, and the classified ending; then nulls `transport`. A `quic_connection_t` held afterwards answers `closed`, `close_reason`, `alpn`, `role` and `stats` from its own copies, `quic_connection_native` returns null, and everything else fails with `vio_quic_connection_closed`.

Stats are latched **at the ending rather than zeroed**, a deliberate deviation from the doc's "zeroed on a tombstone": one struct copy per connection, and a shutdown log line reading "RTT 0" for every closed connection is a worse answer than the truth. `in_slow_start` is derived as `congestion_window < slow_start_threshold` from `path_stats()`, which is exactly `congestion_control_t::in_slow_start()`'s own definition (congestion_control.h:328-331) — no transport accessor is needed. `open_streams` is **not** in the struct at step 4; `connection_t` cannot count them, and shipping a field that reads a fabricated zero is worse than adding one in step 5.

TEARDOWN, in the endpoint's single `on_destroy`, guarded by `closing`:
1. `closing = true` **first**, before anything is resumed, and `uv_prepare_stop`. Every entry point tests `closing`, not `transport.has_value()` — the transport is alive for most of teardown, so a coroutine resumed at step 2 could otherwise dial and park on an op nothing will ever resolve.
2. Sever every connection state, taking the union of the registry, the accept queue and the pending list. The third is not redundant: a state whose ending was latched at the gone hook is erased from the registry and pushed onto `pending`, and if the endpoint is released before that beat runs, walking the registry alone abandons its waiters. Any state that can still acquire a waiter is in one of those three, because a drained milestone reads `reached` and `await_ready` never suspends.
3. Resolve every op — `live_ops` and `ready_ops` — and drain every severed state's milestones and the shutdown milestone, **resuming inline**. There is no later beat to defer to; the prepare is stopped and about to be closed. This is what `tls_server.h`'s `on_destroy` (:95-111) does for its parked listen awaiter and for the same reason.
4. `driver_stop.cancel()`. `cancellation_t::cancel()` runs its callbacks inline (cancellation.h:122-132); the ticker's `sleep` resolves inline, and `run()`'s `stop_reading` registration calls `reader->cancel()` → `detail::deliver` → `continuation.resume()` (udp_datagram.h:129-138), so `run()` breaks its read loop and reaches `co_return` **inside this call** — guaranteed, because it never calls user code. Reaching `co_return` destroys its automatic `datagram_reader_t`, whose destructor is what issues `uv_close` on the reader's `uv_poll_t` (udp_datagram.h:448-451, :648-664). **This step, not the next, is the one the ordering rule is about.**
5. `driver.reset()` — the frame is `done()`, so `~task_t` destroys it (task.h:211-217). This frees frame memory only; the reader is already gone. If `driver->done()` is false here the cancel path has changed and the poll will never close, which surfaces as `uv_loop_close` failing.
6. `transport.reset()` — `~endpoint_impl_t` frees every `connection_t` (which is why step 2 severed first) and then `~udp_t`, whose own `dec()` requests `uv_close` on the `uv_udp_t`.

Then the ref count `uv_close`s the beat and frees storage from that close callback. A coroutine resumed at step 3 that takes a new reference restores `in_destroy_sequence` and defers destruction (ref_counted_impl.h:47-51) — contained, not prevented: `closing` makes every entry point refuse and the state is released for real when that reference goes.

WHAT REPLACES THE EXAMPLES' TEARDOWN DANCE. `examples/quic_echo.cpp`'s `cancel(); sleep 50ms; reset(); sleep 50ms;` becomes `co_await quic_endpoint_shutdown(endpoint);` then letting the handle go out of scope before `loop.stop()`. The sleeps were insurance against an ordering the example could not see; they are unnecessary because both cancellations resolve inline, so `run()` is finished *inside* `driver_stop.cancel()` rather than a loop turn later. CLAUDE.md's one rule — release the handle while the loop can still run — applies unchanged and unextended.

THE DRIVER STARTS ON THE FIRST bind OR connect, NEVER AT create. `endpoint_t::run()` opens with `ensure_socket(impl)` at the `AF_INET` default (quic_endpoint.cpp:944, :268), which is the bug still marked `doctest::should_fail` at test_quic_endpoint.cpp:1790. This is **not** the step-3 experiment that was reverted: that one made `run()` itself wait, costing the reader a loop turn and taking the ECN test from 12/12 to 4/12. `task_t` is eager (`initial_suspend()` returns `suspend_never`), so calling `transport->run(&driver_stop)` on `bind`/`connect`'s own stack executes straight through `datagram_reader_t::create` — whose `uv_poll_start` is synchronous (udp_datagram.h:486) — down to the first `co_await *reader`, before the caller returns and before the loop turns. That is exactly what the comment at test_quic_endpoint.cpp:1786-1788 asks for: "arm the reader the moment the socket appears rather than after a sleep." Order inside each entry point is load-bearing: `transport->bind(address)` first, then start; `transport->connect(...)` first (it calls `ensure_socket(impl, address->sa_family)` at :861), then start. `start_driver` also checks `driver->done()`, because `run()` reports a reader it could not create with a bare `co_return` (:947-951) and without the check a `bind` would report success on an endpoint that will never read a byte.

CONFIG. `quic_flow_control_t` is **dropped**. Its job was done one layer lower by `default_transport_parameters()` (transport_parameters.h:157) and `connection_config_t::transport_parameters` (connection.h:162), which fixes the transport's own callers too; a second copy of the same nine numbers is the "two sources of truth for flow control" the design warns against, pointed the other way, and the doc's rule for it — overwrite `transport.connection.transport_parameters` at create — is now destructive of a value set on the field connection.h documents as the place to set it. One job of it survives and is fixed at the source: `transport_parameters_t::max_ack_delay` (milliseconds, wire) and `connection_config_t::max_ack_delay` (nanoseconds, read by loss recovery at eight sites in quic_connection.cpp) are two fields with two independent defaults that happen to agree, so `quic_endpoint_create` derives the wire value from the config field, **rounded up and clamped below `max_ack_delay_limit`** (transport_parameters.h:89) — because an unclamped derivation turns a legal local 30 s into a wire value the peer's decoder rejects with TRANSPORT_PARAMETER_ERROR.

THE INDEPENDENT CLOSE DISCRIMINATOR IS `closed_locally`, NOT A TRANSPORT CHANGE. All five ending paths write `{error_code = 0, application = false, from_peer = ...}` (quic_connection.cpp:1004, :1788, :3274, :3343, :3361), so an idle timeout and a local `close(0)` differ by nothing but an English reason string. Adding `connection_end_t how` to `connection_close_t` would settle it properly, but it is a step-2-shaped change arriving late and it touches a public struct. Instead every path in *this layer* that closes a connection goes through one helper that sets `closed_locally` — which covers `quic_connection_close`, `quic_endpoint_shutdown` and the cancelled dial, i.e. every way an application using this API closes anything. The one gap, and the header says so: a close issued through `quic_connection_native()->close(0, …)` is reported as an idle timeout.

## The seam

HOW IT INSTALLS. `quic_endpoint_create` takes all three of the transport's dispatch hooks, with a borrowed `quic_endpoint_state_t *` in each closure:

```cpp
state->transport->on_connection([self](vio::quic::connection_t &c) { detail::quic_hook_connection(*self, c); });
state->transport->on_activity([self](vio::quic::connection_t &c) { detail::quic_hook_activity(*self, c); });
state->transport->on_connection_gone([self](vio::quic::connection_t &c) { detail::quic_hook_gone(*self, c); });
```

They are single slots assigned wholesale (`quic_endpoint.cpp:835-848`), so the coroutine layer owns dispatch and an application driving the same endpoint through the callback API cannot. That is structural rather than a concession: the hooks fire from inside `flush_entry`, and the entire point of the design is that no user code runs there — chaining a user closure into the walk would reinstate exactly the hazard the beat removes. It is not enforced with a `claim_hooks` protocol, because that is a public-signature change to three functions in a file outside step 4; `quic_endpoint_native()`'s doc comment says which handlers are spoken for, which is the mitigation the design doc's own migration section settles on.

`on_activity` is installed although step 4 has nothing to read: it is where step 5 drains the edge lists, and installing it now means the beat's shape is fixed here rather than being reworked later. In step 4 it does one thing — look the connection up and, if it is registered and has a pending dial or an unreached milestone, `quic_mark_pending`. It never marks dirty: `run()` already flushes every touched connection, and marking them would double the endpoint's idle flush cost.

**THE ROLE SORT.** `on_connection` fires from `flush_entry` (:722-727) for every connection that reaches `handshake_complete()`, dialled ones included — `test_quic_endpoint.cpp:1556` records exactly that. A dial is matched by **pre-registration, not by role**, because `endpoint_t::connect` inserts into `by_handle` before it flushes and returns (`:888-892`) and `endpoint_t::connection(handle)` is a bare lookup with no walking (:895-899). So `quic_endpoint_connect` does, on the caller's own stack, before returning:

```cpp
auto dialled = state.transport->connect(address, server_name, resumption_ticket);   // fixes the socket family
if (!dialled) { return failed(dialled.error()); }
auto *connection = state.transport->connection(*dialled);
if (connection == nullptr) { return failed(...); }
detail::quic_start_driver(state);                        // after connect, never before

auto entry = ref_ptr_t<detail::quic_connection_state_t>(&state, connection, vio::quic::tls_role_t::client);
entry->pending_dial = op;
state.by_connection.emplace(connection, entry);

// endpoint_t::connect calls flush_entry before it returns, so this connection's
// draining latch -- and with it the gone hook -- may already have fired for a
// connection nothing had registered yet, in which case it will never fire
// again. Nothing can drive a fresh dial to closed today, but the registration
// is not allowed to assume it precedes the first hook.
if (connection->state() == vio::quic::connection_state_t::closed)
{
  detail::quic_sever(state, entry, std::unexpected(error_t{.code = vio_quic_handshake_failed, .msg = "the connection ended before it was dialled"}));
}
```

`quic_hook_connection` is then a single `by_connection.find(&c)`:

- **found** — it is the dial this layer made. Latch the alpn, reach `ready` with success, resolve the pending dial with a `quic_connection_t` naming that entry, `quic_mark_pending`.
- **not found and `c.role() == server`** — a fresh inbound. If `closing`, `shutdown_active`, or `accept_queue.size() >= config.accept_backlog`: `c.close(transport_error_connection_refused, "the accept backlog is full", false)` and `flush_all = true`, registering nothing. Otherwise build a state with `role = server`, latch the alpn, reach `ready`, register it, and either hand it straight to the oldest waiting accept op or push it on `accept_queue`.
- **not found and `c.role() == client`** — dialled behind this layer's back through `quic_endpoint_native()->connect()`. **Ignore it.** It has no awaiter, and pushing it onto the accept queue would hand a server an outbound connection. This is the case a peer-to-peer endpoint makes reachable and the reason `role()` is checked at all.

The role is latched onto the state at registration in every branch, because a tombstone must still answer `quic_connection_role` and the sort itself needs it before anything else about the connection is known.

**THE ACCEPT QUEUE AND THE WAITER FIFO.** `accept_queue` is a `std::deque<ref_ptr_t<quic_connection_state_t>>`; waiters are the accepting entries of `live_ops`, in call order. One dispatch function keeps the two from ever both being non-empty:

```cpp
inline void quic_accept_pump(quic_endpoint_state_t &self)
{
  while (!self.accept_queue.empty())
  {
    auto found = std::find_if(self.live_ops.begin(), self.live_ops.end(), [](const quic_op_t *op) { return op->accepting && !op->done; });
    if (found == self.live_ops.end())
    {
      return;
    }
    auto state = std::move(self.accept_queue.front());
    self.accept_queue.pop_front();
    quic_op_finish(self, *found, quic_connection_t{std::move(state)});
  }
}
```

Called from `quic_hook_connection` after a connection is queued, and **from `quic_endpoint_accept`'s own factory**, which is what makes an accept whose queue is already non-empty resolve without suspending — the property the design calls out, and the difference between draining a burst on one stack and one loop turn per connection. `quic_op_finish` moves the op from `live_ops` to `ready_ops`, keeping the endpoint's hold, which the beat drops after resuming; it resets the cancel registration **before** anything is resumed, because the resuming coroutine owns the token and may destroy it.

There is no `vio_quic_busy` here. With per-call operations a second concurrent accept has nothing to overwrite; both park and both are served, oldest first.

**CANCELLATION LATCHES AND NEVER RESUMES.** The callback on a `cancellation_t` sets the op's result and calls `quic_op_finish`, which puts it on `ready_ops`; the beat resumes it. One resumption site in the whole layer, no exceptions, and the "reset the registration before the resume" rule is then a property of one function rather than a discipline at five call sites. It costs no wall clock, by the same derivation that chose prepare: whatever phase the cancel was called from — a timer callback, an I/O callback, another coroutine the beat resumed — the next prepare is reached before the loop next blocks. A pre-cancelled call never touches the transport at all and returns an already-resolved awaitable, the `tcp_connect` shape. A cancelled dial additionally closes the connection it built, through the same helper that sets `closed_locally`, with `transport_error_no_error` and "dial cancelled"; its registry entry stays, precisely so `on_connection` cannot later mistake it for an inbound arrival.

**THE GONE HOOK IS THE TOMBSTONE POINT.**

```cpp
inline void quic_hook_gone(quic_endpoint_state_t &self, vio::quic::connection_t &connection)
{
  const auto found = self.by_connection.find(&connection);
  if (found == self.by_connection.end())
  {
    return; // arrived and died before its handshake completed; never registered
  }
  const auto state = found->second;
  // Erased here, while the pointer still names this connection. The reap a
  // draining period later frees the connection_t with no notification, and the
  // next one may well be allocated at the same address -- a stale key would
  // hand a new peer's connection to a retired handle.
  self.by_connection.erase(found);
  quic_sever(self, state, {});
  if (self.shutdown_active && self.shutdown_outstanding > 0)
  {
    --self.shutdown_outstanding;   // its CONNECTION_CLOSE is in a datagram
  }
}
```

**SHUTDOWN.** `quic_endpoint_shutdown` closes every registered connection through the `closed_locally` helper, sets `shutdown_active`, records `shutdown_outstanding` as the number it closed and `shutdown_deadline = loop_now(loop) + close_timeout`, marks each dirty, and returns the endpoint's shutdown milestone. `quic_shutdown_check` runs once per beat: it reaches the milestone when `shutdown_outstanding == 0` or the deadline has passed, and clears `shutdown_active`. No `timer_t`: the deadline is compared against `loop_now` in the beat, which the 2 ms ticker guarantees runs — and a shutdown with nothing to close resolves in the factory, which is what covers an endpoint whose driver never started and whose loop may therefore not turn on its own. Shutdown also stops accepting: later accepts pre-resolve with `vio_quic_endpoint_closed` and arriving connections are refused.

**STARTING THE DRIVER.**

```cpp
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
    // run() reports a reader it could not create with a bare co_return, so
    // done() on the first turn is the only signal there is -- and without this
    // a bind would report success on an endpoint that will never read a byte.
    self.driver.reset();
    self.driver_started = false;
    return std::unexpected(error_t{.code = -1, .msg = "the endpoint could not start reading its socket"});
  }
  return {};
}
```

`task_t` is eager, so `run()` executes through `datagram_reader_t::create` — whose `uv_poll_start` is synchronous — down to its first `co_await *reader`, on this stack, before the caller returns. That is the fix the `should_fail` test's own comment asks for, and it is not the reverted experiment, which made `run()` wait and cost a loop turn.

## Errors

SEVEN CODES, `0x9c1c05` … `0x9c1c0b`, which is `10230789`–`10230795` decimal. Checked against every code defined in `src/`: `vio_tls_error` / `clean_shutdown` / `truncated` are `0x715c00`–`0x715c02` (ssl_engine.h:50-52), `vio_cancelled` is `0xca9ce1` (cancellation.h:40), and `vio_uv_ecanceled` is `UV_ECANCELED`, which is negative on every platform. Nothing else in the tree defines one, and `error_t{.code = -1}` is the repo's generic argument-error value. **No collision.**

`0x9c1c01` … `0x9c1c04` are left reserved by comment for `quic_stream.h` (`stream_finished`, `stream_reset`, `stream_stopped`, `stream_stale`). They are not declared in step 4, so the header a program that only dials includes does not carry them, and the published numbers stay put.

| code | value | raised by |
|---|---|---|
| `vio_quic_connection_closed` | `0x9c1c05` | `quic_classify_ending`'s last two arms: a `close_reason` with a non-zero code after the handshake completed (the peer's reason string goes into `error_t::msg`), or an ending with no reason recorded at all. Also what a tombstoned `quic_connection_t` returns from anything it can no longer do. |
| `vio_quic_idle_timeout` | `0x9c1c06` | a zero-code, `from_peer == false` ending that this layer did not ask for. Section 10.1, quic_connection.cpp:3359-3361. |
| `vio_quic_handshake_failed` | `0x9c1c07` | any ending recorded while `handshake_reached` is false: a certificate that did not verify, no ALPN in common, a TLS alert, and the deadline at quic_connection.cpp:3341-3343. One code for all four, because all four mean the dial produced nothing usable; `close_reason()` separates them and its text is carried in `msg`. |
| `vio_quic_stateless_reset` | `0x9c1c08` | `connection_t::reset_by_peer()`, tested first because that path records `{0, false, "stateless reset", from_peer = true}` (:3272-3274) and would otherwise read as a clean ending. |
| `vio_quic_version_unsupported` | `0x9c1c09` | `connection_t::version_negotiation_failed()`, tested second for the same reason (:1786-1788). |
| `vio_quic_endpoint_closed` | `0x9c1c0a` | every operation and milestone still parked at teardown; every factory called on a `closing` endpoint; and `await_resume` on an awaitable whose operation is gone. The doc's wording — "the endpoint was released" — is widened to "released or shut down". |
| `vio_quic_busy` | `0x9c1c0b` | **nothing, in step 4.** Declared because it is published and because step 5's single stream reader is the operation that really has one slot. |

NOT AN ERROR CODE, deliberately: configuration and misuse that is not a race. An accept on a dial-only endpoint, a dial on an answer-only one, an accept or a bind on a released endpoint's still-valid-looking handle, and a milestone on a default-constructed handle all come back as `error_t{.code = -1}` with a full sentence — which is what `endpoint_t::connect` already answers for the mirror case ("this endpoint has no TLS context to dial with", quic_endpoint.cpp:859). Overloading `vio_quic_busy` onto "you configured this wrong" would make the one code an application can usefully branch on unbranchable. This narrows the design doc's usage, which had `vio_quic_busy` carrying "This stream has no receiving half" as well; step 5 should keep the narrowing.

A CLEAN ENDING IS `std::expected` SUCCESS, not a code: a zero error code from either side after the handshake completed. `quic_connection_closed` resolving with a value is the only ending here that is not a failure.

THE ORDER IN `quic_classify_ending` IS THE SPECIFICATION, and it is forced by what the five ending paths actually record — verified at quic_connection.cpp:1004, :1788, :3274, :3343 and :3361, all five of which write `error_code = transport_error_no_error` with `application = false`:

1. `reset_by_peer()` — records `from_peer = true`, so testing the code first would call it clean.
2. `version_negotiation_failed()` — same shape, same reason.
3. `!handshake_reached` — the handshake deadline records `{0, false, false}`, byte for byte what a local transport-space `close(0)` records.
4. `!reason.has_value()` — nothing said why.
5. `reason->error_code != 0` — a real close from either side.
6. `!reason->from_peer && !closed_locally` — the idle timeout, told from a clean local close by the one fact only this layer has.

`error_t` is `{int, std::string}` and shared by every subsystem in vio, so a peer's 62-bit application code does not fit in it. `quic_connection_close_reason()` is where the full `connection_close_t` — code, application-or-transport, reason, `from_peer` — is read, and it keeps answering on a tombstone because it is copied into the handle's own state.

ONE GAP, STATED IN THE HEADER RATHER THAN PAPERED OVER: `closed_locally` is set only by this layer's own close paths. A connection closed through `quic_connection_native()->close(0, …)` records `{0, application, false}` with nothing claiming it, and is reported as `vio_quic_idle_timeout`. Closing it properly needs a discriminator on `connection_close_t` — a `connection_end_t how` set at the five sites — which is a step-2-shaped change to a public struct and is not made here.

## Proposed header

```cpp
// =============================================================================
// src/vio/operation/quic_endpoint.h  --  namespace vio
//
// The coroutine face of QUIC: endpoints and connections. Streams and datagrams
// arrive in quic_stream.h at the next step, and nothing here names one -- a
// program that only dials and closes should not have to parse the stream API
// to do it.
//
// Everything under vio/quic/ stays exactly as it is. connection_t is a sans-I/O
// state machine and endpoint_t is a demultiplexer over one UDP socket, both
// driven by std::function and by integer ids, and both testable with no socket
// under them. That is the right shape for the inside of a transport and the
// wrong shape for an application, which wants to write co_await.
//
// The organising idea is the loop turn. Datagrams that arrived together are
// taken in together by the endpoint's read loop, which marks the connections
// they touched and sends whatever acknowledgements they owe. Then, once, before
// the loop blocks again, every coroutine that has become runnable is resumed
// and everything they wrote is pushed onto the socket. That second half is the
// beat, and it runs from a uv_prepare_t this endpoint owns.
//
// No user code ever runs on the read loop's stack or inside the endpoint's
// reap, and the reason is narrower than it first looks. endpoint_impl_t holds
// its connections as unique_ptr, so a dial's push_back does not move the
// entries a walk is standing on, and the walking counter already defers the
// reap that would free one -- dialling from a callback is safe today. What is
// not safe is what a coroutine may do that a callback may not: drop the last
// quic_endpoint_t, which destroys endpoint_impl_t, run()'s own frame, the
// datagram reader inside it and the vector being walked, from a stack three
// calls deep inside all of them. No amount of bracketing helps; the storage is
// gone. So the transport's three hooks only record, and the beat is the one
// place anything is resumed.
//
// There is no run() and no flush() here. An endpoint starts reading the first
// time it is bound or dialled -- not at create(), because libuv makes a UDP
// socket lazily and whoever touches it first fixes its address family, which is
// how an endpoint that started before it knew where it was going ends up unable
// to reach an IPv6 peer.
// =============================================================================

#pragma once

#include "vio/cancellation.h"
#include "vio/error.h"
#include "vio/event_loop.h"
#include "vio/quic/endpoint.h"
#include "vio/ref_counted_wrapper.h"
#include "vio/task.h"
#include "vio/tick.h"

#include <chrono>
#include <coroutine>
#include <cstdint>
#include <deque>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>
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
// else in vio uses this block: the only other codes are 0x715c00-02 (TLS),
// 0xca9ce1 (cancellation), and libuv's, which are negative.
//
// 0x9c1c01 .. 0x9c1c04 are reserved for vio/operation/quic_stream.h --
// stream_finished, stream_reset, stream_stopped, stream_stale. The hole is left
// rather than closed so the published numbers stay put when step 5 raises them.

// The connection ended under this operation with a non-zero code, after its
// handshake had completed. quic_connection_close_reason() says who said so and
// why; the reason string is also in error_t::msg. A code of zero from either
// side is not this -- it is a clean ending, and arrives as success.
inline constexpr int vio_quic_connection_closed = 0x9c1c05;

// Section 10.1: the negotiated idle period elapsed. Distinct from a close
// because nobody said anything, which is the whole reason the timer exists.
inline constexpr int vio_quic_idle_timeout = 0x9c1c06;

// The connection ended before its handshake completed: a certificate that did
// not verify, no ALPN in common, a TLS alert, or connection_config_t's
// handshake deadline. One code for all four, because all four mean the dial
// produced nothing usable, and close_reason() separates them.
inline constexpr int vio_quic_handshake_failed = 0x9c1c07;

// Section 10.3: the peer no longer remembers this connection at all.
inline constexpr int vio_quic_stateless_reset = 0x9c1c08;

// Section 6.2: the peer offered no QUIC version this build speaks.
inline constexpr int vio_quic_version_unsupported = 0x9c1c09;

// The endpoint was released, or shut down, while this was suspended. Every
// awaitable an endpoint owns resolves with this before its storage goes,
// because a coroutine that is never resumed is a leaked frame and, if it holds
// a handle, an event loop that never returns.
inline constexpr int vio_quic_endpoint_closed = 0x9c1c0a;

// A second concurrent waiter on an operation that has exactly one slot.
//
// Nothing in this header raises it. Accepts and dials are per-call operations,
// so a second concurrent one has nothing to overwrite and simply waits its
// turn; the number is declared here because it is published, and because the
// single reader per stream in quic_stream.h is the operation that really does
// have one slot.
//
// Note what this is not. Asking a dial-only endpoint to accept, or an
// answer-only one to dial, is a configuration mistake rather than a race, and
// comes back as error_t{.code = -1} with a full sentence -- which is what
// endpoint_t::connect already answers for the mirror case. Spending the one
// code an application can usefully branch on covering both would make it
// unbranchable.
inline constexpr int vio_quic_busy = 0x9c1c0b;

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

// There is no separate flow-control type, and there deliberately is not one any
// more. connection_config_t::transport_parameters is already initialised to
// default_transport_parameters() -- 8 MiB across the connection, 2 MiB per
// stream -- so an endpoint configured with nothing carries traffic, and a
// second copy of those nine numbers here would be a second source of truth for
// the one thing that must have exactly one.
//
// To change one, assign the field; do not brace-initialise the struct:
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
  //
  // One field of it is written by quic_endpoint_create and whatever is set here
  // is discarded: connection.transport_parameters.max_ack_delay, which is a
  // second spelling of connection.max_ack_delay. Those are two fields of two
  // types with two independent defaults that happen to agree, and nothing
  // enforces that they still do -- so a caller who tuned one of them put a
  // promise on the wire the loss recovery does not keep. Set the nanosecond
  // one; the millisecond one is derived from it.
  vio::quic::endpoint_config_t transport;

  // Connections whose handshake has completed and which nothing has accepted
  // yet. Past this a connection is closed with CONNECTION_REFUSED rather than
  // queued, because a client told no can go elsewhere and one told nothing
  // waits out its handshake timeout.
  //
  // Be clear about what it does not bound. on_connection fires after the
  // handshake, so a refused connection has already cost a TLS session and three
  // key schedules; endpoint_config_t::max_connections is the earlier and
  // cheaper ceiling, and a server reachable from the internet needs that one
  // and a retry_key, not this.
  std::size_t accept_backlog = 128;

  // step 5 adds stream_accept_backlog, stream_refused_error and the write
  // high-water marks here.
};

// What the path is doing. Nothing steers on these; they are what a progress
// bar, a log line and a bandwidth-delay-product calculation are made of.
//
// Latched as of the ending rather than zeroed on a tombstone, which is one
// struct copy per connection and a deliberate departure from the design note:
// a shutdown log line reading "RTT 0" for every connection that has closed is a
// worse answer than the truth.
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
  // step 5 adds open_streams. It is left out rather than shipped reading zero,
  // because connection_t cannot count them and a number nothing measures is
  // worse than a number that is not there.
};

// ... detail:: state structs and the beat go here; see the state_structs field.
// The physical order of the file is: error codes, config, stats, the detail
// block, the handles, the awaitables, the declarations below, and finally the
// inline definitions -- because ref_ptr_t<T> needs T complete and
// std::expected<quic_connection_t, error_t> needs quic_connection_t complete.

// -----------------------------------------------------------------------------
// Handles
// -----------------------------------------------------------------------------
//
// Aggregate structs over ref_ptr_t, member named `handle`, exactly as tcp_t and
// timer_t are. Copying one is a refcount bump.
//
// Both default to a null ref_ptr, so a handle that names nothing is well
// defined rather than an allocation -- and every entry point below tests for
// that before it dereferences, because ref_ptr_t::data() does not.
struct quic_endpoint_t
{
  ref_ptr_t<detail::quic_endpoint_state_t> handle = ref_ptr_t<detail::quic_endpoint_state_t>::null();
};

// It names a connection rather than owning it. The endpoint collects a closed
// connection after its draining period and that schedule must not slip: the
// collection is what withdraws the connection IDs from routing. A handle held
// past that point does not dangle -- it becomes a tombstone, which still
// answers quic_connection_closed, close_reason, alpn, role and stats from its
// own latched copies, and fails everything else.
struct quic_connection_t
{
  ref_ptr_t<detail::quic_connection_state_t> handle = ref_ptr_t<detail::quic_connection_state_t>::null();
};

// -----------------------------------------------------------------------------
// Awaitables
// -----------------------------------------------------------------------------

// Something that has either happened or has not, reported rather than consumed:
// awaitable late, awaitable twice, and awaitable by several coroutines at once.
// A per-connection supervisor watching for the end while another coroutine
// works is the ordinary shape, and a single stored continuation would silently
// drop all but the last of them.
//
// It holds the milestone's own small allocation and nothing else. A milestone
// owns no libuv handle, so holding one keeps nothing open and can never be the
// reason uv_loop_close fails -- which is exactly why the awaitables below hold
// no reference to the endpoint. It also tolerates a null one, so awaiting a
// milestone on a handle that was never valid is well defined.
//
// Neither copyable nor movable: the waiter node's address must be stable from
// construction, and guaranteed copy elision on a prvalue return means no move
// is ever needed.
class quic_milestone_t
{
public:
  explicit quic_milestone_t(ref_ptr_t<detail::quic_milestone_state_t> slot);
  quic_milestone_t(const quic_milestone_t &) = delete;
  quic_milestone_t &operator=(const quic_milestone_t &) = delete;
  quic_milestone_t(quic_milestone_t &&) = delete;
  quic_milestone_t &operator=(quic_milestone_t &&) = delete;
  // Unlinks before the slot is released, which is why it is written out rather
  // than defaulted: a member's destruction order is not the place to keep a
  // rule this load-bearing.
  ~quic_milestone_t();

  [[nodiscard]] bool await_ready() const noexcept;
  bool await_suspend(std::coroutine_handle<> continuation) noexcept;
  std::expected<void, error_t> await_resume() noexcept;

private:
  ref_ptr_t<detail::quic_milestone_state_t> _slot;
  detail::quic_waiter_t _node;
};

// A per-call operation, heap allocated, released by whichever of the awaitable
// and the endpoint lets go of it last -- the two-party protocol udp_send_op_t
// already uses. Both accepting and dialling get this shape, because any number
// of either may be in flight at once and a single slot on the endpoint would
// make the second concurrent caller either fail or hang.
//
// It borrows the endpoint state and never references it. A strong reference
// here would deadlock: a coroutine suspended in co_await quic_endpoint_accept()
// would keep the state alive, so releasing the last quic_endpoint_t would never
// reach zero, so on_destroy would never run, so the accept would never be
// resolved -- and the beat, the reader's poll and the socket would all stay
// open, which is event_loop_t::stop() running the loop until nothing is left
// and never returning. The borrow cannot dangle either, because the endpoint
// nulls it when the operation resolves and when it tears down, and it never
// frees the operation while this awaitable still holds it.
//
// Abandoning one before it resolves is safe and cancels nothing that has
// already been handed to the transport: the destructor nulls the continuation
// first and then drops one hold.
class quic_connection_awaitable_t
{
public:
  explicit quic_connection_awaitable_t(detail::quic_op_t *op);
  quic_connection_awaitable_t(const quic_connection_awaitable_t &) = delete;
  quic_connection_awaitable_t &operator=(const quic_connection_awaitable_t &) = delete;
  quic_connection_awaitable_t(quic_connection_awaitable_t &&other) noexcept;
  quic_connection_awaitable_t &operator=(quic_connection_awaitable_t &&other) noexcept;
  ~quic_connection_awaitable_t();

  [[nodiscard]] bool await_ready() const noexcept;
  bool await_suspend(std::coroutine_handle<> continuation) noexcept;
  std::expected<quic_connection_t, error_t> await_resume() noexcept;

private:
  void reset() noexcept;
  detail::quic_op_t *_op = nullptr;
};

// Both published spellings, one implementation. They were two shapes in the
// design because the accept was a single slot on the endpoint; making it a
// per-call operation deleted the slot and with it the second-waiter rule, the
// re-arm, and the question of what an abandoned accept leaves behind.
using quic_accept_future_t = quic_connection_awaitable_t;
using quic_connect_awaitable_t = quic_connection_awaitable_t;

// -----------------------------------------------------------------------------
// Endpoint
// -----------------------------------------------------------------------------

// No socket is opened here and nothing is started. libuv makes a UDP socket
// lazily and its address family is fixed by whoever touches it first, so an
// endpoint that opened one at construction would be pinned to IPv4 before
// anyone said where it was going -- which is the bug still marked
// doctest::should_fail in test_quic_endpoint.cpp. The socket, the read loop and
// the beat all start at the first bind or dial, each of which carries the
// family it needs.
//
// The role comes from the context, which already knows what it was built for.
[[nodiscard]] inline std::expected<quic_endpoint_t, error_t> quic_endpoint_create(event_loop_t &loop, const vio::quic::tls_context_t &context, const quic_config_t &config = {});

// The peer-to-peer form: one port that both answers and dials. Either may be
// null -- that is how a dial-only or an answer-only endpoint is expressed --
// and both must outlive the endpoint. The presence of server_context is what
// makes quic_endpoint_accept legal and the presence of client_context what
// makes quic_endpoint_connect legal; asking for the other comes back as a -1
// with a sentence rather than an awaitable nothing can resolve.
//
// This is also where the registry earns itself: a peer that both dials and
// answers gets its own dialled connections back through on_connection, and only
// a registry keyed on connection_t* keeps them out of its accept queue.
[[nodiscard]] inline std::expected<quic_endpoint_t, error_t> quic_endpoint_create(event_loop_t &loop, const vio::quic::tls_context_t *server_context, const vio::quic::tls_context_t *client_context,
                                                                                  const quic_config_t &config = {});

// Binds the socket and starts reading it, in that order, because it is the
// sockaddr that says which address family the socket must have.
[[nodiscard]] inline std::expected<void, error_t> quic_endpoint_bind(quic_endpoint_t &endpoint, const sockaddr *address);
[[nodiscard]] inline std::expected<std::uint16_t, error_t> quic_endpoint_local_port(const quic_endpoint_t &endpoint);

// Resolves once for each connection that has completed a handshake, in the
// order they complete. Connections that complete while nothing is waiting
// queue, bounded by quic_config_t::accept_backlog; waiters that arrive while
// the queue is empty are served in the order they asked.
//
// It yields the connection directly rather than needing a separate synchronous
// accept, because QUIC has no listen call and no backlog to arm: a bound
// endpoint is already answering Initials.
//
// An accept on an endpoint that is not reading its socket -- one that has
// neither bound nor dialled -- is refused with a sentence rather than parked
// for ever on a port that does not exist.
[[nodiscard]] inline quic_accept_future_t quic_endpoint_accept(quic_endpoint_t &endpoint, cancellation_t *cancel = nullptr);

// Dials, and resolves when the handshake completes or fails. Connected means
// what it means for ssl_client_connect -- the certificate has verified, an ALPN
// has been agreed and the peer's transport parameters have arrived, so a stream
// opened on the result will have credit -- and not that the first Initial has
// been queued.
//
// Cancelling closes the connection as well as resolving the caller. A dial
// nobody will ever be handed is told so rather than left to spend its handshake
// timeout saying nothing.
[[nodiscard]] inline quic_connect_awaitable_t quic_endpoint_connect(quic_endpoint_t &endpoint, const sockaddr *address, std::string_view server_name, cancellation_t *cancel = nullptr);
[[nodiscard]] inline quic_connect_awaitable_t quic_endpoint_connect(quic_endpoint_t &endpoint, const sockaddr *address, std::string_view server_name, std::span<const std::uint8_t> resumption_ticket,
                                                                    cancellation_t *cancel = nullptr);

// A snapshot of every connection this endpoint currently holds, which is what a
// server needs in order to shut down: the transport can name its connections
// and the callback API could not hand any of them to an application outside a
// callback. The handles are copyable, so holding the vector is safe and the
// connections in it become tombstones if they end before the caller gets to
// them.
[[nodiscard]] inline std::vector<quic_connection_t> quic_endpoint_connections(const quic_endpoint_t &endpoint);
[[nodiscard]] inline std::size_t quic_endpoint_connection_count(const quic_endpoint_t &endpoint);
[[nodiscard]] inline vio::quic::endpoint_stats_t quic_endpoint_stats(const quic_endpoint_t &endpoint);

// Closes every live connection with this code and reason, stops accepting, and
// resolves when each CONNECTION_CLOSE has been built into a datagram -- or when
// close_timeout has passed for the ones that could not be.
//
// That completion needs no polling to observe. begin_close leaves a connection
// `closing` with a frame pending; the poll_send that writes the frame flips it
// to `closed`; and the same flush_entry pass latches draining and fires
// on_connection_gone. So the hook this layer already installs is the signal,
// and "every entry ended" is exactly "every close has been handed to the
// socket".
//
// The close goes out in transport space by default, unlike
// quic_connection_close. A connection that has not reached 1-RTT cannot carry
// an application-space code -- the packet builder rewrites one to
// INTERNAL_ERROR -- so a shutdown that reached a peer mid-handshake would tell
// it something untrue. NO_ERROR survives that conversion untouched, and a
// shutdown is not an application-protocol statement anyway.
//
// It is not the whole teardown and does not pretend to be: it does not close
// the socket. Releasing the last quic_endpoint_t does that, and that must still
// happen while the loop can turn. Awaiting this first is what makes the release
// orderly rather than abrupt -- without it the peers learn the connection ended
// from their own idle timers.
[[nodiscard]] inline quic_milestone_t quic_endpoint_shutdown(quic_endpoint_t &endpoint, std::uint64_t error_code = 0, std::string_view reason = {}, bool application = false,
                                                             std::chrono::milliseconds close_timeout = std::chrono::milliseconds(200));

// The transport underneath, for anything this header does not wrap: key update,
// path validation, qlog, the peer's raw transport parameters. Null once the
// endpoint has been released.
//
// Its three dispatch hooks are spoken for. on_connection, on_activity and
// on_connection_gone are how this layer learns anything, each is a single slot
// assigned wholesale, and installing one silently replaces ours -- after which
// accepts stop arriving, or an ending is never reported, on an endpoint that
// otherwise looks healthy. Everything else on it is fair game. Do not hold what
// this returns across a co_await; ask again.
[[nodiscard]] inline vio::quic::endpoint_t *quic_endpoint_native(quic_endpoint_t &endpoint);

// -----------------------------------------------------------------------------
// Connection
// -----------------------------------------------------------------------------

// Resolves when the handshake completes, and is safe to await late, twice, or
// not at all. After quic_endpoint_connect it has already happened; it is here
// for a connection that arrived by some other route and for the symmetry step 7
// needs, where a 0-RTT client learns the verdict is in.
//
// A connection that ends before its handshake completes reaches this milestone
// too, with the reason it ended -- a supervisor waiting for readiness must not
// wait for ever.
[[nodiscard]] inline quic_milestone_t quic_connection_ready(quic_connection_t &connection);

// Resolves when the connection ends, however it ends, and says why: a
// CONNECTION_CLOSE from either side, an idle timeout, a handshake that ran out
// of time, a stateless reset, a version negotiation that found nothing in
// common. Success means a clean ending -- error code zero from either side
// after the handshake completed. Anything else arrives as the matching
// vio_quic_* code with the peer's reason string in the message.
[[nodiscard]] inline quic_milestone_t quic_connection_closed(quic_connection_t &connection);

// Queues a CONNECTION_CLOSE, which goes out on the next beat. Void rather than
// awaitable because the first reason wins: a connection the peer has already
// closed, or that has already timed out, queues nothing, and an awaitable that
// resolved successfully having sent nothing would be a lie. Await
// quic_connection_closed to know it ended.
//
// `application` defaults to true because a caller reaching for this from an
// application is closing for a reason in its own error space. Note that
// connection_t::close defaults the other way; this is the layer that has an
// application above it.
//
// Calling this is also what lets a clean local close(0) be told apart from an
// idle timeout, which the transport records with the same three fields. A close
// issued through quic_connection_native() instead is reported as an idle
// timeout, and that is the one gap.
inline void quic_connection_close(quic_connection_t &connection, std::uint64_t error_code = 0, std::string_view reason = {}, bool application = true);

// Engaged from the moment the connection ends and for the life of the handle,
// including after the endpoint has collected the connection or been released,
// because both are copied into this handle's own state at the ending rather
// than read back out of a transport object that may be gone. selected_alpn()
// returns a view into transport storage the reap frees, which is why the alpn
// comes back by value -- the same reason ssl_client_alpn_selected does.
[[nodiscard]] inline std::optional<vio::quic::connection_close_t> quic_connection_close_reason(const quic_connection_t &connection);
[[nodiscard]] inline std::string quic_connection_alpn(const quic_connection_t &connection);
[[nodiscard]] inline bool quic_connection_is_open(const quic_connection_t &connection);

// Which end of the handshake this connection ran, latched when this layer first
// saw it. A peer-to-peer application needs it, because on_connection fires for
// dialled connections too and both kinds arrive through the same handle type.
[[nodiscard]] inline vio::quic::tls_role_t quic_connection_role(const quic_connection_t &connection);

[[nodiscard]] inline quic_connection_stats_t quic_connection_stats(const quic_connection_t &connection);

// Null on a tombstone, and valid only for the stretch of code that asked: do not
// hold it across a co_await, because the endpoint may collect between one
// resumption and the next.
[[nodiscard]] inline vio::quic::connection_t *quic_connection_native(quic_connection_t &connection);
} // namespace vio


// =============================================================================
// src/vio/quic/connection.h  --  the one addition outside the new header
// =============================================================================
namespace vio::quic
{
// RFC 9000 section 20.1. Missing from the list here, and the code an endpoint
// owes a client whose handshake completed into a full accept backlog: told no,
// a client can go elsewhere; told nothing, it waits out its handshake timeout.
inline constexpr std::uint64_t transport_error_connection_refused = 0x02;
} // namespace vio::quic
```

## State structs and the beat

```cpp
// =============================================================================
// The detail:: block of src/vio/operation/quic_endpoint.h, in file order.
// =============================================================================
namespace vio
{
namespace detail
{
struct quic_endpoint_state_t;
struct quic_op_t;
struct quic_milestone_state_t;

// A waiter lives inside the awaitable, which lives inside the awaiting
// coroutine's frame. Intrusive rather than a vector of coroutine handles for
// two reasons that are correctness and not economy: a frame destroyed while
// still suspended unlinks its own node here, where a vector entry would dangle
// and be resumed into freed memory; and the drain below resumes one waiter at a
// time re-reading the head, because the first coroutine resumed may destroy the
// second's frame -- a supervisor tearing down a peer that is also waiting.
struct quic_waiter_t
{
  std::coroutine_handle<> continuation;
  quic_waiter_t *prev = nullptr;
  quic_waiter_t *next = nullptr;
  quic_milestone_state_t *slot = nullptr;

  void link(quic_milestone_state_t &into, std::coroutine_handle<> handle);
  void unlink();
};

// Its own small allocation rather than a member of whatever reached it, so that
// the awaitable can hold it outright. A milestone owns no libuv handle, so a
// suspended waiter keeping one alive keeps nothing open -- which is what lets
// this be a strong reference where nothing pointing at the endpoint may be.
struct quic_milestone_state_t
{
  bool reached = false;
  std::expected<void, error_t> result;
  quic_waiter_t *waiters = nullptr;
};

inline void quic_waiter_t::link(quic_milestone_state_t &into, std::coroutine_handle<> handle)
{
  continuation = handle;
  slot = &into;
  prev = nullptr;
  next = into.waiters;
  if (next != nullptr)
  {
    next->prev = this;
  }
  into.waiters = this;
}

inline void quic_waiter_t::unlink()
{
  if (slot == nullptr)
  {
    return;
  }
  if (prev != nullptr)
  {
    prev->next = next;
  }
  else
  {
    slot->waiters = next;
  }
  if (next != nullptr)
  {
    next->prev = prev;
  }
  slot = nullptr;
  prev = nullptr;
  next = nullptr;
}

// The first reason wins, and reaching one never resumes anything: every site
// that reaches a milestone is inside a walk over the transport's connections.
// The beat drains it.
inline void quic_milestone_reach(quic_milestone_state_t &slot, std::expected<void, error_t> result)
{
  if (slot.reached)
  {
    return;
  }
  slot.reached = true;
  slot.result = std::move(result);
}

inline void quic_milestone_drain(quic_milestone_state_t &slot)
{
  if (!slot.reached)
  {
    return;
  }
  while (slot.waiters != nullptr)
  {
    auto *waiter = slot.waiters;
    const auto continuation = waiter->continuation;
    waiter->unlink();
    if (continuation)
    {
      continuation.resume();
    }
  }
}

// One accept or one dial. Two holds: the awaitable's, dropped by its destructor
// after nulling the continuation, and the endpoint's, taken when the operation
// is registered and dropped by whichever of the beat or the teardown resolves
// it. Either party may let go first and neither can free it under the other.
struct quic_op_t
{
  // Borrowed, and nulled the moment this resolves or the endpoint tears down --
  // which is what makes the borrow safe without the strong reference that would
  // deadlock the whole endpoint.
  quic_endpoint_state_t *endpoint = nullptr;
  // Set for a dial, so that a cancellation can close the connection it built
  // rather than leaving it to spend its handshake timeout saying nothing.
  vio::quic::connection_t *dialled = nullptr;
  std::coroutine_handle<> continuation;
  std::expected<quic_connection_t, error_t> result;
  registration_t cancel_registration;
  bool accepting = false;
  bool done = false;
  int holds = 1;

  void release()
  {
    if (--holds == 0)
    {
      delete this;
    }
  }
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
  // draining latch, because that is the last thing the endpoint tells us: the
  // reap a draining period later erases the entry and frees the connection_t
  // with no notification at all, so a pointer kept past the latch is a pointer
  // nothing will ever say to drop -- and the next connection_t may well be
  // allocated at the same address. `endpoint` goes when the endpoint tears
  // down. Never strong in either direction: a connection that kept its endpoint
  // alive would keep the UDP socket open, which is uv_loop_close failing with
  // EBUSY and ~event_loop_t aborting on its assert.
  quic_endpoint_state_t *endpoint = nullptr;
  vio::quic::connection_t *transport = nullptr;

  // Latched at registration, because on_connection fires for dialled
  // connections too and the sort between the accept queue and the dial needs it
  // before anything else about the connection is known.
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

  // Borrowed; the dial that is waiting for this connection, nulled when it
  // resolves.
  quic_op_t *pending_dial = nullptr;

  bool handshake_reached = false;
  // Set by every path in this layer that closes: quic_connection_close, the
  // shutdown, and a cancelled dial. It is the only thing that tells a clean
  // local close(0) apart from an idle timeout, which the transport records with
  // the same error code, the same application flag and the same from_peer.
  bool closed_locally = false;
  bool severed = false;
  bool queued = false; // on the endpoint's pending list
  bool dirty = false;  // on the endpoint's flush list
  // step 5 adds the stream registry here and nothing else moves.
};
} // namespace detail

struct quic_connection_t;  // declared complete just below, before quic_op_t is used

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
  // Declared before driver_stop and driver, so it is destroyed after both: the
  // driver's frame holds an endpoint_impl_t reference and owns the datagram
  // reader, whose uv_poll_t is armed on this socket's descriptor. Teardown does
  // this in order anyway; the declaration order is the second line of defence.
  std::optional<vio::quic::endpoint_t> transport;
  cancellation_t driver_stop;
  std::optional<task_t<void>> driver;
  quic_config_t config;

  // The seam socket_stream.h's read_cb uses (:203, :899, :928), filled from
  // handle.ref_counted() at create.
  reference_counted_t *rc = nullptr;
  uv_prepare_t beat = {};

  bool driver_started = false;
  // Set as the very first act of teardown, before anything is resumed. Every
  // entry point tests this rather than transport.has_value(), because the
  // transport is alive for most of the teardown -- a coroutine resumed to be
  // told the endpoint is going away could otherwise dial and park on an
  // operation nothing will ever resolve.
  bool closing = false;

  // The identity the hooks hand out is a connection_t &, so this is what turns
  // one back into something with awaiters on it. Erased at the draining latch,
  // which always precedes the reap because reap requires entry.draining and
  // flush_entry sets that immediately before firing the hook.
  std::unordered_map<const vio::quic::connection_t *, ref_ptr_t<quic_connection_state_t>> by_connection;
  std::deque<ref_ptr_t<quic_connection_state_t>> accept_queue;

  // Every operation that has not resolved, in the order it was made -- which is
  // also the FIFO an arriving connection is handed down. One list rather than a
  // separate accept queue and dial list, because two lists to keep in step is a
  // way to leave an operation in one of them.
  std::vector<quic_op_t *> live_ops;
  // Resolved, waiting for the beat to resume them.
  std::vector<quic_op_t *> ready_ops;

  // What the beat walks. `pending` drives resumption and `dirty` drives the
  // flush; they are different sets, and conflating them would flush every
  // connection that merely received a packet, which run() has already done.
  std::vector<ref_ptr_t<quic_connection_state_t>> pending;
  std::vector<ref_ptr_t<quic_connection_state_t>> dirty;
  // For a connection this layer refused before it ever had a state: it is not
  // in the registry, so there is nothing to mark, and its CONNECTION_CLOSE
  // needs the all-connections flush to leave.
  bool flush_all = false;

  ref_ptr_t<quic_milestone_state_t> shutdown;
  bool shutdown_active = false;
  std::size_t shutdown_outstanding = 0;
  tick_t shutdown_deadline;
};

// -----------------------------------------------------------------------------
// The beat
// -----------------------------------------------------------------------------
//
// WHY A uv_prepare_t AND NOT A uv_check_t. libuv's iteration, identical in
// shape on both backends (3rdparty/libuv-v1.52.0/src/unix/core.c uv_run and
// src/win/core.c uv_run), is:
//
//   pending -> idle -> PREPARE -> [backend timeout] -> poll (blocks)
//     -> pending x8 -> CHECK -> closing handles -> update time -> TIMERS
//
// Read that with the wake sources on it. An I/O callback runs inside poll on
// unix and from the pending drain immediately after it on Windows, so a
// coroutine made runnable by a datagram is served by CHECK in the same
// iteration and by PREPARE at the top of the next -- and the loop does not
// block anywhere between those two points, so on that path the two are worth
// the same and neither costs a round trip. That is the honest answer to "does
// the beat cost a round trip": it does not, and it would not with check either.
//
// Timers are what decide it, and they run at the END of the iteration, after
// check. The endpoint's own 2 ms ticker fires there, and it is that tick which
// flushes every connection, which is what latches an idle timeout and fires
// on_connection_gone -- so a connection ending with no traffic on it becomes
// runnable in the timer phase and nowhere else. PREPARE is the next callback
// phase after it with nothing blocking in between. CHECK is reached only after
// the next iteration's poll has blocked for uv__backend_timeout, bounded by the
// ticker today and unbounded the day the ticker becomes deadline-driven.
// Prepare is the only hook downstream of every wake source -- pending, idle,
// poll and timers -- and upstream of the block. It is also why deferring every
// resumption in this layer to the beat, cancellations included, costs no wall
// clock: whatever phase latched the work, prepare is reached before the loop
// next sleeps.
//
// A uv_idle_t is disqualified outright: uv__backend_timeout returns 0 while any
// idle handle is active, so an always-started one turns the loop into a spin.
// Neither prepare nor check appears in that function, so an always-started
// prepare cannot do the same -- which is what makes arming it permanently and
// paying one predicate per turn cheaper to reason about than arming it
// conditionally. Step 3's evidence is that making a periodic mechanism in this
// endpoint conditional produced both a spin and a stall.
//
// Four passes drain every realistic case within one beat; anything left waits
// for the next one, which the 2 ms ticker guarantees. The bound is what stops a
// pathological application from starving I/O inside one prepare callback.
constexpr int quic_beat_max_passes = 4;

[[nodiscard]] inline bool quic_beat_has_queued_work(const quic_endpoint_state_t &self)
{
  return !self.ready_ops.empty() || !self.pending.empty() || !self.dirty.empty() || self.flush_all;
}

inline void quic_beat_resume(quic_endpoint_state_t &self)
{
  // Every list is taken out of the state before anything is resumed, so a
  // resumed coroutine may dial, close a connection or drop the last handle to
  // one without invalidating the walk. The connection entries are ref_ptr and
  // not raw pointers, so an entry the draining latch has already erased from
  // the registry is still alive when the beat reaches it.
  auto ops = std::exchange(self.ready_ops, {});
  for (auto *op : ops)
  {
    // The continuation is taken before the hold is dropped, because dropping it
    // may be what deletes the operation -- an awaitable abandoned before its
    // dial resolved leaves exactly one hold, and a null continuation.
    const auto continuation = std::exchange(op->continuation, {});
    op->endpoint = nullptr;
    op->release();
    if (continuation)
    {
      continuation.resume();
    }
  }

  auto pending = std::exchange(self.pending, {});
  for (auto &state : pending)
  {
    state->queued = false;
    quic_milestone_drain(*state->ready);
    quic_milestone_drain(*state->closed);
  }
}

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
    // The per-connection form: the all-connections flush is O(connections) and
    // builds a vector of connection IDs for each step of it.
    (void)self.transport->flush(*state->transport);
  }
}

inline void quic_shutdown_check(quic_endpoint_state_t &self);

inline void quic_beat_cb(uv_prepare_t *handle)
{
  // data is a borrowed pointer, and there is no null check on purpose: libuv
  // fires no callback for a handle after uv_close, which is the guarantee
  // timer_impl.h relies on for the same field -- and after uv_close the ref
  // count has overwritten data with itself, so a null test would not even be
  // the right test.
  auto *self = static_cast<quic_endpoint_state_t *>(handle->data);
  if (!quic_beat_has_queued_work(*self) && !self->shutdown_active)
  {
    return;
  }
  // Held for the whole body, the discipline socket_stream.h's read_cb uses.
  // Note what it does and does not buy here: because the beat is registered
  // with the ref count, a release reaching zero inside this function would take
  // the uv_close branch and free nothing until the close callback, so this is
  // not a use-after-free guard. What it buys is that the destroy sequence --
  // which resolves awaiters, deletes operations, stops the driver and destroys
  // endpoint_impl_t -- runs after this walk rather than in the middle of it.
  reference_counted_t *rc = self->rc;
  rc->inc();
  int pass = 0;
  do
  {
    quic_beat_resume(*self);
    quic_beat_flush(*self);
  } while (++pass < quic_beat_max_passes && quic_beat_has_queued_work(*self));
  // Once per beat, not once per pass: shutdown_active describes a state rather
  // than remaining work, so putting it in the pass predicate would burn all
  // four passes on every turn while a shutdown is outstanding.
  quic_shutdown_check(*self);
  rc->dec(); // final -- may destroy the state; nothing after this line
}

// -----------------------------------------------------------------------------
// Recording, from inside the transport's walk. None of this resumes anything.
// -----------------------------------------------------------------------------

inline void quic_mark_pending(quic_endpoint_state_t &self, const ref_ptr_t<quic_connection_state_t> &state)
{
  if (state->queued)
  {
    return;
  }
  state->queued = true;
  self.pending.push_back(state);
}

inline void quic_mark_dirty(quic_endpoint_state_t &self, const ref_ptr_t<quic_connection_state_t> &state)
{
  if (state->dirty)
  {
    return;
  }
  state->dirty = true;
  self.dirty.push_back(state);
}

inline quic_connection_stats_t quic_read_stats(const vio::quic::connection_t &connection)
{
  const auto path = connection.path_stats();
  quic_connection_stats_t out;
  out.smoothed_rtt = path.smoothed_rtt;
  out.rtt_variation = path.rtt_variation;
  out.min_rtt = path.min_rtt;
  out.congestion_window = path.congestion_window;
  out.slow_start_threshold = path.slow_start_threshold;
  out.bytes_in_flight = path.bytes_in_flight;
  out.datagram_size = connection.datagram_size();
  out.delivery_rate = connection.delivery_rate();
  out.peak_delivery_rate = connection.peak_delivery_rate();
  out.migrations = connection.migration_count();
  // congestion_control_t::in_slow_start() is exactly this comparison, and both
  // of its terms are already on path_stats, so nothing has to be forwarded.
  out.in_slow_start = path.congestion_window < path.slow_start_threshold;
  return out;
}

// Which of the five endings this was, and the difference between them.
//
// The order is load-bearing. A stateless reset and a failed version negotiation
// both record a close_reason whose error code is zero and whose from_peer is
// true, so reading the code first would report either as a clean ending; and
// the handshake deadline and the idle timeout record the same zero code with
// from_peer false, so each ending that has its own predicate has to be
// recognised by it before anything is read off the code at all.
[[nodiscard]] inline std::expected<void, error_t> quic_classify_ending(const vio::quic::connection_t &connection, bool handshake_reached, bool closed_locally)
{
  if (connection.reset_by_peer())
  {
    return std::unexpected(error_t{.code = vio_quic_stateless_reset, .msg = "the peer no longer remembers this connection"});
  }
  if (connection.version_negotiation_failed())
  {
    return std::unexpected(error_t{.code = vio_quic_version_unsupported, .msg = "the peer offered no QUIC version this build speaks"});
  }
  const auto reason = connection.close_reason();
  if (!handshake_reached)
  {
    // A certificate that did not verify, no ALPN in common, a TLS alert, or the
    // handshake deadline. begin_close already recorded the alert's code and
    // text, so the detail survives in close_reason().
    return std::unexpected(error_t{.code = vio_quic_handshake_failed, .msg = reason.has_value() ? reason->reason : std::string("the handshake did not complete")});
  }
  if (!reason.has_value())
  {
    return std::unexpected(error_t{.code = vio_quic_connection_closed, .msg = "the connection ended"});
  }
  if (reason->error_code != 0)
  {
    return std::unexpected(error_t{.code = vio_quic_connection_closed, .msg = reason->reason});
  }
  // A zero code that nobody claimed. This layer records when it asked, because
  // a local close(0) and an idle timeout are otherwise the same three fields.
  if (!reason->from_peer && !closed_locally)
  {
    return std::unexpected(error_t{.code = vio_quic_idle_timeout, .msg = reason->reason});
  }
  return {};
}

// Everything read off a connection_t that has to survive it. Called from the
// draining latch and from teardown, and from nowhere else, because those are
// the only two moments this layer is told anything.
inline void quic_sever(quic_endpoint_state_t &self, const ref_ptr_t<quic_connection_state_t> &state, std::expected<void, error_t> fallback)
{
  if (state->severed)
  {
    return;
  }
  state->severed = true;
  auto ending = std::move(fallback);
  if (state->transport != nullptr)
  {
    auto &connection = *state->transport;
    state->close_reason = connection.close_reason();
    if (state->alpn.empty())
    {
      state->alpn.assign(connection.selected_alpn());
    }
    state->stats = quic_read_stats(connection);
    ending = quic_classify_ending(connection, state->handshake_reached, state->closed_locally);
  }
  quic_milestone_reach(*state->closed, ending);
  // A connection that ended before its handshake completed never becomes ready;
  // a supervisor awaiting readiness must not wait for ever.
  quic_milestone_reach(*state->ready, ending);
  if (auto *op = std::exchange(state->pending_dial, nullptr); op != nullptr)
  {
    quic_op_finish(self, op, std::unexpected(ending.has_value() ? error_t{.code = vio_quic_connection_closed, .msg = "the connection ended"} : ending.error()));
  }
  state->transport = nullptr;
  quic_mark_pending(self, state);
}
} // namespace detail
} // namespace vio
```

## What the user writes

```cpp
// =============================================================================
// A client at step 4: dial, look at what was negotiated, close politely, and
// let the loop return. No streams -- that is step 5.
// =============================================================================
#include "quic_common.h" // make_self_signed, and the Windows include order

#include <vio/operation/quic_endpoint.h>
#include <vio/run.h>

#include <optional>
#include <print>

namespace
{
vio::task_t<void> client(vio::event_loop_t &loop, const sockaddr *server, vio::quic::tls_context_t &context)
{
  // Nothing is configured. connection_config_t::transport_parameters is already
  // default_transport_parameters(), so this connection has 8 MiB of credit
  // across it and 2 MiB per stream without anyone saying so.
  auto endpoint = vio::quic_endpoint_create(loop, context);
  if (!endpoint)
  {
    std::println("could not create the endpoint: {}", endpoint.error().msg);
    loop.stop();
    co_return;
  }

  // The socket is opened here, with the family of the address being dialled,
  // and the read loop is armed before this call returns.
  auto connection = co_await vio::quic_endpoint_connect(*endpoint, server, "localhost");
  if (!connection)
  {
    // vio_quic_handshake_failed for a certificate that did not verify or an
    // ALPN with nothing in common; vio_quic_version_unsupported if the peer
    // speaks no version this build does.
    std::println("dial failed ({:#x}): {}", connection.error().code, connection.error().msg);
    loop.stop();
    co_return;
  }
  std::println("connected, alpn {}, rtt {}ms", vio::quic_connection_alpn(*connection), vio::quic_connection_stats(*connection).smoothed_rtt.count() / 1000000);

  vio::quic_connection_close(*connection, 0, "done");
  const auto ending = co_await vio::quic_connection_closed(*connection);
  std::println("closed: {}", ending ? "cleanly" : ending.error().msg);

  // No cancel, no sleeps, no reset dance. The endpoint's last reference goes
  // out of scope here, which cancels the read loop, destroys its frame, closes
  // the socket and closes the beat -- all while the loop can still turn, which
  // is the one rule.
}
} // namespace

int main()
{
  vio::event_loop_t loop;
  auto context = make_client_context();
  sockaddr_in server = {};
  uv_ip4_addr("127.0.0.1", 4433, &server);

  std::optional<vio::task_t<void>> task;
  loop.run_in_loop([&] { task.emplace(client(loop, reinterpret_cast<const sockaddr *>(&server), *context)); });
  loop.run();
  return 0;
}


// =============================================================================
// A server at step 4: accept in a loop, report each connection's ending, and
// shut down politely on a signal.
// =============================================================================
namespace
{
// State as parameters, never captures: task_t is eager, so a [&] lambda
// coroutine reads a destroyed closure at its first suspension.
vio::task_t<void> watch(vio::quic_connection_t connection)
{
  std::println("accepted {}, alpn {}", vio::quic_connection_role(connection) == vio::quic::tls_role_t::server ? "an inbound connection" : "our own dial", vio::quic_connection_alpn(connection));
  const auto ending = co_await vio::quic_connection_closed(connection);
  if (ending)
  {
    std::println("ended cleanly");
    co_return;
  }
  // The five endings, told apart. The handle still answers after the endpoint
  // has collected the connection, because both of these were copied into it at
  // the ending rather than read back out of the transport.
  const auto reason = vio::quic_connection_close_reason(connection);
  std::println("ended {:#x}: {} (from the peer: {})", ending.error().code, ending.error().msg, reason && reason->from_peer);
}

vio::task_t<void> server(vio::event_loop_t &loop, vio::quic::tls_context_t &context, vio::cancellation_t &stop)
{
  auto endpoint = vio::quic_endpoint_create(loop, context);
  if (!endpoint)
  {
    loop.stop();
    co_return;
  }
  sockaddr_in6 any = {};
  uv_ip6_addr("::", 4433, &any);
  // Bound before the driver starts, so the socket is v6 and a v4-mapped or v6
  // peer can both reach it. An endpoint that started reading first would have
  // been pinned to AF_INET before anyone said where it was listening.
  if (auto bound = vio::quic_endpoint_bind(*endpoint, reinterpret_cast<const sockaddr *>(&any)); !bound)
  {
    std::println("bind failed: {}", bound.error().msg);
    loop.stop();
    co_return;
  }
  std::println("listening on {}", *vio::quic_endpoint_local_port(*endpoint));

  std::vector<vio::task_t<void>> watchers;
  for (;;)
  {
    auto connection = co_await vio::quic_endpoint_accept(*endpoint, &stop);
    if (!connection)
    {
      break; // cancelled, or the endpoint is shutting down
    }
    // done() is what lets a long-lived accept loop prune its children.
    std::erase_if(watchers, [](const vio::task_t<void> &child) { return child.done(); });
    watchers.push_back(watch(std::move(*connection)));
  }

  // Every peer is told, rather than being left to work it out from its own idle
  // timer. This resolves when each CONNECTION_CLOSE has been handed to the
  // socket, or after 200 ms for any that could not be built.
  (void)co_await vio::quic_endpoint_shutdown(*endpoint, 0, "going away");
  watchers.clear();
  loop.stop();
}
} // namespace
```

## Tests

A new `test/test_quic_coroutine.cpp`, added to `test/CMakeLists.txt` beside `test_quic_endpoint.cpp`. Every case uses the repo's coroutine test pattern — `run_in_loop` storing a `task_t` in a `std::optional`, inner coroutines taking state as parameters — and every one of them runs under a watchdog coroutine that sets a `timed_out` flag and stops the loop after five seconds, so a failure is a failed CHECK and not a hung process. That matters here more than usual: three of the mechanisms below fail by never resuming a coroutine, and a test whose failure mode is a hang is not a failing test.

**1. A client and a server complete a handshake with no polling anywhere.** One loop, a server bound to `127.0.0.1:0` with a coroutine in `co_await quic_endpoint_accept`, a client in `co_await quic_endpoint_connect`. CHECK both resolve with a value; CHECK `quic_connection_alpn` is non-empty on both sides; CHECK `quic_connection_role` is `server` on the accepted one and `client` on the dialled one; CHECK `!timed_out`. Then both endpoints are released and `event_loop.run()` returns.
*Reverted:* delete the `uv_prepare_start` line. Both operations are latched (`op->done == true`, the milestone `reached`) and no continuation is ever resumed, so neither coroutine runs past its `co_await`, `handshaken` stays false, and the watchdog fires. The observable is `CHECK(!timed_out)` failing. This is the build order's first named test and it is the one that proves the beat exists.

**2. Two coroutines await one connection's ending and both are resumed.** After a handshake, two child coroutines each `co_await quic_connection_closed(connection)` on the same handle, each setting its own bool. The peer closes. CHECK `first_woke && second_woke`, and CHECK both saw the same `error_t::code`.
*Reverted:* replace the intrusive waiter list with a single `std::coroutine_handle<> continuation` — the shape every other future in vio uses. The second `await_suspend` overwrites the first, exactly one bool is set, and the first coroutine's frame is still suspended when the loop is asked to stop. The design doc says this one should be written before anything depends on it, and it is the only test that would catch a milestone that reaches but never drains.

**3. An awaitable abandoned while suspended is not resumed into freed memory.** Run under ASan. A `task_t` awaits `quic_connection_closed` on a connection that has not ended; a second coroutine destroys that `task_t` while it is suspended; then the peer closes. CHECK the loop runs to completion and CHECK a second, still-live waiter on the same milestone was resumed.
*Reverted:* replace the intrusive node's self-unlinking destructor with a no-op (or hold the waiters in a vector of handles). The drain resumes a `coroutine_handle` into a destroyed frame; ASan reports a heap-use-after-free inside `quic_milestone_drain`. Repeat the same shape for an abandoned accept and an abandoned dial, which exercise `quic_connection_awaitable_t::reset()` instead — revert the `_op->continuation = {}` line in it and the beat resumes a freed frame.

**4. An endpoint released while a dial is outstanding resolves the dial and the loop closes cleanly.** A client dials a UDP port that is bound but never answers; a second coroutine sleeps 20 ms and then releases the last `quic_endpoint_t`. CHECK the dial resolved with `error().code == vio_quic_endpoint_closed`; CHECK a flag set after `event_loop.run()` returns is true; CHECK `!timed_out`. Under ASan there is no leak report for the `quic_op_t`.
*Reverted, two ways, and the two failures are different, which is the point.* (a) Remove step 3 of teardown: the dialling coroutine is never resumed, its frame leaks (ASan reports the op too) and the watchdog fires. (b) Change `quic_connection_awaitable_t` to hold `ref_ptr_t<detail::quic_endpoint_state_t>` as the design doc has it: the release is not the last one, `dec()` never reaches zero, `on_destroy` never runs, the socket's `uv_close` is never issued, and `event_loop.run()` keeps going past the watchdog — and when the watchdog stops it anyway, `~event_loop_t` prints "udp handle still open" and aborts on its assert. This is the build order's third named test and the falsification of the design doc's own header sketch.

**5. A plain teardown leaves no handle open.** Bind, accept, handshake, both sides close, `co_await quic_endpoint_shutdown` on the server, both endpoints released, `loop.stop()`, `run()` returns. CHECK `uv_loop_close(loop.loop()) == 0` after `run()` (or, since `~event_loop_t` owns that, CHECK the process reaches the end of the test with no assert). This is the two-close-callbacks-deep chain the design reasons about — beat close → `destroyer()` → `~endpoint_t` → `~udp_t` → udp close — and the failure CLAUDE.md says must not be reintroduced.
*Reverted:* swap teardown steps 4 and 6, so `transport.reset()` runs before `driver_stop.cancel()`. `endpoint_impl_t` and its `udp_t` are destroyed while `run()` is still suspended on a `uv_poll_t` armed on that descriptor; the cancel then resumes a coroutine holding a destroyed `endpoint_impl_t &`. Under ASan that is a heap-use-after-free in `run()`; without it, the poll's close callback fires on a socket that has already been closed.

**6. A dial to a certificate that does not verify reports `vio_quic_handshake_failed`.** A client whose CA did not sign the server's certificate dials it. CHECK `error().code == vio_quic_handshake_failed` and CHECK `error().msg` is non-empty (the alert's text from `close_reason()->reason`).
*Reverted:* remove the `!handshake_reached` arm from `quic_classify_ending`. A TLS alert is a non-zero error code, so the ending is read off the code and reported as `vio_quic_connection_closed`; the observable is the exact `int`. It also proves the dial is matched by the gone hook, since `on_connection` never fires for a handshake that failed — delete `quic_sever`'s `pending_dial` resolution and the awaitable never resolves at all and the watchdog fires.

**7. An idle timeout is told apart from a clean close.** Two connections on one loop with `max_idle_timeout` set to one second: one closed with `quic_connection_close(c, 0, "", false)` — **transport space, so it records byte for byte what the idle path records** — and one left to expire. CHECK the first resolves `quic_connection_closed` with a value and the second with `error().code == vio_quic_idle_timeout`.
*Reverted:* drop the `closed_locally` latch from `quic_connection_close`. The clean close is reported as an idle timeout; the first CHECK's `expected<void>` becomes an unexpected carrying `0x9c1c06`. The `application = false` in the test is load-bearing — with the default `true` an implementation that discriminated on `reason->application` would also pass, and would be wrong.

**8. An accept with a connection already queued does not suspend.** Two clients connect before the server's accept loop starts. CHECK `quic_endpoint_accept(endpoint).await_ready()` is true on a factory result while the queue is non-empty, then `co_await` it and CHECK the connection came back and that the second accept in the same resumption also returns without a loop turn.
*Reverted:* remove the `quic_accept_pump` call from the factory and leave every accept to the beat. `await_ready()` reads false. The behavioural cost is one loop turn per accepted connection, which is invisible in a pass/fail sense, so the mechanism is asserted directly — this is the step-4 form of the design's "step 3 must not need step 2 to have run".

**9. An endpoint bound to `::` reaches an IPv6 peer.** Server: `quic_endpoint_bind` to `[::1]:0`, then accept. Client: `quic_endpoint_connect` to `::1` at that port. CHECK the handshake completes on both sides. Skipped where the host has no IPv6 loopback, as the existing case does.
*Reverted:* move `quic_start_driver` from bind and connect into `quic_endpoint_create`. `endpoint_t::run()`'s `ensure_socket(impl)` pins the socket to `AF_INET` before the bind is seen, the dial to `::1` never arrives and the accept never resolves. This is the same defect that is still `doctest::should_fail` at test_quic_endpoint.cpp:1790 for the raw transport, and this test is what stops someone from moving the call back for tidiness.

**10. A coroutine resumed by the beat may drop the last endpoint handle, and teardown does not run under the beat.** A coroutine suspended on `quic_connection_closed` is resumed by the beat and, in its resumption, releases the last `quic_endpoint_t` and then immediately reads `quic_connection_native(connection)` off the handle it still holds. CHECK it is **not** null at that instant, CHECK `quic_connection_close_reason` and `quic_connection_alpn` still answer, and CHECK the loop closes cleanly afterwards.
*Reverted:* remove the `rc->inc()` / `rc->dec()` bracket around the beat's body. The release reaches zero inside the beat, the destroy sequence runs immediately, `quic_sever` nulls the state's `transport`, and `quic_connection_native` reads null at that instant — the CHECK flips. This is the honest observable for the bracket: because the beat is registered with `register_handle`, a zero inside it takes the `uv_close` branch and frees nothing, so there is no crash to catch; what the bracket buys is that teardown runs after the walk rather than in the middle of it, and that is what the test asserts. The second half — reverting the latching of `alpn` and `close_reason` at the ending — makes the tombstone reads report an empty string and `nullopt`.

**11. A coroutine resumed by the beat may dial a second peer.** Under ASan. The accept-resumed coroutine immediately dials a third endpoint; both connections complete and both appear in `quic_endpoint_connections`.
*Reverted:* replace `auto ops = std::exchange(self.ready_ops, {})` with a range-for over `self.ready_ops` (and the same for `pending`). The dial's `push_back` reallocates the vector the beat is iterating and the walk reads freed storage; ASan reports a heap-use-after-free in `quic_beat_resume`. Note what this does *not* test, and what the design must stop claiming: the transport's own `connections` vector holds `unique_ptr`, so a `push_back` there moves nothing and `touched` is safe — the hazard is in the beat's own containers, not the transport's.

**12. A full accept backlog refuses with CONNECTION_REFUSED rather than dropping the client.** Server with `accept_backlog = 1` and no accept loop. Two clients dial. CHECK the second client's `quic_connection_closed` resolves within a bounded wait with `close_reason()->error_code == 0x02` and `from_peer == true`.
*Reverted:* remove the backlog test from `quic_hook_connection`. The second connection queues instead, nothing tells the client anything, and its milestone does not resolve inside the bound — it waits out the negotiated idle timeout.

**13. Shutdown reaches the peer well inside its idle timeout.** Server and client with a 30 s idle timeout. The server awaits `quic_endpoint_shutdown(0, "going away")`. CHECK the client's `quic_connection_closed` resolves within 500 ms with `close_reason()->from_peer == true` and `reason == "going away"`, and CHECK the server's own milestone resolved.
*Reverted:* remove the per-connection close from `quic_endpoint_shutdown` and leave only the milestone. Nothing queues a CONNECTION_CLOSE, the client learns of the ending from its own idle timer, and the 500 ms bound fails.

**14. Alpn and close reason survive the reap.** Hold a `quic_connection_t` after the peer closes and past `draining_period` (3 s) plus a margin, so the endpoint has reaped the transport connection. CHECK `quic_connection_alpn()` still returns the negotiated protocol, `quic_connection_close_reason()` is still engaged, `quic_connection_stats().smoothed_rtt` is non-zero, `quic_connection_native()` is null, and `quic_connection_is_open()` is false.
*Reverted:* forward to the live `connection_t` instead of latching. After the reap the pointer names freed storage: ASan reports a use-after-free on the alpn read, and unsanitised it is an empty string and a `nullopt`. Reverting only the stats latch makes `smoothed_rtt` read zero, which is the deliberate departure from the doc's "zeroed on a tombstone".

**WHAT HAS NO FALSIFYING TEST AT STEP 4, said plainly rather than faked.** The beat's *flush* pass. The transport's 2 ms ticker flushes every connection unconditionally (quic_endpoint.cpp:978-998), so anything a beat-resumed coroutine writes leaves within 2 ms whether or not the beat flushes it — every candidate test passes with the flush pass deleted, differing only in latency that no in-process assertion can see reliably. It is built now because the beat's shape is fixed here and adding it later means rewriting the beat, and its regression test is step 6's: a write fed in pieces from the beat, where a missing flush is a stall and not a delay.

## Build order and open questions

```
BUILD ORDER:
1. 1. `transport_error_connection_refused = 0x02` into `vio/quic/connection.h`'s section-20.1 block, alone. It compiles and changes nothing; the accept-backlog refusal needs it and using a literal instead would defeat the point of the block.
2. 2. The file skeleton: `src/vio/operation/quic_endpoint.h` with the error codes, `quic_config_t`, `quic_connection_stats_t`, `quic_read_stats`, `quic_classify_ending`, and the three `detail::` state structs with no functions on them. Nothing includes it yet. Compile it into `test_quic_coroutine.cpp` as a bare `#include` plus a `TEST_CASE` that default-constructs both handles and checks they are null, which is what proves the declaration order works — `ref_ptr_t<T>` needs `T` complete and `std::expected<quic_connection_t, error_t>` needs `quic_connection_t` complete, so the file's physical order is not free.
3. 3. The milestone: `quic_waiter_t`, `quic_milestone_state_t`, `link`/`unlink`/`reach`/`drain`, and `quic_milestone_t`. Test it with no endpoint under it at all — reach a slot, drain it, drain it twice, attach two waiters and drain, attach a waiter and destroy its awaitable first. That is test 2 and test 3's milestone half, and the design doc is right that it should exist before anything depends on it.
4. 4. The operation: `quic_op_t`, `quic_op_finish`, `quic_op_register`, and `quic_connection_awaitable_t` with its two-hold protocol. Also testable with no endpoint: resolve before the awaitable is awaited, abandon before resolving, abandon after resolving, resolve twice.
5. 5. `quic_endpoint_create` (both overloads), the beat's registration and `uv_unref`, the three recording hooks installed but doing nothing except the registry insert, and `teardown`. Test: create an endpoint, never bind it, `loop.stop()`, and `run()` returns — which is the case the `uv_unref` exists for and the only one where a ref'd beat would be the sole active handle. Then create and release one, and check no handle is left open.
6. 6. `quic_endpoint_bind`, `quic_endpoint_local_port`, `quic_start_driver`. Test 9 (the IPv6 bind) and a bind failure that reports rather than half-starting the driver.
7. 7. `quic_endpoint_connect` with the registry insert, `quic_hook_connection`'s dial branch, `quic_hook_gone`, `quic_sever`, and the beat's resume pass. Test 6 (the failed dial) and test 4 (released mid-dial) land here, and this is the first point at which any of it works end to end.
8. 8. `quic_endpoint_accept`, the accept queue, `quic_accept_pump`, the inbound and refuse branches of `quic_hook_connection`, and the role sort. Tests 1, 8, 11 and 12. Test 1 is the build order's headline and only becomes possible now.
9. 9. `quic_connection_close`, `quic_connection_closed`/`ready`, `close_reason`, `alpn`, `role`, `is_open`, `stats`, `native`, `quic_endpoint_connections`/`connection_count`/`stats`, and the beat's flush pass. Tests 2, 7, 10 and 14.
10. 10. `quic_endpoint_shutdown` and `quic_shutdown_check`. Tests 5 and 13.
11. 11. Cancellation on both operations, and the cancelled dial's close. Its own three cases: pre-cancelled never touches the transport; cancelled while suspended resolves with `vio_cancelled` and the peer sees a CONNECTION_CLOSE; a cancelled accept leaves the queue intact for the next accept.
12. 12. Run the whole file under `cmake --preset asan` and under `msvc-asan`, because tests 3, 4, 5, 11 and 14 are memory-safety assertions and pass vacuously without a sanitiser. Then run the existing `test_quic_endpoint.cpp` unchanged — nothing in this step touches the transport except one constant, so a regression there means the constant was not the only change.

OPEN QUESTIONS:
- Whether `quic_endpoint_shutdown` should also stop the driver. It does not: resolving the milestone leaves the endpoint reading a socket with no connections on it, which is right for one that will dial again and pointless for one about to be dropped. Keeping it tied to the release means the beat, the reader's poll and the socket stay armed between the shutdown resolving and the handle going out of scope. Settle it when there is a program that shuts down and then keeps going.
- The port-only bind, `quic_endpoint_bind(endpoint, std::uint16_t)`, is left out. It needs `endpoint_t::bind(std::uint16_t)` forwarding to `udp_bind_dual_stack` (udp.h:632), because the `udp_t` is private to `endpoint_impl_t` — six lines of transport addition that step 4's stated scope does not cover. Without it a caller who just wants a port has to pick a family, and picking IPv4 is how an endpoint ends up unable to reach an IPv6 peer. Worth doing in step 5 rather than never.
- `quic_connection_resumption_ticket` and `quic_connection_new_token` are not here. Both are `std::vector<std::uint8_t>` copies that would have to be latched at the ending to survive the reap, and nothing in step 4 or 5 spends one — step 7 is where 0-RTT lands and where the latching cost is justified.
- `quic_connection_stats_t::open_streams` is absent rather than present-and-zero. `connection_t` has no stream-count accessor; step 5 adds the field along with the registry that can answer it, which is source-compatible.
- The `closed_locally` gap: a close issued through `quic_connection_native()->close(0, …)` is reported as `vio_quic_idle_timeout`. Fixing it properly means a `connection_end_t how` on `connection_close_t`, set at the five sites in quic_connection.cpp that build one. That is the right fix and it is a step-2-shaped change to a public struct; whether it is worth making late is a call for whoever owns the transport, and if it is made, `quic_classify_ending` collapses to a switch and `closed_locally` goes away.
- Whether the beat should flush per connection or all connections once anything was resumed. It flushes per connection, using `flush(connection_t&)` that step 3 added for the purpose, plus one `flush_all` flag for a refused connection that never got a state. At step 4 the difference is unmeasurable because the ticker flushes everything every 2 ms anyway; at step 5 the per-connection form is the only one that scales, which is why it is written now.
- Ordering on a peer-to-peer endpoint whose first operation is a dial and which later wants a bind. `connect` calls `ensure_socket` with the dial's family and then starts the driver, after which a bind fails because the socket already has a descriptor. The transport has the same restriction today; the coroutine layer makes it less visible, and the header does not yet say so. It needs a sentence, or `quic_endpoint_bind` needs to fail with a better message than libuv's `EINVAL`.
- `quic_beat_max_passes = 4` is a judgement and not a measurement. Too low and work spills to the next turn, bounded at 2 ms by the ticker; too high and a pathological application can starve I/O inside one prepare callback. Step 6's piecewise write feeding is what will exercise it properly.
- The whole layer's ending detection rides on the 2 ms ticker walking every connection (quic_endpoint.cpp:978-998), because `on_connection_gone` only fires from `flush_entry`. If that ticker is ever replaced by the deadline-driven `timer_t` that was tried and reverted in step 3, a connection that closes with no traffic on it is never flushed, the gone hook never fires, and `quic_connection_closed` hangs — and the beat, which today relies on the ticker to guarantee it runs, needs its own kick. That coupling has to be written as a comment at the ticker's site in quic_endpoint.cpp as part of this step, or the next person to attempt that change breaks the coroutine API silently.
- Whether an unaccepted connection sitting in `accept_queue` at teardown should be sent a CONNECTION_CLOSE rather than being dropped when the socket goes. Teardown is the abrupt path and `quic_endpoint_shutdown` is the polite one, so dropping is defensible — but a peer that completed a handshake and is then met with silence waits out its idle timeout, which is exactly the argument that made the backlog refusal a close rather than a drop.
```
