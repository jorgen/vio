# VIO Project

C++ async I/O library with its own event loop over epoll, io_uring, kqueue and IOCP, C++20
coroutines, and BoringSSL for TLS. libuv was removed in October 2026; `EVENT_LOOP_PLAN.md` is the
design and `DECISIONS.md` records every choice made on the way, with its reason.

## Build

```bash
# Configure (debug)
cmake --preset debug

# Build
cmake --build cmake-build-debug

# Run tests
./cmake-build-debug/test/vio_tests

# Run them on io_uring instead of epoll (Linux)
VIO_BACKEND=io_uring ./cmake-build-debug/test/vio_tests
```

Tests for internals live at the bottom of their `src/*.cpp` file inside
`#if defined(VIO_INTERNAL_TESTS)`. A top-level static build with tests compiles the library sources
a second time, with that macro and the doctest implementation, into the `vio_internal_tests`
object library, which only `vio_tests` links. `libvio` itself, which is what gets installed and
what the examples and benchmarks link, never carries doctest or a test registration.

`cmake --build <dir> --target vio_header_check` compiles every public header on its own with
`-fno-exceptions -fno-rtti` (GCC and Clang). A `try` in a header breaks that build for every
downstream that turns exceptions off, so headers spell it `VIO_TRY` / `VIO_CATCH_ALL` from
`vio/detail/exceptions.h`.

### Windows
#### On Windows with MSVC (CLion/Claude Code)

When building from the command line with MSVC toolchain:

```bash
# First, set up the Visual Studio environment
"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"

# Configure with Ninja generator
cmake -B build -S . -G Ninja

# Build
cmake --build build

# Run tests
ctest --test-dir build
# OR
./build/test/vio_tests.exe

```
## Sanitizer Builds

```bash
# AddressSanitizer
cmake --preset asan
cmake --build cmake-build-asan
./cmake-build-asan/test/vio_tests

# ThreadSanitizer
cmake --preset tsan
cmake --build cmake-build-tsan
./cmake-build-tsan/test/vio_tests

# UndefinedBehaviorSanitizer
cmake --preset ubsan
cmake --build cmake-build-ubsan
./cmake-build-ubsan/test/vio_tests
```

### Windows (MSVC AddressSanitizer)

Requires a Visual Studio developer command prompt (vcvars64.bat):

```bash
cmake --preset msvc-asan
cmake --build --preset msvc-asan
ctest --preset msvc-asan
```

Note: MSVC ASan does not include LeakSanitizer. TSan and UBSan are not available on MSVC.

## Docker (Sanitizer Builds)

A Docker image (`ghcr.io/jorgen/vio-ci:latest`) provides a consistent environment for sanitizer
builds. CI uses this image automatically. For local use:

```bash
# Build the image
docker build -t vio-ci .

# Run a sanitizer build inside the container
docker run --rm -v $(pwd):/workspace -w /workspace vio-ci bash -c \
  "cmake -G Ninja -B build -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_COMPILER=gcc-14 -DCMAKE_CXX_COMPILER=g++-14 \
    -DCMAKE_C_FLAGS='-fsanitize=address -fno-omit-frame-pointer' \
    -DCMAKE_CXX_FLAGS='-fsanitize=address -fno-omit-frame-pointer' \
    -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address' && \
  cmake --build build && \
  ./build/test/vio_tests"
```

## Clang-Tidy

The project uses CLion's bundled clang-tidy. Run it via `run-clang-tidy` with the CLion binary:

```bash
/opt/homebrew/opt/llvm/bin/run-clang-tidy \
  -clang-tidy-binary /Applications/CLion.app/Contents/bin/clang/mac/aarch64/bin/clang-tidy \
  -p cmake-build-debug \
  -j$(sysctl -n hw.ncpu) \
  'src/' 'test/'
```

Configuration is in `.clang-tidy` at the project root.

## Project Structure

- `src/vio/` - Library headers and source (most code is in headers)
- `src/vio/loop/`, `src/loop_core.cpp`, `src/backend_*.cpp` - the event loop core and its backends
  (epoll, io_uring, kqueue, IOCP); `src/blocking_pool.cpp`; `src/sys_posix.cpp`, `src/sys_win.cpp`
- `src/vio/operation/` - Async operation implementations (tcp, tls, dns, file, sleep, udp, timer)
- `src/vio/quic/` - QUIC wire primitives, sans-I/O and dependency-free: `varint.h`,
  `packet_number.h`, `connection_id.h`, `frame.h` (the RFC 9000 section 12.4 frame
  table plus the per-frame loss policy), `frame_codec.h` (section 19 encode/decode),
  `packet.h` (section 17 headers; stops at the packet number, since the rest is
  header-protected, and reports the offsets protection needs), `protection.h`
  (RFC 9001: the key schedule, the AEAD, and header protection, over
  `crypto_aead`). `test/quic_rfc9001_vectors.h` is generated from the raw text
  of RFC 9001 Appendix A by script -- no hex is transcribed by hand -- and
  `test_quic_protection.cpp` reproduces the A.2/A.3/A.5 packets byte for byte.
  That is the only external check on the stack: everything below `protection.h`
  is tested only against itself. `tls.h` + `src/quic_tls.cpp` is the seam onto
  BoringSSL's QUIC API (`SSL_CTX_set_quic_method`): CRYPTO bytes in and out,
  traffic secrets out per level, ALPN and transport parameters across. It
  buffers incoming CRYPTO data per level, because the library accepts it only at
  the level it is currently reading while a peer may legitimately have the next
  level already in flight. 0-RTT is refused there explicitly rather than
  silently. `test_quic_tls.cpp` runs a full handshake with no socket under it
  and then protects and opens a packet with the secrets it produced.
  `crypto_stream.h` reassembles CRYPTO frames into the ordered byte stream
  `tls.h` requires (merging overlaps, bounded per section 7.5), and
  `ack_tracker.h` holds what has been received in one packet number space and
  turns it into the descending ACK encoding of section 19.3.1.
  `transport_parameters.h` is the section 18 extension TLS carries; note that
  an absent parameter means its default and the defaults are not all zero, so
  the struct is initialised to them and decoding overwrites only what arrived.
  Those initialisers are the wire's "absent" values and must stay that way --
  raising one makes a silent peer decode as having granted credit it never
  gave. What vio actually advertises is `default_transport_parameters()`, which
  `connection_config_t` uses, so an application that configures nothing still
  gets a connection that carries data. It grants 8 MiB per connection and 2 MiB
  per stream; a server expecting thousands of concurrent connections should
  lower `initial_max_data`, because there is no receive-window auto-tuning to
  grow or shrink it.

  **Peer-to-peer and mutual TLS.** An endpoint holds up to two `tls_context_t`,
  because a context picks `TLS_server_method` or `TLS_client_method` at
  creation and gates tickets and early data on that, so no single one can both
  answer and dial. `endpoint_t::create` has a two-context overload; the
  one-context form puts it in the slot its `role()` names, and which slots are
  filled is what decides whether a dial or an arriving Initial is refused. The
  role is therefore no longer an endpoint-wide fact -- it is written per
  connection by whichever path built it, and read back through
  `connection_t::role()`, which a peer-to-peer application needs because
  `on_connection` fires for dialled connections too.

  Authentication is `tls_config_t::peer_verify`, the same `peer_verify_t` the
  TCP stack has always had, read per role: a client verifies its peer unless
  told not to, a server asks for nothing unless told to. A server that verifies
  needs `ca_certificates_pem` and is refused at create without it -- it falls
  back to no anchors rather than to the public roots, since the CA that signs a
  client population is essentially never one of those.
  `connection_t::peer_certificate_subject()` names the peer, and only once the
  chain behind it verified, so a non-empty answer is an authenticated identity
  and nothing else is. BoringSSL documents no QUIC restriction on client
  certificates -- its QUIC caveats are all about 0-RTT and key release -- so
  `test_quic_tls.cpp` establishes it by running one with no socket underneath.
  `connection.h` + `src/quic_connection.cpp` is the state machine that drives
  all of it: three packet number spaces, the Initial/Handshake/1-RTT key
  progression, anti-amplification (section 8.1) and connection close. It is
  sans-I/O -- datagrams in, datagrams out, `tick_t` in -- so
  `test_quic_connection.cpp` completes a real handshake between two of them
  with no socket, and completes it again over a link that drops datagrams.
  Everything TLS produces is kept per level until acknowledged so a lost CRYPTO
  frame can be resent byte for byte, and a PTO probe carries outstanding data
  rather than a bare PING (section 6.2.4) -- during a handshake a PING would
  elicit an ACK while telling the peer nothing it is waiting for.

  **Connection migration** (section 9) is in, and the whole of it lives in the
  receive path: a datagram from an address the connection is not using moves it,
  but only on the *highest-numbered non-probing* packet that authenticated
  (9.3), so neither reordering nor a replay can drag a connection somewhere the
  peer has already left. Moving resets the congestion controller, the RTT
  estimator and the pacer (9.4) -- the new path is a different path and what the
  old one measured is worth nothing -- switches to a peer connection id the old
  path never carried (9.5), and starts the anti-amplification allowance again
  from zero, because section 8's limit is per path and a spoofed source address
  would otherwise make the server an amplifier aimed at whoever was named. The
  endpoint follows by watching migration_count *change across one datagram*: the
  running total stays above zero for the rest of the connection, so testing it
  would redirect on any later datagram from anywhere.

  The part that is easy to miss, and was: a peer probes a new path *before* it
  moves to it (9.2), and a probing packet by definition does **not** migrate the
  connection (9.1). So the PATH_RESPONSE it is owed goes to an address the
  connection is not using and never will unless that echo arrives -- section
  8.2.2 requires the response on the path the challenge came in on. A
  demultiplexer holding one peer address per connection sends it to the old one
  instead, and the peer's validation quietly times out. That is why
  `path_response_queue_t` carries the arrival address with each echo, and why
  `poll_send` has a three-argument form reporting a per-datagram destination;
  the two-argument form cannot address a datagram, so it holds such an echo
  rather than sending it to the wrong place. An off-path echo goes out alone,
  carrying nothing else at all: the address is unvalidated by definition, and
  section 9.3.1 is about what a spoofed source gets delivered to it.

  Worth knowing how this fails, because it fails *silently*: with the echo
  misaddressed, `picoquicdemo -f 3` still transfers every byte and still exits
  zero -- it simply never migrates, and stays on the path it wanted to leave.
  The interop server prints `migrations=` for exactly this reason. Judging
  migration by whether the data arrived will tell you it works when it does not.
  Retry (section 17.2.5) and key update (RFC 9001 section 6) are both in.
  `retry_token.h` seals the token under a server-held AEAD key with the client
  address as associated data and a lifetime, because a token that is forgeable,
  unbound or eternal proves nothing. Key update keeps three generations --
  previous, current, next -- and derives the next one up front, since deriving
  on demand leaks when updates happen (section 6.3). Note that AEAD open is
  in place and a rejected tag may leave the buffer altered, so any speculative
  attempt must restore the ciphertext before the next one.
  Section 6.6 AEAD usage limits are enforced in both directions: packets
  encrypted per key, and forgery attempts across the connection. The idle
  timeout of section 10.1 closes a connection silently, floored at three PTOs.
  MAX_STREAMS returns credit as the application finishes with peer-initiated
  streams -- without it a peer that reaches the limit stays there forever.

`test/bench_quic.cpp` (target `vio_bench`, excluded from the default build) is
the QUIC hot-path benchmark. It replaces global `operator new` to count
allocations, so it must never share a binary with the tests. Being sans-I/O it
measures exactly the per-packet cost with no kernel in the way, which makes it
a fair measure of protocol overhead and an unfair one of link throughput.
Two things dominated when it was first written, both since fixed: TLS was
driven on every received packet long after the handshake, and
`ack_eliciting_in_flight` scanned every packet in flight from the PTO
calculation on every `poll_send`. With those gone the profile is 80%+ AES-GCM,
which is where an encrypted transport's time belongs.

It also prices the **coroutine API against the callback one**, and for that it has to be
I/O: each shape runs twice over the same real socket, and only the difference between the
pair means anything. The current numbers are the "After" rows of `BASELINE.md` (native loop,
epoll, Release). Bulk favours the coroutine API: 303 and 315 MB/s against 222 MB/s for the
callback server, at 0.3 more allocations per datagram. Pipelined request/response favours the
callback API by about 1.5x: 77.5k against 50.9k req/s, with 9.3 more allocations per request
(24.5 against 15.2). A later set of seven runs on the same tree gave medians near 120k against
73k, so the gap is not noise. On the libuv build (`8e33e02`, MSVC) the request rows ran the
other way, 34.5k through coroutines against 23k through callbacks, and the explanation given
then was the callback server's sweep: `readable_streams()` is a level, so it walks every
stream, sorts and allocates a vector on every call, once per arriving datagram. The callback
server in `bench_quic.cpp` still makes that call per datagram and now wins anyway, so the sweep
no longer decides the result; what does has not been profiled. Choose the API for its shape,
not for these numbers. The request shape is also what found the stream-accept-backlog defect --
a burst of 500 streams was queued by one drain and the overflow reset inside that same drain,
before the application could accept any of it.

`loss_recovery.h` is RFC 9002 sections 5 and 6 (RTT estimation, packet- and
  time-threshold loss detection, PTO with backoff and the anti-deadlock probe),
  transcribed from the appendix A pseudocode. A sent packet records *what it
  meant* -- a list of `sent_frame_t` -- never the bytes, which is what makes
  the `resend_current` loss policy in `frame.h` implementable.
  `congestion_control.h` is section 7 NewReno on top of it: slow start,
  recovery periods (a lost round trip is one congestion event, not one per
  packet), congestion avoidance with the integer remainder carried, and
  persistent congestion. Slow start ends on a rising round trip time
  (HyStart++, RFC 9406) with two deliberate departures from the RFC's
  recommended constants: `min_rtt_thresh` is 1ms rather than 4ms, because on a
  low latency path the 4ms floor -- not the path -- decides, and the
  conservative phase ends early when the round trip time climbs *past the
  baseline it started from* rather than serving out all five rounds. Both exist
  because the recommended values left the window at roughly eleven times the
  bandwidth-delay product on a 20ms path; measured against picoquic they are
  worth 128 -> 163 Mbps and 150 -> 78ms of queue. A cap on slow start growth
  against the delivered rate was tried and reverted: it needs an
  application-limited signal the controller does not have, and without one it
  throttles a sender that simply has little to send. `poll_send` will not exceed the window, except for a
  PTO probe or a CONNECTION_CLOSE, which section 7.5 exempts.
  **QUIC version 2 (RFC 9369)** is supported on both sides. It is version 1
  with a different Initial salt, different HKDF labels, a different Retry key
  and nonce, and long header type codes moved on by one; all of it is selected
  from the version rather than duplicated. The version rides on the connection
  (`connection_config_t::version` for a client to propose, adopted from the
  client's first Initial by a server) and reaches the key schedule through
  `packet_protection_t`, which has to remember it because every later key
  generation is derived from the same labels. `endpoint_config_t::supported_versions`
  defaults to both, so a v2 client is accepted and anything else still gets a
  Version Negotiation. Verified against RFC 9369 Appendix A.1 and against
  picoquic (`picoquicdemo -v 6b3343cf`), including ChaCha20 and HelloRetryRequest.
  Compatible version negotiation (RFC 9368) is not implemented.

  **Extensions.** Three beyond RFC 9000 itself:

  - **DATAGRAM (RFC 9221)** — `max_datagram_frame_size` plus frame types
    0x30/0x31, reached through `write_datagram` / `read_datagram` /
    `max_datagram_payload`. The rule that makes it the extension it is: a lost
    DATAGRAM is *not* retransmitted, so its loss policy is `discard`. Sending is
    refused rather than truncated when the peer offered no room or too little,
    and the peer's limit counts the whole frame, so `max_datagram_payload` does
    that arithmetic once rather than leaving it to callers.
  - **grease_quic_bit (RFC 9287)** — offering the parameter promises to accept a
    cleared QUIC bit (`packet_reader_t` takes a flag for that promise);
    receiving it permits clearing one on short headers, which vio does
    *unpredictably* per packet, because a bit that is reliably zero ossifies as
    readily as one that is reliably one.
  - **CUBIC (RFC 9438)** — a mode on `congestion_control_t`, not a second
    controller, because it differs from NewReno in exactly two places: the
    growth curve in congestion avoidance and the 0.7 (not 0.5) decrease.
    `connection_config_t::congestion_algorithm` selects it; **NewReno remains the
    default**. Measured: identical on a lossless path (they only diverge after a
    congestion event); on a lossy long path (4 MB, 200ms, 0.5% loss, nine runs)
    CUBIC's median is 3.0 Mbps against NewReno's 1.25; on a *short* path CUBIC is
    deliberately the more cautious, since its growth is a function of time where
    Reno's is a function of round trips and there are many of those in a second.

  Not implemented, and why: **ACK_FREQUENCY** is still a draft whose codepoints
  have moved between versions, and measurement showed vio already receives
  *fewer* acknowledgements than picoquic (one per 30 packets against one per 20),
  so it would buy control rather than throughput. **HTTP/3 and QPACK** belong in prism, per
  the architecture. Timestamps and multipath are niche; no two of picoquic,
  msquic and quiche agree on having all of them either.

  **Denial-of-service hardening.** Three defects found in the August 2026
  security review, each of which cost one packet to trigger:

  - **A Version Negotiation packet is never answered** (`quic_endpoint.cpp`).
    Its version field is zero, which no endpoint supports, so replying produced
    a packet that was itself a trigger -- section 6.1 forbids it, and two
    endpoints pointed at each other never stopped. A Version Negotiation is also
    withheld from any datagram below 1200 bytes, for the amplification reason
    section 14.1 gives about Initials.
  - **`connection_config_t::handshake_timeout`** (default 10 s, `0` disables).
    The idle timeout of section 10.1 is negotiated, so it does not exist until
    the peer's transport parameters arrive -- which means a handshake that never
    got that far was never reaped at all, and one spoofed Initial bought a
    connection plus a TLS session for the life of the process. The deadline is
    stamped on the first datagram and reported through `next_timeout`.
  - **`active_connection_id_limit` is clamped** to
    `maximum_active_connection_id_limit` (8) on decode. Section 18.2 gives it a
    floor and no ceiling, but `replenish_connection_ids` loops against it with a
    CSPRNG draw and an HMAC per iteration, so an unbounded value was an
    unbounded loop that froze every connection on the endpoint. Clamped rather
    than refused: the parameter is a promise about what the peer will remember,
    and meeting it partially is legal where rejecting the handshake is rude.

  Thirteen further **high** findings from the same review are also fixed: the
  peer's `ack_delay` is clamped before it can invert the RTT estimate (the value
  and its exponent are both the peer's, and the product overflowed twice); the
  address token is validated *before* a connection is built, since branching on
  a token's presence let one junk byte skip the stateless Retry; both stream and
  CRYPTO reassembly now cap **fragments** as well as bytes, because flow control
  bounds the highest offset reached and never the number of runs held to get
  there; four stream state-machine defects (a half that finished with nothing
  left to take never became terminal and so was never reaped, a reset charged
  connection credit it never released, a reaped index could be reopened and
  re-credited, and a retransmit range over acknowledged bytes emitted empty
  STREAM frames for ever); and the 0-RTT set below.

  Regression tests live beside the code they cover, and **each was confirmed to
  fail with its fix reverted** -- which is the only thing that makes a regression
  test worth having. Two were wrong on the first attempt and are worth knowing
  about: a client only holds early keys until 1-RTT arrives, so a reflection test
  run after the handshake proves nothing, and a `tick_t{}` timestamp looks
  ancient beside the `steady_clock` reading the TLS callback uses, so a register
  filled with one is swept empty before the test reaches its assertion.

  The remaining medium and low findings are catalogued in `SECURITY_BACKLOG.md`,
  with the evidence strength each was recorded at -- the review was
  machine-assisted and one of its claims was checked and found false, so
  "relayed" there means verify before fixing.

  **Session resumption and 0-RTT** (RFC 9001 section 4.6, RFC 8446 section 8).
  Two separate knobs on `tls_config_t`, because they are two features:
  `session_resumption` issues and offers tickets, which shortens a handshake and
  carries no replay exposure; `early_data` additionally permits 0-RTT, and
  implies the first.

  **Hardened in the August 2026 review.** The ticket lifetime is now set from
  the register's window (`SSL_CTX_set_session_psk_dhe_timeout`) rather than left
  at BoringSSL's two-day default, which was 288 times longer than the window
  that would recognise a replay -- the invariant this section used to assert was
  not implemented. The receive path now checks the role before reaching for the
  early key: there is one early-key slot and on a client it holds that client's
  own *write* key, so a reflected copy of its own 0-RTT packet authenticated and
  its frames were acted on, before the server's certificate had been verified.
  The register's digest is keyed per instance, since the identifier is a
  ClientHello random the client chooses freely and an unkeyed hash is a table an
  attacker precomputes once. And a ClientHello must now carry a ticket as well
  as the extension before it can spend a slot -- offering early data costs
  nothing, and because the register is deliberately fail-closed, filling it was a
  way to switch 0-RTT off for everyone.

  A **server with early data on must be given an `anti_replay_t`** or
  `tls_context_t::create` fails -- refusing to build the context beats building
  one that silently never grants 0-RTT. `anti_replay.h` is the RFC 8446 section
  8.2 strike register: it records a digest of each ClientHello random inside a
  window, and it is deliberately **fail-closed and bounded** -- a repeat, or a
  full register, is refused rather than evicting something still inside its
  window. Refusing costs a round trip; forgetting costs the guarantee. It is
  consulted only for ClientHellos that actually offer early data, so ordinary
  full handshakes cannot exhaust the capacity that protects the ones that do.
  One register per endpoint, not per connection -- a replay is by definition a
  second connection.

  The **ticket a caller keeps is one opaque blob** carrying both the TLS session
  and the server's transport parameters, because section 4.6.1 requires a
  resuming client to stay inside the limits from last time and there is nothing
  else to go on before the server has spoken -- without them a 0-RTT client
  cannot even open a stream. The forbidden-to-remember parameters (connection
  IDs, `max_ack_delay`, `ack_delay_exponent`, the reset token) are scrubbed on
  the way in and replaced by the real ones at handshake completion. Read it with
  `connection_t::resumption_ticket()`, spend it with
  `endpoint_t::connect(address, name, ticket)` -- per dial, since a ticket is
  about one peer and an endpoint dials many. A ticket that will not parse is a
  full handshake, never a failure to connect.

  Three transport details that each cost a debugging session: `level_for` maps
  0-RTT to `early_data` (it shares the application packet-number space, only the
  keys differ); the receive gate asks for the **early** key, never the 1-RTT read
  key, which by definition does not exist yet; and `SSL_do_handshake` returning 1
  while `SSL_in_early_data` is **not** completion -- treating it as such sends the
  next call into post-handshake processing, which fails. On rejection the client
  calls `SSL_reset_early_data_reject` and vio **repairs the 0-RTT packets at
  once** (`take_early_data_packets` + `repair_lost`) rather than waiting for loss
  detection, so section 4.6.2's resend costs a retransmit and not a timeout; the
  application never learns it happened. Keys are discarded per section 4.9.3 --
  client when 1-RTT write keys arrive, server at handshake completion.

  Verified against **picoquic in both directions**: picoquic client to vio server
  reports "Zero RTT data is accepted" (including through a Retry), and vio's
  client resumes into picoquic's server with early data accepted --
  `TESTCASE=zerortt` in `interop_endpoint.cpp`. One asymmetry worth knowing:
  picoquic's *server* mints no NewSessionTicket unless the client enabled early
  data, so the `resumption` case does not complete against it; vio to vio it does,
  which is what the in-process tests cover.

  **Path MTU discovery** (`mtu.h`, RFC 8899 as section 14.3 applies it): a
  connection starts at the 1200 bytes every path must carry and probes upward
  with a PING padded to the candidate size, in a datagram of its own. The first
  probe asks for the ceiling outright -- most paths carry it, and a size arrived
  at after slow start has ended has missed the part of the transfer it would
  have helped; only once something is refused does it bisect. A probe is
  disproved by a single loss while optimistic and by three once bisecting, and it
  carries **its own deadline** (`probe_timeout`, RFC 8899 PROBE_TIMER) because a
  path that silently swallows the size produces no acknowledgement *and* no loss
  signal on an otherwise idle connection -- without it the search waits forever.
  Probing waits for the handshake, for window the data was not going to use, and
  for a path that is not already recovering; losing a probe never shrinks the
  window (section 14.4). Repeated timeouts at a validated size retreat to the
  floor. The ceiling is `connection_config_t::datagram_size_ceiling` (1452 by
  default) bounded again by the peer's `max_udp_payload_size`.

  Worth knowing before reaching for it as a performance lever: against picoquic
  it reaches the same 1440 the peer does, but on a **byte**-rate-limited path it
  is worth about 3% and no more -- the link charges bytes, the congestion window
  is counted in bytes, and GSO has already amortised the per-datagram syscall.
  It earns its place on conformance and on paths where the packet rate, rather
  than the byte rate, is what runs out.

  `stream.h` and `streams.h` are sections 2 to 4: a stream is two independent
  halves that share an identifier, each with its own state machine and its own
  flow control limit, which is why `connection_t` asks
  `stream_receive_finished` and `stream_send_finished` separately. Final size
  is the idea that ties them to connection-level accounting -- a sender always
  communicates it, by FIN or by RESET_STREAM, so both endpoints agree exactly
  how much credit the stream consumed, and a later frame implying a different
  one is a FINAL_SIZE_ERROR.
  **The coroutine face** is `src/vio/operation/quic_endpoint.h`, tested by
  `test/test_quic_coroutine.cpp`. Everything under `src/vio/quic/` stays exactly as it
  is -- a sans-I/O state machine driven by `std::function` and integer ids is the right
  shape for the inside of a transport and the wrong one for an application. This layer
  is built on top: `quic_endpoint_create` / `_bind` / `_accept` / `_connect` /
  `_shutdown`, and `quic_connection_close` / `_closed` / `_ready` plus accessors.

  The organising idea is the **loop turn**. The transport's three hooks
  (`on_connection`, `on_activity`, `on_connection_gone`) only *record*; the beat, a
  before-block hook on the loop, resumes everything that became runnable and flushes what
  it wrote, in the same turn. That separation is not stylistic. `endpoint_impl_t` holds connections
  as `unique_ptr` and brackets its walk, so dialling from a callback is already safe;
  what is not safe is what a coroutine may do that a callback may not -- drop the last
  `quic_endpoint_t`, destroying `endpoint_impl_t`, `run()`'s frame, the datagram reader
  inside it and the vector being walked, from a stack several calls deep inside all of
  them. The beat runs after the turn's timers, so the endpoint's 2 ms ticker has already
  fired when it runs. Neither the beat nor the ticker keeps the loop alive, so an endpoint
  that was never bound does not stop `run()` returning.

  **No awaitable holds a strong reference to the endpoint.** A suspended accept that did
  would take the count 2->1 on release, `on_destroy` would never run, nothing would
  resolve it, and the socket's close would never start -- so `run()` would never
  return. That is the second, non-obvious face of the handle-lifetime failure below.
  Operations are per-call heap allocations with a two-hold protocol, so concurrent
  accepts are served FIFO rather than refused.

  A **tombstone** is what a connection becomes when it ends: `connection_t` is freed by
  the endpoint on its own schedule with no notification, so the alpn, close reason, stats
  and ending are latched at the sever and the pointer nulled there. Holding a
  `quic_connection_t` past the ending is safe and is the point. Milestone slots
  (`ready`, `closed`) are allocated on first ask and born reached when the thing they
  name already happened, so asking after the fact answers rather than hanging.

  One rule with teeth: **a cancellation registration is dropped when the operation
  resolves, not when it resumes** -- an operation resolved at call time waits on
  `ready_ops` for the next beat, and the caller's request-scoped `cancellation_t` can die
  in between. `QUIC_COROUTINE_API.md` is the design doc and records what its own build
  order got wrong.

  **Streams** are `src/vio/operation/quic_stream.h`, with the state and the edge drain in
  `quic_endpoint.h` next to the other state -- `quic_connection_state_t` owns the registry
  and a `ref_ptr_t` member needs its type complete, so the physical split is mechanism
  here, application face there. The organising idea is that **an ending is an ordinary
  entry, not a flag on the side**: a read yields bytes until there are none, then
  `vio_quic_stream_finished` or `vio_quic_stream_reset`, which is the whole fix for
  `stream_receive_finished()` answering true for both. Nothing is buffered on the
  application's behalf -- bytes stay in the transport's reassembly until an await takes
  them, and taking them is the call that returns MAX_STREAM_DATA credit, so a stream
  nobody reads stops the peer through the mechanism the protocol already has.
  `quic_accept_stream` is built on `take_opened_streams()` rather than
  `readable_streams()`, because the latter is a *level* and cannot report a stream that
  carried only a zero-length FIN. Section 3.2 reincarnation is handled by that same list:
  an id arriving for which a state already exists is by definition a new stream, so the
  old handle is retired with `vio_quic_stream_stale`.

  **Writes are not yet bounded.** `quic_stream_write` hands everything to the transport
  and resolves at once; the awaitable shape exists so the write layer can add high-water
  marks without moving a call site. `quic_bulk_transfer.cpp` is the example that shows
  what an application still has to do about it, and `quic_stream_stats` is the accounting
  it meters against. Also missing: dropping a handle with an unfinished sending half does
  *not* reset it (that policy needs the send-side accounting), and a server cannot observe
  the 0-RTT window, because `quic_endpoint_accept` resolves only once a handshake has
  completed -- `quic_zero_rtt.cpp` records that.

## Verification

What has actually been run against the QUIC stack, so the next person knows what
a green build does and does not cover.

**On the native event loop.** CI run 93 (commit `4abd446`) is green on all ten jobs: Linux
debug, ASan, TSan and UBSan, each on epoll and on io_uring; macOS debug and ASan on kqueue;
Windows debug and ASan on IOCP; and the wasm smoke test under Node. `DECISIONS.md` keeps that
status current. Interop with picoquic has **not** been rerun since the move off libuv, although
`src/quic_endpoint.cpp` and `operation/quic_endpoint.h` were rewritten for the native loop; treat
the interop results below as history until it is.

**Measured on the libuv build at `8e33e02`**, before the native loop. Platforms: MSVC release
and MSVC ASan on Windows; GCC 14 on Ubuntu 24.04 under ASan, UBSan and TSan, through
`ghcr.io/jorgen/vio-ci`. All clean. Two things only the Linux run can tell you, and both still
hold: MSVC's ASan has **no LeakSanitizer**, so leaks are invisible on Windows -- one in the
coroutine layer's pre-resolved operations survived a full ASan run there and was caught the
first time LeakSanitizer saw it -- and glibc declares `error_t`, so `using namespace vio` in a
test that is only ever built on Windows will not compile on Linux. The reverse trap: Windows
headers define `small` as a macro, so a variable named `small` builds everywhere except MSVC. It
has broken the Windows build three times. The MinGW syntax check cannot catch it, because MinGW's
`rpcndr.h` defines `small` only under `RC_INVOKED`; add `-include` of a header holding
`#define small char` to reproduce the MSVC failure.

TSan needs ASLR off on a modern kernel or it aborts with "unexpected memory
mapping" before running a line: `docker run --privileged ... setarch $(uname -m)
-R ./build/test/vio_tests`.

**Interop with picoquic, also at `8e33e02`** (`3rdparty/interop/picoquic`, v1.1.52). Both
directions, byte-exact: picoquicdemo client to `vio_interop_server` over three
concurrent streams, and `vio_interop_endpoint` as a client against picoquicdemo's
server. Retry with vio minting and validating the token, QUIC version 2
(`picoquicdemo -v 6b3343cf`), session resumption, and 0-RTT reporting "early data
accepted" all passed. One gap: `picoquicdemo -r` does not start a server in this
build -- it prints its token-file line and exits -- so picoquic *sending* a Retry
to a vio client is untested. vio sending one is covered, which is the direction
that exercises vio's own `retry_token.h`.

- `test/` - Tests using doctest
- `3rdparty/` - boringssl, ada, structify, doctest, cmakerc (fetched via cmake-dep)

## Dependencies (toggles & install)

Every dependency is togglable between the bundled fetch and a pre-installed copy.
The knobs are **auto-declared by cmake-dep** from each `CmDepFetchPackage` call in
`CMake/3rdPartyPackages.cmake`, prefixed by the project name (uppercased
`PROJECT_NAME` → `VIO`): `VIO_USE_SYSTEM_{BORINGSSL,ADA,STRUCTIFY,DOCTEST,CMAKERC}`
(default `OFF`) and `VIO_<DEP>_{VERSION,URL,SHA256}` overrides to fetch a different
version/URL/hash without editing the packages file. BoringSSL has no releases and
no stable ABI, so it is pinned by commit and `VIO_BORINGSSL_URL`/`SHA256` are the
overrides that matter. When a toggle is `ON`, cmake-dep skips the fetch;
`CMake/Build3rdParty.cmake` then drives ada/doctest/boringssl through
`CmDepAddPackage` (which owns the find-vs-build branch), while cmakerc
(`include()`-based) branches by hand on the `${name}_USE_SYSTEM` signal. BoringSSL
builds in-tree (SYSTEM EXCLUDE_FROM_ALL, so none of its install rules or extra
targets reach this project) and publishes plain `crypto`/`ssl` targets, aliased to
`BoringSSL::Crypto`/`BoringSSL::SSL` so the link line reads the same either way.
**Building it needs Go on `PATH`, and NASM on Windows** -- without an assembler its
configure stops rather than handing back a build with no AES-NI, which is the trap
LibreSSL fell into and the reason for the move.

`VIO_INSTALL` (default `ON`) installs headers + the `vio` lib and, **when built
with `VIO_USE_SYSTEM_BORINGSSL=ON` and `VIO_USE_SYSTEM_ADA=ON`**, a relocatable
`find_package(vio)` package config (`vio::vio`, from `CMake/vioConfig.cmake.in`).
That config `find_dependency`s BoringSSL through the `OpenSSL` CONFIG package it
installs, recreates the `BoringSSL::SSL`/`::Crypto` names vio links against, finds
ada, and exports the bundled `cmrc-base`/`vio_default_certs`. CI's `install` job
installs BoringSSL, ada and vio into one prefix and builds `test/install_consumer`
against it, so a broken config fails a job instead of a downstream. A bundled-deps
build vendors targets that aren't installed, so it installs lib + headers only (no
config). `vio::vio` is aliased in-tree so consumers use one name
either way. A downstream that `add_subdirectory`s vio (e.g. prism) should force
`VIO_INSTALL OFF`.

## Key Architecture

### The event loop core

`src/vio/loop/` holds the pieces; `event_loop_t` (`src/vio/platform/native/event_loop_impl.h`) is a
thin face over `loop_core_t` (`src/loop_core.cpp`). One loop per thread. It owns a backend, a timer
heap, a posted queue other threads may push to, a deferred queue for work the loop schedules for
itself, before-block hooks, and a registry of open resources so its destructor can name a leak.

One turn: run due timers; drain posted work; drain deferred work; return if `stop()` was called and
nothing is in flight; run the before-block listeners and hooks; wait in the backend.

Backends (`src/backend_*.cpp`) are readiness-first for sockets on every platform: an operation
tries the system call and parks on the socket's `io_watch_t` only on `errc::again`. epoll is
edge-triggered, kqueue uses `EV_CLEAR`, io_uring arms a one-shot `POLL_ADD`, and IOCP polls through
AFD. On Linux `VIO_BACKEND=epoll|io_uring` picks one at run time; epoll is the default, and
`backend_name()` reports which ran. io_uring also runs file reads, writes and `fsync` on the ring.
Everything else that blocks -- other file work, `getaddrinfo` -- runs on the blocking pool
(`src/blocking_pool.cpp`), which has separate file and DNS queues (4 and 2 threads,
`VIO_FILE_THREADS` and `VIO_DNS_THREADS` to change them).

The system calls live in `src/sys_posix.cpp`, `src/sys_win.cpp` and `src/vio/detail/sys_file.h`.
They return a byte count or a negative `vio::errc` code (`src/vio/errc.h`), the same numbers on
every platform.

Two rules that cost a sanitizer run each to learn. A thread that posts wakes the loop **before** it
releases the post lock: otherwise the loop can drain the post, finish and be destroyed while the
poster is still about to touch it. And `unpost` on the loop thread also clears the node from the
batch being drained, because work earlier in the same batch may have destroyed its owner.

Two more rules. A loop created before `fork()` may only be destroyed in the child: running it, or
giving it work, aborts with a message (D51). A child drops the inherited handles first, then the
loop; that abandons the parent's work in flight without a report. And a callback that throws
leaves `run()`, but nothing queued or batched is lost, so calling `run()` again carries on (D52).

### task_t coroutine lifecycle

`task_t<T>` is an eager coroutine (`initial_suspend()` returns `suspend_never`). The coroutine
frame starts executing immediately when the function is called. `final_suspend()` resumes the
continuation (the caller that `co_await`ed). The destructor only destroys the frame if
`_coro.done()` is true.

`operator co_await() &&` copies the `_coro` handle into the `awaiter_t` but does **not** null
`_coro` in the `task_t`. This means:

- For temporary `task_t` (e.g. `co_await some_lambda(args)`) the temporary persists until after
  `await_resume()`, then its destructor destroys the done frame.
- For named `task_t`, the frame is destroyed when the named variable goes out of scope. After
  `co_await std::move(named_task)` completes, the frame is done but still alive. It is destroyed
  when `named_task` is destructed (or you can force it with `{ auto tmp = std::move(named_task); }`).

### ref_ptr_t / reference_counted_t destruction sequence

`ref_ptr_t<T>` is a ref-counted smart pointer. When the last reference is released (`dec()`):

1. `on_destroy` callbacks fire (in reverse registration order)
2. every resource registered with `register_resource` starts its close
3. Storage is freed only after every close has finished, on a later turn (via `close_pending`)

The `on_destroy` callbacks may register more resources (e.g. the socket of a TLS connection). The
`in_destroy_sequence` flag prevents re-entrant destruction if callbacks temporarily increment and
decrement the ref count. A ref that pending work holds (e.g. the linger timer `begin_teardown` arms
while a close_notify is still being written) defers the final destruction until that work releases
it — which is how a best-effort close_notify is flushed on close.

### TLS transport: tls_stream_t + ssl_engine_t

TLS reads and writes the socket itself: it parks on readiness, calls `recv`/`send` when the
socket is ready, and feeds the bytes through the engine. The pieces (all in `src/vio/`):

- `ssl_backend.h` — compile-time backend seam (`VIO_SSL_BACKEND`); only bundled BoringSSL is
  wired, and selecting another value is a configure error rather than a compile-for-one-link-to-
  another mismatch. Portable in-memory cert/key/CA loading (`BIO_new_mem_buf` + `PEM_read_bio_*`),
  feature-gated on the `VIO_SSL_BACKEND_*` macro plus the library's own identity macros (never the
  raw `OPENSSL_VERSION_NUMBER`, which LibreSSL fakes as `0x20000000L`). On Windows it also undefs
  `min`/`max` and wincrypt's X.509 name grabs before including any openssl header — BoringSSL does
  not do that from the inside the way LibreSSL and OpenSSL do, **so every TU that touches openssl
  must include `vio/ssl_backend.h` before it**.
- `ssl_context.h` — `ssl_context_t`: a shared `SSL_CTX` built once from `ssl_config_t` (verify,
  ALPN, keylog, session cache). Server ALPN selection is hand-rolled (server preference, empty-list
  CVE-2024-5535 guard, `NOACK` on no overlap).
- `ssl_engine.h` — `ssl_engine_t`: a per-connection **socket-free** codec (`SSL*` plus a custom
  BIO over the engine's own inbound and outbound buffers). The socket is read straight into
  `inbound_space()`; `SSL_read` yields plaintext; `SSL_write` fills `pending_output()`.
- `socket_stream.h` — `tls_stream_t`: the driver. `service()` flushes output, pumps writes, reads
  the socket (up to `read_budget` reads per turn) and notifies waiters. Processing inbound bytes is
  **handshake-then-fall-through** (a segment carrying Finished + app data decrypts both in one
  pass). After every SSL op it flushes output, so KeyUpdate and alert records are sent. Writes are
  producer-throttled: over `write_high_water`, `SSL_write` is deferred and the awaitable stays
  suspended (natural backpressure); a reader nobody awaits stops reading the socket. The handshake
  is driven to completion at connect/accept.

Reentrancy: work scheduled for a later turn holds a ref (`rc->inc()/dec()`) so a resumed coroutine
that drops the last user ref cannot free the state under it. Never hold a `write_queue[idx]`
reference across a `continuation.resume()` (the vector may reallocate) — re-index after resuming.

### event_loop_t

`event_loop.run()` returns only after `stop()`, and then only once nothing is in flight: a parked
operation, a timer that keeps the loop alive, a blocking-pool job or an unfinished close. `stop()`
is sticky; a later `run()` drains and returns. Tests that don't use coroutines still call
`event_loop.stop()` before `event_loop.run()` so closes finish.

### Handle lifetime vs loop teardown

**A vio handle must be released while the loop can still run.** Dropping the last reference to a
`udp_t`, `timer_t`, `tcp_server_t` … only *starts* its close; the close finishes on a later turn,
and the ref-counted storage is freed only once it has. So a handle still alive when `run()` returns
leaves its close unfinished, and `~event_loop_t` names every resource still open and then asserts.
It prints in every build type, because under `NDEBUG` the assert is gone.

The symptom has two faces, and the second one does not look like a lifetime problem at all:

- `vio: ~event_loop_t: ... still open` and an assertion at the end of a test, *after* every
  assertion passed.
- **`run()` never returns.** An operation still parked on a handle keeps the loop alive after
  `stop()`. A test that calls `loop.stop()` while a read or accept is still waiting hangs rather
  than aborting. A dropped TCP or TLS connection with writes still queued also keeps it alive,
  for up to 10 s, while it delivers them (D49).

The fix is always to shorten the handle's life, not to lengthen the loop's:

```cpp
// Owned by a coroutine that completes before stop() -- the pattern in test_udp.cpp.
auto receiver_task = [](vio::udp_t receiver) -> vio::task_t<void> { … }(std::move(socket));
co_await std::move(receiver_task);
loop.stop();

// Or a plain scope, when a sub-coroutine would be contrived.
{
  auto socket = …;
  auto reader = …;
}                 // close started here
loop.stop();      // and finished by the run() that is still in progress
```

Handles are deliberately **not** force-closed in `~event_loop_t`: they live in reference-counted
storage their owner still holds, and that owner closes them when it is destroyed. Closing them
twice is worse than leaking them. A socket whose storage is destroyed without being closed aborts
with a message, because the backend may still hold a pointer to it.

### Socket reads: queue, read_into (zero-copy), pause/resume

`tcp_reader_t` (`operation/tcp.h`) supports three modes over one reader:
- `co_await reader` — the queue path: the reader takes a buffer from its alloc callback, calls
  `recv` into it and hands the owned `unique_buf_t` over by move. If the socket has nothing, the
  awaiter parks on readiness and tries again when it is woken.
- `reader.read_into(std::span<std::byte> dst)` — **true zero-copy**: `recv` writes straight into
  `dst`; resolves to `std::expected<std::size_t, error_t>` (0 = EOF). Nothing is read between
  calls, so the pull cadence is the backpressure.
- `reader.pause()` / `reader.resume()` — stop and restart delivery. A pause cancels a parked
  queue read; `read.started` stays true across a pause and `read.paused` tracks the armed state.

Because the kernel never holds a caller's buffer, `cancel()` on a `read_into` is synchronous:
prism cancels one and reuses the buffer at once.

TLS (`stream_reader_t`, `socket_stream.h`) decrypts directly into a caller buffer
(`read(std::span<std::byte>)`) and stops reading the socket when nobody waits; it cannot be truly
zero-copy since the socket only carries ciphertext. (These vio APIs back prism's streaming request
bodies.)

## Writing Tests

### Coroutine test pattern

Tests use `event_loop.run_in_loop()` with a non-coroutine lambda that stores the coroutine
`task_t` in a `std::optional`. This keeps the coroutine frame alive until after `event_loop.run()`
returns, preventing memory leaks. The inner lambda coroutine uses **parameters** (not captures)
to avoid dangling-this UB:

```cpp
std::optional<vio::task_t<void>> task;
event_loop.run_in_loop([&] {
    task.emplace(
      [](vio::event_loop_t &event_loop, bool &verified) -> vio::task_t<void> {
          auto server_task = [](args...) -> vio::task_t<void> { ... }(captured_args);
          co_await [](args...) -> vio::task_t<void> { ... }(captured_args); // client
          co_await std::move(server_task);
          event_loop.stop();
      }(event_loop, verified));
});
event_loop.run();
// ~optional destroys task_t, which sees _coro.done()==true and calls _coro.destroy()
```

### Avoiding dangling-this UB in lambda coroutines

**Critical**: Lambda coroutines that capture by reference (`[&]`) and return `task_t<void>` have a
dangling `this` pointer bug. The lambda closure object is a temporary — it is destroyed after the
coroutine is created (since `task_t` is eager). But the coroutine frame holds a `this` pointer to
the closure for accessing captures. Any `co_await` that suspends and resumes later will access
freed memory.

**Safe pattern**: Use immediately-invoked lambda coroutines that take all needed state as
**parameters** (not captures):

```cpp
// SAFE: parameters are copied into the coroutine frame
auto task = [](vio::event_loop_t &el, int port) -> vio::task_t<void> {
    co_await something(el, port);
}(event_loop, port);  // args passed by value/ref — stored in frame
```

```cpp
// UNSAFE: captures become dangling after first suspend
auto task = [&]() -> vio::task_t<void> {
    co_await something(event_loop, port);  // UB: 'this' is dangling
}();
```

The `[&]` capture in `run_in_loop` is safe because that lambda is not a coroutine itself when it
simply creates and co_awaits sub-tasks that follow the parameter pattern.

### TLS disconnect detection

vio reads the socket itself, so disconnects are detected directly — the old
`recv(..., MSG_PEEK)` probe is gone. Distinct, stable `error_t` codes let a downstream (HTTP/2)
branch on the kind of close (defined in `ssl_engine.h`):

1. **Clean shutdown (`vio_tls_clean_shutdown`):** the peer sent `close_notify`, so `SSL_read`
   returns `SSL_ERROR_ZERO_RETURN` (or `recv` returns 0 after `close_notify`).
2. **Unclean truncation (`vio_tls_truncated`):** `recv` returns 0 before any
   `close_notify` — the connection was cut mid-stream.
3. **Transport error:** any other failed `recv` maps to its `vio::errc` code.

### TLS extras: OCSP stapling, session resumption, writev backpressure

- **OCSP stapling** (`ssl_config_t.ocsp_staple_mem`/`ocsp_staple_file`, server): the DER
  response is stored in `ssl_context_t` and stapled via `SSL_CTX_set_tlsext_status_cb`
  (BoringSSL uses `SSL_CTX_set_ocsp_response`, gated in `ssl_context.h`). A client sets
  `request_ocsp_staple` and reads it back with `ssl_client_ocsp_response()`.
- **Client session resumption** (`ssl_config_t.session_cache` → `ssl_session_cache_t`, app-owned,
  keyed by host): wired via `SSL_CTX_sess_set_new_cb` (fires when a ticket arrives) +
  `SSL_set_session` (before handshake). The peer host is stashed in SSL ex_data (`&engine.peer_name`)
  to key the cache. `ssl_client_session_reused()` reports the result. **Caveat, now historical:**
  under the old LibreSSL backend TLS 1.3 resumption could not work in either direction — its server
  never issued NewSessionTicket (`num_tickets` defaults to 0, and setting it to 2 with
  `SSL_SESS_CACHE_SERVER` still produced no ticket bytes) and its client never emitted
  `pre_shared_key`, so only TLS 1.2 resumption (ticket in-handshake) was ever verified. On
  BoringSSL it works: `test_ssl_deep.cpp` now runs the same resumption check at **both** TLS 1.2
  and TLS 1.3, and the 1.3 case resumes off a post-handshake NewSessionTicket. Note the two are
  separate `TEST_CASE`s rather than `SUBCASE`s — the body stands up a server and an event loop, and
  re-entering it for a second subcase in one process hangs. `SSL_CTX_set_num_tickets(2)` is correct
  on this backend.
- **`ssl_*_writev` / `ssl_*_shutdown`**: vectored writes coalesce buffers into one TLS record and
  go through the same producer high-water throttle as `begin_write` (the coalesced plaintext is
  owned in the write slot, so it survives being parked for backpressure); half-close sends a
  one-way `close_notify` and keeps reading.

### on_destroy teardown (begin_teardown)

`tls_client.h` and `tls_server.h` `on_destroy` callbacks call `tls_stream_t::begin_teardown()`:
it cancels a parked read and sends a best-effort one-way `close_notify`. If the socket cannot take
it all at once, the stream holds a ref and arms a linger timer (`teardown_linger_ns`, 10 s) that
defers final destruction until the flush completes or the timer gives up. Plain TCP does the same
through `detail::tcp_begin_teardown` when a dropped `tcp_t` still has writes queued
(`tcp_teardown_linger_ns`). Both keep reading and discarding inbound bytes while they linger, so
two lingering ends drain each other instead of stalling until the timer. Once the writes are out
both shut down the sending side and close only when the peer does, or 2 s later: closing while the
peer still sends draws a reset, which on Windows destroys data the peer has not read (D49). The `SSL*` and its BIOs
are freed by the `ssl_engine_t` destructor when the state's storage is deleted — after the
close_notify has left the engine. Guarded to be a no-op when the engine was never initialized
(e.g. a client dropped before connecting). `ssl_server_create`'s `on_destroy` aborts a pending
listen with `errc::canceled`.
