# Security backlog

Open findings from the August 2026 QUIC review, which produced 51 items across
nine parallel audits. The three critical and thirteen high items are fixed
(`06855ae`, `049f849`, `77268fb`, `aa74985`, `a1bc5cc`); what follows is
everything that remains.

Each entry carries the evidence strength it was recorded with, because that
distinction matters more than usual here — the review was machine-assisted and
one claim in it was checked and found false.

- **Confirmed** — read and verified against the source during the review.
- **Relayed** — reported with file:line evidence, not independently verified.
  Verify before fixing; a fix built on a false premise is worse than none.

Line numbers are from the review and will drift.

---

## Medium

### M1 — ECN counts are never bounded by what this endpoint sent
`src/vio/quic/ecn.h:149` · Relayed

Only the lower bound on reported counts is checked. The validator starts enabled
while the default configuration marks nothing, so a peer's CE counts are obeyed
for packets that were never marked. One forged ACK per round trip pins the
congestion window at its 2400-byte floor. `ect0_rise + ce_rise` is also unchecked
addition and can wrap, which permanently disables ECN.

*Fix:* track packets sent per codepoint; reject counts exceeding them; use
saturating addition; do not enable the validator when `ecn_sending == not_ect`.

### M2 — The early-data context binds only the ALPN
`src/quic_tls.cpp:780` · Confirmed

Built from `tls_config_t::transport_parameters`, which the QUIC layer never
populates — the real parameters travel through `connection_config_t` and are
installed after the session exists. RFC 9001 §4.6.1's guarantee that 0-RTT is
refused when the server's limits have moved is therefore not delivered. Latent
rather than live: a parameter change today requires a restart, which rotates
ticket keys anyway. It becomes live the moment ticket keys are persisted.

*Fix:* compute the context from the connection's parameters before the first
flight; refuse a server context that has early data and no parameters.

### M3 — `remembered_parameters` is written and never read
`src/quic_connection.cpp:3015`, `src/vio/quic/streams.h:163` · Confirmed

RFC 9000 §7.4.1 requires a client that used 0-RTT to check the server's real
limits are not below the remembered ones. The field where that check belongs is
dead. Worse, `apply_peer_parameters` uses `max()` for connection-level and
stream-count limits, so genuine parameters cannot lower what a ticket raised.
Per-stream limits are plain assignments and are replaced correctly.

*Fix:* compare against the remembered set at handshake completion; close with
`PROTOCOL_VIOLATION` on a decrease.

### M4 — Retry is emitted for sub-1200-byte Initials, unrated
`src/quic_endpoint.cpp:890` vs `:486` · Relayed

The §14.1 minimum-size check lives inside `accept_connection`, which the Retry
branch skips. A 29-byte datagram draws an 89-byte reply — above the three-times
ceiling, reflectable, and costing two RNG draws and two AEAD operations with no
rate limiter, while the cheaper stateless-reset path *is* limited.

*Fix:* hoist the size check above the Retry branch; rate-limit it like
`allow_stateless_reset`.

### M5 — `_pending_retires` is unbounded and filled quadratically
`src/vio/quic/connection_id_manager.h:233`, `:347` · Relayed

Frames with a sequence below `_largest_retire_prior_to` take an early return
that precedes both the seen-sequence dedupe and the active-CID limit check, so
neither applies. Each appends after a linear scan. The drain is
congestion-controlled while the fill is not.

*Fix:* consult `_seen_sequences` on that path; cap the queue; take
`pending_retires()` by const reference.

### M6 — Unbounded ACK frames per packet, each walking the whole send window
`src/quic_connection.cpp:1277`, `src/vio/quic/loss_recovery.h:467` · Relayed

No cap on frames per packet. A low `largest_acknowledged` keeps the window
intact for the next frame, so work is quadratic within one packet and scales
with what is in flight.

*Fix:* cap ACK frames processed per packet; skip the body when nothing new is
covered.

### M7 — The anti-amplification budget is per-connection, not per-path
`src/quic_connection.cpp:3111` · Relayed

`bytes_received` is incremented before parsing, authentication, or any
comparison against the current peer address. `migrate_to` reseeds it correctly
but nothing keeps it path-scoped afterwards, so datagrams from any source
re-inflate an unvalidated path's allowance. RFC 9000 §8/§9.3.1 make the limit
per path.

*Fix:* count bytes against the address they arrived from.

### M8 — An oversized forged Retry token permanently wedges a client
`src/quic_connection.cpp:1757`, `:2268` · Relayed

Only emptiness is checked, never length. The Retry integrity key is a published
constant, so anyone who observes the client's first Initial can forge one. A
~1400-byte token makes every later Initial fail its size check and
`build_packet` returns zero silently; the client has already marked the Retry
handled, so a genuine one cannot repair it.

*Fix:* reject a retry token larger than the expected size.

### M9 — Retry integrity is always verified with the version 1 key
`src/quic_connection.cpp:1767`, `src/vio/quic/protection.h:567` · Relayed

`verify_retry_integrity` takes no version and hard-codes the v1 key and nonce, so
a v2 client discards every genuine Retry. An interoperability defect rather than
a vulnerability, but in security-critical code and easy to miss because v2 is
otherwise well covered.

*Fix:* thread the version through and select the key pair from it.

### M10 — The AEAD confidentiality limit closes instead of rotating, and the close cannot escape
`src/quic_connection.cpp:2770` · Relayed

RFC 9001 §6.6 requires initiating a key update before the limit; closing is the
fallback for when an update is impossible, which here it never is. Nothing calls
`initiate_key_update` automatically and the counter is not exposed. The check
also precedes packet protection, and the queued CONNECTION_CLOSE routes through
the same function — so the error frame is discarded on every attempt and the
peer sees only silence. Reached by ordinary bulk transfer at roughly 10 GB.

*Fix:* rotate automatically below the limit; let a close-only packet bypass the
check.

### M11 — The connection send window is read per stream but charged per packet
`src/quic_connection.cpp:2646`, `:2815` · Relayed

`on_data_sent` runs after the whole per-stream loop, so every stream in one
packet sees the same undecremented window and the peer's MAX_DATA can be
exceeded by up to a packet payload. A conforming peer must close the connection.

*Fix:* subtract bytes already written in this packet before offering the window
to the next stream.

### M12 — Raw connection pointers held across the `on_activity` callback
`src/quic_endpoint.cpp:945` · Relayed

The touched-entry list holds resolved pointers across the callback; a nested
`flush` runs `reap`, which can destroy an entry still in the list. Partially
mitigated by the deferred reaping added in `a1bc5cc`, but the pointers are still
resolved early.

*Fix:* store handle ids and re-resolve on each use.

### M13 — The detached ticker holds endpoint state and is never joined without a token
`src/quic_endpoint.cpp:805` · Relayed

Safe with a cancellation token, which drains it synchronously. `run()`'s default
is no token, and the read loop can end on its own — the application's cue to
destroy the endpoint. The ticker's timer then fires up to 2 ms later against
freed state.

*Fix:* give the endpoint its own token that `run()` cancels before returning.

### M14 — Duplicate-parameter detection is a linear scan inside the parse loop
`src/vio/quic/transport_parameters.h:245`, `:278` · Relayed

Quadratic in the parameter count on the handshake path, bounded in practice by
BoringSSL's per-level flight limit — tens of milliseconds of unauthenticated
work.

*Fix:* bitmask for known ids; cap the number of unknown ones accepted.

### M15 — The connection-ID routing table hashes attacker-chosen bytes unkeyed
`src/vio/quic/connection_id.h:96` · Relayed

The hash comment names the problem and does nothing about it. Setup requires one
real handshake per colliding key, which is why it rates below the anti-replay
case, but `max_connections` defaults to unlimited. Note the hash lives in a
public installed header, so keying it needs a per-endpoint hasher rather than a
`std::hash` specialisation.

*Fix:* per-process random key mixed into the hash.

### M16 — No cap on coalesced packets per datagram
`src/quic_connection.cpp:3162` · Relayed

Roughly 2,200 packets from one GRO-sized datagram, each costing a
header-protection removal and an AEAD open. The authentication-failure counter
caps far too high to act as a brake.

*Fix:* cap iterations per datagram, or bound processing by a byte budget.

---

## Low

| # | Finding | Location | Evidence |
|---|---|---|---|
| L1 | `RESET_STREAM` regresses the terminal `data_read` state; §3.2 makes it terminal | `stream.h:275` | Relayed |
| L2 | STREAM data past the final size accepted after a reset instead of `FINAL_SIZE_ERROR` | `stream.h:194` | Relayed |
| L3 | Locally-initiated streams are never freed; `reap_finished` skips them | `streams.h:517` | Relayed |
| L4 | Previous-generation read keys never discarded; §6.5 asks for ~3 PTO | `quic_connection.cpp:1675` | Relayed |
| L5 | A reserved-bits violation during key update is swallowed and the update not committed | `quic_connection.cpp:1984` | Relayed |
| L6 | No packet-number exhaustion check; becomes load-bearing once M10 is fixed | `quic_connection.cpp:2785` | Relayed |
| L7 | No rate limit on peer-forced key updates; §6.2 offers exactly this mitigation | `quic_connection.cpp:1669` | Relayed |
| L8 | Path validation failure never reverts to the last validated address (§9.3.2) | `path.h:155` | Relayed |
| L9 | `disable_active_migration` decoded but never enforced — inert configuration | `transport_parameters.h:392` | Relayed |
| L10 | `retry_source_connection_id` §7.3 cross-check absent (all three MUST rules) | `quic_connection.cpp:1082` | Relayed |
| L11 | Stateless-reset allowance spent before the validity checks that can decline | `quic_endpoint.cpp:346` | Relayed |
| L12 | Received DATAGRAM frames queue without a count limit | `quic_connection.cpp:355`, `:1510` | Relayed |
| L13 | A zero handshake-flight limit is treated as unlimited — fails open | `quic_tls.cpp:875` | Relayed |
| L14 | `connect()` dereferences a null address two lines after handling it as nullable | `quic_endpoint.cpp:716` vs `:739` | Relayed |
| L15 | `~cancellation_t` leaves outstanding registrations dangling | `cancellation.h:114` | Relayed |
| L16 | `anti_replay_t` is unsynchronised with undocumented thread affinity | `anti_replay.h:146` | Relayed |
| L17 | `steady_clock` injected into `tick_t`, which `tick.h` forbids | `quic_tls.cpp:377` | Confirmed |
| L18 | `grease_quic_bit` not scrubbed from remembered parameters (RFC 9287 §3) | `quic_connection.cpp:2954` | Relayed |

**L17 is worth reading before the others.** It is filed low because the register
is currently the only producer of those ticks, so the code is internally
consistent. It is not theoretical: while writing the regression test for the
full-register case, fillers stamped with `tick_t{}` were swept out by `expire()`
because the callback stamps `steady_clock` — the test passed for free until the
clocks were matched. Either use the loop clock, or document this as the one
sanctioned exception.

---

## One claim that was checked and found false

An agent reported that an attacker always chooses the server's local connection
ID through `config.local_connection_id_override`. That assignment is gated on
`retry_key != nullptr && !header.token.empty()` (`quic_endpoint.cpp:490`), so it
is reachable only on the Retry-answer path. Recorded here so it is not
rediscovered and acted on.

## What is missing structurally

There is no fuzzing harness in the repository. For a hand-rolled parser
consuming arbitrary UDP that is the largest remaining gap, and several items
above — M6, M14, M16, and the whole reassembly family — are the kind a corpus
finds in minutes. `connection_t` is sans-I/O and already takes `tick_t now` as a
parameter, which is most of the work. A seedable RNG and a virtual clock are the
prerequisites; without them a fuzzer finds crashes it cannot reproduce.
