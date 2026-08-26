# QUIC: where it stands

A status and roadmap note. `CLAUDE.md` holds the design and the reasoning
behind it; `SECURITY_BACKLOG.md` holds the open findings. This is the short
answer to "what works, what doesn't, and what would I do next".

Last updated 26 August 2026.

## Done

**The base specification is complete.** All 20 RFC 9000 frame types and all 17
transport parameters, loss recovery and congestion control per RFC 9002, packet
protection and key update per RFC 9001. **QUIC v2 (RFC 9369)** on both sides,
selected from the version rather than duplicated.

**Extensions**: DATAGRAM (RFC 9221), grease_quic_bit (RFC 9287), CUBIC
(RFC 9438) alongside NewReno, and path MTU discovery (RFC 8899 as §14.3 applies
it).

**Session resumption and 0-RTT** (RFC 9001 §4.6, RFC 8446 §8), with a
fail-closed anti-replay register. Two separate knobs, because they are two
features: resumption shortens a handshake and carries no replay exposure; early
data implies it. A server with early data and no register is refused a context
rather than silently never granting 0-RTT.

**Interoperates with picoquic in both directions**, including through a Retry:
12/12 cases covering v1, v2, ChaCha20, HelloRetryRequest, large ClientHello,
short connection IDs, CUBIC, preemptive repeat, version upgrade, spin bit,
ticket issue and 0-RTT. Also drives the QUIC Interop Runner harness
(`test/interop_endpoint.cpp`) as both roles.

**529 tests**, clean under ASan, UBSan and TSan, and clean on MSVC.

## The August 2026 security review

Nine parallel audits over ~16,400 lines produced **51 findings**. All three
critical and all thirteen high items are fixed, each with a regression test
**confirmed to fail with its fix reverted** — which is the only thing that makes
a regression test worth having.

The three criticals were each one packet to trigger:

- A Version Negotiation packet was answered with another one. Every reply was
  itself a valid trigger, so two endpoints pointed at each other never stopped.
- No handshake timeout existed. The idle timeout is negotiated, so it does not
  exist until the peer's transport parameters arrive — a handshake that never
  got that far was never reaped, and one spoofed Initial bought a connection for
  the life of the process.
- `active_connection_id_limit` was validated only from below and then used as a
  loop bound, with a random draw and an HMAC per iteration. One transport
  parameter froze the whole endpoint.

The thirteen high items covered 0-RTT (a client decrypted its own reflected
0-RTT packet with its own write key; the ticket lifetime was 288× the
anti-replay window that was supposed to cover it), an `ack_delay` overflow that
inverted the RTT estimate into a negative PTO, unvalidated address tokens
buying connections, missing fragment caps on both reassemblers, and four stream
state-machine defects.

Two of those findings were properties this repository's own documentation
claimed to hold and did not. That is worth remembering when reading any
assertion here: the comment is the intent, not the evidence.

## Where the performance sits

Measured 26 August 2026 — 300 Mbit / 20 ms RTT, picoquicdemo as the single
client against all three servers over `hq-interop`, 7 reps, medians in Mbps:

| | 4 MB | 16 MB | 64 MB |
|---|---|---|---|
| picoquic (BBR, its default) | 174 | 243 | 269 |
| picoquic (NewReno) | 163 | 217 | 262 |
| **vio (CUBIC)** | 114 | 205 | **258** |
| **vio (NewReno)** | 113 | 204 | **257** |
| quiche (CUBIC, its default) | 59 | 120 | 206 |
| quiche (BBR) | 62 | 131 | 201 |

At 64 MB vio is within 1.5% of picoquic on the same controller and ahead of
quiche by about a quarter. The implementation is not what is costing anything.
What remains is the **ramp**: picoquic leads by 40–50% at 4 MB, ~15% at 16 MB,
~2% at 64 MB, which is the shape of a startup difference rather than a
throughput one.

Two cautions if you repeat this. picoquic's small-transfer figure is bimodal and
moves between sessions, so treat the 4 MB row as a range for picoquic and not a
point; vio was the most stable of the three at ±0.4–2%. And quiche needs its
`--max-data` / `--max-stream-data` raised above the defaults or it is
handicapped, so its position is indicative rather than settled.

The security fixes cost nothing: an A/B of the pre-review tree against the
current one put 4 MB medians identical and 64 MB 0.3% apart, inside the spread.

## What is left

**In rough order of what I would do next.**

1. **A fuzzing harness.** There is none — no `LLVMFuzzerTestOneInput`, no AFL.
   For a hand-rolled parser consuming arbitrary UDP this is the largest
   structural gap, and several open findings are the kind a corpus finds in
   minutes. `connection_t` is sans-I/O and already takes `tick_t now` as a
   parameter, which is most of the work; the prerequisites are a seedable RNG
   and a virtual clock, without which a fuzzer finds crashes it cannot
   reproduce. Stateless parser targets first, then a stateful one that treats
   the input as the *plaintext* frame payload and protects it with real keys, so
   every input reaches frame processing instead of bouncing off the AEAD.

2. **The 35 open findings** in `SECURITY_BACKLOG.md` — 16 medium, 19 low. Each
   carries the evidence strength it was recorded at; "relayed" means verify
   before fixing, because the review was machine-assisted and one of its claims
   was checked and found false.

3. **HTTP/3 and QPACK**, which belong in prism rather than here, per the
   architecture. This is the next piece of work.

4. **BBR**, if small-transfer throughput ever matters. The benchmark says it is
   worth roughly 40% at 4 MB and almost nothing at 64 MB, so it is a latency
   feature rather than a throughput one. The delivery-rate estimator it would
   need already exists (`delivery_rate.h`) and nothing currently consumes it.

**Deliberately not done**, with reasons: ACK_FREQUENCY is a moving draft whose
codepoints have shifted, and measurement showed vio already receives fewer
acknowledgements than picoquic, so it would buy control rather than throughput.
Compatible version negotiation (RFC 9368), preferred_address, timestamps and
multipath are all unimplemented; no two of picoquic, msquic and quiche agree on
having them either. The spin bit is hardcoded off, which §17.4 permits.

## Repeating any of this

- **Interop**: build `vio_interop_server`, run picoquicdemo against it. The SNI
  is not optional — without `-n` picoquic will not store a session ticket, so
  every resumption and 0-RTT case silently tests nothing.
- **Benchmarks**: `tc qdisc replace dev lo root netem delay 10ms rate 300mbit
  limit 1000`. The `limit` is mandatory; a bare `delay` has no queue, so
  HyStart cannot work by construction. Remove the qdisc before any download.
  `VIO_CC=cubic` selects the controller without a rebuild.
- **Comparing two revisions** without touching the working tree:
  `git archive <sha> | tar -x -C /tmp/old`, then symlink the gitignored
  `3rdparty` in so dependencies are not refetched.
