# Baseline

Numbers from the libuv build at commit `c1505da`, before any of the event loop work. The new
backends are measured against these.

## Machine

A 4-vCPU cloud container: Intel Xeon @ 2.80 GHz, Linux 6.18, GCC 14.2, Release build. Shared
hardware, so expect a few percent of noise between runs. Each benchmark ran three times.

## Tests

`vio_tests`, one process per test case, Debug build: **620 of 627 pass**. The seven failures all
come from the container, not from vio:

| test | why it fails here |
|------|-------------------|
| DNS address info lookup | no outside network |
| test ssl toy http client | no outside network |
| create_io_manager dispatches on scheme | no outside network |
| tcp ipv6 loopback | no IPv6 loopback |
| udp ipv6 loopback | no IPv6 loopback |
| a dial refuses an address it cannot read | no IPv6 loopback |
| an endpoint reaches an IPv6 peer even with run() started first | no IPv6 loopback |

CI at the same commit: all Linux jobs (debug, ASan, TSan, UBSan) and both Windows jobs pass. macOS
did not build until `c1505da` fixed an ambiguous `task_t`.

## vio_bench (QUIC)

| row | run 1 | run 2 | run 3 |
|-----|-------|-------|-------|
| bulk stream transfer, sans-I/O | 566.8 MB/s | 598.4 MB/s | 588.1 MB/s |
| 512 concurrent streams | 292.3 MB/s | 294.7 MB/s | 297.5 MB/s |
| socket, offload off | 104.2 MB/s | 131.2 MB/s | 128.3 MB/s |
| socket, offload on | 148.1 MB/s | 142.9 MB/s | 141.9 MB/s |
| bulk, callback api | 144.6 MB/s | 149.2 MB/s | 148.6 MB/s |
| bulk, coroutine api (read_into) | 139.3 MB/s | 142.6 MB/s | 120.1 MB/s |
| bulk, coroutine api (owning read) | 145.0 MB/s | 145.4 MB/s | 147.7 MB/s |
| requests, callback api | 38978 req/s | 40201 req/s | 40258 req/s |
| requests, coroutine api | 51578 req/s | 45391 req/s | 52953 req/s |

Allocations: 5.0 per datagram (bulk, sans-I/O), 12.5 per datagram over sockets, 23.1 per request
(callback) and 31.7 per request (coroutine).

## vio_udp_bench (1200-byte datagrams, batches of 32)

| path | send | receive |
|------|------|---------|
| raw `sendmsg`, one at a time | 196 kpps | |
| raw `sendmsg` + `UDP_SEGMENT` | 4282 kpps | |
| raw `sendmmsg` | 185 kpps | |
| `uv_udp_try_send` | 170 kpps | |
| `uv_udp_send` (queued) | 198 kpps | |
| raw `recvmsg` | | 3242 kpps |
| raw `recvmmsg` | | 3311 kpps |
| `uv_udp_recv_start` | | 840 kpps |
| `uv_udp_recv_start` + mmsg | | 1421 kpps |

The receive rows show what libuv's UDP path cost: a quarter to a half of what the raw calls
reach. That gap is the first thing the native datagram path should close.
