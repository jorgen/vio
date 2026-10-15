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

## After: vio on its own event loop

Commit `8dc7ee9`, Release build, same machine. The two builds ran turn about, three times each,
so both saw the same load: about 2 on 4 vCPUs, because a code review was running beside them.
Treat a difference under 20% as noise; the sans-I/O rows, which never touch the event loop, move
that much between runs.

### vio_bench (QUIC), medians, epoll

| row | libuv | native | ratio |
|-----|-------|--------|-------|
| bulk stream transfer, sans-I/O | 388 MB/s | 462 MB/s | noise |
| 512 concurrent streams | 184 MB/s | 201 MB/s | noise |
| socket, offload off | 108 MB/s | 152 MB/s | 1.4x |
| socket, offload on | 133 MB/s | 250 MB/s | 1.9x |
| bulk, callback api | 129 MB/s | 222 MB/s | 1.7x |
| bulk, coroutine api (read_into) | 133 MB/s | 303 MB/s | 2.3x |
| bulk, coroutine api (owning read) | 138 MB/s | 315 MB/s | 2.3x |
| requests, callback api | 34981 req/s | 77511 req/s | 2.2x |
| requests, coroutine api | 41509 req/s | 50925 req/s | 1.2x |

Allocations fell with it: 12.5 per datagram over sockets became 3.3 (callback) and 3.6
(coroutine); 23.1 per request became 15.2 (callback), and 31.7 became 24.5 (coroutine).

io_uring, run separately: the socket rows land within noise of epoll. Sockets are
readiness-first on both, so io_uring only replaces `epoll_wait`, and that is not where the time
goes. It stays off by default (D13).

### vio_udp_bench, epoll

| path | libuv | native |
|------|-------|--------|
| raw `recvmmsg` (the ceiling) | 3462 kpps | 4000 kpps |
| `uv_udp_recv_start` | 1104 kpps | |
| `uv_udp_recv_start` + mmsg | 957 kpps | |
| `udp_reader_t`, pooled | | 896 kpps |
| `udp_reader_t`, pooled + mmsg | | 1070 kpps |
| `datagram_reader_t` | | 4112 kpps |
| `datagram_reader_t`, batch | | 3172 kpps |

`datagram_reader_t` now reaches the raw `recvmmsg` ceiling, about 3.7 times what libuv's
receive path managed. The older `udp_reader_t` hands out one owned buffer per datagram and stays
where libuv was. Sends were bound by the kernel before and still are: every path is within noise
of the raw call it makes.
