# vio without libuv

vio drops libuv and runs on the operating system's own event mechanisms: epoll and io_uring on
Linux, kqueue on macOS, IOCP on Windows. This file is the plan. `DECISIONS.md` lists every choice
made along the way, with the reason, so each one can be reviewed and reversed.

## Goals

1. Keep every feature vio has today.
2. Speed and security come first. Every phase must match or beat the libuv build on the
   benchmarks, and pass the sanitizers, before it lands.
3. No heap allocation per I/O operation once a connection is warm.
4. Window-system events can join the same loop, so a GUI library can be built on vio.
5. Linux, macOS and Windows now. Android and iOS should need only a backend and a driver.
   Emscripten gets a small backend with timers and messaging only.
6. libuv disappears from the public API: no `uv_buf_t`, no `uv_loop_t`, no `UV_E*` codes.

## The shape

One `event_loop_t` per thread. It owns:

- a **backend**: `epoll`, `io_uring`, `kqueue` or `iocp`, chosen at run time on Linux and at
  build time elsewhere;
- a **timer heap** with nanosecond deadlines;
- a **posted queue** that any thread may push to;
- a **ready queue** for work the loop schedules for itself;
- **hooks** that run before the loop blocks and after it wakes;
- a **registry** of open resources, so the loop can name what was leaked when it is destroyed.

One turn of the loop:

1. run timers that are due;
2. run posted work, then ready work;
3. finish closes that completed (storage is freed here, never inside the call that closed it);
4. if `stop()` was called and nothing is in flight, return;
5. run the before-block hooks (the QUIC beat flushes here);
6. wait in the backend until I/O, a wake or the next deadline;
7. dispatch completions, which resume coroutines;
8. run the after-wake hooks.

### Operations live in the coroutine frame

Each awaitable holds an intrusive operation record. The backend finds it by pointer: the
io_uring `user_data`, the `OVERLAPPED` on Windows, or a wait slot on a socket for epoll and kqueue.
The coroutine frame already exists, so starting a read or a write allocates nothing.

```cpp
auto n = co_await vio::read_into(reader, buffer);   // no new, no delete
```

An operation ends only through its completion. Cancel is a request: the awaiter still waits for
the backend to let go. An operation destroyed while the kernel holds it aborts the process with a
message, in every build. A silent use-after-free is the alternative, and that is worse.

### Sockets are readiness-first on every backend

A socket operation tries the system call at once. If the kernel says "would block", the
operation parks on the socket and the backend wakes it when the socket is ready:

| backend  | how it learns a socket is ready                        |
|----------|--------------------------------------------------------|
| epoll    | registered once, edge-triggered, with read and write   |
| kqueue   | registered once, `EV_CLEAR`                            |
| io_uring | one `POLL_ADD` armed when an operation parks           |
| iocp     | an AFD poll, the same mechanism libuv, mio and wepoll use |

Why readiness and not completion for sockets:

- one implementation of TCP, TLS and UDP for all four backends;
- the kernel never holds a caller's buffer, so `cancel()` on `read_into` stays synchronous, which
  prism depends on (it cancels, then reuses the buffer at once);
- data that is already there costs one system call and no wait.

Completion paths (io_uring multishot `recvmsg` with buffer rings, batched sends, overlapped
`WSARecvMsg` with coalescing on Windows) come later, one at a time, and only where a benchmark
shows they win.

### Files are truly asynchronous where the OS allows it

| platform | read, write, fsync          | open, stat, rename, unlink, mkdir |
|----------|-----------------------------|-----------------------------------|
| io_uring | ring operations             | ring operations                   |
| Windows  | overlapped I/O through IOCP | blocking pool                     |
| epoll    | blocking pool               | blocking pool                     |
| macOS    | blocking pool               | blocking pool                     |

The blocking pool is vio's own, separate from the `thread_pool_t` an application uses. It has one
queue for files and one for DNS, so a slow lookup cannot starve file work. The synchronous file
calls stay plain system calls and can run on any thread, as today.

### DNS

`getaddrinfo` and `getnameinfo` run on the blocking pool's DNS queue. Cancel drops the result; a
lookup that has started cannot be stopped, the same as libuv.

### Timers

Deadlines are `steady_clock` nanoseconds in a binary heap. Equal deadlines fire in the order they
were set. The backend wait rounds its timeout up, so the loop never spins on an early wake. This
removes libuv's whole-millisecond rounding: a 2 ms sleep is 2 ms.

### Waking a loop from another thread

The posted queue is a lock-protected list plus a "wake pending" flag. Only the first post after the
loop drains pays for a wake: `eventfd` on Linux, `EVFILT_USER` on macOS, a completion packet on
Windows.

### Closing

`ref_ptr_t` keeps its role. A resource that needs closing registers itself with its storage. When
the last reference goes, each resource starts its close. The storage is freed only after every
close has finished, on a later turn. This is libuv's rule, and code in vio relies on it: an object
can drop its own last reference inside one of its own callbacks.

### Datagrams

UDP reception becomes a batch with metadata in the type:

```cpp
auto batch = co_await socket.receive();
for (const vio::datagram_t &d : *batch)
  handle(d.data, d.peer, d.local, d.ecn, d.segment_size);
```

The socket lends the buffers. They stay valid until the next `receive()`. Under ASan they are
poisoned when returned, so a view kept too long fails loudly. The epoll backend fills the batch
with `recvmmsg`; others use a `recvmsg` loop until the completion paths arrive.

### GUI drivers

`event_loop_t` exposes what a host loop needs to drive it: a native handle to watch (the epoll fd,
the kqueue fd, the IOCP handle through a forwarder thread), the next deadline, and a call that runs
one turn without blocking. A window library supplies the driver. Linux needs nothing more than the
display fd in the same epoll set.

## Public API changes

| before                                   | after                                              |
|------------------------------------------|----------------------------------------------------|
| `uv_buf_t`                               | `std::span<std::byte>` / `std::span<const std::byte>` |
| `unique_buf_t::buf.base`, `.len`         | `unique_buf_t::data()`, `size()`, `span()`         |
| `UV_EOF`, `UV_ECANCELED`, other `UV_E*`  | `vio::errc::eof`, `vio::errc::canceled`, ...       |
| `uv_strerror(code)`                      | `vio::error_message(code)`                         |
| `event_loop_t::loop()`                   | removed                                            |
| `uv_stat_t`                              | `vio::file_stat_t`                                 |
| `uv_file`, `uv_os_fd_t`                  | `vio::native_file_t`, `vio::native_socket_t`       |
| `UV_TCP_REUSEPORT`, `UV_UDP_*` flags     | `vio::tcp_bind_flags`, `vio::udp_bind_flags`       |
| `*_state_t::uv_handle`, `get_tcp()` etc. | removed; `peer_ip(tcp_t &)` and friends instead   |
| `uv_tls_stream_t`                        | `tls_stream_t`                                     |
| `uv_coro.h`                              | `future.h`                                         |

`error_t` keeps its shape (`int code`, `std::string msg`). The codes become vio's own fixed
numbers, the same on every platform.

## Phases

Each phase ends with the full test suite green on every backend it touches, the sanitizers clean,
and the benchmarks recorded next to the baseline.

| phase | work | verified by |
|-------|------|-------------|
| 0 | CI on Linux, macOS, Windows; baseline tests and benchmarks | CI, `BASELINE.md` |
| 1 | core loop, timers, posting, closing, error and buffer types; epoll backend; blocking pool | new unit tests |
| 2 | port every operation: TCP, TLS, UDP, datagrams, files, DNS, work, sleep, timer, QUIC edge, HTTP, object store; port tests and examples | full suite on epoll |
| 3 | io_uring backend: readiness sockets, ring file I/O | full suite with `VIO_BACKEND=io_uring` |
| 4 | kqueue backend | macOS CI |
| 5 | IOCP backend: AFD readiness, overlapped files | Windows CI |
| 6 | delete libuv from the build, the docs and `vioConfig` | all CI |
| 7 | completion fast paths, one at a time | benchmark per change |
| 8 | GUI drivers in the window library; wasm on the shared core; Android, iOS | per platform |

Phases 1 to 6 happen on one branch, because the public API changes at once for prism and points.

## Tests

- The existing suite, run on each backend. On Linux, `VIO_BACKEND=epoll` and `VIO_BACKEND=io_uring`
  force a backend; a test asserts which one was chosen, so CI cannot fall back silently.
- New unit tests for the core: timer order, posting from many threads, close ordering, stop with
  work in flight, wake coalescing, the abort on a destroyed in-flight operation.
- Tests for gaps the inventory found: posting then stopping, cancel then reuse of a `read_into`
  buffer, about-to-block listeners added and removed from other threads, a reader closed before
  its socket, GSO under a full send buffer.
- Tests for code that is not part of the public API live at the bottom of its `.cpp` file, in a
  doctest block.

## Benchmarks

`vio_bench` (QUIC per packet and over sockets), `vio_udp_bench`, TLS bulk transfer, loop wake
latency and timer accuracy. The numbers go in `BASELINE.md` with the machine they came from. A
shared CI runner is too noisy to judge speed, so CI only checks that the benchmarks still run.

## Comparison benchmarks

A separate repository measures vio against libuv, Boost.Asio and Tokio on the same work, on the
same machine, with the same payloads:

- TCP echo and pipelined request/response, one connection and many;
- TLS bulk transfer;
- UDP datagram batches, with and without GSO;
- file reads and writes, buffered and direct;
- timers: accuracy and cost per timer;
- waking a loop from another thread.

Each library gets the idiomatic version of each test, written by someone who would defend it.
Results go in a table with the machine, kernel and versions. The repository needs your approval
before it is created.

## Not in this work

- The window library itself.
- The JS-like `fetch` library for C++ and the browser.
- Android and iOS ports.
- Completion fast paths without a benchmark that justifies them.
