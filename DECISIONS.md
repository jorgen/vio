# Decisions

Choices made while taking libuv out of vio. Each has a reason and a way back. The plan is in
`EVENT_LOOP_PLAN.md`.

## Architecture

**D1. Sockets are readiness-first on every backend.** An operation tries the system call, and
parks on the socket only if the kernel says it would block. epoll and kqueue report readiness
natively; io_uring arms a `POLL_ADD`; Windows uses an AFD poll.
*Why:* one implementation of TCP, TLS and UDP; `cancel()` stays synchronous because the kernel
never holds a caller's buffer (prism cancels a `read_into` and reuses the buffer at once); data
already waiting costs one call and no wait.
*Way back:* completion paths can replace any operation on any backend without changing the API.

**D2. Completion paths come later, and only with a benchmark.** io_uring multishot `recvmsg`,
batched sends, zero-copy sends and overlapped `WSARecvMsg` with coalescing are all good candidates.
None goes in without a `vio_bench` row that shows the gain.

**D3. Files are asynchronous where the kernel allows.** io_uring ring operations on Linux; overlapped
`ReadFile`/`WriteFile` through IOCP on Windows. Everything else goes to vio's blocking pool. macOS
has no usable asynchronous file API, so it uses the pool for all file work.

**D4. vio owns a blocking pool, separate from `thread_pool_t`.** It has one queue for files and one
for DNS, so a slow lookup cannot starve file work. The application's `thread_pool_t` aborts on
enqueue after stop and is often full of CPU work, so it is not used.

**D5. One process-wide blocking pool, created on first use, joined at exit.** libuv does the same.
A `getaddrinfo` stuck in the kernel delays exit; detaching threads that may touch freed memory
at exit is worse.

**D6. Operation state lives in the awaiter, inside the coroutine frame.** No allocation per
operation. An operation that the kernel still holds when it is destroyed aborts the process with a
message, in every build.

**D7. Closes finish on a later turn, never inside the call that closed.** libuv works this way and
vio code depends on it: an object may drop its own last reference inside its own callback.

**D8. `run()` after `stop()` returns once nothing is in flight.** In flight means a parked
operation, an armed timer that keeps the loop alive, a blocking-pool job or an unfinished close.
Posted work keeps running until then. An open but idle socket does not keep the loop alive; the
destructor still names it as leaked.

**D9. about-to-block listeners stop firing after `stop()`.** That matches libuv, where the
listener handle is closed by `stop()`. Adding and removing listeners stays posted and in order with
`run_in_loop`, because points removes one from another thread and then waits on a barrier.

**D10. One clock.** Timers and `loop_now()` both use `steady_clock` in nanoseconds. libuv used a
coarse millisecond clock for timers and a fine one for `loop_now()`. Timers now fire on time instead
of up to a millisecond early or late. How the clock treats system sleep is unchanged and is listed
under open questions.

**D11. Timers with equal deadlines fire in the order they were set.**

**D12. On Linux the backend is chosen at run time.** `VIO_BACKEND=epoll` or `VIO_BACKEND=io_uring`
forces one. A test asserts which backend ran, so a CI job cannot quietly test the wrong one.

**D13. epoll is the default on Linux until io_uring beats it on the benchmarks.** io_uring is
built, tested in CI and selectable. Making it the default is a one-line change once the numbers
justify it. Some deployments forbid io_uring (Android, Docker's default seccomp profile, the
`kernel.io_uring_disabled` sysctl), so epoll must be complete either way.

**D14. io_uring needs Linux 6.1 or newer, and vio talks to it through raw system calls.** 6.1 brings
everything vio wants. Older kernels use epoll. vio carries a small ring class instead of depending
on liburing, which has no CMake build and lags the kernel. libuv, Zig's standard library and
TigerBeetle take the same approach.

**D15. Rings are created after the loop starts.** Rings capture the credentials of the thread that
creates them, and Node's CVE-2024-22017 came from a ring created before `setuid()`. A ring is also
not safe across `fork()`. Both facts are documented.

**D16. Windows sockets use AFD polling for readiness.** It is undocumented, but libuv's `uv_poll`
uses it, and vio already depends on `uv_poll` on Windows, as do mio and wepoll. No new risk.

**D17. Windows files use overlapped I/O with `FILE_SKIP_COMPLETION_PORT_ON_SUCCESS`.** Opening a
file and changing metadata have no overlapped form and go to the blocking pool.

**D18. macOS uses kqueue with `EV_CLEAR` and `EVFILT_USER` for wakes.** Sockets get `SO_NOSIGPIPE`.

## Public API

**D19. `error_t` keeps its shape: `int code`, `std::string msg`.** The codes become vio's own, in
`vio::errc`, with fixed values that are the same on every platform. `vio::error_message(code)`
replaces `uv_strerror`. vio's existing codes (`vio_cancelled`, the TLS and QUIC codes) keep their
values. Changing `code` to an enum would have touched every error in the QUIC and object-store code
for no gain.

**D20. Buffers are `std::span<std::byte>` and `std::span<const std::byte>`.** `unique_buf_t` owns
its memory and exposes `data()`, `size()` and `span()`.

**D21. `sockaddr` stays in the API.** It is an operating-system type, not a libuv one. A vio address
type would be nicer but is a separate change.

**D22. `event_loop_t::loop()` is gone with no replacement.** points used it only to call
synchronous file functions; vio's own synchronous file calls cover that.

**D23. Synchronous file calls stay plain system calls, callable from any thread.** A ring tied to one
thread would make them fail elsewhere.

**D24. `SO_REUSEPORT` is refused where it does not balance load,** which is everywhere except Linux.
That matches libuv, and prism depends on it to decide how many listeners to start.

**D25. The process keeps ignoring `SIGPIPE`.** The event loop constructor did this under libuv, and
child processes inherit it. Sockets also set `MSG_NOSIGNAL` or `SO_NOSIGPIPE`.

**D26. On Windows vio calls `WSAStartup` once. It does not call `SetErrorMode`.** libuv changed the
process error mode as a side effect. A library should not, so the test program sets it instead.

## Process

**D27. CI runs on every branch push**, on ubuntu-24.04 (debug, ASan, TSan, UBSan), macos-15
(debug, ASan) and windows-2025 (debug, ASan). The Linux container runs without Docker's default
seccomp profile, so io_uring is available to test.

**D28. Dependencies stay at their pinned versions, minus libuv.** Nothing needed a newer version.

**D29. No comments in code.** Names and tests carry the meaning. Prose in documents follows
Orwell's six rules.

**D30. No attribution lines in commits.**

## Open questions

- How clocks treat system sleep, per platform. Windows waits skip time spent suspended, and libuv
  woke every loop on resume. That wake is not reproduced yet.
- When io_uring becomes the default on Linux (see D13).
- The wasm backend moves onto the shared core in a later phase. This change keeps it compiling but
  it has no CI.
- Whether application coroutines should run inside Win32 modal loops and Cocoa tracking loops. This
  belongs to the GUI driver work.
