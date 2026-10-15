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

**D3. Files are asynchronous where the kernel allows.** On Linux with io_uring, reads, writes and
`fsync` are ring operations. Everything else goes to vio's blocking pool: all file work on epoll and
macOS, and on Windows for now (D17). macOS has no usable asynchronous file API.

**D4. vio owns a blocking pool, separate from `thread_pool_t`.** It has one queue for files and one
for DNS, so a slow lookup cannot starve file work. The application's `thread_pool_t` aborts on
enqueue after stop and is often full of CPU work, so it is not used.

**D5. One process-wide blocking pool, created on first use, joined at exit.** libuv does the same.
A `getaddrinfo` stuck in the kernel delays exit; detaching threads that may touch freed memory
at exit is worse.

**D6. Socket operation state lives in the awaiter, inside the coroutine frame.** Once a connection
is warm, these allocate nothing per operation: `read_into` on TCP, a TLS read into a caller's
buffer, a borrowed-buffer write on TCP or TLS, `datagram_reader_t` receives, and every send of a
datagram the kernel accepts at once. That is the whole claim. These allocate on every call:
- reads that hand out an owned buffer: `co_await` on `tcp_reader_t` or a TLS `stream_reader_t` (one
  buffer from the allocator callback per read), and `udp_reader_t` (one buffer per datagram, an
  exact-size copy with the default allocator, none with a `buffer_pool_t`);
- an owning `write_tcp` or `send_udp` that has to wait (the payload's holder, plus a
  `udp_send_op_t` for UDP);
- `sleep`, every file operation and every DNS lookup (one reference-counted state through
  `future_t`);
- every operation of the QUIC coroutine layer (a per-call heap operation, by design). `BASELINE.md` counts what that adds up to: 15 to 25 allocations per QUIC request. An
operation that the kernel still holds when it is destroyed aborts the process with a message, in
every build.

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

**D45. Deadlines saturate.** `sleep()` and `timer_rearm()` take any `std::chrono::duration`, clamp
it to the largest nanosecond count, and clamp `now + delay` to the largest deadline, which never
fires. So `sleep(loop, std::chrono::milliseconds::max(), &token)` waits until it is cancelled, as it
did under libuv, whose `uv_timer_start` clamped the same way. Without the clamp the conversion to
nanoseconds overflowed: that sleep finished at once, and a deadline that wrapped negative made the
backend wait for about 292 years while every other timer on the loop starved. The wasm `sleep()`
takes any duration too; browsers and Node treat a timeout above 2^31-1 ms as 1 ms, so it waits in
chunks of that size.

**D48. epoll watches for writability only while a writer waits.** A socket is registered for
reading, edge-triggered. When a write would block, the writer parks and the backend adds `EPOLLOUT`
with `EPOLL_CTL_MOD`, which re-checks readiness, so no edge is lost. A write edge that finds no writer
parked removes it again. Registering both at once woke the loop after every UDP send, because the
kernel signals write space each time a sent datagram is freed: two loop turns per datagram on the
QUIC path. The cost is an `epoll_ctl` to add and another to remove per stalled write. An
`epoll_ctl` or `epoll_wait` failure other than `EINTR` aborts with a message, because the
alternative is a loop that silently stops seeing events; an `epoll_pwait2` the kernel or a seccomp
filter refuses falls back to `epoll_wait` for good.

**D11. Timers with equal deadlines fire in the order they were set.**

**D12. On Linux the backend is chosen at run time.** `VIO_BACKEND=epoll` or `VIO_BACKEND=io_uring`
forces one. A test asserts which backend ran, so a CI job cannot quietly test the wrong one.

**D13. epoll is the default on Linux until io_uring beats it on the benchmarks.** io_uring is
built, tested in CI and selectable. Making it the default is a one-line change once the numbers
justify it. Some deployments forbid io_uring (Android, Docker's default seccomp profile, the
`kernel.io_uring_disabled` sysctl), so epoll must be complete either way. Measured in alternated
runs, the two are level within 3%: with readiness-first sockets io_uring only replaces
`epoll_wait`, which is about 0.1% of the CPU. `BASELINE.md` has the numbers, why, and the
prototypes that did not help.

**D14. io_uring needs Linux 6.1 or newer, and vio talks to it through raw system calls.** 6.1 brings
everything vio wants. Older kernels use epoll. vio carries a small ring class instead of depending
on liburing, which has no CMake build and lags the kernel. libuv, Zig's standard library and
TigerBeetle take the same approach.

**D15. A ring is created with its loop, so create loops after dropping privileges.** Rings
capture the credentials of the thread that creates them; Node's CVE-2024-22017 came from a ring
created before `setuid()`. A ring is also not safe across `fork()`. The ring does not use
`SINGLE_ISSUER` or `DEFER_TASKRUN`: vio builds a loop on one thread and runs it on another
(`thread_with_event_loop_t`), and those flags bind the ring to its creator. It uses
`COOP_TASKRUN` instead.

**D16. Windows sockets use AFD polling for readiness.** It is undocumented, but libuv's `uv_poll`,
mio and wepoll all use it, and vio's datagram reader and QUIC endpoint ran on `uv_poll` on Windows
before this change.
No new risk.

**D17. Windows files use the blocking pool for now.** Overlapped I/O needs a handle opened with
`FILE_FLAG_OVERLAPPED`, and vio's file API hands out CRT file descriptors, as libuv did. Switching
means changing what `native_file_t` is on Windows, so it is a follow-up with its own benchmark.
Linux gets real asynchronous file I/O through io_uring now.

**D18. macOS uses kqueue with `EV_CLEAR` and `EVFILT_USER` for wakes.** Sockets get `SO_NOSIGPIPE`.

**D42. A thread that posts to a loop wakes it before releasing the post lock.** Waking after the
unlock left a gap: the loop could drain the work, finish, and be destroyed while the poster was
still about to touch it. CI's ASan job caught this through a blocking-pool job. Holding the lock
costs one system call inside it, and only the first post after a drain makes that call.

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

**D26. On Windows vio calls `WSAStartup` once. It changes no process-wide error handling.** libuv's
`uv__init` did three things for the whole process as a side effect: `SetErrorMode` to suppress the
critical-error and GP-fault dialogs, a no-op `_set_invalid_parameter_handler`, and in `_DEBUG` builds
a `_CrtSetReportHook`. vio does none of them, and nothing sets `SetErrorMode` for `vio_tests` either.
An application that relied on libuv for those must now set them itself.
The handler mattered for one thing: vio's Windows file API hands out CRT file descriptors (D17), and
the default CRT handler ends the process when a descriptor it does not know reaches `_get_osfhandle`
or `_close`, where under libuv the call failed with `EBADF`. vio now installs a no-op handler for
the current thread only, around exactly those two calls, so a stale or twice-closed descriptor comes
back as `errc::bad_descriptor` again. A debug CRT still reports the bad parameter through
`_CrtDbgReport` first, as it does for every invalid parameter in a debug build.

**D31. `stop()` is sticky.** After `stop()`, every later `run()` returns as soon as nothing is in
flight. Tests rely on calling `run()` again to drain closes they started after the first `run()`
returned.

**D32. Work posted before `stop()` always runs.** Under libuv on Unix it could be dropped if both
arrived in the same wakeup; on Windows it ran. Now it runs everywhere.

**D33. A sleep with a negative duration returns on the next turn.** Under libuv it never fired.

**D34. The QUIC beat and ticker are internal hooks and timers that never keep the loop alive.**
The beat replaces a `uv_unref`ed `uv_prepare_t`. The ticker replaces a referenced 2 ms `sleep()` and
no longer keeps the loop alive, which is safe because the endpoint's reader keeps it alive whenever
`run()` is active.

**D35. Event pipes unlink themselves when destroyed.** They no longer have to outlive `stop()` and
`run()`, and `event_loop_t::add_event_pipe` is gone. Destroy a pipe on its loop's thread, or after
the loop has stopped. A pipe may also outlive its loop, as it could under libuv: a class that
declares its pipes before its `thread_with_event_loop_t` destroys the loop first. The loop owns a
small shared anchor that each pipe holds; destroying the loop clears it, and a pipe destroyed after
that touches nothing. Posting to a pipe whose loop is gone is still a bug.

**D36. Destroying a socket that was never closed aborts with a message.** Sockets live in
reference-counted storage that closes them, so this only fires on a real lifetime bug, and the
alternative is a backend holding a pointer to freed memory.

**D37. The blocking pool starts 4 file threads and 2 DNS threads, on first use.**
`VIO_FILE_THREADS` and `VIO_DNS_THREADS` override the counts.

**D38. `uv_coro.h` becomes `future.h`.** The old name still forwards, so existing includes build.

**D39. Error codes live in `vio::errc` with values from -9001 down; DNS codes from -9101 down.**
The values are fixed on every platform, so a code compiled into prism means the same thing on
Linux, macOS and Windows. They started at -3001, which is inside libuv's `UV_EAI_*` range
(-3000 to -3014): `errc::eof` equalled `UV_EAI_AGAIN`, so a downstream that still compared against
a `UV_*` constant compiled and quietly matched the wrong error. No libuv code is below -4095, and
none is in -9001 to -9999, so a stale comparison now never matches. Every `UV_*` comparison must
still be rewritten against `vio::errc`.

**D40. A comparison benchmark project lives in its own repository.** It compares vio with libuv,
Boost.Asio and Tokio on the same operations. Creating a repository on your account needs your
approval, so its design is in the plan and the repository does not exist yet.

**D44. A write whose token fires before it is awaited reports `vio_cancelled`, even if its bytes
went out.** libuv behaved this way and the `tcp write cancel` test holds it. Cancelled therefore
means "you gave up on this write", not "the peer never saw it"; a caller that cancels a write
should treat the stream as broken. TLS writes follow the same rule.

**D46. Public headers build with exceptions off.** vio has always promised a build with
`-fno-exceptions -fno-rtti`. The port added `try`/`catch` around allocations in five headers, which
GCC and Clang reject outright with exceptions off, so a downstream built that way could not include
DNS, TLS or HTTP. The headers now write `VIO_TRY` / `VIO_CATCH_ALL` from `vio/detail/exceptions.h`:
`try`/`catch (...)` with exceptions on, and with them off a block that always runs and a handler
that never does, which is what a failed allocation does there anyway.

**D47. `datagram_t` is a borrowed view, not an owning value.** Under libuv it held a
`std::vector<std::uint8_t>` and a `sockaddr_storage`. Now `data` is a span and `peer` and `local`
are pointers, all into buffers the reader reuses on its next receive. It stays copyable, because
views are copied freely inside one batch, but a copy does not extend what it points at: code that
queued `*co_await reader` used to own its bytes and now holds a view that the next receive
overwrites with another sender's payload and address. Copy `data` and `*peer` out to keep them.

## Process

**D27. CI runs on every branch push**, on ubuntu-24.04 (debug, ASan, TSan, UBSan, and a shared
library build), macos-15 (debug, ASan) and windows-2025 (debug, ASan). The Linux container runs
without Docker's default seccomp profile, so io_uring is available to test. Two jobs check what the
test suite cannot: `install` builds BoringSSL, ada and vio into one prefix and compiles a
`find_package(vio)` consumer against it, and the Linux and macOS debug jobs build
`vio_header_check`, every public header compiled alone with `-fno-exceptions -fno-rtti`. The CI
image is pushed under its Dockerfile hash from any branch, but only `master` moves `:latest`, the
tag `CLAUDE.md` tells people to pull.

**D28. Dependencies stay at their pinned versions, minus libuv.** Nothing needed a newer version.

**D29. No comments in code.** Names and tests carry the meaning. Prose in documents follows
Orwell's six rules.

**D30. No attribution lines in commits.**

**D41. Tests for internals may live at the bottom of a `src/*.cpp` file**, inside
`#if defined(VIO_INTERNAL_TESTS)`. A top-level static build with tests on compiles the library
sources a second time, with that macro and the doctest implementation, into an object library that
only `vio_tests` links. The first version defined the macro on `libvio` itself, so a default
`cmake --install` shipped an archive carrying doctest, the internal tests and a send-fault hook in
the QUIC send path, and a consumer's own doctest suite ran vio's tests. `libvio` is now always the
library a consumer gets. Shared builds and builds where vio is a subproject leave the macro unset.
The second compile costs about 40 CPU-seconds in a debug build.

**D43. A test that depends on what a kernel does checks for it instead of assuming it.** Three tests
passed on Linux only because of Linux behaviour: one passed a length larger than its buffer and
relied on Linux touching only the pages it fills; one assumed every platform segments UDP sends;
two assumed a 4 MiB send cannot finish at once, which a Windows non-blocking send can. They now
use a buffer as large as the length they claim, probe for segmentation, and stall the socket with
filler writes until one is pending.

## Status

CI run 93 (commit `4abd446`) is green on all ten jobs: Linux debug, ASan, TSan and UBSan, each
on epoll and on io_uring; macOS debug and ASan on kqueue; Windows debug and ASan on IOCP; and a
wasm build whose smoke test runs under Node. Locally,
every test case passes on both Linux backends except seven that need outside network or IPv6
loopback, which this container lacks, and which pass in CI. That suite now includes the sixteen
backend tests of `test/test_backend.cpp`, which sat in the tree without being built and so were
not part of run 93: kqueue and IOCP have not run them yet.

| backend | sockets | files | state |
|---------|---------|-------|-------|
| epoll | readiness, edge-triggered | blocking pool | default on Linux |
| io_uring | readiness through `POLL_ADD` | ring: read, write, `fsync` | `VIO_BACKEND=io_uring` |
| kqueue | readiness, `EV_CLEAR` | blocking pool | macOS |
| IOCP | readiness through AFD | blocking pool (D17) | Windows |
| wasm | none | none | its own small loop; builds, and a smoke test runs under Node in CI |

Benchmarks against libuv are in `BASELINE.md`: the socket rows run 1.4 to 2.3 times faster and
allocate a third to two thirds as much.

## Open questions

- How clocks treat system sleep, per platform. Windows waits skip time spent suspended, and libuv
  woke every loop on resume. That wake is not reproduced yet.
- When io_uring becomes the default on Linux (see D13).
- The wasm backend moves onto the shared core in a later phase. Until then it keeps its own small
  loop. Building it after the change found two breaks: the HTTP client called the native-only
  `loop_now`, and the wasm library did not compile `errc.cpp`, so nothing that built an error
  linked. Both are fixed, and CI now builds the wasm library and runs `test/wasm_smoke.cpp` under
  Node, so the next break shows up at once.
- Whether application coroutines should run inside Win32 modal loops and Cocoa tracking loops. This
  belongs to the GUI driver work.
