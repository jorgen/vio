# vio

**vio** is a lean C++23 async I/O library: [libuv](https://libuv.org) for the
event loop, **C++20 coroutines** for the programming model, and
[LibreSSL](https://www.libressl.org) for TLS. You write straight-line
`co_await` code; vio drives it on a single-threaded event loop without callbacks
or blocking.

```cpp
#include <vio/operation/tls_client.h>
#include <vio/run.h>

int main()
{
  return vio::run([](vio::event_loop_t &loop) -> vio::task_t<int>
  {
    auto client = vio::ssl_client_create(loop);
    if (!client) co_return 1;

    if (auto c = co_await vio::ssl_client_connect(client.value(), "example.com", 443); !c)
      co_return 1;

    std::string req = "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
    uv_buf_t buf{.base = req.data(), .len = req.size()};
    co_await vio::ssl_client_write(client.value(), buf);

    auto reader = vio::ssl_client_create_reader(client.value()).value();
    for (;;)
    {
      auto chunk = co_await reader;              // std::expected<unique_buf_t, error_t>
      if (!chunk) break;                          // EOF or error
      std::fwrite(chunk->buf.base, 1, chunk->buf.len, stdout);
    }
    co_return 0;
  });
}
```

It's the async runtime under [prism](https://github.com/jorgen/prism) (a C++23
REST service library), but stands alone as a general-purpose networking toolkit.

## Highlights

- **Coroutines, not callbacks.** Every operation is a `co_await`-able that
  resolves to `std::expected<T, error_t>` — no error callbacks, no manual state
  machines. Errors are values, so vio builds cleanly with **`-fno-exceptions`
  `-fno-rtti`** (its `task_t` calls `std::terminate` on an unhandled exception
  rather than propagating).
- **TCP, TLS, UDP, DNS, files, timers, a thread pool, and event pipes** — one
  uniform coroutine surface over libuv.
- **TLS** via LibreSSL through a compile-time SSL-backend seam (OpenSSL/BoringSSL
  reserved), with ALPN, SNI, OCSP stapling, and session resumption.
- **Cancellation & timeouts** are first-class: pass a `cancellation_t*` to any
  cancellable op and cancel it from a watchdog coroutine.
- **Backpressure-aware reads**: a queue reader, a **zero-copy `read_into`** that
  lands socket bytes straight in your buffer, and explicit `pause()`/`resume()`.
- **Header-mostly**, C++23, MIT-licensed. Runs on Linux, macOS, Windows (MSVC),
  and WebAssembly (Emscripten).

## Getting started

### The entry point

Two ways to start a loop and run a root coroutine:

```cpp
#include <vio/run.h>

// (1) vio::run — takes a callable returning task_t<T>; runs it to completion on a
// fresh loop and returns its result. The loop stops when the coroutine finishes.
int main()
{
  return vio::run([](vio::event_loop_t &loop) -> vio::task_t<int> { co_return 0; });
}

// (2) VIO_MAIN — generates main() for you; the body is a task_t<int> coroutine
// with `loop`, `argc`, `argv` in scope. Boilerplate-free.
VIO_MAIN(loop, argc, argv)
{
  co_await vio::sleep(loop, std::chrono::milliseconds{100});
  co_return 0;
}
```

### A timer

```cpp
#include <chrono>
#include <print>
#include <vio/operation/sleep.h>
#include <vio/run.h>

VIO_MAIN(loop, argc, argv)
{
  for (int i = 3; i > 0; --i)
  {
    std::println("{}...", i);
    co_await vio::sleep(loop, std::chrono::seconds{1});
  }
  std::println("liftoff");
  co_return 0;
}
```

See [`examples/hello_timer.cpp`](examples/hello_timer.cpp).

## Core concepts

### `event_loop_t`

The libuv loop. Created once (by `vio::run`, or directly); `run()` blocks until
`stop()`. Operations take it (or reach it through their handle) to register work.
On WASM there is no blocking `run()`/`vio::run` — drive the loop with
`event_loop_t::run_in_loop` instead.

### `task_t<T>`

An **eager** coroutine: it starts running when called and suspends at the first
real `co_await`. `co_await`-ing one yields its `T`. Because an unhandled exception
in a `task_t` calls `std::terminate` (never propagates), vio is usable from
exception-free code. Detached fire-and-forget work uses `detached_task_t`, which
frees its own frame on completion.

### Results & errors

Every fallible operation returns `std::expected<T, vio::error_t>`, where
`error_t { int code; std::string msg; }`. Check `.has_value()` / `if (result)`,
read `result.value()` / `result.error()`. Cancellation surfaces as an error;
test it with `vio::is_cancelled(err)` (code `UV_ECANCELED` / `vio_cancelled`).

### Cancellation & timeouts

Cancellable operations take a trailing `cancellation_t*`. The idiom is a
**watchdog**: run the op, race it against a `vio::sleep` on a shared token, and
cancel whichever loses.

```cpp
vio::cancellation_t token;
auto watchdog = [](vio::event_loop_t &el, vio::cancellation_t &tok,
                   std::chrono::milliseconds d) -> vio::task_t<void>
{
  if (auto fired = co_await vio::sleep(el, d, &tok); fired && !tok.is_cancelled())
    tok.cancel();                        // deadline hit -> cancel the real op
}(loop, token, std::chrono::seconds{5});

auto result = co_await vio::write_tcp(sock, data, len, &token);
token.cancel();                          // op won the race -> stop the watchdog
co_await std::move(watchdog);            // both stop AND settle, every path
```

### The dangling-`this` rule (important)

A coroutine's frame outlives the statement that created it, so a **coroutine
lambda that captures by reference (including `this`) is a use-after-free waiting
to happen** — the captured storage may be gone by the time the coroutine
resumes. Prefer **free-function coroutines that take their dependencies by
value** (the values live in the coroutine frame), or capture by value / a
`shared_ptr`. This is the single most common vio footgun.

## Operations

| Area | Header | Entry points (see examples for exact usage) |
|---|---|---|
| **TCP client** | `operation/tcp.h` | `tcp_create`, `tcp_connect`, `tcp_create_reader`, `write_tcp` |
| **TCP server** | `operation/tcp_server.h` | `tcp_create_server`, `tcp_bind`, `tcp_listen`, `tcp_accept`, `sockname` |
| **TLS client** | `operation/tls_client.h` | `ssl_client_create`, `ssl_client_connect`, `ssl_client_write`, `ssl_client_create_reader` |
| **TLS server** | `operation/tls_server.h` | `ssl_server_*` + `ssl_config_t` (cert/key, ALPN); handshake, `ssl_server_client_alpn_selected` |
| **UDP** | `operation/udp.h` | `udp_create`, `udp_bind`, send / `udp_create_reader` |
| **DNS** | `operation/dns.h` | async `getaddrinfo` |
| **Files** | `operation/file.h` | open / read / write / stat / close |
| **Timers** | `operation/sleep.h` | `vio::sleep(loop, ms, cancel?)` |
| **Thread pool** | `thread_pool.h` | `thread_pool_t` — offload blocking work off the loop |
| **Event pipes** | `awaitable_event_pipe.h` | cross-coroutine / cross-thread signalling |
| **Addresses** | `operation/tcp.h` | `ip4_addr`, `ip6_addr` |

### TCP client + server

```cpp
// server: accept one client, echo one message
auto server = vio::tcp_create_server(loop).value();
vio::tcp_bind(server, addr);
co_await vio::tcp_listen(server, /*backlog=*/128);
auto client = vio::tcp_accept(server).value();

auto reader = vio::tcp_create_reader(client).value();
auto in = co_await reader;                         // std::expected<unique_buf_t, error_t>
if (in) co_await vio::write_tcp(client, reinterpret_cast<const uint8_t *>(in->base), in->len);
```

`write_tcp` has an **owning overload** — move in any contiguous byte range
(`std::string`, `std::vector<std::byte>`, …) and vio keeps it alive for the
in-flight `uv_write`, so a cancelled write is UAF-free without a copy. Full
client+server round-trip: [`examples/tcp_echo.cpp`](examples/tcp_echo.cpp).

### Reading: queue, `read_into` (zero-copy), and backpressure

A `tcp_reader_t` supports three modes over one subscription:

- **`co_await reader`** — the queue path: yields an owned `unique_buf_t` per read.
- **`reader.read_into(std::span<std::byte> dst)`** — a scatter read that lands
  socket bytes **directly in your buffer** (true zero-copy; libuv reads into
  `dst`), resolving to `std::expected<std::size_t, error_t>` (`0` == EOF). After a
  direct read the reader is left **paused**, so libuv never buffers ahead — the
  pull cadence is the backpressure.
- **`reader.pause()` / `reader.resume()`** — explicit start/stop of delivery.

```cpp
std::array<std::byte, 64 * 1024> buf{};
for (;;)
{
  auto n = co_await reader.read_into(std::span<std::byte>(buf.data(), buf.size()));
  if (!n || n.value() == 0) break;                 // EOF or error
  process(buf.data(), n.value());                   // reuse one buffer, no per-read alloc
}
```

See [`examples/tcp_read_into.cpp`](examples/tcp_read_into.cpp). (TLS readers
decrypt directly into a caller buffer via `reader.read(uv_buf_t)`; they can't be
truly zero-copy since libuv only ever sees ciphertext.)

### TLS

Client: [`examples/https_get.cpp`](examples/https_get.cpp) and
[`examples/https_fetch.cpp`](examples/https_fetch.cpp). A server binds an
`ssl_config_t` (cert/key files + ALPN list), finishes the handshake, and reads
the negotiated ALPN token to route protocols — see prism's TLS/HTTP2 server for a
full example.

## Building

Requires a C++23 compiler and CMake ≥ 3.30.

```bash
cmake --preset debug
cmake --build cmake-build-debug
./cmake-build-debug/test/vio_tests          # doctest suite
```

The presets pin `ninja` to a homebrew path (macOS-oriented). On Linux, configure
explicitly with your generator, e.g.:

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build
```

### Sanitizers

Presets `asan`, `tsan`, `ubsan` (the whole suite is sanitizer-clean):

```bash
cmake --preset asan && cmake --build cmake-build-asan && ./cmake-build-asan/test/vio_tests
```

### WebAssembly

Builds under Emscripten (`library_wasm.cpp`, no third-party deps). `vio::run` is
unavailable on WASM — drive `event_loop_t` directly via `run_in_loop`.

## Dependencies

Fetched at configure time via [cmake-dep](https://github.com/jorgen/cmake-dep):
**libuv**, **LibreSSL**, **ada** (URL parsing), **doctest** (tests), and
**cmakerc** (embedded default CA bundle). Each is togglable and overridable:

- `VIO_USE_SYSTEM_{LIBUV,LIBRESSL,ADA,DOCTEST,CMAKERC}` — consume a pre-installed
  copy via `find_package` instead of fetching.
- `VIO_<DEP>_VERSION` / `VIO_<DEP>_URL` / `VIO_<DEP>_SHA256` — fetch a different
  version without editing the packages file, e.g.
  `-DVIO_LIBRESSL_VERSION=4.0.0 -DVIO_LIBRESSL_URL=… -DVIO_LIBRESSL_SHA256=…`.

## Consuming vio

**FetchContent** (bundled deps, simplest):

```cmake
include(FetchContent)
FetchContent_Declare(vio
  GIT_REPOSITORY https://github.com/jorgen/vio.git
  GIT_TAG master)
FetchContent_MakeAvailable(vio)
target_link_libraries(my_app PRIVATE vio::vio)
```

**Installed / `find_package`**: build vio with `VIO_INSTALL=ON` **and** against
system deps (`-DVIO_USE_SYSTEM_LIBUV=ON …`) — in that configuration it installs a
relocatable `find_package(vio)` config (`find_dependency`s libuv/LibreSSL/ada):

```cmake
find_package(vio CONFIG REQUIRED)
target_link_libraries(my_app PRIVATE vio::vio)
```

`VIO_BUILD_TESTS` / `VIO_BUILD_EXAMPLES` (default ON) and `VIO_BUILD_SHARED`
(default OFF, static) round out the knobs. A consumer that `add_subdirectory`s
vio should force `VIO_INSTALL OFF`.

## Examples

All under [`examples/`](examples/):

| File | Shows |
|---|---|
| `hello_timer.cpp` | `VIO_MAIN` + `vio::sleep` — the minimal program |
| `tcp_echo.cpp` | TCP server + client round-trip |
| `tcp_read_into.cpp` | zero-copy `read_into` + pause/resume backpressure |
| `udp_echo.cpp` | UDP send/receive |
| `https_get.cpp` / `https_fetch.cpp` | TLS client, ALPN, HTTP fetch |
| `dns_resolve.cpp` | async DNS |
| `file_copy.cpp` | async file I/O |
| `awaitable_event_pipe.cpp` | cross-coroutine signalling |

## License

MIT © 2025 Jørgen Lind. See [LICENSE](LICENSE).
