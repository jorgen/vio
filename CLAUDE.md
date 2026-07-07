# VIO Project

C++ async I/O library built on libuv with C++20 coroutines and libressl for TLS.

## Build

```bash
# Configure (debug)
cmake --preset debug

# Build
cmake --build cmake-build-debug

# Run tests
./cmake-build-debug/test/vio_tests
```

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
- `src/vio/operation/` - Async operation implementations (tcp, tls, dns, file, sleep)
- `test/` - Tests using doctest
- `3rdparty/` - libuv, libressl, doctest, cmakerc, ada (fetched via cmake-dep)

## Dependencies (toggles & install)

Every dependency is togglable between the bundled fetch and a pre-installed copy.
The knobs are **auto-declared by cmake-dep** from each `CmDepFetchPackage` call in
`CMake/3rdPartyPackages.cmake`, prefixed by the project name (uppercased
`PROJECT_NAME` → `VIO`): `VIO_USE_SYSTEM_{LIBUV,LIBRESSL,ADA,DOCTEST,CMAKERC}`
(default `OFF`) and `VIO_<DEP>_{VERSION,URL,SHA256}` overrides to fetch a different
version/URL/hash without editing the packages file (e.g. a newer LibreSSL). When a
toggle is `ON`, cmake-dep skips the fetch; `CMake/Build3rdParty.cmake` then drives
libuv/ada/doctest through `CmDepAddPackage` (which owns the find-vs-build branch),
while cmakerc (`include()`-based) and libressl (ExternalProject) branch by hand on
the `${name}_USE_SYSTEM` signal, and `src/CMakeLists.txt` handles the system-libuv
link (`libuv::uv_a`). `find_package(LibreSSL)` uses the config a CMake-built
LibreSSL installs (`lib/cmake/LibreSSL/LibreSSLConfig.cmake`).

`VIO_INSTALL` (default `ON`) installs headers + the `vio` lib and, **when built
against system deps**, a relocatable `find_package(vio)` package config
(`vio::vio`, from `CMake/vioConfig.cmake.in`, which `find_dependency`s
libuv/LibreSSL/ada and exports the bundled `cmrc-base`/`vio_default_certs`). A
bundled-deps build vendors targets that aren't installed, so it installs lib +
headers only (no config). `vio::vio` is aliased in-tree so consumers use one name
either way. A downstream that `add_subdirectory`s vio (e.g. prism) should force
`VIO_INSTALL OFF`.

## Key Architecture

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
2. `uv_close` is called on all registered closable handles
3. Storage is freed only after all close callbacks have fired (via `close_pending` counter)

The `on_destroy` callbacks may register additional closable handles (e.g. the `uv_tcp_t` for a
TLS connection). The `in_destroy_sequence` flag prevents re-entrant destruction if callbacks
temporarily increment/decrement the ref count. A parked ref that a callback holds (e.g. an
in-flight `uv_write` during teardown, see `begin_teardown`) defers the final destruction until
that callback releases it — which is how a best-effort close_notify write is flushed on close.

### TLS transport: uv_tls_stream_t + ssl_engine_t (memory BIOs)

TLS rides libuv's **stream API** (`uv_read_start` / `uv_write` on the `uv_tcp_t`), not `uv_poll`.
vio issues no raw `recv`/`send`, so libuv's backend (io_uring/IOCP) is invisible to the crypto
layer. The pieces (all in `src/vio/`):

- `ssl_backend.h` — compile-time backend seam (`VIO_SSL_BACKEND`); only bundled LibreSSL is wired.
  Portable in-memory cert/key/CA loading (`BIO_new_mem_buf` + `PEM_read_bio_*`), feature-gated on
  `LIBRESSL_VERSION_NUMBER` (never the fake `OPENSSL_VERSION_NUMBER = 0x20000000L`).
- `ssl_context.h` — `ssl_context_t`: a shared `SSL_CTX` built once from `ssl_config_t` (verify,
  ALPN, keylog, session cache). Server ALPN selection is hand-rolled (server preference, empty-list
  CVE-2024-5535 guard, `NOACK` on no overlap).
- `ssl_engine.h` — `ssl_engine_t`: a per-connection **socket-free** codec (`SSL*` + rbio/wbio
  `BIO_s_mem`). `feed_ciphertext`→rbio, `SSL_read`→plaintext; `SSL_write`→drain wbio→ciphertext.
- `socket_stream.h` — `uv_tls_stream_t`: the driver. `read_cb` feeds rbio then `pump()`s;
  `pump()` is **handshake-then-fall-through** (a segment carrying Finished + app data decrypts
  both in one pass). After every SSL op it drains wbio (so KeyUpdate/alert control records are
  sent). Writes are producer-throttled: over the write high-water mark, `SSL_write` is deferred and
  the awaitable stays suspended (natural backpressure); a bounded `buffer_queue` + `uv_read_stop`
  applies read backpressure. The handshake is driven to completion at connect/accept.

Reentrancy: `read_cb`/`write_cb` hold a callback-duration ref (`rc->inc()/dec()`) so a resumed
coroutine that drops the last user ref cannot free the state mid-callback; each in-flight
`uv_write` parks a ref released in `write_cb`. Never hold a `write_queue[idx]` reference across a
`continuation.resume()` (the vector may reallocate) — re-index after resuming.

### event_loop_t

The event loop has always-active internal handles (async, prepare, event pipes).
`event_loop.run()` (i.e. `uv_run(UV_RUN_DEFAULT)`) will never return on its own — `stop()` must
be called, which sends an async signal that closes all internal handles. Tests that don't use
coroutines still need `event_loop.stop()` before `event_loop.run()` for cleanup.

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

Because vio now owns the TCP read (`uv_read_start`), disconnects are detected directly — the old
`recv(..., MSG_PEEK)` probe is gone. Distinct, stable `error_t` codes let a downstream (HTTP/2)
branch on the kind of close (defined in `ssl_engine.h`):

1. **Clean shutdown (`vio_tls_clean_shutdown`):** the peer sent `close_notify`, so `SSL_read`
   returns `SSL_ERROR_ZERO_RETURN` (or the read callback delivers `UV_EOF` after `close_notify`).
2. **Unclean truncation (`vio_tls_truncated`):** the read callback delivers `UV_EOF` before any
   `close_notify` — the connection was cut mid-stream.
3. **Transport error:** any other negative `nread` maps to the libuv error code.

### TLS extras: OCSP stapling, session resumption, writev backpressure

- **OCSP stapling** (`ssl_config_t.ocsp_staple_mem`/`ocsp_staple_file`, server): the DER
  response is stored in `ssl_context_t` and stapled via `SSL_CTX_set_tlsext_status_cb`
  (BoringSSL uses `SSL_CTX_set_ocsp_response`, gated in `ssl_context.h`). A client sets
  `request_ocsp_staple` and reads it back with `ssl_client_ocsp_response()`.
- **Client session resumption** (`ssl_config_t.session_cache` → `ssl_session_cache_t`, app-owned,
  keyed by host): wired via `SSL_CTX_sess_set_new_cb` (fires when a ticket arrives) +
  `SSL_set_session` (before handshake). The peer host is stashed in SSL ex_data (`&engine.peer_name`)
  to key the cache. `ssl_client_session_reused()` reports the result. **Caveat (root-caused, not a
  vio bug):** the bundled **LibreSSL 4.1.0 TLS 1.3 *server* does not issue NewSessionTicket
  messages** — a standalone LibreSSL probe over memory BIOs shows `num_tickets` defaults to 0 and
  setting it to 2 (+ `SSL_SESS_CACHE_SERVER`) still produces no ticket bytes. So LibreSSL↔LibreSSL
  TLS 1.3 resumption is impossible regardless of vio. The client-side resumption plumbing here is
  correct: it is verified on TLS 1.2 (ticket in-handshake) and will resume over TLS 1.3 against any
  server that issues tickets (OpenSSL/BoringSSL, or real-world servers). `SSL_CTX_set_num_tickets(2)`
  is kept because it is correct for the backends that honor it.
- **`ssl_*_writev` / `ssl_*_shutdown`**: vectored writes coalesce buffers into one TLS record and
  go through the same producer high-water throttle as `begin_write` (the coalesced plaintext is
  owned in the write slot, so it survives being parked for backpressure); half-close sends a
  one-way `close_notify` and keeps reading.

### on_destroy teardown (begin_teardown)

`tls_client.h` and `tls_server.h` `on_destroy` callbacks call `uv_tls_stream_t::begin_teardown()`:
best-effort one-way `close_notify` (its fire-and-forget `uv_write` parks a ref, deferring final
destruction until the flush completes), then `uv_read_stop`. The `SSL*`/BIOs are freed by the
`ssl_engine_t` destructor when the state's storage is deleted — after the close_notify ciphertext
has already been copied out of `wbio`. Guarded to be a no-op when the engine was never initialized
(e.g. a client dropped before connecting). `ssl_server_create`'s `on_destroy` additionally cancels
a pending listen and consumes the raw ref `tcp_listen` parked in `stream->data`.
