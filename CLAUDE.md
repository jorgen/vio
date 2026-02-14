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
- `3rdparty/` - libuv, libressl, doctest, cmakerc

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

The `on_destroy` callbacks may register additional closable handles (e.g. the poll handle for
socket_stream). The `in_destroy_sequence` flag prevents re-entrant destruction if callbacks
temporarily increment/decrement the ref count.

### socket_stream_t event processing

`on_poll_event` processes events in order: WRITABLE, then READABLE, then `set_poll_state()`.
A write completion can resume a coroutine chain that destroys the socket_stream owner, so
defensive `closed` checks are required between each phase:

```
WRITABLE → check closed → READABLE → check closed → set_poll_state
```

Within READABLE, if `write_got_poll_in` is set, `write()` is called first (TLS needs read events
to complete writes). Another `closed` check is needed after that `write()` call.

### event_loop_t

The event loop has always-active internal handles (async, prepare, event pipes).
`event_loop.run()` (i.e. `uv_run(UV_RUN_DEFAULT)`) will never return on its own — `stop()` must
be called, which sends an async signal that closes all internal handles. Tests that don't use
coroutines still need `event_loop.stop()` before `event_loop.run()` for cleanup.

## Writing Tests

### Coroutine test pattern

Tests use `event_loop.run_in_loop()` with a lambda returning `task_t<void>`. Server and client
tasks run as concurrent coroutines within the same event loop. The pattern is:

```cpp
event_loop.run_in_loop([&]() -> vio::task_t<void> {
    auto server_task = [](args...) -> vio::task_t<void> { ... }(captured_args);
    co_await [](args...) -> vio::task_t<void> { ... }(captured_args); // client
    co_await std::move(server_task);
    ev->stop();
});
event_loop.run();
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

TLS disconnect detection works via two mechanisms in `tls_stream_t::read()`:

1. **Clean TLS shutdown (`tls_read` returns 0):** When the peer sends `close_notify`, `tls_read`
   returns 0. This is mapped to an error (`"TLS connection closed"`).
2. **Unclean TCP close (`tls_read` returns `TLS_WANT_POLLIN`):** When the peer closes TCP without
   `close_notify`, `tls_read` returns `TLS_WANT_POLLIN`. A `recv(fd, buf, 1, MSG_PEEK)` check
   distinguishes between "no data yet" (`recv` returns -1/EAGAIN) and "peer closed" (`recv`
   returns 0). The latter maps to an error (`"Connection closed by peer"`).

### socket_stream.h defensive guards

Several guards were added to `socket_stream_t` to prevent crashes when a write completion
destroys the stream during `on_poll_event` processing:

- `uv_is_closing` check at top of `on_poll_event`
- `if (state->closed) return;` between WRITABLE and READABLE processing
- `if (state->closed) return;` after `write()` call within READABLE branch
- `if (!closed)` guard before `uv_poll_stop` in `read()` error path
- `if (state->closed) return;` after READABLE branch before `set_poll_state`

### on_destroy uv_is_closing guards

Both `tls_client.h` and `tls_server.h` have `uv_is_closing` guards in their `on_destroy`
callbacks to prevent calling `uv_poll_stop` on an already-closing handle:

```cpp
if (state_raw->socket_stream.connected && !uv_is_closing(...poll_req...))
```
