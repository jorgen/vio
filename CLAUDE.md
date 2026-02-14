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

## AddressSanitizer Build

```bash
# Configure with ASan
cmake --preset asan

# Build
cmake --build cmake-build-asan

# Run tests under ASan
./cmake-build-asan/test/vio_tests
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
