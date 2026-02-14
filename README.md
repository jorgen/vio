# vio

C++ async I/O library built on libuv with C++20 coroutines and LibreSSL for TLS.

## Building

```bash
cmake --preset debug
cmake --build cmake-build-debug
```

## Testing

```bash
./cmake-build-debug/test/vio_tests
```

### Sanitizers

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

## Dependencies

Fetched automatically during CMake configure:

- [libuv](https://github.com/libuv/libuv) - async I/O
- [LibreSSL](https://www.libressl.org/) - TLS
- [doctest](https://github.com/doctest/doctest) - testing
- [CMakeRC](https://github.com/vector-of-bool/cmrc) - resource compiler
- [ada](https://github.com/ada-url/ada) - URL parser
