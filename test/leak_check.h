#pragma once

// Heap-leak measurement helper for tests.
//
// On MSVC debug builds it uses the CRT debug heap (_CrtMemCheckpoint) to report
// the net number of live heap blocks allocated across a region -- this is the
// native Windows way to catch leaks since MSVC's AddressSanitizer ships without
// LeakSanitizer. On every other toolchain leaked_blocks() returns 0 and leak
// detection is left to ASan/LSan.
//
// Tests should run many iterations and assert leaked_blocks() stays well below
// the iteration count: a real per-iteration leak grows with the loop, whereas
// unavoidable one-time/lazy initialisation (which lands in the measured window
// when earlier suites are filtered out) is a small constant.

#if defined(_MSC_VER) && defined(_DEBUG)

#include <crtdbg.h>

#define VIO_HAVE_LEAK_CHECK 1

namespace vio_test
{
class leak_guard_t
{
public:
  leak_guard_t()
  {
    _CrtMemCheckpoint(&_start);
  }

  // Net number of live normal/client heap blocks since construction.
  [[nodiscard]] long long leaked_blocks() const
  {
    _CrtMemState now;
    _CrtMemCheckpoint(&now);
    const auto before = static_cast<long long>(_start.lCounts[_NORMAL_BLOCK]) + static_cast<long long>(_start.lCounts[_CLIENT_BLOCK]);
    const auto after = static_cast<long long>(now.lCounts[_NORMAL_BLOCK]) + static_cast<long long>(now.lCounts[_CLIENT_BLOCK]);
    return after - before;
  }

private:
  _CrtMemState _start{};
};
} // namespace vio_test

#else

#define VIO_HAVE_LEAK_CHECK 0

namespace vio_test
{
class leak_guard_t
{
public:
  [[nodiscard]] long long leaked_blocks() const
  {
    return 0;
  }
};
} // namespace vio_test

#endif
