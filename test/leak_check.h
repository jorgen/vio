#pragma once

// Scoped heap-leak assertion helper for tests.
//
// On MSVC debug builds it uses the CRT debug heap (_CrtMemCheckpoint /
// _CrtMemDifference) to detect net heap growth across a region -- this is the
// native Windows way to catch leaks since MSVC's AddressSanitizer ships without
// LeakSanitizer. On every other toolchain it is a no-op and leak detection is
// left to ASan/LSan; tests guard the assertion behind VIO_HAVE_LEAK_CHECK.

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

  // Returns true if the normal/client heap grew since construction.
  [[nodiscard]] bool leaked() const
  {
    _CrtMemState now;
    _CrtMemState diff;
    _CrtMemCheckpoint(&now);
    return _CrtMemDifference(&diff, &_start, &now) != 0;
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
  [[nodiscard]] bool leaked() const
  {
    return false;
  }
};
} // namespace vio_test

#endif
