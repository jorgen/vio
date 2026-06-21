#include <doctest/doctest.h>

#include "leak_check.h"

#include <vio/event_loop.h>
#include <vio/operation/file.h>

#include <cstdio>
#include <string>

TEST_SUITE("file leaks")
{
  // open_file/close_file run uv_fs_open/uv_fs_close synchronously. On Windows
  // uv_fs_open allocates a UTF-16 path buffer that is only freed by
  // uv_fs_req_cleanup, so a missing cleanup leaks one buffer per open.
  TEST_CASE("open_file does not leak the libuv request per open")
  {
    vio::event_loop_t loop;

    // A real temp file to open repeatedly.
    auto tmp = vio::mkstemp_file(loop, "test_open_file_leak_XXXXXX");
    REQUIRE(tmp.has_value());
    const std::string path = tmp->second;
    // Release the mkstemp handle but keep the file on disk.
    tmp->first = vio::make_auto_close_file({.event_loop = &loop, .handle = -1});

    auto open_once = [&]() -> bool
    {
      auto file = vio::open_file(loop, path, vio::file_open_flag_t::rdonly, 0);
      return file.has_value(); // auto-closes at scope exit
    };

    // Warm up one-time allocations outside the measured region.
    for (int i = 0; i < 5; ++i)
    {
      REQUIRE(open_once());
    }

    constexpr int iterations = 200;
    int failures = 0;
    vio_test::leak_guard_t guard;
    for (int i = 0; i < iterations; ++i)
    {
      if (!open_once())
      {
        ++failures;
      }
    }
    // Pre-fix this leaks one UTF-16 path buffer per open on Windows
    // (~`iterations` blocks); post-fix only small one-time noise remains.
    const long long leaked_blocks = guard.leaked_blocks();

    CHECK_EQ(failures, 0);
    CHECK_LT(leaked_blocks, iterations / 2);

    std::remove(path.c_str());
    loop.stop();
    loop.run();
  }
}
