#include <doctest/doctest.h>

#include "leak_check.h"

#include <vio/event_loop.h>
#include <vio/operation/file.h>

#include <cstdio>
#include <string>

TEST_SUITE("file leaks")
{
  TEST_CASE("open_file does not leak per open")
  {
    vio::event_loop_t loop;

    auto tmp = vio::mkstemp_file(loop, "test_open_file_leak_XXXXXX");
    REQUIRE(tmp.has_value());
    const std::string path = tmp->second;
    tmp->first = vio::make_auto_close_file({.event_loop = &loop, .handle = -1});

    auto open_once = [&]() -> bool
    {
      auto file = vio::open_file(loop, path, vio::file_open_flag_t::rdonly, 0);
      return file.has_value();
    };

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
    const long long leaked_blocks = guard.leaked_blocks();

    CHECK_EQ(failures, 0);
    CHECK_LT(leaked_blocks, iterations / 2);

    std::remove(path.c_str());
    loop.stop();
    loop.run();
  }

  TEST_CASE("file operations dropped without being awaited still finish and free their state")
  {
    vio::event_loop_t loop;
    auto tmp = vio::mkstemp_file(loop, "test_dropped_read_XXXXXX");
    REQUIRE(tmp.has_value());
    const std::string path = tmp->second;
    std::string text = "dropped";
    REQUIRE(vio::write_file_sync(*tmp->first, reinterpret_cast<const std::uint8_t *>(text.data()), text.size(), 0).has_value());

    std::string buffer(text.size(), '\0');
    {
      auto read = vio::read_file(loop, *tmp->first, reinterpret_cast<std::uint8_t *>(buffer.data()), buffer.size(), 0);
      auto sync = vio::fsync_file(loop, *tmp->first);
      vio::cancellation_t cancel;
      auto cancelled = vio::write_file(loop, *tmp->first, reinterpret_cast<const std::uint8_t *>(text.data()), text.size(), 0, &cancel);
      cancel.cancel();
    }
    loop.stop();
    loop.run();
    CHECK(buffer == text);

    tmp->first = vio::make_auto_close_file({.event_loop = &loop, .handle = -1});
    std::remove(path.c_str());
  }
}
