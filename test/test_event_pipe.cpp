#include <doctest/doctest.h>
#include <vio/awaitable_event_pipe.h>
#include <vio/event_loop.h>
#include <vio/operation/dns.h>
#include <vio/operation/sleep.h>
#include <vio/task.h>

#include <string>

#include "require_expected.h"

namespace
{
TEST_SUITE("Event Pipe")
{
  TEST_CASE("Test basic event pipe")
  {
    vio::event_loop_t primary_event_loop;

    bool has_event_from_secondary_been_called = false; // NOLINT(misc-const-correctness) modified via lambda capture
    vio::event_pipe_t<int> event_from_secondary(primary_event_loop,
                                                [&primary_event_loop, &has_event_from_secondary_been_called](int a)
                                                {
                                                  REQUIRE(a == 55);
                                                  has_event_from_secondary_been_called = true;
                                                  primary_event_loop.stop();
                                                });

    vio::thread_with_event_loop_t secondary_event_loop;  // NOLINT(misc-const-correctness) event_loop() is non-const
    bool has_event_from_main_thread_been_called = false; // NOLINT(misc-const-correctness) modified via lambda capture
    vio::event_pipe_t<int> event_from_main_thread_been_called(secondary_event_loop.event_loop(),
                                                              [&has_event_from_main_thread_been_called, &event_from_secondary](int a)
                                                              {
                                                                REQUIRE(a == 44);
                                                                has_event_from_main_thread_been_called = true;
                                                                event_from_secondary(55);
                                                              });
    std::function<void()> run_in_main = [&event_from_main_thread_been_called]() { event_from_main_thread_been_called(44); };
    primary_event_loop.run_in_loop(std::move(run_in_main));
    primary_event_loop.run();

    REQUIRE(has_event_from_secondary_been_called);
    REQUIRE(has_event_from_main_thread_been_called);
  }

  TEST_CASE("Test awaitable event pipe")
  {
    vio::event_loop_t caller_loop;
    vio::thread_with_event_loop_t handler_thread; // NOLINT(misc-const-correctness)

    vio::awaitable_event_pipe_t<int, int> pipe(caller_loop, handler_thread.event_loop(), [](int x) -> int { return x * 2; });

    int result = 0; // NOLINT(misc-const-correctness)
    caller_loop.run_in_loop([&] {
      return [](vio::event_loop_t &caller_loop, int &result, vio::awaitable_event_pipe_t<int, int> &pipe) -> vio::task_t<void>
        {
          result = co_await pipe.call(21);
          caller_loop.stop();
        }(caller_loop, result, pipe);
    });
    caller_loop.run();

    REQUIRE(result == 42);
  }

  TEST_CASE("Test awaitable event pipe async handler")
  {
    vio::event_loop_t caller_loop;
    vio::thread_with_event_loop_t handler_thread; // NOLINT(misc-const-correctness)
    auto &handler_loop = handler_thread.event_loop();

    vio::awaitable_event_pipe_t<int, int> pipe(caller_loop, handler_loop,
                                               [&handler_loop](int x) -> vio::task_t<int>
                                               {
                                                 auto *el = &handler_loop;
                                                 (void)co_await vio::sleep(*el, std::chrono::milliseconds(10));
                                                 co_return x * 2;
                                               });

    int result = 0; // NOLINT(misc-const-correctness)
    caller_loop.run_in_loop([&] {
      return [](vio::event_loop_t &caller_loop, int &result, vio::awaitable_event_pipe_t<int, int> &pipe) -> vio::task_t<void>
        {
          result = co_await pipe.call(21);
          caller_loop.stop();
        }(caller_loop, result, pipe);
    });
    caller_loop.run();

    REQUIRE(result == 42);
  }

  TEST_CASE("Test awaitable event pipe multiple sequential calls")
  {
    vio::event_loop_t caller_loop;
    vio::thread_with_event_loop_t handler_thread; // NOLINT(misc-const-correctness)

    vio::awaitable_event_pipe_t<int, int> pipe(caller_loop, handler_thread.event_loop(), [](int x) -> int { return x * 2; });

    int sum = 0; // NOLINT(misc-const-correctness)
    caller_loop.run_in_loop([&] {
      return [](vio::event_loop_t &caller_loop, int &sum, vio::awaitable_event_pipe_t<int, int> &pipe) -> vio::task_t<void>
        {
          for (int i = 0; i < 10; i++)
          {
            sum += co_await pipe.call(i);
          }
          caller_loop.stop();
        }(caller_loop, sum, pipe);
    });
    caller_loop.run();

    REQUIRE(sum == 90);
  }

  TEST_CASE("Test awaitable event pipe multiple arguments")
  {
    vio::event_loop_t caller_loop;
    vio::thread_with_event_loop_t handler_thread; // NOLINT(misc-const-correctness)

    vio::awaitable_event_pipe_t<std::string, std::string, int> pipe(caller_loop, handler_thread.event_loop(), [](std::string s, int n) -> std::string { return s + std::to_string(n); });

    std::string result; // NOLINT(misc-const-correctness)
    caller_loop.run_in_loop([&] {
      return [](vio::event_loop_t &caller_loop, std::string &result, vio::awaitable_event_pipe_t<std::string, std::string, int> &pipe) -> vio::task_t<void>
        {
          result = co_await pipe.call(std::string("hello"), 42);
          caller_loop.stop();
        }(caller_loop, result, pipe);
    });
    caller_loop.run();

    REQUIRE(result == "hello42");
  }
  TEST_CASE("Test awaitable event pipe same event loop")
  {
    vio::event_loop_t loop;

    vio::awaitable_event_pipe_t<int, int> pipe(loop, loop, [](int x) -> int { return x * 2; });

    int result = 0; // NOLINT(misc-const-correctness)
    loop.run_in_loop([&] {
      return [](vio::event_loop_t &loop, int &result, vio::awaitable_event_pipe_t<int, int> &pipe) -> vio::task_t<void>
        {
          result = co_await pipe.call(21);
          loop.stop();
        }(loop, result, pipe);
    });
    loop.run();

    REQUIRE(result == 42);
  }
} // TEST_SUITE
} // namespace
