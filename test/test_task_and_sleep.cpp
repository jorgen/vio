#include <algorithm>
#include <array>
#include <doctest/doctest.h>
#include <optional>
#include <vector>
#include <vio/event_loop.h>
#include <vio/event_pipe.h>
#include <vio/operation/sleep.h>
#include <vio/task.h>

// Minimum timer accuracy on Windows is 16ms.
static auto delay = std::chrono::milliseconds(32);

static vio::task_t<int> sleep_task_2(vio::event_loop_t &event_loop)
{

  auto to_wait = vio::sleep(event_loop, delay);
  auto _ = co_await to_wait;
  co_return 1;
}

static vio::task_t<void> sleep_task_3(vio::event_loop_t &event_loop)
{
  auto to_wait = vio::sleep(event_loop, delay * 2);
  auto _ = co_await to_wait;
}

static vio::task_t<int> sleep_task(vio::event_loop_t &event_loop)
{
  auto start_time = std::chrono::high_resolution_clock::now();
  auto to_wait = vio::sleep(event_loop, delay);
  auto _ = co_await to_wait;
  auto end_time = std::chrono::high_resolution_clock::now();
  REQUIRE(std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time) >= delay - std::chrono::milliseconds(2));

  start_time = std::chrono::high_resolution_clock::now();
  auto to_wait2 = vio::sleep(event_loop, delay * 2);
  auto to_wait3 = vio::sleep(event_loop, delay);
  _ = co_await to_wait2;
  _ = co_await to_wait3;
  end_time = std::chrono::high_resolution_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
  auto expected_max_duration = (delay * 2) + (delay / 2);
  REQUIRE(duration <= expected_max_duration);

  start_time = std::chrono::high_resolution_clock::now();
  auto to_wait_4 = sleep_task_2(event_loop);
  co_await sleep_task_3(event_loop);
  auto result = co_await std::move(to_wait_4);
  end_time = std::chrono::high_resolution_clock::now();
  REQUIRE(std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time) < delay * 3);
  REQUIRE(result == 1);

  start_time = std::chrono::high_resolution_clock::now();
  _ = co_await vio::sleep(event_loop, std::chrono::milliseconds(0));
  end_time = std::chrono::high_resolution_clock::now();
  duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
  expected_max_duration = std::chrono::milliseconds(delay);
  REQUIRE(duration < expected_max_duration);

  event_loop.stop();
  co_return 3;
}

TEST_SUITE("Task and Sleep")
{
  TEST_CASE("test sleep and task basics")
  {
    vio::event_loop_t event_loop;
    auto start_time = std::chrono::high_resolution_clock::now();
    std::optional<vio::task_t<int>> task;
    event_loop.run_in_loop([&] { task.emplace(sleep_task(event_loop)); });
    event_loop.run();
    auto end_time = std::chrono::high_resolution_clock::now();
    REQUIRE(std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time) > delay * 3);
  }
} // TEST_SUITE

// A server that spawns a task per connection has to keep those tasks alive --
// task_t destroys a suspended frame's storage only when it is done -- and has
// to be able to drop the finished ones, or the vector grows for the life of
// the process. Both halves of that need a move assignment, because
// std::erase_if reaches std::remove_if, which move-assigns; before task_t had
// one this test did not compile.
TEST_CASE("finished tasks can be pruned from a container")
{
  vio::event_loop_t event_loop;
  int completed = 0;
  std::optional<vio::task_t<void>> driver;

  event_loop.run_in_loop(
    [&]
    {
      driver.emplace(
        [](vio::event_loop_t &loop, int &done_count) -> vio::task_t<void>
        {
          std::vector<vio::task_t<void>> pending;
          for (int i = 0; i < 4; ++i)
          {
            pending.emplace_back(
              [](vio::event_loop_t &inner, int &counter, int index) -> vio::task_t<void>
              {
                auto _ = co_await vio::sleep(inner, std::chrono::milliseconds(8 * (index + 1)));
                ++counter;
              }(loop, done_count, i));
          }
          CHECK(pending.size() == 4);

          // Long enough that the first two have finished and the last two have
          // not, so the erase really has to discriminate.
          auto _ = co_await vio::sleep(loop, std::chrono::milliseconds(24));
          const auto pruned = std::erase_if(pending, [](const vio::task_t<void> &task) { return task.done(); });
          CHECK(pruned > 0);
          CHECK(pending.size() == 4 - pruned);

          auto __ = co_await vio::sleep(loop, std::chrono::milliseconds(64));
          const auto rest = std::erase_if(pending, [](const vio::task_t<void> &task) { return task.done(); });
          CHECK(rest == pending.size() + rest);
          CHECK(pending.empty());
          loop.stop();
        }(event_loop, completed));
    });

  event_loop.run();
  CHECK(completed == 4);
}

namespace
{
struct turn_counter_t
{
  vio::detail::hook_t hook;
  int turns = 0;

  turn_counter_t()
  {
    hook.owner = this;
    hook.run = [](vio::detail::hook_t *raw) { ++static_cast<turn_counter_t *>(raw->owner)->turns; };
  }
};
} // namespace

TEST_CASE("a sleep with a negative duration returns on the next turn")
{
  vio::event_loop_t event_loop;
  turn_counter_t counter;
  vio::detail::core(event_loop).add_hook(counter.hook);
  std::vector<int> turns_waited;
  std::vector<bool> succeeded;
  std::optional<vio::task_t<void>> task;

  const auto start = std::chrono::steady_clock::now();
  event_loop.run_in_loop([&] {
    task.emplace([](vio::event_loop_t &loop, turn_counter_t &counter, std::vector<int> &waited, std::vector<bool> &ok) -> vio::task_t<void> {
      const std::array<std::chrono::nanoseconds, 5> durations = {std::chrono::nanoseconds(-1), std::chrono::milliseconds(-50), std::chrono::hours(-1),
                                                                 std::chrono::nanoseconds::min(), std::chrono::nanoseconds(0)};
      for (auto duration : durations)
      {
        const int before = counter.turns;
        auto result = co_await vio::sleep(loop, duration);
        ok.push_back(result.has_value());
        waited.push_back(counter.turns - before);
      }
      loop.stop();
    }(event_loop, counter, turns_waited, succeeded));
  });
  event_loop.run();
  vio::detail::core(event_loop).remove_hook(counter.hook);

  CHECK(std::chrono::steady_clock::now() - start < std::chrono::seconds(1));
  CHECK(succeeded == std::vector<bool>(5, true));
  CHECK(turns_waited == std::vector<int>(5, 1));
}

TEST_CASE("a sleep never returns before its time")
{
  vio::event_loop_t event_loop;
  std::vector<std::chrono::nanoseconds> shortfalls;
  std::optional<vio::task_t<void>> task;
  event_loop.run_in_loop([&] {
    task.emplace([](vio::event_loop_t &loop, std::vector<std::chrono::nanoseconds> &shortfalls) -> vio::task_t<void> {
      const std::array<std::chrono::nanoseconds, 6> durations = {std::chrono::microseconds(100), std::chrono::microseconds(900), std::chrono::milliseconds(1),
                                                                 std::chrono::microseconds(1500), std::chrono::milliseconds(2), std::chrono::milliseconds(5)};
      for (auto duration : durations)
      {
        for (int i = 0; i < 5; ++i)
        {
          const auto start = std::chrono::steady_clock::now();
          auto result = co_await vio::sleep(loop, duration);
          const auto elapsed = std::chrono::steady_clock::now() - start;
          CHECK(result.has_value());
          if (elapsed < duration)
            shortfalls.push_back(duration - elapsed);
        }
      }
      loop.stop();
    }(event_loop, shortfalls));
  });
  event_loop.run();
  CHECK(shortfalls.empty());
}

TEST_CASE("a sleep with the largest durations waits until it is cancelled")
{
  vio::event_loop_t event_loop;
  std::vector<int> codes;
  std::vector<std::chrono::nanoseconds> waited;
  std::optional<vio::task_t<void>> task;
  event_loop.run_in_loop([&] {
    task.emplace([](vio::event_loop_t &loop, std::vector<int> &codes, std::vector<std::chrono::nanoseconds> &waited) -> vio::task_t<void> {
      for (int which = 0; which < 3; ++which)
      {
        vio::cancellation_t cancel;
        const auto start = std::chrono::steady_clock::now();
        auto pending = which == 0   ? vio::sleep(loop, std::chrono::nanoseconds::max(), &cancel)
                       : which == 1 ? vio::sleep(loop, std::chrono::milliseconds::max(), &cancel)
                                    : vio::sleep(loop, std::chrono::seconds::max(), &cancel);
        auto stopper = vio::sleep(loop, std::chrono::milliseconds(30));
        auto stopped = co_await stopper;
        CHECK(stopped.has_value());
        cancel.cancel();
        auto result = co_await pending;
        codes.push_back(result.has_value() ? 0 : result.error().code);
        waited.push_back(std::chrono::steady_clock::now() - start);
      }
      loop.stop();
    }(event_loop, codes, waited));
  });
  event_loop.run();
  CHECK(codes == std::vector<int>(3, vio::vio_cancelled));
  REQUIRE(waited.size() == 3);
  for (auto elapsed : waited)
    CHECK(elapsed >= std::chrono::milliseconds(25));
}
