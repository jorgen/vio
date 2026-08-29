#include <algorithm>
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
