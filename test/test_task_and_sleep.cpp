#include <doctest/doctest.h>
#include <vio/event_loop.h>
#include <vio/event_pipe.h>
#include <vio/operation/sleep.h>
#include <vio/task.h>

// Minimum timer accuracy on Windows is 16ms.
static auto delay = std::chrono::milliseconds(32);

static vio::task_t<int> sleep_task_2(vio::event_loop_t &event_loop)
{

  auto to_wait = vio::sleep(event_loop, delay);
  co_await to_wait;
  co_return 1;
}

static vio::task_t<void> sleep_task_3(vio::event_loop_t &event_loop)
{
  auto to_wait = vio::sleep(event_loop, delay * 2);
  co_await to_wait;
}

static vio::task_t<int> sleep_task(vio::event_loop_t &event_loop)
{
  auto start_time = std::chrono::high_resolution_clock::now();
  auto to_wait = vio::sleep(event_loop, delay);
  co_await to_wait;
  auto end_time = std::chrono::high_resolution_clock::now();
  REQUIRE(std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time) >= delay);

  start_time = std::chrono::high_resolution_clock::now();
  auto to_wait2 = vio::sleep(event_loop, delay * 2);
  auto to_wait3 = vio::sleep(event_loop, delay);
  co_await to_wait2;
  co_await to_wait3;
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
  co_await vio::sleep(event_loop, std::chrono::milliseconds(0));
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
  event_loop.run_in_loop([&event_loop] { sleep_task(event_loop); });
  event_loop.run();
  auto end_time = std::chrono::high_resolution_clock::now();
  REQUIRE(std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time) > delay * 5);
}
} // TEST_SUITE
