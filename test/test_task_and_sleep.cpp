#include <doctest/doctest.h>
#include <vio/event_loop.h>
#include <vio/event_pipe.h>
#include <vio/task.h>
#include <vio/operation/sleep.h>

auto DELAY = std::chrono::milliseconds(10);

vio::task_t<int> sleep_task_2(vio::event_loop_t &event_loop)
{

  auto to_wait = vio::sleep(event_loop, DELAY);
  co_await to_wait;
  co_return 1;
}

vio::task_t<void> sleep_task_3(vio::event_loop_t &event_loop)
{
  auto to_wait = vio::sleep(event_loop, DELAY * 2);
  co_await to_wait;
}

vio::task_t<int> sleep_task(vio::event_loop_t &event_loop)
{
  auto start_time = std::chrono::high_resolution_clock::now();
  auto to_wait = vio::sleep(event_loop, DELAY);
  co_await to_wait;
  auto end_time = std::chrono::high_resolution_clock::now();
  CHECK(std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time)> DELAY);

  start_time = std::chrono::high_resolution_clock::now();
  auto to_wait2 = vio::sleep(event_loop, DELAY * 2);
  auto to_wait3 = vio::sleep(event_loop, DELAY);
  co_await to_wait2;
  co_await to_wait3;
  end_time = std::chrono::high_resolution_clock::now();
  CHECK(std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time) < DELAY * 3);

  start_time = std::chrono::high_resolution_clock::now();
  auto to_wait_4 = sleep_task_2(event_loop);
  co_await sleep_task_3(event_loop);
  auto result = co_await std::move(to_wait_4);
  end_time = std::chrono::high_resolution_clock::now();
  CHECK(std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time) < DELAY * 3);
  CHECK(result == 1);

  event_loop.stop();
  co_return 3;
}

TEST_CASE("test sleep and task basics")
{
  vio::event_loop_t event_loop;
  auto start_time = std::chrono::high_resolution_clock::now();
  event_loop.run_in_loop([&event_loop] { sleep_task(event_loop); });
  event_loop.run();
  auto end_time = std::chrono::high_resolution_clock::now();
  CHECK(std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time)> DELAY * 5);
}
