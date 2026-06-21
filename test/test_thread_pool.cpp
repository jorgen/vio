#include <doctest/doctest.h>

#include <vio/thread_pool.h>

#include <atomic>
#include <chrono>
#include <thread>

TEST_SUITE("thread_pool")
{
  // enqueue_detached runs a task without allocating a packaged_task/future for a
  // result the caller does not want (used by schedule_work).
  TEST_CASE("enqueue_detached runs every task")
  {
    vio::thread_pool_t pool(4);
    std::atomic<int> counter{0};
    constexpr int n = 200;

    for (int i = 0; i < n; ++i)
    {
      pool.enqueue_detached([&counter] { counter.fetch_add(1, std::memory_order_relaxed); });
    }

    // Wait (bounded) for all tasks to complete.
    for (int i = 0; i < 2000 && counter.load() < n; ++i)
    {
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    CHECK_EQ(counter.load(), n);
  }
}
