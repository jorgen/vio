#include <doctest/doctest.h>
#include <vio/event_loop.h>
#include <vio/operation/work.h>
#include <vio/task.h>

#include <string>

TEST_CASE("Basic work batch")
{
  vio::event_loop_t event_loop;
  vio::thread_pool_t pool(4);

  event_loop.run_in_loop(
    [&event_loop, &pool]
    {
      [](vio::event_loop_t &el, vio::thread_pool_t &p) -> vio::task_t<void>
      {
        std::vector<std::function<std::expected<int, vio::error_t>()>> work_items;
        for (int i = 0; i < 10; ++i)
        {
          work_items.emplace_back([i]() -> std::expected<int, vio::error_t> { return i * i; });
        }

        auto batch = vio::schedule_work<int>(el, p, std::move(work_items));
        auto results = co_await batch;

        REQUIRE(results.size() == 10);
        for (int i = 0; i < 10; ++i)
        {
          REQUIRE(results[i].has_value());
          CHECK(results[i].value() == i * i);
        }

        el.stop();
      }(event_loop, pool);
    });

  event_loop.run();
}

TEST_CASE("Empty work batch")
{
  vio::event_loop_t event_loop;
  vio::thread_pool_t pool(4);

  event_loop.run_in_loop(
    [&event_loop, &pool]
    {
      [](vio::event_loop_t &el, vio::thread_pool_t &p) -> vio::task_t<void>
      {
        std::vector<std::function<std::expected<int, vio::error_t>()>> work_items;

        auto batch = vio::schedule_work<int>(el, p, std::move(work_items));
        auto results = co_await batch;

        CHECK(results.empty());

        el.stop();
      }(event_loop, pool);
    });

  event_loop.run();
}

TEST_CASE("Work batch error propagation")
{
  vio::event_loop_t event_loop;
  vio::thread_pool_t pool(4);

  event_loop.run_in_loop(
    [&event_loop, &pool]
    {
      [](vio::event_loop_t &el, vio::thread_pool_t &p) -> vio::task_t<void>
      {
        std::vector<std::function<std::expected<int, vio::error_t>()>> work_items;
        work_items.emplace_back([]() -> std::expected<int, vio::error_t> { return 42; });
        work_items.emplace_back([]() -> std::expected<int, vio::error_t> { return std::unexpected(vio::error_t{.code = -1, .msg = "test error"}); });
        work_items.emplace_back([]() -> std::expected<int, vio::error_t> { return 99; });

        auto batch = vio::schedule_work<int>(el, p, std::move(work_items));
        auto results = co_await batch;

        REQUIRE(results.size() == 3);
        CHECK(results[0].has_value());
        CHECK(results[0].value() == 42);
        CHECK(!results[1].has_value());
        CHECK(results[1].error().code == -1);
        CHECK(results[2].has_value());
        CHECK(results[2].value() == 99);

        el.stop();
      }(event_loop, pool);
    });

  event_loop.run();
}

TEST_CASE("Work batch cancellation")
{
  vio::event_loop_t event_loop;
  constexpr int pool_size = 4;
  vio::thread_pool_t pool(pool_size);

  event_loop.run_in_loop(
    [&event_loop, &pool]
    {
      [](vio::event_loop_t &el, vio::thread_pool_t &p) -> vio::task_t<void>
      {
        // Block all pool threads so queued items are guaranteed to still be pending.
        std::mutex mtx;
        std::condition_variable cv;
        std::atomic<int> threads_blocked{0};
        std::atomic<bool> release{false};

        std::vector<std::function<std::expected<int, vio::error_t>()>> work_items;

        // First pool_size items: block inside the work function
        for (int i = 0; i < pool_size; ++i)
        {
          work_items.emplace_back([&mtx, &cv, &threads_blocked, &release, i]() -> std::expected<int, vio::error_t>
          {
            threads_blocked.fetch_add(1, std::memory_order_release);
            std::unique_lock<std::mutex> lock(mtx);
            cv.wait(lock, [&release] { return release.load(std::memory_order_acquire); });
            return i;
          });
        }

        // Remaining items: these will be queued but not started
        for (int i = pool_size; i < pool_size + 20; ++i)
        {
          work_items.emplace_back([i]() -> std::expected<int, vio::error_t> { return i; });
        }

        auto batch = vio::schedule_work<int>(el, p, std::move(work_items));

        // Spin until all pool threads are blocked
        while (threads_blocked.load(std::memory_order_acquire) < pool_size)
        {
          std::this_thread::yield();
        }

        // Cancel while remaining items are still queued
        batch.state_ptr->cancel();

        // Release blocked threads
        {
          std::lock_guard<std::mutex> lock(mtx);
          release.store(true, std::memory_order_release);
        }
        cv.notify_all();

        auto results = co_await batch;

        REQUIRE(results.size() == pool_size + 20);
        // Blocked items completed normally (started before cancel)
        for (int i = 0; i < pool_size; ++i)
        {
          CHECK(results[i].has_value());
          CHECK(results[i].value() == i);
        }
        // Queued items should all be cancelled
        for (size_t i = pool_size; i < results.size(); ++i)
        {
          CHECK(!results[i].has_value());
          CHECK(results[i].error().code == UV_ECANCELED);
        }

        el.stop();
      }(event_loop, pool);
    });

  event_loop.run();
}

TEST_CASE("Work batch thread verification")
{
  vio::event_loop_t event_loop;
  vio::thread_pool_t pool(4);

  event_loop.run_in_loop(
    [&event_loop, &pool]
    {
      [](vio::event_loop_t &el, vio::thread_pool_t &p) -> vio::task_t<void>
      {
        auto main_thread_id = std::this_thread::get_id();

        std::vector<std::function<std::expected<std::thread::id, vio::error_t>()>> work_items;
        for (int i = 0; i < 4; ++i)
        {
          work_items.emplace_back([]() -> std::expected<std::thread::id, vio::error_t> { return std::this_thread::get_id(); });
        }

        auto batch = vio::schedule_work<std::thread::id>(el, p, std::move(work_items));
        auto results = co_await batch;

        REQUIRE(results.size() == 4);
        for (size_t i = 0; i < 4; ++i)
        {
          REQUIRE(results[i].has_value());
          CHECK(results[i].value() != main_thread_id);
          CHECK(results[i].value() != std::thread::id());
        }

        el.stop();
      }(event_loop, pool);
    });

  event_loop.run();
}

TEST_CASE("Work batch single item")
{
  vio::event_loop_t event_loop;
  vio::thread_pool_t pool(4);

  event_loop.run_in_loop(
    [&event_loop, &pool]
    {
      [](vio::event_loop_t &el, vio::thread_pool_t &p) -> vio::task_t<void>
      {
        std::vector<std::function<std::expected<int, vio::error_t>()>> work_items;
        work_items.emplace_back([]() -> std::expected<int, vio::error_t> { return 777; });

        auto batch = vio::schedule_work<int>(el, p, std::move(work_items));
        auto results = co_await batch;

        REQUIRE(results.size() == 1);
        REQUIRE(results[0].has_value());
        CHECK(results[0].value() == 777);

        el.stop();
      }(event_loop, pool);
    });

  event_loop.run();
}

TEST_CASE("Work batch with string type")
{
  vio::event_loop_t event_loop;
  vio::thread_pool_t pool(4);

  event_loop.run_in_loop(
    [&event_loop, &pool]
    {
      [](vio::event_loop_t &el, vio::thread_pool_t &p) -> vio::task_t<void>
      {
        std::vector<std::function<std::expected<std::string, vio::error_t>()>> work_items;
        work_items.emplace_back([]() -> std::expected<std::string, vio::error_t> { return "hello"; });
        work_items.emplace_back([]() -> std::expected<std::string, vio::error_t> { return std::unexpected(vio::error_t{.code = -1, .msg = "fail"}); });
        work_items.emplace_back([]() -> std::expected<std::string, vio::error_t>
        {
          std::string s;
          for (int i = 0; i < 1000; ++i)
            s += "x";
          return s;
        });

        auto batch = vio::schedule_work<std::string>(el, p, std::move(work_items));
        auto results = co_await batch;

        REQUIRE(results.size() == 3);
        REQUIRE(results[0].has_value());
        CHECK(results[0].value() == "hello");
        CHECK(!results[1].has_value());
        CHECK(results[1].error().code == -1);
        REQUIRE(results[2].has_value());
        CHECK(results[2].value().size() == 1000);

        el.stop();
      }(event_loop, pool);
    });

  event_loop.run();
}

TEST_CASE("Work batch all items fail")
{
  vio::event_loop_t event_loop;
  vio::thread_pool_t pool(4);

  event_loop.run_in_loop(
    [&event_loop, &pool]
    {
      [](vio::event_loop_t &el, vio::thread_pool_t &p) -> vio::task_t<void>
      {
        std::vector<std::function<std::expected<int, vio::error_t>()>> work_items;
        for (int i = 0; i < 5; ++i)
        {
          work_items.emplace_back([i]() -> std::expected<int, vio::error_t>
          {
            return std::unexpected(vio::error_t{.code = -(i + 1), .msg = "error " + std::to_string(i)});
          });
        }

        auto batch = vio::schedule_work<int>(el, p, std::move(work_items));
        auto results = co_await batch;

        REQUIRE(results.size() == 5);
        for (int i = 0; i < 5; ++i)
        {
          CHECK(!results[i].has_value());
          CHECK(results[i].error().code == -(i + 1));
        }

        el.stop();
      }(event_loop, pool);
    });

  event_loop.run();
}

TEST_CASE("Work batch sequential batches")
{
  vio::event_loop_t event_loop;
  vio::thread_pool_t pool(4);

  event_loop.run_in_loop(
    [&event_loop, &pool]
    {
      [](vio::event_loop_t &el, vio::thread_pool_t &p) -> vio::task_t<void>
      {
        // First batch
        std::vector<std::function<std::expected<int, vio::error_t>()>> items1;
        for (int i = 0; i < 5; ++i)
          items1.emplace_back([i]() -> std::expected<int, vio::error_t> { return i; });

        auto results1 = co_await vio::schedule_work<int>(el, p, std::move(items1));

        REQUIRE(results1.size() == 5);
        for (int i = 0; i < 5; ++i)
        {
          REQUIRE(results1[i].has_value());
          CHECK(results1[i].value() == i);
        }

        // Second batch using results from first
        std::vector<std::function<std::expected<int, vio::error_t>()>> items2;
        for (int i = 0; i < 5; ++i)
        {
          int prev = results1[i].value();
          items2.emplace_back([prev]() -> std::expected<int, vio::error_t> { return prev * 10; });
        }

        auto results2 = co_await vio::schedule_work<int>(el, p, std::move(items2));

        REQUIRE(results2.size() == 5);
        for (int i = 0; i < 5; ++i)
        {
          REQUIRE(results2[i].has_value());
          CHECK(results2[i].value() == i * 10);
        }

        el.stop();
      }(event_loop, pool);
    });

  event_loop.run();
}

TEST_CASE("Work batch concurrent batches")
{
  vio::event_loop_t event_loop;
  vio::thread_pool_t pool(4);

  event_loop.run_in_loop(
    [&event_loop, &pool]
    {
      [](vio::event_loop_t &el, vio::thread_pool_t &p) -> vio::task_t<void>
      {
        std::vector<std::function<std::expected<int, vio::error_t>()>> items_a;
        for (int i = 0; i < 8; ++i)
          items_a.emplace_back([i]() -> std::expected<int, vio::error_t> { return i + 100; });

        std::vector<std::function<std::expected<int, vio::error_t>()>> items_b;
        for (int i = 0; i < 8; ++i)
          items_b.emplace_back([i]() -> std::expected<int, vio::error_t> { return i + 200; });

        // Schedule both before awaiting either
        auto batch_a = vio::schedule_work<int>(el, p, std::move(items_a));
        auto batch_b = vio::schedule_work<int>(el, p, std::move(items_b));

        auto results_a = co_await batch_a;
        auto results_b = co_await batch_b;

        REQUIRE(results_a.size() == 8);
        REQUIRE(results_b.size() == 8);
        for (int i = 0; i < 8; ++i)
        {
          REQUIRE(results_a[i].has_value());
          CHECK(results_a[i].value() == i + 100);
          REQUIRE(results_b[i].has_value());
          CHECK(results_b[i].value() == i + 200);
        }

        el.stop();
      }(event_loop, pool);
    });

  event_loop.run();
}

TEST_CASE("Work batch large")
{
  vio::event_loop_t event_loop;
  vio::thread_pool_t pool(4);

  event_loop.run_in_loop(
    [&event_loop, &pool]
    {
      [](vio::event_loop_t &el, vio::thread_pool_t &p) -> vio::task_t<void>
      {
        constexpr int count = 1000;
        std::vector<std::function<std::expected<int, vio::error_t>()>> work_items;
        work_items.reserve(count);
        for (int i = 0; i < count; ++i)
          work_items.emplace_back([i]() -> std::expected<int, vio::error_t> { return i; });

        auto batch = vio::schedule_work<int>(el, p, std::move(work_items));
        auto results = co_await batch;

        REQUIRE(results.size() == count);
        for (int i = 0; i < count; ++i)
        {
          REQUIRE(results[i].has_value());
          CHECK(results[i].value() == i);
        }

        el.stop();
      }(event_loop, pool);
    });

  event_loop.run();
}

TEST_CASE("Work batch cancel_remaining on failure")
{
  vio::event_loop_t event_loop;
  constexpr int pool_size = 4;
  vio::thread_pool_t pool(pool_size);

  event_loop.run_in_loop(
    [&event_loop, &pool]
    {
      [](vio::event_loop_t &el, vio::thread_pool_t &p) -> vio::task_t<void>
      {
        std::mutex mtx;
        std::condition_variable cv;
        std::atomic<int> threads_blocked{0};
        std::atomic<bool> release{false};

        std::vector<std::function<std::expected<int, vio::error_t>()>> work_items;

        // First pool_size items: block inside the work function, one of them fails
        for (int i = 0; i < pool_size; ++i)
        {
          work_items.emplace_back([&mtx, &cv, &threads_blocked, &release, i]() -> std::expected<int, vio::error_t>
          {
            threads_blocked.fetch_add(1, std::memory_order_release);
            std::unique_lock<std::mutex> lock(mtx);
            cv.wait(lock, [&release] { return release.load(std::memory_order_acquire); });
            if (i == 0)
              return std::unexpected(vio::error_t{.code = -1, .msg = "forced failure"});
            return i;
          });
        }

        // Remaining items: these will be queued but not started
        for (int i = pool_size; i < pool_size + 20; ++i)
        {
          work_items.emplace_back([i]() -> std::expected<int, vio::error_t> { return i; });
        }

        auto batch = vio::schedule_work<int>(el, p, std::move(work_items), vio::on_failure_t::cancel_remaining);

        // Spin until all pool threads are blocked
        while (threads_blocked.load(std::memory_order_acquire) < pool_size)
        {
          std::this_thread::yield();
        }

        // Release blocked threads — item 0 will fail and trigger auto-cancel
        {
          std::lock_guard<std::mutex> lock(mtx);
          release.store(true, std::memory_order_release);
        }
        cv.notify_all();

        auto results = co_await batch;

        REQUIRE(results.size() == pool_size + 20);
        // Item 0 failed
        CHECK(!results[0].has_value());
        CHECK(results[0].error().code == -1);
        // Items 1..pool_size-1 completed normally (already running before cancel)
        for (int i = 1; i < pool_size; ++i)
        {
          CHECK(results[i].has_value());
          CHECK(results[i].value() == i);
        }
        // Queued items should all be cancelled
        for (size_t i = pool_size; i < results.size(); ++i)
        {
          CHECK(!results[i].has_value());
          CHECK(results[i].error().code == UV_ECANCELED);
        }

        el.stop();
      }(event_loop, pool);
    });

  event_loop.run();
}

TEST_CASE("Work batch cancel_remaining all succeed")
{
  vio::event_loop_t event_loop;
  vio::thread_pool_t pool(4);

  event_loop.run_in_loop(
    [&event_loop, &pool]
    {
      [](vio::event_loop_t &el, vio::thread_pool_t &p) -> vio::task_t<void>
      {
        std::vector<std::function<std::expected<int, vio::error_t>()>> work_items;
        for (int i = 0; i < 10; ++i)
        {
          work_items.emplace_back([i]() -> std::expected<int, vio::error_t> { return i * i; });
        }

        auto batch = vio::schedule_work<int>(el, p, std::move(work_items), vio::on_failure_t::cancel_remaining);
        auto results = co_await batch;

        REQUIRE(results.size() == 10);
        for (int i = 0; i < 10; ++i)
        {
          REQUIRE(results[i].has_value());
          CHECK(results[i].value() == i * i);
        }

        el.stop();
      }(event_loop, pool);
    });

  event_loop.run();
}

TEST_CASE("Work batch continue_all with failures")
{
  vio::event_loop_t event_loop;
  constexpr int pool_size = 4;
  vio::thread_pool_t pool(pool_size);

  event_loop.run_in_loop(
    [&event_loop, &pool]
    {
      [](vio::event_loop_t &el, vio::thread_pool_t &p) -> vio::task_t<void>
      {
        std::mutex mtx;
        std::condition_variable cv;
        std::atomic<int> threads_blocked{0};
        std::atomic<bool> release{false};

        std::vector<std::function<std::expected<int, vio::error_t>()>> work_items;

        // First pool_size items: block, one fails
        for (int i = 0; i < pool_size; ++i)
        {
          work_items.emplace_back([&mtx, &cv, &threads_blocked, &release, i]() -> std::expected<int, vio::error_t>
          {
            threads_blocked.fetch_add(1, std::memory_order_release);
            std::unique_lock<std::mutex> lock(mtx);
            cv.wait(lock, [&release] { return release.load(std::memory_order_acquire); });
            if (i == 0)
              return std::unexpected(vio::error_t{.code = -1, .msg = "forced failure"});
            return i;
          });
        }

        // Remaining items
        for (int i = pool_size; i < pool_size + 20; ++i)
        {
          work_items.emplace_back([i]() -> std::expected<int, vio::error_t> { return i; });
        }

        auto batch = vio::schedule_work<int>(el, p, std::move(work_items), vio::on_failure_t::continue_all);

        while (threads_blocked.load(std::memory_order_acquire) < pool_size)
        {
          std::this_thread::yield();
        }

        {
          std::lock_guard<std::mutex> lock(mtx);
          release.store(true, std::memory_order_release);
        }
        cv.notify_all();

        auto results = co_await batch;

        REQUIRE(results.size() == pool_size + 20);
        CHECK(!results[0].has_value());
        // With continue_all, remaining items should NOT be cancelled
        for (int i = 1; i < pool_size; ++i)
        {
          CHECK(results[i].has_value());
          CHECK(results[i].value() == i);
        }
        for (size_t i = pool_size; i < results.size(); ++i)
        {
          CHECK(results[i].has_value());
          CHECK(results[i].value() == static_cast<int>(i));
        }

        el.stop();
      }(event_loop, pool);
    });

  event_loop.run();
}

TEST_CASE("Work batch custom error type")
{
  struct custom_error_t
  {
    int code;
    std::string detail;
    custom_error_t() = default;
    custom_error_t(vio::error_t e)
      : code(e.code)
      , detail(std::move(e.msg))
    {
    }
    custom_error_t(int c, std::string d)
      : code(c)
      , detail(std::move(d))
    {
    }
  };

  vio::event_loop_t event_loop;
  vio::thread_pool_t pool(4);

  event_loop.run_in_loop(
    [&event_loop, &pool]
    {
      [](vio::event_loop_t &el, vio::thread_pool_t &p) -> vio::task_t<void>
      {
        struct custom_error_t
        {
          int code;
          std::string detail;
          custom_error_t() = default;
          custom_error_t(vio::error_t e)
            : code(e.code)
            , detail(std::move(e.msg))
          {
          }
          custom_error_t(int c, std::string d)
            : code(c)
            , detail(std::move(d))
          {
          }
        };

        std::vector<std::function<std::expected<int, custom_error_t>()>> work_items;
        work_items.emplace_back([]() -> std::expected<int, custom_error_t> { return 42; });
        work_items.emplace_back([]() -> std::expected<int, custom_error_t>
        {
          return std::unexpected(custom_error_t{-1, "custom fail"});
        });
        work_items.emplace_back([]() -> std::expected<int, custom_error_t> { return 99; });

        auto batch = vio::schedule_work<int, custom_error_t>(el, p, std::move(work_items));
        auto results = co_await batch;

        REQUIRE(results.size() == 3);
        CHECK(results[0].has_value());
        CHECK(results[0].value() == 42);
        CHECK(!results[1].has_value());
        CHECK(results[1].error().code == -1);
        CHECK(results[1].error().detail == "custom fail");
        CHECK(results[2].has_value());
        CHECK(results[2].value() == 99);

        el.stop();
      }(event_loop, pool);
    });

  event_loop.run();
}

TEST_CASE("Work batch custom error type with cancel_remaining")
{
  struct custom_error_t
  {
    int code;
    std::string detail;
    custom_error_t() = default;
    custom_error_t(vio::error_t e)
      : code(e.code)
      , detail(std::move(e.msg))
    {
    }
    custom_error_t(int c, std::string d)
      : code(c)
      , detail(std::move(d))
    {
    }
  };

  vio::event_loop_t event_loop;
  constexpr int pool_size = 4;
  vio::thread_pool_t pool(pool_size);

  event_loop.run_in_loop(
    [&event_loop, &pool]
    {
      [](vio::event_loop_t &el, vio::thread_pool_t &p) -> vio::task_t<void>
      {
        struct custom_error_t
        {
          int code;
          std::string detail;
          custom_error_t() = default;
          custom_error_t(vio::error_t e)
            : code(e.code)
            , detail(std::move(e.msg))
          {
          }
          custom_error_t(int c, std::string d)
            : code(c)
            , detail(std::move(d))
          {
          }
        };

        std::mutex mtx;
        std::condition_variable cv;
        std::atomic<int> threads_blocked{0};
        std::atomic<bool> release{false};

        std::vector<std::function<std::expected<int, custom_error_t>()>> work_items;

        for (int i = 0; i < pool_size; ++i)
        {
          work_items.emplace_back([&mtx, &cv, &threads_blocked, &release, i]() -> std::expected<int, custom_error_t>
          {
            threads_blocked.fetch_add(1, std::memory_order_release);
            std::unique_lock<std::mutex> lock(mtx);
            cv.wait(lock, [&release] { return release.load(std::memory_order_acquire); });
            if (i == 0)
              return std::unexpected(custom_error_t{-1, "custom failure"});
            return i;
          });
        }

        for (int i = pool_size; i < pool_size + 10; ++i)
        {
          work_items.emplace_back([i]() -> std::expected<int, custom_error_t> { return i; });
        }

        auto batch = vio::schedule_work<int, custom_error_t>(el, p, std::move(work_items), vio::on_failure_t::cancel_remaining);

        while (threads_blocked.load(std::memory_order_acquire) < pool_size)
        {
          std::this_thread::yield();
        }

        {
          std::lock_guard<std::mutex> lock(mtx);
          release.store(true, std::memory_order_release);
        }
        cv.notify_all();

        auto results = co_await batch;

        REQUIRE(results.size() == pool_size + 10);
        CHECK(!results[0].has_value());
        CHECK(results[0].error().code == -1);
        CHECK(results[0].error().detail == "custom failure");
        for (int i = 1; i < pool_size; ++i)
        {
          CHECK(results[i].has_value());
        }
        // Cancelled items get error_t converted to custom_error_t
        for (size_t i = pool_size; i < results.size(); ++i)
        {
          CHECK(!results[i].has_value());
          CHECK(results[i].error().code == UV_ECANCELED);
        }

        el.stop();
      }(event_loop, pool);
    });

  event_loop.run();
}

TEST_CASE("Work batch resumes on event loop thread")
{
  vio::event_loop_t event_loop;
  vio::thread_pool_t pool(4);

  event_loop.run_in_loop(
    [&event_loop, &pool]
    {
      [](vio::event_loop_t &el, vio::thread_pool_t &p) -> vio::task_t<void>
      {
        auto event_loop_thread_id = std::this_thread::get_id();

        std::vector<std::function<std::expected<int, vio::error_t>()>> work_items;
        work_items.emplace_back([]() -> std::expected<int, vio::error_t> { return 1; });

        auto batch = vio::schedule_work<int>(el, p, std::move(work_items));
        co_await batch;

        // After co_await, we should be back on the event loop thread
        CHECK(std::this_thread::get_id() == event_loop_thread_id);

        el.stop();
      }(event_loop, pool);
    });

  event_loop.run();
}
