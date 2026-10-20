/*
Copyright (c) 2025 Jørgen Lind

  Permission is hereby granted, free of charge, to any person obtaining a copy of
  this software and associated documentation files (the "Software"), to deal in
  the Software without restriction, including without limitation the rights to
  use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
  of the Software, and to permit persons to whom the Software is furnished to do
  so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
*/

#include <doctest/doctest.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include <vio/event_loop.h>
#include <vio/event_pipe.h>
#include <vio/loop/blocking_pool.h>
#include <vio/loop/socket.h>
#include <vio/operation/sleep.h>
#include <vio/operation/tcp.h>
#include <vio/operation/tcp_server.h>
#include <vio/operation/timer.h>
#include <vio/operation/tls_client.h>
#include <vio/operation/tls_server.h>
#include <vio/ref_counted_wrapper.h>
#include <vio/task.h>

#include "tls_test_helpers.h"

#if !defined(_WIN32)
#include <cerrno>
#include <csignal>
#include <fcntl.h>
#include <poll.h>
#if defined(__linux__)
#include <sys/prctl.h>
#endif
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#if defined(__SANITIZE_THREAD__)
#define VIO_LOOP_TEST_UNDER_TSAN 1
#elif defined(__has_feature)
#if __has_feature(thread_sanitizer)
#define VIO_LOOP_TEST_UNDER_TSAN 1
#endif
#endif

#if defined(__SANITIZE_ADDRESS__)
#define VIO_LOOP_TEST_UNDER_ASAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define VIO_LOOP_TEST_UNDER_ASAN 1
#endif
#endif

#if !defined(VIO_LOOP_TEST_UNDER_ASAN)
constexpr bool allocator_survives_fork_while_others_allocate = true;
#else
constexpr bool allocator_survives_fork_while_others_allocate = false;
#endif

using namespace std::chrono_literals;

namespace
{
struct turn_counter_t
{
  vio::detail::hook_t hook;
  std::int64_t turns = 0;

  turn_counter_t()
  {
    hook.owner = this;
    hook.run = [](vio::detail::hook_t *raw) { ++static_cast<turn_counter_t *>(raw->owner)->turns; };
  }
};

struct held_resource_t final : vio::detail::resource_t
{
  explicit held_resource_t(vio::event_loop_t &loop)
    : resource_t(vio::detail::core(loop), "held")
  {
  }
  void do_close() noexcept override
  {
    close_finished();
  }
};

struct holder_t
{
  held_resource_t resource;
  bool &freed;
  holder_t(vio::event_loop_t &loop, bool &freed)
    : resource(loop)
    , freed(freed)
  {
  }
  holder_t(const holder_t &) = delete;
  holder_t &operator=(const holder_t &) = delete;
  holder_t(holder_t &&) = delete;
  holder_t &operator=(holder_t &&) = delete;
  ~holder_t()
  {
    freed = true;
  }
};

vio::ref_ptr_t<holder_t> make_holder(vio::event_loop_t &loop, bool &freed)
{
  vio::ref_ptr_t<holder_t> holder(loop, freed);
  holder.register_resource(holder->resource);
  return holder;
}

vio::timer_t make_timer(vio::event_loop_t &loop)
{
  auto created = vio::timer_create(loop);
  REQUIRE(created.has_value());
  return std::move(created.value());
}

void barrier(vio::event_loop_t &loop)
{
  std::promise<void> passed;
  auto future = passed.get_future();
  loop.run_in_loop([&passed] { passed.set_value(); });
  future.wait();
}
} // namespace

TEST_CASE("run_in_loop work runs and stop ends run")
{
  vio::event_loop_t loop;
  int runs = 0;
  loop.run_in_loop([&] {
    ++runs;
    loop.stop();
  });
  loop.run();
  CHECK(runs == 1);
}

TEST_CASE("stop before run still runs work posted before it")
{
  vio::event_loop_t loop;
  std::vector<int> order;
  loop.run_in_loop([&] { order.push_back(1); });
  loop.stop();
  loop.run_in_loop([&] { order.push_back(2); });
  loop.run();
  CHECK(order == std::vector<int>{1, 2});
}

TEST_CASE("posts from many threads all run, in order per thread")
{
  vio::event_loop_t loop;
  constexpr int threads = 4;
  constexpr int posts = 2000;
  std::vector<std::vector<int>> seen(threads);
  std::atomic<int> remaining{threads * posts};
  std::vector<std::thread> posters;
  for (int t = 0; t < threads; ++t)
  {
    posters.emplace_back([&, t] {
      for (int i = 0; i < posts; ++i)
      {
        loop.run_in_loop([&, t, i] {
          seen[t].push_back(i);
          if (--remaining == 0)
            loop.stop();
        });
      }
    });
  }
  loop.run();
  for (auto &poster : posters)
    poster.join();
  for (int t = 0; t < threads; ++t)
  {
    REQUIRE(seen[t].size() == posts);
    for (int i = 0; i < posts; ++i)
      CHECK(seen[t][i] == i);
  }
}

TEST_CASE("timers fire in deadline order and equal deadlines keep their order")
{
  vio::event_loop_t loop;
  auto &core = vio::detail::core(loop);
  std::vector<int> order;
  struct fired_t
  {
    vio::detail::timer_node_t node;
    std::vector<int> *order;
    int id;
  };
  std::vector<fired_t> timers(5);
  auto base = vio::detail::loop_core_t::now() + 5'000'000;
  std::int64_t offsets[] = {3, 1, 1, 0, 2};
  for (int i = 0; i < 5; ++i)
  {
    timers[i].order = &order;
    timers[i].id = i;
    timers[i].node.owner = &timers[i];
    timers[i].node.fire = [](vio::detail::timer_node_t *node) {
      auto *self = static_cast<fired_t *>(node->owner);
      self->order->push_back(self->id);
    };
    core.add_timer(timers[i].node, base + offsets[i] * 1'000'000);
  }
  loop.stop();
  loop.run();
  CHECK(order == std::vector<int>{3, 1, 2, 4, 0});
}

TEST_CASE("a timer rearmed into the past from its own callback fires on a later turn")
{
  vio::event_loop_t loop;
  auto &core = vio::detail::core(loop);
  turn_counter_t counter;
  core.add_hook(counter.hook);
  struct state_t
  {
    vio::detail::timer_node_t node;
    vio::detail::loop_core_t *core = nullptr;
    turn_counter_t *counter = nullptr;
    std::vector<std::int64_t> turns;
  } state;
  state.core = &core;
  state.counter = &counter;
  state.node.owner = &state;
  state.node.fire = [](vio::detail::timer_node_t *node) {
    auto *self = static_cast<state_t *>(node->owner);
    self->turns.push_back(self->counter->turns);
    if (self->turns.size() < 5)
      self->core->add_timer(self->node, vio::detail::loop_core_t::now() - 1'000'000'000);
  };
  core.add_timer(state.node, vio::detail::loop_core_t::now() - 1'000'000'000);
  loop.stop();
  loop.run();
  core.remove_hook(counter.hook);
  REQUIRE(state.turns.size() == 5);
  for (std::size_t i = 1; i < state.turns.size(); ++i)
    CHECK(state.turns[i] > state.turns[i - 1]);
}

TEST_CASE("sleep waits about the time asked and a negative sleep still returns")
{
  vio::event_loop_t loop;
  std::optional<vio::task_t<void>> task;
  std::chrono::steady_clock::duration slept{};
  bool negative_done = false;
  loop.run_in_loop([&] {
    task.emplace([](vio::event_loop_t &loop, std::chrono::steady_clock::duration &slept, bool &negative_done) -> vio::task_t<void> {
      auto start = std::chrono::steady_clock::now();
      auto result = co_await vio::sleep(loop, 20ms);
      CHECK(result.has_value());
      slept = std::chrono::steady_clock::now() - start;
      auto negative = co_await vio::sleep(loop, -5ms);
      negative_done = negative.has_value();
      loop.stop();
    }(loop, slept, negative_done));
  });
  loop.run();
  CHECK(slept >= 20ms);
  CHECK(slept < 2s);
  CHECK(negative_done);
}

TEST_CASE("a cancelled sleep resumes at once with the cancel code")
{
  vio::event_loop_t loop;
  std::optional<vio::task_t<void>> task;
  vio::cancellation_t cancel;
  int code = 0;
  loop.run_in_loop([&] {
    task.emplace([](vio::event_loop_t &loop, vio::cancellation_t &cancel, int &code) -> vio::task_t<void> {
      auto pending = vio::sleep(loop, 10s, &cancel);
      loop.run_in_loop([&cancel] { cancel.cancel(); });
      auto result = co_await pending;
      code = result.has_value() ? 0 : result.error().code;
      loop.stop();
    }(loop, cancel, code));
  });
  loop.run();
  CHECK(code == vio::vio_cancelled);
}

TEST_CASE("run after stop waits for a timer that keeps the loop alive")
{
  vio::event_loop_t loop;
  std::optional<vio::task_t<void>> task;
  bool finished = false;
  loop.run_in_loop([&] {
    task.emplace([](vio::event_loop_t &loop, bool &finished) -> vio::task_t<void> {
      loop.stop();
      co_await vio::sleep(loop, 15ms);
      finished = true;
    }(loop, finished));
  });
  loop.run();
  CHECK(finished);
}

TEST_CASE("timer_t rearms, disarms, and survives dropping itself in its own callback")
{
  vio::event_loop_t loop;
  int fired = 0;
  std::optional<vio::timer_t> timer;
  loop.run_in_loop([&] {
    auto created = vio::timer_create(loop);
    REQUIRE(created.has_value());
    timer.emplace(std::move(*created));
    vio::timer_on_fire(*timer, [&] {
      ++fired;
      if (fired == 1)
      {
        CHECK_FALSE(vio::timer_is_armed(*timer));
        (void)vio::timer_rearm(*timer, 1ms);
        return;
      }
      timer.reset();
      loop.stop();
    });
    (void)vio::timer_rearm(*timer, 1ms);
    CHECK(vio::timer_is_armed(*timer));
  });
  loop.run();
  CHECK(fired == 2);
}

TEST_CASE("a resource is freed only on a later turn")
{
  vio::event_loop_t loop;
  auto &core = vio::detail::core(loop);
  struct probe_t final : vio::detail::resource_t
  {
    explicit probe_t(vio::detail::loop_core_t &loop)
      : resource_t(loop, "probe")
    {
    }
    void do_close() noexcept override
    {
      close_finished();
    }
  };
  struct context_t
  {
    probe_t *probe;
    bool done = false;
  };
  context_t context{new probe_t(core)};
  CHECK(core.open_resources() == 1);
  loop.run_in_loop([&] {
    context.probe->close(
      [](void *raw) {
        auto *ctx = static_cast<context_t *>(raw);
        ctx->done = true;
        delete ctx->probe;
      },
      &context);
    CHECK_FALSE(context.done);
    loop.stop();
  });
  loop.run();
  CHECK(context.done);
  CHECK(core.open_resources() == 0);
}

TEST_CASE("event pipes deliver every event and a void pipe coalesces")
{
  vio::event_loop_t loop;
  std::vector<int> values;
  int signals = 0;
  vio::event_pipe_t<int> pipe(loop, [&](int &&value) {
    values.push_back(value);
    if (values.size() == 100)
      loop.stop();
  });
  vio::event_pipe_t<void> signal(loop, [&] { ++signals; });
  std::thread poster([&] {
    for (int i = 0; i < 100; ++i)
      pipe.post_event(int(i));
  });
  signal.post_event();
  signal.post_event();
  signal.post_event();
  loop.run();
  poster.join();
  REQUIRE(values.size() == 100);
  for (int i = 0; i < 100; ++i)
    CHECK(values[i] == i);
  CHECK(signals == 1);
}

TEST_CASE("about-to-block listeners run before the loop waits and stop after stop")
{
  struct counting_t : vio::about_to_block_t
  {
    int calls = 0;
    void about_to_block() override
    {
      ++calls;
    }
  };
  vio::event_loop_t loop;
  counting_t listener;
  std::thread adder([&] { loop.add_about_to_block_listener(&listener); });
  adder.join();
  int calls_at_inner = -1;
  loop.run_in_loop([&] {
    loop.run_in_loop([&] {
      calls_at_inner = listener.calls;
      loop.stop();
    });
  });
  loop.run();
  CHECK(calls_at_inner >= 1);
  int after_first_run = listener.calls;
  loop.run_in_loop([] {});
  loop.run();
  CHECK(listener.calls == after_first_run);
  loop.remove_about_to_block_listener(&listener);
  loop.run();
}

TEST_CASE("blocking pool work runs off the loop and completes on it")
{
  vio::event_loop_t loop;
  auto &core = vio::detail::core(loop);
  struct job_t
  {
    vio::detail::pool_job_t job;
    std::thread::id worker;
    std::thread::id finisher;
    bool canceled = true;
  } job;
  job.job.owner = &job;
  job.job.work = [](vio::detail::pool_job_t *raw) { static_cast<job_t *>(raw->owner)->worker = std::this_thread::get_id(); };
  job.job.done = [](vio::detail::pool_job_t *raw, bool canceled) {
    auto *self = static_cast<job_t *>(raw->owner);
    self->finisher = std::this_thread::get_id();
    self->canceled = canceled;
  };
  loop.run_in_loop([&] { vio::detail::pool_submit(core, job.job, vio::detail::pool_queue::file); });
  loop.stop();
  loop.run();
  CHECK_FALSE(job.canceled);
  CHECK(job.finisher == std::this_thread::get_id());
  CHECK(job.worker != std::this_thread::get_id());
}

TEST_CASE("the backend named in VIO_BACKEND is the one that runs")
{
  vio::event_loop_t loop;
  const char *requested = std::getenv("VIO_BACKEND");
  if (requested && *requested)
    CHECK(std::string(loop.backend_name()) == requested);
  else
    CHECK(std::strlen(loop.backend_name()) > 0);
}

TEST_CASE("thread_with_event_loop_t runs posted work and joins")
{
  std::atomic<bool> ran{false};
  {
    vio::thread_with_event_loop_t thread;
    thread.event_loop().run_in_loop([&] { ran = true; });
    thread.stop_and_join();
  }
  CHECK(ran);
}

TEST_CASE("work posted before stop from another thread always runs")
{
  for (int round = 0; round < 50; ++round)
  {
    std::atomic<int> ran{0};
    {
      vio::thread_with_event_loop_t thread;
      auto &loop = thread.event_loop();
      for (int i = 0; i < 100; ++i)
        loop.run_in_loop([&ran] { ran.fetch_add(1, std::memory_order_relaxed); });
      thread.stop_and_join();
    }
    REQUIRE(ran.load() == 100);
  }
}

TEST_CASE("work posted by a callback after stop still runs")
{
  vio::event_loop_t loop;
  std::vector<int> order;
  loop.run_in_loop([&] {
    loop.stop();
    loop.run_in_loop([&] {
      order.push_back(1);
      loop.run_in_loop([&] { order.push_back(2); });
    });
  });
  loop.run();
  CHECK(order == std::vector<int>{1, 2});
}

TEST_CASE("many timers at one deadline fire in the order they were armed")
{
  vio::event_loop_t loop;
  auto &core = vio::detail::core(loop);
  constexpr int count = 1000;
  struct fired_t
  {
    vio::detail::timer_node_t node;
    std::vector<int> *order = nullptr;
    int id = 0;
  };
  std::vector<fired_t> timers(count);
  std::vector<int> order;
  std::vector<int> expected;
  const auto deadline = vio::detail::loop_core_t::now() + 2'000'000;
  for (int i = 0; i < count; ++i)
  {
    auto &timer = timers[static_cast<std::size_t>(i)];
    timer.order = &order;
    timer.id = i;
    timer.node.owner = &timer;
    timer.node.fire = [](vio::detail::timer_node_t *node) {
      auto *self = static_cast<fired_t *>(node->owner);
      self->order->push_back(self->id);
    };
    core.add_timer(timer.node, deadline);
  }
  for (int i = 0; i < count; ++i)
  {
    if (i % 11 == 0)
      core.remove_timer(timers[static_cast<std::size_t>(i)].node);
    else if (i % 7 != 0)
      expected.push_back(i);
  }
  for (int i = count - 1; i >= 0; --i)
  {
    if (i % 7 == 0 && i % 11 != 0)
    {
      core.add_timer(timers[static_cast<std::size_t>(i)].node, deadline);
      expected.push_back(i);
    }
  }
  loop.stop();
  loop.run();
  CHECK(order == expected);
  CHECK(core.in_flight() == 0);
}

TEST_CASE("about-to-block listeners added and removed from another thread are done with once a barrier passes")
{
  struct listener_t : vio::about_to_block_t
  {
    std::atomic<int> calls{0};
    void about_to_block() override
    {
      calls.fetch_add(1, std::memory_order_relaxed);
    }
  };
  vio::thread_with_event_loop_t thread;
  auto &loop = thread.event_loop();

  for (int round = 0; round < 100; ++round)
  {
    auto listener = std::make_unique<listener_t>();
    loop.add_about_to_block_listener(listener.get());
    barrier(loop);
    const auto give_up = std::chrono::steady_clock::now() + 5s;
    while (listener->calls.load() == 0 && std::chrono::steady_clock::now() < give_up)
      barrier(loop);
    REQUIRE(listener->calls.load() > 0);

    loop.remove_about_to_block_listener(listener.get());
    barrier(loop);
    const int settled = listener->calls.load();
    barrier(loop);
    barrier(loop);
    REQUIRE(listener->calls.load() == settled);
    listener.reset();
    barrier(loop);

    auto fleeting = std::make_unique<listener_t>();
    loop.add_about_to_block_listener(fleeting.get());
    loop.remove_about_to_block_listener(fleeting.get());
    barrier(loop);
    fleeting.reset();
    barrier(loop);
  }
  thread.stop_and_join();
}

TEST_CASE("stop followed by dropping handles in the same frame closes them before run returns")
{
  vio::event_loop_t loop;
  auto &core = vio::detail::core(loop);
  bool fired = false;
  bool freed = false;
  std::optional<vio::task_t<void>> task;

  SUBCASE("in a posted callback")
  {
    loop.run_in_loop([&] {
      auto timer = make_timer(loop);
      vio::timer_on_fire(timer, [&fired] { fired = true; });
      REQUIRE(vio::timer_rearm(timer, 10s).has_value());
      auto holder = make_holder(loop, freed);
      loop.stop();
    });
  }

  SUBCASE("in a coroutine frame that ends after stop")
  {
    loop.run_in_loop([&] {
      task.emplace([](vio::event_loop_t &loop, bool &fired, bool &freed) -> vio::task_t<void> {
        auto timer = make_timer(loop);
        vio::timer_on_fire(timer, [&fired] { fired = true; });
        REQUIRE(vio::timer_rearm(timer, 10s).has_value());
        auto holder = make_holder(loop, freed);
        auto slept = co_await vio::sleep(loop, 1ms);
        CHECK(slept.has_value());
        loop.stop();
      }(loop, fired, freed));
    });
  }

  const auto start = std::chrono::steady_clock::now();
  loop.run();
  CHECK(std::chrono::steady_clock::now() - start < 5s);
  CHECK_FALSE(fired);
  CHECK(freed);
  CHECK(core.open_resources() == 0);
  CHECK(core.in_flight() == 0);
  CHECK((!task.has_value() || task->done()));
}

TEST_CASE("a loop with a ticking timer does not spin over an idle second")
{
  vio::event_loop_t loop;
  auto &core = vio::detail::core(loop);
  turn_counter_t counter;
  core.add_hook(counter.hook);

  constexpr int ticks_wanted = 100;
  int ticks = 0;
  int early = 0;
  std::int64_t due = 0;
  std::optional<vio::timer_t> timer;
  timer.emplace(make_timer(loop));
  auto arm = [&] {
    due = vio::detail::loop_core_t::now() + std::chrono::nanoseconds(10ms).count();
    REQUIRE(vio::timer_rearm(*timer, 10ms).has_value());
  };
  vio::timer_on_fire(*timer, [&] {
    if (vio::detail::loop_core_t::now() < due)
      ++early;
    if (++ticks == ticks_wanted)
    {
      timer.reset();
      loop.stop();
      return;
    }
    arm();
  });
  arm();

  const auto start = std::chrono::steady_clock::now();
  loop.run();
  const auto elapsed = std::chrono::steady_clock::now() - start;
  core.remove_hook(counter.hook);

  MESSAGE("turns: " << counter.turns << " for " << ticks << " ticks");
  CHECK(ticks == ticks_wanted);
  CHECK(early == 0);
  CHECK(elapsed >= 1s);
  CHECK(counter.turns <= 3 * ticks_wanted + 20);
}

TEST_CASE("an idle loop blocks instead of turning")
{
  vio::thread_with_event_loop_t thread;
  auto &loop = thread.event_loop();
  turn_counter_t counter;
  loop.run_in_loop([&] { vio::detail::core(loop).add_hook(counter.hook); });
  barrier(loop);
  std::this_thread::sleep_for(300ms);
  std::int64_t turns = -1;
  std::promise<void> read;
  auto read_future = read.get_future();
  loop.run_in_loop([&] {
    turns = counter.turns;
    vio::detail::core(loop).remove_hook(counter.hook);
    read.set_value();
  });
  read_future.wait();
  thread.stop_and_join();
  MESSAGE("turns while idle: " << turns);
  CHECK(turns >= 1);
  CHECK(turns <= 5);
}

TEST_CASE("a loop can be destroyed as soon as work posted from another thread has run")
{
  struct spinner_t
  {
    vio::event_loop_t *loop;
    void spin()
    {
      if (!vio::detail::core(*loop).stopping())
        loop->run_in_loop([this] { spin(); });
    }
  };
  for (int i = 0; i < 2000; ++i)
  {
    auto loop = std::make_unique<vio::event_loop_t>();
    auto *raw = loop.get();
    spinner_t spinner{raw};
    std::atomic<bool> go{false};
    std::thread poster([raw, &go] {
      while (!go.load())
      {
      }
      raw->stop();
    });
    raw->run_in_loop([&] {
      spinner.spin();
      go = true;
    });
    raw->run();
    loop.reset();
    poster.join();
  }
}

TEST_CASE("work dropped with its loop may post more work from a destructor")
{
  struct flag_on_drop_t
  {
    bool *flag;
    ~flag_on_drop_t()
    {
      *flag = true;
    }
  };
  struct post_on_drop_t
  {
    vio::event_loop_t *loop;
    bool *flag;
    ~post_on_drop_t()
    {
      loop->run_in_loop([inner = std::make_shared<flag_on_drop_t>(flag)] {});
    }
  };
  bool inner_dropped = false;
  {
    vio::event_loop_t loop;
    loop.stop();
    loop.run();
    loop.run_in_loop([outer = std::make_shared<post_on_drop_t>(&loop, &inner_dropped)] {});
  }
  CHECK(inner_dropped);
}

namespace
{
struct recorded_node_t : vio::detail::posted_t
{
  std::vector<char> *order = nullptr;
  char name = 0;
  std::function<void()> also;

  recorded_node_t(std::vector<char> &order, char name)
    : order(&order)
    , name(name)
  {
    owner = this;
    run = [](vio::detail::posted_t *raw) {
      auto *self = static_cast<recorded_node_t *>(raw->owner);
      self->order->push_back(self->name);
      if (self->also)
        self->also();
    };
  }
};
} // namespace

TEST_CASE("unpost takes a node out of deferred work that is being drained")
{
  vio::event_loop_t loop;
  auto &core = vio::detail::core(loop);
  std::vector<char> order;
  recorded_node_t first(order, 'a');
  recorded_node_t second(order, 'b');
  recorded_node_t third(order, 'c');
  bool removed = false;
  first.also = [&] {
    removed = core.unpost(second);
    core.defer(second);
  };
  loop.run_in_loop([&] {
    core.defer(first);
    core.defer(second);
    core.defer(third);
  });
  loop.stop();
  loop.run();
  CHECK(removed);
  CHECK(order == std::vector<char>{'a', 'c', 'b'});
  CHECK_FALSE(second.queued);
  CHECK_FALSE(third.queued);
}

TEST_CASE("unpost reports only posted work that has not run yet")
{
  vio::event_loop_t loop;
  auto &core = vio::detail::core(loop);
  std::vector<char> order;
  recorded_node_t first(order, 'a');
  recorded_node_t second(order, 'b');
  recorded_node_t third(order, 'c');
  bool removed_ran = true;
  bool removed_pending = false;
  second.also = [&] {
    removed_ran = core.unpost(first);
    removed_pending = core.unpost(third);
  };
  core.post(first);
  core.post(second);
  core.post(third);
  loop.stop();
  loop.run();
  CHECK_FALSE(removed_ran);
  CHECK(removed_pending);
  CHECK(order == std::vector<char>{'a', 'b'});
}

namespace
{
struct callback_failed_t
{
};
} // namespace

TEST_CASE("deferred work queued behind a callback that throws stays queued and runs on the next run")
{
  vio::event_loop_t loop;
  auto &core = vio::detail::core(loop);
  std::vector<char> order;
  recorded_node_t first(order, 'a');
  recorded_node_t second(order, 'b');
  recorded_node_t third(order, 'c');
  recorded_node_t fourth(order, 'd');
  first.also = [&] {
    core.defer(fourth);
    throw callback_failed_t{};
  };
  loop.run_in_loop([&] {
    core.defer(first);
    core.defer(second);
    core.defer(third);
  });
  loop.stop();
  CHECK_THROWS_AS(loop.run(), callback_failed_t);
  CHECK(order == std::vector<char>{'a'});
  CHECK(second.queued);
  CHECK(third.queued);
  CHECK(core.unpost(second));
  CHECK_FALSE(second.queued);
  loop.run();
  CHECK(order == std::vector<char>{'a', 'c', 'd'});
  CHECK_FALSE(third.queued);
  CHECK_FALSE(fourth.queued);
}

TEST_CASE("posted work queued behind a callback that throws stays queued and runs on the next run")
{
  vio::event_loop_t loop;
  auto &core = vio::detail::core(loop);
  std::vector<char> order;
  recorded_node_t first(order, 'a');
  recorded_node_t second(order, 'b');
  recorded_node_t third(order, 'c');
  recorded_node_t fourth(order, 'd');
  auto closure_alive = std::make_shared<int>(0);
  std::weak_ptr<int> closure_watch = closure_alive;
  first.also = [&] {
    core.post(fourth);
    core.post(third);
    throw callback_failed_t{};
  };
  core.post(first);
  loop.run_in_loop([&order, held = std::move(closure_alive)] { order.push_back('x'); });
  core.post(second);
  core.post(third);
  CHECK_THROWS_AS(loop.run(), callback_failed_t);
  CHECK(order == std::vector<char>{'a'});
  CHECK(second.queued);
  CHECK(third.queued);
  CHECK_FALSE(closure_watch.expired());
  loop.stop();
  loop.run();
  CHECK(order == std::vector<char>{'a', 'x', 'b', 'c', 'd'});
  CHECK(closure_watch.expired());
  CHECK_FALSE(second.queued);
  CHECK_FALSE(third.queued);
}

#if !defined(_WIN32) && !defined(VIO_LOOP_TEST_UNDER_TSAN)
namespace
{
int wait_for_child(pid_t child, std::chrono::milliseconds limit)
{
  const auto give_up = std::chrono::steady_clock::now() + limit;
  int status = 0;
  for (;;)
  {
    pid_t done = ::waitpid(child, &status, WNOHANG);
    if (done == child)
      return status;
    if (done < 0 && errno != EINTR)
      return -1;
    if (std::chrono::steady_clock::now() > give_up)
    {
      ::kill(child, SIGKILL);
      ::waitpid(child, &status, 0);
      return -1;
    }
    std::this_thread::sleep_for(5ms);
  }
}

struct pool_probe_t
{
  vio::detail::pool_job_t job;
  bool ran = false;
  bool finished = false;
  bool canceled = true;

  pool_probe_t()
  {
    job.owner = this;
    job.work = [](vio::detail::pool_job_t *raw) { static_cast<pool_probe_t *>(raw->owner)->ran = true; };
    job.done = [](vio::detail::pool_job_t *raw, bool canceled) {
      auto *self = static_cast<pool_probe_t *>(raw->owner);
      self->finished = true;
      self->canceled = canceled;
      raw->loop->stop();
    };
  }
};

bool run_one_pool_job()
{
  vio::event_loop_t loop;
  pool_probe_t probe;
  loop.run_in_loop([&] { vio::detail::pool_submit(vio::detail::core(loop), probe.job, vio::detail::pool_queue::file); });
  loop.run();
  return probe.ran && probe.finished && !probe.canceled;
}

struct death_t
{
  int status = -1;
  std::string message;
};

struct child_pipe_t
{
  int ends[2] = {-1, -1};
};

void enter_child(child_pipe_t &pipe)
{
  std::signal(SIGABRT, SIG_DFL);
  rlimit no_core{0, 0};
  ::setrlimit(RLIMIT_CORE, &no_core);
#if defined(__linux__)
  ::setenv("VIO_BACKEND", "epoll", 1);
#endif
  ::dup2(pipe.ends[1], 2);
  ::close(pipe.ends[0]);
}

death_t watch_child(pid_t child, child_pipe_t &pipe, std::chrono::milliseconds limit)
{
  death_t result;
  ::close(pipe.ends[1]);
  const auto give_up = std::chrono::steady_clock::now() + limit;
  char buffer[512];
  for (;;)
  {
    const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(give_up - std::chrono::steady_clock::now());
    if (left.count() <= 0)
      break;
    pollfd readable{pipe.ends[0], POLLIN, 0};
    int ready = ::poll(&readable, 1, static_cast<int>(left.count()));
    if (ready < 0 && errno == EINTR)
      continue;
    if (ready <= 0)
      break;
    auto got = ::read(pipe.ends[0], buffer, sizeof(buffer));
    if (got > 0)
    {
      result.message.append(buffer, static_cast<std::size_t>(got));
      continue;
    }
    if (got < 0 && errno == EINTR)
      continue;
    break;
  }
  ::close(pipe.ends[0]);
  const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(give_up - std::chrono::steady_clock::now());
  result.status = wait_for_child(child, left.count() > 0 ? left : 0ms);
  return result;
}

template <typename F>
death_t run_in_child(F &&body, std::chrono::milliseconds limit = 20s)
{
  child_pipe_t pipe;
  if (::pipe(pipe.ends) != 0)
    return {};
  pid_t child = ::fork();
  if (child < 0)
  {
    ::close(pipe.ends[0]);
    ::close(pipe.ends[1]);
    return {};
  }
  if (child == 0)
  {
    enter_child(pipe);
    body();
    ::_exit(0);
  }
  return watch_child(child, pipe, limit);
}

bool aborted_with_message(const death_t &death)
{
  return death.status != -1 && WIFSIGNALED(death.status) && WTERMSIG(death.status) == SIGABRT &&
         death.message.find("destroyed while the loop or the kernel still held it") != std::string::npos;
}

bool aborted_by_fork_rule(const death_t &death, const char *action)
{
  return death.status != -1 && WIFSIGNALED(death.status) && WTERMSIG(death.status) == SIGABRT &&
         death.message.find(std::string("an event loop created before fork() was ") + action + " in the child") != std::string::npos &&
         death.message.find("a child may only destroy a loop it inherited and must create its own") != std::string::npos;
}

std::string describe(const death_t &death)
{
  std::string text = "status " + std::to_string(death.status);
  if (death.status != -1 && WIFSIGNALED(death.status))
    text += ", signal " + std::to_string(WTERMSIG(death.status));
  if (death.status != -1 && WIFEXITED(death.status))
    text += ", exit " + std::to_string(WEXITSTATUS(death.status));
  return text + ", output: " + death.message.substr(0, 400);
}

bool exited_quietly(const death_t &death)
{
  return death.status != -1 && WIFEXITED(death.status) && WEXITSTATUS(death.status) == 0 && death.message.empty();
}

struct parked_probe_t : vio::detail::io_op_t
{
  parked_probe_t()
  {
    owner = this;
    complete = [](vio::detail::io_op_t *) {};
  }
};
} // namespace

namespace
{
struct gated_job_t
{
  vio::detail::pool_job_t job;
  std::atomic<bool> *gate = nullptr;
  std::atomic<int> *started = nullptr;
  bool ran = false;
  bool finished = false;
  bool canceled = false;

  gated_job_t(std::atomic<bool> &gate, std::atomic<int> &started)
    : gate(&gate)
    , started(&started)
  {
    job.owner = this;
    job.work = [](vio::detail::pool_job_t *raw) {
      auto *self = static_cast<gated_job_t *>(raw->owner);
      self->started->fetch_add(1);
      while (!self->gate->load())
        std::this_thread::sleep_for(1ms);
      self->ran = true;
    };
    job.done = [](vio::detail::pool_job_t *raw, bool canceled) {
      auto *self = static_cast<gated_job_t *>(raw->owner);
      self->finished = true;
      self->canceled = canceled;
    };
  }
};

int file_pool_threads()
{
  const char *value = std::getenv("VIO_FILE_THREADS");
  if (!value)
    return 4;
  auto parsed = std::strtoul(value, nullptr, 10);
  return parsed == 0 || parsed > 1024 ? 4 : static_cast<int>(parsed);
}

void wait_for_started(std::atomic<int> &started, int wanted)
{
  const auto give_up = std::chrono::steady_clock::now() + 10s;
  while (started.load() < wanted && std::chrono::steady_clock::now() < give_up)
    std::this_thread::sleep_for(1ms);
}

void settle_file_pool()
{
  vio::event_loop_t loop;
  std::atomic<bool> gate{false};
  std::atomic<int> started{0};
  const int count = file_pool_threads();
  std::vector<std::unique_ptr<gated_job_t>> jobs;
  for (int i = 0; i < count; ++i)
  {
    jobs.push_back(std::make_unique<gated_job_t>(gate, started));
    vio::detail::pool_submit(vio::detail::core(loop), jobs.back()->job, vio::detail::pool_queue::file);
  }
  wait_for_started(started, count);
  gate = true;
  loop.stop();
  loop.run();
}
} // namespace

TEST_CASE("the blocking pool runs work in a process forked after it started")
{
  settle_file_pool();
  REQUIRE(run_one_pool_job());
  auto child = run_in_child([] { ::_exit(run_one_pool_job() ? 0 : 1); });
  REQUIRE(child.status != -1);
  CHECK(WIFEXITED(child.status));
  CHECK(WEXITSTATUS(child.status) == 0);
}

TEST_CASE("pool work in flight at a fork is abandoned when the child destroys the loop it inherited, and runs once, in the parent")
{
  settle_file_pool();
  std::optional<vio::event_loop_t> loop;
  loop.emplace();
  auto &core = vio::detail::core(*loop);
  std::atomic<bool> gate{false};
  std::atomic<int> started{0};
  const int count = file_pool_threads() + 8;
  std::vector<std::unique_ptr<gated_job_t>> jobs;
  for (int i = 0; i < count; ++i)
  {
    jobs.push_back(std::make_unique<gated_job_t>(gate, started));
    vio::detail::pool_submit(core, jobs.back()->job, vio::detail::pool_queue::file);
  }
  wait_for_started(started, file_pool_threads());
  REQUIRE(started.load() == file_pool_threads());

  auto child = run_in_child([&] {
    const int started_at_fork = started.load();
    loop.reset();
    for (auto &job : jobs)
    {
      if (job->finished || job->ran)
        ::_exit(1);
      if (job->job.state.load() != vio::detail::pool_job_finished)
        ::_exit(2);
    }
    if (!run_one_pool_job())
      ::_exit(3);
    ::_exit(started.load() == started_at_fork ? 0 : 4);
  });
  gate = true;
  loop->stop();
  loop->run();
  CHECK(exited_quietly(child));
  CHECK(child.message == "");
  CHECK(started.load() == count);
  for (auto &job : jobs)
  {
    CHECK(job->finished);
    CHECK_FALSE(job->canceled);
    CHECK(job->ran);
  }
  CHECK(core.in_flight() == 0);
}

TEST_CASE("pool work that finished but was not yet delivered at a fork is abandoned with the loop in the child")
{
  std::optional<vio::event_loop_t> loop;
  loop.emplace();
  auto &core = vio::detail::core(*loop);
  pool_probe_t probe;
  vio::detail::pool_submit(core, probe.job, vio::detail::pool_queue::file);
  const auto give_up = std::chrono::steady_clock::now() + 10s;
  while (probe.job.state.load(std::memory_order_acquire) != vio::detail::pool_job_finished && std::chrono::steady_clock::now() < give_up)
    std::this_thread::sleep_for(1ms);
  REQUIRE(probe.job.state.load(std::memory_order_acquire) == vio::detail::pool_job_finished);
  REQUIRE(core.in_flight() == 1);

  auto child = run_in_child([&] {
    loop.reset();
    ::_exit(probe.finished ? 1 : 0);
  });
  CHECK(exited_quietly(child));
  CHECK(child.message == "");
  loop->run();
  CHECK(probe.ran);
  CHECK(probe.finished);
  CHECK_FALSE(probe.canceled);
  CHECK(core.in_flight() == 0);
}

TEST_CASE("pool work in flight at a fork runs once, in the parent, and running the inherited loop in the child aborts naming the rule before any of its work runs")
{
  settle_file_pool();
  vio::event_loop_t loop;
  auto &core = vio::detail::core(loop);
  std::atomic<bool> gate{false};
  std::atomic<int> started{0};
  const int count = file_pool_threads() + 8;
  std::vector<std::unique_ptr<gated_job_t>> jobs;
  for (int i = 0; i < count; ++i)
  {
    jobs.push_back(std::make_unique<gated_job_t>(gate, started));
    vio::detail::pool_submit(core, jobs.back()->job, vio::detail::pool_queue::file);
  }
  wait_for_started(started, file_pool_threads());
  REQUIRE(started.load() == file_pool_threads());
  const pid_t parent = ::getpid();
  bool ran = false;
  loop.run_in_loop([&] {
    ran = true;
    static const char marker[] = "posted work ran in the child\n";
    if (::getpid() != parent)
      (void)!::write(2, marker, sizeof(marker) - 1);
  });

  auto child = run_in_child([&] {
    loop.stop();
    loop.run();
    ::_exit(5);
  });
  CHECK(aborted_by_fork_rule(child, "run"));
  CHECK(child.message.find("posted work ran in the child") == std::string::npos);
  gate = true;
  loop.stop();
  loop.run();
  CHECK(ran);
  CHECK(started.load() == count);
  for (auto &job : jobs)
  {
    CHECK(job->finished);
    CHECK_FALSE(job->canceled);
    CHECK(job->ran);
  }
  CHECK(core.in_flight() == 0);
}

namespace
{
struct fork_site_t
{
  pid_t parent = ::getpid();
  death_t child;
  int second_ran = 0;
  bool forked = false;

  void fork_here()
  {
    if (forked)
      return;
    forked = true;
    child_pipe_t pipe;
    if (::pipe(pipe.ends) != 0)
      return;
    pid_t pid = ::fork();
    if (pid == 0)
    {
      enter_child(pipe);
      return;
    }
    child = watch_child(pid, pipe, 20s);
  }

  void leave_if_child() const
  {
    if (::getpid() != parent)
      ::_exit(7);
  }

  void second()
  {
    ++second_ran;
    static const char marker[] = "the second callback ran in the child\n";
    if (::getpid() != parent)
      (void)!::write(2, marker, sizeof(marker) - 1);
  }

  void check() const
  {
    CHECK(forked);
    CHECK(aborted_by_fork_rule(child, "run"));
    CHECK(child.message.find("the second callback ran in the child") == std::string::npos);
    CHECK(second_ran >= 1);
  }
};

struct fork_site_node_t
{
  vio::detail::posted_t posted;
  vio::detail::hook_t hook;
  fork_site_t *site = nullptr;
  bool forks = false;

  fork_site_node_t(fork_site_t &site, bool forks)
    : site(&site)
    , forks(forks)
  {
    posted.owner = this;
    posted.run = [](vio::detail::posted_t *raw) { static_cast<fork_site_node_t *>(raw->owner)->fire(); };
    hook.owner = this;
    hook.run = [](vio::detail::hook_t *raw) { static_cast<fork_site_node_t *>(raw->owner)->fire(); };
  }

  void fire()
  {
    if (forks)
      site->fork_here();
    else
      site->second();
  }
};

struct fork_site_op_t : vio::detail::io_op_t
{
  fork_site_node_t *node = nullptr;

  explicit fork_site_op_t(fork_site_node_t &node)
    : node(&node)
  {
    owner = this;
    complete = [](vio::detail::io_op_t *raw) { static_cast<fork_site_op_t *>(raw->owner)->node->fire(); };
  }
};

struct fork_site_file_t
{
  vio::detail::file_op_t op;
  fork_site_node_t *node = nullptr;
  char bytes[8] = {};

  fork_site_file_t(fork_site_node_t &node, int file)
    : node(&node)
  {
    op.owner = this;
    op.kind = vio::detail::file_op_kind::read;
    op.file = file;
    op.offset = 0;
    op.data = reinterpret_cast<std::byte *>(bytes);
    op.size = sizeof(bytes);
    op.complete = [](vio::detail::file_op_t *raw) { static_cast<fork_site_file_t *>(raw->owner)->node->fire(); };
  }
};
} // namespace

TEST_CASE("a child that returns from any loop callback it forked in aborts before the next callback runs")
{
  vio::event_loop_t loop;
  auto &core = vio::detail::core(loop);
  fork_site_t site;
  fork_site_node_t first(site, true);
  fork_site_node_t second(site, false);

  SUBCASE("posted work")
  {
    core.post(first.posted);
    core.post(second.posted);
    loop.stop();
    loop.run();
    site.leave_if_child();
    site.check();
  }
  SUBCASE("deferred work")
  {
    loop.run_in_loop([&] {
      core.defer(first.posted);
      core.defer(second.posted);
    });
    loop.stop();
    loop.run();
    site.leave_if_child();
    site.check();
  }
  SUBCASE("hooks")
  {
    vio::detail::timer_node_t linger;
    linger.fire = [](vio::detail::timer_node_t *) {};
    core.add_hook(first.hook);
    core.add_hook(second.hook);
    core.add_timer(linger, vio::detail::loop_core_t::deadline_after(std::int64_t{20} * 1000000));
    loop.stop();
    loop.run();
    site.leave_if_child();
    core.remove_hook(first.hook);
    core.remove_hook(second.hook);
    site.check();
  }
  SUBCASE("socket completions")
  {
    int ends[2];
    REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, ends) == 0);
    REQUIRE(vio::detail::socket_set_nonblocking(ends[0]) == 0);
    vio::detail::socket_resource_t socket(core);
    REQUIRE(socket.adopt(ends[0]) == 0);
    fork_site_op_t forking(first);
    fork_site_op_t following(second);
    socket.wait(vio::detail::interest_read, forking);
    socket.wait(vio::detail::interest_read, following);
    std::byte ping{0x42};
    REQUIRE(vio::detail::socket_send(ends[1], vio::detail::const_bytes_t(&ping, 1)) == 1);
    loop.stop();
    loop.run();
    site.leave_if_child();
    socket.close(nullptr, nullptr);
    loop.run();
    ::close(ends[1]);
    site.check();
  }
  SUBCASE("event pipe events")
  {
    vio::event_pipe_t<int> pipe(loop, [&](int &&value) {
      if (value == 1)
        first.fire();
      else
        second.fire();
    });
    pipe.post_event(1);
    pipe.post_event(2);
    loop.stop();
    loop.run();
    site.leave_if_child();
    site.check();
  }
  SUBCASE("ring file completions")
  {
    if (!core.backend().supports_async_files())
    {
      MESSAGE("the backend has no ring file operations; skipped");
      return;
    }
    int file = ::open("/dev/zero", O_RDONLY | O_CLOEXEC);
    REQUIRE(file >= 0);
    fork_site_file_t forking(first, file);
    fork_site_file_t following(second, file);
    loop.run_in_loop([&] {
      core.backend().submit_file(forking.op);
      core.backend().submit_file(following.op);
    });
    loop.stop();
    loop.run();
    site.leave_if_child();
    ::close(file);
    site.check();
  }
}

TEST_CASE("a child that returns from a loop callback it forked in aborts before the loop runs anything else")
{
  settle_file_pool();
  vio::event_loop_t loop;
  auto &core = vio::detail::core(loop);
  struct fork_point_t
  {
    vio::detail::timer_node_t forking;
    vio::detail::timer_node_t next;
    std::atomic<bool> gate{false};
    std::atomic<int> started{0};
    std::vector<std::unique_ptr<gated_job_t>> jobs;
    death_t child;
    pid_t parent = ::getpid();
    int next_fired = 0;
  } point;
  const int count = file_pool_threads() + 2;
  for (int i = 0; i < count; ++i)
  {
    point.jobs.push_back(std::make_unique<gated_job_t>(point.gate, point.started));
    vio::detail::pool_submit(core, point.jobs.back()->job, vio::detail::pool_queue::file);
  }
  wait_for_started(point.started, file_pool_threads());
  REQUIRE(point.started.load() == file_pool_threads());
  point.forking.owner = &point;
  point.forking.keeps_alive = false;
  point.forking.fire = [](vio::detail::timer_node_t *raw) {
    auto &self = *static_cast<fork_point_t *>(raw->owner);
    child_pipe_t pipe;
    if (::pipe(pipe.ends) != 0)
      return;
    pid_t child = ::fork();
    if (child == 0)
    {
      enter_child(pipe);
      return;
    }
    self.child = watch_child(child, pipe, 20s);
    self.gate = true;
  };
  point.next.owner = &point;
  point.next.keeps_alive = false;
  point.next.fire = [](vio::detail::timer_node_t *raw) {
    auto &self = *static_cast<fork_point_t *>(raw->owner);
    ++self.next_fired;
    static const char marker[] = "the next callback ran in the child\n";
    if (::getpid() != self.parent)
      (void)!::write(2, marker, sizeof(marker) - 1);
  };
  const auto deadline = vio::detail::loop_core_t::deadline_after(std::int64_t{20} * 1000000);
  core.add_timer(point.forking, deadline);
  core.add_timer(point.next, deadline);
  loop.stop();
  loop.run();
  if (::getpid() != point.parent)
    ::_exit(7);
  CHECK(aborted_by_fork_rule(point.child, "run"));
  CHECK(point.child.message.find("the next callback ran in the child") == std::string::npos);
  CHECK(point.next_fired == 1);
  for (auto &job : point.jobs)
  {
    CHECK(job->finished);
    CHECK_FALSE(job->canceled);
    CHECK(job->ran);
  }
  CHECK(core.in_flight() == 0);
}

TEST_CASE("a child that gives an inherited loop a socket or blocking work, or waits on one of its sockets, aborts naming the rule")
{
  vio::event_loop_t loop;
  auto &core = vio::detail::core(loop);
  int ends[2];
  REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, ends) == 0);
  REQUIRE(vio::detail::socket_set_nonblocking(ends[0]) == 0);
  REQUIRE(vio::detail::socket_set_nonblocking(ends[1]) == 0);
  vio::detail::socket_resource_t inherited(core);
  REQUIRE(inherited.adopt(ends[0]) == 0);

  SUBCASE("giving it a socket")
  {
    auto child = run_in_child([&] {
      int spare[2];
      if (::socketpair(AF_UNIX, SOCK_STREAM, 0, spare) != 0)
        ::_exit(3);
      vio::detail::socket_resource_t added(core);
      (void)added.adopt(spare[0]);
      ::_exit(5);
    });
    CHECK(aborted_by_fork_rule(child, "given a socket"));
  }
  SUBCASE("giving it blocking work")
  {
    auto child = run_in_child([&] {
      pool_probe_t probe;
      vio::detail::pool_submit(core, probe.job, vio::detail::pool_queue::file);
      ::_exit(5);
    });
    CHECK(aborted_by_fork_rule(child, "given blocking work"));
  }
  SUBCASE("waiting on one of its sockets")
  {
    auto child = run_in_child([&] {
      parked_probe_t reader;
      inherited.wait(vio::detail::interest_read, reader);
      ::_exit(5);
    });
    CHECK(aborted_by_fork_rule(child, "used to wait on a socket"));
  }
  SUBCASE("starting a ring file operation on it")
  {
    if (core.backend().supports_async_files())
    {
      auto child = run_in_child([&] {
        int file = ::open("/dev/zero", O_RDONLY | O_CLOEXEC);
        if (file < 0)
          ::_exit(3);
        vio::detail::file_op_t op;
        std::byte byte{};
        op.kind = vio::detail::file_op_kind::read;
        op.file = file;
        op.offset = 0;
        op.data = &byte;
        op.size = 1;
        op.complete = [](vio::detail::file_op_t *) {};
        core.backend().submit_file(op);
        ::_exit(5);
      });
      CHECK(aborted_by_fork_rule(child, "used to start an operation"));
    }
    else
    {
      MESSAGE("the backend has no ring file operations; skipped");
    }
  }
  inherited.close(nullptr, nullptr);
  ::close(ends[1]);
  loop.stop();
  loop.run();
  CHECK(core.open_resources() == 0);
}

TEST_CASE("a child that closes an inherited loop's socket leaves the parent's registration of it in place")
{
  vio::event_loop_t loop;
  auto &core = vio::detail::core(loop);
  int ends[2];
  REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, ends) == 0);
  REQUIRE(vio::detail::socket_set_nonblocking(ends[0]) == 0);
  REQUIRE(vio::detail::socket_set_nonblocking(ends[1]) == 0);
  vio::detail::socket_resource_t shared(core);
  REQUIRE(shared.adopt(ends[0]) == 0);

  struct reader_t : vio::detail::io_op_t
  {
    vio::detail::loop_core_t *core = nullptr;
    vio::detail::socket_resource_t *socket = nullptr;
    vio::detail::timer_node_t bail;
    std::int64_t got = 0;
  } reader;
  reader.core = &core;
  reader.socket = &shared;
  reader.owner = &reader;
  reader.complete = [](vio::detail::io_op_t *raw) {
    auto &self = *static_cast<reader_t *>(raw->owner);
    std::byte buffer[16];
    self.got = vio::detail::socket_recv(self.socket->native(), buffer);
    if (self.got == vio::errc::again)
    {
      self.socket->wait(vio::detail::interest_read, self);
      return;
    }
    self.core->remove_timer(self.bail);
    self.socket->close(nullptr, nullptr);
    self.core->stop();
  };
  reader.bail.owner = &reader;
  reader.bail.keeps_alive = false;
  reader.bail.fire = [](vio::detail::timer_node_t *raw) {
    auto &self = *static_cast<reader_t *>(raw->owner);
    self.socket->cancel(self);
    self.socket->close(nullptr, nullptr);
    self.core->stop();
  };
  shared.wait(vio::detail::interest_read, reader);

  auto child = run_in_child([&] {
    shared.close(nullptr, nullptr);
    ::_exit(0);
  });
  CHECK(exited_quietly(child));
  CHECK(child.message == "");

  std::byte ping{0x42};
  REQUIRE(vio::detail::socket_send(ends[1], vio::detail::const_bytes_t(&ping, 1)) == 1);
  core.add_timer(reader.bail, vio::detail::loop_core_t::deadline_after(std::int64_t{5000} * 1000000));
  loop.run();
  CHECK(reader.got == 1);
  CHECK_FALSE(reader.parked);
  ::close(ends[1]);
  CHECK(core.open_resources() == 0);
}

TEST_CASE("a socket of a loop inherited across fork() is not open in the child, so a handle dropped there neither sends nor reads")
{
  vio::event_loop_t loop;
  auto &core = vio::detail::core(loop);
  int ends[2];
  REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, ends) == 0);
  REQUIRE(vio::detail::socket_set_nonblocking(ends[0]) == 0);
  REQUIRE(vio::detail::socket_set_nonblocking(ends[1]) == 0);
  vio::detail::socket_resource_t shared(core);
  REQUIRE(shared.adopt(ends[0]) == 0);
  REQUIRE(shared.is_open());

  auto child = run_in_child([&] { ::_exit(shared.is_open() ? 1 : 0); });
  CHECK(exited_quietly(child));
  CHECK(shared.is_open());

  shared.close(nullptr, nullptr);
  ::close(ends[1]);
  loop.stop();
  loop.run();
  CHECK(core.open_resources() == 0);
}

namespace
{
struct forked_tcp_drop_t
{
  bool ready = false;
  std::size_t queued = 0;
  death_t child;
  int owed_bytes = -1;
  std::string client_read;
};

vio::task_t<void> drop_tcp_in_child(vio::event_loop_t &loop, forked_tcp_drop_t &result)
{
  auto listener = vio_test::get_ephemeral_port(loop);
  if (!listener)
  {
    loop.stop();
    co_return;
  }
  const int port = listener->second;
  std::optional<vio::tcp_t> peer;
  auto server_task = [](vio::tcp_server_t server, std::optional<vio::tcp_t> &out) -> vio::task_t<void> {
    auto listening = co_await vio::tcp_listen(server, 10);
    if (!listening)
      co_return;
    auto accepted = vio::tcp_accept(server);
    if (accepted)
      out.emplace(std::move(accepted.value()));
  }(std::move(listener->first), peer);
  std::optional<vio::tcp_t> client;
  client.emplace(std::move(vio::tcp_create(loop).value()));
  auto target = vio::ip4_addr("127.0.0.1", port);
  auto connected = co_await vio::tcp_connect(*client, reinterpret_cast<const sockaddr *>(&target.value()));
  co_await std::move(server_task);
  if (!connected || !peer)
  {
    loop.stop();
    co_return;
  }
  const std::string owed = "data-for-the-parent";
  auto pushed = co_await vio::write_tcp(*peer, reinterpret_cast<const std::uint8_t *>(owed.data()), owed.size());
  if (!pushed)
  {
    loop.stop();
    co_return;
  }
  std::this_thread::sleep_for(50ms);
  {
    auto dropped = vio::write_tcp(*client, std::vector<std::byte>(std::size_t{32} << 20));
  }
  result.queued = client->handle->write.count;
  result.ready = true;

  result.child = run_in_child([&] { client.reset(); });

  int pending = 0;
  if (::ioctl(client->handle->socket.native(), FIONREAD, &pending) == 0)
    result.owed_bytes = pending;
  if (result.owed_bytes > 0)
  {
    auto reader = vio::tcp_create_reader(*client);
    auto got = co_await reader.value();
    if (got)
      result.client_read.assign(got->chars(), got->size());
  }
  peer.reset();
  loop.stop();
}

struct forked_tls_drop_t
{
  bool ready = false;
  death_t child;
  int owed_bytes = -1;
  std::string server_read;
  std::string client_read;
};

vio::task_t<void> drop_tls_in_child(vio::event_loop_t &loop, vio::ssl_config_t server_config, vio::ssl_config_t client_config, forked_tls_drop_t &result)
{
  auto listener = vio_test::get_ephemeral_port(loop);
  if (!listener)
  {
    loop.stop();
    co_return;
  }
  const int port = listener->second;
  auto server = vio::ssl_server_create(loop, std::move(listener->first), "localhost", server_config);
  if (!server)
  {
    loop.stop();
    co_return;
  }
  std::optional<vio::ssl_server_client_t> accepted;
  auto server_task = [](vio::ssl_server_t &server, int port, std::optional<vio::ssl_server_client_t> &out) -> vio::task_t<void> {
    auto listening = co_await vio::ssl_server_listen(server, port);
    if (!listening)
      co_return;
    auto client = vio::ssl_server_accept(server);
    if (client)
      out.emplace(std::move(client.value()));
  }(*server, port, accepted);
  std::optional<vio::ssl_client_t> client;
  client.emplace(std::move(vio::ssl_client_create(loop, client_config).value()));
  auto connected = co_await vio::ssl_client_connect(*client, "localhost", port, "127.0.0.1");
  co_await std::move(server_task);
  if (!connected || !accepted)
  {
    loop.stop();
    co_return;
  }
  auto peer = std::move(*accepted);
  accepted.reset();
  auto server_reader = vio::ssl_server_client_create_reader(peer);
  const std::string hello = "hello";
  auto hello_written = co_await vio::ssl_client_write(*client, hello.data(), hello.size());
  auto hello_read = co_await server_reader.value();
  const std::string owed = "data-for-the-parent";
  auto owed_written = co_await vio::ssl_server_client_write(peer, owed.data(), owed.size());
  if (!hello_written || !hello_read || !owed_written)
  {
    loop.stop();
    co_return;
  }
  std::this_thread::sleep_for(50ms);
  result.ready = true;

  result.child = run_in_child([&] { client.reset(); });

  int pending = 0;
  if (::ioctl(client->state->socket_stream.socket->native(), FIONREAD, &pending) == 0)
    result.owed_bytes = pending;
  const std::string ping = "ping";
  auto pinged = co_await vio::ssl_client_write(*client, ping.data(), ping.size());
  auto got = co_await server_reader.value();
  if (pinged && got)
    result.server_read.assign(got->chars(), got->size());
  if (result.owed_bytes > 0)
  {
    auto client_reader = vio::ssl_client_create_reader(*client);
    auto from_server = co_await client_reader.value();
    if (from_server)
      result.client_read.assign(from_server->chars(), from_server->size());
  }
  loop.stop();
}
} // namespace

TEST_CASE("a TCP connection with writes queued, dropped in a child forked from its loop, leaves the parent's connection and its bytes alone")
{
  forked_tcp_drop_t result;
  {
    vio::event_loop_t loop;
    std::optional<vio::task_t<void>> task;
    loop.run_in_loop([&] { task.emplace(drop_tcp_in_child(loop, result)); });
    loop.run();
  }
  REQUIRE(result.ready);
  CHECK(result.queued > 0);
  CHECK(exited_quietly(result.child));
  CHECK(result.child.message == "");
  CHECK(result.owed_bytes == 19);
  CHECK(result.client_read == "data-for-the-parent");
}

TEST_CASE("a TLS client dropped in a child forked from its loop sends nothing on the parent's connection and reads nothing from it")
{
  auto certs = vio_test::make_cert_set("localhost");
  const vio::ssl_config_t server_config{.ca_mem = certs.ca_cert, .cert_mem = certs.cert, .key_mem = certs.key};
  const vio::ssl_config_t client_config{.ca_mem = certs.ca_cert};
  forked_tls_drop_t result;
  {
    vio::event_loop_t loop;
    std::optional<vio::task_t<void>> task;
    loop.run_in_loop([&] { task.emplace(drop_tls_in_child(loop, server_config, client_config, result)); });
    loop.run();
  }
  REQUIRE(result.ready);
  CHECK(exited_quietly(result.child));
  CHECK(result.child.message == "");
  CHECK(result.owed_bytes > 0);
  CHECK(result.server_read == "ping");
  CHECK(result.client_read == "data-for-the-parent");
}

TEST_CASE("a child that closes an inherited loop's handles and then destroys the loop exits quietly")
{
  SUBCASE("a socket closed in the child")
  {
    std::optional<vio::event_loop_t> loop;
    loop.emplace();
    auto &core = vio::detail::core(*loop);
    int ends[2];
    REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, ends) == 0);
    REQUIRE(vio::detail::socket_set_nonblocking(ends[0]) == 0);
    vio::detail::socket_resource_t shared(core);
    REQUIRE(shared.adopt(ends[0]) == 0);
    auto child = run_in_child([&] {
      shared.close(nullptr, nullptr);
      loop.reset();
    });
    CHECK(exited_quietly(child));
    CHECK(child.message == "");
    shared.close(nullptr, nullptr);
    ::close(ends[1]);
    loop->stop();
    loop->run();
    CHECK(core.open_resources() == 0);
    CHECK(core.in_flight() == 0);
  }
  SUBCASE("timer and TCP handles dropped in the child")
  {
    std::optional<vio::event_loop_t> loop;
    loop.emplace();
    auto &core = vio::detail::core(*loop);
    std::optional<vio::timer_t> timer;
    timer.emplace(make_timer(*loop));
    REQUIRE(vio::timer_rearm(*timer, 60s).has_value());
    std::optional<vio::tcp_t> tcp;
    tcp.emplace(std::move(vio::tcp_create(*loop).value()));
    auto child = run_in_child([&] {
      timer.reset();
      tcp.reset();
      loop.reset();
    });
    CHECK(exited_quietly(child));
    CHECK(child.message == "");
    timer.reset();
    tcp.reset();
    loop->stop();
    loop->run();
    CHECK(core.open_resources() == 0);
    CHECK(core.in_flight() == 0);
  }
  SUBCASE("a close the parent started before the fork")
  {
    std::optional<vio::event_loop_t> loop;
    loop.emplace();
    auto &core = vio::detail::core(*loop);
    int ends[2];
    REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, ends) == 0);
    REQUIRE(vio::detail::socket_set_nonblocking(ends[0]) == 0);
    vio::detail::socket_resource_t shared(core);
    REQUIRE(shared.adopt(ends[0]) == 0);
    bool closed = false;
    shared.close([](void *raw) { *static_cast<bool *>(raw) = true; }, &closed);
    REQUIRE(core.open_resources() == 1);
    auto child = run_in_child([&] { loop.reset(); });
    CHECK(exited_quietly(child));
    CHECK(child.message == "");
    ::close(ends[1]);
    loop->stop();
    loop->run();
    CHECK(closed);
    CHECK(core.open_resources() == 0);
    CHECK(core.in_flight() == 0);
  }
}

namespace
{
struct mid_drain_fork_t
{
  std::optional<vio::event_loop_t> loop;
  std::atomic<int> phase{0};
  std::atomic<bool> gate{false};
  death_t child;
  vio::detail::posted_t holder;

  mid_drain_fork_t()
  {
    loop.emplace();
    holder.owner = this;
    holder.run = [](vio::detail::posted_t *node) {
      auto &self = *static_cast<mid_drain_fork_t *>(node->owner);
      self.phase = 1;
      while (self.phase.load() != 2)
        std::this_thread::sleep_for(1ms);
      self.gate = true;
    };
  }

  std::thread forker(std::function<void()> first = {})
  {
    return std::thread([this, first = std::move(first)] {
      while (phase.load() != 1)
        std::this_thread::sleep_for(1ms);
      child = run_in_child([this, &first] {
        if (first)
          first();
        loop.reset();
      });
      phase = 2;
    });
  }
};
} // namespace

TEST_CASE("a child that destroys a loop it inherited in the middle of a drain abandons the work the drain had not reached")
{
  SUBCASE("posted work")
  {
    mid_drain_fork_t fork;
    auto &core = vio::detail::core(*fork.loop);
    pool_probe_t probe;
    core.post(fork.holder);
    vio::detail::pool_submit(core, probe.job, vio::detail::pool_queue::file);
    const auto give_up = std::chrono::steady_clock::now() + 10s;
    while (probe.job.state.load(std::memory_order_acquire) != vio::detail::pool_job_finished && std::chrono::steady_clock::now() < give_up)
      std::this_thread::sleep_for(1ms);
    REQUIRE(probe.job.state.load(std::memory_order_acquire) == vio::detail::pool_job_finished);
    std::this_thread::sleep_for(20ms);
    REQUIRE(core.in_flight() == 1);
    auto forker = fork.forker();
    fork.loop->run();
    forker.join();
    CHECK(exited_quietly(fork.child));
    CHECK(fork.child.message == "");
    CHECK(probe.finished);
    CHECK_FALSE(probe.canceled);
    CHECK(core.in_flight() == 0);
  }
  SUBCASE("deferred work")
  {
    settle_file_pool();
    mid_drain_fork_t fork;
    auto &core = vio::detail::core(*fork.loop);
    pool_probe_t probe;
    std::atomic<int> started{0};
    std::vector<std::unique_ptr<gated_job_t>> blockers;
    const int count = file_pool_threads();
    for (int i = 0; i < count; ++i)
    {
      blockers.push_back(std::make_unique<gated_job_t>(fork.gate, started));
      vio::detail::pool_submit(core, blockers.back()->job, vio::detail::pool_queue::file);
    }
    wait_for_started(started, count);
    REQUIRE(started.load() == count);
    bool cancelled = false;
    fork.loop->run_in_loop([&] {
      core.defer(fork.holder);
      vio::detail::pool_submit(core, probe.job, vio::detail::pool_queue::file);
      cancelled = vio::detail::pool_cancel(probe.job);
    });
    auto forker = fork.forker();
    fork.loop->stop();
    fork.loop->run();
    forker.join();
    CHECK(cancelled);
    CHECK(exited_quietly(fork.child));
    CHECK(fork.child.message == "");
    CHECK(probe.finished);
    CHECK(probe.canceled);
    CHECK(core.in_flight() == 0);
  }
}

TEST_CASE("destroying an inherited loop in the child is not stalled by a lock another thread held at the fork")
{
  std::optional<vio::event_loop_t> loop;
  loop.emplace();
  auto &core = vio::detail::core(*loop);
  vio::detail::posted_t node;
  node.run = [](vio::detail::posted_t *) {};
  std::atomic<bool> done{false};
  std::thread poster([&] {
    while (!done.load(std::memory_order_relaxed))
      core.post(node);
  });
  std::thread piper([&] {
    while (!done.load(std::memory_order_relaxed))
      vio::event_pipe_t<int> pipe(*loop, [](int &&) {});
  });
  int quiet = 0;
  constexpr int forks = 40;
  for (int i = 0; i < forks; ++i)
  {
    auto child = run_in_child(
      [&] {
        loop.reset();
        ::_exit(0);
      },
      2s);
    if (!exited_quietly(child))
      break;
    ++quiet;
  }
  done = true;
  poster.join();
  piper.join();
  CHECK(quiet == forks);
  loop->stop();
  loop->run();
}

TEST_CASE("an event pipe a child drops while the parent's drain held its node is not touched again when the child destroys the loop")
{
  mid_drain_fork_t fork;
  auto &core = vio::detail::core(*fork.loop);
  int delivered = 0;
  auto pipe = std::make_unique<vio::event_pipe_t<int>>(*fork.loop, [&delivered](int &&value) { delivered += value; });
  core.post(fork.holder);
  pipe->post_event(1);
  auto forker = fork.forker([&pipe] { pipe.reset(); });
  fork.loop->stop();
  fork.loop->run();
  forker.join();
  CHECK(exited_quietly(fork.child));
  CHECK(fork.child.message == "");
  CHECK(delivered == 1);
  pipe.reset();
  CHECK(core.in_flight() == 0);
}

TEST_CASE("a child that drops an event pipe and then destroys the loop is not stalled by a lock another thread held at the fork")
{
  std::optional<vio::event_loop_t> loop;
  loop.emplace();
  auto &core = vio::detail::core(*loop);
  std::optional<vio::event_pipe_t<int>> pipe;
  pipe.emplace(*loop, [](int &&) {});
  auto drop_then_destroy = [&] {
    pipe.reset();
    loop.reset();
    ::_exit(0);
  };

  SUBCASE("the pipe anchor's lock")
  {
    auto anchor = core.pipe_anchor();
    std::atomic<int> phase{0};
    std::thread holder([&] {
      std::lock_guard lock(anchor->mutex);
      phase = 1;
      while (phase.load() != 2)
        std::this_thread::sleep_for(1ms);
    });
    while (phase.load() != 1)
      std::this_thread::sleep_for(1ms);
    auto child = run_in_child(drop_then_destroy, 2s);
    phase = 2;
    holder.join();
    CHECK(exited_quietly(child));
    CHECK(child.message == "");
  }
  SUBCASE("the post lock")
  {
    std::vector<vio::detail::posted_t> nodes(3);
    for (auto &node : nodes)
      node.run = [](vio::detail::posted_t *) {};
    std::atomic<bool> done{false};
    std::thread runner([&] { loop->run(); });
    std::vector<std::thread> posters;
    for (auto &node : nodes)
      posters.emplace_back([&done, &core, &node] {
        while (!done.load(std::memory_order_relaxed))
          core.post(node);
      });
    int quiet = 0;
    constexpr int forks = 60;
    for (int i = 0; i < forks; ++i)
    {
      auto child = run_in_child(drop_then_destroy, 2s);
      if (!exited_quietly(child))
        break;
      ++quiet;
    }
    done = true;
    for (auto &poster : posters)
      poster.join();
    loop->stop();
    runner.join();
    CHECK(quiet == forks);
  }
  pipe.reset();
  loop->stop();
  loop->run();
  CHECK(core.in_flight() == 0);
}

namespace
{
struct lingering_fork_t
{
  std::optional<vio::event_loop_t> loop;
  std::optional<vio::tcp_server_t> listener;
  std::optional<vio::tcp_t> peer;
  std::optional<vio::tcp_t> client;
  std::size_t queued = 0;
  std::size_t peer_got = 0;
  bool lingering = false;
  bool ready = false;
  death_t child;
};

vio::task_t<void> fork_while_lingering(lingering_fork_t &s)
{
  auto &loop = *s.loop;
  auto listener = vio_test::get_ephemeral_port(loop);
  if (!listener)
  {
    loop.stop();
    co_return;
  }
  const int port = listener->second;
  s.listener.emplace(std::move(listener->first));
  auto server_task = [](vio::tcp_server_t &server, std::optional<vio::tcp_t> &out) -> vio::task_t<void> {
    auto listening = co_await vio::tcp_listen(server, 10);
    if (!listening)
      co_return;
    auto accepted = vio::tcp_accept(server);
    if (accepted)
      out.emplace(std::move(accepted.value()));
  }(*s.listener, s.peer);
  s.client.emplace(std::move(vio::tcp_create(loop).value()));
  auto target = vio::ip4_addr("127.0.0.1", port);
  auto connected = co_await vio::tcp_connect(*s.client, reinterpret_cast<const sockaddr *>(&target.value()));
  co_await std::move(server_task);
  if (!connected || !s.peer)
  {
    s.client.reset();
    s.peer.reset();
    s.listener.reset();
    loop.stop();
    co_return;
  }
  {
    auto dropped = vio::write_tcp(*s.client, std::vector<std::byte>(std::size_t{32} << 20));
  }
  s.queued = s.client->handle->write.count;
  auto *state = &s.client->handle.data();
  s.client.reset();
  s.lingering = state->lingering;
  s.ready = true;

  s.child = run_in_child([&s] {
    s.peer.reset();
    s.listener.reset();
    s.loop.reset();
  });

  {
    auto reader = vio::tcp_create_reader(*s.peer);
    if (reader)
    {
      for (;;)
      {
        auto got = co_await reader.value();
        if (!got)
          break;
        s.peer_got += got->size();
      }
    }
  }
  s.peer.reset();
  s.listener.reset();
  loop.stop();
}

struct sleeping_fork_t
{
  std::optional<vio::event_loop_t> loop;
  death_t child;
  bool woke = false;
};
} // namespace

TEST_CASE("a child destroys an inherited loop quietly while a TCP connection the parent dropped still lingers on it, and the parent still delivers every byte")
{
  lingering_fork_t s;
  s.loop.emplace();
  {
    std::optional<vio::task_t<void>> task;
    s.loop->run_in_loop([&] { task.emplace(fork_while_lingering(s)); });
    s.loop->run();
  }
  REQUIRE(s.ready);
  CHECK(s.queued > 0);
  CHECK(s.lingering);
  CHECK(exited_quietly(s.child));
  CHECK(s.child.message == "");
  CHECK(s.peer_got == (std::size_t{32} << 20));
  CHECK(vio::detail::core(*s.loop).in_flight() == 0);
}

TEST_CASE("a child destroys an inherited loop quietly while a parent coroutine sleeps on it, and the sleep still ends in the parent")
{
  sleeping_fork_t s;
  s.loop.emplace();
  std::optional<vio::task_t<void>> sleeper;
  std::optional<vio::task_t<void>> forker;
  s.loop->run_in_loop([&] {
    sleeper.emplace([](vio::event_loop_t &loop, bool &woke) -> vio::task_t<void> {
      auto slept = co_await vio::sleep(loop, 300ms);
      woke = slept.has_value();
    }(*s.loop, s.woke));
    forker.emplace([](sleeping_fork_t &s) -> vio::task_t<void> {
      auto slept = co_await vio::sleep(*s.loop, 20ms);
      if (slept)
        s.child = run_in_child([&s] { s.loop.reset(); });
      s.loop->stop();
    }(s));
  });
  s.loop->run();
  CHECK(exited_quietly(s.child));
  CHECK(s.child.message == "");
  CHECK(s.woke);
  CHECK(vio::detail::core(*s.loop).in_flight() == 0);
}

TEST_CASE("destroying an inherited io_uring loop in the child leaves the parent's ring file operations alone")
{
  std::optional<vio::event_loop_t> loop;
  loop.emplace();
  auto &core = vio::detail::core(*loop);
  if (!core.backend().supports_async_files())
  {
    MESSAGE("the backend has no ring file operations; skipped");
    return;
  }
  int ends[2];
  REQUIRE(::pipe(ends) == 0);
  struct read_t
  {
    vio::detail::file_op_t op;
    vio::detail::timer_node_t forking;
    vio::detail::timer_node_t bail;
    std::optional<vio::event_loop_t> *loop = nullptr;
    vio::detail::loop_core_t *core = nullptr;
    int writer = -1;
    char bytes[8] = {};
    std::int64_t result = 0;
    bool completed = false;
    death_t child;
  } read;
  read.loop = &loop;
  read.core = &core;
  read.writer = ends[1];
  read.op.owner = &read;
  read.op.kind = vio::detail::file_op_kind::read;
  read.op.file = ends[0];
  read.op.offset = -1;
  read.op.data = reinterpret_cast<std::byte *>(read.bytes);
  read.op.size = sizeof(read.bytes);
  read.op.complete = [](vio::detail::file_op_t *raw) {
    auto &self = *static_cast<read_t *>(raw->owner);
    self.completed = true;
    self.result = raw->result;
    self.core->remove_timer(self.bail);
    self.core->stop();
  };
  read.forking.owner = &read;
  read.forking.keeps_alive = false;
  read.forking.fire = [](vio::detail::timer_node_t *raw) {
    auto &self = *static_cast<read_t *>(raw->owner);
    child_pipe_t pipe;
    if (::pipe(pipe.ends) != 0)
      return;
    pid_t child = ::fork();
    if (child == 0)
    {
      enter_child(pipe);
      self.loop->reset();
      ::_exit(self.op.in_flight ? 1 : 0);
    }
    self.child = watch_child(child, pipe, 20s);
    (void)!::write(self.writer, "ring", 4);
  };
  read.bail.owner = &read;
  read.bail.keeps_alive = false;
  read.bail.fire = [](vio::detail::timer_node_t *raw) {
    auto &self = *static_cast<read_t *>(raw->owner);
    self.core->backend().cancel_file(self.op);
  };
  loop->run_in_loop([&] {
    core.backend().submit_file(read.op);
    core.add_timer(read.forking, vio::detail::loop_core_t::deadline_after(std::int64_t{50} * 1000000));
    core.add_timer(read.bail, vio::detail::loop_core_t::deadline_after(std::int64_t{10000} * 1000000));
  });
  loop->run();
  ::close(ends[0]);
  ::close(ends[1]);
  CHECK(exited_quietly(read.child));
  CHECK(read.child.message == "");
  CHECK(read.completed);
  CHECK(read.result == 4);
  CHECK(std::string(read.bytes, 4) == "ring");
  CHECK(core.in_flight() == 0);
}

TEST_CASE("destroying an operation the loop or the kernel still holds aborts with a message")
{
  SUBCASE("a parked socket operation")
  {
    auto death = run_in_child([] {
      int ends[2];
      if (::socketpair(AF_UNIX, SOCK_STREAM, 0, ends) != 0)
        ::_exit(3);
      vio::event_loop_t loop;
      vio::detail::socket_resource_t resource(vio::detail::core(loop));
      if (resource.adopt(ends[0]) != 0)
        ::_exit(3);
      auto op = std::make_unique<parked_probe_t>();
      resource.wait(vio::detail::interest_read, *op);
      op.reset();
    });
    CHECK(aborted_with_message(death));
  }
  SUBCASE("a queued blocking pool job")
  {
    auto death = run_in_child([] {
      vio::event_loop_t loop;
      auto probe = std::make_unique<pool_probe_t>();
      probe->job.work = [](vio::detail::pool_job_t *) { std::this_thread::sleep_for(200ms); };
      vio::detail::pool_submit(vio::detail::core(loop), probe->job, vio::detail::pool_queue::file);
      probe.reset();
    });
    CHECK(aborted_with_message(death));
  }
  SUBCASE("a file operation in flight")
  {
    auto death = run_in_child([] {
      auto op = std::make_unique<vio::detail::file_op_t>();
      op->in_flight = true;
      op.reset();
    });
    CHECK(aborted_with_message(death));
  }
}

TEST_CASE("a child destroys an inherited thread_with_event_loop_t without stopping or joining the parent's loop thread")
{
  auto owner = std::make_unique<vio::thread_with_event_loop_t>();
  auto &loop = owner->event_loop();

  SUBCASE("while other threads post to it")
  {
    if (!allocator_survives_fork_while_others_allocate)
      return;
    std::atomic<bool> done{false};
    std::vector<std::thread> posters;
    for (int i = 0; i < 3; ++i)
      posters.emplace_back([&done, &loop] {
        while (!done.load(std::memory_order_relaxed))
          loop.run_in_loop([] {});
      });
    int quiet = 0;
    constexpr int forks = 60;
    for (int i = 0; i < forks; ++i)
    {
      auto child = run_in_child(
        [&] {
          owner.reset();
          ::_exit(0);
        },
        60s);
      if (!exited_quietly(child))
      {
        MESSAGE("child " << i << ": " << describe(child));
        break;
      }
      ++quiet;
    }
    done = true;
    for (auto &poster : posters)
      poster.join();
    CHECK(quiet == forks);
  }
  SUBCASE("after the child started a loop thread of its own")
  {
    auto child = run_in_child(
      [&] {
        auto own = std::make_unique<vio::thread_with_event_loop_t>();
        owner.reset();
        own.reset();
        ::_exit(0);
      },
      2s);
    CHECK(exited_quietly(child));
  }
  owner.reset();
}


TEST_CASE("a child that stops an inherited loop and runs it is refused by the fork rule even when another thread held the post lock at the fork")
{
  std::optional<vio::event_loop_t> loop;
  loop.emplace();
  auto &core = vio::detail::core(*loop);
  std::vector<vio::detail::posted_t> nodes(3);
  for (auto &node : nodes)
    node.run = [](vio::detail::posted_t *) {};
  std::atomic<bool> done{false};
  std::thread runner([&] { loop->run(); });
  std::vector<std::thread> posters;
  for (auto &node : nodes)
    posters.emplace_back([&done, &core, &node] {
      while (!done.load(std::memory_order_relaxed))
        core.post(node);
    });
  int refused = 0;
  constexpr int forks = 60;
  for (int i = 0; i < forks; ++i)
  {
    auto child = run_in_child(
      [&] {
#if defined(__linux__)
        ::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
#endif
        loop->stop();
        loop->run();
        ::_exit(5);
      },
      2s);
    if (!aborted_by_fork_rule(child, "run"))
    {
      MESSAGE("child " << i << ": " << describe(child));
      break;
    }
    ++refused;
  }
  done = true;
  for (auto &poster : posters)
    poster.join();
  loop->stop();
  runner.join();
  CHECK(refused == forks);
  CHECK(core.in_flight() == 0);
}

#endif
