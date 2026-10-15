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
#include <vio/operation/timer.h>
#include <vio/ref_counted_wrapper.h>
#include <vio/task.h>

#if !defined(_WIN32)
#include <cerrno>
#include <csignal>
#include <poll.h>
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

template <typename F>
death_t run_in_child(F &&body)
{
  death_t result;
  int pipe_ends[2];
  if (::pipe(pipe_ends) != 0)
    return result;
  pid_t child = ::fork();
  if (child < 0)
    return result;
  if (child == 0)
  {
    std::signal(SIGABRT, SIG_DFL);
    ::dup2(pipe_ends[1], 2);
    ::close(pipe_ends[0]);
    body();
    ::_exit(0);
  }
  ::close(pipe_ends[1]);
  const auto give_up = std::chrono::steady_clock::now() + 20s;
  char buffer[512];
  for (;;)
  {
    const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(give_up - std::chrono::steady_clock::now());
    if (left.count() <= 0)
      break;
    pollfd readable{pipe_ends[0], POLLIN, 0};
    int ready = ::poll(&readable, 1, static_cast<int>(left.count()));
    if (ready < 0 && errno == EINTR)
      continue;
    if (ready <= 0)
      break;
    auto got = ::read(pipe_ends[0], buffer, sizeof(buffer));
    if (got > 0)
    {
      result.message.append(buffer, static_cast<std::size_t>(got));
      continue;
    }
    if (got < 0 && errno == EINTR)
      continue;
    break;
  }
  ::close(pipe_ends[0]);
  const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(give_up - std::chrono::steady_clock::now());
  result.status = wait_for_child(child, left.count() > 0 ? left : 0ms);
  return result;
}

bool aborted_with_message(const death_t &death)
{
  return death.status != -1 && WIFSIGNALED(death.status) && WTERMSIG(death.status) == SIGABRT &&
         death.message.find("destroyed while the loop or the kernel still held it") != std::string::npos;
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

TEST_CASE("pool work in flight at a fork finishes as cancelled in the child and runs once, in the parent")
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

  auto child = run_in_child([&] {
    const int started_at_fork = started.load();
    loop.stop();
    loop.run();
    for (auto &job : jobs)
    {
      if (!job->finished || !job->canceled || job->ran)
        ::_exit(1);
    }
    if (core.in_flight() != 0)
      ::_exit(2);
    if (!run_one_pool_job())
      ::_exit(3);
    ::_exit(started.load() == started_at_fork ? 0 : 4);
  });
  gate = true;
  loop.stop();
  loop.run();
  REQUIRE(child.status != -1);
  CHECK(WIFEXITED(child.status));
  CHECK(WEXITSTATUS(child.status) == 0);
  CHECK(started.load() == count);
  for (auto &job : jobs)
  {
    CHECK(job->finished);
    CHECK_FALSE(job->canceled);
    CHECK(job->ran);
  }
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
#endif
