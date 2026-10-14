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
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include <vio/event_loop.h>
#include <vio/event_pipe.h>
#include <vio/loop/blocking_pool.h>
#include <vio/operation/sleep.h>
#include <vio/operation/timer.h>
#include <vio/task.h>

using namespace std::chrono_literals;

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

TEST_CASE("a timer rearmed for now from its own callback fires on a later turn")
{
  vio::event_loop_t loop;
  auto &core = vio::detail::core(loop);
  struct state_t
  {
    vio::detail::timer_node_t node;
    vio::detail::loop_core_t *core;
    int fired = 0;
  } state;
  state.core = &core;
  state.node.owner = &state;
  state.node.fire = [](vio::detail::timer_node_t *node) {
    auto *self = static_cast<state_t *>(node->owner);
    if (++self->fired < 3)
      self->core->add_timer(self->node, vio::detail::loop_core_t::now() - 1);
  };
  core.add_timer(state.node, vio::detail::loop_core_t::now());
  loop.stop();
  loop.run();
  CHECK(state.fired == 3);
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
