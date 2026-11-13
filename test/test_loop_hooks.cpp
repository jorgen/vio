/*
  Copyright (c) 2026 Jørgen Lind

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

#include <chrono>
#include <optional>

#include <vio/event_loop.h>
#include <vio/host_loop.h>
#include <vio/loop_hooks.h>

using namespace std::chrono_literals;

TEST_CASE("loop_hooks: a hook runs before the loop blocks, and keeps running while a stop drains")
{
  vio::event_loop_t loop;
  int runs = 0;
  int runs_after_stop = 0;
  vio::before_block_hook_t hook(loop, [&] {
    ++runs;
    if (vio::detail::core(loop).stopping())
      ++runs_after_stop;
  });
  hook.start();
  CHECK(hook.started());
  std::optional<vio::deferred_call_t> keep_going;
  int turns = 0;
  keep_going.emplace(loop, [&] {
    ++turns;
    if (turns == 3)
      loop.stop();
    if (turns < 5)
      keep_going->schedule();
  });
  keep_going->schedule();
  loop.run();
  hook.stop();
  CHECK_FALSE(hook.started());
  CHECK(runs >= 3);
  CHECK(runs_after_stop >= 1);
}

TEST_CASE("loop_hooks: a hook that stops itself is not run again")
{
  vio::event_loop_t loop;
  int runs = 0;
  std::optional<vio::before_block_hook_t> hook;
  hook.emplace(loop, [&] {
    ++runs;
    hook->stop();
  });
  hook->start();
  vio::deferred_call_t again(loop, [&] { loop.stop(); });
  loop.run_in_loop([&] { loop.run_in_loop([&] { again.schedule(); }); });
  loop.run();
  CHECK(runs == 1);
}

TEST_CASE("loop_hooks: a nested turn started by a hook runs the other hooks but not that one")
{
  vio::event_loop_t loop;
  int outer = 0;
  int inner = 0;
  bool nesting = false;
  vio::before_block_hook_t nester(loop, [&] {
    ++outer;
    if (outer != 1)
      return;
    nesting = true;
    vio::loop_run_nested(loop);
    nesting = false;
    loop.stop();
  });
  int inner_during_nesting = 0;
  vio::before_block_hook_t counter(loop, [&] {
    ++inner;
    if (nesting)
      ++inner_during_nesting;
  });
  nester.start();
  counter.start();
  loop.run();
  CHECK(outer >= 1);
  CHECK(inner_during_nesting == 1);
}

TEST_CASE("loop_hooks: a deferred call scheduled twice runs once")
{
  vio::event_loop_t loop;
  int runs = 0;
  vio::deferred_call_t call(loop, [&] { ++runs; });
  loop.run_in_loop([&] {
    call.schedule();
    call.schedule();
    CHECK(call.scheduled());
    loop.stop();
  });
  loop.run();
  CHECK(runs == 1);
  CHECK_FALSE(call.scheduled());
}

TEST_CASE("loop_hooks: a cancelled deferred call does not run, and neither does one destroyed while scheduled")
{
  vio::event_loop_t loop;
  int cancelled_runs = 0;
  int destroyed_runs = 0;
  vio::deferred_call_t cancelled(loop, [&] { ++cancelled_runs; });
  std::optional<vio::deferred_call_t> destroyed;
  destroyed.emplace(loop, [&] { ++destroyed_runs; });
  loop.run_in_loop([&] {
    cancelled.schedule();
    destroyed->schedule();
    cancelled.cancel();
    destroyed.reset();
    CHECK_FALSE(cancelled.scheduled());
    loop.stop();
  });
  loop.run();
  CHECK(cancelled_runs == 0);
  CHECK(destroyed_runs == 0);
}

TEST_CASE("loop_hooks: a deferred call cancelled by an earlier one in the same drain does not run")
{
  vio::event_loop_t loop;
  int second_runs = 0;
  std::optional<vio::deferred_call_t> second;
  second.emplace(loop, [&] { ++second_runs; });
  vio::deferred_call_t first(loop, [&] { second->cancel(); });
  loop.run_in_loop([&] {
    first.schedule();
    second->schedule();
    loop.stop();
  });
  loop.run();
  CHECK(second_runs == 0);
}

TEST_CASE("loop_hooks: a deferred call rescheduling itself never lets the loop block")
{
  vio::event_loop_t loop;
  int runs = 0;
  std::optional<vio::deferred_call_t> call;
  call.emplace(loop, [&] {
    if (++runs < 100)
      call->schedule();
    else
      loop.stop();
  });
  const auto started = std::chrono::steady_clock::now();
  call->schedule();
  loop.run();
  CHECK(runs == 100);
  CHECK(std::chrono::steady_clock::now() - started < 2s);
}
