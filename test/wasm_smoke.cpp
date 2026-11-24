#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <string>
#include <vector>

#include <emscripten.h>
#include <emscripten/eventloop.h>

#include "vio/cancellation.h"
#include "vio/errc.h"
#include "vio/event_loop.h"
#include "vio/event_pipe.h"
#include "vio/host_loop.h"
#include "vio/loop_hooks.h"
#include "vio/operation/fd_watch.h"
#include "vio/operation/sleep.h"
#include "vio/operation/timer.h"

// The shared loop core on the browser backend (D69), run under Node. Node has the same
// setTimeout and setImmediate a page does, and the backend needs nothing else.

namespace
{
int failures = 0;

void expect(bool condition, const char *what)
{
  if (!condition)
  {
    ++failures;
    std::printf("FAILED: %s\n", what);
  }
}

vio::task_t<void> sleep_after(vio::event_loop_t &loop, int ms, std::vector<int> &order)
{
  auto slept = co_await vio::sleep(loop, std::chrono::milliseconds(ms));
  expect(slept.has_value(), "a sleep that is not cancelled succeeds");
  order.push_back(ms);
}

vio::task_t<void> cancel_after(vio::event_loop_t &loop, vio::cancellation_t &token, int ms)
{
  co_await vio::sleep(loop, std::chrono::milliseconds(ms));
  token.cancel();
}

vio::task_t<void> sleeps(vio::event_loop_t &loop)
{
  std::vector<int> order;
  auto slow = sleep_after(loop, 20, order);
  auto fast = sleep_after(loop, 1, order);
  co_await std::move(slow);
  co_await std::move(fast);
  expect(order == std::vector<int>{1, 20}, "sleeps finish in deadline order");

  vio::cancellation_t token;
  token.cancel();
  auto cancelled = co_await vio::sleep(loop, std::chrono::milliseconds(50), &token);
  expect(!cancelled.has_value() && vio::is_cancelled(cancelled.error()), "a cancelled sleep reports cancellation");

  auto sub_ms = co_await vio::sleep(loop, std::chrono::microseconds(500));
  expect(sub_ms.has_value(), "a sleep shorter than a millisecond completes");

  // Longer than a browser timeout can be: the backend arms the longest it may and asks again.
  vio::cancellation_t forever;
  const auto start = std::chrono::steady_clock::now();
  auto canceller = cancel_after(loop, forever, 30);
  auto longest = co_await vio::sleep(loop, std::chrono::milliseconds::max(), &forever);
  co_await std::move(canceller);
  expect(!longest.has_value() && vio::is_cancelled(longest.error()), "the longest sleep waits until it is cancelled");
  expect(std::chrono::steady_clock::now() - start >= std::chrono::milliseconds(25), "the longest sleep does not end early");
}

vio::task_t<void> timers(vio::event_loop_t &loop)
{
  auto timer = vio::timer_create(loop);
  expect(timer.has_value(), "a timer can be created");
  if (!timer)
    co_return;
  int fired = 0;
  vio::timer_on_fire(*timer, [&fired] { ++fired; });
  expect(vio::timer_rearm(*timer, std::chrono::milliseconds(5)).has_value(), "a timer can be armed");
  expect(vio::timer_is_armed(*timer), "an armed timer says so");
  co_await vio::sleep(loop, std::chrono::milliseconds(30));
  expect(fired == 1, "an armed timer fires once");
  expect(!vio::timer_is_armed(*timer), "a timer that fired is no longer armed");

  (void)vio::timer_rearm(*timer, std::chrono::milliseconds(10));
  vio::timer_disarm(*timer);
  co_await vio::sleep(loop, std::chrono::milliseconds(30));
  expect(fired == 1, "a disarmed timer does not fire");

  // A timer pushed later is waited for at its new deadline, not its first one.
  (void)vio::timer_rearm(*timer, std::chrono::milliseconds(5));
  (void)vio::timer_rearm(*timer, std::chrono::milliseconds(40));
  co_await vio::sleep(loop, std::chrono::milliseconds(20));
  expect(fired == 1, "a rearmed timer does not fire at its old deadline");
  co_await vio::sleep(loop, std::chrono::milliseconds(40));
  expect(fired == 2, "a rearmed timer fires at its new deadline");
}

vio::task_t<void> hooks(vio::event_loop_t &loop)
{
  std::vector<std::string> seen;
  vio::before_block_hook_t hook(loop, [&seen] {
    if (seen.empty() || seen.back() != "hook")
      seen.push_back("hook");
  });
  vio::deferred_call_t deferred(loop, [&seen] { seen.push_back("deferred"); });
  hook.start();
  loop.run_in_loop([&seen, &deferred] {
    seen.push_back("posted");
    deferred.schedule();
  });
  co_await vio::sleep(loop, std::chrono::milliseconds(5));
  hook.stop();
  // The hook may already have run in the turn that started it; what matters is the order within
  // the turn that ran the post.
  auto posted = std::find(seen.begin(), seen.end(), "posted");
  expect(posted != seen.end(), "work posted from inside the loop runs");
  expect(posted != seen.end() && posted + 1 != seen.end() && *(posted + 1) == "deferred", "deferred work runs in the turn that scheduled it");
  expect(posted != seen.end() && posted + 2 < seen.end() && *(posted + 2) == "hook", "a before-block hook runs after the turn's work");

  vio::deferred_call_t cancelled(loop, [&seen] { seen.push_back("cancelled"); });
  cancelled.schedule();
  cancelled.cancel();
  co_await vio::sleep(loop, std::chrono::milliseconds(5));
  expect(std::find(seen.begin(), seen.end(), "cancelled") == seen.end(), "a cancelled deferred call does not run");
}

struct outside_t
{
  vio::event_loop_t *loop;
  bool ran_inside = false;
  bool ran_before_return = false;
};

// A browser callback (a key press, a frame) arrives outside any turn. It records what happened and
// runs a turn on the spot, which is what vui's web backend does.
void from_outside(void *context)
{
  auto *outside = static_cast<outside_t *>(context);
  outside->loop->run_in_loop([outside] { outside->ran_inside = true; });
  vio::loop_run_nested(*outside->loop);
  outside->ran_before_return = outside->ran_inside;
}

vio::task_t<void> host(vio::event_loop_t &loop)
{
  expect(std::string(loop.backend_name()) == "browser", "the loop runs on the browser backend");

  struct never_t : vio::host_wait_t
  {
    void wait(std::optional<std::chrono::nanoseconds>) override
    {
    }
  } never;
  auto refused = vio::loop_set_host_wait(loop, &never);
  expect(!refused.has_value() && refused.error().code == vio::errc::not_supported, "a host wait is refused: nothing may block");

  auto watch = vio::fd_watch_create(loop, 0);
  expect(!watch.has_value() && watch.error().code == vio::errc::not_supported, "a descriptor watch is refused");

  outside_t outside{&loop};
  emscripten_set_timeout(&from_outside, 1, &outside);
  co_await vio::sleep(loop, std::chrono::milliseconds(20));
  expect(outside.ran_before_return, "a nested turn from a browser callback runs posted work before the callback returns");
}

vio::task_t<void> pipes(vio::event_loop_t &loop)
{
  std::vector<std::string> events;
  vio::event_pipe_t<std::string> pipe(loop, [&events](std::string &&event) { events.push_back(std::move(event)); });
  pipe.post_event("first");
  pipe.post_event("second");
  for (int i = 0; i < 200 && events.size() < 2; ++i)
    co_await vio::sleep(loop, std::chrono::milliseconds(5));
  expect(events == std::vector<std::string>{"first", "second"}, "an event pipe delivers in order");
}

bool scenario_done = false;

vio::task_t<void> scenario(vio::event_loop_t &loop)
{
  co_await sleeps(loop);
  co_await timers(loop);
  co_await hooks(loop);
  co_await host(loop);
  co_await pipes(loop);
  expect(std::string(vio::error_message(vio::errc::eof)) == "end of file", "error codes have messages");
  expect(vio::make_error(vio::errc::canceled).code == vio::errc::canceled, "make_error keeps the code");
  scenario_done = true;
  loop.stop();
}

void finished(void *)
{
  expect(scenario_done, "the loop finishes after stop(), once its work is done");
  std::printf("%s\n", failures == 0 ? "wasm smoke: passed" : "wasm smoke: FAILED");
  emscripten_force_exit(failures == 0 ? 0 : 1);
}
} // namespace

int main()
{
  static vio::event_loop_t loop;
  vio::detail::core(loop).set_on_finished(&finished, nullptr);
  loop.run_in_loop([] { return scenario(loop); });
  // run() returns at once on the web; the turns come from the browser's callbacks.
  loop.run();
  emscripten_runtime_keepalive_push();
  return 0;
}
