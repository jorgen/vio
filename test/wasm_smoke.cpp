#include <chrono>
#include <cstdio>
#include <string>
#include <vector>

#include <vio/cancellation.h>
#include <vio/errc.h>
#include <vio/error.h>
#include <vio/event_loop.h>
#include <vio/event_pipe.h>
#include <vio/objstore/create_object_store.h>
#include <vio/operation/http_client.h>
#include <vio/operation/sleep.h>
#include <vio/run.h>
#include <vio/task.h>
#include <vio/thread_pool.h>

#include <emscripten.h>

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

vio::task_t<void> scenario(vio::event_loop_t &loop, std::vector<int> &order, std::vector<std::string> &events)
{
  auto slow = sleep_after(loop, 20, order);
  auto fast = sleep_after(loop, 1, order);
  co_await std::move(slow);
  co_await std::move(fast);

  vio::cancellation_t token;
  token.cancel();
  auto cancelled = co_await vio::sleep(loop, std::chrono::milliseconds(50), &token);
  expect(!cancelled.has_value() && vio::is_cancelled(cancelled.error()), "a cancelled sleep reports cancellation");

  vio::event_pipe_t<std::string> pipe(loop, [&events](std::string &&event) { events.push_back(std::move(event)); });
  pipe.post_event("first");
  pipe.post_event("second");
  for (int i = 0; i < 200 && events.size() < 2; ++i)
    co_await vio::sleep(loop, std::chrono::milliseconds(5));

  expect(order == std::vector<int>{1, 20}, "sleeps finish in deadline order");
  expect(events == std::vector<std::string>{"first", "second"}, "an event pipe delivers in order");
  expect(std::string(vio::error_message(vio::errc::eof)) == "end of file", "error codes have messages");
  expect(vio::make_error(vio::errc::canceled).code == vio::errc::canceled, "make_error keeps the code");

  loop.stop();
  std::printf("%s\n", failures == 0 ? "wasm smoke: passed" : "wasm smoke: FAILED");
  emscripten_force_exit(failures == 0 ? 0 : 1);
}
} // namespace

int main()
{
  static vio::event_loop_t loop;
  static std::vector<int> order;
  static std::vector<std::string> events;
  loop.run_in_loop([] { return scenario(loop, order, events); });
  loop.run();
  return 0;
}
