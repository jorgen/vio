#include <chrono>
#include <cstdio>

#include "vio/event_loop.h"
#include "vio/operation/sleep.h"
#include "vio/run.h"

// vio::run on the web (D69): main() returns before the loop has run, and the program exits with
// the task's result once the loop has finished. CI checks that the exit code is 7. Also the
// cooperative layer: a thread_with_event_loop_t runs on its own, and vio::wasm::pump() settles it.

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
} // namespace

int main()
{
  int captured = 7;
  // The callable is a temporary in main()'s frame, which is gone before it runs: vio::run must
  // keep its own copy, captures and all.
  return vio::run([captured](vio::event_loop_t &loop) -> vio::task_t<int> {
    const int result = captured;
    auto slept = co_await vio::sleep(loop, std::chrono::milliseconds(5));
    expect(slept.has_value(), "a sleep inside vio::run completes");

    vio::thread_with_event_loop_t worker;
    bool ran = false;
    worker.event_loop().run_in_loop([&ran] { ran = true; });
    vio::wasm::pump();
    expect(ran, "pump() runs a registered loop's posted work at once");

    bool ran_alone = false;
    worker.event_loop().run_in_loop([&ran_alone] { ran_alone = true; });
    co_await vio::sleep(loop, std::chrono::milliseconds(5));
    expect(ran_alone, "a registered loop also runs its own turns");
    worker.stop_and_join();

    std::printf("%s\n", failures == 0 ? "wasm run: passed" : "wasm run: FAILED");
    co_return failures == 0 ? result : 1;
  });
}
