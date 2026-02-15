#include <print>
#include <string>

#include <vio/awaitable_event_pipe.h>
#include <vio/operation/sleep.h>

int main()
{
  vio::event_loop_t event_loop;
  vio::thread_with_event_loop_t worker; // NOLINT(misc-const-correctness)
  auto &worker_loop = worker.event_loop();

  // Sync handler: runs directly on the worker thread
  vio::awaitable_event_pipe_t<int, int, int> multiply(event_loop, worker_loop,
                                                      [](int a, int b) -> int
                                                      {
                                                        std::println("  [worker] computing {} * {} ...", a, b);
                                                        return a * b;
                                                      });

  // Async handler: can co_await on the worker thread before returning
  vio::awaitable_event_pipe_t<std::string, std::string> slow_upper(event_loop, worker_loop,
                                                                   [&worker_loop](std::string s) -> vio::task_t<std::string>
                                                                   {
                                                                     auto *el = &worker_loop;
                                                                     std::println("  [worker] uppercasing \"{}\" (with simulated delay) ...", s);
                                                                     (void)co_await vio::sleep(*el, std::chrono::milliseconds(100));
                                                                     for (auto &c : s)
                                                                       c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
                                                                     co_return s;
                                                                   });

  // Same-loop pipe: caller and handler on the same event loop
  vio::awaitable_event_pipe_t<int, int> increment(event_loop, event_loop, [](int x) -> int { return x + 1; });

  event_loop.run_in_loop(
    [&event_loop, &multiply, &slow_upper, &increment]() -> vio::task_t<void>
    {
      auto *ev = &event_loop;
      auto *mul = &multiply;
      auto *upper = &slow_upper;
      auto *inc = &increment;

      std::println("--- Cross-thread sync handler ---");
      auto product = co_await mul->call(6, 7);
      std::println("  result: {}", product);

      std::println("\n--- Cross-thread async handler ---");
      auto upper_result = co_await upper->call(std::string("hello vio"));
      std::println("  result: {}", upper_result);

      std::println("\n--- Same-loop handler ---");
      auto inc_result = co_await inc->call(41);
      std::println("  result: {}", inc_result);

      std::println("\n--- Multiple sequential calls ---");
      int sum = 0;
      for (int i = 1; i <= 5; i++)
      {
        sum += co_await mul->call(i, i);
        std::println("  running sum: {}", sum);
      }
      std::println("  sum of squares 1..5: {}", sum);

      std::println("\nDone!");
      ev->stop();
    });
  event_loop.run();

  return 0;
}
