#include <chrono>
#include <print>

#include <vio/operation/sleep.h>
#include <vio/run.h>

// The minimal vio program: VIO_MAIN generates main() and gives you a
// task_t<int> coroutine body with `loop`, `argc`, `argv` in scope.
VIO_MAIN(loop, argc, argv)
{
  for (int i = 3; i > 0; --i)
  {
    std::println("{}...", i);
    co_await vio::sleep(loop, std::chrono::seconds{1});
  }
  std::println("liftoff");
  co_return 0;
}
