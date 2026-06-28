#pragma once

#include "event_loop.h"
#include "task.h"

#include <type_traits>

namespace vio
{

template <typename T>
struct task_result;

template <typename T>
struct task_result<task_t<T>>
{
  using type = T;
};

template <typename T>
using task_result_t = typename task_result<T>::type;

template <typename F>
inline auto run(F &&f)
{
#ifdef __EMSCRIPTEN__
  static_assert(!sizeof(F *), "vio::run() is not available on WASM. Use event_loop_t::run() directly with run_in_loop().");
#endif
  using result_t = task_result_t<std::invoke_result_t<F, event_loop_t &>>;

  if constexpr (std::is_void_v<result_t>)
  {
    event_loop_t event_loop;
    event_loop.run_in_loop(
      [&event_loop, &f]() -> task_t<void>
      {
        auto *ev = &event_loop;
        co_await std::forward<F>(f)(*ev);
        ev->stop();
      });
    event_loop.run();
  }
  else
  {
    event_loop_t event_loop;
    result_t result{};
    event_loop.run_in_loop(
      [&event_loop, &f, &result]() -> task_t<void>
      {
        auto *ev = &event_loop;
        auto *r = &result;
        *r = co_await std::forward<F>(f)(*ev);
        ev->stop();
      });
    event_loop.run();
    return result;
  }
}

} // namespace vio

// Generates main() for a vio program: the body that follows the macro is a
// task_t<int> coroutine with `loop`, `argc`, and `argv` in scope, run on a fresh
// event loop.
//
//   VIO_MAIN(loop, argc, argv)
//   {
//     co_await something(loop);
//     co_return 0;
//   }
#define VIO_MAIN(loop, argc, argv)                                                       \
  static vio::task_t<int> vio_main_impl(vio::event_loop_t &loop, int argc, char **argv); \
  int main(int argc, char **argv)                                                        \
  {                                                                                      \
    return vio::run([argc, argv](vio::event_loop_t &loop) -> vio::task_t<int>            \
                    { return vio_main_impl(loop, argc, argv); });                        \
  }                                                                                      \
  vio::task_t<int> vio_main_impl(vio::event_loop_t &loop, [[maybe_unused]] int argc, [[maybe_unused]] char **argv)
