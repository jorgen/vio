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

#pragma once

#include "event_loop.h"
#include "task.h"

#include <type_traits>

#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#include <emscripten/eventloop.h>
#endif

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

#ifdef __EMSCRIPTEN__
namespace detail
{
// What vio::run keeps on the heap on the web: main() returns before the loop has run at all.
template <typename F>
struct wasm_run_t
{
  event_loop_t loop;
  std::decay_t<F> function;
  int exit_code = 0;

  static void finished(void *self)
  {
    // The loop's turn is still on the stack, so the loop is freed from the next one.
    emscripten_set_immediate(&wasm_run_t::exit, self);
  }

  static void exit(void *self)
  {
    auto *state = static_cast<wasm_run_t *>(self);
    const int code = state->exit_code;
    delete state;
    emscripten_runtime_keepalive_pop();
    emscripten_force_exit(code);
  }
};
} // namespace detail

// On the web nothing may block (D69), so run() starts the loop and returns at once, keeping the
// runtime alive. When the task has finished and the loop with it, the program exits with the
// task's result when that is an int, else 0. Use it as `return vio::run(...)` in main(), as on
// native: the value returned there is not the task's result.
template <typename F>
inline auto run(F &&f)
{
  using result_t = task_result_t<std::invoke_result_t<F, event_loop_t &>>;
  using state_t = detail::wasm_run_t<F>;
  auto *state = new state_t{.function = std::forward<F>(f)};
  emscripten_runtime_keepalive_push();
  detail::core(state->loop).set_on_finished(&state_t::finished, state);
  state->loop.run_in_loop(
    [state]() -> task_t<void>
    {
      auto *s = state;
      if constexpr (std::is_void_v<result_t>)
      {
        co_await s->function(s->loop);
      }
      else
      {
        auto result = co_await s->function(s->loop);
        if constexpr (std::is_convertible_v<result_t, int>)
          s->exit_code = static_cast<int>(result);
      }
      s->loop.stop();
    });
  state->loop.run();
  if constexpr (!std::is_void_v<result_t>)
    return result_t{};
}
#else
template <typename F>
inline auto run(F &&f)
{
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
#endif

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
