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
