#pragma once

#include <doctest/doctest.h>

#include <chrono>
#include <optional>

#include <vio/event_loop.h>
#include <vio/operation/timer.h>
#include <vio/task.h>

template <typename Task>
void run_gui_test(vio::event_loop_t &loop, Task &&task, std::chrono::milliseconds limit = std::chrono::seconds(10))
{
  std::optional<vio::task_t<void>> holder;
  holder.emplace(std::forward<Task>(task));
  bool timed_out = false;
  {
    auto guard = std::move(*vio::timer_create(loop));
    vio::timer_set_keeps_loop_alive(guard, false);
    vio::timer_on_fire(guard, [&] {
      timed_out = true;
      loop.stop();
    });
    REQUIRE(vio::timer_rearm(guard, limit));
    loop.run();
  }
  loop.stop();
  loop.run();
  REQUIRE_MESSAGE(!timed_out, "the test did not finish in time");
  CHECK(holder->done());
}
