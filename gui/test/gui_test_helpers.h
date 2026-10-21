#pragma once

#include <doctest/doctest.h>

#include <chrono>
#include <optional>

#include <vio/event_loop.h>
#include <vio/task.h>

template <typename Task>
void run_gui_test(vio::event_loop_t &loop, Task &&task, std::chrono::milliseconds limit = std::chrono::seconds(10))
{
  std::optional<vio::task_t<void>> holder;
  holder.emplace(std::forward<Task>(task));
  bool timed_out = false;
  vio::detail::timer_node_t guard;
  guard.owner = &timed_out;
  guard.keeps_alive = false;
  guard.fire = [](vio::detail::timer_node_t *node) { *static_cast<bool *>(node->owner) = true; };
  auto &core = vio::detail::core(loop);
  core.add_timer(guard, vio::detail::loop_core_t::deadline_after(std::chrono::nanoseconds(limit).count()));
  struct watchdog_t
  {
    vio::detail::hook_t hook;
    vio::event_loop_t *loop;
    bool *timed_out;
  } watchdog{{}, &loop, &timed_out};
  watchdog.hook.owner = &watchdog;
  watchdog.hook.run = [](vio::detail::hook_t *hook) {
    auto *self = static_cast<watchdog_t *>(hook->owner);
    if (*self->timed_out)
      self->loop->stop();
  };
  core.add_hook(watchdog.hook);
  loop.run();
  core.remove_hook(watchdog.hook);
  core.remove_timer(guard);
  REQUIRE_MESSAGE(!timed_out, "the test did not finish in time");
  CHECK(holder->done());
}
