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

#include <chrono>
#include <expected>
#include <functional>
#include <utility>

#include "vio/error.h"
#include "vio/event_loop.h"
#include "vio/ref_counted_wrapper.h"

namespace vio
{
struct timer_state_t
{
  class resource_t final : public detail::resource_t
  {
  public:
    resource_t(detail::loop_core_t &loop, detail::timer_node_t &node) noexcept
      : detail::resource_t(loop, "timer")
      , _node(node)
    {
    }

  private:
    void do_close() noexcept override
    {
      loop().remove_timer(_node);
      close_finished();
    }

    detail::timer_node_t &_node;
  };

  explicit timer_state_t(event_loop_t &loop)
    : event_loop(loop)
    , resource(detail::core(loop), node)
  {
    node.owner = this;
    node.fire = [](detail::timer_node_t *fired) {
      auto *state = static_cast<timer_state_t *>(fired->owner);
      if (state->on_fire)
        state->on_fire();
    };
  }

  event_loop_t &event_loop;
  detail::timer_node_t node;
  resource_t resource;
  std::function<void()> on_fire;
};

struct timer_t
{
  ref_ptr_t<timer_state_t> handle;
};

inline std::expected<timer_t, error_t> timer_create(event_loop_t &loop)
{
  timer_t timer{ref_ptr_t<timer_state_t>(loop)};
  timer.handle.register_resource(timer.handle->resource);
  return timer;
}

inline void timer_on_fire(timer_t &timer, std::function<void()> callback)
{
  timer.handle->on_fire = std::move(callback);
}

inline void timer_set_keeps_loop_alive(timer_t &timer, bool keeps_alive)
{
  auto &state = timer.handle.data();
  if (state.node.keeps_alive == keeps_alive)
    return;
  bool armed = state.node.armed();
  auto deadline = state.node.deadline;
  auto &core = detail::core(state.event_loop);
  core.remove_timer(state.node);
  state.node.keeps_alive = keeps_alive;
  if (armed)
    core.add_timer(state.node, deadline);
}

inline std::expected<void, error_t> timer_rearm(timer_t &timer, std::chrono::nanoseconds delay)
{
  auto &state = timer.handle.data();
  auto offset = delay.count() <= 0 ? std::int64_t{0} : static_cast<std::int64_t>(delay.count());
  detail::core(state.event_loop).add_timer(state.node, detail::loop_core_t::now() + offset);
  return {};
}

inline void timer_disarm(timer_t &timer)
{
  auto &state = timer.handle.data();
  detail::core(state.event_loop).remove_timer(state.node);
}

[[nodiscard]] inline bool timer_is_armed(timer_t &timer)
{
  return timer.handle->node.armed();
}
} // namespace vio
