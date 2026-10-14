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

#include <algorithm>
#include <chrono>
#include <coroutine>
#include <expected>

#include "vio/cancellation.h"
#include "vio/error.h"
#include "vio/event_loop.h"
#include "vio/future.h"
#include "vio/ref_counted_wrapper.h"

namespace vio
{
struct sleep_state_t
{
  detail::timer_node_t node;
  detail::loop_core_t *loop = nullptr;
  std::expected<void, error_t> result = {};
  std::coroutine_handle<> continuation = {};
  registration_t cancel_registration;
  bool done = false;

  [[nodiscard]] bool await_ready() const noexcept
  {
    return done;
  }

  bool await_suspend(std::coroutine_handle<> handle) noexcept
  {
    if (done)
      return false;
    continuation = handle;
    return true;
  }

  auto await_resume() noexcept
  {
    return std::move(result);
  }
};

inline future_t<sleep_state_t> sleep(event_loop_t &event_loop, std::chrono::nanoseconds duration, cancellation_t *cancel = nullptr)
{
  using ret_t = future_t<sleep_state_t>;
  using future_ref_ptr_t = ret_t::future_ref_ptr_t;
  ret_t ret;
  auto &state = ret.state_ptr.data();

  if (cancel && cancel->is_cancelled())
  {
    state.done = true;
    state.result = std::unexpected(error_t{.code = vio_cancelled, .msg = "cancelled"});
    return ret;
  }

  state.loop = &detail::core(event_loop);
  auto parked = ret.state_ptr;
  state.node.owner = parked.release_to_raw();
  state.node.fire = [](detail::timer_node_t *node) {
    auto owned = future_ref_ptr_t::from_raw(node->owner);
    owned->done = true;
    owned->cancel_registration.reset();
    if (owned->continuation)
      owned->continuation.resume();
  };
  auto delay = std::max<std::int64_t>(0, duration.count());
  state.loop->add_timer(state.node, detail::loop_core_t::now() + delay);

  if (cancel)
  {
    auto *raw = &state;
    state.cancel_registration = cancel->register_callback([raw]() {
      if (raw->done)
        return;
      raw->loop->remove_timer(raw->node);
      auto owned = future_ref_ptr_t::from_raw(raw->node.owner);
      raw->done = true;
      raw->result = std::unexpected(error_t{.code = vio_cancelled, .msg = "cancelled"});
      raw->cancel_registration.reset();
      if (raw->continuation)
        raw->continuation.resume();
    });
  }

  return ret;
}
} // namespace vio
