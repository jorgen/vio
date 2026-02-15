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

#include "vio/cancellation.h"
#include "vio/error.h"
#include "vio/event_loop.h"
#include "vio/ref_counted_wrapper.h"
#include "vio/uv_coro.h"

#include <chrono>
#include <coroutine>
#include <expected>
#include <uv.h>

namespace vio
{

struct sleep_state_t
{
  uv_timer_t timer = {};
  std::expected<void, error_t> result = {};
  std::coroutine_handle<> continuation = {};
  registration_t cancel_registration;
  bool done = false;

  [[nodiscard]] bool await_ready() const noexcept
  {
    return done;
  }

  bool await_suspend(std::coroutine_handle<> continuation) noexcept
  {
    if (done)
    {
      return false;
    }
    this->continuation = continuation;
    return true;
  }

  auto await_resume() noexcept
  {
    return std::move(result);
  }
};

inline future_t<sleep_state_t> sleep(event_loop_t &event_loop, std::chrono::milliseconds milliseconds, cancellation_t *cancel = nullptr)
{
  using ret_t = future_t<sleep_state_t>;
  using future_ref_ptr_t = ret_t::future_ref_ptr_t;
  ret_t ret;

  if (cancel && cancel->is_cancelled())
  {
    ret.state_ptr->done = true;
    ret.state_ptr->result = std::unexpected(error_t{.code = vio_cancelled, .msg = "cancelled"});
    return ret;
  }

  uv_timer_init(event_loop.loop(), &ret.state_ptr->timer);
  auto copy = ret.state_ptr;
  ret.state_ptr->timer.data = copy.release_to_raw();
  auto callback = [](uv_timer_t *timer)
  {
    uv_timer_stop(timer);
    auto timer_state = future_ref_ptr_t::from_raw(timer->data);
    timer_state->done = true;
    timer_state->cancel_registration.reset();
    auto to_callback = timer_state;
    timer->data = to_callback.release_to_raw();
    auto close_callback = [](uv_handle_t *handle) { auto timer_state = future_ref_ptr_t::from_raw(handle->data); };
    uv_close((uv_handle_t *)timer, close_callback);
    if (timer_state->continuation)
    {
      timer_state->continuation.resume();
    }
  };
  auto r = uv_timer_start(&ret.state_ptr->timer, callback, milliseconds.count(), 0);
  if (r < 0)
  {
    ret.state_ptr->done = true;
    ret.state_ptr->result = std::unexpected(error_t{.code = r, .msg = uv_strerror(r)});
    return ret;
  }

  if (cancel)
  {
    auto *state_raw = &ret.state_ptr.data();
    ret.state_ptr->cancel_registration = cancel->register_callback([state_raw]()
    {
      if (state_raw->done)
        return;
      uv_timer_stop(&state_raw->timer);
      state_raw->done = true;
      state_raw->result = std::unexpected(error_t{.code = vio_cancelled, .msg = "cancelled"});
      state_raw->cancel_registration.reset();
      auto state_ref = future_ref_ptr_t::from_raw(state_raw->timer.data);
      auto to_close = state_ref;
      state_raw->timer.data = to_close.release_to_raw();
      auto close_callback = [](uv_handle_t *handle) { auto timer_state = future_ref_ptr_t::from_raw(handle->data); };
      uv_close((uv_handle_t *)&state_raw->timer, close_callback);
      if (state_raw->continuation)
      {
        state_raw->continuation.resume();
      }
    });
  }

  return ret;
}
} // namespace vio