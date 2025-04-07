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

#include <uv.h>
#include <coroutine>
#include <chrono>

#include "vio/ref_ptr.h"
#include "vio/event_loop.h"
#include "vio/uv_coro.h"

namespace vio
{

uv_coro_awaitable<uv_timer_t, void> sleep(event_loop_t &event_loop, std::chrono::milliseconds milliseconds)
{
  uv_coro_awaitable<uv_timer_t, void> ret;
  uv_timer_init(event_loop.loop(), &(ret.state->req));
  auto copy = ret.state;
  ret.state->req.data = copy.release_to_raw();
  auto callback = [](uv_timer_t *timer)
  {
    uv_timer_stop(timer);
    auto timer_state = ref_ptr_t<uv_coro_state<uv_timer_t,void>>::from_raw(timer->data);
    timer_state->done = true;
    auto to_callback = timer_state;
    timer->data = to_callback.release_to_raw();
    auto close_callback = [](uv_handle_t *handle) { auto timer_state = ref_ptr_t<uv_coro_state<uv_timer_t,void>>::from_raw(handle->data); };
    uv_close((uv_handle_t *)timer, close_callback);
    if (timer_state->continuation)
      timer_state->continuation.resume();
  };
  auto r = uv_timer_start(&ret.state->req, callback, milliseconds.count(), 0);
  if (r < 0)
  {
    // Mark as done right away and set the error.
    ret.state->done = true;
    ret.state->result = std::unexpected(error_t{r, uv_strerror(r)});
  }
  return ret;
}
} // namespace vio