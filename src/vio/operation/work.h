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

#include "vio/error.h"
#include "vio/event_loop.h"
#include "vio/thread_pool.h"
#include "vio/uv_coro.h"

#include <atomic>
#include <cstdint>
#include <coroutine>
#include <expected>
#include <functional>
#include <vector>

#include <uv.h>

namespace vio
{

enum class on_failure_t : std::uint8_t
{
  continue_all,
  cancel_remaining
};

template <typename T, typename E = error_t>
struct work_batch_state_t
{
  std::vector<std::expected<T, E>> results;
  std::atomic<size_t> remaining{0};
  std::atomic<bool> cancelled{false};
  std::coroutine_handle<> continuation = {};
  bool done = false;
  event_loop_t *event_loop = nullptr;

  void cancel()
  {
    cancelled.store(true, std::memory_order_release);
  }

  [[nodiscard]] bool await_ready() const noexcept
  {
    return done;
  }

  bool await_suspend(std::coroutine_handle<> cont) noexcept
  {
    if (done)
    {
      return false;
    }
    this->continuation = cont;
    return true;
  }

  std::vector<std::expected<T, E>> await_resume() noexcept
  {
    return std::move(results);
  }
};

template <typename T, typename E = error_t>
future_t<work_batch_state_t<T, E>> schedule_work(event_loop_t &event_loop, thread_pool_t &pool, std::vector<std::function<std::expected<T, E>()>> work_items,
                                                  on_failure_t on_failure = on_failure_t::continue_all)
{
  using state_t = work_batch_state_t<T, E>;
  using ret_t = future_t<state_t>;
  using future_ref_ptr_t = typename ret_t::future_ref_ptr_t;

  ret_t ret;
  ret.state_ptr->event_loop = &event_loop;

  size_t count = work_items.size();
  if (count == 0)
  {
    ret.state_ptr->done = true;
    return ret;
  }

  ret.state_ptr->results.resize(count);
  ret.state_ptr->remaining.store(count, std::memory_order_relaxed);

  auto shared_state = ret.state_ptr;

  for (size_t i = 0; i < count; ++i)
  {
    auto state_copy = shared_state;
    pool.enqueue([i, on_failure, state_copy, work_fn = std::move(work_items[i])]() mutable
    {
      if (state_copy->cancelled.load(std::memory_order_acquire))
      {
        state_copy->results[i] = std::unexpected(E(error_t{.code = UV_ECANCELED, .msg = uv_strerror(UV_ECANCELED)}));
      }
      else
      {
        state_copy->results[i] = work_fn();
        if (on_failure == on_failure_t::cancel_remaining && !state_copy->results[i].has_value())
        {
          state_copy->cancelled.store(true, std::memory_order_release);
        }
      }

      if (state_copy->remaining.fetch_sub(1, std::memory_order_acq_rel) == 1)
      {
        auto *el = state_copy->event_loop;
        auto completion_state = std::move(state_copy);
        el->run_in_loop([completion_state = std::move(completion_state)]() mutable
        {
          completion_state->done = true;
          if (completion_state->continuation)
          {
            completion_state->continuation.resume();
          }
        });
      }
    });
  }

  return ret;
}

} // namespace vio
