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

// A rearmable timer.
//
// vio::sleep() allocates a uv_timer_t per call and uv_close()s it on both the
// fire and the cancel path, which suits awaiting a one-off delay. A protocol
// timer is the opposite shape: one handle, initialised once, rescheduled
// constantly -- QUIC loss detection rearms on every packet sent and every
// acknowledgement received. timer_t keeps a single uv_timer_t alive for the
// lifetime of the handle, so a rearm is a bare uv_timer_start and costs no
// allocation and no close.
//
// The handle is registered with the ref count, so teardown performs the single
// uv_close. The fire callback holds a reference for its duration, so an
// on_fire callback that drops the last user reference cannot free the state
// underneath itself.

#include "vio/error.h"
#include "vio/event_loop.h"
#include "vio/ref_counted_wrapper.h"

#include <chrono>
#include <expected>
#include <functional>
#include <utility>
#include <uv.h>

namespace vio
{
struct timer_state_t
{
  explicit timer_state_t(event_loop_t &loop)
    : event_loop(loop)
  {
  }

  event_loop_t &event_loop;
  uv_timer_t uv_handle = {};
  std::function<void()> on_fire;

  uv_timer_t *get_timer()
  {
    return &uv_handle;
  }

  uv_handle_t *get_handle()
  {
    return reinterpret_cast<uv_handle_t *>(&uv_handle);
  }
};

struct timer_t
{
  ref_ptr_t<timer_state_t> handle;

  uv_timer_t *get_timer()
  {
    return handle->get_timer();
  }

  uv_handle_t *get_handle()
  {
    return handle->get_handle();
  }
};

namespace detail
{
// data is a borrowed pointer, never an owning reference: the handle is
// registered with the ref count, so a reference parked here would keep the
// count above zero forever and the uv_close would never be issued.
//
// Borrowing is safe in both directions. libuv fires no callback for a handle
// after uv_close, and the ref count frees the storage only once every close
// callback has run -- so an on_fire callback that releases the last reference
// to its own timer does not destroy the std::function it is executing.
inline void timer_fire_cb(uv_timer_t *uv_handle)
{
  auto *state = static_cast<timer_state_t *>(uv_handle->data);
  if (state->on_fire)
  {
    state->on_fire();
  }
}
} // namespace detail

inline std::expected<timer_t, error_t> timer_create(event_loop_t &loop)
{
  timer_t timer{ref_ptr_t<timer_state_t>(loop)};
  if (auto r = uv_timer_init(loop.loop(), timer.get_timer()); r < 0)
  {
    return std::unexpected(error_t{.code = r, .msg = uv_strerror(r)});
  }
  timer.handle.register_handle(timer.get_timer());
  timer.get_timer()->data = &timer.handle.data();
  return timer;
}

inline void timer_on_fire(timer_t &timer, std::function<void()> callback)
{
  timer.handle->on_fire = std::move(callback);
}

// A deadline already in the past rearms for the next loop iteration rather
// than failing: loss recovery routinely computes a timeout that has already
// elapsed by the time it is scheduled.
inline std::expected<void, error_t> timer_rearm(timer_t &timer, std::chrono::milliseconds delay)
{
  const std::uint64_t timeout = delay.count() <= 0 ? 0u : static_cast<std::uint64_t>(delay.count());
  if (auto r = uv_timer_start(timer.get_timer(), detail::timer_fire_cb, timeout, 0); r < 0)
  {
    return std::unexpected(error_t{.code = r, .msg = uv_strerror(r)});
  }
  return {};
}

inline void timer_disarm(timer_t &timer)
{
  uv_timer_stop(timer.get_timer());
}

[[nodiscard]] inline bool timer_is_armed(timer_t &timer)
{
  return uv_is_active(timer.get_handle()) != 0;
}
} // namespace vio
