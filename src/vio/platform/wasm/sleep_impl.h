#pragma once

#include "vio/cancellation.h"
#include "vio/error.h"
#include "vio/event_loop.h"
#include "vio/ref_counted_wrapper.h"
#include "vio/uv_coro.h"

#include <chrono>
#include <coroutine>
#include <expected>

#include <emscripten.h>
#include <emscripten/eventloop.h> // emscripten_set_timeout

namespace vio
{

struct sleep_state_t
{
  int timer_id = 0;
  void *raw_ref = nullptr;
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

  auto copy = ret.state_ptr;
  void *raw = copy.release_to_raw();
  ret.state_ptr->raw_ref = raw;

  auto timer_callback = [](void *user_data)
  {
    auto timer_state = future_ref_ptr_t::from_raw(user_data);
    timer_state->done = true;
    timer_state->raw_ref = nullptr;
    timer_state->cancel_registration.reset();
    if (timer_state->continuation)
    {
      timer_state->continuation.resume();
    }
  };

  ret.state_ptr->timer_id = emscripten_set_timeout(timer_callback, static_cast<double>(milliseconds.count()), raw);

  if (cancel)
  {
    auto *state_raw = &ret.state_ptr.data();
    ret.state_ptr->cancel_registration = cancel->register_callback([state_raw, &event_loop]()
    {
      if (state_raw->done)
        return;
      event_loop.cancel_timer(state_raw->timer_id);
      state_raw->done = true;
      state_raw->result = std::unexpected(error_t{.code = vio_cancelled, .msg = "cancelled"});
      state_raw->cancel_registration.reset();
      if (state_raw->raw_ref)
      {
        auto state_ref = future_ref_ptr_t::from_raw(state_raw->raw_ref);
        state_raw->raw_ref = nullptr;
      }
      if (state_raw->continuation)
      {
        state_raw->continuation.resume();
      }
    });
  }

  return ret;
}
} // namespace vio
