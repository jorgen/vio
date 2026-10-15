#pragma once

#include "vio/cancellation.h"
#include "vio/error.h"
#include "vio/event_loop.h"
#include "vio/ref_counted_wrapper.h"
#include "vio/future.h"

#include <chrono>
#include <algorithm>
#include <coroutine>
#include <cstdint>
#include <expected>
#include <limits>

#include <emscripten.h>
#include <emscripten/eventloop.h> // emscripten_set_timeout

namespace vio
{

namespace detail
{
inline constexpr std::int64_t wasm_timeout_limit_ms = 2147483647;

template <typename Rep, typename Period>
[[nodiscard]] std::int64_t wasm_delay_ms(std::chrono::duration<Rep, Period> delay)
{
  if (delay <= delay.zero())
    return 0;
  const long double ms = std::chrono::duration<long double, std::milli>(delay).count();
  if (ms >= static_cast<long double>(std::numeric_limits<std::int64_t>::max()))
    return std::numeric_limits<std::int64_t>::max();
  auto whole = static_cast<std::int64_t>(ms);
  if (static_cast<long double>(whole) < ms)
    ++whole;
  return whole;
}
} // namespace detail

struct sleep_state_t
{
  int timer_id = 0;
  std::int64_t remaining_ms = 0;
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

namespace detail
{
inline void wasm_sleep_fire(void *user_data)
{
  auto timer_state = future_t<sleep_state_t>::future_ref_ptr_t::from_raw(user_data);
  if (timer_state->remaining_ms > 0)
  {
    const auto chunk = std::min(timer_state->remaining_ms, wasm_timeout_limit_ms);
    timer_state->remaining_ms -= chunk;
    auto *state = &timer_state.data();
    void *again = timer_state.release_to_raw();
    state->raw_ref = again;
    state->timer_id = emscripten_set_timeout(&wasm_sleep_fire, static_cast<double>(chunk), again);
    return;
  }
  timer_state->done = true;
  timer_state->raw_ref = nullptr;
  timer_state->cancel_registration.reset();
  if (timer_state->continuation)
  {
    timer_state->continuation.resume();
  }
}
} // namespace detail

template <typename Rep, typename Period>
future_t<sleep_state_t> sleep(event_loop_t &event_loop, std::chrono::duration<Rep, Period> delay, cancellation_t *cancel = nullptr)
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

  const auto total_ms = detail::wasm_delay_ms(delay);
  const auto first = std::min(total_ms, detail::wasm_timeout_limit_ms);
  ret.state_ptr->remaining_ms = total_ms - first;
  ret.state_ptr->timer_id = emscripten_set_timeout(&detail::wasm_sleep_fire, static_cast<double>(first), raw);

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
