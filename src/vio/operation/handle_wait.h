/*
  Copyright (c) 2026 Jørgen Lind

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

#if !defined(_WIN32)
#error "vio/operation/handle_wait.h waits on Windows kernel objects"
#endif

#include <coroutine>
#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <utility>

#include "vio/cancellation.h"
#include "vio/detail/native.h"
#include "vio/error.h"
#include "vio/event_loop.h"
#include "vio/future.h"
#include "vio/loop/backend.h"
#include "vio/ref_counted_wrapper.h"

namespace vio
{
struct handle_wait_state_t
{
  class resource_t final : public detail::resource_t
  {
  public:
    resource_t(detail::loop_core_t &loop, handle_wait_state_t &state) noexcept
      : detail::resource_t(loop, "handle wait")
    {
      op.owner = &state;
      op.complete = &handle_wait_state_t::on_signalled;
      _removed.owner = this;
      _removed.run = &resource_t::on_removed;
    }

    [[nodiscard]] int open(HANDLE object) noexcept
    {
      watch.object = object;
      if (int result = loop().backend().add_handle_watch(watch); result < 0)
        return result;
      _registered = true;
      return 0;
    }

    [[nodiscard]] int arm()
    {
      if (!_registered || closing())
        return errc::bad_descriptor;
      return loop().backend().wait_handle(watch, op);
    }

    void cancel() noexcept
    {
      loop().backend().cancel_handle_wait(watch, op);
    }

    detail::handle_watch_t watch;
    detail::io_op_t op;

  private:
    void do_close() noexcept override
    {
      cancel();
      if (_registered)
      {
        _registered = false;
        loop().backend().remove_handle_watch(watch, _removed);
      }
      else
      {
        loop().defer(_removed);
      }
    }

    static void on_removed(detail::posted_t *node)
    {
      static_cast<resource_t *>(node->owner)->close_finished();
    }

    detail::posted_t _removed;
    bool _registered = false;
  };

  explicit handle_wait_state_t(event_loop_t &loop)
    : event_loop(loop)
    , resource(detail::core(loop), *this)
  {
  }

  void notify()
  {
    if (!on_signalled_callback)
      return;
    auto callback = std::move(on_signalled_callback);
    on_signalled_callback = nullptr;
    struct restore_t
    {
      handle_wait_state_t &state;
      std::function<void()> &callback;
      std::uint32_t generation;
      ~restore_t()
      {
        if (state.callback_generation == generation)
          state.on_signalled_callback = std::move(callback);
      }
    } restore{*this, callback, callback_generation};
    callback();
  }

  static void on_signalled(detail::io_op_t *op)
  {
    static_cast<handle_wait_state_t *>(op->owner)->notify();
  }

  event_loop_t &event_loop;
  resource_t resource;
  std::function<void()> on_signalled_callback;
  std::uint32_t callback_generation = 0;
};

struct handle_wait_t
{
  ref_ptr_t<handle_wait_state_t> handle;
};

inline std::expected<handle_wait_t, error_t> handle_wait_create(event_loop_t &loop, HANDLE object)
{
  handle_wait_t wait{ref_ptr_t<handle_wait_state_t>(loop)};
  wait.handle.register_resource(wait.handle->resource);
  if (int result = wait.handle->resource.open(object); result < 0)
    return std::unexpected(make_error(result));
  return wait;
}

inline void handle_wait_on_signalled(handle_wait_t &wait, std::function<void()> callback)
{
  auto &state = wait.handle.data();
  state.on_signalled_callback = std::move(callback);
  ++state.callback_generation;
}

inline std::expected<void, error_t> handle_wait_arm(handle_wait_t &wait)
{
  if (int result = wait.handle->resource.arm(); result < 0)
    return std::unexpected(make_error(result));
  return {};
}

inline void handle_wait_disarm(handle_wait_t &wait)
{
  wait.handle->resource.cancel();
}

[[nodiscard]] inline bool handle_wait_is_armed(handle_wait_t &wait)
{
  return wait.handle->resource.op.parked;
}

inline std::expected<void, error_t> handle_wait_set_keeps_loop_alive(handle_wait_t &wait, bool keeps_alive)
{
  auto &resource = wait.handle->resource;
  if (resource.op.keeps_alive == keeps_alive)
    return {};
  const bool armed = resource.op.parked;
  resource.cancel();
  resource.op.keeps_alive = keeps_alive;
  if (armed)
    return handle_wait_arm(wait);
  return {};
}

struct handle_signal_state_t
{
  std::optional<handle_wait_t> wait;
  std::expected<void, error_t> result = {};
  std::coroutine_handle<> continuation = {};
  registration_t cancel_registration;
  bool done = false;

  void resolve(std::expected<void, error_t> outcome)
  {
    if (done)
      return;
    done = true;
    result = std::move(outcome);
    cancel_registration.reset();
    if (wait)
      handle_wait_disarm(*wait);
    if (continuation)
      std::exchange(continuation, nullptr).resume();
  }

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

inline future_t<handle_signal_state_t> wait_for_handle(event_loop_t &loop, HANDLE object, cancellation_t *cancel = nullptr)
{
  future_t<handle_signal_state_t> ret;
  auto &state = ret.state_ptr.data();
  if (cancel && cancel->is_cancelled())
  {
    state.resolve(std::unexpected(error_t{.code = vio_cancelled, .msg = "cancelled"}));
    return ret;
  }
  auto created = handle_wait_create(loop, object);
  if (!created)
  {
    state.resolve(std::unexpected(created.error()));
    return ret;
  }
  state.wait.emplace(std::move(*created));
  auto *raw = &state;
  handle_wait_on_signalled(*state.wait, [raw] { raw->resolve({}); });
  if (auto armed = handle_wait_arm(*state.wait); !armed)
  {
    state.resolve(std::unexpected(armed.error()));
    return ret;
  }
  if (cancel)
    state.cancel_registration = cancel->register_callback([raw] { raw->resolve(std::unexpected(error_t{.code = vio_cancelled, .msg = "cancelled"})); });
  return ret;
}
} // namespace vio
