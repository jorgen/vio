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

#ifdef __EMSCRIPTEN__
#error "vio/operation/fd_watch.h needs the native event loop"
#endif

#include <cstdint>
#include <expected>
#include <functional>
#include <utility>

#include "vio/detail/native.h"
#include "vio/error.h"
#include "vio/event_loop.h"
#include "vio/loop/backend.h"
#include "vio/ref_counted_wrapper.h"

namespace vio
{
enum class fd_interest : std::uint8_t
{
  read = detail::interest_read,
  write = detail::interest_write
};

struct fd_watch_state_t
{
  class resource_t final : public detail::resource_t
  {
  public:
    resource_t(detail::loop_core_t &loop, fd_watch_state_t &state) noexcept
      : detail::resource_t(loop, "fd watch")
    {
      reader.owner = &state;
      reader.complete = &fd_watch_state_t::on_readable;
      writer.owner = &state;
      writer.complete = &fd_watch_state_t::on_writable;
      _removed.owner = this;
      _removed.run = &resource_t::on_removed;
    }

    [[nodiscard]] int open(native_socket_t fd) noexcept
    {
      watch.socket = fd;
      if (int result = loop().backend().open_watch(watch); result < 0)
        return result;
      _registered = true;
      return 0;
    }

    void arm(detail::io_op_t &op, std::uint8_t interest)
    {
      if (_registered && !closing() && !op.parked)
        loop().backend().wait(watch, interest, op);
    }

    void cancel(detail::io_op_t &op) noexcept
    {
      loop().backend().cancel_wait(watch, op);
    }

    detail::io_watch_t watch;
    detail::io_op_t reader;
    detail::io_op_t writer;

  private:
    void do_close() noexcept override
    {
      cancel(reader);
      cancel(writer);
      if (_registered)
      {
        _registered = false;
        loop().backend().close_watch(watch, _removed);
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

  explicit fd_watch_state_t(event_loop_t &loop)
    : event_loop(loop)
    , resource(detail::core(loop), *this)
  {
  }

  [[nodiscard]] detail::io_op_t &op(fd_interest interest) noexcept
  {
    return interest == fd_interest::read ? resource.reader : resource.writer;
  }

  void notify(fd_interest interest)
  {
    if (!on_ready)
      return;
    auto callback = std::move(on_ready);
    on_ready = nullptr;
    struct restore_t
    {
      fd_watch_state_t &state;
      std::function<void(fd_interest)> &callback;
      std::uint32_t generation;
      ~restore_t()
      {
        if (state.callback_generation == generation)
          state.on_ready = std::move(callback);
      }
    } restore{*this, callback, callback_generation};
    callback(interest);
  }

  static void on_readable(detail::io_op_t *op)
  {
    static_cast<fd_watch_state_t *>(op->owner)->notify(fd_interest::read);
  }

  static void on_writable(detail::io_op_t *op)
  {
    static_cast<fd_watch_state_t *>(op->owner)->notify(fd_interest::write);
  }

  event_loop_t &event_loop;
  resource_t resource;
  std::function<void(fd_interest)> on_ready;
  std::uint32_t callback_generation = 0;
};

struct fd_watch_t
{
  ref_ptr_t<fd_watch_state_t> handle;
};

inline std::expected<fd_watch_t, error_t> fd_watch_create(event_loop_t &loop, native_socket_t fd)
{
  fd_watch_t watch{ref_ptr_t<fd_watch_state_t>(loop)};
  watch.handle.register_resource(watch.handle->resource);
  if (int result = watch.handle->resource.open(fd); result < 0)
    return std::unexpected(make_error(result));
  return watch;
}

inline void fd_watch_on_ready(fd_watch_t &watch, std::function<void(fd_interest)> callback)
{
  auto &state = watch.handle.data();
  state.on_ready = std::move(callback);
  ++state.callback_generation;
}

inline void fd_watch_arm(fd_watch_t &watch, fd_interest interest)
{
  auto &state = watch.handle.data();
  state.resource.arm(state.op(interest), static_cast<std::uint8_t>(interest));
}

inline void fd_watch_disarm(fd_watch_t &watch, fd_interest interest)
{
  auto &state = watch.handle.data();
  state.resource.cancel(state.op(interest));
}

[[nodiscard]] inline bool fd_watch_is_armed(fd_watch_t &watch, fd_interest interest)
{
  return watch.handle->op(interest).parked;
}

inline void fd_watch_set_keeps_loop_alive(fd_watch_t &watch, bool keeps_alive)
{
  auto &state = watch.handle.data();
  for (auto interest : {fd_interest::read, fd_interest::write})
  {
    auto &op = state.op(interest);
    if (op.keeps_alive == keeps_alive)
      continue;
    const bool armed = op.parked;
    state.resource.cancel(op);
    op.keeps_alive = keeps_alive;
    if (armed)
      state.resource.arm(op, static_cast<std::uint8_t>(interest));
  }
}
} // namespace vio
