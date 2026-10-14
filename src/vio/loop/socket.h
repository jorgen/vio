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

#include <coroutine>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

#include "vio/detail/sys.h"
#include "vio/errc.h"
#include "vio/loop/loop_core.h"

namespace vio::detail
{
class socket_resource_t final : public resource_t
{
public:
  explicit socket_resource_t(loop_core_t &loop, const char *kind = "socket") noexcept
    : resource_t(loop, kind)
  {
    _removed.owner = this;
    _removed.run = &socket_resource_t::on_removed;
  }

  ~socket_resource_t() override
  {
    if (_registered && !closing())
    {
      std::fprintf(stderr, "vio: a %s was destroyed without being closed\n", kind());
      std::abort();
    }
    if (watch.socket != invalid_native_socket && !closing())
      socket_close(watch.socket);
  }

  [[nodiscard]] int open(int family, int type, int protocol) noexcept
  {
    native_socket_t socket = invalid_native_socket;
    if (int result = socket_open(family, type, protocol, socket); result < 0)
      return result;
    return adopt(socket);
  }

  [[nodiscard]] int adopt(native_socket_t socket) noexcept
  {
    watch.socket = socket;
    if (int result = loop().backend().add_watch(watch); result < 0)
      return result;
    _registered = true;
    return 0;
  }

  [[nodiscard]] native_socket_t native() const noexcept
  {
    return watch.socket;
  }

  [[nodiscard]] bool is_open() const noexcept
  {
    return watch.socket != invalid_native_socket && !closing();
  }

  void wait(std::uint8_t interest, io_op_t &op)
  {
    loop().backend().wait(watch, interest, op);
  }

  void cancel(io_op_t &op) noexcept
  {
    loop().backend().cancel_wait(watch, op);
  }

  io_watch_t watch;

private:
  void do_close() noexcept override
  {
    if (_registered)
    {
      _registered = false;
      loop().backend().remove_watch(watch, _removed);
    }
    else
    {
      loop().defer(_removed);
    }
    socket_close(watch.socket);
  }

  static void on_removed(posted_t *node)
  {
    auto *self = static_cast<socket_resource_t *>(node->owner);
    self->watch.socket = invalid_native_socket;
    self->close_finished();
  }

  posted_t _removed;
  bool _registered = false;
};

template <typename Derived>
struct readiness_awaiter_t : io_op_t
{
  std::coroutine_handle<> continuation = {};
  std::int64_t result = 0;

  [[nodiscard]] bool await_ready() noexcept
  {
    result = self().attempt();
    return result != errc::again;
  }

  void await_suspend(std::coroutine_handle<> handle) noexcept
  {
    continuation = handle;
    owner = this;
    complete = &readiness_awaiter_t::on_ready;
    self().socket().wait(self().interest(), *this);
  }

  void cancel_wait() noexcept
  {
    if (!parked)
      return;
    self().socket().cancel(*this);
    result = errc::canceled;
    continuation.resume();
  }

private:
  Derived &self() noexcept
  {
    return static_cast<Derived &>(*this);
  }

  static void on_ready(io_op_t *op)
  {
    auto *awaiter = static_cast<readiness_awaiter_t *>(op->owner);
    awaiter->result = awaiter->self().attempt();
    if (awaiter->result == errc::again)
    {
      awaiter->self().socket().wait(awaiter->self().interest(), *awaiter);
      return;
    }
    awaiter->continuation.resume();
  }
};
} // namespace vio::detail
