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

#include <utility>

#include <vio/loop/backend.h>
#include <vio/loop/loop_core.h>

namespace vio::gui::detail
{
class fd_watch_t final : public vio::detail::resource_t
{
public:
  using ready_fn_t = void (*)(void *context);

  fd_watch_t(vio::detail::loop_core_t &core, const char *kind, ready_fn_t ready = nullptr, void *context = nullptr) noexcept
    : resource_t(core, kind)
    , _ready(ready)
    , _context(context)
  {
    _op.owner = this;
    _op.complete = &fd_watch_t::on_ready;
    _op.keeps_alive = false;
    _removed.owner = this;
    _removed.run = &fd_watch_t::on_removed;
  }

  ~fd_watch_t() override
  {
    if (_op.parked)
      loop().backend().cancel_wait(_watch, _op);
  }

  [[nodiscard]] int open(int fd) noexcept
  {
    _watch.socket = fd;
    if (int result = loop().backend().open_watch(_watch); result < 0)
      return result;
    _registered = true;
    park();
    return 0;
  }

  void park() noexcept
  {
    if (_registered && !closing() && !_op.parked)
      loop().backend().wait(_watch, vio::detail::interest_read, _op);
  }

  bool take_readable() noexcept
  {
    return std::exchange(_readable, false);
  }

  [[nodiscard]] int fd() const noexcept
  {
    return _watch.socket;
  }

private:
  void do_close() noexcept override
  {
    if (_op.parked)
      loop().backend().cancel_wait(_watch, _op);
    if (_registered)
    {
      _registered = false;
      loop().backend().close_watch(_watch, _removed);
    }
    else
    {
      loop().defer(_removed);
    }
  }

  static void on_ready(vio::detail::io_op_t *op)
  {
    auto *self = static_cast<fd_watch_t *>(op->owner);
    self->_readable = true;
    if (self->_ready)
      self->_ready(self->_context);
  }

  static void on_removed(vio::detail::posted_t *node)
  {
    static_cast<fd_watch_t *>(node->owner)->close_finished();
  }

  vio::detail::io_watch_t _watch;
  vio::detail::io_op_t _op;
  vio::detail::posted_t _removed;
  ready_fn_t _ready;
  void *_context;
  bool _readable = false;
  bool _registered = false;
};
} // namespace vio::gui::detail
