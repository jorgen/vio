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
#error "vio/loop_hooks.h needs the native event loop"
#endif

#include <functional>
#include <utility>

#include "vio/event_loop.h"

namespace vio
{
class before_block_hook_t
{
public:
  before_block_hook_t(event_loop_t &loop, std::function<void()> callback)
    : _core(detail::core(loop))
    , _callback(std::move(callback))
  {
    _hook.owner = this;
    _hook.run = &before_block_hook_t::on_run;
  }
  before_block_hook_t(const before_block_hook_t &) = delete;
  before_block_hook_t &operator=(const before_block_hook_t &) = delete;
  ~before_block_hook_t()
  {
    stop();
  }

  void start()
  {
    if (_started)
      return;
    _core.add_hook(_hook);
    _started = true;
  }

  void stop() noexcept
  {
    if (!_started)
      return;
    _core.remove_hook(_hook);
    _started = false;
  }

  [[nodiscard]] bool started() const noexcept
  {
    return _started;
  }

private:
  static void on_run(detail::hook_t *hook)
  {
    static_cast<before_block_hook_t *>(hook->owner)->_callback();
  }

  detail::loop_core_t &_core;
  detail::hook_t _hook;
  std::function<void()> _callback;
  bool _started = false;
};

class deferred_call_t
{
public:
  deferred_call_t(event_loop_t &loop, std::function<void()> callback)
    : _core(detail::core(loop))
    , _callback(std::move(callback))
  {
    _node.owner = this;
    _node.run = &deferred_call_t::on_run;
  }
  deferred_call_t(const deferred_call_t &) = delete;
  deferred_call_t &operator=(const deferred_call_t &) = delete;
  ~deferred_call_t()
  {
    cancel();
  }

  void schedule() noexcept
  {
    _core.defer(_node);
  }

  void cancel() noexcept
  {
    if (_node.queued)
      _core.unpost(_node);
  }

  [[nodiscard]] bool scheduled() const noexcept
  {
    return _node.queued;
  }

private:
  static void on_run(detail::posted_t *node)
  {
    static_cast<deferred_call_t *>(node->owner)->_callback();
  }

  detail::loop_core_t &_core;
  detail::posted_t _node;
  std::function<void()> _callback;
};
} // namespace vio
