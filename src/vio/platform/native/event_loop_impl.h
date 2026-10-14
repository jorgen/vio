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

#include <condition_variable>
#include <csignal>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <type_traits>

#include "vio/about_to_block.h"
#include "vio/loop/loop_core.h"
#include "vio/platform/native/event_loop_fwd.h"
#include "vio/task.h"
#include "vio/tick.h"

namespace vio
{
using backend_kind_t = detail::backend_kind;

struct barrier_t
{
  std::mutex mutex;
  std::condition_variable wait;
  bool released = false;
};

class event_loop_t
{
public:
  event_loop_t()
    : event_loop_t(backend_kind_t::automatic)
  {
  }

  explicit event_loop_t(backend_kind_t kind)
    : _core(kind)
  {
#if !defined(_WIN32) && !defined(VIO_NO_SIGPIPE_IGNORE)
    std::signal(SIGPIPE, SIG_IGN);
#endif
  }

  event_loop_t(const event_loop_t &) = delete;
  event_loop_t &operator=(const event_loop_t &) = delete;
  event_loop_t(event_loop_t &&) = delete;
  event_loop_t &operator=(event_loop_t &&) = delete;
  ~event_loop_t() = default;

  void run_in_loop(std::function<void()> &&event)
  {
    struct node_t : detail::posted_t
    {
      std::function<void()> function;
    };
    auto *node = new node_t;
    node->function = std::move(event);
    node->owner = node;
    node->run = [](detail::posted_t *posted) {
      auto *self = static_cast<node_t *>(posted->owner);
      auto function = std::move(self->function);
      delete self;
      function();
    };
    node->discard = [](detail::posted_t *posted) { delete static_cast<node_t *>(posted->owner); };
    _core.post(*node);
  }

  template <typename F>
    requires std::is_same_v<std::invoke_result_t<F>, task_t<void>>
  void run_in_loop(F &&f)
  {
    run_in_loop(std::function<void()>([func = std::forward<F>(f)]() mutable { [](task_t<void> t) -> detached_task_t { co_await std::move(t); }(func()); }));
  }

  void override_thread_id(std::thread::id thread_id)
  {
    _core.set_thread(thread_id);
  }

  int run()
  {
    return _core.run();
  }

  void stop()
  {
    _core.stop();
  }

  void add_about_to_block_listener(about_to_block_t *listener)
  {
    run_in_loop([this, listener] { _core.add_listener(listener); });
  }

  void remove_about_to_block_listener(about_to_block_t *listener)
  {
    run_in_loop([this, listener] { _core.remove_listener(listener); });
  }

  [[nodiscard]] const char *backend_name() const noexcept
  {
    return _core.backend_name();
  }

  [[nodiscard]] bool in_loop_thread() const noexcept
  {
    return _core.in_loop_thread();
  }

private:
  friend detail::loop_core_t &detail::core(event_loop_t &loop) noexcept;
  detail::loop_core_t _core;
};

namespace detail
{
inline loop_core_t &core(event_loop_t &loop) noexcept
{
  return loop._core;
}
} // namespace detail

class thread_with_event_loop_t
{
public:
  thread_with_event_loop_t(const thread_with_event_loop_t &) = delete;
  thread_with_event_loop_t(thread_with_event_loop_t &&) = delete;
  thread_with_event_loop_t &operator=(const thread_with_event_loop_t &) = delete;
  thread_with_event_loop_t &operator=(thread_with_event_loop_t &&) = delete;

  thread_with_event_loop_t()
  {
    barrier_t barrier;
    _thread = std::make_unique<std::thread>([&barrier, this] {
      {
        std::lock_guard lock(barrier.mutex);
        barrier.released = true;
        barrier.wait.notify_one();
      }
      _event_loop.run();
    });
    std::unique_lock lock(barrier.mutex);
    barrier.wait.wait(lock, [&barrier] { return barrier.released; });
  }

  ~thread_with_event_loop_t()
  {
    stop_and_join();
  }

  void stop_and_join()
  {
    if (_thread && _thread->joinable())
    {
      _event_loop.stop();
      _thread->join();
    }
  }

  [[nodiscard]] event_loop_t &event_loop()
  {
    return _event_loop;
  }

  [[nodiscard]] const event_loop_t &event_loop() const
  {
    return _event_loop;
  }

  [[nodiscard]] std::thread::id thread_id() const
  {
    return _thread->get_id();
  }

private:
  event_loop_t _event_loop;
  std::unique_ptr<std::thread> _thread;
};

inline tick_t loop_now(event_loop_t &event_loop)
{
  (void)event_loop;
  return tick_t::from_nanoseconds(std::chrono::nanoseconds(detail::loop_core_t::now()));
}
} // namespace vio
