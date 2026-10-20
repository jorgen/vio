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

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include "vio/loop/backend.h"
#include "vio/loop/intrusive.h"
#include "vio/loop/timer_heap.h"
#include "vio/vio_export.h"

namespace vio
{
class about_to_block_t;
}

namespace vio::detail
{
class loop_core_t;

extern VIO_EXPORT std::atomic<unsigned> fork_epoch;

struct hook_t
{
  using run_fn_t = void (*)(hook_t *hook);
  run_fn_t run = nullptr;
  void *owner = nullptr;
};

class VIO_EXPORT resource_t
{
public:
  using done_fn_t = void (*)(void *context);

  resource_t(loop_core_t &loop, const char *kind) noexcept;
  resource_t(const resource_t &) = delete;
  resource_t &operator=(const resource_t &) = delete;
  virtual ~resource_t();

  void close(done_fn_t done, void *context) noexcept;

  [[nodiscard]] bool closing() const noexcept
  {
    return _closing;
  }
  [[nodiscard]] const char *kind() const noexcept
  {
    return _kind;
  }
  [[nodiscard]] loop_core_t &loop() const noexcept
  {
    return *_loop;
  }

protected:
  virtual void do_close() noexcept = 0;
  void close_finished() noexcept;

private:
  friend class loop_core_t;
  static void on_done(posted_t *node);

  loop_core_t *_loop;
  const char *_kind;
  resource_t *_previous = nullptr;
  resource_t *_next = nullptr;
  posted_t _done_node;
  done_fn_t _done = nullptr;
  void *_context = nullptr;
  bool _closing = false;
  bool _tracked = false;
};

struct pipe_anchor_t
{
  std::mutex mutex;
  loop_core_t *core = nullptr;
  unsigned epoch = 0;
};

class pipe_anchor_owner_t
{
public:
  pipe_anchor_owner_t(loop_core_t *core, unsigned epoch)
    : _anchor(std::make_shared<pipe_anchor_t>())
  {
    _anchor->core = core;
    _anchor->epoch = epoch;
  }
  pipe_anchor_owner_t(const pipe_anchor_owner_t &) = delete;
  pipe_anchor_owner_t &operator=(const pipe_anchor_owner_t &) = delete;
  ~pipe_anchor_owner_t()
  {
    std::lock_guard lock(_anchor->mutex);
    _anchor->core = nullptr;
  }

  [[nodiscard]] const std::shared_ptr<pipe_anchor_t> &anchor() const noexcept
  {
    return _anchor;
  }

private:
  std::shared_ptr<pipe_anchor_t> _anchor;
};

class VIO_EXPORT loop_core_t
{
public:
  explicit loop_core_t(backend_kind kind);
  loop_core_t(const loop_core_t &) = delete;
  loop_core_t &operator=(const loop_core_t &) = delete;
  ~loop_core_t();

  int run();
  void stop();

  void post(posted_t &node);
  bool unpost(posted_t &node) noexcept;
  void unpost_inherited(posted_t &node) noexcept;
  void defer(posted_t &node) noexcept;

  void add_timer(timer_node_t &node, std::int64_t deadline);
  void remove_timer(timer_node_t &node) noexcept;

  void retain() noexcept;
  void release() noexcept;

  void add_listener(about_to_block_t *listener);
  void remove_listener(about_to_block_t *listener) noexcept;
  void add_hook(hook_t &hook);
  void remove_hook(hook_t &hook) noexcept;

  void track(resource_t &resource) noexcept;
  void untrack(resource_t &resource) noexcept;

  [[nodiscard]] backend_t &backend() noexcept
  {
    return *_backend;
  }
  [[nodiscard]] const char *backend_name() const noexcept;
  [[nodiscard]] int init_error() const noexcept
  {
    return _init_error;
  }
  [[nodiscard]] bool in_loop_thread() const noexcept;
  [[nodiscard]] bool running() const noexcept
  {
    return _running;
  }
  [[nodiscard]] bool stopping() const noexcept
  {
    return _stopping;
  }
  [[nodiscard]] std::size_t open_resources() const noexcept
  {
    return _resource_count;
  }
  [[nodiscard]] std::size_t in_flight() const noexcept
  {
    return _alive;
  }
  void set_thread(std::thread::id id) noexcept;
  [[nodiscard]] const std::shared_ptr<pipe_anchor_t> &pipe_anchor() const noexcept
  {
    return _pipe_anchor.anchor();
  }

  [[nodiscard]] bool inherited() const noexcept
  {
    return _fork_epoch != fork_epoch.load(std::memory_order_relaxed);
  }
  void refuse_if_inherited() const noexcept
  {
    if (inherited()) [[unlikely]]
      abort_inherited("run");
  }
  [[noreturn]] void abort_inherited(const char *action) const noexcept;

  [[nodiscard]] static std::int64_t now() noexcept;
  [[nodiscard]] static std::int64_t deadline_after(std::int64_t delay) noexcept;

private:
  static void on_stop(posted_t *node);
  static void note_fork_in_child() noexcept;

  void reclaim_after_fork() noexcept;
  void abandon_after_fork() noexcept;
  void discard_draining() noexcept;
  void abandon_resources() noexcept;
  void discard_queued() noexcept;
  void run_timers();
  void drain_posted();
  void requeue_draining(std::size_t from) noexcept;
  void drain_deferred();
  void run_before_block();
  [[nodiscard]] std::int64_t wait_timeout() noexcept;
  [[nodiscard]] bool alive() noexcept;

  std::unique_ptr<backend_t> _backend;
  int _init_error = 0;
  timer_heap_t _timers;

  std::mutex _post_mutex;
  posted_list_t _posted;
  std::vector<posted_t *> _draining;
  std::atomic<bool> _wake_pending{false};

  posted_list_t _deferred;
  posted_t *_deferred_draining = nullptr;
  std::vector<about_to_block_t *> _listeners;
  std::vector<hook_t *> _hooks;
  std::size_t _alive = 0;

  resource_t *_resources = nullptr;
  std::size_t _resource_count = 0;

  posted_t _stop_node;
  std::atomic<std::thread::id> _thread_id;
  unsigned _fork_epoch = 0;
  bool _stopping = false;
  bool _running = false;
  pipe_anchor_owner_t _pipe_anchor{this, _fork_epoch};
};

inline void unpost_anchored(pipe_anchor_t &anchor, posted_t &node) noexcept
{
  if (anchor.epoch != fork_epoch.load(std::memory_order_relaxed)) [[unlikely]]
  {
    if (anchor.core)
      anchor.core->unpost_inherited(node);
    return;
  }
  std::lock_guard lock(anchor.mutex);
  if (anchor.core)
    anchor.core->unpost(node);
}
} // namespace vio::detail
