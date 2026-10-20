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

#include "vio/loop/loop_core.h"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <new>
#include <utility>

#if !defined(_WIN32)
#include <pthread.h>
#endif

#include "backends.h"
#include "vio/about_to_block.h"
#include "vio/errc.h"
#include "vio/loop/blocking_pool.h"

namespace vio::detail
{
std::atomic<unsigned> fork_epoch{0};

void abort_destroyed_in_flight(const char *what) noexcept
{
  std::fprintf(stderr, "vio: a %s was destroyed while the loop or the kernel still held it\n", what);
  std::abort();
}

resource_t::resource_t(loop_core_t &loop, const char *kind) noexcept
  : _loop(&loop)
  , _kind(kind)
{
  _done_node.run = &resource_t::on_done;
  _done_node.owner = this;
  loop.track(*this);
}

resource_t::~resource_t()
{
  if (_tracked)
    _loop->untrack(*this);
}

void resource_t::close(done_fn_t done, void *context) noexcept
{
  if (_closing)
    return;
  _closing = true;
  _done = done;
  _context = context;
  _loop->retain();
  do_close();
}

void resource_t::close_finished() noexcept
{
  _loop->defer(_done_node);
}

void resource_t::on_done(posted_t *node)
{
  auto *self = static_cast<resource_t *>(node->owner);
  auto *loop = self->_loop;
  loop->untrack(*self);
  auto done = self->_done;
  auto *context = self->_context;
  loop->release();
  if (done)
    done(context);
}

void backend_t::submit_file(file_op_t &)
{
  std::fprintf(stderr, "vio: backend %s has no asynchronous file support\n", name());
  std::abort();
}

void backend_t::cancel_file(file_op_t &) noexcept
{
}

void backend_t::abandon_after_fork() noexcept
{
}

void backend_t::arm(io_watch_t &, std::uint8_t)
{
}

int backend_t::open_watch(io_watch_t &watch)
{
  if (_loop.inherited()) [[unlikely]]
    _loop.abort_inherited("given a socket");
  return add_watch(watch);
}

void backend_t::close_watch(io_watch_t &watch, posted_t &done)
{
  forget_retry(watch);
  if (_loop.inherited())
  {
    watch.closed = true;
    watch.armed = 0;
    _loop.defer(done);
    return;
  }
  remove_watch(watch, done);
}

void backend_t::retry_later(io_watch_t &watch, bool readable, bool writable) noexcept
{
  if (watch.closed)
    return;
  auto interest = static_cast<std::uint8_t>((readable ? interest_read : 0) | (writable ? interest_write : 0));
  if (interest == 0)
    return;
  if (watch.retry == 0)
  {
    watch.retry_next = nullptr;
    if (_retry_tail)
      _retry_tail->retry_next = &watch;
    else
      _retry_head = &watch;
    _retry_tail = &watch;
  }
  watch.retry |= interest;
  _loop.defer(_retry);
}

void backend_t::forget_retry(io_watch_t &watch) noexcept
{
  if (watch.retry == 0)
    return;
  io_watch_t *previous = nullptr;
  for (auto *it = _retry_head; it; previous = it, it = it->retry_next)
  {
    if (it != &watch)
      continue;
    if (previous)
      previous->retry_next = it->retry_next;
    else
      _retry_head = it->retry_next;
    if (_retry_tail == it)
      _retry_tail = previous;
    break;
  }
  watch.retry_next = nullptr;
  watch.retry = 0;
}

void backend_t::on_retry(posted_t *node)
{
  auto &self = *static_cast<backend_t *>(node->owner);
  struct interrupted_t
  {
    backend_t &self;
    ~interrupted_t()
    {
      if (self._retry_head)
        self._loop.defer(self._retry);
    }
  } pending{self};
  while (auto *watch = self._retry_head)
  {
    self._retry_head = watch->retry_next;
    if (!self._retry_head)
      self._retry_tail = nullptr;
    watch->retry_next = nullptr;
    auto interest = std::exchange(watch->retry, std::uint8_t{0});
    self.dispatch(*watch, (interest & interest_read) != 0, (interest & interest_write) != 0);
  }
}

void backend_t::wait(io_watch_t &watch, std::uint8_t interest, io_op_t &op)
{
  if (_loop.inherited()) [[unlikely]]
    _loop.abort_inherited("used to wait on a socket");
  op.interest = interest;
  op.epoch = watch.epoch;
  op.parked = true;
  if (interest == interest_read)
    watch.readers.push_back(op);
  else
    watch.writers.push_back(op);
  if (op.keeps_alive)
    _loop.retain();
  arm(watch, interest);
}

void backend_t::cancel_wait(io_watch_t &watch, io_op_t &op) noexcept
{
  if (!op.parked)
    return;
  if (op.interest == interest_read)
    watch.readers.remove(op);
  else
    watch.writers.remove(op);
  op.parked = false;
  if (op.keeps_alive)
    _loop.release();
}

static void complete_older_than(loop_core_t &loop, io_watch_t &watch, op_list_t &list, std::uint32_t epoch)
{
  for (;;)
  {
    if (watch.closed)
      return;
    auto *op = list.front();
    if (!op || op->epoch == epoch)
      return;
    list.remove(*op);
    op->parked = false;
    if (op->keeps_alive)
      loop.release();
    op->complete(op);
    loop.refuse_if_inherited();
  }
}

void backend_t::dispatch(io_watch_t &watch, bool readable, bool writable)
{
  if (watch.closed)
    return;
  auto epoch = ++watch.epoch;
  struct interrupted_t
  {
    backend_t &backend;
    io_watch_t &watch;
    bool readable;
    bool writable;
    ~interrupted_t()
    {
      if (readable || writable)
        backend.retry_later(watch, readable, writable);
    }
  } pending{*this, watch, readable, writable};
  if (readable)
    complete_older_than(_loop, watch, watch.readers, epoch);
  pending.readable = false;
  if (writable)
    complete_older_than(_loop, watch, watch.writers, epoch);
  pending.writable = false;
}

loop_core_t::loop_core_t(backend_kind kind)
  : _thread_id(std::this_thread::get_id())
  , _fork_epoch(fork_epoch.load(std::memory_order_relaxed))
{
#if !defined(_WIN32)
  static const bool fork_watched = ::pthread_atfork(nullptr, nullptr, &loop_core_t::note_fork_in_child) == 0;
  if (!fork_watched)
  {
    std::fprintf(stderr, "vio: event loop could not register its fork handler\n");
    std::abort();
  }
#endif
  _stop_node.run = &loop_core_t::on_stop;
  _stop_node.owner = this;
  _backend = make_backend(*this, kind, _init_error);
  if (!_backend)
  {
    std::fprintf(stderr, "vio: event loop could not create a backend (%d)\n", _init_error);
    std::abort();
  }
}

loop_core_t::~loop_core_t()
{
  if (inherited())
    abandon_after_fork();
  if (_resource_count > 0 || _alive > 0)
  {
    std::fprintf(stderr, "vio: ~event_loop_t: %zu resource(s) still open, %zu operation(s) in flight\n", _resource_count, _alive);
    for (auto *it = _resources; it; it = it->_next)
      std::fprintf(stderr, "vio: ~event_loop_t: %s still open\n", it->_kind);
    std::fprintf(stderr, "vio: ~event_loop_t: a vio handle outlived its event loop; release it before the loop stops running -- "
                         "owning it inside a coroutine that completes, or in a scope that ends, before stop() is the usual fix.\n");
    assert(_resource_count == 0 && _alive == 0);
  }
  discard_queued();
  _backend.reset();
}

void loop_core_t::discard_queued() noexcept
{
  {
    std::lock_guard lock(_post_mutex);
    set_thread(std::this_thread::get_id());
  }
  for (;;)
  {
    posted_t *node;
    posted_t::run_fn_t discard;
    {
      std::lock_guard lock(_post_mutex);
      node = _posted.pop_front();
      if (!node)
        node = _deferred.pop_front();
      if (!node)
        break;
      node->queued = false;
      discard = node->discard;
    }
    if (discard)
      discard(node);
  }
}

void loop_core_t::note_fork_in_child() noexcept
{
  fork_epoch.fetch_add(1, std::memory_order_relaxed);
}

void loop_core_t::abort_inherited(const char *action) const noexcept
{
  std::fprintf(stderr,
               "vio: an event loop created before fork() was %s in the child; its %s backend belongs to the parent, so a child may only destroy a loop it inherited and must create its own\n",
               action, backend_name());
  std::abort();
}

void loop_core_t::abandon_after_fork() noexcept
{
  new (&_post_mutex) std::mutex();
  new (&_pipe_anchor.anchor()->mutex) std::mutex();
  set_thread(std::this_thread::get_id());
  pool_abandon_after_fork(*this);
  discard_draining();
  discard_queued();
  abandon_closes();
  _backend->abandon_after_fork();
}

void loop_core_t::discard_draining() noexcept
{
  for (std::size_t i = 0; i < _draining.size(); ++i)
  {
    auto *node = std::exchange(_draining[i], nullptr);
    if (node && !node->queued && node->discard)
      node->discard(node);
  }
  _draining.clear();
  while (auto *node = _deferred_draining)
  {
    _deferred_draining = node->next;
    node->next = nullptr;
    node->queued = false;
    if (node->discard)
      node->discard(node);
  }
}

void loop_core_t::abandon_closes() noexcept
{
  for (auto *it = _resources; it;)
  {
    auto *next = it->_next;
    if (it->_closing)
    {
      untrack(*it);
      release();
    }
    it = next;
  }
}

std::int64_t loop_core_t::now() noexcept
{
  return std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
}

std::int64_t loop_core_t::deadline_after(std::int64_t delay) noexcept
{
  auto current = now();
  if (delay <= 0)
    return current;
  if (delay > std::numeric_limits<std::int64_t>::max() - current)
    return std::numeric_limits<std::int64_t>::max();
  return current + delay;
}

const char *loop_core_t::backend_name() const noexcept
{
  return _backend->name();
}

bool loop_core_t::in_loop_thread() const noexcept
{
  return _thread_id.load(std::memory_order_relaxed) == std::this_thread::get_id();
}

void loop_core_t::set_thread(std::thread::id id) noexcept
{
  _thread_id.store(id, std::memory_order_relaxed);
}

int loop_core_t::run()
{
  refuse_if_inherited();
  set_thread(std::this_thread::get_id());
  _running = true;
  for (;;)
  {
    run_timers();
    drain_posted();
    drain_deferred();
    if (_stopping && !alive())
      break;
    run_before_block();
    _backend->poll(wait_timeout());
  }
  _running = false;
  return 0;
}

void loop_core_t::stop()
{
  post(_stop_node);
}

void loop_core_t::on_stop(posted_t *node)
{
  static_cast<loop_core_t *>(node->owner)->_stopping = true;
}

void loop_core_t::post(posted_t &node)
{
  std::lock_guard lock(_post_mutex);
  if (node.queued)
    return;
  node.queued = true;
  _posted.push_back(node);
  if (!_wake_pending.exchange(true, std::memory_order_acq_rel))
    _backend->wake();
}

bool loop_core_t::unpost(posted_t &node) noexcept
{
  bool removed = false;
  std::lock_guard lock(_post_mutex);
  if (in_loop_thread())
  {
    for (auto &pending : _draining)
    {
      if (pending == &node)
      {
        pending = nullptr;
        removed = true;
      }
    }
    if (_deferred.remove(node))
    {
      node.queued = false;
      removed = true;
    }
    for (posted_t **link = &_deferred_draining; *link; link = &(*link)->next)
    {
      if (*link != &node)
        continue;
      *link = node.next;
      node.next = nullptr;
      node.queued = false;
      removed = true;
      break;
    }
  }
  if (!node.queued)
    return removed;
  node.queued = false;
  return _posted.remove(node) || removed;
}

void loop_core_t::defer(posted_t &node) noexcept
{
  if (node.queued)
    return;
  node.queued = true;
  _deferred.push_back(node);
}

void loop_core_t::drain_posted()
{
  _wake_pending.store(false, std::memory_order_release);
  _draining.clear();
  {
    std::lock_guard lock(_post_mutex);
    auto *head = _posted.take_all();
    while (head)
    {
      auto *next = head->next;
      head->next = nullptr;
      head->queued = false;
      _draining.push_back(head);
      head = next;
    }
  }
  struct interrupted_t
  {
    loop_core_t &core;
    std::size_t next = 0;
    ~interrupted_t()
    {
      if (next < core._draining.size())
        core.requeue_draining(next);
    }
  } drain{*this};
  for (; drain.next < _draining.size(); ++drain.next)
  {
    if (auto *node = std::exchange(_draining[drain.next], nullptr))
    {
      node->run(node);
      refuse_if_inherited();
    }
  }
  _draining.clear();
}

void loop_core_t::requeue_draining(std::size_t from) noexcept
{
  std::lock_guard lock(_post_mutex);
  posted_t *head = nullptr;
  posted_t **link = &head;
  for (auto i = from; i < _draining.size(); ++i)
  {
    auto *node = std::exchange(_draining[i], nullptr);
    if (!node || (node->queued && !_posted.remove(*node)))
      continue;
    node->queued = true;
    node->next = nullptr;
    *link = node;
    link = &node->next;
  }
  _posted.prepend(head);
  _draining.clear();
}

void loop_core_t::drain_deferred()
{
  struct interrupted_t
  {
    loop_core_t &core;
    ~interrupted_t()
    {
      core._deferred.prepend(std::exchange(core._deferred_draining, nullptr));
    }
  } drain{*this};
  _deferred_draining = _deferred.take_all();
  while (auto *node = _deferred_draining)
  {
    _deferred_draining = node->next;
    node->next = nullptr;
    node->queued = false;
    node->run(node);
    refuse_if_inherited();
  }
}

void loop_core_t::add_timer(timer_node_t &node, std::int64_t deadline)
{
  remove_timer(node);
  node.deadline = deadline;
  _timers.insert(node);
  if (node.keeps_alive)
    retain();
}

void loop_core_t::remove_timer(timer_node_t &node) noexcept
{
  if (!node.armed())
    return;
  _timers.erase(node);
  if (node.keeps_alive)
    release();
}

void loop_core_t::run_timers()
{
  if (_timers.empty())
    return;
  auto current = now();
  auto limit = _timers.next_sequence();
  for (;;)
  {
    auto *top = _timers.top();
    if (!top || top->deadline > current || top->sequence >= limit)
      return;
    _timers.erase(*top);
    if (top->keeps_alive)
      release();
    top->fire(top);
    refuse_if_inherited();
  }
}

void loop_core_t::run_before_block()
{
  if (!_stopping)
  {
    for (std::size_t i = 0; i < _listeners.size(); ++i)
    {
      _listeners[i]->about_to_block();
      refuse_if_inherited();
    }
  }
  for (std::size_t i = 0; i < _hooks.size(); ++i)
  {
    _hooks[i]->run(_hooks[i]);
    refuse_if_inherited();
  }
}

std::int64_t loop_core_t::wait_timeout() noexcept
{
  if (!_deferred.empty())
    return 0;
  {
    std::lock_guard lock(_post_mutex);
    if (!_posted.empty())
      return 0;
  }
  auto *top = _timers.top();
  if (!top)
    return -1;
  return std::max<std::int64_t>(0, top->deadline - now());
}

bool loop_core_t::alive() noexcept
{
  if (_alive > 0 || !_deferred.empty())
    return true;
  std::lock_guard lock(_post_mutex);
  return !_posted.empty();
}

void loop_core_t::retain() noexcept
{
  ++_alive;
}

void loop_core_t::release() noexcept
{
  assert(_alive > 0);
  --_alive;
}

void loop_core_t::add_listener(about_to_block_t *listener)
{
  _listeners.push_back(listener);
}

void loop_core_t::remove_listener(about_to_block_t *listener) noexcept
{
  _listeners.erase(std::remove(_listeners.begin(), _listeners.end(), listener), _listeners.end());
}

void loop_core_t::add_hook(hook_t &hook)
{
  _hooks.push_back(&hook);
}

void loop_core_t::remove_hook(hook_t &hook) noexcept
{
  _hooks.erase(std::remove(_hooks.begin(), _hooks.end(), &hook), _hooks.end());
}

void loop_core_t::track(resource_t &resource) noexcept
{
  resource._previous = nullptr;
  resource._next = _resources;
  if (_resources)
    _resources->_previous = &resource;
  _resources = &resource;
  resource._tracked = true;
  ++_resource_count;
}

void loop_core_t::untrack(resource_t &resource) noexcept
{
  if (!resource._tracked)
    return;
  if (resource._previous)
    resource._previous->_next = resource._next;
  else
    _resources = resource._next;
  if (resource._next)
    resource._next->_previous = resource._previous;
  resource._previous = nullptr;
  resource._next = nullptr;
  resource._tracked = false;
  --_resource_count;
}
} // namespace vio::detail
