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

// The browser backend (D69). A page may not block, so this backend never waits: poll(timeout)
// asks the browser to call back when the next turn is due, through one setTimeout or one
// setImmediate, and the callback runs loop_core_t::run_host_turn(). There are no descriptors;
// a watch is refused with not_supported. The blocking pool has no threads here either: its work
// runs inline when it is submitted, and finishes on the next turn as it would with a worker.

#if defined(__EMSCRIPTEN__)

#include <cstdint>
#include <limits>
#include <memory>

#include <emscripten/eventloop.h>
#if defined(__EMSCRIPTEN_PTHREADS__)
#include <emscripten/proxying.h>
#include <emscripten/threading.h>
#endif

#include "backends.h"
#include "vio/errc.h"
#include "vio/loop/blocking_pool.h"
#include "vio/loop/loop_core.h"

namespace vio::detail
{
namespace
{
// Browsers treat a timeout above 2^31-1 ms as 1 ms. A longer wait is cut to this; the turn it
// brings finds nothing due and asks again.
constexpr std::int64_t longest_timeout_ms = 2147483647;

class browser_backend_t final : public backend_t
{
public:
  explicit browser_backend_t(loop_core_t &loop) noexcept
    : backend_t(loop)
  {
  }

  ~browser_backend_t() override
  {
    disarm_immediate();
    disarm_timeout();
  }

  [[nodiscard]] const char *name() const noexcept override
  {
    return "browser";
  }

  [[nodiscard]] bool supports_host_wait() const noexcept override
  {
    return false;
  }

  [[nodiscard]] bool host_driven() const noexcept override
  {
    return true;
  }

  [[nodiscard]] int add_watch(io_watch_t &) override
  {
    return errc::not_supported;
  }

  void remove_watch(io_watch_t &watch, posted_t &done) override
  {
    watch.closed = true;
    watch.armed = 0;
    _loop.defer(done);
  }

  void wake() noexcept override
  {
#if defined(__EMSCRIPTEN_PTHREADS__)
    // Timers belong to the thread that sets them, and the loop runs on the main thread.
    if (!emscripten_is_main_runtime_thread())
    {
      emscripten_proxy_async(emscripten_proxy_get_system_queue(), emscripten_main_runtime_thread_id(), &browser_backend_t::wake_on_main, this);
      return;
    }
#endif
    arm_immediate();
  }

  void poll(std::int64_t timeout_ns) override
  {
    if (timeout_ns < 0)
    {
      // Nothing is queued and no timer is armed, or the loop has finished: nothing may call back.
      disarm_immediate();
      disarm_timeout();
      return;
    }
    if (timeout_ns == 0)
    {
      arm_immediate();
      return;
    }
    arm_timeout(timeout_ns);
  }

private:
#if defined(__EMSCRIPTEN_PTHREADS__)
  static void wake_on_main(void *self)
  {
    static_cast<browser_backend_t *>(self)->arm_immediate();
  }
#endif

  void arm_immediate()
  {
    if (_immediate_armed)
      return;
    _immediate_armed = true;
    _immediate = emscripten_set_immediate(&browser_backend_t::on_immediate, this);
  }

  void arm_timeout(std::int64_t timeout_ns)
  {
    std::int64_t ms = timeout_ns / 1000000;
    if (ms * 1000000 < timeout_ns)
      ++ms;
    if (ms > longest_timeout_ms)
      ms = longest_timeout_ms;
    const std::int64_t deadline = loop_core_t::deadline_after(ms * 1000000);
    // The same deadline asked for again, to the millisecond, keeps the timeout that is armed.
    if (_timeout_armed && _deadline - deadline < 1000000 && deadline - _deadline < 1000000)
      return;
    disarm_timeout();
    _timeout_armed = true;
    _deadline = deadline;
    _timeout = emscripten_set_timeout(&browser_backend_t::on_timeout, static_cast<double>(ms), this);
  }

  void disarm_immediate() noexcept
  {
    if (!_immediate_armed)
      return;
    emscripten_clear_immediate(_immediate);
    _immediate_armed = false;
  }

  void disarm_timeout() noexcept
  {
    if (!_timeout_armed)
      return;
    emscripten_clear_timeout(_timeout);
    _timeout_armed = false;
  }

  static void on_immediate(void *self)
  {
    auto *backend = static_cast<browser_backend_t *>(self);
    backend->_immediate_armed = false;
    backend->_loop.run_host_turn();
  }

  static void on_timeout(void *self)
  {
    auto *backend = static_cast<browser_backend_t *>(self);
    backend->_timeout_armed = false;
    backend->_loop.run_host_turn();
  }

  int _immediate = 0;
  int _timeout = 0;
  std::int64_t _deadline = 0;
  bool _immediate_armed = false;
  bool _timeout_armed = false;
};

void on_pool_finished(posted_t *node)
{
  auto *job = static_cast<pool_job_t *>(node->owner);
  job->loop->release();
  job->done(job, job->canceled);
}

void on_pool_discarded(posted_t *node)
{
  static_cast<pool_job_t *>(node->owner)->loop->release();
}
} // namespace

std::unique_ptr<backend_t> make_browser_backend(loop_core_t &loop, int &error)
{
  error = 0;
  return std::make_unique<browser_backend_t>(loop);
}

void pool_submit(loop_core_t &loop, pool_job_t &job, pool_queue queue)
{
  job.loop = &loop;
  job.canceled = false;
  job.finished.run = &on_pool_finished;
  job.finished.discard = &on_pool_discarded;
  job.finished.owner = &job;
  job.queue = queue;
  loop.retain();
  job.state.store(pool_job_running, std::memory_order_relaxed);
  job.work(&job);
  job.state.store(pool_job_finished, std::memory_order_release);
  loop.defer(job.finished);
}

bool pool_cancel(pool_job_t &job) noexcept
{
  job.canceled = true;
  return false;
}

void pool_shutdown() noexcept
{
}

void pool_abandon_after_fork(loop_core_t &) noexcept
{
}
} // namespace vio::detail

#endif
