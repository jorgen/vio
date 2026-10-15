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

#include "vio/loop/blocking_pool.h"

#include <condition_variable>
#include <cstdlib>
#include <mutex>
#include <new>
#include <thread>
#include <vector>

#if !defined(_WIN32)
#include <pthread.h>
#endif

#include "vio/loop/loop_core.h"

namespace vio::detail
{
namespace
{
class job_queue_t
{
public:
  explicit job_queue_t(unsigned thread_count) noexcept
    : _thread_count(thread_count)
  {
  }

  ~job_queue_t()
  {
    shutdown();
  }

  void push(pool_job_t &job)
  {
    {
      std::lock_guard lock(_mutex);
      if (_threads.empty() && !_stopped)
        start();
      job.next = nullptr;
      if (_tail)
        _tail->next = &job;
      else
        _head = &job;
      _tail = &job;
    }
    _ready.notify_one();
  }

  bool remove(pool_job_t &job) noexcept
  {
    std::lock_guard lock(_mutex);
    pool_job_t *previous = nullptr;
    for (auto *it = _head; it; previous = it, it = it->next)
    {
      if (it != &job)
        continue;
      if (previous)
        previous->next = it->next;
      else
        _head = it->next;
      if (_tail == it)
        _tail = previous;
      it->next = nullptr;
      return true;
    }
    return false;
  }

  void shutdown() noexcept
  {
    std::vector<std::thread> threads;
    {
      std::lock_guard lock(_mutex);
      _stopped = true;
      threads.swap(_threads);
    }
    _ready.notify_all();
    for (auto &thread : threads)
      thread.join();
  }

  void forget_after_fork() noexcept
  {
    new (&_mutex) std::mutex();
    new (&_ready) std::condition_variable();
    new (&_threads) std::vector<std::thread>();
    _head = nullptr;
    _tail = nullptr;
    _stopped = false;
  }

private:
  void start()
  {
    _threads.reserve(_thread_count);
    for (unsigned i = 0; i < _thread_count; ++i)
      _threads.emplace_back([this] { work(); });
  }

  void work()
  {
    for (;;)
    {
      pool_job_t *job;
      {
        std::unique_lock lock(_mutex);
        _ready.wait(lock, [this] { return _stopped || _head; });
        if (!_head)
          return;
        job = _head;
        _head = job->next;
        if (!_head)
          _tail = nullptr;
        job->next = nullptr;
        job->state.store(pool_job_running, std::memory_order_relaxed);
      }
      job->work(job);
      job->state.store(pool_job_finished, std::memory_order_release);
      job->loop->post(job->finished);
    }
  }

  unsigned _thread_count;
  std::mutex _mutex;
  std::condition_variable _ready;
  std::vector<std::thread> _threads;
  pool_job_t *_head = nullptr;
  pool_job_t *_tail = nullptr;
  bool _stopped = false;
};

unsigned threads_from_environment(const char *name, unsigned fallback) noexcept
{
  const char *value = std::getenv(name);
  if (!value)
    return fallback;
  auto parsed = std::strtoul(value, nullptr, 10);
  if (parsed == 0 || parsed > 1024)
    return fallback;
  return static_cast<unsigned>(parsed);
}

struct pools_t
{
  pools_t()
  {
#if !defined(_WIN32)
    current = this;
    if (::pthread_atfork(nullptr, nullptr, &pools_t::after_fork_in_child) != 0)
      std::abort();
#endif
  }

  ~pools_t()
  {
    current = nullptr;
  }

  static void after_fork_in_child() noexcept
  {
    if (!current)
      return;
    current->file.forget_after_fork();
    current->dns.forget_after_fork();
  }

  static inline pools_t *current = nullptr;
  job_queue_t file{threads_from_environment("VIO_FILE_THREADS", 4)};
  job_queue_t dns{threads_from_environment("VIO_DNS_THREADS", 2)};
};

job_queue_t &queue_for(pool_queue queue)
{
  static pools_t pools;
  return queue == pool_queue::dns ? pools.dns : pools.file;
}

void on_finished(posted_t *node)
{
  auto *job = static_cast<pool_job_t *>(node->owner);
  auto *loop = job->loop;
  loop->release();
  job->done(job, job->canceled);
}
} // namespace

void pool_submit(loop_core_t &loop, pool_job_t &job, pool_queue queue)
{
  job.loop = &loop;
  job.canceled = false;
  job.finished.run = &on_finished;
  job.finished.owner = &job;
  job.queue = queue;
  job.state.store(pool_job_queued, std::memory_order_relaxed);
  loop.retain();
  queue_for(queue).push(job);
}

bool pool_cancel(pool_job_t &job) noexcept
{
  job.canceled = true;
  if (job.state.load(std::memory_order_acquire) != pool_job_queued)
    return false;
  if (!queue_for(job.queue).remove(job))
    return false;
  job.state.store(pool_job_finished, std::memory_order_relaxed);
  job.loop->defer(job.finished);
  return true;
}

void pool_shutdown() noexcept
{
  queue_for(pool_queue::file).shutdown();
  queue_for(pool_queue::dns).shutdown();
}
} // namespace vio::detail
