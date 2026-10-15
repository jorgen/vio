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

#include <atomic>
#include <condition_variable>
#include <cstdlib>
#include <mutex>
#include <new>
#include <thread>
#include <utility>
#include <vector>

#if !defined(_WIN32)
#include <pthread.h>
#endif

#include "vio/loop/loop_core.h"

namespace vio::detail
{
namespace
{
struct job_list_t
{
  pool_job_t *head = nullptr;
  pool_job_t *tail = nullptr;

  [[nodiscard]] bool empty() const noexcept
  {
    return head == nullptr;
  }

  void push_back(pool_job_t &job) noexcept
  {
    job.next = nullptr;
    if (tail)
      tail->next = &job;
    else
      head = &job;
    tail = &job;
  }

  pool_job_t *pop_front() noexcept
  {
    auto *job = head;
    if (!job)
      return nullptr;
    head = job->next;
    if (!head)
      tail = nullptr;
    job->next = nullptr;
    return job;
  }

  bool remove(pool_job_t &job) noexcept
  {
    pool_job_t *previous = nullptr;
    for (auto *it = head; it; previous = it, it = it->next)
    {
      if (it != &job)
        continue;
      if (previous)
        previous->next = it->next;
      else
        head = it->next;
      if (tail == it)
        tail = previous;
      it->next = nullptr;
      return true;
    }
    return false;
  }
};

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
      _queued.push_back(job);
    }
    _ready.notify_one();
  }

  bool remove(pool_job_t &job) noexcept
  {
    std::lock_guard lock(_mutex);
    return _queued.remove(job) || _orphaned.remove(job);
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

  void lock_for_fork() noexcept
  {
    _mutex.lock();
  }

  void unlock_after_fork() noexcept
  {
    _mutex.unlock();
  }

  void orphan_after_fork() noexcept
  {
    new (&_mutex) std::mutex();
    new (&_ready) std::condition_variable();
    new (&_threads) std::vector<std::thread>();
    while (auto *job = _running.pop_front())
    {
      job->state.store(pool_job_queued, std::memory_order_relaxed);
      _orphaned.push_back(*job);
    }
    while (auto *job = _queued.pop_front())
      _orphaned.push_back(*job);
    _stopped = false;
  }

  void reclaim(loop_core_t &loop) noexcept
  {
    std::lock_guard lock(_mutex);
    job_list_t kept;
    while (auto *job = _orphaned.pop_front())
    {
      if (job->loop != &loop)
      {
        kept.push_back(*job);
        continue;
      }
      job->canceled = true;
      job->state.store(pool_job_finished, std::memory_order_relaxed);
      loop.defer(job->finished);
    }
    _orphaned = kept;
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
        _ready.wait(lock, [this] { return _stopped || !_queued.empty(); });
        job = _queued.pop_front();
        if (!job)
          return;
        job->state.store(pool_job_running, std::memory_order_relaxed);
        _running.push_back(*job);
      }
      job->work(job);
      std::lock_guard lock(_mutex);
      if (!_running.remove(*job))
        continue;
      job->state.store(pool_job_finished, std::memory_order_release);
      job->loop->post(job->finished);
    }
  }

  unsigned _thread_count;
  std::mutex _mutex;
  std::condition_variable _ready;
  std::vector<std::thread> _threads;
  job_list_t _queued;
  job_list_t _running;
  job_list_t _orphaned;
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
    current.store(this, std::memory_order_release);
    if (::pthread_atfork(&pools_t::before_fork, &pools_t::after_fork_in_parent, &pools_t::after_fork_in_child) != 0)
      std::abort();
#endif
  }

  ~pools_t()
  {
    current.store(nullptr, std::memory_order_release);
  }

  static void before_fork() noexcept
  {
    forking = current.load(std::memory_order_acquire);
    if (!forking)
      return;
    forking->file.lock_for_fork();
    forking->dns.lock_for_fork();
  }

  static void after_fork_in_parent() noexcept
  {
    auto *pools = std::exchange(forking, nullptr);
    if (!pools)
      return;
    pools->dns.unlock_after_fork();
    pools->file.unlock_after_fork();
  }

  static void after_fork_in_child() noexcept
  {
    auto *pools = std::exchange(forking, nullptr);
    if (!pools)
      return;
    pools->file.orphan_after_fork();
    pools->dns.orphan_after_fork();
    loop_core_t::note_fork_in_child();
  }

  static inline std::atomic<pools_t *> current{nullptr};
  static inline pools_t *forking = nullptr;
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

void pool_reclaim_after_fork(loop_core_t &loop) noexcept
{
  auto *pools = pools_t::current.load(std::memory_order_acquire);
  if (!pools)
    return;
  pools->file.reclaim(loop);
  pools->dns.reclaim(loop);
}
} // namespace vio::detail
