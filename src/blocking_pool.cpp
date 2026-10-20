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
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <memory>
#include <mutex>
#include <new>
#include <thread>
#include <utility>
#include <vector>

#if !defined(_WIN32)
#include <pthread.h>
#endif
#if defined(_MSC_VER)
#include <intrin.h>
#endif

#include "vio/loop/loop_core.h"

namespace vio::detail
{
namespace
{
constexpr std::chrono::microseconds worker_spin{50};

inline void cpu_relax() noexcept
{
#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
  _mm_pause();
#elif defined(_MSC_VER) && defined(_M_ARM64)
  __yield();
#elif defined(__x86_64__) || defined(__i386__)
  __builtin_ia32_pause();
#elif defined(__aarch64__) || defined(__arm__)
  asm volatile("yield");
#endif
}

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
  explicit job_queue_t(unsigned thread_count)
    : _thread_count(thread_count)
    , _current(new std::atomic<pool_job_t *>[thread_count])
  {
    for (unsigned i = 0; i < thread_count; ++i)
      _current[i].store(nullptr, std::memory_order_relaxed);
  }

  ~job_queue_t()
  {
    shutdown();
  }

  void push(pool_job_t &job)
  {
    bool wake;
    {
      std::lock_guard lock(_mutex);
      if (_threads.empty() && !_stopped)
        start();
      _queued.push_back(job);
      _queued_count.store(_queued_count.load(std::memory_order_relaxed) + 1, std::memory_order_release);
      wake = _idle > 0 && _spinning == 0 && _waking == 0;
      if (wake)
        ++_waking;
    }
    if (wake)
      _ready.notify_one();
  }

  bool remove(pool_job_t &job) noexcept
  {
    std::lock_guard lock(_mutex);
    if (_queued.remove(job))
    {
      _queued_count.store(_queued_count.load(std::memory_order_relaxed) - 1, std::memory_order_relaxed);
      return true;
    }
    return _orphaned.remove(job);
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
    _idle = 0;
    _spinning = 0;
    _waking = 0;
    _queued_count.store(0, std::memory_order_relaxed);
    for (unsigned i = 0; i < _thread_count; ++i)
    {
      auto *job = _current[i].exchange(nullptr, std::memory_order_relaxed);
      if (!job)
        continue;
      job->state.store(pool_job_queued, std::memory_order_relaxed);
      _orphaned.push_back(*job);
    }
    while (auto *job = _queued.pop_front())
      _orphaned.push_back(*job);
    _stopped = false;
  }

  void abandon(loop_core_t &loop) noexcept
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
      loop.release();
    }
    _orphaned = kept;
  }

private:
  void start()
  {
    _threads.reserve(_thread_count);
    for (unsigned i = 0; i < _thread_count; ++i)
      _threads.emplace_back([this, i] { work(_current[i]); });
  }

  void work(std::atomic<pool_job_t *> &current)
  {
    std::unique_lock lock(_mutex);
    for (;;)
    {
      if (!_stopped && _queued.empty())
        spin(lock);
      while (!_stopped && _queued.empty())
      {
        ++_idle;
        _ready.wait(lock);
        --_idle;
        if (_waking > 0)
          --_waking;
      }
      auto *job = _queued.pop_front();
      if (!job)
        return;
      _queued_count.store(_queued_count.load(std::memory_order_relaxed) - 1, std::memory_order_relaxed);
      const bool wake_next = !_queued.empty() && _spinning == 0 && _idle > _waking;
      if (wake_next)
        ++_waking;
      job->state.store(pool_job_running, std::memory_order_relaxed);
      current.store(job, std::memory_order_relaxed);
      lock.unlock();
      if (wake_next)
        _ready.notify_one();
      job->work(job);
      current.store(nullptr, std::memory_order_relaxed);
      job->state.store(pool_job_finished, std::memory_order_release);
      job->loop->post(job->finished);
      lock.lock();
    }
  }

  void spin(std::unique_lock<std::mutex> &lock)
  {
    ++_spinning;
    lock.unlock();
    const auto until = std::chrono::steady_clock::now() + worker_spin;
    for (unsigned i = 1; _queued_count.load(std::memory_order_acquire) == 0; ++i)
    {
      cpu_relax();
      if ((i & 63) == 0 && std::chrono::steady_clock::now() >= until)
        break;
    }
    lock.lock();
    --_spinning;
  }

  unsigned _thread_count;
  std::mutex _mutex;
  std::condition_variable _ready;
  std::vector<std::thread> _threads;
  job_list_t _queued;
  std::unique_ptr<std::atomic<pool_job_t *>[]> _current;
  job_list_t _orphaned;
  std::atomic<std::size_t> _queued_count{0};
  unsigned _idle = 0;
  unsigned _spinning = 0;
  unsigned _waking = 0;
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

void on_discarded(posted_t *node)
{
  static_cast<pool_job_t *>(node->owner)->loop->release();
}
} // namespace

void pool_submit(loop_core_t &loop, pool_job_t &job, pool_queue queue)
{
  if (loop.inherited()) [[unlikely]]
    loop.abort_inherited("given blocking work");
  job.loop = &loop;
  job.canceled = false;
  job.finished.run = &on_finished;
  job.finished.discard = &on_discarded;
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

void pool_abandon_after_fork(loop_core_t &loop) noexcept
{
  auto *pools = pools_t::current.load(std::memory_order_acquire);
  if (!pools)
    return;
  pools->file.abandon(loop);
  pools->dns.abandon(loop);
}
} // namespace vio::detail
