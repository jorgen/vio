#pragma once

#include "vio/about_to_block.h"
#include "vio/event_pipe.h"
#include "vio/task.h"
#include "vio/thread_pool.h"
#include "vio/tick.h"

#include <chrono>

#include <memory>
#include <mutex>
#include <thread>
#include <type_traits>
#include <utility>
#include <uv.h>

#include <barrier>
#include <cassert>
#include <cstdio>
#ifndef _WIN32
#include <csignal>
#endif

namespace vio
{

struct barrier_t
{
  std::mutex mutex;
  std::condition_variable wait;
};

class event_loop_t
{
public:
  event_loop_t()
    : _loop(nullptr)
    , _add_pipe([this](std::function<uv_handle_t *(uv_loop_t *)> &&event) { add_event_pipe_cb(std::move(event)); })
    , _run_in_loop([](std::function<void()> &&event) { event(); })
    , _thread_id(std::this_thread::get_id())
  {
#if !defined(_WIN32) && !defined(VIO_NO_SIGPIPE_IGNORE)
    signal(SIGPIPE, SIG_IGN);
#endif
    _to_close_handles.reserve(16);
    _loop = new uv_loop_t();
    uv_loop_init(_loop);

    uv_async_init(_loop, &_async_stop, &exit_event_loop_cb);
    _async_stop.data = this;
    _to_close_handles.push_back((uv_handle_t *)&_async_stop);
    _to_close_handles.push_back(_add_pipe.initialize_in_loop(_loop));
    _to_close_handles.push_back(_run_in_loop.initialize_in_loop(_loop));

    uv_prepare_init(_loop, &_about_to_block);
    _about_to_block.data = this;
    uv_prepare_start(&_about_to_block, &about_to_block_cb);
    _to_close_handles.push_back((uv_handle_t *)&_about_to_block);
    uv_run(_loop, UV_RUN_NOWAIT);
  }

  event_loop_t(const event_loop_t &) = delete;

  event_loop_t &operator=(const event_loop_t &) = delete;

  event_loop_t(event_loop_t &&other) = delete;

  event_loop_t &operator=(event_loop_t &&other) = delete;

  // uv_loop_close fails while any handle is still open, which happens when a
  // vio handle outlives the loop: its uv_close is requested after the loop
  // stopped running, so the close callback never fires. The failure is a
  // programming error, but assert() alone reports it as a bare abort with no
  // context in debug and vanishes entirely under NDEBUG, leaking the loop and
  // every handle on it. Naming the open handles costs nothing and turns it
  // into a one-line diagnosis.
  //
  // The handles are deliberately not force-closed here. They live inside
  // reference-counted storage their owner still holds, and that owner will
  // uv_close them when it is destroyed; closing them twice is worse than
  // leaking them.
  ~event_loop_t()
  {
    auto close_result = uv_loop_close(_loop);
    if (close_result != 0)
    {
      int open_handles = 0;
      uv_walk(
        _loop,
        [](uv_handle_t *handle, void *arg)
        {
          ++*static_cast<int *>(arg);
          std::fprintf(stderr, "vio: ~event_loop_t: %s handle still open\n", uv_handle_type_name(handle->type));
        },
        &open_handles);
      std::fprintf(stderr,
                   "vio: ~event_loop_t: %d handle(s) still open (%s). A vio handle outlived its event loop; "
                   "release it before the loop stops running -- owning it inside a coroutine that completes, "
                   "or in a scope that ends, before stop() is the usual fix.\n",
                   open_handles, uv_strerror(close_result));
    }
    assert(close_result == 0);
    delete _loop;
    _loop = nullptr;
  }

  void run_in_loop(std::function<void()> &&event)
  {
    _run_in_loop.post_event(std::move(event));
  }

  template <typename F>
    requires std::is_same_v<std::invoke_result_t<F>, task_t<void>>
  void run_in_loop(F &&f)
  {
    _run_in_loop.post_event(
      [func = std::forward<F>(f)]() mutable
      {
        [](task_t<void> t) -> detached_task_t { co_await std::move(t); }(func());
      });
  }

  void override_thread_id(std::thread::id thread_id)
  {
    _thread_id = thread_id;
  }

  auto run()
  {
    _thread_id = std::this_thread::get_id();
    return uv_run(_loop, UV_RUN_DEFAULT);
  }

  void stop()
  {
    uv_async_send(&_async_stop);
  }

  template <typename... ARGS>
  void add_event_pipe(event_pipe_t<ARGS...> &event_pipe)
  {
    if (_thread_id == std::this_thread::get_id())
    {
      _to_close_handles.push_back(event_pipe.initialize_in_loop(_loop));
    }
    else
    {
      barrier_t barrier; // NOLINT(misc-const-correctness)
      std::unique_lock<std::mutex> lock(barrier.mutex);

      std::function<uv_handle_t *(uv_loop_t *)> func = [&event_pipe, &barrier](uv_loop_t *loop)
      {
        auto to_ret = event_pipe.initialize_in_loop(loop);
        std::unique_lock<std::mutex> lock(barrier.mutex);
        barrier.wait.notify_one();
        return to_ret;
      };
      _add_pipe.post_event(std::move(func));
      barrier.wait.wait(lock);
    }
  }

  void add_about_to_block_listener(about_to_block_t *listener)
  {
    _run_in_loop.post_event([this, listener] { _about_to_block_listeners.push_back(listener); });
  }

  void remove_about_to_block_listener(about_to_block_t *listener)
  {
    _run_in_loop.post_event([this, listener] { _about_to_block_listeners.erase(std::remove(_about_to_block_listeners.begin(), _about_to_block_listeners.end(), listener), _about_to_block_listeners.end()); });
  }

  [[nodiscard]] uv_loop_t *loop() const
  {
    return _loop;
  }

private:
  void add_event_pipe_cb(std::function<uv_handle_t *(uv_loop_t *)> &&event)
  {
    _to_close_handles.emplace_back(event(_loop));
  }

  static void about_to_block_cb(uv_prepare_t *handle)
  {
    auto *event_loop = static_cast<event_loop_t *>(handle->data);
    for (auto listener : event_loop->_about_to_block_listeners)
    {
      listener->about_to_block();
    }
  }

  static void exit_event_loop_cb(uv_async_t *handle)
  {
    auto *event_loop = static_cast<event_loop_t *>(handle->data);
    for (auto close_handle : event_loop->_to_close_handles)
    {
      uv_close(close_handle, nullptr);
    }
    uv_run(event_loop->_loop, UV_RUN_DEFAULT);

    uv_prepare_stop(&event_loop->_about_to_block);
  }

  uv_loop_t *_loop;
  uv_async_t _async_stop;
  std::mutex _mutex;
  std::vector<uv_handle_t *> _to_close_handles;
  event_pipe_t<std::function<uv_handle_t *(uv_loop_t *)>> _add_pipe;
  event_pipe_t<std::function<void()>> _run_in_loop;

  uv_prepare_t _about_to_block;
  std::vector<about_to_block_t *> _about_to_block_listeners;

  std::thread::id _thread_id;
};

class thread_with_event_loop_t
{
public:
  thread_with_event_loop_t(const thread_with_event_loop_t &) = delete;
  thread_with_event_loop_t(thread_with_event_loop_t &&) = delete;
  thread_with_event_loop_t &operator=(const thread_with_event_loop_t &) = delete;
  thread_with_event_loop_t &operator=(thread_with_event_loop_t &&) = delete;

  thread_with_event_loop_t()
    : _event_loop()
  {
    barrier_t barrier;
    std::unique_lock<std::mutex> lock(barrier.mutex);

    auto run = [&barrier, this]
    {
      {
        std::unique_lock<std::mutex> lock(barrier.mutex);
        barrier.wait.notify_one();
      }
      _event_loop.run();
    };

    _thread.reset(new std::thread(run));
    barrier.wait.wait(lock);
  }

  ~thread_with_event_loop_t() // NOLINT(modernize-use-equals-default)
  {
    stop_and_join();
  }

  // Stop the loop and join the thread. Idempotent. Call this before destroying
  // any event_pipe registered on this loop: otherwise the loop thread may still
  // be draining the pipe while the pipe's storage is torn down (a data race).
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

// The single producer of tick_t in a process.
//
// uv_hrtime() rather than uv_now(): uv_now() is the loop's cached time in
// milliseconds, too coarse for an RTT estimate. The event loop is taken by
// parameter although uv_hrtime() is global, so that a caller cannot read the
// clock without having a loop in hand.
inline tick_t loop_now(event_loop_t &event_loop)
{
  (void)event_loop;
  return tick_t::from_nanoseconds(std::chrono::nanoseconds(uv_hrtime()));
}

} // namespace vio
