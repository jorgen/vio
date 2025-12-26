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

#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <utility>
#include <uv.h>

#include "event_pipe.h"
#include "thread_pool.h"
#include "worker.h"

#include <barrier>
#include <cassert>

namespace vio
{

class about_to_block_t
{
public:
  virtual ~about_to_block_t() = default;

  virtual void about_to_block() = 0;

  template <typename Ret, typename Class, typename... Args>
  std::function<void(Args &&...)> bind(Ret (Class::*f)(Args &&...))
  {
    return [this, f](Args &&...args) { return ((*static_cast<Class *>(this)).*f)(std::move(args)...); };
  }
};

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

  ~event_loop_t()
  {
    auto close_result = uv_loop_close(_loop);
    assert(close_result == 0);
    delete _loop;
    _loop = nullptr;
  }

  void run_in_loop(std::function<void()> &&event)
  {
    _run_in_loop.post_event(std::move(event));
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
      barrier_t barrier;
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

  void add_worker_done(worker_t *done)
  {
    _run_in_loop.post_event(
      [done]
      {
        done->mark_done();
        done->after_work(worker_t::completed);
      });
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
    auto event_loop = static_cast<event_loop_t *>(handle->data);
    for (auto cancel_handle : event_loop->_to_cancel_work_handles)
      uv_cancel((uv_req_t *)cancel_handle);
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
  std::vector<uv_work_t *> _to_cancel_work_handles;
  event_pipe_t<std::function<uv_handle_t *(uv_loop_t *)>> _add_pipe;
  event_pipe_t<std::function<void()>> _run_in_loop;

  uv_prepare_t _about_to_block;
  std::vector<about_to_block_t *> _about_to_block_listeners;

  std::thread::id _thread_id;

  friend class worker_t;
};

class thread_with_event_loop_t
{
public:
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

  ~thread_with_event_loop_t()
  {
    _event_loop.stop();
    _thread->join();
  }

  event_loop_t &event_loop()
  {
    return _event_loop;
  }

  const event_loop_t &event_loop() const
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

} // namespace vio
