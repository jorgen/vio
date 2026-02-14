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
#include <mutex>
#include <utility>
#include <uv.h>
#include <vector>

namespace vio
{
struct event_bind_t
{
  template <typename Ret, typename Class, typename... Args>
  static std::function<void(Args &&...)> bind(Class &ref, Ret (Class::*f)(Args &&...))
  {
    return [&ref, f](Args &&...args) { return ((*static_cast<Class *>(&ref)).*f)(std::forward<Args>(args)...); };
  }
};

template <typename... ARGS>
class event_pipe_t
{
public:
  using tuple_t = std::tuple<std::decay_t<ARGS>...>;

  template <typename EventLoop>
  event_pipe_t(EventLoop &event_loop, std::function<void(ARGS &&...event)> &&event_callback)
    : _event_callback(std::move(event_callback))
  {
    _pipe.data = this;
    event_loop.add_event_pipe(*this);
  }

  explicit event_pipe_t(std::function<void(ARGS &&...event)> event_callback)
    : _event_callback(event_callback)
  {
    _pipe.data = this;
  }

  uv_handle_t *initialize_in_loop(uv_loop_t *loop)
  {
    auto on_event = [](uv_async_t *handle)
    {
      auto *event_pipe = static_cast<event_pipe_t *>(handle->data);
      std::vector<tuple_t> event_vec;
      event_pipe->swap_events(event_vec);
      for (auto &event : event_vec)
      {
        std::apply(event_pipe->_event_callback, std::move(event));
      }
    };
    uv_async_init(loop, &_pipe, on_event);

    return reinterpret_cast<uv_handle_t *>(&_pipe);
  }

  void post_event(ARGS &&...args)
  {
    std::unique_lock<std::mutex> lock(_mutex);
    _events.emplace_back(std::forward<ARGS>(args)...);
    uv_async_send(&_pipe);
  }

  void operator()(ARGS &&...args)
  {
    post_event(std::forward<ARGS>(args)...);
  }

  void swap_events(std::vector<tuple_t> &to_swap)
  {
    std::unique_lock<std::mutex> lock(_mutex);
    std::swap(_events, to_swap);
    _events.reserve(to_swap.capacity());
  }

private:
  std::function<void(ARGS &&...args)> _event_callback;
  std::vector<tuple_t> _events;
  uv_async_t _pipe{};
  std::mutex _mutex;
};

template <>
class event_pipe_t<void>
{
public:
  template <typename EventLoop>
  event_pipe_t(EventLoop &event_loop, std::function<void()> &&event_callback)
    : _event_callback(std::move(event_callback))
  {
    _pipe.data = this;
    event_loop.add_event_pipe(*this);
  }

  explicit event_pipe_t(std::function<void()> &&event_callback)
    : _event_callback(std::move(event_callback))
  {
    _pipe.data = this;
  }

  uv_handle_t *initialize_in_loop(uv_loop_t *loop)
  {
    auto on_event = [](uv_async_t *handle)
    {
      auto *event_pipe = static_cast<event_pipe_t *>(handle->data);
      event_pipe->_event_callback();
    };
    uv_async_init(loop, &_pipe, on_event);

    return reinterpret_cast<uv_handle_t *>(&_pipe);
  }

  void post_event()
  {
    uv_async_send(&_pipe);
  }

private:
  std::function<void()> _event_callback;
  uv_async_t _pipe{};
};

} // namespace vio
