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
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

#include "vio/platform/native/event_loop_fwd.h"

namespace vio
{
template <typename... ARGS>
class event_pipe_t
{
public:
  using tuple_t = std::tuple<std::decay_t<ARGS>...>;

  template <typename EventLoop>
  event_pipe_t(EventLoop &event_loop, std::function<void(ARGS &&...event)> &&event_callback)
    : _event_callback(std::move(event_callback))
    , _core(&detail::core(event_loop))
    , _anchor(_core->pipe_anchor())
  {
    _node.owner = this;
    _node.run = &event_pipe_t::on_posted;
  }

  event_pipe_t(const event_pipe_t &) = delete;
  event_pipe_t &operator=(const event_pipe_t &) = delete;
  event_pipe_t(event_pipe_t &&) = delete;
  event_pipe_t &operator=(event_pipe_t &&) = delete;

  ~event_pipe_t()
  {
    detail::unpost_anchored(*_anchor, _node);
  }

  void post_event(ARGS &&...args)
  {
    {
      std::lock_guard lock(_mutex);
      _events.emplace_back(std::forward<ARGS>(args)...);
    }
    _core->post(_node);
  }

  void operator()(ARGS &&...args)
  {
    post_event(std::forward<ARGS>(args)...);
  }

  void drain_events()
  {
    if (_draining)
    {
      _core->post(_node);
      return;
    }
    {
      std::lock_guard lock(_mutex);
      if (_drain_next == _drain_buffer.size())
      {
        std::swap(_events, _drain_buffer);
      }
      else if (!_events.empty())
      {
        _drain_buffer.insert(_drain_buffer.end(), std::make_move_iterator(_events.begin()), std::make_move_iterator(_events.end()));
        _events.clear();
      }
    }
    struct interrupted_t
    {
      event_pipe_t &pipe;
      ~interrupted_t()
      {
        pipe._draining = false;
        if (pipe._drain_next < pipe._drain_buffer.size())
        {
          pipe._core->post(pipe._node);
          return;
        }
        pipe._drain_buffer.clear();
        pipe._drain_next = 0;
      }
    } drain{*this};
    _draining = true;
    while (_drain_next < _drain_buffer.size())
    {
      auto &event = _drain_buffer[_drain_next++];
      std::apply(_event_callback, std::move(event));
      _core->refuse_if_inherited();
    }
  }

private:
  static void on_posted(detail::posted_t *node)
  {
    static_cast<event_pipe_t *>(node->owner)->drain_events();
  }

  std::function<void(ARGS &&...args)> _event_callback;
  detail::loop_core_t *_core;
  std::shared_ptr<detail::pipe_anchor_t> _anchor;
  detail::posted_t _node;
  std::mutex _mutex;
  std::vector<tuple_t> _events;
  std::vector<tuple_t> _drain_buffer;
  std::size_t _drain_next = 0;
  bool _draining = false;
};

template <>
class event_pipe_t<void>
{
public:
  template <typename EventLoop>
  event_pipe_t(EventLoop &event_loop, std::function<void()> &&event_callback)
    : _event_callback(std::move(event_callback))
    , _core(&detail::core(event_loop))
    , _anchor(_core->pipe_anchor())
  {
    _node.owner = this;
    _node.run = &event_pipe_t::on_posted;
  }

  event_pipe_t(const event_pipe_t &) = delete;
  event_pipe_t &operator=(const event_pipe_t &) = delete;
  event_pipe_t(event_pipe_t &&) = delete;
  event_pipe_t &operator=(event_pipe_t &&) = delete;

  ~event_pipe_t()
  {
    detail::unpost_anchored(*_anchor, _node);
  }

  void post_event()
  {
    _core->post(_node);
  }

  void operator()()
  {
    post_event();
  }

private:
  static void on_posted(detail::posted_t *node)
  {
    static_cast<event_pipe_t *>(node->owner)->_event_callback();
  }

  std::function<void()> _event_callback;
  detail::loop_core_t *_core;
  std::shared_ptr<detail::pipe_anchor_t> _anchor;
  detail::posted_t _node;
};
} // namespace vio
