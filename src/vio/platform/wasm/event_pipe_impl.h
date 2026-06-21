#pragma once

#include <functional>
#include <utility>
#include <vector>

namespace vio
{

template <typename... ARGS>
class event_pipe_t
{
public:
  using tuple_t = std::tuple<std::decay_t<ARGS>...>;

  template <typename EventLoop>
  event_pipe_t(EventLoop &, std::function<void(ARGS &&...event)> &&event_callback)
    : _event_callback(std::move(event_callback))
  {
  }

  explicit event_pipe_t(std::function<void(ARGS &&...event)> event_callback)
    : _event_callback(std::move(event_callback))
  {
  }

  void post_event(ARGS &&...args)
  {
    _events.emplace_back(std::forward<ARGS>(args)...);
    if (!_draining)
    {
      _draining = true;
      while (!_events.empty())
      {
        auto events = std::move(_events);
        _events.clear();
        for (auto &event : events)
        {
          std::apply(_event_callback, std::move(event));
        }
      }
      _draining = false;
    }
  }

  void operator()(ARGS &&...args)
  {
    post_event(std::forward<ARGS>(args)...);
  }

private:
  std::function<void(ARGS &&...args)> _event_callback;
  std::vector<tuple_t> _events;
  bool _draining = false;
};

template <>
class event_pipe_t<void>
{
public:
  template <typename EventLoop>
  event_pipe_t(EventLoop &, std::function<void()> &&event_callback)
    : _event_callback(std::move(event_callback))
  {
  }

  explicit event_pipe_t(std::function<void()> &&event_callback)
    : _event_callback(std::move(event_callback))
  {
  }

  void post_event()
  {
    _event_callback();
  }

private:
  std::function<void()> _event_callback;
};

} // namespace vio
