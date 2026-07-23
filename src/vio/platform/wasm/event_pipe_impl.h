#pragma once

#include <functional>
#include <tuple>
#include <utility>
#include <vector>

namespace vio
{
// event_loop_t is completed by the time these member templates are instantiated (the consumer includes
// <vio/event_loop.h>). Forward-declaring it here keeps this header free of an include cycle.
class event_loop_t;

// Cross-loop event pipe for the single-threaded WebAssembly runtime. Unlike a naive inline drain, this
// mirrors the libuv contract the rest of vio/points is written against: post_event returns immediately
// and the callback runs LATER on the pipe's *owning* loop (scheduled via run_in_loop, drained on that
// loop's next cooperative poll) -- never re-entrantly on the poster's stack. That matters when loop A
// posts to a pipe owned by loop B: B's handler must run in B's turn, not inside A.
template <typename... ARGS>
class event_pipe_t
{
public:
  using tuple_t = std::tuple<std::decay_t<ARGS>...>;

  template <typename EventLoop>
  event_pipe_t(EventLoop &event_loop, std::function<void(ARGS &&...event)> &&event_callback)
    : _event_callback(std::move(event_callback))
    , _loop(&event_loop)
  {
  }

  // Loopless pipe (no owning loop): drains inline. Only used by event-loop internals; on wasm this path
  // is essentially unused, but it is kept for API parity with the libuv implementation.
  explicit event_pipe_t(std::function<void(ARGS &&...event)> event_callback)
    : _event_callback(std::move(event_callback))
    , _loop(nullptr)
  {
  }

  void post_event(ARGS &&...args)
  {
    _events.emplace_back(std::forward<ARGS>(args)...);
    schedule_drain();
  }

  void operator()(ARGS &&...args)
  {
    post_event(std::forward<ARGS>(args)...);
  }

private:
  void schedule_drain();

  void drain()
  {
    if (_draining)
      return; // reentrancy guard for the loopless inline path
    _draining = true;
    while (!_events.empty())
    {
      auto events = std::move(_events);
      _events.clear();
      for (auto &event : events)
        std::apply(_event_callback, std::move(event));
    }
    _draining = false;
    _drain_scheduled = false;
  }

  std::function<void(ARGS &&...args)> _event_callback;
  std::vector<tuple_t> _events;
  event_loop_t *_loop = nullptr;
  bool _drain_scheduled = false;
  bool _draining = false;
};

template <>
class event_pipe_t<void>
{
public:
  template <typename EventLoop>
  event_pipe_t(EventLoop &event_loop, std::function<void()> &&event_callback)
    : _event_callback(std::move(event_callback))
    , _loop(&event_loop)
  {
  }

  explicit event_pipe_t(std::function<void()> &&event_callback)
    : _event_callback(std::move(event_callback))
    , _loop(nullptr)
  {
  }

  // Coalesced, like uv_async_send: any number of posts before the owning loop's next turn results in a
  // single callback invocation there.
  void post_event();

private:
  std::function<void()> _event_callback;
  event_loop_t *_loop = nullptr;
  bool _scheduled = false;
};

} // namespace vio

// The scheduling helpers need the complete event_loop_t (for run_in_loop), so they are defined after it.
#include <vio/platform/wasm/event_loop_impl.h>

namespace vio
{

template <typename... ARGS>
inline void event_pipe_t<ARGS...>::schedule_drain()
{
  if (_drain_scheduled || _draining)
    return;
  if (_loop)
  {
    _drain_scheduled = true;
    _loop->run_in_loop([this]() { drain(); });
  }
  else
  {
    drain();
  }
}

inline void event_pipe_t<void>::post_event()
{
  if (_scheduled)
    return;
  if (_loop)
  {
    _scheduled = true;
    _loop->run_in_loop([this]() {
      _scheduled = false;
      _event_callback();
    });
  }
  else
  {
    _event_callback();
  }
}

} // namespace vio
