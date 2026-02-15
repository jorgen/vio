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

#include <coroutine>
#include <memory>
#include <tuple>
#include <type_traits>

#include "event_loop.h"
#include "event_pipe.h"
#include "task.h"

namespace vio
{

struct detached_task_t
{
  struct promise_type // NOLINT(readability-identifier-naming)
  {
    detached_task_t get_return_object()
    {
      return {};
    }
    std::suspend_never initial_suspend()
    {
      return {};
    }
    std::suspend_never final_suspend() noexcept
    {
      return {};
    }
    void return_void()
    {
    }
    void unhandled_exception()
    {
      std::terminate();
    }
  };
};

template <typename Result, typename... ARGS>
class awaitable_event_pipe_t
{
public:
  struct call_state_t
  {
    Result result{};
    std::tuple<std::decay_t<ARGS>...> args;
    std::coroutine_handle<> continuation;
  };

  struct call_awaitable_t
  {
    std::shared_ptr<call_state_t> _state;

    explicit call_awaitable_t(std::shared_ptr<call_state_t> state)
      : _state(std::move(state))
    {
    }

    [[nodiscard]] bool await_ready() const noexcept
    {
      return false;
    }

    void await_suspend(std::coroutine_handle<> continuation) noexcept
    {
      _state->continuation = continuation;
    }

    Result await_resume() noexcept
    {
      return std::move(_state->result);
    }
  };

  template <typename F>
  awaitable_event_pipe_t(event_loop_t &caller_loop, event_loop_t &handler_loop, F &&handler)
    : _response_pipe(caller_loop,
        std::function<void(std::shared_ptr<call_state_t> &&)>([](std::shared_ptr<call_state_t> &&state) { state->continuation.resume(); }))
    , _request_pipe(handler_loop, make_request_callback(std::forward<F>(handler)))
  {
  }

  awaitable_event_pipe_t(const awaitable_event_pipe_t &) = delete;
  awaitable_event_pipe_t(awaitable_event_pipe_t &&) = delete;
  awaitable_event_pipe_t &operator=(const awaitable_event_pipe_t &) = delete;
  awaitable_event_pipe_t &operator=(awaitable_event_pipe_t &&) = delete;

  call_awaitable_t call(ARGS... args)
  {
    auto state = std::make_shared<call_state_t>();
    state->args = std::make_tuple(std::move(args)...);
    call_awaitable_t awaitable(state);
    _request_pipe.post_event(std::move(state));
    return awaitable;
  }

private:
  template <typename F>
  std::function<void(std::shared_ptr<call_state_t> &&)> make_request_callback(F &&handler)
  {
    return [handler = std::forward<F>(handler), response_pipe = &_response_pipe](std::shared_ptr<call_state_t> &&state) mutable
    {
      using invoke_result = std::invoke_result_t<std::decay_t<F>, ARGS...>;
      if constexpr (std::is_same_v<invoke_result, Result>)
      {
        state->result = std::apply(handler, std::move(state->args));
        response_pipe->post_event(std::move(state));
      }
      else
      {
        static_assert(std::is_same_v<invoke_result, task_t<Result>>, "Handler must return Result or task_t<Result>");
        [](std::decay_t<F> h, std::shared_ptr<call_state_t> s, event_pipe_t<std::shared_ptr<call_state_t>> *rp) -> detached_task_t
        {
          s->result = co_await std::apply(std::move(h), std::move(s->args));
          rp->post_event(std::move(s));
        }(handler, std::move(state), response_pipe);
      }
    };
  }

  event_pipe_t<std::shared_ptr<call_state_t>> _response_pipe;
  event_pipe_t<std::shared_ptr<call_state_t>> _request_pipe;
};

} // namespace vio
