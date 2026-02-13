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

#include <algorithm>
#include <coroutine>

namespace vio
{
template <typename T>
class task_t
{
public:
  task_t(task_t &&t) noexcept
    : _coro(std::exchange(t._coro, {}))
  {
  }

  task_t(const task_t &) = delete;
  task_t &operator=(const task_t &) = delete;
  task_t &operator=(task_t &&) = delete;

  ~task_t()
  {
    if (_coro && _coro.done())
    {
      _coro.destroy();
    }
  }

  struct promise_t
  {
    task_t get_return_object()
    {
      return task_t{std::coroutine_handle<promise_t>::from_promise(*this)};
    }

    void unhandled_exception()
    {
      std::terminate();
    }

    void return_value(T &&value)
    {
      return_value_holder = std::move(value);
    }

    std::suspend_never initial_suspend()
    {
      return {};
    }

    struct final_awaitable_t
    {
      [[nodiscard]] bool await_ready() const noexcept
      {
        return false;
      }

      std::coroutine_handle<> await_suspend(std::coroutine_handle<promise_t> co) noexcept
      {
        if (co.promise().continuation)
        {
          return co.promise().continuation;
        }

        return std::noop_coroutine();
      }

      void await_resume() const noexcept
      {
      }
    };

    final_awaitable_t final_suspend() noexcept
    {
      return {};
    }

    std::coroutine_handle<> continuation;
    T return_value_holder;
  };

  class awaiter_t;

  inline awaiter_t operator co_await() && noexcept;

  using promise_type = promise_t; // NOLINT(readability-identifier-naming)

private:
  explicit task_t(std::coroutine_handle<promise_t> coro) noexcept
    : _coro(coro)
  {
  }

  std::coroutine_handle<promise_t> _coro;
};

template <typename T>
class task_t<T>::awaiter_t
{
public:
  bool await_ready() noexcept
  {
    return _coro.done();
  }

  void await_suspend(std::coroutine_handle<> continuation) noexcept
  {
    _coro.promise().continuation = continuation;
  }

  T await_resume() noexcept
  {
    return std::move(_coro.promise().return_value_holder);
  }

  explicit awaiter_t(std::coroutine_handle<task_t::promise_type> h) noexcept
    : _coro(h)
  {
  }

private:
  std::coroutine_handle<task_t::promise_type> _coro;
};

template <typename T>
inline task_t<T>::awaiter_t task_t<T>::operator co_await() && noexcept
{
  return awaiter_t{_coro};
}

template <>
class task_t<void>
{
public:
  task_t(task_t &&t) noexcept
    : _coro(std::exchange(t._coro, {}))
  {
  }

  task_t(const task_t &) = delete;
  task_t &operator=(const task_t &) = delete;
  task_t &operator=(task_t &&) = delete;

  ~task_t()
  {
    if (_coro && _coro.done())
    {
      _coro.destroy();
    }
  }

  struct promise_t
  {
    task_t get_return_object()
    {
      return task_t{std::coroutine_handle<promise_t>::from_promise(*this)};
    }

    void unhandled_exception()
    {
      std::terminate();
    }

    void return_void()
    {
    }

    std::suspend_never initial_suspend()
    {
      return {};
    }

    struct final_awaitable_t
    {
      [[nodiscard]] bool await_ready() const noexcept
      {
        return false;
      }

      std::coroutine_handle<> await_suspend(std::coroutine_handle<promise_t> co) noexcept
      {
        if (co.promise().continuation)
        {
          return co.promise().continuation;
        }

        return std::noop_coroutine();
      }

      void await_resume() const noexcept
      {
      }
    };

    final_awaitable_t final_suspend() noexcept
    {
      return {};
    }

    std::coroutine_handle<> continuation;
  };

  class awaiter_t;

  inline awaiter_t operator co_await() && noexcept;

  using promise_type = promise_t; // NOLINT(readability-identifier-naming)

private:
  explicit task_t(std::coroutine_handle<promise_t> coro) noexcept
    : _coro(coro)
  {
  }

  std::coroutine_handle<promise_t> _coro;
};

class task_t<void>::awaiter_t
{
public:
  bool await_ready() noexcept
  {
    return _coro.done();
  }

  void await_suspend(std::coroutine_handle<> continuation) noexcept
  {
    _coro.promise().continuation = continuation;
  }

  void await_resume() noexcept
  {
  }

  explicit awaiter_t(std::coroutine_handle<task_t::promise_type> h) noexcept
    : _coro(h)
  {
  }

private:
  std::coroutine_handle<task_t::promise_type> _coro;
};

inline task_t<void>::awaiter_t task_t<void>::operator co_await() && noexcept
{
  return awaiter_t{_coro};
}

} // namespace vio
