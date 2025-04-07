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
#include <expected>
#include <coroutine>

namespace vio
{

struct error_t {
  int code;
  std::string msg;
};

template <typename REQUEST, typename RESULT>
struct uv_coro_state
{
  uv_coro_state()
    : req({})
  {
  }

  REQUEST req;
  std::expected<RESULT, error_t> result;
  bool done = false;
  std::coroutine_handle<> continuation;
};

template <typename REQUEST, typename RESULT>
struct uv_coro_awaitable
{
  ref_ptr_t<uv_coro_state<REQUEST, RESULT>> state = make_ref_ptr<uv_coro_state<REQUEST, RESULT>>();

  bool await_ready() noexcept
  {
    return state->done;
  }

  void await_suspend(std::coroutine_handle<> continuation) noexcept
  {
    if (state->done)
    {
      continuation.resume();
    }
    else
    {
      state->continuation = continuation;
    }
  }

  std::expected<RESULT, error_t> await_resume() noexcept
  {
    return state->result;
  }
};

} // namespace vio