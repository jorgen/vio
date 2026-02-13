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

#include "thread_pool.h"

#include <uv.h>

namespace vio
{
class event_loop_t;
class worker_t
{
public:
  enum completion_t : std::uint8_t
  {
    cancelled,
    completed
  };
  worker_t();
  worker_t(const worker_t &) = delete;
  worker_t(worker_t &&) = default;
  worker_t &operator=(const worker_t &) = delete;
  worker_t &operator=(worker_t &&) = default;
  virtual ~worker_t();
  virtual void work() = 0;
  virtual void after_work(completion_t completion) = 0;

  void enqueue(event_loop_t &loop, thread_pool_t &pool);
  void mark_done()
  {
    _done = true;
  }
  [[nodiscard]] bool done() const
  {
    return _done;
  }

private:
  bool _done{false};
  uv_async_t _async = {};
};
} // namespace points::converter
