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

#include <atomic>

#include "vio/loop/intrusive.h"
#include "vio/vio_export.h"

namespace vio::detail
{
class loop_core_t;

enum class pool_queue
{
  file,
  dns
};

struct pool_job_t
{
  using work_fn_t = void (*)(pool_job_t *job);
  using done_fn_t = void (*)(pool_job_t *job, bool canceled);

  work_fn_t work = nullptr;
  done_fn_t done = nullptr;
  void *owner = nullptr;
  loop_core_t *loop = nullptr;
  pool_job_t *next = nullptr;
  posted_t finished;
  std::atomic<int> state{0};
  pool_queue queue = pool_queue::file;
  bool canceled = false;
};

VIO_EXPORT void pool_submit(loop_core_t &loop, pool_job_t &job, pool_queue queue);
VIO_EXPORT bool pool_cancel(pool_job_t &job) noexcept;
VIO_EXPORT void pool_shutdown() noexcept;
} // namespace vio::detail
