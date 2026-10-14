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

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "backends.h"
#include "vio/errc.h"

namespace vio::detail
{
static backend_kind kind_from_environment() noexcept
{
  const char *value = std::getenv("VIO_BACKEND");
  if (!value || !*value)
    return backend_kind::automatic;
  if (std::strcmp(value, "epoll") == 0)
    return backend_kind::epoll;
  if (std::strcmp(value, "io_uring") == 0)
    return backend_kind::io_uring;
  if (std::strcmp(value, "kqueue") == 0)
    return backend_kind::kqueue;
  if (std::strcmp(value, "iocp") == 0)
    return backend_kind::iocp;
  std::fprintf(stderr, "vio: VIO_BACKEND=%s is not a backend this build knows; using the default\n", value);
  return backend_kind::automatic;
}

std::unique_ptr<backend_t> make_backend(loop_core_t &loop, backend_kind kind, int &error)
{
  error = 0;
  if (kind == backend_kind::automatic)
    kind = kind_from_environment();
#if defined(__linux__)
  if (kind == backend_kind::io_uring)
  {
    auto backend = make_uring_backend(loop, error);
    if (backend)
      return backend;
    std::fprintf(stderr, "vio: io_uring is not available here (%d); using epoll\n", error);
    error = 0;
  }
  return make_epoll_backend(loop, error);
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
  return make_kqueue_backend(loop, error);
#elif defined(_WIN32)
  return make_iocp_backend(loop, error);
#else
  error = errc::not_supported;
  return nullptr;
#endif
}
} // namespace vio::detail
