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

#if defined(__linux__)

#include <cerrno>
#include <cstdint>
#include <ctime>

#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "backends.h"
#include "vio/detail/sys.h"
#include "vio/loop/loop_core.h"

namespace vio::detail
{
namespace
{
constexpr int max_events = 128;

class epoll_backend_t final : public backend_t
{
public:
  epoll_backend_t(loop_core_t &loop, int epoll_fd, int wake_fd) noexcept
    : backend_t(loop)
    , _epoll_fd(epoll_fd)
    , _wake_fd(wake_fd)
  {
  }

  ~epoll_backend_t() override
  {
    ::close(_wake_fd);
    ::close(_epoll_fd);
  }

  [[nodiscard]] const char *name() const noexcept override
  {
    return "epoll";
  }

  [[nodiscard]] int add_watch(io_watch_t &watch) override
  {
    epoll_event event{};
    event.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET;
    event.data.ptr = &watch;
    if (::epoll_ctl(_epoll_fd, EPOLL_CTL_ADD, watch.socket, &event) != 0)
      return errc_from_errno(errno);
    watch.closed = false;
    return 0;
  }

  void remove_watch(io_watch_t &watch, posted_t &done) override
  {
    if (!watch.closed)
    {
      epoll_event event{};
      ::epoll_ctl(_epoll_fd, EPOLL_CTL_DEL, watch.socket, &event);
      watch.closed = true;
    }
    _loop.defer(done);
  }

  void wake() noexcept override
  {
    std::uint64_t one = 1;
    while (::write(_wake_fd, &one, sizeof(one)) < 0 && errno == EINTR)
    {
    }
  }

  void poll(std::int64_t timeout_ns) override
  {
    epoll_event events[max_events];
    int count = wait_for_events(events, timeout_ns);
    for (int i = 0; i < count; ++i)
    {
      auto *watch = static_cast<io_watch_t *>(events[i].data.ptr);
      if (!watch)
      {
        drain_wake();
        continue;
      }
      auto flags = events[i].events;
      bool failed = (flags & (EPOLLERR | EPOLLHUP)) != 0;
      bool readable = failed || (flags & (EPOLLIN | EPOLLRDHUP | EPOLLPRI)) != 0;
      bool writable = failed || (flags & EPOLLOUT) != 0;
      dispatch(*watch, readable, writable);
    }
  }

private:
  int wait_for_events(epoll_event *events, std::int64_t timeout_ns)
  {
#if defined(SYS_epoll_pwait2)
    if (_has_pwait2)
    {
      timespec timeout{};
      timespec *timeout_pointer = nullptr;
      if (timeout_ns >= 0)
      {
        timeout.tv_sec = static_cast<time_t>(timeout_ns / 1000000000);
        timeout.tv_nsec = static_cast<long>(timeout_ns % 1000000000);
        timeout_pointer = &timeout;
      }
      for (;;)
      {
        long count = ::syscall(SYS_epoll_pwait2, _epoll_fd, events, max_events, timeout_pointer, nullptr, 0);
        if (count >= 0)
          return static_cast<int>(count);
        if (errno == EINTR)
          return 0;
        if (errno == ENOSYS)
        {
          _has_pwait2 = false;
          break;
        }
        return 0;
      }
    }
#endif
    int timeout_ms = -1;
    if (timeout_ns >= 0)
    {
      auto rounded = (timeout_ns + 999999) / 1000000;
      timeout_ms = rounded > 0x7fffffff ? 0x7fffffff : static_cast<int>(rounded);
    }
    int count = ::epoll_wait(_epoll_fd, events, max_events, timeout_ms);
    return count < 0 ? 0 : count;
  }

  void drain_wake() noexcept
  {
    std::uint64_t value;
    while (::read(_wake_fd, &value, sizeof(value)) < 0 && errno == EINTR)
    {
    }
  }

  int _epoll_fd;
  int _wake_fd;
  bool _has_pwait2 = true;
};
} // namespace

std::unique_ptr<backend_t> make_epoll_backend(loop_core_t &loop, int &error)
{
  int epoll_fd = ::epoll_create1(EPOLL_CLOEXEC);
  if (epoll_fd < 0)
  {
    error = errc_from_errno(errno);
    return nullptr;
  }
  int wake_fd = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
  if (wake_fd < 0)
  {
    error = errc_from_errno(errno);
    ::close(epoll_fd);
    return nullptr;
  }
  epoll_event event{};
  event.events = EPOLLIN;
  event.data.ptr = nullptr;
  if (::epoll_ctl(epoll_fd, EPOLL_CTL_ADD, wake_fd, &event) != 0)
  {
    error = errc_from_errno(errno);
    ::close(wake_fd);
    ::close(epoll_fd);
    return nullptr;
  }
  return std::make_unique<epoll_backend_t>(loop, epoll_fd, wake_fd);
}
} // namespace vio::detail

#endif
