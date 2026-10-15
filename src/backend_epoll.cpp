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
#include <cstdio>
#include <cstdlib>
#include <cstring>
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
constexpr std::uint32_t read_events = EPOLLIN | EPOLLRDHUP | EPOLLET;
constexpr std::uint32_t write_events = read_events | EPOLLOUT;

[[noreturn]] void fatal(const char *what, int error) noexcept
{
  std::fprintf(stderr, "vio: epoll %s (%s)\n", what, std::strerror(error));
  std::abort();
}

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
    event.events = read_events;
    event.data.ptr = &watch;
    if (::epoll_ctl(_epoll_fd, EPOLL_CTL_ADD, watch.socket, &event) != 0)
      return errc_from_errno(errno);
    watch.closed = false;
    watch.armed = 0;
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
      bool unwanted_write = (flags & EPOLLOUT) != 0 && watch->writers.empty();
      dispatch(*watch, readable, writable);
      if (unwanted_write && !watch->closed && watch->writers.empty() && (watch->armed & interest_write))
      {
        modify(*watch, read_events);
        watch->armed &= static_cast<std::uint8_t>(~interest_write);
      }
    }
  }

protected:
  void arm(io_watch_t &watch, std::uint8_t interest) override
  {
    if (interest != interest_write || watch.closed || (watch.armed & interest_write))
      return;
    modify(watch, write_events);
    watch.armed |= interest_write;
  }

private:
  void modify(io_watch_t &watch, std::uint32_t mask)
  {
    epoll_event event{};
    event.events = mask;
    event.data.ptr = &watch;
    if (::epoll_ctl(_epoll_fd, EPOLL_CTL_MOD, watch.socket, &event) != 0)
      fatal("could not change what a socket is watched for", errno);
  }

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
      long count = ::syscall(SYS_epoll_pwait2, _epoll_fd, events, max_events, timeout_pointer, nullptr, 0);
      if (count >= 0)
        return static_cast<int>(count);
      if (errno == EINTR)
        return 0;
      _has_pwait2 = false;
    }
#endif
    int timeout_ms = -1;
    if (timeout_ns >= 0)
    {
      auto rounded = timeout_ns / 1000000 + (timeout_ns % 1000000 != 0 ? 1 : 0);
      timeout_ms = rounded > 0x7fffffff ? 0x7fffffff : static_cast<int>(rounded);
    }
    int count = ::epoll_wait(_epoll_fd, events, max_events, timeout_ms);
    if (count >= 0)
      return count;
    if (errno != EINTR)
      fatal("wait failed", errno);
    return 0;
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

#if defined(VIO_INTERNAL_TESTS)
#include <doctest/doctest.h>

#include <chrono>
#include <csignal>
#include <cstddef>
#include <functional>
#include <iterator>
#include <thread>

#include <linux/filter.h>
#include <linux/seccomp.h>
#include <netinet/in.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include "vio/errc.h"
#include "vio/loop/socket.h"

#if defined(__SANITIZE_THREAD__)
#define VIO_EPOLL_TEST_UNDER_TSAN 1
#elif defined(__has_feature)
#if __has_feature(thread_sanitizer)
#define VIO_EPOLL_TEST_UNDER_TSAN 1
#endif
#endif

namespace vio::detail
{
namespace
{
constexpr std::int64_t epoll_test_millisecond = 1000000;

struct epoll_test_turns_t
{
  hook_t hook;
  std::int64_t turns = 0;

  epoll_test_turns_t()
  {
    hook.owner = this;
    hook.run = [](hook_t *raw) { ++static_cast<epoll_test_turns_t *>(raw->owner)->turns; };
  }
};

struct epoll_test_alarm_t
{
  timer_node_t node;
  std::function<void()> fire;

  epoll_test_alarm_t()
  {
    node.owner = this;
    node.fire = [](timer_node_t *raw) { static_cast<epoll_test_alarm_t *>(raw->owner)->fire(); };
  }

  void arm(loop_core_t &loop, std::int64_t delay_ns)
  {
    loop.add_timer(node, loop_core_t::now() + delay_ns);
  }
};

struct epoll_test_op_t : io_op_t
{
  std::function<void(epoll_test_op_t &)> on_complete;

  epoll_test_op_t()
  {
    owner = this;
    complete = [](io_op_t *op) {
      auto *self = static_cast<epoll_test_op_t *>(op->owner);
      self->on_complete(*self);
    };
  }
};

void epoll_test_close(socket_resource_t &resource)
{
  resource.close(nullptr, nullptr);
}

const_bytes_t epoll_test_bytes(const char *text, std::size_t size)
{
  return {reinterpret_cast<const std::byte *>(text), size};
}
} // namespace

TEST_CASE("epoll: datagrams sent with no writer parked do not wake the loop")
{
  loop_core_t loop(backend_kind::epoll);
  epoll_test_turns_t counter;
  loop.add_hook(counter.hook);

  native_socket_t receiver = invalid_native_socket;
  REQUIRE(socket_open(AF_INET, SOCK_DGRAM, 0, receiver) == 0);
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  REQUIRE(socket_bind(receiver, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) == 0);
  sockaddr_storage target{};
  int target_length = sizeof(target);
  REQUIRE(socket_name(receiver, target, target_length) == 0);

  socket_resource_t sender(loop, "epoll test sender");
  REQUIRE(sender.open(AF_INET, SOCK_DGRAM, 0) == 0);

  constexpr int sends = 40;
  int sent = 0;
  std::int64_t first_turn = 0;
  std::int64_t last_turn = 0;
  epoll_test_alarm_t ticker;
  ticker.fire = [&] {
    CHECK(socket_sendto(sender.native(), epoll_test_bytes("x", 1), reinterpret_cast<const sockaddr *>(&target), target_length) == 1);
    ++sent;
    if (sent == 1)
      first_turn = counter.turns;
    if (sent == sends)
    {
      last_turn = counter.turns;
      epoll_test_close(sender);
      loop.stop();
      return;
    }
    ticker.arm(loop, 2 * epoll_test_millisecond);
  };
  ticker.arm(loop, 2 * epoll_test_millisecond);
  loop.run();
  loop.remove_hook(counter.hook);
  socket_close(receiver);

  const auto turns = last_turn - first_turn;
  MESSAGE("epoll: " << turns << " turns for " << (sends - 1) << " sends");
  CHECK(sent == sends);
  CHECK(turns < (sends - 1) * 3 / 2);
  CHECK(loop.open_resources() == 0);
}

TEST_CASE("epoll: write interest is dropped while no writer waits and restored when one parks")
{
  loop_core_t loop(backend_kind::epoll);
  int ends[2];
  REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, ends) == 0);
  REQUIRE(socket_set_nonblocking(ends[0]) == 0);
  REQUIRE(socket_set_nonblocking(ends[1]) == 0);
  int small = 4096;
  ::setsockopt(ends[0], SOL_SOCKET, SO_SNDBUF, &small, sizeof(small));
  ::setsockopt(ends[1], SOL_SOCKET, SO_RCVBUF, &small, sizeof(small));
  socket_resource_t writer_socket(loop, "epoll test writer");
  socket_resource_t reader_socket(loop, "epoll test reader");
  REQUIRE(writer_socket.adopt(ends[0]) == 0);
  REQUIRE(reader_socket.adopt(ends[1]) == 0);

  std::byte chunk[1024] = {};
  auto fill = [&] {
    for (;;)
    {
      auto sent = socket_send(writer_socket.native(), const_bytes_t(chunk, sizeof(chunk)));
      if (sent <= 0)
        return sent == errc::again;
    }
  };
  auto drain = [&] {
    std::byte buffer[4096];
    while (socket_recv(reader_socket.native(), buffer) > 0)
    {
    }
  };
  auto write_interest = [&] { return (writer_socket.watch.armed & interest_write) != 0; };

  epoll_test_op_t writer;
  epoll_test_alarm_t step;
  epoll_test_alarm_t bail;
  int phase = 0;
  int wakes = 0;
  bool armed_on_first_park = false;
  bool dropped_while_idle = false;
  bool restored_on_park = false;
  bool timed_out = false;
  auto finish = [&] {
    loop.remove_timer(bail.node);
    loop.remove_timer(step.node);
    writer_socket.cancel(writer);
    epoll_test_close(writer_socket);
    epoll_test_close(reader_socket);
    loop.stop();
  };
  writer.on_complete = [&](epoll_test_op_t &) {
    ++wakes;
    if (phase == 1)
    {
      phase = 2;
      step.arm(loop, 5 * epoll_test_millisecond);
    }
    else if (phase == 4)
    {
      finish();
    }
  };
  step.fire = [&] {
    switch (phase)
    {
    case 0:
      phase = 1;
      drain();
      return;
    case 2:
      phase = 3;
      CHECK(socket_send(writer_socket.native(), const_bytes_t(chunk, 1)) == 1);
      drain();
      step.arm(loop, 5 * epoll_test_millisecond);
      return;
    case 3:
      phase = 4;
      dropped_while_idle = !write_interest();
      CHECK(fill());
      writer_socket.wait(interest_write, writer);
      restored_on_park = write_interest();
      step.arm(loop, 5 * epoll_test_millisecond);
      return;
    default:
      drain();
      return;
    }
  };
  bail.fire = [&] {
    timed_out = true;
    finish();
  };
  bail.arm(loop, 5000 * epoll_test_millisecond);
  CHECK_FALSE(write_interest());
  REQUIRE(fill());
  writer_socket.wait(interest_write, writer);
  armed_on_first_park = write_interest();
  step.arm(loop, 5 * epoll_test_millisecond);
  loop.run();
  CHECK_FALSE(timed_out);
  CHECK(wakes == 2);
  CHECK(armed_on_first_park);
  CHECK(dropped_while_idle);
  CHECK(restored_on_park);
  CHECK(loop.open_resources() == 0);
}

#if !defined(VIO_EPOLL_TEST_UNDER_TSAN)
namespace
{
int epoll_test_wait_for_child(pid_t child, std::chrono::milliseconds limit)
{
  const auto give_up = std::chrono::steady_clock::now() + limit;
  int status = 0;
  for (;;)
  {
    pid_t done = ::waitpid(child, &status, WNOHANG);
    if (done == child)
      return status;
    if (done < 0 && errno != EINTR)
      return -1;
    if (std::chrono::steady_clock::now() > give_up)
    {
      ::kill(child, SIGKILL);
      ::waitpid(child, &status, 0);
      return -1;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
}

int epoll_test_refusing_registration()
{
  if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
    return 77;
  loop_core_t loop(backend_kind::epoll);
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  constexpr std::uint32_t operation = offsetof(seccomp_data, args) + sizeof(std::uint64_t) + sizeof(std::uint32_t);
#else
  constexpr std::uint32_t operation = offsetof(seccomp_data, args) + sizeof(std::uint64_t);
#endif
  sock_filter filter[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, nr)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_epoll_ctl, 0, 3),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, operation),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, EPOLL_CTL_ADD, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (ENOSPC & SECCOMP_RET_DATA)),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };
  sock_fprog program{static_cast<unsigned short>(std::size(filter)), filter};
  if (::prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program, 0, 0) != 0)
    return 77;

  socket_resource_t opened(loop, "epoll test opened");
  if (opened.open(AF_INET, SOCK_STREAM, 0) != errc_from_errno(ENOSPC))
    return 3;
  if (opened.is_open() || opened.native() != invalid_native_socket)
    return 4;

  int ends[2];
  if (::socketpair(AF_UNIX, SOCK_STREAM, 0, ends) != 0)
    return 5;
  socket_resource_t adopted(loop, "epoll test adopted");
  if (adopted.adopt(ends[0]) != errc_from_errno(ENOSPC))
    return 6;
  epoll_test_op_t writer;
  writer.on_complete = [](epoll_test_op_t &) {};
  adopted.wait(interest_write, writer);
  adopted.cancel(writer);
  epoll_test_close(opened);
  epoll_test_close(adopted);
  loop.stop();
  loop.run();
  ::close(ends[1]);
  return loop.open_resources() == 0 ? 0 : 7;
}
} // namespace

TEST_CASE("epoll: a socket whose registration is refused is left closed and a waiter on it never re-arms it")
{
  pid_t child = ::fork();
  REQUIRE(child >= 0);
  if (child == 0)
    ::_exit(epoll_test_refusing_registration());
  int status = epoll_test_wait_for_child(child, std::chrono::seconds(20));
  REQUIRE(status != -1);
  if (WIFEXITED(status) && WEXITSTATUS(status) == 77)
  {
    MESSAGE("seccomp filters are not available here; skipped");
    return;
  }
  CHECK(WIFEXITED(status));
  CHECK(WEXITSTATUS(status) == 0);
}

#if defined(SYS_epoll_pwait2)
namespace
{
int epoll_test_without_pwait2(int server_end, int client_end)
{
  if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
    return 77;
  sock_filter filter[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, nr)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_epoll_pwait2, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };
  sock_fprog program{static_cast<unsigned short>(std::size(filter)), filter};
  if (::prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program, 0, 0) != 0)
    return 77;
  if (::syscall(SYS_epoll_pwait2, -1, nullptr, 0, nullptr, nullptr, 0) != -1 || errno != EPERM)
    return 78;

  loop_core_t loop(backend_kind::epoll);
  epoll_test_turns_t counter;
  loop.add_hook(counter.hook);
  socket_resource_t server(loop, "epoll test server");
  socket_resource_t client(loop, "epoll test client");
  if (server.adopt(server_end) != 0 || client.adopt(client_end) != 0)
    return 3;

  epoll_test_op_t reader;
  epoll_test_alarm_t idle;
  epoll_test_alarm_t bail;
  bool received = false;
  std::int64_t idle_turns = -1;
  reader.on_complete = [&](epoll_test_op_t &op) {
    std::byte buffer[16];
    auto got = socket_recv(server.native(), buffer);
    if (got == errc::again)
    {
      server.wait(interest_read, op);
      return;
    }
    received = got == 4;
    loop.remove_timer(bail.node);
    epoll_test_close(server);
    epoll_test_close(client);
    loop.stop();
  };
  server.wait(interest_read, reader);
  const auto start = counter.turns;
  idle.fire = [&] {
    idle_turns = counter.turns - start;
    (void)socket_send(client.native(), epoll_test_bytes("ping", 4));
  };
  idle.arm(loop, 50 * epoll_test_millisecond);
  bail.fire = [] { ::_exit(2); };
  bail.arm(loop, 5000 * epoll_test_millisecond);
  loop.run();
  loop.remove_hook(counter.hook);
  if (!received)
    return 4;
  if (idle_turns < 0 || idle_turns > 10)
    return 5;
  return 0;
}
} // namespace

TEST_CASE("epoll: a sandbox that refuses epoll_pwait2 falls back to epoll_wait")
{
  int ends[2];
  REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, ends) == 0);
  REQUIRE(socket_set_nonblocking(ends[0]) == 0);
  REQUIRE(socket_set_nonblocking(ends[1]) == 0);
  pid_t child = ::fork();
  REQUIRE(child >= 0);
  if (child == 0)
    ::_exit(epoll_test_without_pwait2(ends[0], ends[1]));
  ::close(ends[0]);
  ::close(ends[1]);
  int status = epoll_test_wait_for_child(child, std::chrono::seconds(20));
  REQUIRE(status != -1);
  REQUIRE(WIFEXITED(status));
  if (WEXITSTATUS(status) == 77)
  {
    MESSAGE("seccomp filters are not available here; skipped");
    return;
  }
  CHECK(WEXITSTATUS(status) == 0);
}
#endif
#endif
} // namespace vio::detail
#endif

#endif
