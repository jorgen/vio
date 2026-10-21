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

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)

#include <cerrno>
#include <cstdint>
#include <ctime>
#include <memory>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <unistd.h>

#include "backends.h"
#include "vio/detail/sys.h"
#include "vio/loop/loop_core.h"

namespace vio::detail
{
namespace
{
using kevent_t = struct kevent;

constexpr int max_events = 128;
constexpr std::int64_t max_timeout_ns = std::int64_t{86400} * 1000000000;
constexpr timespec no_wait{};

#if defined(EV_RECEIPT)
constexpr unsigned receipt = EV_RECEIPT;
#else
constexpr unsigned receipt = 0;
#endif

void set_change(kevent_t &event, std::uintptr_t ident, int filter, unsigned flags, unsigned fflags, io_watch_t *watch) noexcept
{
  event = kevent_t{};
  event.ident = ident;
  event.filter = static_cast<decltype(event.filter)>(filter);
  event.flags = static_cast<decltype(event.flags)>(flags);
  event.fflags = static_cast<decltype(event.fflags)>(fflags);
  event.udata = reinterpret_cast<decltype(event.udata)>(watch);
}

io_watch_t *watch_of(const kevent_t &event) noexcept
{
  return reinterpret_cast<io_watch_t *>(event.udata);
}

void collect(const kevent_t &event, bool &readable, bool &writable) noexcept
{
  if ((event.flags & EV_ERROR) != 0)
  {
    if (event.data != 0)
    {
      readable = true;
      writable = true;
    }
    return;
  }
  if (event.filter == EVFILT_READ)
    readable = true;
  else if (event.filter == EVFILT_WRITE)
    writable = true;
  if ((event.flags & EV_EOF) != 0 && event.fflags != 0)
  {
    readable = true;
    writable = true;
  }
}

int set_cloexec(int fd) noexcept
{
  int flags = ::fcntl(fd, F_GETFD, 0);
  if (flags < 0 || ::fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0)
    return errno;
  return 0;
}

int set_nonblocking(int fd) noexcept
{
  int flags = ::fcntl(fd, F_GETFL, 0);
  if (flags < 0 || ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
    return errno;
  return 0;
}

class kqueue_backend_t final : public backend_t
{
public:
  kqueue_backend_t(loop_core_t &loop, int kqueue_fd, int wake_read, int wake_write) noexcept
    : backend_t(loop)
    , _kqueue_fd(kqueue_fd)
    , _wake_read(wake_read)
    , _wake_write(wake_write)
  {
  }

  ~kqueue_backend_t() override
  {
    if (_wake_read >= 0)
      ::close(_wake_read);
    if (_wake_write >= 0)
      ::close(_wake_write);
    if (_kqueue_fd >= 0)
      ::close(_kqueue_fd);
  }

  void abandon_after_fork() noexcept override
  {
    _kqueue_fd = -1;
  }

  [[nodiscard]] const char *name() const noexcept override
  {
    return "kqueue";
  }
  [[nodiscard]] std::intptr_t native_handle() const noexcept override
  {
    return _kqueue_fd;
  }

  [[nodiscard]] int add_watch(io_watch_t &watch) override
  {
    auto ident = static_cast<std::uintptr_t>(watch.socket);
    kevent_t changes[2];
    set_change(changes[0], ident, EVFILT_READ, EV_ADD | EV_CLEAR | receipt, 0, &watch);
    set_change(changes[1], ident, EVFILT_WRITE, EV_ADD | EV_CLEAR | receipt, 0, &watch);
    if (int error = apply(changes); error != 0)
    {
      remove_filters(ident);
      return errc_from_errno(error);
    }
    watch.closed = false;
    return 0;
  }

  void remove_watch(io_watch_t &watch, posted_t &done) override
  {
    if (!watch.closed)
    {
      remove_filters(static_cast<std::uintptr_t>(watch.socket));
      watch.closed = true;
    }
    _loop.defer(done);
  }

  void wake() noexcept override
  {
#if defined(EVFILT_USER) && defined(NOTE_TRIGGER)
    if (_wake_write < 0)
    {
      kevent_t event;
      set_change(event, 0, EVFILT_USER, 0, NOTE_TRIGGER, nullptr);
      while (::kevent(_kqueue_fd, &event, 1, nullptr, 0, &no_wait) < 0 && errno == EINTR)
      {
      }
      return;
    }
#endif
    char byte = 1;
    while (::write(_wake_write, &byte, 1) < 0 && errno == EINTR)
    {
    }
  }

  void poll(std::int64_t timeout_ns) override
  {
    kevent_t events[max_events];
    timespec timeout{};
    const timespec *timeout_pointer = nullptr;
    if (timeout_ns >= 0)
    {
      auto bounded = timeout_ns < max_timeout_ns ? timeout_ns : max_timeout_ns;
      bounded = (bounded + 999) / 1000 * 1000;
      timeout.tv_sec = static_cast<decltype(timeout.tv_sec)>(bounded / 1000000000);
      timeout.tv_nsec = static_cast<decltype(timeout.tv_nsec)>(bounded % 1000000000);
      timeout_pointer = &timeout;
    }
    int count = ::kevent(_kqueue_fd, nullptr, 0, events, max_events, timeout_pointer);
    struct interrupted_t
    {
      kqueue_backend_t &backend;
      const kevent_t *events;
      int count;
      int next = 0;
      ~interrupted_t()
      {
        for (; next < count; ++next)
        {
          auto *watch = watch_of(events[next]);
          if (!watch)
            continue;
          bool readable = false;
          bool writable = false;
          collect(events[next], readable, writable);
          backend.retry_later(*watch, readable, writable);
        }
      }
    } batch{*this, events, count};
    while (batch.next < count)
    {
      const auto &event = events[batch.next++];
      auto *watch = watch_of(event);
      if (!watch)
      {
        drain_wake();
        continue;
      }
      bool readable = false;
      bool writable = false;
      collect(event, readable, writable);
      while (batch.next < count && watch_of(events[batch.next]) == watch)
        collect(events[batch.next++], readable, writable);
      if (readable || writable)
        dispatch(*watch, readable, writable);
    }
  }

  [[nodiscard]] int queue() const noexcept
  {
    return _kqueue_fd;
  }

private:
  int apply(kevent_t (&changes)[2]) noexcept
  {
#if defined(EV_RECEIPT)
    kevent_t results[2];
    int received;
    do
      received = ::kevent(_kqueue_fd, changes, 2, results, 2, &no_wait);
    while (received < 0 && errno == EINTR);
    if (received < 0)
      return errno;
    for (int i = 0; i < received; ++i)
    {
      if ((results[i].flags & EV_ERROR) != 0 && results[i].data != 0)
        return static_cast<int>(results[i].data);
    }
    return 0;
#else
    int first = 0;
    for (auto &change : changes)
    {
      int result;
      do
        result = ::kevent(_kqueue_fd, &change, 1, nullptr, 0, &no_wait);
      while (result < 0 && errno == EINTR);
      if (result < 0 && first == 0)
        first = errno;
    }
    return first;
#endif
  }

  void remove_filters(std::uintptr_t ident) noexcept
  {
    kevent_t changes[2];
    set_change(changes[0], ident, EVFILT_READ, EV_DELETE | receipt, 0, nullptr);
    set_change(changes[1], ident, EVFILT_WRITE, EV_DELETE | receipt, 0, nullptr);
    (void)apply(changes);
  }

  void drain_wake() noexcept
  {
    if (_wake_read < 0)
      return;
    char buffer[64];
    for (;;)
    {
      auto got = ::read(_wake_read, buffer, sizeof(buffer));
      if (got > 0 || (got < 0 && errno == EINTR))
        continue;
      return;
    }
  }

  int _kqueue_fd;
  int _wake_read;
  int _wake_write;
};

int make_wake_pipe(int kqueue_fd, int (&fds)[2]) noexcept
{
  if (::pipe(fds) != 0)
    return errno;
  int failure = 0;
  for (int fd : fds)
  {
    if (failure == 0)
      failure = set_cloexec(fd);
    if (failure == 0)
      failure = set_nonblocking(fd);
  }
  if (failure == 0)
  {
    kevent_t event;
    set_change(event, static_cast<std::uintptr_t>(fds[0]), EVFILT_READ, EV_ADD | EV_CLEAR, 0, nullptr);
    if (::kevent(kqueue_fd, &event, 1, nullptr, 0, &no_wait) < 0)
      failure = errno;
  }
  if (failure != 0)
  {
    ::close(fds[0]);
    ::close(fds[1]);
  }
  return failure;
}
} // namespace

std::unique_ptr<backend_t> make_kqueue_backend(loop_core_t &loop, int &error)
{
  int kqueue_fd = ::kqueue();
  if (kqueue_fd < 0)
  {
    error = errc_from_errno(errno);
    return nullptr;
  }
  if (int failure = set_cloexec(kqueue_fd); failure != 0)
  {
    error = errc_from_errno(failure);
    ::close(kqueue_fd);
    return nullptr;
  }
#if defined(EVFILT_USER) && defined(NOTE_TRIGGER)
  kevent_t event;
  set_change(event, 0, EVFILT_USER, EV_ADD | EV_CLEAR, 0, nullptr);
  int registered;
  do
    registered = ::kevent(kqueue_fd, &event, 1, nullptr, 0, &no_wait);
  while (registered < 0 && errno == EINTR);
  if (registered == 0)
    return std::make_unique<kqueue_backend_t>(loop, kqueue_fd, -1, -1);
#endif
  int fds[2] = {-1, -1};
  if (int failure = make_wake_pipe(kqueue_fd, fds); failure != 0)
  {
    error = errc_from_errno(failure);
    ::close(kqueue_fd);
    return nullptr;
  }
  return std::make_unique<kqueue_backend_t>(loop, kqueue_fd, fds[0], fds[1]);
}
} // namespace vio::detail

#if defined(VIO_INTERNAL_TESTS)
#include <doctest/doctest.h>

#include <climits>
#include <string>

#include <sys/wait.h>

#include "vio/errc.h"
#include "vio/loop/socket.h"

namespace vio::detail
{
namespace
{
constexpr std::int64_t kqueue_test_deadline_ns = std::int64_t{10} * 1000000000;

socket_resource_t *adopt_test_socket(loop_core_t &loop, int fd)
{
  CHECK(socket_set_nonblocking(fd) == 0);
  auto *resource = new socket_resource_t(loop, "kqueue test socket");
  CHECK(resource->adopt(fd) == 0);
  return resource;
}

void release_parked(socket_resource_t &resource) noexcept
{
  while (auto *op = resource.watch.readers.front())
    resource.cancel(*op);
  while (auto *op = resource.watch.writers.front())
    resource.cancel(*op);
}

void close_test_socket(socket_resource_t *&resource)
{
  if (!resource)
    return;
  resource->close(
    [](void *raw) {
      auto *closed = static_cast<socket_resource_t *>(raw);
      release_parked(*closed);
      delete closed;
    },
    resource);
  resource = nullptr;
}

std::int64_t send_byte(socket_resource_t *resource, unsigned char value)
{
  std::byte byte{value};
  return socket_send(resource->native(), const_bytes_t(&byte, 1));
}

std::int64_t receive_some(socket_resource_t *resource)
{
  std::byte buffer[64];
  return socket_recv(resource->native(), buffer);
}

struct kqueue_fixture_t
{
  loop_core_t loop{backend_kind::kqueue};
  socket_resource_t *sockets[6] = {};
  timer_node_t watchdog;
  posted_t start;
  bool timed_out = false;

  explicit kqueue_fixture_t(std::int64_t deadline_ns = kqueue_test_deadline_ns)
  {
    watchdog.owner = this;
    watchdog.keeps_alive = false;
    watchdog.fire = [](timer_node_t *node) {
      auto &self = *static_cast<kqueue_fixture_t *>(node->owner);
      self.timed_out = true;
      self.finish();
    };
    loop.add_timer(watchdog, loop_core_t::now() + deadline_ns);
  }

  kqueue_fixture_t(const kqueue_fixture_t &) = delete;
  kqueue_fixture_t &operator=(const kqueue_fixture_t &) = delete;

  ~kqueue_fixture_t()
  {
    loop.remove_timer(watchdog);
    for (auto *socket : sockets)
    {
      if (!socket)
        continue;
      finish();
      loop.run();
      return;
    }
  }

  bool adopt_pair(int first, int second)
  {
    int fds[2] = {-1, -1};
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
      return false;
    sockets[first] = adopt_test_socket(loop, fds[0]);
    sockets[second] = adopt_test_socket(loop, fds[1]);
    return true;
  }

  void prepare(io_op_t &op, void *owner, io_op_t::complete_fn_t complete)
  {
    op.owner = owner;
    op.complete = complete;
    op.keeps_alive = false;
  }

  void start_and_run(void *owner, posted_t::run_fn_t first)
  {
    start.owner = owner;
    start.run = first;
    loop.post(start);
    loop.run();
  }

  void run(void *owner, posted_t::run_fn_t first)
  {
    start_and_run(owner, first);
    CHECK_FALSE(timed_out);
    CHECK(loop.open_resources() == 0);
  }

  void finish()
  {
    loop.remove_timer(watchdog);
    for (auto *&socket : sockets)
      close_test_socket(socket);
    loop.stop();
  }
};
} // namespace

TEST_CASE("kqueue backend: a parked reader wakes on every new edge")
{
  struct context_t : kqueue_fixture_t
  {
    io_op_t reader;
    int edges = 0;
    std::int64_t received = 0;
  } context;
  CHECK(std::string(context.loop.backend_name()) == "kqueue");
  REQUIRE(context.adopt_pair(0, 1));
  context.prepare(context.reader, &context, [](io_op_t *op) {
    auto &self = *static_cast<context_t *>(op->owner);
    auto got = receive_some(self.sockets[0]);
    if (got == errc::again)
    {
      self.sockets[0]->wait(interest_read, *op);
      return;
    }
    CHECK(got == 1);
    if (got > 0)
      self.received += got;
    if (++self.edges == 1 && got == 1)
    {
      CHECK(receive_some(self.sockets[0]) == errc::again);
      self.sockets[0]->wait(interest_read, *op);
      CHECK(send_byte(self.sockets[1], 2) == 1);
      return;
    }
    self.finish();
  });
  context.run(&context, [](posted_t *node) {
    auto &self = *static_cast<context_t *>(node->owner);
    CHECK(receive_some(self.sockets[0]) == errc::again);
    self.sockets[0]->wait(interest_read, self.reader);
    CHECK(send_byte(self.sockets[1], 1) == 1);
  });
  CHECK(context.edges == 2);
  CHECK(context.received == 2);
}

TEST_CASE("kqueue backend: a writer parked on a full socket wakes when the peer drains it")
{
  struct context_t : kqueue_fixture_t
  {
    io_op_t writer;
    posted_t drain;
    std::int64_t filled = 0;
    std::int64_t drained = 0;
    bool wrote = false;
  } context;
  REQUIRE(context.adopt_pair(0, 1));
  context.prepare(context.writer, &context, [](io_op_t *op) {
    auto &self = *static_cast<context_t *>(op->owner);
    auto sent = send_byte(self.sockets[0], 7);
    if (sent == errc::again)
    {
      self.sockets[0]->wait(interest_write, *op);
      return;
    }
    CHECK(sent == 1);
    self.wrote = sent == 1;
    self.finish();
  });
  context.drain.owner = &context;
  context.drain.run = [](posted_t *node) {
    auto &self = *static_cast<context_t *>(node->owner);
    std::byte buffer[4096];
    std::int64_t got = 0;
    while ((got = socket_recv(self.sockets[1]->native(), buffer)) > 0)
      self.drained += got;
    CHECK(got == errc::again);
  };
  context.run(&context, [](posted_t *node) {
    auto &self = *static_cast<context_t *>(node->owner);
    std::byte chunk[4096] = {};
    std::int64_t sent = 0;
    for (int i = 0; i < 1 << 16; ++i)
    {
      sent = socket_send(self.sockets[0]->native(), chunk);
      if (sent <= 0)
        break;
      self.filled += sent;
    }
    CHECK(sent == errc::again);
    CHECK(self.filled > 0);
    self.sockets[0]->wait(interest_write, self.writer);
    self.loop.post(self.drain);
  });
  CHECK(context.wrote);
  CHECK(context.drained == context.filled);
}

TEST_CASE("kqueue backend: a peer that closes wakes a parked reader with end of file")
{
  struct context_t : kqueue_fixture_t
  {
    io_op_t reader;
    std::int64_t outcome = 1;
  } context;
  REQUIRE(context.adopt_pair(0, 1));
  context.prepare(context.reader, &context, [](io_op_t *op) {
    auto &self = *static_cast<context_t *>(op->owner);
    auto got = receive_some(self.sockets[0]);
    if (got == errc::again)
    {
      self.sockets[0]->wait(interest_read, *op);
      return;
    }
    self.outcome = got;
    self.finish();
  });
  context.run(&context, [](posted_t *node) {
    auto &self = *static_cast<context_t *>(node->owner);
    CHECK(receive_some(self.sockets[0]) == errc::again);
    self.sockets[0]->wait(interest_read, self.reader);
    close_test_socket(self.sockets[1]);
  });
  CHECK(context.outcome == 0);
}

TEST_CASE("kqueue backend: a socket closed earlier in the same batch is not dispatched")
{
  struct context_t : kqueue_fixture_t
  {
    io_op_t readers[2];
    int completions[2] = {};
  } context;
  REQUIRE(context.adopt_pair(0, 1));
  REQUIRE(context.adopt_pair(2, 3));
  auto complete = [](io_op_t *op) {
    auto &self = *static_cast<context_t *>(op->owner);
    int index = op == &self.readers[0] ? 0 : 1;
    ++self.completions[index];
    close_test_socket(self.sockets[(1 - index) * 2]);
    self.finish();
  };
  context.prepare(context.readers[0], &context, complete);
  context.prepare(context.readers[1], &context, complete);
  context.run(&context, [](posted_t *node) {
    auto &self = *static_cast<context_t *>(node->owner);
    for (int index = 0; index < 2; ++index)
    {
      CHECK(receive_some(self.sockets[index * 2]) == errc::again);
      self.sockets[index * 2]->wait(interest_read, self.readers[index]);
    }
    CHECK(send_byte(self.sockets[1], 1) == 1);
    CHECK(send_byte(self.sockets[3], 1) == 1);
  });
  CHECK(context.completions[0] + context.completions[1] == 1);
}

TEST_CASE("kqueue backend: a test that outlives its deadline ends with its operations released")
{
  struct context_t : kqueue_fixture_t
  {
    context_t()
      : kqueue_fixture_t(std::int64_t{100} * 1000000)
    {
    }
    io_op_t reader;
    io_op_t writer;
  } context;
  REQUIRE(context.adopt_pair(0, 1));
  context.prepare(context.reader, &context, [](io_op_t *) {});
  context.prepare(context.writer, &context, [](io_op_t *) {});
  context.start_and_run(&context, [](posted_t *node) {
    auto &self = *static_cast<context_t *>(node->owner);
    CHECK(receive_some(self.sockets[0]) == errc::again);
    self.sockets[0]->wait(interest_read, self.reader);
    std::byte chunk[4096] = {};
    for (int i = 0; i < 1 << 16 && socket_send(self.sockets[0]->native(), chunk) > 0; ++i)
    {
    }
    self.sockets[0]->wait(interest_write, self.writer);
  });
  CHECK(context.timed_out);
  CHECK_FALSE(context.reader.parked);
  CHECK_FALSE(context.writer.parked);
  CHECK(context.loop.open_resources() == 0);
}

TEST_CASE("kqueue backend: registering and removing watches does not swallow pending readiness")
{
  struct context_t : kqueue_fixture_t
  {
    io_op_t reader;
    posted_t stage;
    bool woke = false;
  } context;
  REQUIRE(context.adopt_pair(0, 1));
  context.prepare(context.reader, &context, [](io_op_t *op) {
    auto &self = *static_cast<context_t *>(op->owner);
    auto got = receive_some(self.sockets[0]);
    if (got == errc::again)
    {
      self.sockets[0]->wait(interest_read, *op);
      return;
    }
    CHECK(got == 1);
    self.woke = got == 1;
    self.finish();
  });
  context.stage.owner = &context;
  context.stage.run = [](posted_t *node) {
    auto &self = *static_cast<context_t *>(node->owner);
    CHECK(receive_some(self.sockets[0]) == errc::again);
    self.sockets[0]->wait(interest_read, self.reader);
    CHECK(send_byte(self.sockets[1], 1) == 1);
    CHECK(self.adopt_pair(2, 3));
    CHECK(self.adopt_pair(4, 5));
    close_test_socket(self.sockets[4]);
  };
  context.run(&context, [](posted_t *node) {
    auto &self = *static_cast<context_t *>(node->owner);
    self.loop.post(self.stage);
  });
  CHECK(context.woke);
}

TEST_CASE("kqueue backend: a refused connect wakes the parked connect with the error")
{
  struct context_t : kqueue_fixture_t
  {
    io_op_t writer;
    sockaddr_in address{};
    int outcome = 0;
  } context;

  int probe = ::socket(AF_INET, SOCK_STREAM, 0);
  REQUIRE(probe >= 0);
  context.address.sin_family = AF_INET;
  context.address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  socklen_t length = sizeof(context.address);
  bool bound = ::bind(probe, reinterpret_cast<sockaddr *>(&context.address), length) == 0 &&
               ::getsockname(probe, reinterpret_cast<sockaddr *>(&context.address), &length) == 0;
  ::close(probe);
  REQUIRE(bound);

  auto *client = new socket_resource_t(context.loop, "kqueue test socket");
  context.sockets[0] = client;
  CHECK(client->open(AF_INET, SOCK_STREAM, 0) == 0);
  context.prepare(context.writer, &context, [](io_op_t *op) {
    auto &self = *static_cast<context_t *>(op->owner);
    int pending = socket_pending_error(self.sockets[0]->native());
    if (pending == 0)
    {
      sockaddr_storage peer{};
      int peer_length = 0;
      pending = socket_peer_name(self.sockets[0]->native(), peer, peer_length);
    }
    self.outcome = pending;
    self.finish();
  });
  context.run(&context, [](posted_t *node) {
    auto &self = *static_cast<context_t *>(node->owner);
    int result = socket_connect(self.sockets[0]->native(), reinterpret_cast<const sockaddr *>(&self.address), static_cast<int>(sizeof(self.address)));
    if (result == errc::in_progress)
    {
      self.sockets[0]->wait(interest_write, self.writer);
      return;
    }
    self.outcome = result;
    self.finish();
  });
  CHECK(context.outcome == errc::connection_refused);
}

TEST_CASE("kqueue backend: registering a descriptor that is not open fails and leaves nothing behind")
{
  loop_core_t loop(backend_kind::kqueue);
  auto *resource = new socket_resource_t(loop, "kqueue test socket");
  CHECK(resource->adopt(INT_MAX - 1) == errc::bad_descriptor);
  close_test_socket(resource);
  loop.stop();
  loop.run();
  CHECK(loop.open_resources() == 0);
}

TEST_CASE("kqueue backend: destroying a loop inherited across fork() leaves alone the descriptor the child reused")
{
  auto *loop = new loop_core_t(backend_kind::kqueue);
  const int queue = static_cast<kqueue_backend_t &>(loop->backend()).queue();
  REQUIRE(queue >= 0);
  pid_t child = ::fork();
  REQUIRE(child >= 0);
  if (child == 0)
  {
    int file = ::open("/dev/null", O_RDONLY);
    if (file < 0)
      ::_exit(3);
    if (file != queue && ::dup2(file, queue) != queue)
      ::_exit(4);
    delete loop;
    ::_exit(::fcntl(queue, F_GETFD) != -1 ? 0 : 1);
  }
  int status = 0;
  while (::waitpid(child, &status, 0) < 0 && errno == EINTR)
  {
  }
  CHECK(WIFEXITED(status));
  CHECK(WEXITSTATUS(status) == 0);
  delete loop;
}
} // namespace vio::detail
#endif

#endif
