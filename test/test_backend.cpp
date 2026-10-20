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

#include <doctest/doctest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <future>
#include <memory>
#include <span>
#include <string>
#include <thread>
#include <vector>

#include <vio/event_loop.h>
#include <vio/loop/socket.h>

#if !defined(_WIN32)
#include <cstdlib>
#include <unistd.h>
#endif

using namespace std::chrono_literals;

namespace
{
namespace detail = vio::detail;

struct probe_op_t : detail::io_op_t
{
  int completions = 0;
  std::function<void(probe_op_t &)> on_complete;

  probe_op_t()
  {
    owner = this;
    complete = [](detail::io_op_t *op) {
      auto *self = static_cast<probe_op_t *>(op->owner);
      ++self->completions;
      if (self->on_complete)
        self->on_complete(*self);
    };
  }
};

class harness_t;

struct test_socket_t
{
  explicit test_socket_t(harness_t &harness);
  test_socket_t(const test_socket_t &) = delete;
  test_socket_t &operator=(const test_socket_t &) = delete;
  ~test_socket_t();

  void close()
  {
    resource.close(
      [](void *raw) {
        auto *self = static_cast<test_socket_t *>(raw);
        self->closed = true;
        auto callback = std::move(self->on_closed);
        if (callback)
          callback();
      },
      this);
  }

  void release() noexcept
  {
    while (auto *op = resource.watch.readers.front())
      resource.cancel(*op);
    while (auto *op = resource.watch.writers.front())
      resource.cancel(*op);
    on_closed = nullptr;
    if (!resource.closing())
      close();
  }

  [[nodiscard]] vio::native_socket_t native() const
  {
    return resource.native();
  }

  harness_t &harness;
  detail::socket_resource_t resource;
  bool closed = false;
  std::function<void()> on_closed;
};

struct turn_counter_t
{
  detail::hook_t hook;
  std::int64_t turns = 0;

  turn_counter_t()
  {
    hook.owner = this;
    hook.run = [](detail::hook_t *raw) { ++static_cast<turn_counter_t *>(raw->owner)->turns; };
  }
};

struct alarm_t
{
  explicit alarm_t(harness_t &harness);
  alarm_t(const alarm_t &) = delete;
  alarm_t &operator=(const alarm_t &) = delete;
  ~alarm_t();

  void arm(std::chrono::nanoseconds delay, std::function<void()> callback);

  harness_t &harness;
  detail::timer_node_t node;
  std::function<void()> fire;
};

class harness_t
{
public:
  explicit harness_t(vio::event_loop_t &loop, std::chrono::nanoseconds deadline = 60s)
    : core(detail::core(loop))
    , _loop(loop)
    , _deadline(deadline)
  {
    _watchdog.owner = this;
    _watchdog.keeps_alive = false;
    _watchdog.fire = [](detail::timer_node_t *raw) { static_cast<harness_t *>(raw->owner)->expire(); };
  }
  harness_t(const harness_t &) = delete;
  harness_t &operator=(const harness_t &) = delete;
  ~harness_t()
  {
    core.remove_timer(_watchdog);
  }

  bool run()
  {
    core.add_timer(_watchdog, detail::loop_core_t::now() + _deadline.count());
    try
    {
      _loop.run();
    }
    catch (...)
    {
      abandon();
      throw;
    }
    core.remove_timer(_watchdog);
    return !_timed_out;
  }

  void abandon() noexcept
  {
    _abandoning = true;
    _loop.stop();
    for (int round = 0; round < 100; ++round)
    {
      try
      {
        release();
        core.add_timer(_watchdog, detail::loop_core_t::now() + sweep_interval.count());
        _loop.run();
        release();
        break;
      }
      catch (...)
      {
      }
    }
    core.remove_timer(_watchdog);
  }

  [[nodiscard]] bool timed_out() const noexcept
  {
    return _timed_out;
  }

  void enroll(test_socket_t &socket)
  {
    _sockets.push_back(&socket);
  }
  void withdraw(test_socket_t &socket) noexcept
  {
    _sockets.erase(std::remove(_sockets.begin(), _sockets.end(), &socket), _sockets.end());
  }
  void enroll(alarm_t &alarm)
  {
    _alarms.push_back(&alarm);
  }
  void withdraw(alarm_t &alarm) noexcept
  {
    _alarms.erase(std::remove(_alarms.begin(), _alarms.end(), &alarm), _alarms.end());
  }

  detail::loop_core_t &core;

private:
  static constexpr std::chrono::nanoseconds sweep_interval = 10ms;

  void release() noexcept
  {
    for (auto *alarm : _alarms)
      core.remove_timer(alarm->node);
    for (auto *socket : _sockets)
      socket->release();
  }

  void expire()
  {
    if (!_abandoning)
      _timed_out = true;
    release();
    _loop.stop();
    core.add_timer(_watchdog, detail::loop_core_t::now() + sweep_interval.count());
  }

  vio::event_loop_t &_loop;
  std::chrono::nanoseconds _deadline;
  detail::timer_node_t _watchdog;
  std::vector<test_socket_t *> _sockets;
  std::vector<alarm_t *> _alarms;
  bool _timed_out = false;
  bool _abandoning = false;
};

test_socket_t::test_socket_t(harness_t &harness)
  : harness(harness)
  , resource(harness.core)
{
  harness.enroll(*this);
}

test_socket_t::~test_socket_t()
{
  harness.withdraw(*this);
  if (resource.closing())
    return;
  release();
  harness.abandon();
}

alarm_t::alarm_t(harness_t &harness)
  : harness(harness)
{
  node.owner = this;
  node.fire = [](detail::timer_node_t *raw) { static_cast<alarm_t *>(raw->owner)->fire(); };
  harness.enroll(*this);
}

alarm_t::~alarm_t()
{
  harness.core.remove_timer(node);
  harness.withdraw(*this);
}

void alarm_t::arm(std::chrono::nanoseconds delay, std::function<void()> callback)
{
  fire = std::move(callback);
  harness.core.add_timer(node, detail::loop_core_t::now() + delay.count());
}

struct tcp_pair_t
{
  vio::native_socket_t client = vio::invalid_native_socket;
  vio::native_socket_t server = vio::invalid_native_socket;
};

void set_buffer_sizes(vio::native_socket_t socket, int size)
{
  detail::socket_set_option(socket, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));
  detail::socket_set_option(socket, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
}

tcp_pair_t make_tcp_pair()
{
  vio::native_socket_t listener = vio::invalid_native_socket;
  REQUIRE(detail::socket_open(AF_INET, SOCK_STREAM, 0, listener) == 0);
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = 0;
  REQUIRE(detail::socket_bind(listener, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) == 0);
  REQUIRE(detail::socket_listen(listener, 16) == 0);
  sockaddr_storage bound{};
  int bound_length = sizeof(bound);
  REQUIRE(detail::socket_name(listener, bound, bound_length) == 0);

  tcp_pair_t pair;
  REQUIRE(detail::socket_open(AF_INET, SOCK_STREAM, 0, pair.client) == 0);
  int connected = detail::socket_connect(pair.client, reinterpret_cast<const sockaddr *>(&bound), bound_length);
  REQUIRE((connected == 0 || connected == vio::errc::in_progress || connected == vio::errc::again));
  const auto give_up = std::chrono::steady_clock::now() + 5s;
  for (;;)
  {
    int accepted = detail::socket_accept(listener, pair.server, nullptr, nullptr);
    if (accepted == 0)
      break;
    REQUIRE(accepted == vio::errc::again);
    REQUIRE(std::chrono::steady_clock::now() < give_up);
    std::this_thread::sleep_for(1ms);
  }
  for (;;)
  {
    sockaddr_storage peer{};
    int peer_length = sizeof(peer);
    if (detail::socket_peer_name(pair.client, peer, peer_length) == 0)
      break;
    REQUIRE(std::chrono::steady_clock::now() < give_up);
    std::this_thread::sleep_for(1ms);
  }
  detail::socket_close(listener);
  return pair;
}

std::span<const std::byte> bytes(const char *text)
{
  return {reinterpret_cast<const std::byte *>(text), std::strlen(text)};
}

std::int64_t drain(vio::native_socket_t socket)
{
  std::int64_t total = 0;
  std::byte buffer[16384];
  for (;;)
  {
    auto got = detail::socket_recv(socket, buffer);
    if (got <= 0)
      return got == vio::errc::again || got == 0 ? total : got;
    total += got;
  }
}

std::int64_t fill(vio::native_socket_t socket)
{
  std::int64_t total = 0;
  std::vector<std::byte> chunk(16384, std::byte{0x5a});
  for (std::size_t size = chunk.size(); size > 0;)
  {
    auto sent = detail::socket_send(socket, std::span<const std::byte>(chunk).first(size));
    if (sent == vio::errc::again)
    {
      size /= 2;
      continue;
    }
    REQUIRE(sent > 0);
    total += sent;
  }
  return total;
}

bool would_block_reading(vio::native_socket_t socket)
{
  std::byte buffer[1];
  return detail::socket_recv(socket, buffer) == vio::errc::again;
}
} // namespace

TEST_CASE("backend: a parked reader wakes when the peer writes")
{
  vio::event_loop_t loop;
  auto &core = detail::core(loop);
  harness_t harness(loop);
  MESSAGE("backend: " << std::string(loop.backend_name()));
  auto pair = make_tcp_pair();
  test_socket_t server(harness);
  test_socket_t client(harness);
  REQUIRE(server.resource.adopt(pair.server) == 0);
  REQUIRE(client.resource.adopt(pair.client) == 0);

  probe_op_t reader;
  std::string received;
  reader.on_complete = [&](probe_op_t &op) {
    std::byte buffer[64];
    auto got = detail::socket_recv(server.native(), buffer);
    if (got == vio::errc::again)
    {
      server.resource.wait(detail::interest_read, op);
      return;
    }
    REQUIRE(got > 0);
    received.assign(reinterpret_cast<const char *>(buffer), static_cast<std::size_t>(got));
    server.close();
    client.close();
    loop.stop();
  };
  loop.run_in_loop([&] {
    REQUIRE(would_block_reading(server.native()));
    server.resource.wait(detail::interest_read, reader);
    CHECK(reader.parked);
    CHECK(core.in_flight() == 1);
    loop.run_in_loop([&] { CHECK(detail::socket_send(client.native(), bytes("ping")) == 4); });
  });
  CHECK(harness.run());
  CHECK(received == "ping");
  CHECK(reader.completions >= 1);
  CHECK(server.closed);
  CHECK(client.closed);
  CHECK(core.in_flight() == 0);
  CHECK(core.open_resources() == 0);
}

TEST_CASE("backend: a parked writer wakes when the peer drains")
{
  vio::event_loop_t loop;
  auto &core = detail::core(loop);
  harness_t harness(loop);
  auto pair = make_tcp_pair();
  set_buffer_sizes(pair.client, 8192);
  set_buffer_sizes(pair.server, 8192);
  test_socket_t server(harness);
  test_socket_t client(harness);
  REQUIRE(server.resource.adopt(pair.server) == 0);
  REQUIRE(client.resource.adopt(pair.client) == 0);

  probe_op_t writer;
  probe_op_t drainer;
  std::int64_t filled = 0;
  std::int64_t drained = 0;
  bool wrote_after_wake = false;
  std::function<void()> drain_some = [&] {
    auto got = drain(server.native());
    REQUIRE(got >= 0);
    drained += got;
    server.resource.wait(detail::interest_read, drainer);
  };
  drainer.on_complete = [&](probe_op_t &) { drain_some(); };
  writer.on_complete = [&](probe_op_t &op) {
    std::byte one[1] = {std::byte{1}};
    auto sent = detail::socket_send(client.native(), one);
    if (sent == vio::errc::again)
    {
      client.resource.wait(detail::interest_write, op);
      return;
    }
    REQUIRE(sent == 1);
    if (drained == 0)
    {
      fill(client.native());
      client.resource.wait(detail::interest_write, op);
      return;
    }
    wrote_after_wake = true;
    server.resource.cancel(drainer);
    server.close();
    client.close();
    loop.stop();
  };
  loop.run_in_loop([&] {
    filled = fill(client.native());
    REQUIRE(filled > 0);
    client.resource.wait(detail::interest_write, writer);
    CHECK(writer.parked);
    loop.run_in_loop([&] { drain_some(); });
  });
  CHECK(harness.run());
  CHECK(wrote_after_wake);
  CHECK(drained > 0);
  CHECK_FALSE(drainer.parked);
  CHECK(core.in_flight() == 0);
  CHECK(core.open_resources() == 0);
}

TEST_CASE("backend: cancel_wait detaches a parked op at once and it never completes")
{
  vio::event_loop_t loop;
  auto &core = detail::core(loop);
  harness_t harness(loop);
  auto pair = make_tcp_pair();
  test_socket_t server(harness);
  test_socket_t client(harness);
  REQUIRE(server.resource.adopt(pair.server) == 0);
  REQUIRE(client.resource.adopt(pair.client) == 0);

  probe_op_t reader;
  alarm_t alarm(harness);
  bool data_still_there = false;
  loop.run_in_loop([&] {
    REQUIRE(would_block_reading(server.native()));
    auto before = core.in_flight();
    server.resource.wait(detail::interest_read, reader);
    CHECK(core.in_flight() == before + 1);
    loop.run_in_loop([&] {
      auto before_cancel = core.in_flight();
      server.resource.cancel(reader);
      CHECK_FALSE(reader.parked);
      CHECK(core.in_flight() == before_cancel - 1);
      CHECK(detail::socket_send(client.native(), bytes("late")) == 4);
      alarm.arm(30ms, [&] {
        std::byte buffer[16];
        data_still_there = detail::socket_recv(server.native(), buffer) == 4;
        server.close();
        client.close();
        loop.stop();
      });
    });
  });
  CHECK(harness.run());
  CHECK(reader.completions == 0);
  CHECK(data_still_there);
  CHECK(core.in_flight() == 0);
}

TEST_CASE("backend: two ops parked on one interest both wake")
{
  vio::event_loop_t loop;
  auto &core = detail::core(loop);
  harness_t harness(loop);
  auto pair = make_tcp_pair();
  test_socket_t server(harness);
  test_socket_t client(harness);
  REQUIRE(server.resource.adopt(pair.server) == 0);
  REQUIRE(client.resource.adopt(pair.client) == 0);

  probe_op_t first;
  probe_op_t second;
  auto finish = [&] {
    if (first.completions == 0 || second.completions == 0)
      return;
    drain(server.native());
    server.close();
    client.close();
    loop.stop();
  };
  first.on_complete = [&](probe_op_t &) { finish(); };
  second.on_complete = [&](probe_op_t &) { finish(); };
  loop.run_in_loop([&] {
    REQUIRE(would_block_reading(server.native()));
    server.resource.wait(detail::interest_read, first);
    server.resource.wait(detail::interest_read, second);
    loop.run_in_loop([&] { CHECK(detail::socket_send(client.native(), bytes("x")) == 1); });
  });
  CHECK(harness.run());
  CHECK(first.completions == 1);
  CHECK(second.completions == 1);
  CHECK(core.in_flight() == 0);
}

TEST_CASE("backend: a wake from another thread ends a blocking wait")
{
  vio::event_loop_t loop;
  std::thread poster([&] {
    std::this_thread::sleep_for(50ms);
    loop.run_in_loop([&] { loop.stop(); });
  });
  const auto start = std::chrono::steady_clock::now();
  loop.run();
  const auto elapsed = std::chrono::steady_clock::now() - start;
  poster.join();
  CHECK(elapsed >= 45ms);
  CHECK(elapsed < 5s);
}

TEST_CASE("backend: wake latency from another thread")
{
  vio::thread_with_event_loop_t thread;
  auto &loop = thread.event_loop();
  constexpr int rounds = 300;
  std::vector<std::int64_t> latencies;
  latencies.reserve(rounds);
  for (int i = 0; i < rounds; ++i)
  {
    std::this_thread::sleep_for(200us);
    std::promise<std::int64_t> woke;
    auto future = woke.get_future();
    const auto sent = detail::loop_core_t::now();
    loop.run_in_loop([&woke] { woke.set_value(detail::loop_core_t::now()); });
    latencies.push_back(future.get() - sent);
  }
  thread.stop_and_join();
  std::sort(latencies.begin(), latencies.end());
  const auto median = latencies[latencies.size() / 2];
  const auto p99 = latencies[latencies.size() * 99 / 100];
  MESSAGE(std::string(loop.backend_name()) << " wake latency: median " << median / 1000 << " us, p99 " << p99 / 1000 << " us");
  CHECK(median < 50'000'000);
}

TEST_CASE("backend: closing a watch with a parked op neither completes the op nor finishes under it")
{
  vio::event_loop_t loop;
  auto &core = detail::core(loop);
  harness_t harness(loop);
  auto pair = make_tcp_pair();
  test_socket_t server(harness);
  test_socket_t client(harness);
  REQUIRE(server.resource.adopt(pair.server) == 0);
  REQUIRE(client.resource.adopt(pair.client) == 0);

  probe_op_t reader;
  bool parked_at_close = false;
  bool closed_synchronously = true;
  server.on_closed = [&] {
    parked_at_close = reader.parked;
    server.resource.cancel(reader);
    client.close();
    loop.stop();
  };
  loop.run_in_loop([&] {
    REQUIRE(would_block_reading(server.native()));
    server.resource.wait(detail::interest_read, reader);
    loop.run_in_loop([&] {
      CHECK(detail::socket_send(client.native(), bytes("after")) == 5);
      server.close();
      closed_synchronously = server.closed;
    });
  });
  CHECK(harness.run());
  CHECK_FALSE(closed_synchronously);
  CHECK(server.closed);
  CHECK(parked_at_close);
  CHECK(reader.completions == 0);
  CHECK_FALSE(reader.parked);
  CHECK(core.in_flight() == 0);
  CHECK(core.open_resources() == 0);
}

TEST_CASE("backend: remove_watch finishes on a later turn, also with a poll already in the kernel")
{
  vio::event_loop_t loop;
  auto &core = detail::core(loop);
  harness_t harness(loop);
  turn_counter_t counter;
  core.add_hook(counter.hook);
  auto pair = make_tcp_pair();
  test_socket_t server(harness);
  test_socket_t client(harness);
  REQUIRE(server.resource.adopt(pair.server) == 0);
  REQUIRE(client.resource.adopt(pair.client) == 0);

  probe_op_t reader;
  std::int64_t closed_on = -1;
  std::int64_t finished_on = -1;
  server.on_closed = [&] {
    finished_on = counter.turns;
    client.close();
    loop.stop();
  };
  loop.run_in_loop([&] {
    REQUIRE(would_block_reading(server.native()));
    server.resource.wait(detail::interest_read, reader);
    loop.run_in_loop([&] {
      server.resource.cancel(reader);
      closed_on = counter.turns;
      server.close();
      CHECK_FALSE(server.closed);
    });
  });
  CHECK(harness.run());
  core.remove_hook(counter.hook);
  CHECK(server.closed);
  CHECK(finished_on > closed_on);
  CHECK(reader.completions == 0);
  CHECK(core.open_resources() == 0);
}

TEST_CASE("backend: readiness that races a close is dropped")
{
  vio::event_loop_t loop;
  auto &core = detail::core(loop);
  harness_t harness(loop);
  auto pair = make_tcp_pair();
  test_socket_t server(harness);
  test_socket_t client(harness);
  REQUIRE(server.resource.adopt(pair.server) == 0);
  REQUIRE(client.resource.adopt(pair.client) == 0);

  probe_op_t reader;
  server.on_closed = [&] {
    client.close();
    loop.stop();
  };
  loop.run_in_loop([&] {
    REQUIRE(would_block_reading(server.native()));
    server.resource.wait(detail::interest_read, reader);
    loop.run_in_loop([&] {
      CHECK(detail::socket_send(client.native(), bytes("race")) == 4);
      std::this_thread::sleep_for(5ms);
      server.resource.cancel(reader);
      server.close();
    });
  });
  CHECK(harness.run());
  CHECK(server.closed);
  CHECK(reader.completions == 0);
  CHECK(core.in_flight() == 0);
}

TEST_CASE("backend: a socket closed after its loop moved to another thread is freed only once the kernel lets go")
{
  vio::event_loop_t loop;
  auto &core = detail::core(loop);
  harness_t harness(loop);
  auto pair = make_tcp_pair();
  auto *server = new test_socket_t(harness);
  test_socket_t client(harness);
  REQUIRE(server->resource.adopt(pair.server) == 0);
  REQUIRE(client.resource.adopt(pair.client) == 0);

  probe_op_t reader;
  reader.keeps_alive = false;
  std::atomic<bool> first_returned{false};
  std::atomic<bool> keep_spinning{true};
  std::thread first([&] {
    loop.run_in_loop([&] {
      REQUIRE(would_block_reading(server->native()));
      server->resource.wait(detail::interest_read, reader);
      loop.run_in_loop([&] { loop.stop(); });
    });
    loop.run();
    first_returned = true;
    const auto give_up = std::chrono::steady_clock::now() + 2s;
    while (keep_spinning.load(std::memory_order_relaxed) && std::chrono::steady_clock::now() < give_up)
    {
    }
  });
  while (!first_returned.load())
    std::this_thread::sleep_for(1ms);

  bool freed = false;
  server->on_closed = [&] {
    delete server;
    server = nullptr;
    freed = true;
    client.close();
    loop.stop();
  };
  loop.run_in_loop([&] {
    CHECK(reader.parked);
    server->resource.cancel(reader);
    server->close();
  });
  const auto start = std::chrono::steady_clock::now();
  CHECK(harness.run());
  const auto waited = std::chrono::steady_clock::now() - start;
  keep_spinning = false;
  first.join();
  MESSAGE("close after a thread switch took " << std::chrono::duration_cast<std::chrono::microseconds>(waited).count() << " us");
  CHECK(freed);
  CHECK(reader.completions == 0);
  CHECK(core.open_resources() == 0);
  CHECK(core.in_flight() == 0);
}

TEST_CASE("backend: a writer facing a half-closed peer with a full buffer does not spin")
{
  vio::event_loop_t loop;
  auto &core = detail::core(loop);
  harness_t harness(loop);
  turn_counter_t counter;
  core.add_hook(counter.hook);
  auto pair = make_tcp_pair();
  set_buffer_sizes(pair.client, 8192);
  set_buffer_sizes(pair.server, 8192);
  test_socket_t server(harness);
  test_socket_t client(harness);
  REQUIRE(server.resource.adopt(pair.server) == 0);
  REQUIRE(client.resource.adopt(pair.client) == 0);

  probe_op_t writer;
  probe_op_t drainer;
  alarm_t settle(harness);
  alarm_t observe(harness);
  std::int64_t turns_at_park = 0;
  std::int64_t turns_while_parked = -1;
  bool wrote = false;
  std::function<void()> drain_some = [&] {
    REQUIRE(drain(server.native()) >= 0);
    server.resource.wait(detail::interest_read, drainer);
  };
  drainer.on_complete = [&](probe_op_t &) { drain_some(); };
  writer.on_complete = [&](probe_op_t &op) {
    std::byte one[1] = {std::byte{1}};
    auto sent = detail::socket_send(client.native(), one);
    if (sent == vio::errc::again)
    {
      client.resource.wait(detail::interest_write, op);
      return;
    }
    REQUIRE(sent == 1);
    if (turns_while_parked < 0)
    {
      fill(client.native());
      client.resource.wait(detail::interest_write, op);
      return;
    }
    wrote = true;
    server.resource.cancel(drainer);
    server.close();
    client.close();
    loop.stop();
  };
  loop.run_in_loop([&] {
    REQUIRE(fill(client.native()) > 0);
    REQUIRE(detail::socket_shutdown_write(server.native()) == 0);
    settle.arm(20ms, [&] {
      fill(client.native());
      client.resource.wait(detail::interest_write, writer);
      turns_at_park = counter.turns;
      observe.arm(200ms, [&] {
        turns_while_parked = counter.turns - turns_at_park;
        drain_some();
      });
    });
  });
  CHECK(harness.run());
  core.remove_hook(counter.hook);
  MESSAGE("turns while a writer waited on a half-closed peer: " << turns_while_parked);
  CHECK(wrote);
  CHECK(turns_while_parked >= 0);
  CHECK(turns_while_parked < 50);
  CHECK(core.in_flight() == 0);
}

TEST_CASE("backend: many sockets exchange messages without a lost wake")
{
  vio::event_loop_t loop;
  auto &core = detail::core(loop);
  harness_t harness(loop);
  constexpr int pairs = 24;
  constexpr int rounds = 40;

  struct lane_t
  {
    explicit lane_t(harness_t &harness)
      : server(harness)
      , client(harness)
    {
    }
    test_socket_t server;
    test_socket_t client;
    probe_op_t server_reader;
    probe_op_t client_reader;
    int round = 0;
  };
  std::vector<std::unique_ptr<lane_t>> lanes;
  int finished = 0;
  for (int i = 0; i < pairs; ++i)
  {
    auto pair = make_tcp_pair();
    auto lane = std::make_unique<lane_t>(harness);
    REQUIRE(lane->server.resource.adopt(pair.server) == 0);
    REQUIRE(lane->client.resource.adopt(pair.client) == 0);
    lanes.push_back(std::move(lane));
  }
  for (auto &owned : lanes)
  {
    auto *lane = owned.get();
    lane->server_reader.on_complete = [lane](probe_op_t &op) {
      std::byte buffer[64];
      for (;;)
      {
        auto got = detail::socket_recv(lane->server.native(), buffer);
        if (got == vio::errc::again)
          break;
        REQUIRE(got > 0);
        REQUIRE(detail::socket_send(lane->server.native(), std::span<const std::byte>(buffer, static_cast<std::size_t>(got))) == got);
      }
      lane->server.resource.wait(detail::interest_read, op);
    };
    lane->client_reader.on_complete = [lane, &finished, &loop](probe_op_t &op) {
      std::byte buffer[64];
      auto got = detail::socket_recv(lane->client.native(), buffer);
      if (got == vio::errc::again)
      {
        lane->client.resource.wait(detail::interest_read, op);
        return;
      }
      REQUIRE(got == 1);
      if (++lane->round == rounds)
      {
        lane->server.resource.cancel(lane->server_reader);
        lane->server.close();
        lane->client.close();
        if (++finished == pairs)
          loop.stop();
        return;
      }
      REQUIRE(detail::socket_send(lane->client.native(), bytes("r")) == 1);
      lane->client.resource.wait(detail::interest_read, op);
    };
  }
  loop.run_in_loop([&] {
    for (auto &lane : lanes)
    {
      lane->server.resource.wait(detail::interest_read, lane->server_reader);
      REQUIRE(detail::socket_send(lane->client.native(), bytes("r")) == 1);
      lane->client.resource.wait(detail::interest_read, lane->client_reader);
    }
  });
  CHECK(harness.run());
  CHECK(finished == pairs);
  for (auto &lane : lanes)
  {
    CHECK(lane->round == rounds);
    CHECK(lane->server.closed);
    CHECK(lane->client.closed);
  }
  CHECK(core.in_flight() == 0);
  CHECK(core.open_resources() == 0);
}

namespace
{
struct deliberate_failure_t
{
};
} // namespace

TEST_CASE("backend: a callback that throws ends the test with its sockets closed and its operations released")
{
  vio::event_loop_t loop;
  auto &core = detail::core(loop);
  harness_t harness(loop);
  auto pair = make_tcp_pair();
  test_socket_t server(harness);
  test_socket_t client(harness);
  REQUIRE(server.resource.adopt(pair.server) == 0);
  REQUIRE(client.resource.adopt(pair.client) == 0);

  probe_op_t woken;
  probe_op_t idle;
  alarm_t never(harness);
  woken.on_complete = [](probe_op_t &) { throw deliberate_failure_t{}; };
  loop.run_in_loop([&] {
    REQUIRE(would_block_reading(server.native()));
    REQUIRE(would_block_reading(client.native()));
    server.resource.wait(detail::interest_read, woken);
    client.resource.wait(detail::interest_read, idle);
    never.arm(3600s, [] {});
    CHECK(detail::socket_send(client.native(), bytes("go")) == 2);
  });
  CHECK_THROWS_AS(harness.run(), deliberate_failure_t);
  CHECK(woken.completions == 1);
  CHECK_FALSE(woken.parked);
  CHECK_FALSE(idle.parked);
  CHECK(idle.completions == 0);
  CHECK_FALSE(never.node.armed());
  CHECK(server.closed);
  CHECK(client.closed);
  CHECK(core.in_flight() == 0);
  CHECK(core.open_resources() == 0);
}

TEST_CASE("backend: a test that outlives its deadline ends with its sockets closed and its operations released")
{
  vio::event_loop_t loop;
  auto &core = detail::core(loop);
  harness_t harness(loop, 100ms);
  auto pair = make_tcp_pair();
  test_socket_t server(harness);
  test_socket_t client(harness);
  REQUIRE(server.resource.adopt(pair.server) == 0);
  REQUIRE(client.resource.adopt(pair.client) == 0);

  probe_op_t reader;
  bool closed_callback_ran = false;
  server.on_closed = [&] { closed_callback_ran = true; };
  loop.run_in_loop([&] {
    REQUIRE(would_block_reading(server.native()));
    server.resource.wait(detail::interest_read, reader);
  });
  const auto start = std::chrono::steady_clock::now();
  CHECK_FALSE(harness.run());
  CHECK(std::chrono::steady_clock::now() - start < 30s);
  CHECK(harness.timed_out());
  CHECK_FALSE(reader.parked);
  CHECK(reader.completions == 0);
  CHECK_FALSE(closed_callback_ran);
  CHECK(server.closed);
  CHECK(client.closed);
  CHECK(core.in_flight() == 0);
  CHECK(core.open_resources() == 0);
}

namespace
{
struct thrown_once_t
{
};

struct throwing_readers_t
{
  explicit throwing_readers_t(harness_t &harness)
    : bail(harness)
  {
    for (auto *reader : {&first, &second})
    {
      reader->on_complete = [this](probe_op_t &op) {
        if (op.completions != 1)
          return;
        ++thrown;
        throw thrown_once_t{};
      };
    }
  }

  void arm_bail(vio::event_loop_t &loop, std::vector<test_socket_t *> sockets)
  {
    bail.arm(5s, [this, &loop, sockets] {
      timed_out = true;
      for (auto *socket : sockets)
        socket->release();
      loop.stop();
    });
  }

  probe_op_t first;
  probe_op_t second;
  alarm_t bail;
  int thrown = 0;
  bool timed_out = false;
};
} // namespace

TEST_CASE("backend: a completion that throws leaves the rest of its batch for the next run")
{
  vio::event_loop_t loop;
  auto &core = detail::core(loop);
  harness_t harness(loop);
  MESSAGE("backend: " << std::string(loop.backend_name()));
  auto first_pair = make_tcp_pair();
  auto second_pair = make_tcp_pair();
  test_socket_t first_server(harness);
  test_socket_t first_client(harness);
  test_socket_t second_server(harness);
  test_socket_t second_client(harness);
  REQUIRE(first_server.resource.adopt(first_pair.server) == 0);
  REQUIRE(first_client.resource.adopt(first_pair.client) == 0);
  REQUIRE(second_server.resource.adopt(second_pair.server) == 0);
  REQUIRE(second_client.resource.adopt(second_pair.client) == 0);

  throwing_readers_t readers(harness);
  readers.arm_bail(loop, {&first_server, &first_client, &second_server, &second_client});
  loop.run_in_loop([&] {
    REQUIRE(would_block_reading(first_server.native()));
    REQUIRE(would_block_reading(second_server.native()));
    first_server.resource.wait(detail::interest_read, readers.first);
    second_server.resource.wait(detail::interest_read, readers.second);
    loop.run_in_loop([&] {
      CHECK(detail::socket_send(first_client.native(), bytes("a")) == 1);
      CHECK(detail::socket_send(second_client.native(), bytes("b")) == 1);
    });
  });
  CHECK_THROWS_AS(loop.run(), thrown_once_t);
  CHECK(readers.thrown == 1);
  CHECK_THROWS_AS(loop.run(), thrown_once_t);
  CHECK(readers.thrown == 2);
  CHECK_FALSE(readers.timed_out);
  CHECK(readers.first.completions == 1);
  CHECK(readers.second.completions == 1);
  CHECK_FALSE(readers.first.parked);
  CHECK_FALSE(readers.second.parked);
  core.remove_timer(readers.bail.node);
  first_server.close();
  first_client.close();
  second_server.close();
  second_client.close();
  loop.stop();
  CHECK(harness.run());
  CHECK(core.in_flight() == 0);
  CHECK(core.open_resources() == 0);
}

TEST_CASE("backend: a completion that throws leaves the other operations parked on its socket to be woken")
{
  vio::event_loop_t loop;
  auto &core = detail::core(loop);
  harness_t harness(loop);
  MESSAGE("backend: " << std::string(loop.backend_name()));
  auto pair = make_tcp_pair();
  test_socket_t server(harness);
  test_socket_t client(harness);
  REQUIRE(server.resource.adopt(pair.server) == 0);
  REQUIRE(client.resource.adopt(pair.client) == 0);

  throwing_readers_t readers(harness);
  readers.arm_bail(loop, {&server, &client});
  loop.run_in_loop([&] {
    REQUIRE(would_block_reading(server.native()));
    server.resource.wait(detail::interest_read, readers.first);
    server.resource.wait(detail::interest_read, readers.second);
    loop.run_in_loop([&] { CHECK(detail::socket_send(client.native(), bytes("a")) == 1); });
  });
  CHECK_THROWS_AS(loop.run(), thrown_once_t);
  CHECK(readers.thrown == 1);
  CHECK_THROWS_AS(loop.run(), thrown_once_t);
  CHECK(readers.thrown == 2);
  CHECK_FALSE(readers.timed_out);
  CHECK(readers.first.completions == 1);
  CHECK(readers.second.completions == 1);
  CHECK_FALSE(readers.first.parked);
  CHECK_FALSE(readers.second.parked);
  core.remove_timer(readers.bail.node);
  server.close();
  client.close();
  loop.stop();
  CHECK(harness.run());
  CHECK(core.in_flight() == 0);
  CHECK(core.open_resources() == 0);
}

TEST_CASE("backend: a retried completion that closes its own socket and throws leaves the rest of the retries for the next run")
{
  vio::event_loop_t loop;
  auto &core = detail::core(loop);
  harness_t harness(loop);
  MESSAGE("backend: " << std::string(loop.backend_name()));
  auto first_pair = make_tcp_pair();
  auto second_pair = make_tcp_pair();
  auto third_pair = make_tcp_pair();
  test_socket_t first_server(harness);
  test_socket_t first_client(harness);
  test_socket_t second_server(harness);
  test_socket_t second_client(harness);
  test_socket_t third_server(harness);
  test_socket_t third_client(harness);
  REQUIRE(first_server.resource.adopt(first_pair.server) == 0);
  REQUIRE(first_client.resource.adopt(first_pair.client) == 0);
  REQUIRE(second_server.resource.adopt(second_pair.server) == 0);
  REQUIRE(second_client.resource.adopt(second_pair.client) == 0);
  REQUIRE(third_server.resource.adopt(third_pair.server) == 0);
  REQUIRE(third_client.resource.adopt(third_pair.client) == 0);

  alarm_t bail(harness);
  bool timed_out = false;
  int thrown = 0;
  probe_op_t first;
  probe_op_t second;
  probe_op_t third;
  first.on_complete = [&](probe_op_t &op) {
    if (op.completions != 1)
      return;
    ++thrown;
    throw thrown_once_t{};
  };
  second.on_complete = [&](probe_op_t &op) {
    if (op.completions != 1)
      return;
    second_server.close();
    ++thrown;
    throw thrown_once_t{};
  };
  third.on_complete = [&](probe_op_t &) { core.remove_timer(bail.node); };
  bail.arm(5s, [&] {
    timed_out = true;
    for (auto *socket : {&first_server, &first_client, &second_server, &second_client, &third_server, &third_client})
      socket->release();
    loop.stop();
  });
  loop.run_in_loop([&] {
    REQUIRE(would_block_reading(first_server.native()));
    REQUIRE(would_block_reading(second_server.native()));
    REQUIRE(would_block_reading(third_server.native()));
    first_server.resource.wait(detail::interest_read, first);
    second_server.resource.wait(detail::interest_read, second);
    third_server.resource.wait(detail::interest_read, third);
    loop.run_in_loop([&] {
      CHECK(detail::socket_send(first_client.native(), bytes("a")) == 1);
      CHECK(detail::socket_send(second_client.native(), bytes("b")) == 1);
      CHECK(detail::socket_send(third_client.native(), bytes("c")) == 1);
    });
  });
  CHECK_THROWS_AS(loop.run(), thrown_once_t);
  CHECK_THROWS_AS(loop.run(), thrown_once_t);
  CHECK(thrown == 2);
  loop.stop();
  CHECK(harness.run());
  CHECK_FALSE(timed_out);
  CHECK(first.completions == 1);
  CHECK(second.completions == 1);
  CHECK(third.completions == 1);
  CHECK_FALSE(third.parked);
  core.remove_timer(bail.node);
  first_server.close();
  first_client.close();
  second_client.close();
  third_server.close();
  third_client.close();
  CHECK(harness.run());
  CHECK(core.in_flight() == 0);
  CHECK(core.open_resources() == 0);
}

#if !defined(_WIN32)
namespace
{
void reuse_descriptor_after_close(bool submitted_first)
{
  vio::event_loop_t loop;
  auto &core = detail::core(loop);
  harness_t harness(loop);
  auto first = make_tcp_pair();
  auto second = make_tcp_pair();
  test_socket_t old_server(harness);
  test_socket_t old_client(harness);
  test_socket_t new_server(harness);
  test_socket_t new_client(harness);
  REQUIRE(old_server.resource.adopt(first.server) == 0);
  REQUIRE(old_client.resource.adopt(first.client) == 0);
  REQUIRE(new_client.resource.adopt(second.client) == 0);

  probe_op_t old_reader;
  probe_op_t new_reader;
  int reused = -1;
  int closes = 0;
  auto closed = [&] {
    if (++closes == 4)
      loop.stop();
  };
  old_server.on_closed = closed;
  old_client.on_closed = closed;
  new_server.on_closed = closed;
  new_client.on_closed = closed;
  new_reader.on_complete = [&](probe_op_t &op) {
    std::byte buffer[16];
    auto got = detail::socket_recv(new_server.native(), buffer);
    if (got == vio::errc::again)
    {
      new_server.resource.wait(detail::interest_read, op);
      return;
    }
    CHECK(got == 3);
    old_client.close();
    new_server.close();
    new_client.close();
  };
  auto swap_sockets = [&] {
    auto old_descriptor = old_server.native();
    old_server.resource.cancel(old_reader);
    old_server.close();
    reused = ::dup2(second.server, old_descriptor);
    REQUIRE(reused == old_descriptor);
    ::close(second.server);
    REQUIRE(new_server.resource.adopt(reused) == 0);
    REQUIRE(would_block_reading(new_server.native()));
    new_server.resource.wait(detail::interest_read, new_reader);
    loop.run_in_loop([&] {
      (void)detail::socket_send(old_client.native(), bytes("old"));
      CHECK(detail::socket_send(new_client.native(), bytes("new")) == 3);
    });
  };
  loop.run_in_loop([&] {
    REQUIRE(would_block_reading(old_server.native()));
    old_server.resource.wait(detail::interest_read, old_reader);
    if (submitted_first)
      loop.run_in_loop(swap_sockets);
    else
      swap_sockets();
  });
  CHECK(harness.run());
  CHECK(old_reader.completions == 0);
  CHECK(new_reader.completions >= 1);
  CHECK(core.in_flight() == 0);
  CHECK(core.open_resources() == 0);
}

struct file_probe_t
{
  detail::file_op_t op;
  int completions = 0;
  std::function<void()> next;

  file_probe_t()
  {
    op.owner = this;
    op.complete = [](detail::file_op_t *raw) {
      auto *self = static_cast<file_probe_t *>(raw->owner);
      ++self->completions;
      CHECK_FALSE(raw->in_flight);
      auto next = std::move(self->next);
      self->next = nullptr;
      if (next)
        next();
    };
  }

  void start(detail::loop_core_t &core, detail::file_op_kind kind, int file, std::byte *data, std::size_t size, std::int64_t offset, std::function<void()> then)
  {
    op.kind = kind;
    op.file = file;
    op.data = data;
    op.size = size;
    op.offset = offset;
    op.in_flight = true;
    next = std::move(then);
    core.backend().submit_file(op);
  }
};
} // namespace

TEST_CASE("backend: a descriptor reused in the turn its socket closed gets only its own readiness")
{
  reuse_descriptor_after_close(false);
}

TEST_CASE("backend: a descriptor reused after its old poll reached the kernel gets only its own readiness")
{
  reuse_descriptor_after_close(true);
}

TEST_CASE("backend: file operations complete through the backend when it supports them")
{
  vio::event_loop_t loop;
  auto &core = detail::core(loop);
  if (!core.backend().supports_async_files())
  {
    MESSAGE(std::string(loop.backend_name()) << " has no asynchronous file support; skipped");
    return;
  }
  char path[] = "/tmp/vio_backend_XXXXXX";
  int file = ::mkstemp(path);
  REQUIRE(file >= 0);
  ::unlink(path);

  file_probe_t probe;
  std::string text = "hello world";
  std::vector<std::byte> buffer(64);
  std::vector<std::int64_t> results;
  auto as_string = [&](std::int64_t count) { return count < 0 ? std::string() : std::string(reinterpret_cast<const char *>(buffer.data()), static_cast<std::size_t>(count)); };
  std::vector<std::string> reads;
  auto record = [&] { results.push_back(probe.op.result); };

  loop.run_in_loop([&] {
    auto *data = reinterpret_cast<std::byte *>(text.data());
    probe.start(core, detail::file_op_kind::write, file, data, text.size(), 0, [&] {
      record();
      probe.start(core, detail::file_op_kind::read, file, buffer.data(), 5, 6, [&] {
        record();
        reads.push_back(as_string(probe.op.result));
        static const char abc[] = "abc";
        probe.start(core, detail::file_op_kind::write, file, reinterpret_cast<std::byte *>(const_cast<char *>(abc)), 3, -1, [&] {
          record();
          probe.start(core, detail::file_op_kind::read, file, buffer.data(), 4, -1, [&] {
            record();
            reads.push_back(as_string(probe.op.result));
            probe.start(core, detail::file_op_kind::fsync, file, nullptr, 0, -1, [&] {
              record();
              probe.start(core, detail::file_op_kind::fdatasync, file, nullptr, 0, -1, [&] {
                record();
                probe.start(core, detail::file_op_kind::read, file, buffer.data(), buffer.size(), 100, [&] {
                  record();
                  probe.start(core, detail::file_op_kind::read, -1, buffer.data(), buffer.size(), 0, [&] {
                    record();
                    loop.stop();
                  });
                });
              });
            });
          });
        });
      });
    });
    CHECK(core.in_flight() == 1);
  });
  loop.run();
  ::close(file);
  REQUIRE(results.size() == 8);
  CHECK(results[0] == 11);
  CHECK(results[1] == 5);
  CHECK(results[2] == 3);
  CHECK(results[3] == 4);
  CHECK(results[4] == 0);
  CHECK(results[5] == 0);
  CHECK(results[6] == 0);
  CHECK(results[7] == vio::errc::bad_descriptor);
  REQUIRE(reads.size() == 2);
  CHECK(reads[0] == "world");
  CHECK(reads[1] == "lo w");
  CHECK(probe.completions == 8);
  CHECK(core.in_flight() == 0);
}

TEST_CASE("backend: a file operation that cannot finish is cancelled")
{
  vio::event_loop_t loop;
  auto &core = detail::core(loop);
  if (!core.backend().supports_async_files())
  {
    MESSAGE(std::string(loop.backend_name()) << " has no asynchronous file support; skipped");
    return;
  }
  int pipe_ends[2];
  REQUIRE(::pipe(pipe_ends) == 0);
  std::vector<std::byte> buffer(16);
  file_probe_t same_turn;
  file_probe_t later_turn;
  int done = 0;
  auto finished = [&] {
    if (++done == 2)
      loop.stop();
  };
  loop.run_in_loop([&] {
    same_turn.start(core, detail::file_op_kind::read, pipe_ends[0], buffer.data(), buffer.size(), -1, finished);
    core.backend().cancel_file(same_turn.op);
    later_turn.start(core, detail::file_op_kind::read, pipe_ends[0], buffer.data(), buffer.size(), -1, finished);
    loop.run_in_loop([&] {
      CHECK(later_turn.op.in_flight);
      core.backend().cancel_file(later_turn.op);
    });
  });
  loop.run();
  ::close(pipe_ends[0]);
  ::close(pipe_ends[1]);
  CHECK(same_turn.completions == 1);
  CHECK(later_turn.completions == 1);
  CHECK(same_turn.op.result == vio::errc::canceled);
  CHECK(later_turn.op.result == vio::errc::canceled);
  CHECK(core.in_flight() == 0);
}
#endif
