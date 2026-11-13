/*
  Copyright (c) 2026 Jørgen Lind

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

#include <chrono>
#include <cstddef>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <utility>

#include <vio/event_loop.h>
#include <vio/loop/socket.h>
#include <vio/operation/fd_watch.h>

using namespace std::chrono_literals;

namespace
{
namespace detail = vio::detail;

struct socket_pair_t
{
  vio::native_socket_t client = vio::invalid_native_socket;
  vio::native_socket_t server = vio::invalid_native_socket;

  socket_pair_t()
  {
    vio::native_socket_t listener = vio::invalid_native_socket;
    REQUIRE(detail::socket_open(AF_INET, SOCK_STREAM, 0, listener) == 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    REQUIRE(detail::socket_bind(listener, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) == 0);
    REQUIRE(detail::socket_listen(listener, 16) == 0);
    sockaddr_storage bound{};
    int bound_length = sizeof(bound);
    REQUIRE(detail::socket_name(listener, bound, bound_length) == 0);
    REQUIRE(detail::socket_open(AF_INET, SOCK_STREAM, 0, client) == 0);
    int connected = detail::socket_connect(client, reinterpret_cast<const sockaddr *>(&bound), bound_length);
    REQUIRE((connected == 0 || connected == vio::errc::in_progress || connected == vio::errc::again));
    const auto give_up = std::chrono::steady_clock::now() + 5s;
    for (;;)
    {
      int accepted = detail::socket_accept(listener, server, nullptr, nullptr);
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
      if (detail::socket_peer_name(client, peer, peer_length) == 0)
        break;
      REQUIRE(std::chrono::steady_clock::now() < give_up);
      std::this_thread::sleep_for(1ms);
    }
    detail::socket_close(listener);
  }
  socket_pair_t(const socket_pair_t &) = delete;
  socket_pair_t &operator=(const socket_pair_t &) = delete;
  ~socket_pair_t()
  {
    detail::socket_close(client);
    detail::socket_close(server);
  }
};

std::span<const std::byte> bytes(const char *text)
{
  return {reinterpret_cast<const std::byte *>(text), std::strlen(text)};
}

std::string drain(vio::native_socket_t socket)
{
  std::string received;
  for (;;)
  {
    std::byte buffer[256];
    auto got = detail::socket_recv(socket, buffer);
    if (got <= 0)
      return received;
    received.append(reinterpret_cast<const char *>(buffer), static_cast<std::size_t>(got));
  }
}

vio::fd_watch_t make_watch(vio::event_loop_t &loop, vio::native_socket_t socket)
{
  auto created = vio::fd_watch_create(loop, socket);
  REQUIRE(created.has_value());
  return std::move(created.value());
}
} // namespace

TEST_CASE("fd_watch: an armed watch reports read readiness when the peer writes")
{
  vio::event_loop_t loop;
  socket_pair_t pair;
  std::optional<vio::fd_watch_t> watch;
  std::string received;
  int calls = 0;
  loop.run_in_loop([&] {
    watch = make_watch(loop, pair.server);
    vio::fd_watch_on_ready(*watch, [&](vio::fd_interest interest) {
      ++calls;
      CHECK(interest == vio::fd_interest::read);
      CHECK_FALSE(vio::fd_watch_is_armed(*watch, vio::fd_interest::read));
      received = drain(pair.server);
      watch.reset();
      loop.stop();
    });
    vio::fd_watch_arm(*watch, vio::fd_interest::read);
    CHECK(vio::fd_watch_is_armed(*watch, vio::fd_interest::read));
    CHECK(detail::socket_send(pair.client, bytes("ping")) == 4);
  });
  loop.run();
  CHECK(calls == 1);
  CHECK(received == "ping");
  CHECK(detail::core(loop).open_resources() == 0);
}

TEST_CASE("fd_watch: readiness is reported once per arm")
{
  vio::event_loop_t loop;
  socket_pair_t pair;
  std::optional<vio::fd_watch_t> watch;
  std::string received;
  int calls = 0;
  loop.run_in_loop([&] {
    watch = make_watch(loop, pair.server);
    vio::fd_watch_on_ready(*watch, [&](vio::fd_interest) {
      ++calls;
      received += drain(pair.server);
      if (calls == 1)
      {
        vio::fd_watch_arm(*watch, vio::fd_interest::read);
        loop.run_in_loop([&] { CHECK(detail::socket_send(pair.client, bytes("two")) == 3); });
        return;
      }
      watch.reset();
      loop.stop();
    });
    vio::fd_watch_arm(*watch, vio::fd_interest::read);
    CHECK(detail::socket_send(pair.client, bytes("one")) == 3);
  });
  loop.run();
  CHECK(calls == 2);
  CHECK(received == "onetwo");
}

TEST_CASE("fd_watch: a connected socket reports write readiness")
{
  vio::event_loop_t loop;
  socket_pair_t pair;
  std::optional<vio::fd_watch_t> watch;
  std::optional<vio::fd_interest> reported;
  loop.run_in_loop([&] {
    watch = make_watch(loop, pair.client);
    vio::fd_watch_on_ready(*watch, [&](vio::fd_interest interest) {
      reported = interest;
      watch.reset();
      loop.stop();
    });
    vio::fd_watch_arm(*watch, vio::fd_interest::write);
  });
  loop.run();
  REQUIRE(reported.has_value());
  CHECK(*reported == vio::fd_interest::write);
}

TEST_CASE("fd_watch: a disarmed watch is not called")
{
  vio::event_loop_t loop;
  socket_pair_t pair;
  std::optional<vio::fd_watch_t> watch;
  int calls = 0;
  loop.run_in_loop([&] {
    watch = make_watch(loop, pair.server);
    vio::fd_watch_on_ready(*watch, [&](vio::fd_interest) { ++calls; });
    vio::fd_watch_arm(*watch, vio::fd_interest::read);
    vio::fd_watch_disarm(*watch, vio::fd_interest::read);
    CHECK_FALSE(vio::fd_watch_is_armed(*watch, vio::fd_interest::read));
    CHECK(detail::socket_send(pair.client, bytes("ignored")) == 7);
    std::this_thread::sleep_for(20ms);
    loop.run_in_loop([&] {
      loop.run_in_loop([&] {
        watch.reset();
        loop.stop();
      });
    });
  });
  loop.run();
  CHECK(calls == 0);
}

TEST_CASE("fd_watch: an armed watch that does not keep the loop alive lets run() return")
{
  vio::event_loop_t loop;
  socket_pair_t pair;
  std::optional<vio::fd_watch_t> watch;
  loop.run_in_loop([&] {
    watch = make_watch(loop, pair.server);
    vio::fd_watch_set_keeps_loop_alive(*watch, false);
    vio::fd_watch_arm(*watch, vio::fd_interest::read);
    loop.stop();
  });
  loop.run();
  REQUIRE(watch.has_value());
  CHECK(vio::fd_watch_is_armed(*watch, vio::fd_interest::read));
  CHECK(detail::core(loop).in_flight() == 0);

  vio::fd_watch_set_keeps_loop_alive(*watch, true);
  CHECK(vio::fd_watch_is_armed(*watch, vio::fd_interest::read));
  CHECK(detail::core(loop).in_flight() == 1);

  watch.reset();
  loop.stop();
  loop.run();
  CHECK(detail::core(loop).in_flight() == 0);
  CHECK(detail::core(loop).open_resources() == 0);
}

TEST_CASE("fd_watch: a callback that replaces itself keeps the replacement")
{
  vio::event_loop_t loop;
  socket_pair_t pair;
  std::optional<vio::fd_watch_t> watch;
  int first = 0;
  int second = 0;
  loop.run_in_loop([&] {
    watch = make_watch(loop, pair.server);
    vio::fd_watch_on_ready(*watch, [&](vio::fd_interest) {
      ++first;
      drain(pair.server);
      vio::fd_watch_on_ready(*watch, [&](vio::fd_interest) {
        ++second;
        drain(pair.server);
        watch.reset();
        loop.stop();
      });
      vio::fd_watch_arm(*watch, vio::fd_interest::read);
      loop.run_in_loop([&] { CHECK(detail::socket_send(pair.client, bytes("b")) == 1); });
    });
    vio::fd_watch_arm(*watch, vio::fd_interest::read);
    CHECK(detail::socket_send(pair.client, bytes("a")) == 1);
  });
  loop.run();
  CHECK(first == 1);
  CHECK(second == 1);
}
