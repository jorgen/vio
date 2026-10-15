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

#include <vio/event_loop.h>
#include <vio/operation/sleep.h>
#include <vio/operation/tcp.h>
#include <vio/operation/tcp_server.h>
#include <vio/task.h>

#include "require_expected.h"

#include <chrono>
#include <utility>
#include <vector>

#if !defined(_WIN32)
#include <fcntl.h>
#endif

namespace
{
std::expected<std::pair<vio::tcp_server_t, int>, vio::error_t> make_bound_server(vio::event_loop_t &event_loop)
{
  auto addr = vio::ip4_addr("127.0.0.1", 0);
  if (!addr)
    return std::unexpected(addr.error());
  auto server = vio::tcp_create_server(event_loop);
  if (!server)
    return std::unexpected(server.error());
  auto bound = vio::tcp_bind(server.value(), reinterpret_cast<const sockaddr *>(&addr.value()));
  if (!bound)
    return std::unexpected(bound.error());
  auto sn = vio::sockname(server->tcp);
  if (!sn)
    return std::unexpected(sn.error());
  sockaddr_storage storage = sn.value();
  const auto *in = reinterpret_cast<const sockaddr_in *>(&storage);
  return std::make_pair(std::move(server.value()), static_cast<int>(ntohs(in->sin_port)));
}

vio::task_t<void> listen_overrelease_scenario(vio::event_loop_t &event_loop, long long &before, long long &after, bool &second_arrived)
{
  auto server_and_port = make_bound_server(event_loop);
  REQUIRE_EXPECTED(server_and_port);
  auto server = std::move(server_and_port->first);
  const int port = server_and_port->second;

  auto addr = vio::ip4_addr("127.0.0.1", port);
  REQUIRE_EXPECTED(addr);
  const auto *sa = reinterpret_cast<const sockaddr *>(&addr.value());

  // Hold the server state alive independently so an over-release cannot free it
  // mid-test: we want a clean refcount read, not a use-after-free crash.
  auto keepalive = server.tcp.handle;

  auto first_client = vio::tcp_create(event_loop);
  REQUIRE_EXPECTED(first_client);
  auto client1 = std::move(first_client.value());

  auto listen_future = vio::tcp_listen(server, 128);
  auto connect1 = co_await vio::tcp_connect(client1, sa);
  REQUIRE_EXPECTED(connect1);
  auto listen_result = co_await std::move(listen_future);
  REQUIRE_EXPECTED(listen_result);
  auto accepted1 = vio::tcp_accept(server);
  REQUIRE_EXPECTED(accepted1);
  auto client1_on_server = std::move(accepted1.value());

  [[maybe_unused]] auto slept1 = co_await vio::sleep(event_loop, std::chrono::milliseconds(30));

  before = static_cast<long long>(keepalive.ref_counted()->ref_count.load());

  auto second_client = vio::tcp_create(event_loop);
  REQUIRE_EXPECTED(second_client);
  auto client2 = std::move(second_client.value());
  auto connect2 = co_await vio::tcp_connect(client2, sa);
  REQUIRE_EXPECTED(connect2);

  std::expected<vio::tcp_t, vio::error_t> accepted2 = std::unexpected(vio::error_t{.code = -1, .msg = "pending"});
  for (int i = 0; i < 40 && !accepted2.has_value(); ++i)
  {
    [[maybe_unused]] auto slept = co_await vio::sleep(event_loop, std::chrono::milliseconds(10));
    accepted2 = vio::tcp_accept(server);
  }
  second_arrived = accepted2.has_value();

  after = static_cast<long long>(keepalive.ref_counted()->ref_count.load());

  // If the bug is present the refcount was spuriously decremented; repair it so
  // teardown does not double-free the state (we want a clean assertion failure,
  // not a corrupted-heap crash/hang). A no-op when the fix is in place.
  if (after < before)
  {
    keepalive.ref_counted()->ref_count.fetch_add(static_cast<std::size_t>(before - after));
  }
}

vio::task_t<void> fifo_accept_scenario(vio::event_loop_t &event_loop, std::vector<int> &order, bool &nonblocking)
{
  auto server_and_port = make_bound_server(event_loop);
  REQUIRE_EXPECTED(server_and_port);
  auto server = std::move(server_and_port->first);
  auto addr = vio::ip4_addr("127.0.0.1", server_and_port->second);
  REQUIRE_EXPECTED(addr);
  const auto *sa = reinterpret_cast<const sockaddr *>(&addr.value());

  auto acceptor = [](vio::tcp_server_t &server, int id, std::vector<int> &order, std::vector<vio::tcp_t> &accepted) -> vio::task_t<void>
  {
    auto ready = co_await vio::tcp_listen(server, 16);
    REQUIRE_EXPECTED(ready);
    order.push_back(id);
    auto connection = vio::tcp_accept(server);
    REQUIRE_EXPECTED(connection);
    accepted.push_back(std::move(connection.value()));
  };

  std::vector<vio::tcp_t> accepted;
  auto first = acceptor(server, 1, order, accepted);
  auto second = acceptor(server, 2, order, accepted);
  auto third = acceptor(server, 3, order, accepted);

  std::vector<vio::tcp_t> clients;
  for (int i = 0; i < 3; ++i)
  {
    auto client = vio::tcp_create(event_loop);
    REQUIRE_EXPECTED(client);
    auto connected = co_await vio::tcp_connect(client.value(), sa);
    REQUIRE_EXPECTED(connected);
    clients.push_back(std::move(client.value()));
  }
  co_await std::move(first);
  co_await std::move(second);
  co_await std::move(third);
  REQUIRE(accepted.size() == 3);

  nonblocking = true;
#if !defined(_WIN32)
  for (auto &connection : accepted)
  {
    int flags = fcntl(connection.handle->socket.native(), F_GETFL, 0);
    nonblocking = nonblocking && flags >= 0 && (flags & O_NONBLOCK) != 0;
  }
#endif
}

vio::task_t<void> abort_scenario(vio::event_loop_t &event_loop, int &code, bool &resolved_at_once)
{
  auto server_and_port = make_bound_server(event_loop);
  REQUIRE_EXPECTED(server_and_port);
  auto server = std::move(server_and_port->first);

  auto waiter = [](vio::tcp_server_t &server, int &code) -> vio::task_t<void>
  {
    auto ready = co_await vio::tcp_listen(server, 4);
    REQUIRE_FALSE(ready.has_value());
    code = ready.error().code;
  }(server, code);

  [[maybe_unused]] auto slept = co_await vio::sleep(event_loop, std::chrono::milliseconds(10));
  vio::tcp_listen_abort(server, vio::error_t{.code = vio::errc::canceled, .msg = "server stopped"});
  resolved_at_once = waiter.done();
  co_await std::move(waiter);
}
} // namespace

TEST_SUITE("tcp_listen")
{
  TEST_CASE("a second connection does not over-release the listen state")
  {
    vio::event_loop_t event_loop;
    long long before = 0;
    long long after = 0;
    bool second_arrived = false;

    event_loop.run_in_loop(
      [&]
      {
        return [](vio::event_loop_t &el, long long &b, long long &a, bool &arrived) -> vio::task_t<void>
        {
          co_await listen_overrelease_scenario(el, b, a, arrived);
          el.stop();
        }(event_loop, before, after, second_arrived);
      });

    event_loop.run();

    REQUIRE(second_arrived);
    CHECK_EQ(after, before);
  }

  TEST_CASE("concurrent listens are served in the order they waited")
  {
    vio::event_loop_t event_loop;
    std::vector<int> order;
    bool nonblocking = false;

    event_loop.run_in_loop(
      [&]
      {
        return [](vio::event_loop_t &el, std::vector<int> &o, bool &n) -> vio::task_t<void>
        {
          co_await fifo_accept_scenario(el, o, n);
          el.stop();
        }(event_loop, order, nonblocking);
      });

    event_loop.run();

    CHECK(order == std::vector<int>{1, 2, 3});
    CHECK(nonblocking);
  }

  TEST_CASE("tcp_listen_abort resolves a waiting listen")
  {
    vio::event_loop_t event_loop;
    int code = 0;
    bool resolved_at_once = false;

    event_loop.run_in_loop(
      [&]
      {
        return [](vio::event_loop_t &el, int &c, bool &r) -> vio::task_t<void>
        {
          co_await abort_scenario(el, c, r);
          el.stop();
        }(event_loop, code, resolved_at_once);
      });

    event_loop.run();

    CHECK(resolved_at_once);
    CHECK(code == vio::errc::canceled);
  }
}
