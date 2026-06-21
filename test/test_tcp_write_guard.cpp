#include <doctest/doctest.h>

#include <vio/event_loop.h>
#include <vio/operation/sleep.h>
#include <vio/operation/tcp.h>
#include <vio/operation/tcp_server.h>
#include <vio/task.h>

#include "require_expected.h"

#include <chrono>
#include <string>
#include <utility>

namespace
{
std::expected<std::pair<vio::tcp_server_t, int>, vio::error_t> bound_tcp_server(vio::event_loop_t &event_loop)
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

vio::task_t<void> write_guard_scenario(vio::event_loop_t &event_loop, bool &second_rejected, bool &first_completed)
{
  auto server_and_port = bound_tcp_server(event_loop);
  REQUIRE_EXPECTED(server_and_port);
  const int port = server_and_port->second;
  auto addr = vio::ip4_addr("127.0.0.1", port);
  REQUIRE_EXPECTED(addr);

  auto server_task = [](vio::tcp_server_t s) -> vio::task_t<void>
  {
    auto server = std::move(s);
    auto listen_result = co_await vio::tcp_listen(server, 10);
    REQUIRE_EXPECTED(listen_result);
    auto accepted = vio::tcp_accept(server);
    REQUIRE_EXPECTED(accepted);
    auto client_on_server = std::move(accepted.value());
    auto reader = vio::tcp_create_reader(client_on_server);
    REQUIRE_EXPECTED(reader);
    auto r = std::move(reader.value());
    while (true)
    {
      auto chunk = co_await r;
      if (!chunk.has_value())
        break; // EOF once the client closes
    }
  }(std::move(server_and_port->first));

  co_await [](vio::event_loop_t &el, const sockaddr *sa, bool &rejected, bool &completed) -> vio::task_t<void>
  {
    auto client_or_err = vio::tcp_create(el);
    REQUIRE_EXPECTED(client_or_err);
    auto client = std::move(client_or_err.value());
    auto connect_result = co_await vio::tcp_connect(client, sa);
    REQUIRE_EXPECTED(connect_result);

    const std::string payload = "hello";

    // Issue two writes back-to-back with no suspension in between, so the first
    // is still in flight (its uv_write callback cannot have run yet) when the
    // second is issued.
    auto write1 = vio::write_tcp(client, reinterpret_cast<const uint8_t *>(payload.data()), payload.size());
    auto write2 = vio::write_tcp(client, reinterpret_cast<const uint8_t *>(payload.data()), payload.size());

    auto result2 = co_await std::move(write2);
    rejected = !result2.has_value();

    auto result1 = co_await std::move(write1);
    completed = true;
    (void)result1;

    // Let the first write's real uv_write callback run so its parked ref is
    // reclaimed before the buffer/socket go away.
    [[maybe_unused]] auto slept = co_await vio::sleep(el, std::chrono::milliseconds(20));
  }(event_loop, reinterpret_cast<const sockaddr *>(&addr.value()), second_rejected, first_completed);

  co_await std::move(server_task);
}
} // namespace

TEST_SUITE("tcp write guard")
{
  // write_tcp must reject a second write while one is in flight rather than
  // overwriting the single embedded uv_write_t and leaking the first parked ref.
  TEST_CASE("a concurrent second write is rejected")
  {
    vio::event_loop_t event_loop;
    bool second_rejected = false;
    bool first_completed = false;

    event_loop.run_in_loop(
      [&]
      {
        return [](vio::event_loop_t &el, bool &r, bool &c) -> vio::task_t<void>
        {
          co_await write_guard_scenario(el, r, c);
          el.stop();
        }(event_loop, second_rejected, first_completed);
      });

    event_loop.run();

    CHECK(first_completed);
    CHECK(second_rejected);
  }
}
