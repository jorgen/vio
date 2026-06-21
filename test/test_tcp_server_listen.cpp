#include <doctest/doctest.h>

#include <vio/event_loop.h>
#include <vio/operation/sleep.h>
#include <vio/operation/tcp.h>
#include <vio/operation/tcp_server.h>
#include <vio/task.h>

#include "require_expected.h"

#include <chrono>
#include <utility>

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

// Reproduces the tcp_listen parked-ref over-release: on_connection consumes the
// ref parked in stream->data but (pre-fix) never nulls it, so a second incoming
// connection (before the listen is re-armed) re-consumes the same raw pointer
// and spuriously decrements the server state's refcount. This scenario owns all
// of its handles and does NOT stop the loop; the caller stops it after awaiting,
// so every handle is uv_close()'d before teardown.
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

  // First connection -> on_connection #1 consumes the parked ref.
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

  // Let on_connection #1 fully unwind (its parked-ref drop has happened).
  [[maybe_unused]] auto slept1 = co_await vio::sleep(event_loop, std::chrono::milliseconds(30));

  before = static_cast<long long>(keepalive.ref_counted()->ref_count.load());

  // Second connection WITHOUT re-arming the listen: uv calls on_connection
  // again on the still-armed socket. Pre-fix this re-consumes the parked ref.
  auto second_client = vio::tcp_create(event_loop);
  REQUIRE_EXPECTED(second_client);
  auto client2 = std::move(second_client.value());
  auto connect2 = co_await vio::tcp_connect(client2, sa);
  REQUIRE_EXPECTED(connect2);

  // Poll until the second connection is acceptable, i.e. on_connection has had
  // its chance to fire (rather than relying on a single fixed-length sleep).
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
}
