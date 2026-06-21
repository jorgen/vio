#include <doctest/doctest.h>

#include <vio/event_loop.h>
#include <vio/operation/tcp.h>
#include <vio/operation/tcp_server.h>
#include <vio/operation/udp.h>
#include <vio/task.h>

#include "require_expected.h"

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

std::expected<vio::udp_t, vio::error_t> bound_udp(vio::event_loop_t &event_loop)
{
  auto addr = vio::ip4_addr("127.0.0.1", 0);
  if (!addr)
    return std::unexpected(addr.error());
  auto udp = vio::udp_create(event_loop);
  if (!udp)
    return std::unexpected(udp.error());
  auto bound = vio::udp_bind(udp.value(), reinterpret_cast<const sockaddr *>(&addr.value()));
  if (!bound)
    return std::unexpected(bound.error());
  return std::move(udp.value());
}

vio::task_t<void> tcp_cancel_scenario(vio::event_loop_t &event_loop, bool &started_before, bool &started_after, bool &got_cancelled)
{
  auto server_and_port = bound_tcp_server(event_loop);
  REQUIRE_EXPECTED(server_and_port);
  const int port = server_and_port->second;
  auto addr = vio::ip4_addr("127.0.0.1", port);
  REQUIRE_EXPECTED(addr);

  // Server accepts and then reads (gets EOF once the client closes).
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
    [[maybe_unused]] auto eof = co_await reader.value();
  }(std::move(server_and_port->first));

  co_await [](vio::event_loop_t &el, const sockaddr *sa, bool &before, bool &after, bool &cancelled) -> vio::task_t<void>
  {
    auto client_or_err = vio::tcp_create(el);
    REQUIRE_EXPECTED(client_or_err);
    auto client = std::move(client_or_err.value());
    auto connect_result = co_await vio::tcp_connect(client, sa);
    REQUIRE_EXPECTED(connect_result);

    auto reader_or_err = vio::tcp_create_reader(client);
    REQUIRE_EXPECTED(reader_or_err);
    auto reader = std::move(reader_or_err.value());

    before = reader.handle->read.started;
    reader.cancel();
    after = reader.handle->read.started;

    auto read_result = co_await reader;
    cancelled = !read_result.has_value() && read_result.error().code == UV_ECANCELED;
  }(event_loop, reinterpret_cast<const sockaddr *>(&addr.value()), started_before, started_after, got_cancelled);

  co_await std::move(server_task);
}

vio::task_t<void> udp_cancel_scenario(vio::event_loop_t &event_loop, bool &started_before, bool &started_after, bool &got_cancelled)
{
  auto udp_or_err = bound_udp(event_loop);
  REQUIRE_EXPECTED(udp_or_err);
  auto udp = std::move(udp_or_err.value());

  auto reader_or_err = vio::udp_create_reader(udp);
  REQUIRE_EXPECTED(reader_or_err);
  auto reader = std::move(reader_or_err.value());

  started_before = reader.handle->recv.started;
  reader.cancel();
  started_after = reader.handle->recv.started;

  auto recv_result = co_await reader;
  got_cancelled = !recv_result.has_value() && recv_result.error().code == UV_ECANCELED;
}
} // namespace

TEST_SUITE("reader cancel")
{
  // cancel() must stop uv delivery (uv_read_stop / uv_udp_recv_stop) so no more
  // buffers are allocated after cancellation -- observable as read.started /
  // recv.started becoming false.
  TEST_CASE("tcp reader cancel stops delivery")
  {
    vio::event_loop_t event_loop;
    bool started_before = false;
    bool started_after = true;
    bool got_cancelled = false;

    event_loop.run_in_loop(
      [&]
      {
        return [](vio::event_loop_t &el, bool &b, bool &a, bool &c) -> vio::task_t<void>
        {
          co_await tcp_cancel_scenario(el, b, a, c);
          el.stop();
        }(event_loop, started_before, started_after, got_cancelled);
      });

    event_loop.run();

    CHECK(started_before);     // reader was actively reading
    CHECK_FALSE(started_after); // cancel() called uv_read_stop
    CHECK(got_cancelled);
  }

  TEST_CASE("udp reader cancel stops delivery")
  {
    vio::event_loop_t event_loop;
    bool started_before = false;
    bool started_after = true;
    bool got_cancelled = false;

    event_loop.run_in_loop(
      [&]
      {
        return [](vio::event_loop_t &el, bool &b, bool &a, bool &c) -> vio::task_t<void>
        {
          co_await udp_cancel_scenario(el, b, a, c);
          el.stop();
        }(event_loop, started_before, started_after, got_cancelled);
      });

    event_loop.run();

    CHECK(started_before);
    CHECK_FALSE(started_after);
    CHECK(got_cancelled);
  }
}
