#include <doctest/doctest.h>
#include <string>
#include <string_view>
#include <vio/error.h>
#include <vio/event_loop.h>
#include <vio/operation/tcp.h>
#include <vio/task.h>

#include "require_expected.h"
#include "vio/operation/tcp_server.h"

namespace
{

vio::task_t<void> test_tcp_server(vio::event_loop_t &event_loop, vio::tcp_server_t &&s, int port, bool &server_got_data, bool &server_wrote_msg)
{
  auto server = std::move(s);
  auto listen_reply = co_await vio::tcp_listen(server, 10);
  REQUIRE_EXPECTED(listen_reply);
  auto client_or_err = vio::tcp_accept(server);
  REQUIRE_EXPECTED(client_or_err);
  auto client = std::move(client_or_err.value());

  {
    auto reader_or_error = vio::tcp_create_reader(client);
    REQUIRE_EXPECTED(reader_or_error);
    auto reader = std::move(reader_or_error.value());
    auto read_result = co_await reader;
    REQUIRE_EXPECTED(read_result);
  }
  server_got_data = true;

  // Echo a message back, e.g. "hello from server"
  const std::string reply = "Hello from server";
  auto write_result = co_await vio::write_tcp(client, reinterpret_cast<const uint8_t *>(reply.data()), reply.size());
  REQUIRE_EXPECTED(write_result);
  server_wrote_msg = true;

  {
    auto reader = vio::tcp_create_reader(client);
    REQUIRE_EXPECTED(reader);
    auto read_result = co_await reader.value();
    REQUIRE(!read_result.has_value());
  }
};

// A client task that connects to the server, writes a message, and reads the server's reply
vio::task_t<void> test_tcp_client(vio::event_loop_t &event_loop, int server_port, bool &client_got_server_reply)
{
  auto client_or_err = vio::tcp_create(event_loop);
  REQUIRE_EXPECTED(client_or_err);
  auto client_raw = std::move(client_or_err.value());

  auto server_addr_or_err = vio::ip4_addr("127.0.0.1", server_port);
  REQUIRE_EXPECTED(server_addr_or_err);

  auto connect_result = co_await vio::tcp_connect(client_raw, reinterpret_cast<const sockaddr *>(&server_addr_or_err.value()));
  REQUIRE_EXPECTED(connect_result);

  std::string client_message = "Hello TCP server";
  auto write_result = co_await vio::write_tcp(client_raw, reinterpret_cast<const uint8_t *>(client_message.data()), client_message.size());
  REQUIRE_EXPECTED(write_result);
  auto reader = vio::tcp_create_reader(client_raw);
  REQUIRE_EXPECTED(reader);
  auto read_result = co_await reader.value();
  REQUIRE_EXPECTED(read_result);
  auto &read_data = read_result.value();
  const std::string_view sv(read_data->base, read_data->len);
  if (sv.find("Hello from server") != std::string_view::npos)
  {
    client_got_server_reply = true;
  }
}

#define PROPAGATE_ERROR(x)                                                                                                                                                                                                 \
  if (!(x).has_value())                                                                                                                                                                                                    \
    return std::unexpected(std::move((x).error()));

std::expected<std::pair<vio::tcp_server_t, int>, vio::error_t> get_ephemeral_port(vio::event_loop_t &event_loop)
{
  auto addr_or_err = vio::ip4_addr("127.0.0.1", 0);
  PROPAGATE_ERROR(addr_or_err);
  auto tmp_tcp = vio::tcp_create_server(event_loop);
  PROPAGATE_ERROR(tmp_tcp);
  auto bind_res = vio::tcp_bind(tmp_tcp.value(), reinterpret_cast<const sockaddr *>(&addr_or_err.value()));
  PROPAGATE_ERROR(bind_res);

  auto sockname_result = vio::sockname(tmp_tcp->tcp);
  PROPAGATE_ERROR(sockname_result);
  sockaddr_storage sa_storage = sockname_result.value();
  const auto *sa_in = reinterpret_cast<sockaddr_in *>(&sa_storage);
  return std::make_pair(std::move(tmp_tcp.value()), static_cast<int>(ntohs(sa_in->sin_port)));
}

TEST_CASE("test basic tcp")
{
  // We'll spawn server and client tasks that talk to each other
  // following a style similar to the file tests.

  vio::event_loop_t event_loop;

  // We'll use these flags to check we got the data
  bool server_got_data = false;
  bool server_wrote_msg = false;
  bool client_got_server_reply = false;

  server_got_data = false;
  server_wrote_msg = false;
  client_got_server_reply = false;

  event_loop.run_in_loop(
    [&event_loop, &server_got_data, &server_wrote_msg, &client_got_server_reply]() -> vio::task_t<void>
    {
      auto *ev = &event_loop;
      auto server_tcp_pair = get_ephemeral_port(*ev);
      REQUIRE_EXPECTED(server_tcp_pair);

      auto server = test_tcp_server(*ev, std::move(server_tcp_pair->first), server_tcp_pair->second, server_got_data, server_wrote_msg);
      co_await test_tcp_client(*ev, server_tcp_pair->second, client_got_server_reply);
      co_await std::move(server);

      ev->stop();
    });

  event_loop.run();

  REQUIRE(server_got_data);
  REQUIRE(server_wrote_msg);
  REQUIRE(client_got_server_reply);
}
} // namespace
