#include <atomic>
#include <doctest/doctest.h>
#include <string>
#include <string_view>
#include <vio/error.h>
#include <vio/event_loop.h>
#include <vio/operation/tcp.h>
#include <vio/task.h>

#include "require_expected.h"

namespace
{

//// A simple task that creates a TCP server, binds it to localhost:0 (ephemeral port),
//// listens for a connection, accepts it, then reads any incoming data into a buffer,
//// and finally writes a response back.
vio::task_t<void> test_tcp_server(vio::event_loop_t &event_loop, vio::tcp_t &&s, int port, bool &serverGotData, bool &serverWroteMsg)
{
  auto server = std::move(s);
  fprintf(stderr, "Listening on port %d\n", port);
  auto listen_reply = co_await vio::tcp_listen(server, 10);
  REQUIRE_EXPECTED(listen_reply);
  fprintf(stderr, "Accepted connection\n");
  auto clientOrErr = vio::tcp_accept(server);
  REQUIRE_EXPECTED(clientOrErr);
  auto client = std::move(clientOrErr.value());
  fprintf(stderr, "Created server client %p\n", client.get_handle());

  {
    auto readerOrError = vio::tcp_create_reader(client);
    REQUIRE_EXPECTED(readerOrError);
    auto reader = std::move(readerOrError.value());
    auto read_result = co_await reader;
    REQUIRE_EXPECTED(read_result);
  }
  fprintf(stderr, "Server Read operation succeeded\n");
  serverGotData = true;

  // Echo a message back, e.g. "hello from server"
  const std::string reply = "Hello from server";
  auto writeResult = co_await vio::write_tcp(client, reinterpret_cast<const uint8_t *>(reply.data()), reply.size());
  REQUIRE_EXPECTED(writeResult);
  serverWroteMsg = true;
  fprintf(stderr, "Server Write operation succeeded\n");

  {
    auto reader = vio::tcp_create_reader(client);
    REQUIRE_EXPECTED(reader);
    auto read_result = co_await reader.value();
    REQUIRE(!read_result.has_value());
  }
};

// A client task that connects to the server, writes a message, and reads the server's reply
vio::task_t<void> test_tcp_client(vio::event_loop_t &event_loop, int serverPort, bool &clientGotServerReply)
{
  auto clientOrErr = vio::create_tcp(event_loop);
  REQUIRE_EXPECTED(clientOrErr);
  auto client_raw = std::move(clientOrErr.value());
  fprintf(stderr, "Created client %p\n", client_raw.get_handle());

  auto serverAddrOrErr = vio::ip4_addr("127.0.0.1", serverPort);
  REQUIRE_EXPECTED(serverAddrOrErr);

  fprintf(stderr, "Connecting to server with port %d\n", serverPort);
  auto connectResult = co_await vio::tcp_connect(client_raw, reinterpret_cast<const sockaddr *>(&serverAddrOrErr.value()));
  REQUIRE_EXPECTED(connectResult);

  std::string clientMessage = "Hello TCP server";
  auto writeResult = co_await vio::write_tcp(client_raw, reinterpret_cast<const uint8_t *>(clientMessage.data()), clientMessage.size());
  if (!writeResult.has_value())
  {
    fprintf(stderr, "Write operation failed: %s\n", writeResult.error().msg.c_str());
  }
  REQUIRE_EXPECTED(writeResult);
  fprintf(stderr, "Write operation succeeded\n");
  auto reader = vio::tcp_create_reader(client_raw);
  REQUIRE_EXPECTED(reader);
  auto read_result = co_await reader.value();
  REQUIRE_EXPECTED(read_result);
  auto &read_data = read_result.value();
  std::string_view sv(reinterpret_cast<const char *>(read_data.data.get()), read_data.size);
  if (sv.find("Hello from server") != std::string_view::npos)
  {
    clientGotServerReply = true;
  }
  fprintf(stderr, "Read operation succeeded\n");
}

#define PROPAGATE_ERROR(x)                                                                                                                                                                                                 \
  if (!x.has_value())                                                                                                                                                                                                      \
    return std::unexpected(std::move(x.error()));

std::expected<std::pair<vio::tcp_t, int>, vio::error_t> get_ephemeral_port(vio::event_loop_t &event_loop)
{
  auto addrOrErr = vio::ip4_addr("127.0.0.1", 0);
  PROPAGATE_ERROR(addrOrErr);
  auto tmp_tcp = vio::create_tcp(event_loop);
  fprintf(stderr, "created tcp server %p\n", tmp_tcp->get_handle());
  PROPAGATE_ERROR(tmp_tcp);
  auto bindRes = vio::tcp_bind(tmp_tcp.value(), reinterpret_cast<const sockaddr *>(&addrOrErr.value()));
  PROPAGATE_ERROR(bindRes);

  sockaddr_storage saStorage;
  int namelen = sizeof(saStorage);
  uv_tcp_getsockname(tmp_tcp.value().get_tcp(), reinterpret_cast<sockaddr *>(&saStorage), &namelen);
  auto *sa_in = reinterpret_cast<sockaddr_in *>(&saStorage);
  return std::make_pair(std::move(tmp_tcp.value()), int(ntohs(sa_in->sin_port)));
}

TEST_CASE("test basic tcp")
{
  // We'll spawn server and client tasks that talk to each other
  // following a style similar to the file tests.

  vio::event_loop_t event_loop;

  // We'll use these flags to check we got the data
  bool serverGotData = false;
  bool serverWroteMsg = false;
  bool clientGotServerReply = false;

  serverGotData = false;
  serverWroteMsg = false;
  clientGotServerReply = false;

  event_loop.run_in_loop(
    [&event_loop]() -> vio::task_t<void>
    {
      auto ev = &event_loop;
      auto server_tcp_pair = get_ephemeral_port(*ev);
      REQUIRE_EXPECTED(server_tcp_pair);

      auto server = test_tcp_server(*ev, std::move(server_tcp_pair->first), server_tcp_pair->second, serverGotData, serverWroteMsg);
      co_await test_tcp_client(*ev, server_tcp_pair->second, clientGotServerReply);
      co_await std::move(server);

      ev->stop();
    });

  event_loop.run();

  REQUIRE(serverGotData);
  REQUIRE(serverWroteMsg);
  REQUIRE(clientGotServerReply);
}
} // namespace
