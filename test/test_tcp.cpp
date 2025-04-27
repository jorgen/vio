#include <atomic>
#include <doctest/doctest.h>
#include <string>
#include <string_view>
#include <vio/event_loop.h>
#include <vio/operation/tcp.h>
#include <vio/task.h>

#include "require_expected.h"

namespace
{

// A simple task that creates a TCP server, binds it to localhost:0 (ephemeral port),
// listens for a connection, accepts it, then reads any incoming data into a buffer,
// and finally writes a response back.
vio::task_t<void> test_tcp_server(vio::event_loop_t &event_loop, vio::tcp_t server, int port, std::atomic<bool> &serverGotData, std::atomic<bool> &serverWroteMsg)
{
  fprintf(stderr, "Listening on port %d\n", port);
  auto listen_reply = co_await vio::tcp_listen(event_loop, server, 10);
  REQUIRE_EXPECTED(listen_reply);
  fprintf(stderr, "Accepted connection\n");
  auto clientOrErr = vio::tcp_accept(server);
  REQUIRE_EXPECTED(clientOrErr);
  auto client = std::move(clientOrErr.value());

  // auto reader = vio::create_tcp_reader(*client);
  vio::tcp_reader_t<> reader(*client, vio::default_tcp_alloc_cb, std::default_delete<uint8_t[]>());
  REQUIRE(reader.initialize().code == 0);
  auto read_result = co_await reader;
  REQUIRE_EXPECTED(read_result);

  fprintf(stderr, "Server Read operation succeeded\n");
  serverGotData = true;

  // Echo a message back, e.g. "hello from server"
  const std::string reply = "Hello from server";
  auto writeResult = co_await vio::write_tcp(event_loop, *client, reinterpret_cast<const uint8_t *>(reply.data()), reply.size());
  REQUIRE_EXPECTED(writeResult);
  serverWroteMsg = true;
  fprintf(stderr, "Server Write operation succeeded\n");

  read_result = co_await reader;
  REQUIRE(!read_result.has_value());
};

// A client task that connects to the server, writes a message, and reads the server's reply
vio::task_t<void> test_tcp_client(vio::event_loop_t &event_loop, int serverPort, std::atomic<bool> &clientGotServerReply)
{
  // Create client TCP
  auto clientOrErr = vio::create_tcp(event_loop);
  REQUIRE_EXPECTED(clientOrErr);
  auto client = std::move(clientOrErr.value());

  // Prepare server address
  auto serverAddrOrErr = vio::ip4_addr("127.0.0.1", serverPort);
  REQUIRE_EXPECTED(serverAddrOrErr);

  fprintf(stderr, "Connecting to server with port %d\n", serverPort);
  auto connectResult = co_await vio::tcp_connect(event_loop, client, reinterpret_cast<const sockaddr *>(&serverAddrOrErr.value()));
  REQUIRE_EXPECTED(connectResult);

  std::string clientMessage = "Hello TCP server";
  auto writeResult = co_await vio::write_tcp(event_loop, client, reinterpret_cast<const uint8_t *>(clientMessage.data()), clientMessage.size());
  if (!writeResult.has_value())
  {
    fprintf(stderr, "Write operation failed: %s\n", writeResult.error().msg.c_str());
  }
  REQUIRE_EXPECTED(writeResult);
  fprintf(stderr, "Write operation succeeded\n");
  vio::tcp_reader_t<> reader(client);
  REQUIRE(reader.initialize().code == 0);
  auto read_result = co_await reader;
  REQUIRE_EXPECTED(read_result);
  auto &read_data = read_result.value();
  std::string_view sv(reinterpret_cast<const char *>(read_data.data.get()), static_cast<size_t>(read_data.size));
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
  PROPAGATE_ERROR(tmp_tcp);
  auto bindRes = vio::tcp_bind(tmp_tcp.value(), reinterpret_cast<const sockaddr *>(&addrOrErr.value()));
  PROPAGATE_ERROR(bindRes);

  sockaddr_storage saStorage;
  int namelen = sizeof(saStorage);
  uv_tcp_getsockname(tmp_tcp.value().handle.get(), reinterpret_cast<sockaddr *>(&saStorage), &namelen);
  auto *sa_in = reinterpret_cast<sockaddr_in *>(&saStorage);
  return std::make_pair(std::move(tmp_tcp.value()), int(ntohs(sa_in->sin_port)));
}

TEST_CASE("test basic tcp")
{
  // We'll spawn server and client tasks that talk to each other
  // following a style similar to the file tests.

  vio::event_loop_t event_loop;

  // We'll use these flags to check we got the data
  static std::atomic<bool> serverGotData{false};
  static std::atomic<bool> serverWroteMsg{false};
  static std::atomic<bool> clientGotServerReply{false};

  serverGotData = false;
  serverWroteMsg = false;
  clientGotServerReply = false;

  // Start the server in our loop
  // We'll get a port, then run the client after the server is ready
  event_loop.run_in_loop(
    [&event_loop]() -> vio::task_t<void>
    {
      // Start the server
      auto server_tcp_pair = get_ephemeral_port(event_loop);
      REQUIRE_EXPECTED(server_tcp_pair);

      auto server = test_tcp_server(event_loop, std::move(server_tcp_pair->first), server_tcp_pair->second, serverGotData, serverWroteMsg);
      co_await test_tcp_client(event_loop, server_tcp_pair->second, clientGotServerReply);
      co_await std::move(server);
      event_loop.stop();
    });

  // Run the event loop
  event_loop.run();

  // Check the flags after the loop finishes
  // Real usage would have the server and client using a real port from the ephemeral server's bind.
  // This snippet is meant as an illustrative example, so some logic for the port might be incomplete.
  REQUIRE(serverGotData.load());        // We expected the server to receive data
  REQUIRE(serverWroteMsg.load());       // We expected the server to write a response
  REQUIRE(clientGotServerReply.load()); // We expected the client to receive that response
}
} // namespace
