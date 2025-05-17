#include <doctest/doctest.h>
#include <vio/event_loop.h>
#include <vio/event_pipe.h>
#include <vio/operation/ssl.h>
#include <vio/operation/tcp.h>
#include <vio/task.h>

#include "require_expected.h"

static vio::task_t<void> read_from_server(vio::event_loop_t &event_loop)
{
  auto server_addr_or_err = vio::ip4_addr("google.com", 443);
  REQUIRE_EXPECTED(server_addr_or_err);

  auto connect_result = co_await vio::ssl_connect(client, server_addr_or_err.value());
  REQUIRE_EXPECTED(connect_result);

  auto ssl_client_or_err = vio::create_ssl_client(std::move(client));
  REQUIRE_EXPECTED(ssl_client_or_err);
  auto ssl_client = std::move(ssl_client_or_err.value());

  auto handshake_result = co_await vio::ssl_handshake(ssl_client);
  REQUIRE_EXPECTED(handshake_result);

  std::string request = "GET / HTTP/1.1\r\nHost: google.com\r\nConnection: close\r\n\r\n";
  auto write_result = co_await vio::write_ssl(ssl_client, reinterpret_cast<const uint8_t *>(request.data()), request.size());
  REQUIRE_EXPECTED(write_result);

  auto reader = vio::ssl_create_reader(ssl_client);
  REQUIRE_EXPECTED(reader);
  auto read_result = co_await reader.value();
  REQUIRE_EXPECTED(read_result);
  REQUIRE(read_result->size > 0);

  event_loop.stop();
}

TEST_CASE("test basic ssl client ")
{
  vio::event_loop_t event_loop;
  event_loop.run_in_loop([&event_loop] { read_from_server(event_loop); });
  event_loop.run();
}
