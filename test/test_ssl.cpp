#include <doctest/doctest.h>
#include <vio/event_loop.h>
#include <vio/event_pipe.h>
#include <vio/operation/ssl_client.h>
#include <vio/operation/tcp.h>
#include <vio/task.h>

#include "require_expected.h"
#include "vio/operation/sleep.h"

static vio::task_t<void> test_ssl_client_connect(vio::event_loop_t &event_loop)
{
  vio::ssl_config config;
  config.ca_file = "C:/Users/jorge/dev/vio/test/ssl_debug_server/ca.crt";
  auto ssl_client = vio::ssl_client_create(event_loop, config);
  REQUIRE_EXPECTED(ssl_client);

  auto connect_result = co_await ssl_client_connect(ssl_client.value(), "127.0.0.1", 4433);
  REQUIRE_EXPECTED(connect_result);

  {
    auto read_create_result = vio::ssl_client_create_reader(ssl_client.value());
    REQUIRE_EXPECTED(read_create_result);
  }
  //   auto reader = std::move(read_create_result.value());
  //   auto read_result = co_await reader;
  //   REQUIRE(read_result.has_value());
  //   MESSAGE("Got " << read_result.value().first.len << " bytes from SSL client");
  event_loop.stop();
  co_return;
}

TEST_CASE("test ssl client connect")
{
  vio::event_loop_t event_loop;
  event_loop.run_in_loop([&event_loop] { test_ssl_client_connect(event_loop); });
  event_loop.run();
}
