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
  // config.ca_file = "C:/Users/jorge/dev/vio/test/ssl_debug_server/ca.crt";
  auto ssl_client = vio::ssl_client_create(event_loop, config);
  REQUIRE_EXPECTED(ssl_client);

  auto connect_result = co_await ssl_client_connect(ssl_client.value(), "en.wikipedia.org", 443);
  REQUIRE_EXPECTED(connect_result);

  {

    std::string client_message = "GET /wiki/Susan_B._Anthony HTTP/1.1\r\nHost: en.wikipedia.org\r\nConnection: close\r\n\r\n";
    uv_buf_t buf;
    buf.base = client_message.data();
    buf.len = client_message.size();
    auto write_result = co_await vio::ssl_client_write(ssl_client.value(), buf);
  }

  {
    auto read_create_result = vio::ssl_client_create_reader(ssl_client.value());
    REQUIRE_EXPECTED(read_create_result);
    auto reader = std::move(read_create_result.value());
    auto read_result = co_await reader;
    REQUIRE_EXPECTED(read_result);
    auto &value = read_result.value();
    MESSAGE("Got " << read_result.value().first.len << " bytes from SSL client");
    MESSAGE("Payload " << std::string_view(reinterpret_cast<const char *>(value.first.base), value.first.len));
  }
  event_loop.stop();
  co_return;
}

TEST_CASE("test ssl client connect")
{
  vio::event_loop_t event_loop;
  event_loop.run_in_loop([&event_loop] { test_ssl_client_connect(event_loop); });
  event_loop.run();
}
