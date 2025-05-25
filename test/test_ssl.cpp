#include <doctest/doctest.h>
#include <vio/event_loop.h>
#include <vio/event_pipe.h>
#include <vio/operation/ssl_client.h>
#include <vio/operation/tcp.h>
#include <vio/task.h>

#include "require_expected.h"

static vio::task_t<void> test_ssl_client_connect(vio::event_loop_t &event_loop)
{
  auto ssl_client = vio::ssl_client_create(event_loop);
  REQUIRE(ssl_client.has_value());

  auto connect_result = co_await ssl_client_connect(ssl_client.value(), "google.com", 443);
  REQUIRE(connect_result.has_value());

  event_loop.stop();
  co_return;
}

TEST_CASE("test ssl client connect")
{
  vio::event_loop_t event_loop;
  event_loop.run_in_loop([&event_loop] { test_ssl_client_connect(event_loop); });
  event_loop.run();
}
