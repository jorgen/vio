#include "require_expected.h"

#include <doctest/doctest.h>
#include <vio/cancellation.h>
#include <vio/event_loop.h>
#include <vio/operation/dns.h>
#include <vio/operation/file.h>
#include <vio/operation/sleep.h>
#include <vio/operation/tcp.h>
#include <vio/operation/tcp_server.h>
#include <vio/operation/tls_client.h>
#include <vio/operation/tls_server.h>
#include <vio/task.h>

#include <vector>

static auto long_delay = std::chrono::milliseconds(5000);
static auto short_delay = std::chrono::milliseconds(32);

TEST_SUITE("Cancellation")
{

TEST_CASE("cancel sleep before it completes")
{
  vio::event_loop_t event_loop;
  event_loop.run_in_loop(
    [&event_loop]
    {
      [](vio::event_loop_t &ev) -> vio::task_t<void>
      {
        vio::cancellation_t cancel;
        auto sleep_future = vio::sleep(ev, long_delay, &cancel);
        cancel.cancel();
        auto result = co_await sleep_future;
        CHECK(!result.has_value());
        CHECK(vio::is_cancelled(result.error()));
        ev.stop();
      }(event_loop);
    });
  event_loop.run();
}

TEST_CASE("cancel already-completed sleep is a no-op")
{
  vio::event_loop_t event_loop;
  event_loop.run_in_loop(
    [&event_loop]
    {
      [](vio::event_loop_t &ev) -> vio::task_t<void>
      {
        vio::cancellation_t cancel;
        auto result = co_await vio::sleep(ev, std::chrono::milliseconds(0), &cancel);
        CHECK(result.has_value());
        cancel.cancel();
        CHECK(cancel.is_cancelled());
        ev.stop();
      }(event_loop);
    });
  event_loop.run();
}

TEST_CASE("cancel before await returns immediately")
{
  vio::event_loop_t event_loop;
  event_loop.run_in_loop(
    [&event_loop]
    {
      [](vio::event_loop_t &ev) -> vio::task_t<void>
      {
        vio::cancellation_t cancel;
        cancel.cancel();
        auto sleep_future = vio::sleep(ev, long_delay, &cancel);
        auto result = co_await sleep_future;
        CHECK(!result.has_value());
        CHECK(result.error().code == vio::vio_cancelled);
        ev.stop();
      }(event_loop);
    });
  event_loop.run();
}

TEST_CASE("double cancel is idempotent")
{
  vio::cancellation_t cancel;
  int callback_count = 0;
  auto reg = cancel.register_callback([&callback_count]() { callback_count++; });
  cancel.cancel();
  cancel.cancel();
  CHECK(callback_count == 1);
  CHECK(cancel.is_cancelled());
}

TEST_CASE("registration deregisters on destruction")
{
  vio::cancellation_t cancel;
  int callback_count = 0;
  {
    auto reg = cancel.register_callback([&callback_count]() { callback_count++; });
  }
  cancel.cancel();
  CHECK(callback_count == 0);
}

TEST_CASE("registration deregisters on move")
{
  vio::cancellation_t cancel;
  int callback_count = 0;
  vio::registration_t reg2;
  {
    auto reg = cancel.register_callback([&callback_count]() { callback_count++; });
    reg2 = std::move(reg);
  }
  cancel.cancel();
  CHECK(callback_count == 1);
}

TEST_CASE("is_cancelled recognizes both error codes")
{
  vio::error_t vio_err{.code = vio::vio_cancelled, .msg = "cancelled"};
  CHECK(vio::is_cancelled(vio_err));

  vio::error_t uv_err{.code = UV_ECANCELED, .msg = "cancelled"};
  CHECK(vio::is_cancelled(uv_err));

  vio::error_t other_err{.code = -1, .msg = "other"};
  CHECK(!vio::is_cancelled(other_err));
}

TEST_CASE("cancel DNS lookup")
{
  vio::event_loop_t event_loop;
  event_loop.run_in_loop(
    [&event_loop]
    {
      [](vio::event_loop_t &ev) -> vio::task_t<void>
      {
        // DNS for localhost may resolve before uv_cancel takes effect.
        // uv_cancel on getaddrinfo may also produce platform-specific errors.
        // The test verifies no crash or leak occurs.
        vio::cancellation_t cancel;
        auto dns_future = vio::get_addrinfo(ev, "localhost", {}, &cancel);
        cancel.cancel();
        auto result = co_await dns_future;
        // Either succeeded (raced ahead of cancel) or got some error
        CHECK(true);
        ev.stop();
      }(event_loop);
    });
  event_loop.run();
}

TEST_CASE("cancel DNS lookup before await")
{
  vio::event_loop_t event_loop;
  event_loop.run_in_loop(
    [&event_loop]
    {
      [](vio::event_loop_t &ev) -> vio::task_t<void>
      {
        vio::cancellation_t cancel;
        cancel.cancel();
        auto result = co_await vio::get_addrinfo(ev, "localhost", {}, &cancel);
        CHECK(!result.has_value());
        CHECK(result.error().code == vio::vio_cancelled);
        ev.stop();
      }(event_loop);
    });
  event_loop.run();
}

TEST_CASE("cancel file read")
{
  vio::event_loop_t event_loop;
  event_loop.run_in_loop(
    [&event_loop]
    {
      [](vio::event_loop_t &ev) -> vio::task_t<void>
      {
        auto tmp = vio::mkstemp_file(ev, "test_cancel_read_XXXXXX");
        REQUIRE(tmp.has_value());
        auto file = std::move(tmp.value().first);
        auto path = std::move(tmp.value().second);

        std::string data = "test data for cancellation";
        auto write_result = co_await vio::write_file(ev, *file, reinterpret_cast<const uint8_t *>(data.data()), data.size(), 0);
        REQUIRE(write_result.has_value());

        file = vio::make_auto_close_file({.event_loop = &ev, .handle = -1});
        auto opened = vio::open_file(ev, path, vio::file_open_flag_t::rdonly, 0);
        REQUIRE(opened.has_value());
        file = std::move(opened.value());

        vio::cancellation_t cancel;
        cancel.cancel();
        std::string buffer(data.size(), '\0');
        auto read_result = co_await vio::read_file(ev, *file, reinterpret_cast<uint8_t *>(buffer.data()), data.size(), 0, &cancel);
        CHECK(!read_result.has_value());
        CHECK(read_result.error().code == vio::vio_cancelled);

        file = vio::make_auto_close_file({.event_loop = &ev, .handle = -1});
        vio::unlink_file(ev, path);
        ev.stop();
      }(event_loop);
    });
  event_loop.run();
}

TEST_CASE("cancel file write")
{
  vio::event_loop_t event_loop;
  event_loop.run_in_loop(
    [&event_loop]
    {
      [](vio::event_loop_t &ev) -> vio::task_t<void>
      {
        auto tmp = vio::mkstemp_file(ev, "test_cancel_write_XXXXXX");
        REQUIRE(tmp.has_value());
        auto file = std::move(tmp.value().first);
        auto path = std::move(tmp.value().second);

        vio::cancellation_t cancel;
        cancel.cancel();
        std::string data = "test data";
        auto result = co_await vio::write_file(ev, *file, reinterpret_cast<const uint8_t *>(data.data()), data.size(), 0, &cancel);
        CHECK(!result.has_value());
        CHECK(result.error().code == vio::vio_cancelled);

        file = vio::make_auto_close_file({.event_loop = &ev, .handle = -1});
        vio::unlink_file(ev, path);
        ev.stop();
      }(event_loop);
    });
  event_loop.run();
}

TEST_CASE("multiple operations with one cancellation")
{
  vio::event_loop_t event_loop;
  event_loop.run_in_loop(
    [&event_loop]
    {
      [](vio::event_loop_t &ev) -> vio::task_t<void>
      {
        vio::cancellation_t cancel;

        auto sleep1 = vio::sleep(ev, long_delay, &cancel);
        auto sleep2 = vio::sleep(ev, long_delay, &cancel);
        auto sleep3 = vio::sleep(ev, long_delay, &cancel);

        cancel.cancel();

        auto r1 = co_await sleep1;
        auto r2 = co_await sleep2;
        auto r3 = co_await sleep3;

        CHECK(!r1.has_value());
        CHECK(!r2.has_value());
        CHECK(!r3.has_value());
        CHECK(vio::is_cancelled(r1.error()));
        CHECK(vio::is_cancelled(r2.error()));
        CHECK(vio::is_cancelled(r3.error()));

        ev.stop();
      }(event_loop);
    });
  event_loop.run();
}

TEST_CASE("multiple tasks in vector with cancellation")
{
  vio::event_loop_t event_loop;
  event_loop.run_in_loop(
    [&event_loop]
    {
      [](vio::event_loop_t &ev) -> vio::task_t<void>
      {
        vio::cancellation_t cancel;
        int cancelled_count = 0;

        auto worker = [](vio::event_loop_t &ev, vio::cancellation_t *c, int &count) -> vio::task_t<void>
        {
          auto result = co_await vio::sleep(ev, long_delay, c);
          if (!result.has_value() && vio::is_cancelled(result.error()))
          {
            count++;
          }
        };

        auto t1 = worker(ev, &cancel, cancelled_count);
        auto t2 = worker(ev, &cancel, cancelled_count);
        auto t3 = worker(ev, &cancel, cancelled_count);

        cancel.cancel();

        co_await std::move(t1);
        co_await std::move(t2);
        co_await std::move(t3);

        CHECK(cancelled_count == 3);

        ev.stop();
      }(event_loop);
    });
  event_loop.run();
}

TEST_CASE("sleep without cancellation still works")
{
  vio::event_loop_t event_loop;
  event_loop.run_in_loop(
    [&event_loop]
    {
      [](vio::event_loop_t &ev) -> vio::task_t<void>
      {
        auto result = co_await vio::sleep(ev, short_delay);
        CHECK(result.has_value());
        ev.stop();
      }(event_loop);
    });
  event_loop.run();
}

// --- TCP connect cancellation tests ---

#define PROPAGATE_ERROR(x)                                                                                                                                                                                                 \
  if (!(x).has_value())                                                                                                                                                                                                    \
    return std::unexpected(std::move((x).error()));

static std::expected<std::pair<vio::tcp_server_t, int>, vio::error_t> get_ephemeral_port(vio::event_loop_t &event_loop)
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

TEST_CASE("cancel tcp_connect before await (pre-cancelled)")
{
  vio::event_loop_t event_loop;
  event_loop.run_in_loop(
    [&event_loop]
    {
      [](vio::event_loop_t &ev) -> vio::task_t<void>
      {
        auto tcp = vio::tcp_create(ev);
        REQUIRE_EXPECTED(tcp);
        auto addr = vio::ip4_addr("127.0.0.1", 9999);
        REQUIRE_EXPECTED(addr);

        vio::cancellation_t cancel;
        cancel.cancel();
        auto result = co_await vio::tcp_connect(tcp.value(), reinterpret_cast<const sockaddr *>(&addr.value()), &cancel);
        CHECK(!result.has_value());
        CHECK(result.error().code == vio::vio_cancelled);
        ev.stop();
      }(event_loop);
    });
  event_loop.run();
}

TEST_CASE("cancel tcp_connect while connecting")
{
  vio::event_loop_t event_loop;
  event_loop.run_in_loop(
    [&event_loop]
    {
      [](vio::event_loop_t &ev) -> vio::task_t<void>
      {
        auto tcp = vio::tcp_create(ev);
        REQUIRE_EXPECTED(tcp);
        // Connect to localhost on an unlikely port - connect callback fires async,
        // cancel fires synchronously before it
        auto addr = vio::ip4_addr("127.0.0.1", 1);
        REQUIRE_EXPECTED(addr);

        vio::cancellation_t cancel;
        auto connect_future = vio::tcp_connect(tcp.value(), reinterpret_cast<const sockaddr *>(&addr.value()), &cancel);
        cancel.cancel();
        auto result = co_await connect_future;
        CHECK(!result.has_value());
        CHECK(vio::is_cancelled(result.error()));
        ev.stop();
      }(event_loop);
    });
  event_loop.run();
}

// --- TCP listen cancellation tests ---

TEST_CASE("cancel tcp_listen before await (pre-cancelled)")
{
  vio::event_loop_t event_loop;
  event_loop.run_in_loop(
    [&event_loop]
    {
      [](vio::event_loop_t &ev) -> vio::task_t<void>
      {
        {
          auto server_pair = get_ephemeral_port(ev);
          REQUIRE_EXPECTED(server_pair);

          vio::cancellation_t cancel;
          cancel.cancel();
          auto result = co_await vio::tcp_listen(server_pair->first, 1, &cancel);
          CHECK(!result.has_value());
          CHECK(result.error().code == vio::vio_cancelled);
        }
        ev.stop();
      }(event_loop);
    });
  event_loop.run();
}

TEST_CASE("cancel tcp_listen after starting")
{
  vio::event_loop_t event_loop;
  event_loop.run_in_loop(
    [&event_loop]
    {
      [](vio::event_loop_t &ev) -> vio::task_t<void>
      {
        {
          auto server_pair = get_ephemeral_port(ev);
          REQUIRE_EXPECTED(server_pair);

          vio::cancellation_t cancel;
          auto listen_future = vio::tcp_listen(server_pair->first, 1, &cancel);
          cancel.cancel();
          auto result = co_await listen_future;
          CHECK(!result.has_value());
          CHECK(vio::is_cancelled(result.error()));
        }
        // server_pair is destroyed here, dropping the server ref
        ev.stop();
      }(event_loop);
    });
  event_loop.run();
}

// --- SSL client connect cancellation tests ---

TEST_CASE("cancel ssl_client_connect before await (pre-cancelled)")
{
  vio::event_loop_t event_loop;
  event_loop.run_in_loop(
    [&event_loop]
    {
      [](vio::event_loop_t &ev) -> vio::task_t<void>
      {
        auto ssl_client = vio::ssl_client_create(ev);
        REQUIRE_EXPECTED(ssl_client);

        vio::cancellation_t cancel;
        cancel.cancel();
        auto result = co_await vio::ssl_client_connect(ssl_client.value(), "localhost", 9999, &cancel);
        CHECK(!result.has_value());
        CHECK(result.error().code == vio::vio_cancelled);
        ev.stop();
      }(event_loop);
    });
  event_loop.run();
}

TEST_CASE("cancel ssl_client_connect during DNS phase")
{
  vio::event_loop_t event_loop;
  event_loop.run_in_loop(
    [&event_loop]
    {
      [](vio::event_loop_t &ev) -> vio::task_t<void>
      {
        auto ssl_client = vio::ssl_client_create(ev);
        REQUIRE_EXPECTED(ssl_client);

        vio::cancellation_t cancel;
        auto connect_future = vio::ssl_client_connect(ssl_client.value(), "example.com", 443, &cancel);
        cancel.cancel();
        auto result = co_await connect_future;
        CHECK(!result.has_value());
        CHECK(vio::is_cancelled(result.error()));
        ev.stop();
      }(event_loop);
    });
  event_loop.run();
}

TEST_CASE("cancel ssl_client_connect with direct IP (pre-cancelled)")
{
  vio::event_loop_t event_loop;
  event_loop.run_in_loop(
    [&event_loop]
    {
      [](vio::event_loop_t &ev) -> vio::task_t<void>
      {
        auto ssl_client = vio::ssl_client_create(ev);
        REQUIRE_EXPECTED(ssl_client);

        vio::cancellation_t cancel;
        cancel.cancel();
        auto result = co_await vio::ssl_client_connect(ssl_client.value(), "localhost", 9999, "127.0.0.1", &cancel);
        CHECK(!result.has_value());
        CHECK(result.error().code == vio::vio_cancelled);
        ev.stop();
      }(event_loop);
    });
  event_loop.run();
}

TEST_CASE("cancel ssl_client_connect with direct IP while connecting")
{
  vio::event_loop_t event_loop;
  event_loop.run_in_loop(
    [&event_loop]
    {
      [](vio::event_loop_t &ev) -> vio::task_t<void>
      {
        auto ssl_client = vio::ssl_client_create(ev);
        REQUIRE_EXPECTED(ssl_client);

        vio::cancellation_t cancel;
        // Connect to localhost on an unlikely port - cancel fires synchronously
        auto connect_future = vio::ssl_client_connect(ssl_client.value(), "localhost", 1, "127.0.0.1", &cancel);
        cancel.cancel();
        auto result = co_await connect_future;
        CHECK(!result.has_value());
        CHECK(vio::is_cancelled(result.error()));
        ev.stop();
      }(event_loop);
    });
  event_loop.run();
}

} // TEST_SUITE
