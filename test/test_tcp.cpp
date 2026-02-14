#include <ostream>

#include <doctest/doctest.h>
#include <numeric>
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

TEST_SUITE("TCP")
{
TEST_CASE("test basic tcp")
{
  vio::event_loop_t event_loop;

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

TEST_CASE("tcp echo multiple messages")
{
  vio::event_loop_t event_loop;
  bool data_verified = false;

  event_loop.run_in_loop(
    [&]() -> vio::task_t<void>
    {
      auto *ev = &event_loop;

      auto server_tcp_pair = get_ephemeral_port(*ev);
      REQUIRE_EXPECTED(server_tcp_pair);
      int port = server_tcp_pair->second;

      auto server_task = [](vio::tcp_server_t s) -> vio::task_t<void>
      {
        auto server = std::move(s);
        auto listen_result = co_await vio::tcp_listen(server, 10);
        REQUIRE_EXPECTED(listen_result);
        auto client_or_err = vio::tcp_accept(server);
        REQUIRE_EXPECTED(client_or_err);
        auto client = std::move(client_or_err.value());

        auto reader_or_err = vio::tcp_create_reader(client);
        REQUIRE_EXPECTED(reader_or_err);
        auto reader = std::move(reader_or_err.value());
        while (true)
        {
          auto read_result = co_await reader;
          if (!read_result.has_value())
            break;
          auto &data = read_result.value();
          auto write_result = co_await vio::write_tcp(client, reinterpret_cast<const uint8_t *>(data->base), data->len);
          REQUIRE_EXPECTED(write_result);
        }
      }(std::move(server_tcp_pair->first));

      co_await [](vio::event_loop_t &el, int p, bool &dv) -> vio::task_t<void>
      {
        auto client_or_err = vio::tcp_create(el);
        REQUIRE_EXPECTED(client_or_err);
        auto client = std::move(client_or_err.value());

        auto addr = vio::ip4_addr("127.0.0.1", p);
        REQUIRE_EXPECTED(addr);
        auto connect_result = co_await vio::tcp_connect(client, reinterpret_cast<const sockaddr *>(&addr.value()));
        REQUIRE_EXPECTED(connect_result);

        constexpr int num_messages = 10;
        std::string all_data;
        for (int i = 0; i < num_messages; i++)
          all_data += "message_" + std::to_string(i) + ";";

        auto write_result = co_await vio::write_tcp(client, reinterpret_cast<const uint8_t *>(all_data.data()), all_data.size());
        REQUIRE_EXPECTED(write_result);

        std::vector<char> received;
        auto reader_or_err = vio::tcp_create_reader(client);
        REQUIRE_EXPECTED(reader_or_err);
        auto reader = std::move(reader_or_err.value());
        while (received.size() < all_data.size())
        {
          auto read_result = co_await reader;
          if (!read_result.has_value())
            break;
          auto &data = read_result.value();
          received.insert(received.end(), data->base, data->base + data->len);
        }

        REQUIRE(received.size() >= all_data.size());
        std::string received_str(received.data(), all_data.size());
        REQUIRE(received_str == all_data);
        dv = true;
      }(event_loop, port, data_verified);

      co_await std::move(server_task);
      ev->stop();
    });

  event_loop.run();
  REQUIRE(data_verified);
}

TEST_CASE("tcp large data transfer")
{
  vio::event_loop_t event_loop;
  constexpr size_t data_size = 1024 * 1024; // 1MB
  bool data_verified = false;

  event_loop.run_in_loop(
    [&]() -> vio::task_t<void>
    {
      auto *ev = &event_loop;
      auto *dv = &data_verified;

      auto server_tcp_pair = get_ephemeral_port(*ev);
      REQUIRE_EXPECTED(server_tcp_pair);
      int port = server_tcp_pair->second;

      auto server_task = [](vio::tcp_server_t s, size_t ds) -> vio::task_t<void>
      {
        auto server = std::move(s);
        auto listen_result = co_await vio::tcp_listen(server, 10);
        REQUIRE_EXPECTED(listen_result);
        auto client_or_err = vio::tcp_accept(server);
        REQUIRE_EXPECTED(client_or_err);
        auto client = std::move(client_or_err.value());

        std::vector<char> received;
        auto reader_or_err = vio::tcp_create_reader(client);
        REQUIRE_EXPECTED(reader_or_err);
        auto reader = std::move(reader_or_err.value());
        while (true)
        {
          auto read_result = co_await reader;
          if (!read_result.has_value())
            break;
          auto &data = read_result.value();
          received.insert(received.end(), data->base, data->base + data->len);
        }

        REQUIRE(received.size() == ds);
      }(std::move(server_tcp_pair->first), data_size);

      co_await [](vio::event_loop_t &el, int p, size_t ds) -> vio::task_t<void>
      {
        auto client_or_err = vio::tcp_create(el);
        REQUIRE_EXPECTED(client_or_err);
        auto client = std::move(client_or_err.value());

        auto addr = vio::ip4_addr("127.0.0.1", p);
        REQUIRE_EXPECTED(addr);
        auto connect_result = co_await vio::tcp_connect(client, reinterpret_cast<const sockaddr *>(&addr.value()));
        REQUIRE_EXPECTED(connect_result);

        std::vector<uint8_t> send_data(ds);
        std::iota(send_data.begin(), send_data.end(), uint8_t(0));

        auto write_result = co_await vio::write_tcp(client, send_data.data(), send_data.size());
        REQUIRE_EXPECTED(write_result);
      }(event_loop, port, data_size);

      co_await std::move(server_task);
      *dv = true;
      ev->stop();
    });

  event_loop.run();
  REQUIRE(data_verified);
}

TEST_CASE("tcp large data round trip")
{
  vio::event_loop_t event_loop;
  constexpr size_t data_size = 256 * 1024; // 256KB
  bool data_verified = false;

  event_loop.run_in_loop(
    [&]() -> vio::task_t<void>
    {
      auto *ev = &event_loop;

      auto server_tcp_pair = get_ephemeral_port(*ev);
      REQUIRE_EXPECTED(server_tcp_pair);
      int port = server_tcp_pair->second;

      auto server_task = [](vio::tcp_server_t s, size_t ds) -> vio::task_t<void>
      {
        auto server = std::move(s);
        auto listen_result = co_await vio::tcp_listen(server, 10);
        REQUIRE_EXPECTED(listen_result);
        auto client_or_err = vio::tcp_accept(server);
        REQUIRE_EXPECTED(client_or_err);
        auto client = std::move(client_or_err.value());

        size_t total_read = 0;
        std::vector<char> received;
        received.reserve(ds);
        auto reader_or_err = vio::tcp_create_reader(client);
        REQUIRE_EXPECTED(reader_or_err);
        auto reader = std::move(reader_or_err.value());
        while (total_read < ds)
        {
          auto read_result = co_await reader;
          if (!read_result.has_value())
            break;
          auto &data = read_result.value();
          received.insert(received.end(), data->base, data->base + data->len);
          total_read += data->len;
        }
        REQUIRE(total_read == ds);

        auto write_result = co_await vio::write_tcp(client, reinterpret_cast<const uint8_t *>(received.data()), received.size());
        REQUIRE_EXPECTED(write_result);
      }(std::move(server_tcp_pair->first), data_size);

      co_await [](vio::event_loop_t &el, int p, size_t ds, bool &dv) -> vio::task_t<void>
      {
        auto client_or_err = vio::tcp_create(el);
        REQUIRE_EXPECTED(client_or_err);
        auto client = std::move(client_or_err.value());

        auto addr = vio::ip4_addr("127.0.0.1", p);
        REQUIRE_EXPECTED(addr);
        auto connect_result = co_await vio::tcp_connect(client, reinterpret_cast<const sockaddr *>(&addr.value()));
        REQUIRE_EXPECTED(connect_result);

        std::vector<uint8_t> send_data(ds);
        std::iota(send_data.begin(), send_data.end(), uint8_t(0));

        auto write_result = co_await vio::write_tcp(client, send_data.data(), send_data.size());
        REQUIRE_EXPECTED(write_result);

        size_t total_read = 0;
        std::vector<char> received;
        received.reserve(ds);
        auto reader_or_err = vio::tcp_create_reader(client);
        REQUIRE_EXPECTED(reader_or_err);
        auto reader = std::move(reader_or_err.value());
        while (total_read < ds)
        {
          auto read_result = co_await reader;
          if (!read_result.has_value())
            break;
          auto &data = read_result.value();
          received.insert(received.end(), data->base, data->base + data->len);
          total_read += data->len;
        }
        REQUIRE(total_read == ds);
        REQUIRE(std::memcmp(received.data(), send_data.data(), ds) == 0);
        dv = true;
      }(event_loop, port, data_size, data_verified);

      co_await std::move(server_task);
      ev->stop();
    });

  event_loop.run();
  REQUIRE(data_verified);
}

TEST_CASE("tcp client disconnect causes server EOF")
{
  vio::event_loop_t event_loop;
  bool server_got_eof = false;

  event_loop.run_in_loop(
    [&]() -> vio::task_t<void>
    {
      auto *ev = &event_loop;

      auto server_tcp_pair = get_ephemeral_port(*ev);
      REQUIRE_EXPECTED(server_tcp_pair);
      int port = server_tcp_pair->second;

      auto server_task = [](vio::tcp_server_t s, bool &got_eof) -> vio::task_t<void>
      {
        auto server = std::move(s);
        auto listen_result = co_await vio::tcp_listen(server, 10);
        REQUIRE_EXPECTED(listen_result);
        auto client_or_err = vio::tcp_accept(server);
        REQUIRE_EXPECTED(client_or_err);
        auto client = std::move(client_or_err.value());

        auto reader_or_err = vio::tcp_create_reader(client);
        REQUIRE_EXPECTED(reader_or_err);
        auto reader = std::move(reader_or_err.value());
        auto read_result = co_await reader;
        REQUIRE(!read_result.has_value());
        REQUIRE(read_result.error().code == UV_EOF);
        got_eof = true;
      }(std::move(server_tcp_pair->first), server_got_eof);

      // Client as temporary: frame destroyed after co_await, closing TCP -> server gets EOF
      co_await [](vio::event_loop_t &el, int p) -> vio::task_t<void>
      {
        auto client_or_err = vio::tcp_create(el);
        REQUIRE_EXPECTED(client_or_err);
        auto client = std::move(client_or_err.value());

        auto addr = vio::ip4_addr("127.0.0.1", p);
        REQUIRE_EXPECTED(addr);
        auto connect_result = co_await vio::tcp_connect(client, reinterpret_cast<const sockaddr *>(&addr.value()));
        REQUIRE_EXPECTED(connect_result);
      }(event_loop, port);

      co_await std::move(server_task);
      ev->stop();
    });

  event_loop.run();
  REQUIRE(server_got_eof);
}

TEST_CASE("tcp server disconnect causes client EOF")
{
  vio::event_loop_t event_loop;
  bool client_got_eof = false;

  event_loop.run_in_loop(
    [&]() -> vio::task_t<void>
    {
      auto *ev = &event_loop;

      auto server_tcp_pair = get_ephemeral_port(*ev);
      REQUIRE_EXPECTED(server_tcp_pair);
      int port = server_tcp_pair->second;

      // Server as named task: created first so uv_listen() is called before client connects
      auto server_task = [](vio::tcp_server_t s) -> vio::task_t<void>
      {
        auto server = std::move(s);
        auto listen_result = co_await vio::tcp_listen(server, 10);
        REQUIRE_EXPECTED(listen_result);
        auto client_or_err = vio::tcp_accept(server);
        REQUIRE_EXPECTED(client_or_err);

        auto client = std::move(client_or_err.value());
        auto reader_or_err = vio::tcp_create_reader(client);
        REQUIRE_EXPECTED(reader_or_err);
        auto reader = std::move(reader_or_err.value());
        auto read_result = co_await reader;
        REQUIRE_EXPECTED(read_result);
      }(std::move(server_tcp_pair->first));

      // Client as named task: server is already listening by now
      auto client_task = [](vio::event_loop_t &el, int p, bool &got_eof) -> vio::task_t<void>
      {
        auto client_or_err = vio::tcp_create(el);
        REQUIRE_EXPECTED(client_or_err);
        auto client = std::move(client_or_err.value());

        auto addr = vio::ip4_addr("127.0.0.1", p);
        REQUIRE_EXPECTED(addr);
        auto connect_result = co_await vio::tcp_connect(client, reinterpret_cast<const sockaddr *>(&addr.value()));
        REQUIRE_EXPECTED(connect_result);

        std::string msg = "ping";
        auto write_result = co_await vio::write_tcp(client, reinterpret_cast<const uint8_t *>(msg.data()), msg.size());
        REQUIRE_EXPECTED(write_result);

        auto reader_or_err = vio::tcp_create_reader(client);
        REQUIRE_EXPECTED(reader_or_err);
        auto reader = std::move(reader_or_err.value());
        auto read_result = co_await reader;
        REQUIRE(!read_result.has_value());
        got_eof = true;
      }(event_loop, port, client_got_eof);

      // Wait for server to finish reading, then destroy its frame to close
      // the accepted connection — this triggers EOF on the client side
      co_await std::move(server_task);
      { auto tmp = std::move(server_task); }

      co_await std::move(client_task);
      ev->stop();
    });

  event_loop.run();
  REQUIRE(client_got_eof);
}

TEST_CASE("tcp multiple clients to same server")
{
  vio::event_loop_t event_loop;
  constexpr int num_clients = 5;
  int clients_served = 0;
  int clients_replied = 0;

  event_loop.run_in_loop(
    [&]() -> vio::task_t<void>
    {
      auto *ev = &event_loop;

      auto server_tcp_pair = get_ephemeral_port(*ev);
      REQUIRE_EXPECTED(server_tcp_pair);
      int port = server_tcp_pair->second;

      auto server_task = [](vio::tcp_server_t s, int nc, int &served) -> vio::task_t<void>
      {
        auto server = std::move(s);
        for (int i = 0; i < nc; i++)
        {
          auto listen_result = co_await vio::tcp_listen(server, 10);
          REQUIRE_EXPECTED(listen_result);
          auto client_or_err = vio::tcp_accept(server);
          REQUIRE_EXPECTED(client_or_err);
          auto client = std::move(client_or_err.value());
          server.tcp.handle->listen.done = false;

          auto reader_or_err = vio::tcp_create_reader(client);
          REQUIRE_EXPECTED(reader_or_err);
          auto reader = std::move(reader_or_err.value());
          auto read_result = co_await reader;
          REQUIRE_EXPECTED(read_result);
          served++;

          auto &data = read_result.value();
          auto write_result = co_await vio::write_tcp(client, reinterpret_cast<const uint8_t *>(data->base), data->len);
          REQUIRE_EXPECTED(write_result);
        }
      }(std::move(server_tcp_pair->first), num_clients, clients_served);

      // Each client is a separate connection
      co_await [](vio::event_loop_t &el, int p, int nc, int &cr) -> vio::task_t<void>
      {
        for (int i = 0; i < nc; i++)
        {
          auto client_or_err = vio::tcp_create(el);
          REQUIRE_EXPECTED(client_or_err);
          auto client = std::move(client_or_err.value());

          auto addr = vio::ip4_addr("127.0.0.1", p);
          REQUIRE_EXPECTED(addr);
          auto connect_result = co_await vio::tcp_connect(client, reinterpret_cast<const sockaddr *>(&addr.value()));
          REQUIRE_EXPECTED(connect_result);

          std::string msg = "client_" + std::to_string(i);
          auto write_result = co_await vio::write_tcp(client, reinterpret_cast<const uint8_t *>(msg.data()), msg.size());
          REQUIRE_EXPECTED(write_result);

          auto reader_or_err = vio::tcp_create_reader(client);
          REQUIRE_EXPECTED(reader_or_err);
          auto reader = std::move(reader_or_err.value());
          auto read_result = co_await reader;
          REQUIRE_EXPECTED(read_result);
          auto &data = read_result.value();
          std::string_view sv(data->base, data->len);
          REQUIRE(sv == msg);
          cr++;
        }
      }(event_loop, port, num_clients, clients_replied);

      co_await std::move(server_task);
      ev->stop();
    });

  event_loop.run();
  REQUIRE(clients_served == num_clients);
  REQUIRE(clients_replied == num_clients);
}

TEST_CASE("tcp cancel reader")
{
  vio::event_loop_t event_loop;
  bool reader_cancelled = false;

  event_loop.run_in_loop(
    [&]() -> vio::task_t<void>
    {
      auto *ev = &event_loop;

      auto server_tcp_pair = get_ephemeral_port(*ev);
      REQUIRE_EXPECTED(server_tcp_pair);
      int port = server_tcp_pair->second;

      auto server_task = [](vio::tcp_server_t s) -> vio::task_t<void>
      {
        auto server = std::move(s);
        auto listen_result = co_await vio::tcp_listen(server, 10);
        REQUIRE_EXPECTED(listen_result);
        auto client_or_err = vio::tcp_accept(server);
        REQUIRE_EXPECTED(client_or_err);
        auto client = std::move(client_or_err.value());

        auto reader_or_err = vio::tcp_create_reader(client);
        REQUIRE_EXPECTED(reader_or_err);
        auto reader = std::move(reader_or_err.value());
        auto read_result = co_await reader;
      }(std::move(server_tcp_pair->first));

      co_await [](vio::event_loop_t &el, int p, bool &cancelled) -> vio::task_t<void>
      {
        auto client_or_err = vio::tcp_create(el);
        REQUIRE_EXPECTED(client_or_err);
        auto client = std::move(client_or_err.value());

        auto addr = vio::ip4_addr("127.0.0.1", p);
        REQUIRE_EXPECTED(addr);
        auto connect_result = co_await vio::tcp_connect(client, reinterpret_cast<const sockaddr *>(&addr.value()));
        REQUIRE_EXPECTED(connect_result);

        auto reader_or_err = vio::tcp_create_reader(client);
        REQUIRE_EXPECTED(reader_or_err);
        auto reader = std::move(reader_or_err.value());

        reader.cancel();
        REQUIRE(reader.is_cancelled());

        auto read_result = co_await reader;
        REQUIRE(!read_result.has_value());
        REQUIRE(read_result.error().code == UV_ECANCELED);
        cancelled = true;
      }(event_loop, port, reader_cancelled);

      co_await std::move(server_task);
      ev->stop();
    });

  event_loop.run();
  REQUIRE(reader_cancelled);
}

TEST_CASE("tcp cannot create multiple active readers")
{
  vio::event_loop_t event_loop;
  bool error_caught = false;

  event_loop.run_in_loop(
    [&]() -> vio::task_t<void>
    {
      auto *ev = &event_loop;

      auto server_tcp_pair = get_ephemeral_port(*ev);
      REQUIRE_EXPECTED(server_tcp_pair);
      int port = server_tcp_pair->second;

      auto server_task = [](vio::tcp_server_t s) -> vio::task_t<void>
      {
        auto server = std::move(s);
        auto listen_result = co_await vio::tcp_listen(server, 10);
        REQUIRE_EXPECTED(listen_result);
        auto client_or_err = vio::tcp_accept(server);
        REQUIRE_EXPECTED(client_or_err);
        auto client = std::move(client_or_err.value());
        auto reader_or_err = vio::tcp_create_reader(client);
        REQUIRE_EXPECTED(reader_or_err);
        auto reader = std::move(reader_or_err.value());
        auto read_result = co_await reader;
      }(std::move(server_tcp_pair->first));

      co_await [](vio::event_loop_t &el, int p, bool &ec) -> vio::task_t<void>
      {
        auto client_or_err = vio::tcp_create(el);
        REQUIRE_EXPECTED(client_or_err);
        auto client = std::move(client_or_err.value());

        auto addr = vio::ip4_addr("127.0.0.1", p);
        REQUIRE_EXPECTED(addr);
        auto connect_result = co_await vio::tcp_connect(client, reinterpret_cast<const sockaddr *>(&addr.value()));
        REQUIRE_EXPECTED(connect_result);

        auto reader1 = vio::tcp_create_reader(client);
        REQUIRE_EXPECTED(reader1);

        auto reader2 = vio::tcp_create_reader(client);
        REQUIRE(!reader2.has_value());
        ec = true;
      }(event_loop, port, error_caught);

      co_await std::move(server_task);
      ev->stop();
    });

  event_loop.run();
  REQUIRE(error_caught);
}

TEST_CASE("tcp connect to unreachable address")
{
  vio::event_loop_t event_loop;
  bool connect_failed = false;

  event_loop.run_in_loop(
    [&]() -> vio::task_t<void>
    {
      auto *ev = &event_loop;
      auto *cf = &connect_failed;

      auto client_or_err = vio::tcp_create(*ev);
      REQUIRE_EXPECTED(client_or_err);
      auto client = std::move(client_or_err.value());

      auto addr = vio::ip4_addr("127.0.0.1", 1);
      REQUIRE_EXPECTED(addr);
      auto connect_result = co_await vio::tcp_connect(client, reinterpret_cast<const sockaddr *>(&addr.value()));
      REQUIRE(!connect_result.has_value());
      *cf = true;
      ev->stop();
    });

  event_loop.run();
  REQUIRE(connect_failed);
}

TEST_CASE("tcp write then read on same connection")
{
  vio::event_loop_t event_loop;
  bool verified = false;

  event_loop.run_in_loop(
    [&]() -> vio::task_t<void>
    {
      auto *ev = &event_loop;

      auto server_tcp_pair = get_ephemeral_port(*ev);
      REQUIRE_EXPECTED(server_tcp_pair);
      int port = server_tcp_pair->second;

      auto server_task = [](vio::tcp_server_t s) -> vio::task_t<void>
      {
        auto server = std::move(s);
        auto listen_result = co_await vio::tcp_listen(server, 10);
        REQUIRE_EXPECTED(listen_result);
        auto client_or_err = vio::tcp_accept(server);
        REQUIRE_EXPECTED(client_or_err);
        auto client = std::move(client_or_err.value());

        std::string msg = "server_first";
        auto write_result = co_await vio::write_tcp(client, reinterpret_cast<const uint8_t *>(msg.data()), msg.size());
        REQUIRE_EXPECTED(write_result);

        auto reader_or_err = vio::tcp_create_reader(client);
        REQUIRE_EXPECTED(reader_or_err);
        auto reader = std::move(reader_or_err.value());
        auto read_result = co_await reader;
        REQUIRE_EXPECTED(read_result);
        auto &data = read_result.value();
        std::string_view sv(data->base, data->len);
        REQUIRE(sv == "client_response");
      }(std::move(server_tcp_pair->first));

      co_await [](vio::event_loop_t &el, int p, bool &v) -> vio::task_t<void>
      {
        auto client_or_err = vio::tcp_create(el);
        REQUIRE_EXPECTED(client_or_err);
        auto client = std::move(client_or_err.value());

        auto addr = vio::ip4_addr("127.0.0.1", p);
        REQUIRE_EXPECTED(addr);
        auto connect_result = co_await vio::tcp_connect(client, reinterpret_cast<const sockaddr *>(&addr.value()));
        REQUIRE_EXPECTED(connect_result);

        auto reader_or_err = vio::tcp_create_reader(client);
        REQUIRE_EXPECTED(reader_or_err);
        auto reader = std::move(reader_or_err.value());
        auto read_result = co_await reader;
        REQUIRE_EXPECTED(read_result);
        auto &data = read_result.value();
        std::string_view sv(data->base, data->len);
        REQUIRE(sv == "server_first");

        reader.cancel();
        { auto temp = std::move(reader); }

        std::string msg = "client_response";
        auto write_result = co_await vio::write_tcp(client, reinterpret_cast<const uint8_t *>(msg.data()), msg.size());
        REQUIRE_EXPECTED(write_result);
        v = true;
      }(event_loop, port, verified);

      co_await std::move(server_task);
      ev->stop();
    });

  event_loop.run();
  REQUIRE(verified);
}

TEST_CASE("tcp reader destroyed then new reader created")
{
  vio::event_loop_t event_loop;
  bool verified = false;

  event_loop.run_in_loop(
    [&]() -> vio::task_t<void>
    {
      auto *ev = &event_loop;

      auto server_tcp_pair = get_ephemeral_port(*ev);
      REQUIRE_EXPECTED(server_tcp_pair);
      int port = server_tcp_pair->second;

      auto server_task = [](vio::tcp_server_t s) -> vio::task_t<void>
      {
        auto server = std::move(s);
        auto listen_result = co_await vio::tcp_listen(server, 10);
        REQUIRE_EXPECTED(listen_result);
        auto client_or_err = vio::tcp_accept(server);
        REQUIRE_EXPECTED(client_or_err);
        auto client = std::move(client_or_err.value());

        std::string msg1 = "first";
        auto write1 = co_await vio::write_tcp(client, reinterpret_cast<const uint8_t *>(msg1.data()), msg1.size());
        REQUIRE_EXPECTED(write1);

        {
          auto reader_or_err = vio::tcp_create_reader(client);
          REQUIRE_EXPECTED(reader_or_err);
          auto reader = std::move(reader_or_err.value());
          auto read_result = co_await reader;
          REQUIRE_EXPECTED(read_result);
        }

        std::string msg2 = "second";
        auto write2 = co_await vio::write_tcp(client, reinterpret_cast<const uint8_t *>(msg2.data()), msg2.size());
        REQUIRE_EXPECTED(write2);
      }(std::move(server_tcp_pair->first));

      co_await [](vio::event_loop_t &el, int p, bool &v) -> vio::task_t<void>
      {
        auto client_or_err = vio::tcp_create(el);
        REQUIRE_EXPECTED(client_or_err);
        auto client = std::move(client_or_err.value());

        auto addr = vio::ip4_addr("127.0.0.1", p);
        REQUIRE_EXPECTED(addr);
        auto connect_result = co_await vio::tcp_connect(client, reinterpret_cast<const sockaddr *>(&addr.value()));
        REQUIRE_EXPECTED(connect_result);

        {
          auto reader_or_err = vio::tcp_create_reader(client);
          REQUIRE_EXPECTED(reader_or_err);
          auto reader = std::move(reader_or_err.value());
          auto read_result = co_await reader;
          REQUIRE_EXPECTED(read_result);
          auto &data = read_result.value();
          std::string_view sv(data->base, data->len);
          REQUIRE(sv == "first");
        }

        std::string ack = "ack";
        auto write_result = co_await vio::write_tcp(client, reinterpret_cast<const uint8_t *>(ack.data()), ack.size());
        REQUIRE_EXPECTED(write_result);

        {
          auto reader_or_err = vio::tcp_create_reader(client);
          REQUIRE_EXPECTED(reader_or_err);
          auto reader = std::move(reader_or_err.value());
          auto read_result = co_await reader;
          REQUIRE_EXPECTED(read_result);
          auto &data = read_result.value();
          std::string_view sv(data->base, data->len);
          REQUIRE(sv == "second");
        }

        v = true;
      }(event_loop, port, verified);

      co_await std::move(server_task);
      ev->stop();
    });

  event_loop.run();
  REQUIRE(verified);
}

TEST_CASE("tcp ipv6 loopback")
{
  vio::event_loop_t event_loop;
  bool verified = false;

  event_loop.run_in_loop(
    [&]() -> vio::task_t<void>
    {
      auto *ev = &event_loop;

      auto addr_or_err = vio::ip6_addr("::1", 0);
      REQUIRE_EXPECTED(addr_or_err);
      auto server_tcp = vio::tcp_create_server(*ev);
      REQUIRE_EXPECTED(server_tcp);
      auto bind_res = vio::tcp_bind(server_tcp.value(), reinterpret_cast<const sockaddr *>(&addr_or_err.value()));
      REQUIRE_EXPECTED(bind_res);

      auto sockname_result = vio::sockname(server_tcp->tcp);
      REQUIRE_EXPECTED(sockname_result);
      sockaddr_storage sa_storage = sockname_result.value();
      const auto *sa_in6 = reinterpret_cast<sockaddr_in6 *>(&sa_storage);
      int port = ntohs(sa_in6->sin6_port);

      auto server_task = [](vio::tcp_server_t s) -> vio::task_t<void>
      {
        auto server = std::move(s);
        auto listen_result = co_await vio::tcp_listen(server, 10);
        REQUIRE_EXPECTED(listen_result);
        auto client_or_err = vio::tcp_accept(server);
        REQUIRE_EXPECTED(client_or_err);
        auto client = std::move(client_or_err.value());

        auto reader_or_err = vio::tcp_create_reader(client);
        REQUIRE_EXPECTED(reader_or_err);
        auto reader = std::move(reader_or_err.value());
        auto read_result = co_await reader;
        REQUIRE_EXPECTED(read_result);

        auto &data = read_result.value();
        auto write_result = co_await vio::write_tcp(client, reinterpret_cast<const uint8_t *>(data->base), data->len);
        REQUIRE_EXPECTED(write_result);
      }(std::move(server_tcp.value()));

      co_await [](vio::event_loop_t &el, int p, bool &v) -> vio::task_t<void>
      {
        auto client_or_err = vio::tcp_create(el);
        REQUIRE_EXPECTED(client_or_err);
        auto client = std::move(client_or_err.value());

        auto addr = vio::ip6_addr("::1", p);
        REQUIRE_EXPECTED(addr);
        auto connect_result = co_await vio::tcp_connect(client, reinterpret_cast<const sockaddr *>(&addr.value()));
        REQUIRE_EXPECTED(connect_result);

        std::string msg = "ipv6_test";
        auto write_result = co_await vio::write_tcp(client, reinterpret_cast<const uint8_t *>(msg.data()), msg.size());
        REQUIRE_EXPECTED(write_result);

        auto reader_or_err = vio::tcp_create_reader(client);
        REQUIRE_EXPECTED(reader_or_err);
        auto reader = std::move(reader_or_err.value());
        auto read_result = co_await reader;
        REQUIRE_EXPECTED(read_result);
        auto &data = read_result.value();
        std::string_view sv(data->base, data->len);
        REQUIRE(sv == "ipv6_test");
        v = true;
      }(event_loop, port, verified);

      co_await std::move(server_task);
      ev->stop();
    });

  event_loop.run();
  REQUIRE(verified);
}

TEST_CASE("tcp sockname returns correct address")
{
  vio::event_loop_t event_loop;

  auto addr_or_err = vio::ip4_addr("127.0.0.1", 0);
  REQUIRE_EXPECTED(addr_or_err);
  auto server_tcp = vio::tcp_create_server(event_loop);
  REQUIRE_EXPECTED(server_tcp);
  auto bind_res = vio::tcp_bind(server_tcp.value(), reinterpret_cast<const sockaddr *>(&addr_or_err.value()));
  REQUIRE_EXPECTED(bind_res);

  auto sockname_result = vio::sockname(server_tcp->tcp);
  REQUIRE_EXPECTED(sockname_result);

  sockaddr_storage sa_storage = sockname_result.value();
  REQUIRE(sa_storage.ss_family == AF_INET);
  const auto *sa_in = reinterpret_cast<sockaddr_in *>(&sa_storage);
  REQUIRE(ntohs(sa_in->sin_port) > 0);

  // Cleanup: destroy server then run event loop to process uv_close callbacks
  { auto tmp = std::move(server_tcp); }
  event_loop.stop();
  event_loop.run();
}
} // TEST_SUITE

} // namespace
