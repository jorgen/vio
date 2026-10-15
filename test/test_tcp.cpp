/*
Copyright (c) 2025 Jørgen Lind

  Permission is hereby granted, free of charge, to any person obtaining a copy of
  this software and associated documentation files (the "Software"), to deal in
  the Software without restriction, including without limitation the rights to
  use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
  of the Software, and to permit persons to whom the Software is furnished to do
  so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
*/

#include <chrono>
#include <cstring>
#include <optional>
#include <ostream>

#include <doctest/doctest.h>
#include <numeric>
#include <string>
#include <string_view>
#include <utility>
#include <vio/error.h>
#include <vio/event_loop.h>
#include <vio/operation/sleep.h>
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
  const std::string_view sv(read_data.chars(), read_data.size());
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

struct tcp_pair_t
{
  vio::tcp_t client;
  vio::tcp_t server;
};

vio::task_t<std::optional<tcp_pair_t>> connected_pair(vio::event_loop_t &loop)
{
  auto server_and_port = get_ephemeral_port(loop);
  REQUIRE_EXPECTED(server_and_port);
  auto server = std::move(server_and_port->first);
  auto address = vio::ip4_addr("127.0.0.1", server_and_port->second);
  REQUIRE_EXPECTED(address);
  auto listening = vio::tcp_listen(server, 8);
  auto client = vio::tcp_create(loop);
  REQUIRE_EXPECTED(client);
  auto connected = co_await vio::tcp_connect(client.value(), reinterpret_cast<const sockaddr *>(&address.value()));
  REQUIRE_EXPECTED(connected);
  auto ready = co_await std::move(listening);
  REQUIRE_EXPECTED(ready);
  auto accepted = vio::tcp_accept(server);
  REQUIRE_EXPECTED(accepted);
  co_return tcp_pair_t{std::move(client.value()), std::move(accepted.value())};
}

template <typename Scenario>
void run_tcp_scenario(Scenario &&scenario)
{
  vio::event_loop_t loop;
  loop.run_in_loop([&] {
    return [](vio::event_loop_t &loop, Scenario &scenario) -> vio::task_t<void> {
      co_await scenario(loop);
      loop.stop();
    }(loop, scenario);
  });
  loop.run();
}

vio::task_t<void> pause_scenario(vio::event_loop_t &loop, bool &done_while_paused, std::string &received)
{
  auto pair = co_await connected_pair(loop);
  REQUIRE(pair.has_value());
  auto reader = vio::tcp_create_reader(pair->server);
  REQUIRE_EXPECTED(reader);
  reader->pause();
  bool done = false;
  auto read_task = [](vio::tcp_reader_t &reader, bool &done, std::string &received) -> vio::task_t<void> {
    auto chunk = co_await reader;
    REQUIRE_EXPECTED(chunk);
    received.assign(chunk->chars(), chunk->size());
    done = true;
  }(reader.value(), done, received);

  const std::string payload = "ping";
  auto written = co_await vio::write_tcp(pair->client, reinterpret_cast<const uint8_t *>(payload.data()), payload.size());
  REQUIRE_EXPECTED(written);
  [[maybe_unused]] auto slept = co_await vio::sleep(loop, std::chrono::milliseconds(30));
  done_while_paused = done;
  reader->resume();
  co_await std::move(read_task);
}

vio::task_t<void> peer_ip_scenario(vio::event_loop_t &loop, std::string &client_view, std::string &server_view, std::string &unconnected_view)
{
  auto pair = co_await connected_pair(loop);
  REQUIRE(pair.has_value());
  client_view = vio::peer_ip(pair->client);
  server_view = vio::peer_ip(pair->server);
  auto lone = vio::tcp_create(loop);
  REQUIRE_EXPECTED(lone);
  unconnected_view = vio::peer_ip(lone.value());
}

vio::task_t<void> write_while_connecting_scenario(vio::event_loop_t &loop, std::string &received, bool &write_ok)
{
  auto server_and_port = get_ephemeral_port(loop);
  REQUIRE_EXPECTED(server_and_port);
  auto server = std::move(server_and_port->first);
  auto address = vio::ip4_addr("127.0.0.1", server_and_port->second);
  REQUIRE_EXPECTED(address);
  auto listening = vio::tcp_listen(server, 8);

  auto client = vio::tcp_create(loop);
  REQUIRE_EXPECTED(client);
  auto connecting = vio::tcp_connect(client.value(), reinterpret_cast<const sockaddr *>(&address.value()));
  auto early = vio::write_tcp(client.value(), std::string("early"));
  auto connected = co_await std::move(connecting);
  REQUIRE_EXPECTED(connected);
  auto written = co_await std::move(early);
  write_ok = written.has_value();

  auto ready = co_await std::move(listening);
  REQUIRE_EXPECTED(ready);
  auto accepted = vio::tcp_accept(server);
  REQUIRE_EXPECTED(accepted);
  auto reader = vio::tcp_create_reader(accepted.value());
  REQUIRE_EXPECTED(reader);
  while (received.size() < 5)
  {
    auto chunk = co_await reader.value();
    REQUIRE_EXPECTED(chunk);
    received.append(chunk->chars(), chunk->size());
  }
}

vio::task_t<void> refused_reader_scenario(vio::event_loop_t &loop, bool &connect_failed, bool &read_resolved, bool &read_failed)
{
  auto client = vio::tcp_create(loop);
  REQUIRE_EXPECTED(client);
  auto address = vio::ip4_addr("127.0.0.1", 1);
  REQUIRE_EXPECTED(address);
  auto connecting = vio::tcp_connect(client.value(), reinterpret_cast<const sockaddr *>(&address.value()));
  auto reader = vio::tcp_create_reader(client.value());
  REQUIRE_EXPECTED(reader);
  bool done = false;
  auto read_task = [](vio::tcp_reader_t &reader, bool &done, bool &failed) -> vio::task_t<void> {
    auto chunk = co_await reader;
    failed = !chunk.has_value() && chunk.error().code != vio::errc::canceled;
    done = true;
  }(reader.value(), done, read_failed);
  auto connected = co_await std::move(connecting);
  connect_failed = !connected.has_value();
  [[maybe_unused]] auto slept = co_await vio::sleep(loop, std::chrono::milliseconds(50));
  read_resolved = done;
  if (!done)
    reader->cancel();
  co_await std::move(read_task);
}

vio::task_t<void> connect_cancel_scenario(vio::event_loop_t &loop, int &code)
{
  auto server_and_port = get_ephemeral_port(loop);
  REQUIRE_EXPECTED(server_and_port);
  auto address = vio::ip4_addr("127.0.0.1", server_and_port->second);
  REQUIRE_EXPECTED(address);
  auto listening = vio::tcp_listen(server_and_port->first, 8);
  auto client = vio::tcp_create(loop);
  REQUIRE_EXPECTED(client);
  vio::cancellation_t token;
  auto connecting = vio::tcp_connect(client.value(), reinterpret_cast<const sockaddr *>(&address.value()), &token);
  token.cancel();
  auto connected = co_await std::move(connecting);
  REQUIRE_FALSE(connected.has_value());
  code = connected.error().code;
}

vio::task_t<void> write_before_connect_scenario(vio::event_loop_t &loop, int &early_code, int &reader_code, bool &later_ok, std::string &received)
{
  auto server_and_port = get_ephemeral_port(loop);
  REQUIRE_EXPECTED(server_and_port);
  auto server = std::move(server_and_port->first);
  auto address = vio::ip4_addr("127.0.0.1", server_and_port->second);
  REQUIRE_EXPECTED(address);
  auto listening = vio::tcp_listen(server, 8);

  {
    auto client = vio::tcp_create(loop);
    REQUIRE_EXPECTED(client);
    vio::tcp_server_t bound_client{client.value()};
    auto local = vio::ip4_addr("127.0.0.1", 0);
    REQUIRE_EXPECTED(local);
    REQUIRE_EXPECTED(vio::tcp_bind(bound_client, reinterpret_cast<const sockaddr *>(&local.value())));

    auto early = co_await vio::write_tcp(client.value(), std::string("early"));
    REQUIRE_FALSE(early.has_value());
    early_code = early.error().code;
    auto reader = vio::tcp_create_reader(server.tcp);
    REQUIRE_FALSE(reader.has_value());
    reader_code = reader.error().code;

    auto connected = co_await vio::tcp_connect(client.value(), reinterpret_cast<const sockaddr *>(&address.value()));
    REQUIRE_EXPECTED(connected);
    auto later = co_await vio::write_tcp(client.value(), std::string("later"));
    later_ok = later.has_value();
  }

  auto ready = co_await std::move(listening);
  REQUIRE_EXPECTED(ready);
  auto accepted = vio::tcp_accept(server);
  REQUIRE_EXPECTED(accepted);
  auto peer_reader = vio::tcp_create_reader(accepted.value());
  REQUIRE_EXPECTED(peer_reader);
  for (;;)
  {
    auto chunk = co_await peer_reader.value();
    if (!chunk.has_value())
      break;
    received.append(chunk->chars(), chunk->size());
  }
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

  event_loop.run_in_loop([&] {
    return [](vio::event_loop_t &event_loop, bool &server_got_data, bool &server_wrote_msg, bool &client_got_server_reply) -> vio::task_t<void>
      {
        auto *ev = &event_loop;
        auto server_tcp_pair = get_ephemeral_port(*ev);
        REQUIRE_EXPECTED(server_tcp_pair);

        auto server = test_tcp_server(*ev, std::move(server_tcp_pair->first), server_tcp_pair->second, server_got_data, server_wrote_msg);
        co_await test_tcp_client(*ev, server_tcp_pair->second, client_got_server_reply);
        co_await std::move(server);

        ev->stop();
      }(event_loop, server_got_data, server_wrote_msg, client_got_server_reply);
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

  event_loop.run_in_loop([&] {
    return [](vio::event_loop_t &event_loop, bool &data_verified) -> vio::task_t<void>
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
            auto write_result = co_await vio::write_tcp(client, reinterpret_cast<const uint8_t *>(data.chars()), data.size());
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
            received.insert(received.end(), data.chars(), data.chars() + data.size());
          }

          REQUIRE(received.size() >= all_data.size());
          std::string received_str(received.data(), all_data.size());
          REQUIRE(received_str == all_data);
          dv = true;
        }(event_loop, port, data_verified);

        co_await std::move(server_task);
        ev->stop();
      }(event_loop, data_verified);
  });

  event_loop.run();
  REQUIRE(data_verified);
}

TEST_CASE("tcp large data transfer")
{
  vio::event_loop_t event_loop;
  constexpr size_t data_size = 1024 * 1024; // 1MB
  bool data_verified = false;

  event_loop.run_in_loop([&] {
    return [](vio::event_loop_t &event_loop, size_t data_size, bool &data_verified) -> vio::task_t<void>
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
            received.insert(received.end(), data.chars(), data.chars() + data.size());
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
        data_verified = true;
        ev->stop();
      }(event_loop, data_size, data_verified);
  });

  event_loop.run();
  REQUIRE(data_verified);
}

TEST_CASE("tcp large data round trip")
{
  vio::event_loop_t event_loop;
  constexpr size_t data_size = 256 * 1024; // 256KB
  bool data_verified = false;

  event_loop.run_in_loop([&] {
    return [](vio::event_loop_t &event_loop, size_t data_size, bool &data_verified) -> vio::task_t<void>
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
            received.insert(received.end(), data.chars(), data.chars() + data.size());
            total_read += data.size();
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
            received.insert(received.end(), data.chars(), data.chars() + data.size());
            total_read += data.size();
          }
          REQUIRE(total_read == ds);
          REQUIRE(std::memcmp(received.data(), send_data.data(), ds) == 0);
          dv = true;
        }(event_loop, port, data_size, data_verified);

        co_await std::move(server_task);
        ev->stop();
      }(event_loop, data_size, data_verified);
  });

  event_loop.run();
  REQUIRE(data_verified);
}

TEST_CASE("tcp client disconnect causes server EOF")
{
  vio::event_loop_t event_loop;
  bool server_got_eof = false;

  event_loop.run_in_loop([&] {
    return [](vio::event_loop_t &event_loop, bool &server_got_eof) -> vio::task_t<void>
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
          REQUIRE(read_result.error().code == vio::errc::eof);
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
      }(event_loop, server_got_eof);
  });

  event_loop.run();
  REQUIRE(server_got_eof);
}

TEST_CASE("tcp server disconnect causes client EOF")
{
  vio::event_loop_t event_loop;
  bool client_got_eof = false;

  event_loop.run_in_loop([&] {
    return [](vio::event_loop_t &event_loop, bool &client_got_eof) -> vio::task_t<void>
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
      }(event_loop, client_got_eof);
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

  event_loop.run_in_loop([&] {
    return [](vio::event_loop_t &event_loop, int num_clients, int &clients_served, int &clients_replied) -> vio::task_t<void>
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

            auto reader_or_err = vio::tcp_create_reader(client);
            REQUIRE_EXPECTED(reader_or_err);
            auto reader = std::move(reader_or_err.value());
            auto read_result = co_await reader;
            REQUIRE_EXPECTED(read_result);
            served++;

            auto &data = read_result.value();
            auto write_result = co_await vio::write_tcp(client, reinterpret_cast<const uint8_t *>(data.chars()), data.size());
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
            std::string_view sv(data.chars(), data.size());
            REQUIRE(sv == msg);
            cr++;
          }
        }(event_loop, port, num_clients, clients_replied);

        co_await std::move(server_task);
        ev->stop();
      }(event_loop, num_clients, clients_served, clients_replied);
  });

  event_loop.run();
  REQUIRE(clients_served == num_clients);
  REQUIRE(clients_replied == num_clients);
}

TEST_CASE("tcp cancel reader")
{
  vio::event_loop_t event_loop;
  bool reader_cancelled = false;

  event_loop.run_in_loop([&] {
    return [](vio::event_loop_t &event_loop, bool &reader_cancelled) -> vio::task_t<void>
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
          REQUIRE(read_result.error().code == vio::errc::canceled);
          cancelled = true;
        }(event_loop, port, reader_cancelled);

        co_await std::move(server_task);
        ev->stop();
      }(event_loop, reader_cancelled);
  });

  event_loop.run();
  REQUIRE(reader_cancelled);
}

TEST_CASE("tcp cannot create multiple active readers")
{
  vio::event_loop_t event_loop;
  bool error_caught = false;

  event_loop.run_in_loop([&] {
    return [](vio::event_loop_t &event_loop, bool &error_caught) -> vio::task_t<void>
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
      }(event_loop, error_caught);
  });

  event_loop.run();
  REQUIRE(error_caught);
}

TEST_CASE("tcp connect to unreachable address")
{
  vio::event_loop_t event_loop;
  bool connect_failed = false;

  event_loop.run_in_loop([&] {
    return [](vio::event_loop_t &event_loop, bool &connect_failed) -> vio::task_t<void>
      {
        auto *ev = &event_loop;

        auto client_or_err = vio::tcp_create(*ev);
        REQUIRE_EXPECTED(client_or_err);
        auto client = std::move(client_or_err.value());

        auto addr = vio::ip4_addr("127.0.0.1", 1);
        REQUIRE_EXPECTED(addr);
        auto connect_result = co_await vio::tcp_connect(client, reinterpret_cast<const sockaddr *>(&addr.value()));
        REQUIRE(!connect_result.has_value());
        connect_failed = true;
        ev->stop();
      }(event_loop, connect_failed);
  });

  event_loop.run();
  REQUIRE(connect_failed);
}

TEST_CASE("tcp write then read on same connection")
{
  vio::event_loop_t event_loop;
  bool verified = false;

  event_loop.run_in_loop([&] {
    return [](vio::event_loop_t &event_loop, bool &verified) -> vio::task_t<void>
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
          std::string_view sv(data.chars(), data.size());
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
          std::string_view sv(data.chars(), data.size());
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
      }(event_loop, verified);
  });

  event_loop.run();
  REQUIRE(verified);
}

TEST_CASE("tcp reader destroyed then new reader created")
{
  vio::event_loop_t event_loop;
  bool verified = false;

  event_loop.run_in_loop([&] {
    return [](vio::event_loop_t &event_loop, bool &verified) -> vio::task_t<void>
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
            std::string_view sv(data.chars(), data.size());
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
            std::string_view sv(data.chars(), data.size());
            REQUIRE(sv == "second");
          }

          v = true;
        }(event_loop, port, verified);

        co_await std::move(server_task);
        ev->stop();
      }(event_loop, verified);
  });

  event_loop.run();
  REQUIRE(verified);
}

TEST_CASE("tcp ipv6 loopback")
{
  vio::event_loop_t event_loop;
  bool verified = false;

  event_loop.run_in_loop([&] {
    return [](vio::event_loop_t &event_loop, bool &verified) -> vio::task_t<void>
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
          auto write_result = co_await vio::write_tcp(client, reinterpret_cast<const uint8_t *>(data.chars()), data.size());
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
          std::string_view sv(data.chars(), data.size());
          REQUIRE(sv == "ipv6_test");
          v = true;
        }(event_loop, port, verified);

        co_await std::move(server_task);
        ev->stop();
      }(event_loop, verified);
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

  { auto tmp = std::move(server_tcp); }
  event_loop.stop();
  event_loop.run();
}

TEST_CASE("tcp write cancel")
{
  vio::event_loop_t event_loop;
  bool verified = false;

  event_loop.run_in_loop([&] {
    return [](vio::event_loop_t &event_loop, bool &verified) -> vio::task_t<void>
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
          }
        }(std::move(server_tcp_pair->first));

        auto client_task = [](vio::event_loop_t &el, int p, bool &v) -> vio::task_t<void>
        {
          auto client_or_err = vio::tcp_create(el);
          REQUIRE_EXPECTED(client_or_err);
          auto client = std::move(client_or_err.value());

          auto addr = vio::ip4_addr("127.0.0.1", p);
          REQUIRE_EXPECTED(addr);
          auto connect_result = co_await vio::tcp_connect(client, reinterpret_cast<const sockaddr *>(&addr.value()));
          REQUIRE_EXPECTED(connect_result);

          std::vector<uint8_t> small_payload(16, 0x42);
          {
            vio::cancellation_t pre;
            pre.cancel();
            auto fut = vio::write_tcp(client, small_payload.data(), small_payload.size(), &pre);
            auto result = co_await fut;
            REQUIRE(!result.has_value());
            REQUIRE(vio::is_cancelled(result.error()));
          }

          std::vector<uint8_t> payload(64u * 1024u, 0x41);
          {
            vio::cancellation_t token;
            auto fut = vio::write_tcp(client, payload.data(), payload.size(), &token);
            token.cancel();
            auto result = co_await fut;
            REQUIRE(!result.has_value());
            REQUIRE(vio::is_cancelled(result.error()));
          }

          v = true;
        }(event_loop, port, verified);

        co_await std::move(client_task);
        { auto destroy = std::move(client_task); }
        co_await std::move(server_task);
        ev->stop();
      }(event_loop, verified);
  });

  event_loop.run();
  REQUIRE(verified);
}
TEST_CASE("tcp pause holds a waiting read until resume")
{
  bool done_while_paused = true;
  std::string received;
  run_tcp_scenario([&](vio::event_loop_t &loop) { return pause_scenario(loop, done_while_paused, received); });
  CHECK_FALSE(done_while_paused);
  CHECK(received == "ping");
}

TEST_CASE("tcp peer_ip names the connected peer")
{
  std::string client_view;
  std::string server_view;
  std::string unconnected_view = "unset";
  run_tcp_scenario([&](vio::event_loop_t &loop) { return peer_ip_scenario(loop, client_view, server_view, unconnected_view); });
  CHECK(client_view == "127.0.0.1");
  CHECK(server_view == "127.0.0.1");
  CHECK(unconnected_view.empty());
}

TEST_CASE("tcp address parsing")
{
  CHECK(vio::ip4_addr("127.0.0.1", 80).has_value());
  CHECK(ntohs(vio::ip4_addr("127.0.0.1", 8080)->sin_port) == 8080);
  auto bad4 = vio::ip4_addr("256.0.0.1", 80);
  REQUIRE_FALSE(bad4.has_value());
  CHECK(bad4.error().code == vio::errc::invalid_argument);
  CHECK_FALSE(vio::ip4_addr("not an address", 80).has_value());
  auto loopback6 = vio::ip6_addr("::1", 443);
  REQUIRE_EXPECTED(loopback6);
  CHECK(loopback6->sin6_family == AF_INET6);
  CHECK(ntohs(loopback6->sin6_port) == 443);
  auto scoped = vio::ip6_addr("fe80::1%7", 1);
  REQUIRE_EXPECTED(scoped);
  CHECK(scoped->sin6_scope_id == 7);
  auto bad6 = vio::ip6_addr("zz::1", 1);
  REQUIRE_FALSE(bad6.has_value());
  CHECK(bad6.error().code == vio::errc::invalid_argument);
}

TEST_CASE("tcp bind flags")
{
  vio::event_loop_t event_loop;
  {
    auto any = vio::ip4_addr("127.0.0.1", 0);
    REQUIRE_EXPECTED(any);
    auto first = vio::tcp_create_server(event_loop);
    REQUIRE_EXPECTED(first);
    auto bound = vio::tcp_bind(first.value(), reinterpret_cast<const sockaddr *>(&any.value()), vio::tcp_bind_flags::reuse_port);
#if defined(__linux__)
    REQUIRE_EXPECTED(bound);
    auto name = vio::sockname(first->tcp);
    REQUIRE_EXPECTED(name);
    auto port = ntohs(reinterpret_cast<const sockaddr_in *>(&name.value())->sin_port);
    auto same = vio::ip4_addr("127.0.0.1", port);
    REQUIRE_EXPECTED(same);
    auto first_listen = vio::tcp_listen(first.value(), 4);
    CHECK_FALSE(first_listen.done);

    auto second = vio::tcp_create_server(event_loop);
    REQUIRE_EXPECTED(second);
    auto shared = vio::tcp_bind(second.value(), reinterpret_cast<const sockaddr *>(&same.value()), vio::tcp_bind_flags::reuse_port);
    CHECK(shared.has_value());

    auto third = vio::tcp_create_server(event_loop);
    REQUIRE_EXPECTED(third);
    auto refused = vio::tcp_bind(third.value(), reinterpret_cast<const sockaddr *>(&same.value()));
    REQUIRE_FALSE(refused.has_value());
    CHECK(refused.error().code == vio::errc::address_in_use);
#else
    REQUIRE_FALSE(bound.has_value());
    CHECK(bound.error().code == vio::errc::not_supported);
#endif

    auto v4 = vio::tcp_create_server(event_loop);
    REQUIRE_EXPECTED(v4);
    auto only_on_v4 = vio::tcp_bind(v4.value(), reinterpret_cast<const sockaddr *>(&any.value()), vio::tcp_bind_flags::ipv6_only);
    REQUIRE_FALSE(only_on_v4.has_value());
    CHECK(only_on_v4.error().code == vio::errc::invalid_argument);

    auto wildcard6 = vio::ip6_addr("::", 0);
    REQUIRE_EXPECTED(wildcard6);
    auto v6only = vio::tcp_create_server(event_loop);
    REQUIRE_EXPECTED(v6only);
    auto bound6 = vio::tcp_bind(v6only.value(), reinterpret_cast<const sockaddr *>(&wildcard6.value()), vio::tcp_bind_flags::ipv6_only);
    if (!bound6.has_value() && bound6.error().code == vio::errc::address_family_not_supported)
    {
      MESSAGE("IPv6 is not available here; IPV6_V6ONLY is not checked");
    }
    else
    {
      REQUIRE_EXPECTED(bound6);
      int value = 0;
      int length = static_cast<int>(sizeof(value));
      REQUIRE(vio::detail::socket_get_option(v6only->tcp.handle->socket.native(), IPPROTO_IPV6, IPV6_V6ONLY, &value, length) == 0);
      CHECK(value == 1);

      auto dual = vio::tcp_create_server(event_loop);
      REQUIRE_EXPECTED(dual);
      REQUIRE_EXPECTED(vio::tcp_bind(dual.value(), reinterpret_cast<const sockaddr *>(&wildcard6.value())));
      length = static_cast<int>(sizeof(value));
      REQUIRE(vio::detail::socket_get_option(dual->tcp.handle->socket.native(), IPPROTO_IPV6, IPV6_V6ONLY, &value, length) == 0);
      CHECK(value == 0);
    }
  }
  event_loop.stop();
  event_loop.run();
}

TEST_CASE("tcp writes issued while connecting are sent once connected")
{
  std::string received;
  bool write_ok = false;
  run_tcp_scenario([&](vio::event_loop_t &loop) { return write_while_connecting_scenario(loop, received, write_ok); });
  CHECK(write_ok);
  CHECK(received == "early");
}

TEST_CASE("tcp a read waiting on a refused connect resolves with an error")
{
  bool connect_failed = false;
  bool read_resolved = false;
  bool read_failed = false;
  run_tcp_scenario([&](vio::event_loop_t &loop) { return refused_reader_scenario(loop, connect_failed, read_resolved, read_failed); });
  CHECK(connect_failed);
  CHECK(read_resolved);
  CHECK(read_failed);
}

TEST_CASE("tcp connect cancelled before it is awaited reports cancellation")
{
  int code = 0;
  run_tcp_scenario([&](vio::event_loop_t &loop) { return connect_cancel_scenario(loop, code); });
  CHECK(code == vio::vio_cancelled);
}
TEST_CASE("tcp a write before connecting fails without spoiling the socket")
{
  int early_code = 0;
  int reader_code = 0;
  bool later_ok = false;
  std::string received;
  run_tcp_scenario([&](vio::event_loop_t &loop) { return write_before_connect_scenario(loop, early_code, reader_code, later_ok, received); });
  CHECK(early_code == vio::errc::not_connected);
  CHECK(reader_code == vio::errc::not_connected);
  CHECK(later_ok);
  CHECK(received == "later");
}
} // TEST_SUITE

} // namespace
