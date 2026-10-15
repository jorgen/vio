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

#include <doctest/doctest.h>

#include <cstdint>
#include <string>
#include <string_view>

#include <vio/event_loop.h>
#include <vio/operation/tcp.h>
#include <vio/operation/tls_client.h>
#include <vio/operation/tls_server.h>
#include <vio/task.h>

#include "require_expected.h"
#include "tls_test_helpers.h"

// ssl_client_upgrade adopts an already-connected plaintext tcp_t and completes a
// TLS client handshake on it, verifying the server certificate against the CA and
// pinning the hostname. Exercised in-process against vio's own TLS server with
// small messages (the in-process large-transfer backpressure deadlock does not
// apply to a handshake + tiny echo).
TEST_CASE("ssl_client_upgrade: adopt a connected socket and TLS-handshake as a client")
{
  vio::event_loop_t event_loop;
  auto certs = vio_test::make_cert_set("localhost");
  const vio::ssl_config_t server_config{.ca_mem = certs.ca_cert, .cert_mem = certs.cert, .key_mem = certs.key};
  const vio::ssl_config_t client_config{.ca_mem = certs.ca_cert};

  constexpr int num_messages = 4;
  int server_received = 0;
  int client_received = 0;
  bool upgraded = false;

  event_loop.run_in_loop(
    [&]
    {
      return [](vio::event_loop_t &event_loop, vio::ssl_config_t server_config, vio::ssl_config_t client_config, int num_messages, int &server_received, int &client_received, bool &upgraded) -> vio::task_t<void>
      {
        auto *ev = &event_loop;
        auto server_tcp_pair = vio_test::get_ephemeral_port(*ev);
        REQUIRE_EXPECTED(server_tcp_pair);
        int port = server_tcp_pair->second;

        auto server_task = [](vio::event_loop_t &el, vio::tcp_server_t s, vio::ssl_config_t sc, int p, int nm, int &sr) -> vio::task_t<void>
        {
          auto server_create_result = vio::ssl_server_create(el, std::move(s), "localhost", sc);
          REQUIRE_EXPECTED(server_create_result);
          auto server = std::move(server_create_result.value());

          auto listen_result = co_await vio::ssl_server_listen(server, p);
          REQUIRE_EXPECTED(listen_result);
          auto client_or_err = vio::ssl_server_accept(server);
          REQUIRE_EXPECTED(client_or_err);
          auto client = std::move(client_or_err.value());

          auto reader_or_err = vio::ssl_server_client_create_reader(client);
          REQUIRE_EXPECTED(reader_or_err);
          auto reader = std::move(reader_or_err.value());

          for (int i = 0; i < nm; i++)
          {
            auto read_result = co_await reader;
            REQUIRE_EXPECTED(read_result);
            sr++;
            auto &data = read_result.value();
            auto buf = std::span<const std::byte>(data.span());
            auto write_result = co_await vio::ssl_server_client_write(client, buf);
            REQUIRE_EXPECTED(write_result);
          }
        }(event_loop, std::move(server_tcp_pair->first), server_config, port, num_messages, server_received);

        auto client_task = [](vio::event_loop_t &el, vio::ssl_config_t cc, int p, int nm, int &cr, bool &up) -> vio::task_t<void>
        {
          auto tcp = vio::tcp_create(el);
          REQUIRE_EXPECTED(tcp);
          auto addr = vio::ip4_addr("127.0.0.1", p);
          REQUIRE_EXPECTED(addr);
          auto connected = co_await vio::tcp_connect(tcp.value(), reinterpret_cast<const sockaddr *>(&addr.value()));
          REQUIRE_EXPECTED(connected);

          auto upgraded_or_err = co_await vio::ssl_client_upgrade(std::move(tcp.value()), cc, "localhost");
          REQUIRE_EXPECTED(upgraded_or_err);
          up = true;
          auto client = std::move(upgraded_or_err.value());

          auto reader_or_err = vio::ssl_client_create_reader(client);
          REQUIRE_EXPECTED(reader_or_err);
          auto reader = std::move(reader_or_err.value());

          for (int i = 0; i < nm; i++)
          {
            std::string msg = "upgrade_msg_" + std::to_string(i);
            auto buf = std::as_bytes(std::span(msg));
            auto write_result = co_await vio::ssl_client_write(client, buf);
            REQUIRE_EXPECTED(write_result);

            auto read_result = co_await reader;
            REQUIRE_EXPECTED(read_result);
            auto &data = read_result.value();
            std::string_view sv(data.chars(), data.size());
            REQUIRE(sv == msg);
            cr++;
          }
        }(event_loop, client_config, port, num_messages, client_received, upgraded);

        co_await std::move(client_task);
        co_await std::move(server_task);
        ev->stop();
      }(event_loop, server_config, client_config, num_messages, server_received, client_received, upgraded);
    });

  event_loop.run();
  REQUIRE(upgraded);
  REQUIRE(server_received == num_messages);
  REQUIRE(client_received == num_messages);
}
