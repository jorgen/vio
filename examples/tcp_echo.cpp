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

#include <print>
#include <string>
#include <string_view>

#include <vio/operation/tcp.h>
#include <vio/operation/tcp_server.h>
#include <vio/run.h>

int main()
{
  return vio::run([](vio::event_loop_t &event_loop) -> vio::task_t<int>
  {
    // Bind server to ephemeral port
    auto addr = vio::ip4_addr("127.0.0.1", 0);
    if (!addr)
    {
      std::println(stderr, "ip4_addr failed: {}", addr.error().msg);
      co_return 1;
    }

    auto server = vio::tcp_create_server(event_loop);
    if (!server)
    {
      std::println(stderr, "tcp_create_server failed: {}", server.error().msg);
      co_return 1;
    }

    auto bind_result = vio::tcp_bind(server.value(), reinterpret_cast<const sockaddr *>(&addr.value()));
    if (!bind_result)
    {
      std::println(stderr, "tcp_bind failed: {}", bind_result.error().msg);
      co_return 1;
    }

    auto sn = vio::sockname(server->tcp);
    if (!sn)
    {
      std::println(stderr, "sockname failed: {}", sn.error().msg);
      co_return 1;
    }
    const auto *sa_in = reinterpret_cast<sockaddr_in *>(&sn.value());
    int port = ntohs(sa_in->sin_port);
    std::println("Server listening on 127.0.0.1:{}", port);

    // Server coroutine: accept one client, read message, echo it back
    auto server_task = [](vio::tcp_server_t s) -> vio::task_t<void>
    {
      auto server = std::move(s);
      auto listen_result = co_await vio::tcp_listen(server, 1);
      if (!listen_result)
      {
        std::println(stderr, "tcp_listen failed: {}", listen_result.error().msg);
        co_return;
      }

      auto client = vio::tcp_accept(server);
      if (!client)
      {
        std::println(stderr, "tcp_accept failed: {}", client.error().msg);
        co_return;
      }
      std::println("Server: accepted a connection");

      auto reader_result = vio::tcp_create_reader(client.value());
      if (!reader_result)
      {
        std::println(stderr, "tcp_create_reader failed: {}", reader_result.error().msg);
        co_return;
      }
      auto reader = std::move(reader_result.value());
      auto read_result = co_await reader;
      if (!read_result)
      {
        std::println(stderr, "Server read failed: {}", read_result.error().msg);
        co_return;
      }
      auto &data = read_result.value();
      std::string_view msg(data.chars(), data.size());
      std::println("Server: received \"{}\"", msg);

      auto write_result = co_await vio::write_tcp(client.value(), reinterpret_cast<const uint8_t *>(data.chars()), data.size());
      if (!write_result)
      {
        std::println(stderr, "Server write failed: {}", write_result.error().msg);
        co_return;
      }
      std::println("Server: echoed message back");
    }(std::move(server.value()));

    // Client coroutine: connect, send message, read echo
    co_await [](vio::event_loop_t &el, int p) -> vio::task_t<void>
    {
      auto client = vio::tcp_create(el);
      if (!client)
      {
        std::println(stderr, "tcp_create failed: {}", client.error().msg);
        co_return;
      }

      auto addr = vio::ip4_addr("127.0.0.1", p);
      if (!addr)
      {
        std::println(stderr, "ip4_addr failed: {}", addr.error().msg);
        co_return;
      }

      auto connect_result = co_await vio::tcp_connect(client.value(), reinterpret_cast<const sockaddr *>(&addr.value()));
      if (!connect_result)
      {
        std::println(stderr, "tcp_connect failed: {}", connect_result.error().msg);
        co_return;
      }
      std::println("Client: connected to server");

      std::string message = "Hello VIO!";
      auto write_result = co_await vio::write_tcp(client.value(), reinterpret_cast<const uint8_t *>(message.data()), message.size());
      if (!write_result)
      {
        std::println(stderr, "Client write failed: {}", write_result.error().msg);
        co_return;
      }
      std::println("Client: sent \"{}\"", message);

      auto reader_result = vio::tcp_create_reader(client.value());
      if (!reader_result)
      {
        std::println(stderr, "tcp_create_reader failed: {}", reader_result.error().msg);
        co_return;
      }
      auto reader = std::move(reader_result.value());
      auto read_result = co_await reader;
      if (!read_result)
      {
        std::println(stderr, "Client read failed: {}", read_result.error().msg);
        co_return;
      }
      auto &data = read_result.value();
      std::string_view echo(data.chars(), data.size());
      std::println("Client: received echo \"{}\"", echo);
    }(event_loop, port);

    co_await std::move(server_task);
    std::println("Done!");
    co_return 0;
  });
}
