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

#include <vio/event_loop.h>
#include <vio/operation/sleep.h>
#include <vio/operation/tcp.h>
#include <vio/operation/tcp_server.h>
#include <vio/task.h>

#include "require_expected.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <utility>

namespace
{
int allocations = 0;

std::span<std::byte> counting_alloc(void *, std::size_t size)
{
  ++allocations;
  return {new std::byte[size], size};
}

std::expected<std::pair<vio::tcp_server_t, int>, vio::error_t> bound_tcp_server(vio::event_loop_t &event_loop)
{
  auto addr = vio::ip4_addr("127.0.0.1", 0);
  if (!addr)
    return std::unexpected(addr.error());
  auto server = vio::tcp_create_server(event_loop);
  if (!server)
    return std::unexpected(server.error());
  auto bound = vio::tcp_bind(server.value(), reinterpret_cast<const sockaddr *>(&addr.value()));
  if (!bound)
    return std::unexpected(bound.error());
  auto sn = vio::sockname(server->tcp);
  if (!sn)
    return std::unexpected(sn.error());
  sockaddr_storage storage = sn.value();
  const auto *in = reinterpret_cast<const sockaddr_in *>(&storage);
  return std::make_pair(std::move(server.value()), static_cast<int>(ntohs(in->sin_port)));
}

std::string make_payload(std::size_t size)
{
  std::string payload;
  payload.reserve(size);
  for (std::size_t i = 0; i < size; ++i)
  {
    payload.push_back(static_cast<char>('a' + (i % 26)));
  }
  return payload;
}

vio::task_t<void> read_into_scenario(vio::event_loop_t &event_loop, std::string &received, bool &nothing_buffered, bool &hit_eof)
{
  auto server_and_port = bound_tcp_server(event_loop);
  REQUIRE_EXPECTED(server_and_port);
  const int port = server_and_port->second;
  auto addr = vio::ip4_addr("127.0.0.1", port);
  REQUIRE_EXPECTED(addr);

  const std::string payload = make_payload(100000);

  auto server_task = [](vio::tcp_server_t s, std::string data) -> vio::task_t<void>
  {
    auto server = std::move(s);
    auto listen_result = co_await vio::tcp_listen(server, 10);
    REQUIRE_EXPECTED(listen_result);
    auto accepted = vio::tcp_accept(server);
    REQUIRE_EXPECTED(accepted);
    auto conn = std::move(accepted.value());
    auto write_result = co_await vio::write_tcp(conn, reinterpret_cast<const uint8_t *>(data.data()), data.size());
    REQUIRE_EXPECTED(write_result);
  }(std::move(server_and_port->first), payload);

  co_await [](vio::event_loop_t &el, const sockaddr *sa, std::string &out, bool &unbuffered, bool &eof) -> vio::task_t<void>
  {
    auto client_or_err = vio::tcp_create(el);
    REQUIRE_EXPECTED(client_or_err);
    auto client = std::move(client_or_err.value());
    auto connect_result = co_await vio::tcp_connect(client, sa);
    REQUIRE_EXPECTED(connect_result);

    client.handle->read.alloc_buffer_cb = counting_alloc;
    auto reader_or_err = vio::tcp_create_reader(client);
    REQUIRE_EXPECTED(reader_or_err);
    auto reader = std::move(reader_or_err.value());

    std::array<std::byte, 4096> buffer{};
    for (;;)
    {
      auto n = co_await reader.read_into(std::span<std::byte>(buffer.data(), buffer.size()));
      REQUIRE_EXPECTED(n);
      if (n.value() == 0)
      {
        eof = true;
        break;
      }
      out.append(reinterpret_cast<const char *>(buffer.data()), n.value());
      unbuffered = unbuffered && allocations == 0;
    }
  }(event_loop, reinterpret_cast<const sockaddr *>(&addr.value()), received, nothing_buffered, hit_eof);

  co_await std::move(server_task);

  CHECK(received == payload);
}

vio::task_t<void> cancel_reuse_scenario(vio::event_loop_t &event_loop, int &cancel_code, bool &buffer_untouched, std::string &later)
{
  auto server_and_port = bound_tcp_server(event_loop);
  REQUIRE_EXPECTED(server_and_port);
  auto server = std::move(server_and_port->first);
  auto addr = vio::ip4_addr("127.0.0.1", server_and_port->second);
  REQUIRE_EXPECTED(addr);

  auto listening = vio::tcp_listen(server, 4);
  auto client_or_err = vio::tcp_create(event_loop);
  REQUIRE_EXPECTED(client_or_err);
  auto client = std::move(client_or_err.value());
  auto connected = co_await vio::tcp_connect(client, reinterpret_cast<const sockaddr *>(&addr.value()));
  REQUIRE_EXPECTED(connected);
  auto ready = co_await std::move(listening);
  REQUIRE_EXPECTED(ready);
  auto accepted = vio::tcp_accept(server);
  REQUIRE_EXPECTED(accepted);
  auto peer = std::move(accepted.value());

  std::array<std::byte, 64> buffer{};
  {
    auto reader = vio::tcp_create_reader(client);
    REQUIRE_EXPECTED(reader);
    auto read_task = [](vio::tcp_reader_t &reader, std::span<std::byte> target, int &code) -> vio::task_t<void>
    {
      auto n = co_await reader.read_into(target);
      REQUIRE_FALSE(n.has_value());
      code = n.error().code;
    }(reader.value(), std::span<std::byte>(buffer.data(), buffer.size()), cancel_code);

    [[maybe_unused]] auto slept = co_await vio::sleep(event_loop, std::chrono::milliseconds(10));
    reader->cancel();
    REQUIRE(read_task.done());
    buffer.fill(std::byte{'B'});

    const std::string payload = "hello";
    auto written = co_await vio::write_tcp(peer, reinterpret_cast<const uint8_t *>(payload.data()), payload.size());
    REQUIRE_EXPECTED(written);
    [[maybe_unused]] auto settled = co_await vio::sleep(event_loop, std::chrono::milliseconds(30));
    buffer_untouched = std::all_of(buffer.begin(), buffer.end(), [](std::byte b) { return b == std::byte{'B'}; });
    co_await std::move(read_task);
  }

  auto reader = vio::tcp_create_reader(client);
  REQUIRE_EXPECTED(reader);
  std::array<std::byte, 64> second{};
  auto n = co_await reader->read_into(std::span<std::byte>(second.data(), second.size()));
  REQUIRE_EXPECTED(n);
  later.assign(reinterpret_cast<const char *>(second.data()), n.value());
}
} // namespace

TEST_SUITE("tcp read_into")
{
  TEST_CASE("read_into reassembles a large payload without allocating a buffer")
  {
    vio::event_loop_t event_loop;
    std::string received;
    bool nothing_buffered = true;
    bool hit_eof = false;

    event_loop.run_in_loop(
      [&]
      {
        return [](vio::event_loop_t &el, std::string &r, bool &n, bool &e) -> vio::task_t<void>
        {
          co_await read_into_scenario(el, r, n, e);
          el.stop();
        }(event_loop, received, nothing_buffered, hit_eof);
      });

    event_loop.run();

    CHECK(received.size() == 100000);
    CHECK(hit_eof);
    CHECK(nothing_buffered);
  }

  TEST_CASE("a cancelled read_into hands the buffer back at once")
  {
    vio::event_loop_t event_loop;
    int cancel_code = 0;
    bool buffer_untouched = false;
    std::string later;

    event_loop.run_in_loop(
      [&]
      {
        return [](vio::event_loop_t &el, int &code, bool &untouched, std::string &later) -> vio::task_t<void>
        {
          co_await cancel_reuse_scenario(el, code, untouched, later);
          el.stop();
        }(event_loop, cancel_code, buffer_untouched, later);
      });

    event_loop.run();

    CHECK(cancel_code == vio::errc::canceled);
    CHECK(buffer_untouched);
    CHECK(later == "hello");
  }
}
