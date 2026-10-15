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

#include <array>
#include <chrono>
#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <utility>

namespace
{
struct alloc_counts_t
{
  int allocs = 0;
  int deallocs = 0;
};

std::span<std::byte> counting_alloc(void *user, std::size_t size)
{
  ++static_cast<alloc_counts_t *>(user)->allocs;
  return {new std::byte[size], size};
}

void counting_dealloc(void *user, std::span<std::byte> buffer)
{
  ++static_cast<alloc_counts_t *>(user)->deallocs;
  delete[] buffer.data();
}

struct connected_pair_t
{
  vio::tcp_t client;
  vio::tcp_t server;
};

vio::task_t<std::optional<connected_pair_t>> connect_pair(vio::event_loop_t &loop)
{
  auto any = vio::ip4_addr("127.0.0.1", 0);
  REQUIRE_EXPECTED(any);
  auto server = vio::tcp_create_server(loop);
  REQUIRE_EXPECTED(server);
  auto bound = vio::tcp_bind(server.value(), reinterpret_cast<const sockaddr *>(&any.value()));
  REQUIRE_EXPECTED(bound);
  auto name = vio::sockname(server->tcp);
  REQUIRE_EXPECTED(name);
  auto port = ntohs(reinterpret_cast<const sockaddr_in *>(&name.value())->sin_port);
  auto address = vio::ip4_addr("127.0.0.1", port);
  REQUIRE_EXPECTED(address);

  auto listening = vio::tcp_listen(server.value(), 8);
  auto client = vio::tcp_create(loop);
  REQUIRE_EXPECTED(client);
  auto connected = co_await vio::tcp_connect(client.value(), reinterpret_cast<const sockaddr *>(&address.value()));
  REQUIRE_EXPECTED(connected);
  auto ready = co_await std::move(listening);
  REQUIRE_EXPECTED(ready);
  auto accepted = vio::tcp_accept(server.value());
  REQUIRE_EXPECTED(accepted);
  co_return connected_pair_t{std::move(client.value()), std::move(accepted.value())};
}

vio::task_t<void> wait_without_data_scenario(vio::event_loop_t &loop, alloc_counts_t &counts, bool &done_before_data, bool &held_while_waiting, std::string &received)
{
  auto pair = co_await connect_pair(loop);
  REQUIRE(pair.has_value());
  pair->server.handle->read.alloc_buffer_cb = counting_alloc;
  pair->server.handle->read.dealloc_buffer_cb = counting_dealloc;
  pair->server.handle->read.alloc_cb_data = &counts;

  {
    auto reader = vio::tcp_create_reader(pair->server);
    REQUIRE_EXPECTED(reader);
    bool done = false;
    auto read_task = [](vio::tcp_reader_t &reader, bool &done, std::string &received) -> vio::task_t<void> {
      auto chunk = co_await reader;
      REQUIRE_EXPECTED(chunk);
      received.assign(chunk->chars(), chunk->size());
      done = true;
    }(reader.value(), done, received);

    [[maybe_unused]] auto slept = co_await vio::sleep(loop, std::chrono::milliseconds(30));
    done_before_data = done;
    held_while_waiting = counts.allocs != counts.deallocs;

    const std::string payload = "x";
    auto written = co_await vio::write_tcp(pair->client, reinterpret_cast<const uint8_t *>(payload.data()), payload.size());
    REQUIRE_EXPECTED(written);
    co_await std::move(read_task);
    CHECK(done);
  }
  CHECK(counts.deallocs == counts.allocs);
}

vio::task_t<void> eof_scenario(vio::event_loop_t &loop, int &queued_code, std::size_t &into_bytes, bool &into_ok)
{
  auto pair = co_await connect_pair(loop);
  REQUIRE(pair.has_value());
  auto reader = vio::tcp_create_reader(pair->client);
  REQUIRE_EXPECTED(reader);
  {
    auto peer = std::move(pair->server);
  }
  auto chunk = co_await reader.value();
  REQUIRE_FALSE(chunk.has_value());
  queued_code = chunk.error().code;

  std::array<std::byte, 16> buffer{};
  auto into = co_await reader->read_into(std::span<std::byte>(buffer.data(), buffer.size()));
  into_ok = into.has_value();
  if (into_ok)
    into_bytes = into.value();
}

vio::task_t<void> cancel_releases_scenario(vio::event_loop_t &loop, alloc_counts_t &counts, int &code)
{
  auto pair = co_await connect_pair(loop);
  REQUIRE(pair.has_value());
  pair->client.handle->read.alloc_buffer_cb = counting_alloc;
  pair->client.handle->read.dealloc_buffer_cb = counting_dealloc;
  pair->client.handle->read.alloc_cb_data = &counts;
  auto reader = vio::tcp_create_reader(pair->client);
  REQUIRE_EXPECTED(reader);
  auto read_task = [](vio::tcp_reader_t &reader, int &code) -> vio::task_t<void> {
    auto chunk = co_await reader;
    REQUIRE_FALSE(chunk.has_value());
    code = chunk.error().code;
  }(reader.value(), code);
  [[maybe_unused]] auto slept = co_await vio::sleep(loop, std::chrono::milliseconds(10));
  reader->cancel();
  co_await std::move(read_task);
  CHECK(counts.deallocs == counts.allocs);
}
} // namespace

TEST_SUITE("tcp read readiness")
{
  TEST_CASE("a read with nothing to read waits instead of reporting eof")
  {
    vio::event_loop_t loop;
    alloc_counts_t counts;
    bool done_before_data = true;
    bool held_while_waiting = true;
    std::string received;
    loop.run_in_loop([&] {
      return [](vio::event_loop_t &loop, alloc_counts_t &counts, bool &done_before_data, bool &held_while_waiting, std::string &received) -> vio::task_t<void> {
        co_await wait_without_data_scenario(loop, counts, done_before_data, held_while_waiting, received);
        loop.stop();
      }(loop, counts, done_before_data, held_while_waiting, received);
    });
    loop.run();
    CHECK_FALSE(done_before_data);
    CHECK_FALSE(held_while_waiting);
    CHECK(received == "x");
    CHECK(counts.allocs > 0);
    CHECK(counts.deallocs == counts.allocs);
  }

  TEST_CASE("a closed peer reads as eof")
  {
    vio::event_loop_t loop;
    int queued_code = 0;
    std::size_t into_bytes = 99;
    bool into_ok = false;
    loop.run_in_loop([&] {
      return [](vio::event_loop_t &loop, int &queued_code, std::size_t &into_bytes, bool &into_ok) -> vio::task_t<void> {
        co_await eof_scenario(loop, queued_code, into_bytes, into_ok);
        loop.stop();
      }(loop, queued_code, into_bytes, into_ok);
    });
    loop.run();
    CHECK(queued_code == vio::errc::eof);
    CHECK(into_ok);
    CHECK(into_bytes == 0);
  }

  TEST_CASE("a cancelled read holds no buffer")
  {
    vio::event_loop_t loop;
    alloc_counts_t counts;
    int code = 0;
    loop.run_in_loop([&] {
      return [](vio::event_loop_t &loop, alloc_counts_t &counts, int &code) -> vio::task_t<void> {
        co_await cancel_releases_scenario(loop, counts, code);
        loop.stop();
      }(loop, counts, code);
    });
    loop.run();
    CHECK(code == vio::errc::canceled);
    CHECK(counts.deallocs == counts.allocs);
  }
}
