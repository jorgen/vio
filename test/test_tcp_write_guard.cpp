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

#include <chrono>
#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace
{
constexpr std::size_t chunk_size = 4u * 1024u * 1024u;

void shrink_buffers(vio::tcp_t &tcp)
{
  int size = 64 * 1024;
  auto socket = tcp.handle->socket.native();
  REQUIRE(vio::detail::socket_set_option(socket, SOL_SOCKET, SO_SNDBUF, &size, static_cast<int>(sizeof(size))) == 0);
  REQUIRE(vio::detail::socket_set_option(socket, SOL_SOCKET, SO_RCVBUF, &size, static_cast<int>(sizeof(size))) == 0);
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
  shrink_buffers(client.value());
  shrink_buffers(accepted.value());
  co_return connected_pair_t{std::move(client.value()), std::move(accepted.value())};
}

vio::task_t<void> read_all(vio::tcp_t connection, std::string &received)
{
  auto reader = vio::tcp_create_reader(connection);
  REQUIRE_EXPECTED(reader);
  for (;;)
  {
    auto chunk = co_await reader.value();
    if (!chunk.has_value())
    {
      CHECK(chunk.error().code == vio::errc::eof);
      break;
    }
    received.append(chunk->chars(), chunk->size());
  }
}

vio::task_t<void> ordered_writes_scenario(vio::event_loop_t &loop, std::string &received, std::size_t &queued_after_issue, std::size_t &queued_after_done, int &results)
{
  auto pair = co_await connect_pair(loop);
  REQUIRE(pair.has_value());
  auto reader_task = read_all(std::move(pair->server), received);

  {
    auto client = std::move(pair->client);
    std::string first(chunk_size, 'a');
    std::vector<std::byte> third(chunk_size, std::byte{'c'});

    auto write1 = vio::write_tcp(client, reinterpret_cast<const uint8_t *>(first.data()), first.size());
    auto write2 = vio::write_tcp(client, std::string(chunk_size, 'b'));
    auto write3 = vio::write_tcp(client, std::span<const std::byte>(third.data(), third.size()));
    queued_after_issue = vio::tcp_write_queue_size(client);

    auto result3 = co_await std::move(write3);
    queued_after_done = vio::tcp_write_queue_size(client);
    auto result2 = co_await std::move(write2);
    auto result1 = co_await std::move(write1);
    results = int(result1.has_value()) + int(result2.has_value()) + int(result3.has_value());
  }
  co_await std::move(reader_task);
}

std::size_t stall_writes(vio::tcp_t &client, std::vector<vio::tcp_write_future_t> &fillers)
{
  constexpr int max_fillers = 16;
  fillers.reserve(max_fillers);
  for (int i = 0; i < max_fillers; ++i)
  {
    fillers.push_back(vio::write_tcp(client, std::string(chunk_size, 'f')));
    if (!fillers.back().await_ready())
      break;
  }
  REQUIRE_FALSE(fillers.back().await_ready());
  return fillers.size() * chunk_size;
}

vio::task_t<void> await_fillers(std::vector<vio::tcp_write_future_t> &fillers)
{
  for (auto &filler : fillers)
  {
    auto written = co_await std::move(filler);
    REQUIRE_EXPECTED(written);
  }
}

vio::task_t<void> dropped_future_scenario(vio::event_loop_t &loop, std::string &received, std::size_t &filled)
{
  auto pair = co_await connect_pair(loop);
  REQUIRE(pair.has_value());
  auto reader_task = read_all(std::move(pair->server), received);
  {
    auto client = std::move(pair->client);
    std::vector<vio::tcp_write_future_t> fillers;
    filled = stall_writes(client, fillers);
    std::string payload(chunk_size, 'd');
    {
      auto dropped = vio::write_tcp(client, reinterpret_cast<const uint8_t *>(payload.data()), payload.size());
      CHECK_FALSE(dropped.await_ready());
    }
    payload.assign(payload.size(), 'z');
    const std::string tail = "e";
    auto flushed = co_await vio::write_tcp(client, reinterpret_cast<const uint8_t *>(tail.data()), tail.size());
    REQUIRE_EXPECTED(flushed);
    co_await await_fillers(fillers);
  }
  co_await std::move(reader_task);
}

vio::task_t<void> cancelled_unsent_scenario(vio::event_loop_t &loop, std::string &received, std::size_t &filled, int &cancelled_code, bool &others_ok)
{
  auto pair = co_await connect_pair(loop);
  REQUIRE(pair.has_value());
  auto reader_task = read_all(std::move(pair->server), received);
  {
    auto client = std::move(pair->client);
    std::vector<vio::tcp_write_future_t> fillers;
    filled = stall_writes(client, fillers);
    std::string big(chunk_size, 'a');
    auto first = vio::write_tcp(client, reinterpret_cast<const uint8_t *>(big.data()), big.size());
    vio::cancellation_t token;
    auto skipped = vio::write_tcp(client, std::string("BBBB"), &token);
    auto last = vio::write_tcp(client, std::string("CCCC"));
    token.cancel();
    auto skipped_result = co_await std::move(skipped);
    REQUIRE_FALSE(skipped_result.has_value());
    cancelled_code = skipped_result.error().code;
    auto first_result = co_await std::move(first);
    auto last_result = co_await std::move(last);
    others_ok = first_result.has_value() && last_result.has_value();
    co_await await_fillers(fillers);
  }
  co_await std::move(reader_task);
}

vio::task_t<void> sticky_error_scenario(vio::event_loop_t &loop, int &first_error, int &second_error)
{
  auto pair = co_await connect_pair(loop);
  REQUIRE(pair.has_value());
  auto client = std::move(pair->client);
  {
    auto peer = std::move(pair->server);
  }
  [[maybe_unused]] auto slept = co_await vio::sleep(loop, std::chrono::milliseconds(20));
  std::string payload(64 * 1024, 'x');
  for (int i = 0; i < 100 && first_error == 0; ++i)
  {
    auto written = co_await vio::write_tcp(client, reinterpret_cast<const uint8_t *>(payload.data()), payload.size());
    if (!written.has_value())
    {
      first_error = written.error().code;
      break;
    }
    [[maybe_unused]] auto pause = co_await vio::sleep(loop, std::chrono::milliseconds(5));
  }
  auto again = co_await vio::write_tcp(client, reinterpret_cast<const uint8_t *>(payload.data()), 1);
  if (!again.has_value())
    second_error = again.error().code;
}

std::string make_pattern(std::size_t size)
{
  std::string out(size, '\0');
  for (std::size_t i = 0; i < size; ++i)
    out[i] = static_cast<char>((i * 131 + (i >> 13)) & 0xff);
  return out;
}

vio::task_t<void> dropped_connection_scenario(vio::event_loop_t &loop, const std::string &expected, bool owned, std::string &received, std::size_t &filled, std::size_t &queued_at_drop)
{
  auto pair = co_await connect_pair(loop);
  REQUIRE(pair.has_value());
  auto reader_task = read_all(std::move(pair->server), received);
  std::string source = expected;
  {
    auto client = std::move(pair->client);
    std::vector<vio::tcp_write_future_t> fillers;
    filled = stall_writes(client, fillers);
    if (owned)
    {
      auto bytes = std::as_bytes(std::span(source));
      auto dropped = vio::write_tcp(client, std::vector<std::byte>(bytes.begin(), bytes.end()));
      queued_at_drop = vio::tcp_write_queue_size(client);
    }
    else
    {
      auto dropped = vio::write_tcp(client, std::as_bytes(std::span(source)));
      queued_at_drop = vio::tcp_write_queue_size(client);
    }
  }
  source.assign(source.size(), 'z');
  co_await std::move(reader_task);
}

vio::task_t<void> dropped_connection_peer_gone_scenario(vio::event_loop_t &loop, std::size_t &queued_at_drop)
{
  auto pair = co_await connect_pair(loop);
  REQUIRE(pair.has_value());
  {
    auto client = std::move(pair->client);
    std::vector<vio::tcp_write_future_t> fillers;
    stall_writes(client, fillers);
    queued_at_drop = vio::tcp_write_queue_size(client);
  }
  [[maybe_unused]] auto slept = co_await vio::sleep(loop, std::chrono::milliseconds(20));
  {
    auto peer = std::move(pair->server);
  }
}

vio::task_t<void> mutual_linger_scenario(vio::event_loop_t &loop, std::size_t &queued_client, std::size_t &queued_server)
{
  auto pair = co_await connect_pair(loop);
  REQUIRE(pair.has_value());
  {
    auto client = std::move(pair->client);
    auto server = std::move(pair->server);
    std::vector<vio::tcp_write_future_t> client_fillers;
    std::vector<vio::tcp_write_future_t> server_fillers;
    stall_writes(client, client_fillers);
    stall_writes(server, server_fillers);
    queued_client = vio::tcp_write_queue_size(client);
    queued_server = vio::tcp_write_queue_size(server);
  }
}

vio::task_t<void> upload_then_read_scenario(vio::event_loop_t &loop, const std::string &response, std::size_t &filled, std::size_t &queued_at_drop, bool &uploaded, std::string &received)
{
  auto pair = co_await connect_pair(loop);
  REQUIRE(pair.has_value());
  auto peer = std::move(pair->client);
  {
    auto server = std::move(pair->server);
    std::vector<vio::tcp_write_future_t> fillers;
    filled = stall_writes(server, fillers);
    auto dropped = vio::write_tcp(server, std::string(response));
    queued_at_drop = vio::tcp_write_queue_size(server);
  }
  auto upload = co_await vio::write_tcp(peer, std::string(chunk_size, 'u'));
  uploaded = upload.has_value();
  co_await read_all(std::move(peer), received);
}

template <typename Scenario>
void run_scenario(Scenario &&scenario)
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
} // namespace

TEST_SUITE("tcp write queue")
{
  TEST_CASE("concurrent writes are queued and sent in the order they were issued")
  {
    std::string received;
    std::size_t queued_after_issue = 0;
    std::size_t queued_after_done = 1;
    int results = 0;
    run_scenario([&](vio::event_loop_t &loop) { return ordered_writes_scenario(loop, received, queued_after_issue, queued_after_done, results); });

    CHECK(results == 3);
    CHECK(queued_after_issue > 0);
    CHECK(queued_after_issue <= 3 * chunk_size);
    CHECK(queued_after_done == 0);
    REQUIRE(received.size() == 3 * chunk_size);
    CHECK(received == std::string(chunk_size, 'a') + std::string(chunk_size, 'b') + std::string(chunk_size, 'c'));
  }

  TEST_CASE("a write whose future is dropped still sends the bytes it was given")
  {
    std::string received;
    std::size_t filled = 0;
    run_scenario([&](vio::event_loop_t &loop) { return dropped_future_scenario(loop, received, filled); });
    REQUIRE(received.size() == filled + chunk_size + 1);
    CHECK(received == std::string(filled, 'f') + std::string(chunk_size, 'd') + "e");
  }

  TEST_CASE("a cancelled write that has not started is never sent")
  {
    std::string received;
    std::size_t filled = 0;
    int cancelled_code = 0;
    bool others_ok = false;
    run_scenario([&](vio::event_loop_t &loop) { return cancelled_unsent_scenario(loop, received, filled, cancelled_code, others_ok); });
    CHECK(cancelled_code == vio::vio_cancelled);
    CHECK(others_ok);
    CHECK(received == std::string(filled, 'f') + std::string(chunk_size, 'a') + "CCCC");
  }

  TEST_CASE("a connection dropped with megabytes still queued delivers them before the peer sees eof")
  {
    const std::string expected = make_pattern(chunk_size + 7);
    for (bool owned : {true, false})
    {
      CAPTURE(owned);
      std::string received;
      std::size_t filled = 0;
      std::size_t queued_at_drop = 0;
      run_scenario([&](vio::event_loop_t &loop) { return dropped_connection_scenario(loop, expected, owned, received, filled, queued_at_drop); });
      CHECK(queued_at_drop > expected.size());
      REQUIRE(received.size() == filled + expected.size());
      CHECK(received.compare(0, filled, std::string(filled, 'f')) == 0);
      CHECK(received.compare(filled, expected.size(), expected) == 0);
    }
  }

  TEST_CASE("a dropped connection stops lingering as soon as its peer goes away")
  {
    std::size_t queued_at_drop = 0;
    auto started = std::chrono::steady_clock::now();
    run_scenario([&](vio::event_loop_t &loop) { return dropped_connection_peer_gone_scenario(loop, queued_at_drop); });
    auto elapsed = std::chrono::steady_clock::now() - started;
    CHECK(queued_at_drop > 0);
    CHECK(elapsed < std::chrono::seconds(5));
  }

  TEST_CASE("two dropped ends that both linger drain each other instead of waiting out the linger")
  {
    std::size_t queued_client = 0;
    std::size_t queued_server = 0;
    auto started = std::chrono::steady_clock::now();
    run_scenario([&](vio::event_loop_t &loop) { return mutual_linger_scenario(loop, queued_client, queued_server); });
    auto elapsed = std::chrono::steady_clock::now() - started;
    CHECK(queued_client > 0);
    CHECK(queued_server > 0);
    CHECK(elapsed < std::chrono::seconds(5));
  }

  TEST_CASE("a lingering connection keeps reading, so a peer that uploads before it reads gets the whole response")
  {
    const std::string response = make_pattern(chunk_size + 3);
    std::size_t filled = 0;
    std::size_t queued_at_drop = 0;
    bool uploaded = false;
    std::string received;
    auto started = std::chrono::steady_clock::now();
    run_scenario([&](vio::event_loop_t &loop) { return upload_then_read_scenario(loop, response, filled, queued_at_drop, uploaded, received); });
    auto elapsed = std::chrono::steady_clock::now() - started;
    CHECK(queued_at_drop > response.size());
    CHECK(uploaded);
    REQUIRE(received.size() == filled + response.size());
    CHECK(received.compare(0, filled, std::string(filled, 'f')) == 0);
    CHECK(received.compare(filled, response.size(), response) == 0);
    CHECK(elapsed < std::chrono::seconds(5));
  }

  TEST_CASE("a write to a vanished peer fails, and later writes fail the same way")
  {
    int first_error = 0;
    int second_error = 0;
    run_scenario([&](vio::event_loop_t &loop) { return sticky_error_scenario(loop, first_error, second_error); });
    CHECK(first_error != 0);
    CHECK(second_error == first_error);
  }
}
