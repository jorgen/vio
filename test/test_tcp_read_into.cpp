#include <doctest/doctest.h>

#include <vio/event_loop.h>
#include <vio/operation/tcp.h>
#include <vio/operation/tcp_server.h>
#include <vio/task.h>

#include "require_expected.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <utility>

namespace
{
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

vio::task_t<void> read_into_scenario(vio::event_loop_t &event_loop, std::string &received, bool &paused_after_read, bool &hit_eof)
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

  co_await [](vio::event_loop_t &el, const sockaddr *sa, std::string &out, bool &paused, bool &eof) -> vio::task_t<void>
  {
    auto client_or_err = vio::tcp_create(el);
    REQUIRE_EXPECTED(client_or_err);
    auto client = std::move(client_or_err.value());
    auto connect_result = co_await vio::tcp_connect(client, sa);
    REQUIRE_EXPECTED(connect_result);

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
      paused = paused || reader.handle->read.paused;
    }
  }(event_loop, reinterpret_cast<const sockaddr *>(&addr.value()), received, paused_after_read, hit_eof);

  co_await std::move(server_task);

  CHECK(received == payload);
}
} // namespace

TEST_SUITE("tcp read_into")
{
  // read_into lands socket bytes directly in the caller's buffer (zero-copy),
  // returns bytes-per-read (0 == EOF), and leaves the reader paused after each
  // direct read so libuv does not buffer ahead -- the pull cadence is the
  // backpressure. Reading a 100 KB payload through a 4 KB caller buffer
  // exercises many resume/read/pause cycles.
  TEST_CASE("read_into reassembles a large payload and paces via pause/resume")
  {
    vio::event_loop_t event_loop;
    std::string received;
    bool paused_after_read = false;
    bool hit_eof = false;

    event_loop.run_in_loop(
      [&]
      {
        return [](vio::event_loop_t &el, std::string &r, bool &p, bool &e) -> vio::task_t<void>
        {
          co_await read_into_scenario(el, r, p, e);
          el.stop();
        }(event_loop, received, paused_after_read, hit_eof);
      });

    event_loop.run();

    CHECK(received.size() == 100000);
    CHECK(hit_eof);
    CHECK(paused_after_read);
  }
}
