#include "require_expected.h"

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include <doctest/doctest.h>
#include <vio/event_loop.h>
#include <vio/operation/tcp.h>
#include <vio/operation/udp.h>
#include <vio/task.h>

// A QUIC server owns one unconnected socket and talks to every peer through
// it. send_udp refuses a second concurrent send by design, so these cover the
// synchronous paths that do not.
//
// Sockets are owned inside the coroutine and the loop is stopped from within
// it, so every uv_close is drained before the loop is torn down.

namespace
{
std::span<const std::uint8_t> as_bytes(std::string_view text)
{
  return {reinterpret_cast<const std::uint8_t *>(text.data()), text.size()};
}

std::expected<std::pair<vio::udp_t, int>, vio::error_t> bound_socket(vio::event_loop_t &loop)
{
  auto udp = vio::udp_create(loop);
  if (!udp.has_value())
  {
    return std::unexpected(udp.error());
  }
  auto addr = vio::ip4_addr("127.0.0.1", 0);
  if (!addr.has_value())
  {
    return std::unexpected(addr.error());
  }
  auto bound = vio::udp_bind(udp.value(), reinterpret_cast<const sockaddr *>(&addr.value()));
  if (!bound.has_value())
  {
    return std::unexpected(bound.error());
  }
  auto name = vio::udp_sockname(udp.value());
  if (!name.has_value())
  {
    return std::unexpected(name.error());
  }
  const auto *in = reinterpret_cast<const sockaddr_in *>(&name.value());
  return std::make_pair(std::move(udp.value()), static_cast<int>(ntohs(in->sin_port)));
}
} // namespace

TEST_SUITE("udp batch")
{
TEST_CASE("udp_try_send issues many datagrams back to back from one socket")
{
  constexpr int datagram_count = 16;
  vio::event_loop_t event_loop;
  int received = 0;

  event_loop.run_in_loop(
    [&]
    {
      return [](vio::event_loop_t &loop, int &received) -> vio::task_t<void>
      {
        auto receiver_pair = bound_socket(loop);
        REQUIRE_EXPECTED(receiver_pair);
        const int port = receiver_pair->second;

        auto receiver_task = [](vio::udp_t receiver, int &received) -> vio::task_t<void>
        {
          auto reader_or_err = vio::udp_create_reader(receiver);
          REQUIRE_EXPECTED(reader_or_err);
          auto reader = std::move(reader_or_err.value());
          for (int i = 0; i < datagram_count; ++i)
          {
            auto datagram = co_await reader;
            REQUIRE_EXPECTED(datagram);
            ++received;
          }
        }(std::move(receiver_pair->first), received);

        co_await [](vio::event_loop_t &el, int p) -> vio::task_t<void>
        {
          auto sender_pair = bound_socket(el);
          REQUIRE_EXPECTED(sender_pair);
          auto dest = vio::ip4_addr("127.0.0.1", p);
          REQUIRE_EXPECTED(dest);

          for (int i = 0; i < datagram_count; ++i)
          {
            auto sent = vio::udp_try_send(sender_pair->first, as_bytes("quic"), reinterpret_cast<const sockaddr *>(&dest.value()));
            REQUIRE_EXPECTED(sent);
            REQUIRE(*sent == 4);
          }
          co_return;
        }(loop, port);

        co_await std::move(receiver_task);
        {
          auto tmp = std::move(receiver_task);
        }
        loop.stop();
      }(event_loop, received);
    });

  event_loop.run();
  CHECK(received == datagram_count);
}

TEST_CASE("udp_try_send reaches distinct peers from one unconnected socket")
{
  vio::event_loop_t event_loop;
  int first_got = 0;
  int second_got = 0;

  event_loop.run_in_loop(
    [&]
    {
      return [](vio::event_loop_t &loop, int &first_got, int &second_got) -> vio::task_t<void>
      {
        auto first = bound_socket(loop);
        REQUIRE_EXPECTED(first);
        auto second = bound_socket(loop);
        REQUIRE_EXPECTED(second);
        const int first_port = first->second;
        const int second_port = second->second;

        auto receive_one = [](vio::udp_t peer, int &counter) -> vio::task_t<void>
        {
          auto reader_or_err = vio::udp_create_reader(peer);
          REQUIRE_EXPECTED(reader_or_err);
          auto reader = std::move(reader_or_err.value());
          auto datagram = co_await reader;
          REQUIRE_EXPECTED(datagram);
          ++counter;
        };

        auto first_task = receive_one(std::move(first->first), first_got);
        auto second_task = receive_one(std::move(second->first), second_got);

        co_await [](vio::event_loop_t &el, int a, int b) -> vio::task_t<void>
        {
          auto sender_pair = bound_socket(el);
          REQUIRE_EXPECTED(sender_pair);
          for (int port : {a, b})
          {
            auto dest = vio::ip4_addr("127.0.0.1", port);
            REQUIRE_EXPECTED(dest);
            auto sent = vio::udp_try_send(sender_pair->first, as_bytes("peer"), reinterpret_cast<const sockaddr *>(&dest.value()));
            REQUIRE_EXPECTED(sent);
          }
          co_return;
        }(loop, first_port, second_port);

        co_await std::move(first_task);
        co_await std::move(second_task);
        {
          auto a = std::move(first_task);
          auto b = std::move(second_task);
        }
        loop.stop();
      }(event_loop, first_got, second_got);
    });

  event_loop.run();
  CHECK(first_got == 1);
  CHECK(second_got == 1);
}

TEST_CASE("udp_try_send_batch delivers a run of datagrams")
{
  constexpr unsigned int batch = 8;
  vio::event_loop_t event_loop;
  unsigned int accepted = 0;
  unsigned int received = 0;

  event_loop.run_in_loop(
    [&]
    {
      return [](vio::event_loop_t &loop, unsigned int &accepted, unsigned int &received) -> vio::task_t<void>
      {
        auto receiver_pair = bound_socket(loop);
        REQUIRE_EXPECTED(receiver_pair);
        const int port = receiver_pair->second;

        auto sender_pair = bound_socket(loop);
        REQUIRE_EXPECTED(sender_pair);
        auto dest = vio::ip4_addr("127.0.0.1", port);
        REQUIRE_EXPECTED(dest);

        std::array<vio::udp_out_datagram_t, batch> datagrams = {};
        for (auto &datagram : datagrams)
        {
          datagram.bytes = as_bytes("batched");
          datagram.addr = reinterpret_cast<const sockaddr *>(&dest.value());
        }
        auto sent = vio::udp_try_send_batch(sender_pair->first, datagrams);
        REQUIRE_EXPECTED(sent);
        accepted = *sent;
        REQUIRE(accepted > 0);

        auto receiver_task = [](vio::udp_t receiver, unsigned int expected, unsigned int &received) -> vio::task_t<void>
        {
          auto reader_or_err = vio::udp_create_reader(receiver);
          REQUIRE_EXPECTED(reader_or_err);
          auto reader = std::move(reader_or_err.value());
          while (received < expected)
          {
            auto datagram = co_await reader;
            REQUIRE_EXPECTED(datagram);
            ++received;
          }
        }(std::move(receiver_pair->first), accepted, received);

        co_await std::move(receiver_task);
        {
          auto tmp = std::move(receiver_task);
        }
        loop.stop();
      }(event_loop, accepted, received);
    });

  event_loop.run();
  CHECK(received == accepted);
}

TEST_CASE("udp_bind_dual_stack accepts an IPv4-mapped peer")
{
  vio::event_loop_t event_loop;
  bool got = false;

  event_loop.run_in_loop(
    [&]
    {
      return [](vio::event_loop_t &loop, bool &got) -> vio::task_t<void>
      {
        auto server = vio::udp_create(loop);
        REQUIRE_EXPECTED(server);
        auto bound = vio::udp_bind_dual_stack(server.value(), 0);
        REQUIRE_EXPECTED(bound);

        auto name = vio::udp_sockname(server.value());
        REQUIRE_EXPECTED(name);
        const int port = name->ss_family == AF_INET6 ? ntohs(reinterpret_cast<const sockaddr_in6 *>(&name.value())->sin6_port) : ntohs(reinterpret_cast<const sockaddr_in *>(&name.value())->sin_port);
        REQUIRE(port != 0);

        auto receiver_task = [](vio::udp_t receiver, bool &got) -> vio::task_t<void>
        {
          auto reader_or_err = vio::udp_create_reader(receiver);
          REQUIRE_EXPECTED(reader_or_err);
          auto reader = std::move(reader_or_err.value());
          auto datagram = co_await reader;
          got = datagram.has_value();
        }(std::move(server.value()), got);

        co_await [](vio::event_loop_t &el, int p) -> vio::task_t<void>
        {
          auto sender_pair = bound_socket(el);
          REQUIRE_EXPECTED(sender_pair);
          auto dest = vio::ip4_addr("127.0.0.1", p);
          REQUIRE_EXPECTED(dest);
          auto sent = vio::udp_try_send(sender_pair->first, as_bytes("mapped"), reinterpret_cast<const sockaddr *>(&dest.value()));
          REQUIRE_EXPECTED(sent);
          co_return;
        }(loop, port);

        co_await std::move(receiver_task);
        {
          auto tmp = std::move(receiver_task);
        }
        loop.stop();
      }(event_loop, got);
    });

  event_loop.run();
  CHECK(got);
}

TEST_CASE("udp_set_allocator routes reader allocations through the hook")
{
  struct counters_t
  {
    int allocs = 0;
    int deallocs = 0;
  };

  vio::event_loop_t event_loop;
  counters_t counters;

  event_loop.run_in_loop(
    [&]
    {
      return [](vio::event_loop_t &loop, counters_t &counters) -> vio::task_t<void>
      {
        auto receiver_pair = bound_socket(loop);
        REQUIRE_EXPECTED(receiver_pair);
        const int port = receiver_pair->second;

        vio::udp_set_allocator(
          receiver_pair->first,
          [](void *user, size_t suggested, uv_buf_t *buf)
          {
            ++static_cast<counters_t *>(user)->allocs;
            buf->base = new char[suggested];
            buf->len = static_cast<decltype(buf->len)>(suggested);
          },
          [](void *user, uv_buf_t *buf)
          {
            ++static_cast<counters_t *>(user)->deallocs;
            delete[] buf->base;
            buf->base = nullptr;
          },
          &counters);

        auto receiver_task = [](vio::udp_t receiver) -> vio::task_t<void>
        {
          auto reader_or_err = vio::udp_create_reader(receiver);
          REQUIRE_EXPECTED(reader_or_err);
          auto reader = std::move(reader_or_err.value());
          auto datagram = co_await reader;
          REQUIRE_EXPECTED(datagram);
        }(std::move(receiver_pair->first));

        co_await [](vio::event_loop_t &el, int p) -> vio::task_t<void>
        {
          auto sender_pair = bound_socket(el);
          REQUIRE_EXPECTED(sender_pair);
          auto dest = vio::ip4_addr("127.0.0.1", p);
          REQUIRE_EXPECTED(dest);
          REQUIRE_EXPECTED(vio::udp_try_send(sender_pair->first, as_bytes("alloc"), reinterpret_cast<const sockaddr *>(&dest.value())));
          co_return;
        }(loop, port);

        co_await std::move(receiver_task);
        {
          auto tmp = std::move(receiver_task);
        }
        loop.stop();
      }(event_loop, counters);
    });

  event_loop.run();
  CHECK(counters.allocs > 0);
}

TEST_CASE("udp_fileno returns the underlying socket")
{
  vio::event_loop_t event_loop;
  bool valid = false;

  event_loop.run_in_loop(
    [&]
    {
      return [](vio::event_loop_t &loop, bool &valid) -> vio::task_t<void>
      {
        auto udp = bound_socket(loop);
        REQUIRE_EXPECTED(udp);
        auto fd = vio::udp_fileno(udp->first);
        REQUIRE_EXPECTED(fd);
#ifdef _WIN32
        valid = *fd != INVALID_HANDLE_VALUE;
#else
        valid = *fd >= 0;
#endif
        loop.stop();
        co_return;
      }(event_loop, valid);
    });

  event_loop.run();
  CHECK(valid);
}
}
