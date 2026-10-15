#include "require_expected.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include <doctest/doctest.h>
#include <vio/buffer_pool.h>
#include <vio/cancellation.h>
#include <vio/event_loop.h>
#include <vio/operation/sleep.h>
#include <vio/operation/udp.h>
#include <vio/task.h>

// A QUIC server owns one unconnected socket and talks to every peer through
// it. send_udp refuses a second concurrent send by design, so these cover the
// synchronous paths that do not.
//
// Sockets are owned inside the coroutine and the loop is stopped from within
// it, so every close is drained before the loop is torn down.

namespace
{
std::expected<sockaddr_in, vio::error_t> make_ip4(const char *ip, int port)
{
  sockaddr_in address = {};
  address.sin_family = AF_INET;
  address.sin_port = htons(static_cast<std::uint16_t>(port));
  if (inet_pton(AF_INET, ip, &address.sin_addr) != 1)
  {
    return std::unexpected(vio::make_error(vio::errc::invalid_argument));
  }
  return address;
}

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
  auto addr = make_ip4("127.0.0.1", 0);
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
          auto dest = make_ip4("127.0.0.1", p);
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
            auto dest = make_ip4("127.0.0.1", port);
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
        auto dest = make_ip4("127.0.0.1", port);
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
          auto dest = make_ip4("127.0.0.1", p);
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

        REQUIRE_EXPECTED(vio::udp_set_allocator(
          receiver_pair->first,
          [](void *user, size_t suggested) -> std::span<std::byte>
          {
            ++static_cast<counters_t *>(user)->allocs;
            return {new std::byte[suggested], suggested};
          },
          [](void *user, std::span<std::byte> buf)
          {
            ++static_cast<counters_t *>(user)->deallocs;
            delete[] buf.data();
          },
          &counters));

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
          auto dest = make_ip4("127.0.0.1", p);
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
  CHECK(counters.deallocs == counters.allocs);
}

TEST_CASE("the receive queue is bounded and drops are counted")
{
  static constexpr std::size_t limit = 4;
  constexpr int sent_count = 32;
  vio::event_loop_t event_loop;
  vio::udp_recv_stats_t stats = {};
  int received = 0;

  event_loop.run_in_loop(
    [&]
    {
      return [](vio::event_loop_t &loop, vio::udp_recv_stats_t &stats, int &received) -> vio::task_t<void>
      {
        {
        auto receiver_pair = bound_socket(loop);
        REQUIRE_EXPECTED(receiver_pair);
        const int port = receiver_pair->second;
        vio::udp_set_recv_queue_limit(receiver_pair->first, limit);

        auto reader_or_err = vio::udp_create_reader(receiver_pair->first);
        REQUIRE_EXPECTED(reader_or_err);
        auto reader = std::move(reader_or_err.value());

        co_await [](vio::event_loop_t &el, int p) -> vio::task_t<void>
        {
          auto sender_pair = bound_socket(el);
          REQUIRE_EXPECTED(sender_pair);
          auto dest = make_ip4("127.0.0.1", p);
          REQUIRE_EXPECTED(dest);
          for (int i = 0; i < sent_count; ++i)
          {
            REQUIRE_EXPECTED(vio::udp_try_send(sender_pair->first, as_bytes("flood"), reinterpret_cast<const sockaddr *>(&dest.value())));
          }
          co_return;
        }(loop, port);

        auto sleeper = vio::sleep(loop, std::chrono::milliseconds(100));
        auto idle = co_await sleeper;
        REQUIRE_EXPECTED(idle);

        stats = vio::udp_recv_stats(receiver_pair->first);
        std::array<std::expected<vio::udp_datagram_t, vio::error_t>, 16> out;
        for (auto taken = vio::udp_reader_take_batch(reader, out); taken > 0; taken = vio::udp_reader_take_batch(reader, out))
        {
          for (std::size_t i = 0; i < taken; ++i)
          {
            REQUIRE_EXPECTED(out[i]);
            ++received;
          }
        }
        }
        loop.stop();
      }(event_loop, stats, received);
    });

  event_loop.run();
  CHECK(stats.queued == limit);
  CHECK(stats.dropped_datagrams == sent_count - limit);
  CHECK(stats.recv_errors == 0);
  CHECK(received == static_cast<int>(limit));
}

namespace
{
struct burst_result_t
{
  int received = 0;
  vio::udp_recv_stats_t stats = {};
};

vio::task_t<void> burst_while_idle(vio::event_loop_t &loop, vio::udp_recvmmsg_t mode, std::size_t limit, int total, burst_result_t &result)
{
  {
    auto receiver = vio::udp_create(loop, mode);
    REQUIRE_EXPECTED(receiver);
    auto any = make_ip4("127.0.0.1", 0);
    REQUIRE_EXPECTED(any);
    REQUIRE_EXPECTED(vio::udp_bind(receiver.value(), reinterpret_cast<const sockaddr *>(&any.value())));
    auto name = vio::udp_sockname(receiver.value());
    REQUIRE_EXPECTED(name);
    const int port = ntohs(reinterpret_cast<const sockaddr_in *>(&name.value())->sin_port);
    if (limit > 0)
    {
      vio::udp_set_recv_queue_limit(receiver.value(), limit);
    }
    auto reader_or_err = vio::udp_create_reader(receiver.value());
    REQUIRE_EXPECTED(reader_or_err);
    auto reader = std::move(reader_or_err.value());

    auto sender_pair = bound_socket(loop);
    REQUIRE_EXPECTED(sender_pair);
    auto dest = make_ip4("127.0.0.1", port);
    REQUIRE_EXPECTED(dest);
    const std::vector<std::uint8_t> payload(1200, 0x42);
    constexpr int burst = 20;
    for (int sent = 0; sent < total;)
    {
      for (int i = 0; i < burst && sent < total; ++i, ++sent)
      {
        REQUIRE_EXPECTED(vio::udp_try_send(sender_pair->first, payload, reinterpret_cast<const sockaddr *>(&dest.value())));
      }
      auto pause = vio::sleep(loop, std::chrono::milliseconds(1));
      auto paused = co_await pause;
      REQUIRE_EXPECTED(paused);
    }
    auto settle = vio::sleep(loop, std::chrono::milliseconds(20));
    auto settled = co_await settle;
    REQUIRE_EXPECTED(settled);

    std::array<std::expected<vio::udp_datagram_t, vio::error_t>, 64> out;
    for (auto taken = vio::udp_reader_take_batch(reader, out); taken > 0; taken = vio::udp_reader_take_batch(reader, out))
    {
      for (std::size_t i = 0; i < taken; ++i)
      {
        REQUIRE_EXPECTED(out[i]);
        CHECK(out[i]->data.size() == payload.size());
        ++result.received;
      }
    }
    result.stats = vio::udp_recv_stats(receiver.value());
  }
  loop.stop();
}
} // namespace

TEST_CASE("a reader nobody is awaiting still takes a burst larger than the kernel buffer off the socket")
{
  constexpr int total = 400;
  for (auto mode : {vio::udp_recvmmsg_t::off, vio::udp_recvmmsg_t::on})
  {
    CAPTURE(static_cast<int>(mode));
    vio::event_loop_t event_loop;
    burst_result_t result;
    event_loop.run_in_loop([&] { return burst_while_idle(event_loop, mode, 0, total, result); });
    event_loop.run();
    CHECK(result.received == total);
    CHECK(result.stats.dropped_datagrams == 0);
    CHECK(result.stats.recv_errors == 0);
  }
}

TEST_CASE("a burst beyond the queue limit is dropped from the tail and counted")
{
  constexpr int total = 400;
  constexpr std::size_t limit = 50;
  for (auto mode : {vio::udp_recvmmsg_t::off, vio::udp_recvmmsg_t::on})
  {
    CAPTURE(static_cast<int>(mode));
    vio::event_loop_t event_loop;
    burst_result_t result;
    event_loop.run_in_loop([&] { return burst_while_idle(event_loop, mode, limit, total, result); });
    event_loop.run();
    CHECK(result.received == static_cast<int>(limit));
    CHECK(result.stats.dropped_datagrams == total - limit);
    CHECK(result.stats.recv_errors == 0);
  }
}

TEST_CASE("a datagram from the default allocator holds only its own length")
{
  for (auto mode : {vio::udp_recvmmsg_t::off, vio::udp_recvmmsg_t::on})
  {
    CAPTURE(static_cast<int>(mode));
    vio::event_loop_t event_loop;
    std::size_t size = 0;
    std::size_t capacity = 0;

    event_loop.run_in_loop(
      [&]
      {
        return [](vio::event_loop_t &loop, vio::udp_recvmmsg_t mode, std::size_t &size, std::size_t &capacity) -> vio::task_t<void>
        {
          {
            auto receiver = vio::udp_create(loop, mode);
            REQUIRE_EXPECTED(receiver);
            auto any = make_ip4("127.0.0.1", 0);
            REQUIRE_EXPECTED(any);
            REQUIRE_EXPECTED(vio::udp_bind(receiver.value(), reinterpret_cast<const sockaddr *>(&any.value())));
            auto name = vio::udp_sockname(receiver.value());
            REQUIRE_EXPECTED(name);
            const int port = ntohs(reinterpret_cast<const sockaddr_in *>(&name.value())->sin_port);
            auto reader_or_err = vio::udp_create_reader(receiver.value());
            REQUIRE_EXPECTED(reader_or_err);
            auto reader = std::move(reader_or_err.value());

            auto sender_pair = bound_socket(loop);
            REQUIRE_EXPECTED(sender_pair);
            auto dest = make_ip4("127.0.0.1", port);
            REQUIRE_EXPECTED(dest);
            const std::vector<std::uint8_t> payload(1200, 0x17);
            REQUIRE_EXPECTED(vio::udp_try_send(sender_pair->first, payload, reinterpret_cast<const sockaddr *>(&dest.value())));
            auto datagram = co_await reader;
            REQUIRE_EXPECTED(datagram);
            size = datagram->data.size();
            capacity = datagram->data.capacity();
            CHECK(std::all_of(datagram->data.data(), datagram->data.data() + datagram->data.size(), [](std::byte b) { return b == std::byte{0x17}; }));
          }
          loop.stop();
        }(event_loop, mode, size, capacity);
      });

    event_loop.run();
    CHECK(size == 1200);
    CHECK(capacity == size);
  }
}

TEST_CASE("udp_reader_take_batch drains without suspending")
{
  constexpr int sent_count = 5;
  vio::event_loop_t event_loop;
  std::size_t taken = 0;
  std::size_t taken_when_empty = 1;

  event_loop.run_in_loop(
    [&]
    {
      return [](vio::event_loop_t &loop, std::size_t &taken, std::size_t &taken_when_empty) -> vio::task_t<void>
      {
        {
        auto receiver_pair = bound_socket(loop);
        REQUIRE_EXPECTED(receiver_pair);
        const int port = receiver_pair->second;

        auto reader_or_err = vio::udp_create_reader(receiver_pair->first);
        REQUIRE_EXPECTED(reader_or_err);
        auto reader = std::move(reader_or_err.value());

        co_await [](vio::event_loop_t &el, int p) -> vio::task_t<void>
        {
          auto sender_pair = bound_socket(el);
          REQUIRE_EXPECTED(sender_pair);
          auto dest = make_ip4("127.0.0.1", p);
          REQUIRE_EXPECTED(dest);
          for (int i = 0; i < sent_count; ++i)
          {
            REQUIRE_EXPECTED(vio::udp_try_send(sender_pair->first, as_bytes("drain"), reinterpret_cast<const sockaddr *>(&dest.value())));
          }
          co_return;
        }(loop, port);

        auto sleeper = vio::sleep(loop, std::chrono::milliseconds(100));
        auto idle = co_await sleeper;
        REQUIRE_EXPECTED(idle);

        std::array<std::expected<vio::udp_datagram_t, vio::error_t>, 16> out;
        taken = vio::udp_reader_take_batch(reader, out);
        for (std::size_t i = 0; i < taken; ++i)
        {
          REQUIRE_EXPECTED(out[i]);
        }

        taken_when_empty = vio::udp_reader_take_batch(reader, out);
        }
        loop.stop();
      }(event_loop, taken, taken_when_empty);
    });

  event_loop.run();
  CHECK(taken > 0);
  CHECK(taken_when_empty == 0);
}

TEST_CASE("recvmmsg delivers every datagram exactly once")
{
  constexpr int datagram_count = 40;
  vio::event_loop_t event_loop;
  int received = 0;
  bool using_recvmmsg = false;
  vio::udp_recv_stats_t stats = {};
  vio::buffer_pool_t pool(vio::default_pool_block_size, 64);

  event_loop.run_in_loop(
    [&]
    {
      return [](vio::event_loop_t &loop, vio::buffer_pool_t &pool, int &received, bool &using_recvmmsg, vio::udp_recv_stats_t &stats) -> vio::task_t<void>
      {
        auto receiver = vio::udp_create(loop, vio::udp_recvmmsg_t::on);
        REQUIRE_EXPECTED(receiver);
        using_recvmmsg = vio::udp_using_recvmmsg(receiver.value());
        REQUIRE_EXPECTED(vio::udp_use_buffer_pool(receiver.value(), pool));

        auto addr = make_ip4("127.0.0.1", 0);
        REQUIRE_EXPECTED(addr);
        REQUIRE_EXPECTED(vio::udp_bind(receiver.value(), reinterpret_cast<const sockaddr *>(&addr.value())));
        auto name = vio::udp_sockname(receiver.value());
        REQUIRE_EXPECTED(name);
        const int port = ntohs(reinterpret_cast<const sockaddr_in *>(&name.value())->sin_port);

        auto receiver_task = [](vio::udp_t socket, int &received, vio::udp_recv_stats_t &stats) -> vio::task_t<void>
        {
          auto reader_or_err = vio::udp_create_reader(socket);
          REQUIRE_EXPECTED(reader_or_err);
          auto reader = std::move(reader_or_err.value());
          for (int i = 0; i < datagram_count; ++i)
          {
            auto datagram = co_await reader;
            REQUIRE_EXPECTED(datagram);
            REQUIRE(datagram->data.size() == 5);
            REQUIRE(std::string_view(datagram->data.chars(), datagram->data.size()) == "mmsg!");
            ++received;
          }
          stats = vio::udp_recv_stats(socket);
        }(std::move(receiver.value()), received, stats);

        co_await [](vio::event_loop_t &el, int p) -> vio::task_t<void>
        {
          auto sender_pair = bound_socket(el);
          REQUIRE_EXPECTED(sender_pair);
          auto dest = make_ip4("127.0.0.1", p);
          REQUIRE_EXPECTED(dest);
          for (int i = 0; i < datagram_count; ++i)
          {
            REQUIRE_EXPECTED(vio::udp_try_send(sender_pair->first, as_bytes("mmsg!"), reinterpret_cast<const sockaddr *>(&dest.value())));
          }
          co_return;
        }(loop, port);

        co_await std::move(receiver_task);
        {
          auto tmp = std::move(receiver_task);
        }
        loop.stop();
      }(event_loop, pool, received, using_recvmmsg, stats);
    });

  event_loop.run();

  CHECK(received == datagram_count);
  CHECK(stats.truncated_datagrams == 0);
  MESSAGE("using_recvmmsg=" << using_recvmmsg << " received=" << received << " pool_allocations=" << pool.allocations());
}

TEST_CASE("a reader destroyed mid batch hands the recvmmsg buffer back")
{
  constexpr int datagram_count = 16;
  vio::event_loop_t event_loop;
  int received = 0;
  bool using_recvmmsg = false;
  vio::buffer_pool_t pool(vio::default_pool_block_size, 64);

  event_loop.run_in_loop(
    [&]
    {
      return [](vio::event_loop_t &loop, vio::buffer_pool_t &pool, int &received, bool &using_recvmmsg) -> vio::task_t<void>
      {
        auto receiver = vio::udp_create(loop, vio::udp_recvmmsg_t::on);
        REQUIRE_EXPECTED(receiver);
        using_recvmmsg = vio::udp_using_recvmmsg(receiver.value());
        REQUIRE_EXPECTED(vio::udp_use_buffer_pool(receiver.value(), pool));

        auto addr = make_ip4("127.0.0.1", 0);
        REQUIRE_EXPECTED(addr);
        REQUIRE_EXPECTED(vio::udp_bind(receiver.value(), reinterpret_cast<const sockaddr *>(&addr.value())));
        auto name = vio::udp_sockname(receiver.value());
        REQUIRE_EXPECTED(name);
        const int port = ntohs(reinterpret_cast<const sockaddr_in *>(&name.value())->sin_port);

        auto receiver_task = [](vio::udp_t socket, int &received) -> vio::task_t<void>
        {
          auto reader_or_err = vio::udp_create_reader(socket);
          REQUIRE_EXPECTED(reader_or_err);
          auto reader = std::move(reader_or_err.value());
          auto datagram = co_await reader;
          REQUIRE_EXPECTED(datagram);
          ++received;
        }(std::move(receiver.value()), received);

        co_await [](vio::event_loop_t &el, int p) -> vio::task_t<void>
        {
          auto sender_pair = bound_socket(el);
          REQUIRE_EXPECTED(sender_pair);
          auto dest = make_ip4("127.0.0.1", p);
          REQUIRE_EXPECTED(dest);
          for (int i = 0; i < datagram_count; ++i)
          {
            REQUIRE_EXPECTED(vio::udp_try_send(sender_pair->first, as_bytes("batch"), reinterpret_cast<const sockaddr *>(&dest.value())));
          }
          co_return;
        }(loop, port);

        co_await std::move(receiver_task);
        {
          auto tmp = std::move(receiver_task);
        }
        loop.stop();
      }(event_loop, pool, received, using_recvmmsg);
    });

  event_loop.run();

  CHECK(received == 1);
  // Every block the pool ever handed out is back on its free list.
  CHECK(pool.retained() == pool.allocations());
  MESSAGE("using_recvmmsg=" << using_recvmmsg << " allocations=" << pool.allocations() << " retained=" << pool.retained());
}

TEST_CASE("a second reader on the same socket does not strand the first buffer")
{
  constexpr int datagram_count = 16;
  vio::event_loop_t event_loop;
  int received = 0;
  bool using_recvmmsg = false;
  std::uint64_t allocations = 0;
  std::size_t retained = 0;
  std::size_t queued = 0;
  vio::buffer_pool_t pool(vio::default_pool_block_size, 64);

  event_loop.run_in_loop(
    [&]
    {
      return [](vio::event_loop_t &loop, vio::buffer_pool_t &pool, int &received, bool &using_recvmmsg, std::uint64_t &allocations, std::size_t &retained, std::size_t &queued) -> vio::task_t<void>
      {
        auto receiver = vio::udp_create(loop, vio::udp_recvmmsg_t::on);
        REQUIRE_EXPECTED(receiver);
        using_recvmmsg = vio::udp_using_recvmmsg(receiver.value());
        REQUIRE_EXPECTED(vio::udp_use_buffer_pool(receiver.value(), pool));

        auto addr = make_ip4("127.0.0.1", 0);
        REQUIRE_EXPECTED(addr);
        REQUIRE_EXPECTED(vio::udp_bind(receiver.value(), reinterpret_cast<const sockaddr *>(&addr.value())));
        auto name = vio::udp_sockname(receiver.value());
        REQUIRE_EXPECTED(name);
        const int port = ntohs(reinterpret_cast<const sockaddr_in *>(&name.value())->sin_port);

        auto receiver_task = [](vio::udp_t socket, int &received, vio::buffer_pool_t &pool, std::uint64_t &allocations, std::size_t &retained, std::size_t &queued) -> vio::task_t<void>
        {
          for (int round = 0; round < 2; ++round)
          {
            auto reader_or_err = vio::udp_create_reader(socket);
            REQUIRE_EXPECTED(reader_or_err);
            auto reader = std::move(reader_or_err.value());
            auto datagram = co_await reader;
            REQUIRE_EXPECTED(datagram);
            ++received;
          }
          allocations = pool.allocations();
          retained = pool.retained();
          queued = vio::udp_recv_stats(socket).queued;
        }(std::move(receiver.value()), received, pool, allocations, retained, queued);

        co_await [](vio::event_loop_t &el, int p) -> vio::task_t<void>
        {
          auto sender_pair = bound_socket(el);
          REQUIRE_EXPECTED(sender_pair);
          auto dest = make_ip4("127.0.0.1", p);
          REQUIRE_EXPECTED(dest);
          for (int i = 0; i < datagram_count; ++i)
          {
            REQUIRE_EXPECTED(vio::udp_try_send(sender_pair->first, as_bytes("again"), reinterpret_cast<const sockaddr *>(&dest.value())));
          }
          co_return;
        }(loop, port);

        co_await std::move(receiver_task);
        {
          auto tmp = std::move(receiver_task);
        }
        loop.stop();
      }(event_loop, pool, received, using_recvmmsg, allocations, retained, queued);
    });

  event_loop.run();

  CHECK(received == 2);
  CHECK(retained + queued == allocations);
  CHECK(pool.retained() == pool.allocations());
  MESSAGE("using_recvmmsg=" << using_recvmmsg << " allocations=" << allocations << " retained=" << retained << " queued=" << queued);
}

TEST_CASE("the allocator cannot be swapped under a running reader")
{
  vio::event_loop_t event_loop;
  bool refused = false;
  bool accepted_before = false;

  event_loop.run_in_loop(
    [&]
    {
      return [](vio::event_loop_t &loop, bool &refused, bool &accepted_before) -> vio::task_t<void>
      {
        {
          auto socket = bound_socket(loop);
          REQUIRE_EXPECTED(socket);
          vio::buffer_pool_t pool(2048, 8);

          accepted_before = vio::udp_use_buffer_pool(socket->first, pool).has_value();

          auto reader_or_err = vio::udp_create_reader(socket->first);
          REQUIRE_EXPECTED(reader_or_err);
          auto reader = std::move(reader_or_err.value());

          // Buffers already handed out came from the pool; pointing the
          // socket at a different allocator now would have them freed by the
          // wrong one.
          vio::buffer_pool_t other(64, 8);
          refused = !vio::udp_use_buffer_pool(socket->first, other).has_value();
        }
        loop.stop();
        co_return;
      }(event_loop, refused, accepted_before);
    });

  event_loop.run();
  CHECK(accepted_before);
  CHECK(refused);
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
        valid = *fd != vio::invalid_native_socket;
        loop.stop();
        co_return;
      }(event_loop, valid);
    });

  event_loop.run();
  CHECK(valid);
}

TEST_CASE("a udp reader drains a backlog larger than one burst without a new edge")
{
  constexpr int sent_count = 100;
  for (auto mode : {vio::udp_recvmmsg_t::off, vio::udp_recvmmsg_t::on})
  {
    CAPTURE(static_cast<int>(mode));
    vio::event_loop_t event_loop;
    int received = 0;
    std::uint64_t truncated = 1;

    event_loop.run_in_loop(
      [&]
      {
        return [](vio::event_loop_t &loop, vio::udp_recvmmsg_t mode, int &received, std::uint64_t &truncated) -> vio::task_t<void>
        {
          {
            auto receiver = vio::udp_create(loop, mode);
            REQUIRE_EXPECTED(receiver);
            auto any = make_ip4("127.0.0.1", 0);
            REQUIRE_EXPECTED(any);
            REQUIRE_EXPECTED(vio::udp_bind(receiver.value(), reinterpret_cast<const sockaddr *>(&any.value())));
            auto name = vio::udp_sockname(receiver.value());
            REQUIRE_EXPECTED(name);
            const int port = ntohs(reinterpret_cast<const sockaddr_in *>(&name.value())->sin_port);
            auto reader_or_err = vio::udp_create_reader(receiver.value());
            REQUIRE_EXPECTED(reader_or_err);
            auto reader = std::move(reader_or_err.value());

            auto sender_pair = bound_socket(loop);
            REQUIRE_EXPECTED(sender_pair);
            auto dest = make_ip4("127.0.0.1", port);
            REQUIRE_EXPECTED(dest);
            for (int i = 0; i < sent_count; ++i)
            {
              REQUIRE_EXPECTED(vio::udp_try_send(sender_pair->first, as_bytes("backlog"), reinterpret_cast<const sockaddr *>(&dest.value())));
            }
            auto settle = vio::sleep(loop, std::chrono::milliseconds(20));
            co_await settle;

            bool done = false;
            auto watchdog = [](vio::event_loop_t &el, vio::udp_reader_t &r, const bool &finished) -> vio::task_t<void>
            {
              for (int i = 0; i < 200 && !finished; ++i)
              {
                auto tick = vio::sleep(el, std::chrono::milliseconds(10));
                co_await tick;
              }
              if (!finished)
              {
                r.cancel();
              }
            }(loop, reader, done);

            while (received < sent_count)
            {
              auto datagram = co_await reader;
              if (!datagram.has_value())
              {
                break;
              }
              ++received;
            }
            done = true;
            co_await std::move(watchdog);
            truncated = vio::udp_recv_stats(receiver.value()).truncated_datagrams;
          }
          loop.stop();
        }(event_loop, mode, received, truncated);
      });

    event_loop.run();
    CHECK(received == sent_count);
    CHECK(truncated == 0);
  }
}

TEST_CASE("a second coroutine waiting on the same udp reader is refused, and cancel wakes the first")
{
  vio::event_loop_t event_loop;
  bool second_refused = false;
  bool first_cancelled = false;
  bool resumed_inside_cancel = false;

  event_loop.run_in_loop(
    [&]
    {
      return [](vio::event_loop_t &loop, bool &second_refused, bool &first_cancelled, bool &resumed_inside_cancel) -> vio::task_t<void>
      {
        {
          auto socket = bound_socket(loop);
          REQUIRE_EXPECTED(socket);
          auto reader_or_err = vio::udp_create_reader(socket->first);
          REQUIRE_EXPECTED(reader_or_err);
          auto reader = std::move(reader_or_err.value());

          bool finished = false;
          auto first = [](vio::udp_reader_t &r, bool &cancelled, bool &finished) -> vio::task_t<void>
          {
            auto datagram = co_await r;
            cancelled = !datagram.has_value() && vio::is_cancelled(datagram.error());
            finished = true;
          }(reader, first_cancelled, finished);

          auto second = co_await reader;
          second_refused = !second.has_value() && second.error().code == vio::errc::already_in_progress;

          reader.cancel();
          resumed_inside_cancel = finished;
          co_await std::move(first);
        }
        loop.stop();
      }(event_loop, second_refused, first_cancelled, resumed_inside_cancel);
    });

  event_loop.run();
  CHECK(second_refused);
  CHECK(first_cancelled);
  CHECK(resumed_inside_cancel);
}

TEST_CASE("a datagram larger than a pool block is counted as truncated, not delivered")
{
  vio::event_loop_t event_loop;
  vio::buffer_pool_t pool(256, 8);
  std::string got;
  vio::udp_recv_stats_t stats = {};

  event_loop.run_in_loop(
    [&]
    {
      return [](vio::event_loop_t &loop, vio::buffer_pool_t &pool, std::string &got, vio::udp_recv_stats_t &stats) -> vio::task_t<void>
      {
        {
          auto receiver_pair = bound_socket(loop);
          REQUIRE_EXPECTED(receiver_pair);
          REQUIRE_EXPECTED(vio::udp_use_buffer_pool(receiver_pair->first, pool));
          auto reader_or_err = vio::udp_create_reader(receiver_pair->first);
          REQUIRE_EXPECTED(reader_or_err);
          auto reader = std::move(reader_or_err.value());

          auto sender_pair = bound_socket(loop);
          REQUIRE_EXPECTED(sender_pair);
          auto dest = make_ip4("127.0.0.1", receiver_pair->second);
          REQUIRE_EXPECTED(dest);
          std::vector<std::uint8_t> large(1000, 0x5a);
          REQUIRE_EXPECTED(vio::udp_try_send(sender_pair->first, large, reinterpret_cast<const sockaddr *>(&dest.value())));
          REQUIRE_EXPECTED(vio::udp_try_send(sender_pair->first, as_bytes(""), reinterpret_cast<const sockaddr *>(&dest.value())));
          REQUIRE_EXPECTED(vio::udp_try_send(sender_pair->first, as_bytes("fits"), reinterpret_cast<const sockaddr *>(&dest.value())));

          auto empty = co_await reader;
          REQUIRE_EXPECTED(empty);
          CHECK(empty->data.size() == 0);
          CHECK(empty->sender_port() == sender_pair->second);
          auto datagram = co_await reader;
          REQUIRE_EXPECTED(datagram);
          got.assign(datagram->data.chars(), datagram->data.size());
          stats = vio::udp_recv_stats(receiver_pair->first);
        }
        loop.stop();
      }(event_loop, pool, got, stats);
    });

  event_loop.run();
  CHECK(got == "fits");
  CHECK(stats.truncated_datagrams == 1);
  CHECK(stats.recv_errors == 0);
  CHECK(pool.retained() == pool.allocations());
}
}
