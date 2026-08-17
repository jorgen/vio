#include "require_expected.h"

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include <doctest/doctest.h>
#include <vio/cancellation.h>
#include <vio/event_loop.h>
#include <vio/operation/tcp.h>
#include <vio/operation/udp.h>
#include <vio/task.h>

// The owning send_udp overload holds the caller's bytes until libuv is done
// with them, so the payload may be a temporary and any number may be in
// flight. Sockets are owned inside the coroutine and the loop stopped from
// within it, so every uv_close drains before teardown.

namespace
{
std::expected<std::pair<vio::udp_t, int>, vio::error_t> bound_socket(vio::event_loop_t &loop)
{
  auto udp = vio::udp_create(loop);
  if (!udp.has_value())
  {
    return std::unexpected(udp.error());
  }
  auto addr = vio::ip4_addr("127.0.0.1", 0);
  auto bound = vio::udp_bind(udp.value(), reinterpret_cast<const sockaddr *>(&addr.value()));
  if (!bound.has_value())
  {
    return std::unexpected(bound.error());
  }
  auto name = vio::udp_sockname(udp.value());
  const auto *in = reinterpret_cast<const sockaddr_in *>(&name.value());
  return std::make_pair(std::move(udp.value()), static_cast<int>(ntohs(in->sin_port)));
}
} // namespace

TEST_SUITE("udp async send")
{
TEST_CASE("an owned payload survives a temporary going out of scope")
{
  vio::event_loop_t event_loop;
  std::string got;

  event_loop.run_in_loop(
    [&]
    {
      return [](vio::event_loop_t &loop, std::string &got) -> vio::task_t<void>
      {
        auto receiver_pair = bound_socket(loop);
        REQUIRE_EXPECTED(receiver_pair);
        const int port = receiver_pair->second;

        auto receiver_task = [](vio::udp_t receiver, std::string &got) -> vio::task_t<void>
        {
          auto reader_or_err = vio::udp_create_reader(receiver);
          REQUIRE_EXPECTED(reader_or_err);
          auto reader = std::move(reader_or_err.value());
          auto datagram = co_await reader;
          REQUIRE_EXPECTED(datagram);
          got.assign(datagram->data->base, datagram->data->len);
        }(std::move(receiver_pair->first), got);

        co_await [](vio::event_loop_t &el, int p) -> vio::task_t<void>
        {
          auto sender_pair = bound_socket(el);
          REQUIRE_EXPECTED(sender_pair);
          auto dest = vio::ip4_addr("127.0.0.1", p);
          auto sent = co_await vio::send_udp(sender_pair->first, std::string("owned payload"), reinterpret_cast<const sockaddr *>(&dest.value()));
          REQUIRE_EXPECTED(sent);
        }(loop, port);

        co_await std::move(receiver_task);
        {
          auto tmp = std::move(receiver_task);
        }
        loop.stop();
      }(event_loop, got);
    });

  event_loop.run();
  CHECK(got == "owned payload");
}

TEST_CASE("many sends are in flight at once")
{
  constexpr int send_count = 24;
  vio::event_loop_t event_loop;
  int received = 0;
  int completed = 0;

  event_loop.run_in_loop(
    [&]
    {
      return [](vio::event_loop_t &loop, int &received, int &completed) -> vio::task_t<void>
      {
        auto receiver_pair = bound_socket(loop);
        REQUIRE_EXPECTED(receiver_pair);
        const int port = receiver_pair->second;

        auto receiver_task = [](vio::udp_t receiver, int &received) -> vio::task_t<void>
        {
          auto reader_or_err = vio::udp_create_reader(receiver);
          REQUIRE_EXPECTED(reader_or_err);
          auto reader = std::move(reader_or_err.value());
          for (int i = 0; i < send_count; ++i)
          {
            auto datagram = co_await reader;
            REQUIRE_EXPECTED(datagram);
            ++received;
          }
        }(std::move(receiver_pair->first), received);

        co_await [](vio::event_loop_t &el, int p, int &completed) -> vio::task_t<void>
        {
          auto sender_pair = bound_socket(el);
          REQUIRE_EXPECTED(sender_pair);
          auto dest = vio::ip4_addr("127.0.0.1", p);

          // Submitted before any is awaited: the single-slot send_udp would
          // have refused the second one.
          std::vector<vio::udp_send_awaitable_t> pending;
          pending.reserve(send_count);
          for (int i = 0; i < send_count; ++i)
          {
            pending.emplace_back(vio::send_udp(sender_pair->first, std::string("payload ") + std::to_string(i), reinterpret_cast<const sockaddr *>(&dest.value())));
          }
          for (auto &send : pending)
          {
            auto result = co_await send;
            if (result.has_value())
            {
              ++completed;
            }
          }
          co_return;
        }(loop, port, completed);

        co_await std::move(receiver_task);
        {
          auto tmp = std::move(receiver_task);
        }
        loop.stop();
      }(event_loop, received, completed);
    });

  event_loop.run();
  CHECK(completed == send_count);
  CHECK(received == send_count);
}

TEST_CASE("a send cancelled before submission fails immediately")
{
  vio::event_loop_t event_loop;
  bool cancelled = false;

  event_loop.run_in_loop(
    [&]
    {
      return [](vio::event_loop_t &loop, bool &cancelled) -> vio::task_t<void>
      {
        auto sender_pair = bound_socket(loop);
        REQUIRE_EXPECTED(sender_pair);
        auto dest = vio::ip4_addr("127.0.0.1", 9);

        vio::cancellation_t cancel;
        cancel.cancel();

        auto result = co_await vio::send_udp(sender_pair->first, std::string("never sent"), reinterpret_cast<const sockaddr *>(&dest.value()), &cancel);
        cancelled = !result.has_value() && vio::is_cancelled(result.error());
        loop.stop();
      }(event_loop, cancelled);
    });

  event_loop.run();
  CHECK(cancelled);
}

TEST_CASE("an abandoned send still completes without leaking")
{
  vio::event_loop_t event_loop;
  bool reached_end = false;

  event_loop.run_in_loop(
    [&]
    {
      return [](vio::event_loop_t &loop, bool &reached_end) -> vio::task_t<void>
      {
        auto sender_pair = bound_socket(loop);
        REQUIRE_EXPECTED(sender_pair);
        auto dest = vio::ip4_addr("127.0.0.1", 9);

        // Dropped without ever being awaited: the operation must outlive the
        // awaitable, because libuv is still reading the payload.
        {
          auto discarded = vio::send_udp(sender_pair->first, std::string("dropped on the floor"), reinterpret_cast<const sockaddr *>(&dest.value()));
        }

        auto settle = co_await vio::send_udp(sender_pair->first, std::string("after"), reinterpret_cast<const sockaddr *>(&dest.value()));
        REQUIRE_EXPECTED(settle);
        reached_end = true;
        loop.stop();
      }(event_loop, reached_end);
    });

  event_loop.run();
  CHECK(reached_end);
}

TEST_CASE("a vector payload is accepted")
{
  vio::event_loop_t event_loop;
  std::size_t got = 0;

  event_loop.run_in_loop(
    [&]
    {
      return [](vio::event_loop_t &loop, std::size_t &got) -> vio::task_t<void>
      {
        auto receiver_pair = bound_socket(loop);
        REQUIRE_EXPECTED(receiver_pair);
        const int port = receiver_pair->second;

        auto receiver_task = [](vio::udp_t receiver, std::size_t &got) -> vio::task_t<void>
        {
          auto reader_or_err = vio::udp_create_reader(receiver);
          REQUIRE_EXPECTED(reader_or_err);
          auto reader = std::move(reader_or_err.value());
          auto datagram = co_await reader;
          REQUIRE_EXPECTED(datagram);
          got = datagram->data->len;
        }(std::move(receiver_pair->first), got);

        co_await [](vio::event_loop_t &el, int p) -> vio::task_t<void>
        {
          auto sender_pair = bound_socket(el);
          REQUIRE_EXPECTED(sender_pair);
          auto dest = vio::ip4_addr("127.0.0.1", p);
          std::vector<std::uint8_t> payload(37, 0x5a);
          auto sent = co_await vio::send_udp(sender_pair->first, std::move(payload), reinterpret_cast<const sockaddr *>(&dest.value()));
          REQUIRE_EXPECTED(sent);
        }(loop, port);

        co_await std::move(receiver_task);
        {
          auto tmp = std::move(receiver_task);
        }
        loop.stop();
      }(event_loop, got);
    });

  event_loop.run();
  CHECK(got == 37);
}
}
