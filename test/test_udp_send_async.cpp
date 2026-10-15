#include "require_expected.h"

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include <doctest/doctest.h>
#include <vio/cancellation.h>
#include <vio/event_loop.h>
#include <vio/operation/sleep.h>
#include <vio/operation/udp.h>
#include <vio/task.h>

// The owning send_udp overload holds the caller's bytes until the socket has
// taken them, so the payload may be a temporary and any number may be in
// flight. Sockets are owned inside the coroutine and the loop stopped from
// within it, so every close drains before teardown.

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

std::expected<std::pair<vio::udp_t, int>, vio::error_t> bound_socket(vio::event_loop_t &loop)
{
  auto udp = vio::udp_create(loop);
  if (!udp.has_value())
  {
    return std::unexpected(udp.error());
  }
  auto addr = make_ip4("127.0.0.1", 0);
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
          got.assign(datagram->data.chars(), datagram->data.size());
        }(std::move(receiver_pair->first), got);

        co_await [](vio::event_loop_t &el, int p) -> vio::task_t<void>
        {
          auto sender_pair = bound_socket(el);
          REQUIRE_EXPECTED(sender_pair);
          auto dest = make_ip4("127.0.0.1", p);
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
          auto dest = make_ip4("127.0.0.1", p);

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
        auto dest = make_ip4("127.0.0.1", 9);

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
        auto dest = make_ip4("127.0.0.1", 9);

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
          got = datagram->data.size();
        }(std::move(receiver_pair->first), got);

        co_await [](vio::event_loop_t &el, int p) -> vio::task_t<void>
        {
          auto sender_pair = bound_socket(el);
          REQUIRE_EXPECTED(sender_pair);
          auto dest = make_ip4("127.0.0.1", p);
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

TEST_CASE("an immediate send result belongs to its own future")
{
  vio::event_loop_t event_loop;
  bool first_failed = false;
  bool second_succeeded = false;

  event_loop.run_in_loop(
    [&]
    {
      return [](vio::event_loop_t &loop, bool &first_failed, bool &second_succeeded) -> vio::task_t<void>
      {
        {
          auto sender_pair = bound_socket(loop);
          REQUIRE_EXPECTED(sender_pair);
          auto refused = make_ip4("127.0.0.1", 0);
          REQUIRE_EXPECTED(refused);
          auto accepted = make_ip4("127.0.0.1", 9);
          REQUIRE_EXPECTED(accepted);
          static const std::string payload = "which result";
          const auto *bytes = reinterpret_cast<const std::uint8_t *>(payload.data());

          auto first = vio::send_udp(sender_pair->first, bytes, payload.size(), reinterpret_cast<const sockaddr *>(&refused.value()));
          auto second = vio::send_udp(sender_pair->first, bytes, payload.size(), reinterpret_cast<const sockaddr *>(&accepted.value()));
          auto first_result = co_await first;
          auto second_result = co_await second;
          first_failed = !first_result.has_value();
          second_succeeded = second_result.has_value();
        }
        loop.stop();
      }(event_loop, first_failed, second_succeeded);
    });

  event_loop.run();
  CHECK(first_failed);
  CHECK(second_succeeded);
}

TEST_CASE("cancelling a parked owning send stops the wait, not the datagram")
{
  vio::event_loop_t event_loop;
  std::string got;
  bool cancelled = false;
  bool answered_at_once = false;

  event_loop.run_in_loop(
    [&]
    {
      return [](vio::event_loop_t &loop, std::string &got, bool &cancelled, bool &answered_at_once) -> vio::task_t<void>
      {
        {
          auto receiver_pair = bound_socket(loop);
          REQUIRE_EXPECTED(receiver_pair);
          auto reader_or_err = vio::udp_create_reader(receiver_pair->first);
          REQUIRE_EXPECTED(reader_or_err);
          auto reader = std::move(reader_or_err.value());

          bool done = false;
          auto watchdog = [](vio::event_loop_t &el, vio::udp_reader_t &r, const bool &finished) -> vio::task_t<void>
          {
            for (int i = 0; i < 100 && !finished; ++i)
            {
              auto tick = vio::sleep(el, std::chrono::milliseconds(10));
              co_await tick;
            }
            if (!finished)
            {
              r.cancel();
            }
          }(loop, reader, done);

          auto sender_pair = bound_socket(loop);
          REQUIRE_EXPECTED(sender_pair);
          auto dest = make_ip4("127.0.0.1", receiver_pair->second);
          REQUIRE_EXPECTED(dest);
          vio::detail::udp_target_t target;
          REQUIRE(vio::detail::udp_prepare_target(sender_pair->first.handle.data(), reinterpret_cast<const sockaddr *>(&dest.value()), target) == 0);

          vio::cancellation_t cancel;
          auto pending = vio::detail::udp_send_park(sender_pair->first, std::string("still sent"), target, &cancel);
          cancel.cancel();
          answered_at_once = pending.await_ready();
          auto result = co_await pending;
          cancelled = !result.has_value() && vio::is_cancelled(result.error());

          auto datagram = co_await reader;
          if (datagram.has_value())
          {
            got.assign(datagram->data.chars(), datagram->data.size());
          }
          done = true;
          co_await std::move(watchdog);
        }
        loop.stop();
      }(event_loop, got, cancelled, answered_at_once);
    });

  event_loop.run();
  CHECK(answered_at_once);
  CHECK(cancelled);
  CHECK(got == "still sent");
}
}
