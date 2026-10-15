#include "require_expected.h"

#include <array>
#include <chrono>
#include <cstdint>
#include <span>
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
          auto accepted = make_ip4("127.0.0.1", 9);
          REQUIRE_EXPECTED(accepted);
          static const std::string payload = "which result";
          static const std::vector<std::uint8_t> oversized(65536, 0x5a);
          const auto *bytes = reinterpret_cast<const std::uint8_t *>(payload.data());

          auto first = vio::send_udp(sender_pair->first, oversized.data(), oversized.size(), reinterpret_cast<const sockaddr *>(&accepted.value()));
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

TEST_CASE("an owning send whose token fires before it is awaited reports cancellation even though it went out")
{
  vio::event_loop_t event_loop;
  bool immediate_went_straight_out = false;
  bool parked_finished_first = false;
  int immediate_code = 0;
  int parked_code = 0;
  bool awaited_ok = false;
  std::vector<std::string> got;

  event_loop.run_in_loop(
    [&]
    {
      return [](vio::event_loop_t &loop, bool &immediate_went_straight_out, bool &parked_finished_first, int &immediate_code, int &parked_code, bool &awaited_ok,
                std::vector<std::string> &got) -> vio::task_t<void>
      {
        {
          auto receiver_pair = bound_socket(loop);
          REQUIRE_EXPECTED(receiver_pair);
          auto reader_or_err = vio::udp_create_reader(receiver_pair->first);
          REQUIRE_EXPECTED(reader_or_err);
          auto reader = std::move(reader_or_err.value());
          auto sender_pair = bound_socket(loop);
          REQUIRE_EXPECTED(sender_pair);
          auto dest = make_ip4("127.0.0.1", receiver_pair->second);
          REQUIRE_EXPECTED(dest);
          const auto *to = reinterpret_cast<const sockaddr *>(&dest.value());

          vio::cancellation_t immediate_token;
          auto immediate = vio::send_udp(sender_pair->first, std::string("immediate"), to, &immediate_token);
          immediate_went_straight_out = immediate.op == nullptr;
          immediate_token.cancel();
          auto immediate_result = co_await immediate;
          immediate_code = immediate_result.has_value() ? 0 : immediate_result.error().code;

          vio::detail::udp_target_t target;
          REQUIRE(vio::detail::udp_prepare_target(sender_pair->first.handle.data(), to, target) == 0);
          vio::cancellation_t parked_token;
          auto parked = vio::detail::udp_send_park(sender_pair->first, std::string("parked"), target, &parked_token);
          for (int i = 0; i < 100 && !parked.op->completed; ++i)
          {
            auto tick = vio::sleep(loop, std::chrono::milliseconds(1));
            co_await tick;
          }
          parked_finished_first = parked.op->completed;
          parked_token.cancel();
          auto parked_result = co_await parked;
          parked_code = parked_result.has_value() ? 0 : parked_result.error().code;

          auto fresh_pair = bound_socket(loop);
          REQUIRE_EXPECTED(fresh_pair);
          vio::detail::udp_target_t fresh_target;
          REQUIRE(vio::detail::udp_prepare_target(fresh_pair->first.handle.data(), to, fresh_target) == 0);
          vio::cancellation_t later_token;
          auto awaited = vio::detail::udp_send_park(fresh_pair->first, std::string("awaited"), fresh_target, &later_token);
          auto awaited_result = co_await awaited;
          later_token.cancel();
          awaited_ok = awaited_result.has_value();

          for (int i = 0; i < 3; ++i)
          {
            auto datagram = co_await reader;
            REQUIRE_EXPECTED(datagram);
            got.emplace_back(datagram->data.chars(), datagram->data.size());
          }
        }
        loop.stop();
      }(event_loop, immediate_went_straight_out, parked_finished_first, immediate_code, parked_code, awaited_ok, got);
    });

  event_loop.run();
  CHECK(immediate_went_straight_out);
  CHECK(immediate_code == vio::vio_cancelled);
  CHECK(parked_finished_first);
  CHECK(parked_code == vio::vio_cancelled);
  CHECK(awaited_ok);
  CHECK(got == std::vector<std::string>{"immediate", "parked", "awaited"});
}

TEST_CASE("an owning send that completed unawaited leaves its token, so a cancel that drops it first never reaches it")
{
  vio::event_loop_t event_loop;
  bool completed_before_cancel = false;
  bool left_token = false;
  bool timeout_cancelled = false;
  std::string got;

  event_loop.run_in_loop(
    [&]
    {
      return [](vio::event_loop_t &loop, bool &completed_before_cancel, bool &left_token, bool &timeout_cancelled, std::string &got) -> vio::task_t<void>
      {
        {
          auto receiver_pair = bound_socket(loop);
          REQUIRE_EXPECTED(receiver_pair);
          auto reader_or_err = vio::udp_create_reader(receiver_pair->first);
          REQUIRE_EXPECTED(reader_or_err);
          auto reader = std::move(reader_or_err.value());
          auto sender_pair = bound_socket(loop);
          REQUIRE_EXPECTED(sender_pair);
          auto dest = make_ip4("127.0.0.1", receiver_pair->second);
          REQUIRE_EXPECTED(dest);
          vio::detail::udp_target_t target;
          REQUIRE(vio::detail::udp_prepare_target(sender_pair->first.handle.data(), reinterpret_cast<const sockaddr *>(&dest.value()), target) == 0);

          vio::cancellation_t token;
          auto firer = [](vio::event_loop_t &el, vio::cancellation_t &cancel) -> vio::task_t<void>
          {
            auto tick = vio::sleep(el, std::chrono::milliseconds(30));
            co_await tick;
            cancel.cancel();
          }(loop, token);
          {
            auto timeout = vio::sleep(loop, std::chrono::seconds(5), &token);
            auto send = vio::detail::udp_send_park(sender_pair->first, std::string("unawaited"), target, &token);
            auto *op = send.op;
            REQUIRE(op != nullptr);
            for (int i = 0; i < 20 && !op->completed; ++i)
            {
              auto settle = vio::sleep(loop, std::chrono::milliseconds(1));
              co_await settle;
            }
            completed_before_cancel = op->completed;
            left_token = !op->cancel_registration.active();
            auto result = co_await timeout;
            timeout_cancelled = !result.has_value() && vio::is_cancelled(result.error());
          }
          co_await std::move(firer);

          auto datagram = co_await reader;
          if (datagram.has_value())
          {
            got.assign(datagram->data.chars(), datagram->data.size());
          }
        }
        loop.stop();
      }(event_loop, completed_before_cancel, left_token, timeout_cancelled, got);
    });

  event_loop.run();
  CHECK(completed_before_cancel);
  CHECK(left_token);
  CHECK(timeout_cancelled);
  CHECK(got == "unawaited");
}

TEST_CASE("a send parked on a connected socket never reaches a peer connected after it")
{
  vio::event_loop_t event_loop;
  int cancelled_code = 0;
  int kept_code = 0;
  int borrowed_code = 0;
  std::size_t reached_first_peer = 1;
  std::string first_at_second_peer;

  event_loop.run_in_loop(
    [&]
    {
      return [](vio::event_loop_t &loop, int &cancelled_code, int &kept_code, int &borrowed_code, std::size_t &reached_first_peer, std::string &first_at_second_peer) -> vio::task_t<void>
      {
        {
          auto first_pair = bound_socket(loop);
          REQUIRE_EXPECTED(first_pair);
          auto first_reader_or_err = vio::udp_create_reader(first_pair->first);
          REQUIRE_EXPECTED(first_reader_or_err);
          auto first_reader = std::move(first_reader_or_err.value());
          auto second_pair = bound_socket(loop);
          REQUIRE_EXPECTED(second_pair);
          auto second_reader_or_err = vio::udp_create_reader(second_pair->first);
          REQUIRE_EXPECTED(second_reader_or_err);
          auto second_reader = std::move(second_reader_or_err.value());

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
          }(loop, second_reader, done);

          auto first_peer = make_ip4("127.0.0.1", first_pair->second);
          REQUIRE_EXPECTED(first_peer);
          auto second_peer = make_ip4("127.0.0.1", second_pair->second);
          REQUIRE_EXPECTED(second_peer);
          auto sender_pair = bound_socket(loop);
          REQUIRE_EXPECTED(sender_pair);
          auto &sender = sender_pair->first;
          REQUIRE_EXPECTED(vio::udp_connect(sender, reinterpret_cast<const sockaddr *>(&first_peer.value())));

          vio::detail::udp_target_t target;
          REQUIRE(vio::detail::udp_prepare_target(sender.handle.data(), nullptr, target) == 0);
          vio::cancellation_t token;
          auto cancelled = vio::detail::udp_send_park(sender, std::string("cancelled, meant for the first peer"), target, &token);
          token.cancel();
          auto cancelled_result = co_await cancelled;
          cancelled_code = cancelled_result.has_value() ? 0 : cancelled_result.error().code;
          auto kept = vio::detail::udp_send_park(sender, std::string("kept, meant for the first peer"), target, nullptr);
          static const std::string borrowed_payload = "borrowed, meant for the first peer";
          auto borrowed = vio::detail::udp_send_borrowed_park(sender, reinterpret_cast<const std::uint8_t *>(borrowed_payload.data()), borrowed_payload.size(), target);

          REQUIRE_EXPECTED(vio::udp_disconnect(sender));
          REQUIRE_EXPECTED(vio::udp_connect(sender, reinterpret_cast<const sockaddr *>(&second_peer.value())));

          auto kept_result = co_await kept;
          kept_code = kept_result.has_value() ? 0 : kept_result.error().code;
          auto borrowed_result = co_await borrowed;
          borrowed_code = borrowed_result.has_value() ? 0 : borrowed_result.error().code;

          auto settle = vio::sleep(loop, std::chrono::milliseconds(20));
          co_await settle;
          REQUIRE_EXPECTED(vio::udp_try_send(sender, std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>("marker"), 6), nullptr));
          auto datagram = co_await second_reader;
          if (datagram.has_value())
          {
            first_at_second_peer.assign(datagram->data.chars(), datagram->data.size());
          }
          std::array<std::expected<vio::udp_datagram_t, vio::error_t>, 4> stray;
          reached_first_peer = vio::udp_reader_take_batch(first_reader, stray);
          done = true;
          co_await std::move(watchdog);
        }
        loop.stop();
      }(event_loop, cancelled_code, kept_code, borrowed_code, reached_first_peer, first_at_second_peer);
    });

  event_loop.run();
  CHECK(cancelled_code == vio::vio_cancelled);
  CHECK(kept_code == vio::errc::not_connected);
  CHECK(borrowed_code == vio::errc::not_connected);
  CHECK(first_at_second_peer == "marker");
  CHECK(reached_first_peer == 0);
}
}
