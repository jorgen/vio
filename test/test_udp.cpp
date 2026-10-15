#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <ostream>
#include <vector>

#include <doctest/doctest.h>
#include <vio/cancellation.h>
#include <vio/operation/sleep.h>
#include <string>
#include <string_view>
#include <vio/error.h>
#include <vio/event_loop.h>
#include <vio/operation/udp.h>
#include <vio/operation/udp_datagram.h>
#include <vio/task.h>

#include "require_expected.h"

#if defined(__SANITIZE_ADDRESS__)
#define VIO_TEST_ASAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define VIO_TEST_ASAN 1
#endif
#endif
#if defined(VIO_TEST_ASAN)
extern "C" int __asan_address_is_poisoned(void const volatile *address);
#endif

using namespace std::chrono_literals;

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

std::expected<sockaddr_in6, vio::error_t> make_ip6(const char *ip, int port)
{
  sockaddr_in6 address = {};
  address.sin6_family = AF_INET6;
  address.sin6_port = htons(static_cast<std::uint16_t>(port));
  if (inet_pton(AF_INET6, ip, &address.sin6_addr) != 1)
  {
    return std::unexpected(vio::make_error(vio::errc::invalid_argument));
  }
  return address;
}

#define PROPAGATE_ERROR(x)                                                                                                                                                                                                 \
  if (!(x).has_value())                                                                                                                                                                                                    \
    return std::unexpected(std::move((x).error()));

std::expected<std::pair<vio::udp_t, int>, vio::error_t> get_udp_ephemeral_port(vio::event_loop_t &event_loop)
{
  auto addr_or_err = make_ip4("127.0.0.1", 0);
  PROPAGATE_ERROR(addr_or_err);
  auto udp_or_err = vio::udp_create(event_loop);
  PROPAGATE_ERROR(udp_or_err);
  auto bind_res = vio::udp_bind(udp_or_err.value(), reinterpret_cast<const sockaddr *>(&addr_or_err.value()));
  PROPAGATE_ERROR(bind_res);

  auto sockname_result = vio::udp_sockname(udp_or_err.value());
  PROPAGATE_ERROR(sockname_result);
  sockaddr_storage sa_storage = sockname_result.value();
  const auto *sa_in = reinterpret_cast<sockaddr_in *>(&sa_storage);
  return std::make_pair(std::move(udp_or_err.value()), static_cast<int>(ntohs(sa_in->sin_port)));
}

TEST_SUITE("UDP")
{
TEST_CASE("udp basic send and receive")
{
  vio::event_loop_t event_loop;
  bool verified = false;

  event_loop.run_in_loop([&] {
    return [](vio::event_loop_t &event_loop, bool &verified) -> vio::task_t<void>
      {
        auto receiver_pair = get_udp_ephemeral_port(event_loop);
        REQUIRE_EXPECTED(receiver_pair);
        int port = receiver_pair->second;

        auto receiver_task = [](vio::udp_t receiver) -> vio::task_t<void>
        {
          auto reader_or_err = vio::udp_create_reader(receiver);
          REQUIRE_EXPECTED(reader_or_err);
          auto reader = std::move(reader_or_err.value());
          auto recv_result = co_await reader;
          REQUIRE_EXPECTED(recv_result);
          auto &datagram = recv_result.value();
          std::string_view sv(datagram.data.chars(), datagram.data.size());
          REQUIRE(sv == "hello udp");
          REQUIRE(datagram.sender_port() > 0);
        }(std::move(receiver_pair->first));

        co_await [](vio::event_loop_t &el, int p) -> vio::task_t<void>
        {
          auto sender_or_err = vio::udp_create(el);
          REQUIRE_EXPECTED(sender_or_err);
          auto sender = std::move(sender_or_err.value());

          auto dest_addr = make_ip4("127.0.0.1", p);
          REQUIRE_EXPECTED(dest_addr);

          std::string msg = "hello udp";
          auto send_result = co_await vio::send_udp(sender, reinterpret_cast<const uint8_t *>(msg.data()), msg.size(), reinterpret_cast<const sockaddr *>(&dest_addr.value()));
          REQUIRE_EXPECTED(send_result);
        }(event_loop, port);

        co_await std::move(receiver_task);
        verified = true;
        {
          auto tmp = std::move(receiver_task);
        }
        event_loop.stop();
      }(event_loop, verified);
  });

  event_loop.run();
  REQUIRE(verified);
}

TEST_CASE("udp echo multiple datagrams")
{
  vio::event_loop_t event_loop;
  bool verified = false;

  event_loop.run_in_loop([&] {
    return [](vio::event_loop_t &event_loop, bool &verified) -> vio::task_t<void>
      {
        auto echo_pair = get_udp_ephemeral_port(event_loop);
        REQUIRE_EXPECTED(echo_pair);
        int echo_port = echo_pair->second;

        constexpr int num_datagrams = 5;

        auto echo_task = [](vio::udp_t echo_sock, int count) -> vio::task_t<void>
        {
          auto reader_or_err = vio::udp_create_reader(echo_sock);
          REQUIRE_EXPECTED(reader_or_err);
          auto reader = std::move(reader_or_err.value());
          for (int i = 0; i < count; i++)
          {
            auto recv_result = co_await reader;
            REQUIRE_EXPECTED(recv_result);
            auto &datagram = recv_result.value();
            auto send_result = co_await vio::send_udp(echo_sock, reinterpret_cast<const uint8_t *>(datagram.data.data()), datagram.data.size(), datagram.get_sender());
            REQUIRE_EXPECTED(send_result);
          }
        }(std::move(echo_pair->first), num_datagrams);

        co_await [](vio::event_loop_t &el, int p, int count, bool &v) -> vio::task_t<void>
        {
          auto client_pair = get_udp_ephemeral_port(el);
          REQUIRE_EXPECTED(client_pair);
          auto client = std::move(client_pair->first);

          auto dest_addr = make_ip4("127.0.0.1", p);
          REQUIRE_EXPECTED(dest_addr);

          auto reader_or_err = vio::udp_create_reader(client);
          REQUIRE_EXPECTED(reader_or_err);
          auto reader = std::move(reader_or_err.value());

          for (int i = 0; i < count; i++)
          {
            std::string msg = "datagram_" + std::to_string(i);
            auto send_result = co_await vio::send_udp(client, reinterpret_cast<const uint8_t *>(msg.data()), msg.size(), reinterpret_cast<const sockaddr *>(&dest_addr.value()));
            REQUIRE_EXPECTED(send_result);

            auto recv_result = co_await reader;
            REQUIRE_EXPECTED(recv_result);
            auto &datagram = recv_result.value();
            std::string str(datagram.data.chars(), datagram.data.size());
            REQUIRE(str == msg);
          }
          v = true;
        }(event_loop, echo_port, num_datagrams, verified);

        co_await std::move(echo_task);
        {
          auto tmp = std::move(echo_task);
        }
        event_loop.stop();
      }(event_loop, verified);
  });

  event_loop.run();
  REQUIRE(verified);
}

TEST_CASE("udp connected mode")
{
  vio::event_loop_t event_loop;
  bool verified = false;

  event_loop.run_in_loop([&] {
    return [](vio::event_loop_t &event_loop, bool &verified) -> vio::task_t<void>
      {
        auto receiver_pair = get_udp_ephemeral_port(event_loop);
        REQUIRE_EXPECTED(receiver_pair);
        int port = receiver_pair->second;

        auto receiver_task = [](vio::udp_t receiver) -> vio::task_t<void>
        {
          auto reader_or_err = vio::udp_create_reader(receiver);
          REQUIRE_EXPECTED(reader_or_err);
          auto reader = std::move(reader_or_err.value());
          auto recv_result = co_await reader;
          REQUIRE_EXPECTED(recv_result);
          auto &datagram = recv_result.value();
          std::string_view sv(datagram.data.chars(), datagram.data.size());
          REQUIRE(sv == "connected mode");
        }(std::move(receiver_pair->first));

        co_await [](vio::event_loop_t &el, int p) -> vio::task_t<void>
        {
          auto sender_or_err = vio::udp_create(el);
          REQUIRE_EXPECTED(sender_or_err);
          auto sender = std::move(sender_or_err.value());

          auto dest_addr = make_ip4("127.0.0.1", p);
          REQUIRE_EXPECTED(dest_addr);

          auto connect_result = vio::udp_connect(sender, reinterpret_cast<const sockaddr *>(&dest_addr.value()));
          REQUIRE_EXPECTED(connect_result);

          std::string msg = "connected mode";
          auto send_result = co_await vio::send_udp(sender, reinterpret_cast<const uint8_t *>(msg.data()), msg.size());
          REQUIRE_EXPECTED(send_result);
        }(event_loop, port);

        co_await std::move(receiver_task);
        {
          auto tmp = std::move(receiver_task);
        }
        verified = true;
        event_loop.stop();
      }(event_loop, verified);
  });

  event_loop.run();
  REQUIRE(verified);
}

TEST_CASE("udp cancel reader")
{
  vio::event_loop_t event_loop;
  bool reader_cancelled = false;

  event_loop.run_in_loop([&] {
    return [](vio::event_loop_t &event_loop, bool &reader_cancelled) -> vio::task_t<void>
      {
        co_await [](vio::event_loop_t &el, bool &cancelled) -> vio::task_t<void>
        {
          auto udp_pair = get_udp_ephemeral_port(el);
          REQUIRE_EXPECTED(udp_pair);
          auto udp = std::move(udp_pair->first);

          auto reader_or_err = vio::udp_create_reader(udp);
          REQUIRE_EXPECTED(reader_or_err);
          auto reader = std::move(reader_or_err.value());

          reader.cancel();
          REQUIRE(reader.is_cancelled());

          auto recv_result = co_await reader;
          REQUIRE(!recv_result.has_value());
          REQUIRE(recv_result.error().code == vio::errc::canceled);
          cancelled = true;
        }(event_loop, reader_cancelled);

        event_loop.stop();
      }(event_loop, reader_cancelled);
  });

  event_loop.run();
  REQUIRE(reader_cancelled);
}

TEST_CASE("udp cannot create multiple active readers")
{
  vio::event_loop_t event_loop;
  bool error_caught = false;

  event_loop.run_in_loop([&] {
    return [](vio::event_loop_t &event_loop, bool &error_caught) -> vio::task_t<void>
      {
        co_await [](vio::event_loop_t &el, bool &ec) -> vio::task_t<void>
        {
          auto udp_pair = get_udp_ephemeral_port(el);
          REQUIRE_EXPECTED(udp_pair);
          auto udp = std::move(udp_pair->first);

          auto reader1 = vio::udp_create_reader(udp);
          REQUIRE_EXPECTED(reader1);

          auto reader2 = vio::udp_create_reader(udp);
          REQUIRE(!reader2.has_value());
          ec = true;
          co_return;
        }(event_loop, error_caught);

        event_loop.stop();
      }(event_loop, error_caught);
  });

  event_loop.run();
  REQUIRE(error_caught);
}

TEST_CASE("udp ipv6 loopback")
{
  vio::event_loop_t event_loop;
  bool verified = false;

  event_loop.run_in_loop([&] {
    return [](vio::event_loop_t &event_loop, bool &verified) -> vio::task_t<void>
      {
        auto addr_or_err = make_ip6("::1", 0);
        REQUIRE_EXPECTED(addr_or_err);
        auto receiver_or_err = vio::udp_create(event_loop);
        REQUIRE_EXPECTED(receiver_or_err);
        auto bind_res = vio::udp_bind(receiver_or_err.value(), reinterpret_cast<const sockaddr *>(&addr_or_err.value()));
        REQUIRE_EXPECTED(bind_res);

        auto sockname_result = vio::udp_sockname(receiver_or_err.value());
        REQUIRE_EXPECTED(sockname_result);
        sockaddr_storage sa_storage = sockname_result.value();
        const auto *sa_in6 = reinterpret_cast<sockaddr_in6 *>(&sa_storage);
        int port = ntohs(sa_in6->sin6_port);

        auto receiver_task = [](vio::udp_t receiver) -> vio::task_t<void>
        {
          auto reader_or_err = vio::udp_create_reader(receiver);
          REQUIRE_EXPECTED(reader_or_err);
          auto reader = std::move(reader_or_err.value());
          auto recv_result = co_await reader;
          REQUIRE_EXPECTED(recv_result);
          auto &datagram = recv_result.value();
          std::string_view sv(datagram.data.chars(), datagram.data.size());
          REQUIRE(sv == "ipv6_udp_test");
          REQUIRE(datagram.sender_addr.ss_family == AF_INET6);
        }(std::move(receiver_or_err.value()));

        co_await [](vio::event_loop_t &el, int p) -> vio::task_t<void>
        {
          auto sender_or_err = vio::udp_create(el);
          REQUIRE_EXPECTED(sender_or_err);
          auto sender = std::move(sender_or_err.value());

          auto dest_addr = make_ip6("::1", p);
          REQUIRE_EXPECTED(dest_addr);

          std::string msg = "ipv6_udp_test";
          auto send_result = co_await vio::send_udp(sender, reinterpret_cast<const uint8_t *>(msg.data()), msg.size(), reinterpret_cast<const sockaddr *>(&dest_addr.value()));
          REQUIRE_EXPECTED(send_result);
        }(event_loop, port);

        co_await std::move(receiver_task);
        { auto tmp = std::move(receiver_task); }
        verified = true;
        event_loop.stop();
      }(event_loop, verified);
  });

  event_loop.run();
  REQUIRE(verified);
}

TEST_CASE("udp sockname returns correct address")
{
  vio::event_loop_t event_loop;

  auto addr_or_err = make_ip4("127.0.0.1", 0);
  REQUIRE_EXPECTED(addr_or_err);
  auto udp_or_err = vio::udp_create(event_loop);
  REQUIRE_EXPECTED(udp_or_err);
  auto bind_res = vio::udp_bind(udp_or_err.value(), reinterpret_cast<const sockaddr *>(&addr_or_err.value()));
  REQUIRE_EXPECTED(bind_res);

  auto sockname_result = vio::udp_sockname(udp_or_err.value());
  REQUIRE_EXPECTED(sockname_result);

  sockaddr_storage sa_storage = sockname_result.value();
  REQUIRE(sa_storage.ss_family == AF_INET);
  const auto *sa_in = reinterpret_cast<sockaddr_in *>(&sa_storage);
  REQUIRE(ntohs(sa_in->sin_port) > 0);

  { auto tmp = std::move(udp_or_err); }
  event_loop.stop();
  event_loop.run();
}
} // TEST_SUITE

TEST_CASE("a datagram carries its ECN codepoint through our own recvmsg")
{
  // The whole reason for taking the read away from libuv. libuv's recvmsg
  // leaves msg_control null, so the codepoint the kernel reports alongside the
  // payload is dropped before anything can see it. This reads the socket
  // directly and asks for the control message.
  vio::event_loop_t event_loop;
  bool verified = false;
  int seen_ecn = -1;
  std::string seen_payload;

  event_loop.run_in_loop([&] {
    return [](vio::event_loop_t &event_loop, bool &verified, int &seen_ecn, std::string &seen_payload) -> vio::task_t<void>
      {
        auto receiver_pair = get_udp_ephemeral_port(event_loop);
        REQUIRE_EXPECTED(receiver_pair);
        int port = receiver_pair->second;
        auto receiver = std::move(receiver_pair->first);

        auto reader_or_err = vio::datagram_reader_t::create(event_loop, receiver);
        REQUIRE_EXPECTED(reader_or_err);
        auto reader = std::move(reader_or_err.value());
        REQUIRE_EXPECTED(reader.receive_ecn(true));

        auto sender_pair = get_udp_ephemeral_port(event_loop);
        REQUIRE_EXPECTED(sender_pair);
        auto sender = std::move(sender_pair->first);

        auto destination = make_ip4("127.0.0.1", port);
        REQUIRE_EXPECTED(destination);
        const std::string message = "marked";
        // Section 13.4 of RFC 9000: marked per datagram, in a control message.
        // Windows has no socket option for the outgoing codepoint at all, and
        // per-datagram is the better shape anyway -- one socket can carry
        // several connections whose paths disagree about ECN.
        const std::span<const std::uint8_t> payload(reinterpret_cast<const std::uint8_t *>(message.data()), message.size());
        auto sent = vio::send_datagram(sender, payload, reinterpret_cast<const sockaddr *>(&destination.value()), vio::udp_ecn_t::ect0);
        REQUIRE_EXPECTED(sent);

        auto received = co_await reader;
        REQUIRE_EXPECTED(received);
        seen_payload.assign(received->data.begin(), received->data.end());
        seen_ecn = static_cast<int>(received->ecn);

        verified = true;
        event_loop.stop();
      }(event_loop, verified, seen_ecn, seen_payload);
  });

  event_loop.run();
  REQUIRE(verified);
  CHECK(seen_payload == "marked");
  // ECT(0) is 0b10. Arriving as not_ect would mean the control message never
  // came through, which is the bug this whole path exists to fix.
  CHECK(seen_ecn == static_cast<int>(vio::udp_ecn_t::ect0));
}
TEST_CASE("one send carries several datagrams through segmentation offload")
{
  // The change that moves throughput most: one system call puts several
  // datagrams on the wire, and one read can take several off it. Whether the
  // kernel and interface actually coalesce on the way in is theirs to decide --
  // what has to hold either way is that the pieces come back whole, in order,
  // and with the right boundaries.
  vio::event_loop_t event_loop;
  bool verified = false;
  bool segmented = false;
  std::vector<std::string> pieces;

  event_loop.run_in_loop([&] {
    return [](vio::event_loop_t &event_loop, bool &verified, bool &segmented, std::vector<std::string> &pieces) -> vio::task_t<void>
      {
        auto receiver_pair = get_udp_ephemeral_port(event_loop);
        REQUIRE_EXPECTED(receiver_pair);
        int port = receiver_pair->second;
        auto receiver = std::move(receiver_pair->first);

        auto reader_or_err = vio::datagram_reader_t::create(event_loop, receiver);
        REQUIRE_EXPECTED(reader_or_err);
        auto reader = std::move(reader_or_err.value());
        // Refusal is allowed -- it depends on the kernel and the interface --
        // so the result is noted rather than required.
        const bool coalescing = reader.receive_coalesced(65536).has_value();
        (void)coalescing;

        auto sender_pair = get_udp_ephemeral_port(event_loop);
        REQUIRE_EXPECTED(sender_pair);
        auto sender = std::move(sender_pair->first);

        auto destination = make_ip4("127.0.0.1", port);
        REQUIRE_EXPECTED(destination);

        // Five segments of a hundred bytes, each filled with its own index.
        // Every segment is full length except the last, which is the rule that
        // makes a batch decodable at the far end.
        constexpr std::size_t segment = 100;
        constexpr std::size_t count = 5;
        std::vector<std::uint8_t> batch(segment * count);
        for (std::size_t i = 0; i < count; ++i)
        {
          std::fill(batch.begin() + static_cast<std::ptrdiff_t>(i * segment), batch.begin() + static_cast<std::ptrdiff_t>((i + 1) * segment), static_cast<std::uint8_t>('a' + i));
        }

        auto sent = vio::send_segments(sender, batch, segment, reinterpret_cast<const sockaddr *>(&destination.value()), vio::udp_ecn_t::not_ect);
        if (!sent.has_value())
        {
          // No segmentation here. Nothing to test, and not a failure of ours.
          verified = true;
          event_loop.stop();
          co_return;
        }
        segmented = true;

        for (std::size_t i = 0; i < count; ++i)
        {
          auto received = co_await reader;
          REQUIRE_EXPECTED(received);
          pieces.emplace_back(reinterpret_cast<const char *>(received->data.data()), received->data.size());
        }

        verified = true;
        event_loop.stop();
      }(event_loop, verified, segmented, pieces);
  });

  event_loop.run();
  REQUIRE(verified);
  if (segmented)
  {
    REQUIRE(pieces.size() == 5);
    for (std::size_t i = 0; i < pieces.size(); ++i)
    {
      CAPTURE(i);
      CHECK(pieces[i].size() == 100);
      CHECK(pieces[i] == std::string(100, static_cast<char>('a' + i)));
    }
  }
}

std::span<const std::uint8_t> text_bytes(std::string_view text)
{
  return {reinterpret_cast<const std::uint8_t *>(text.data()), text.size()};
}

int port_of(const sockaddr *address)
{
  if (address == nullptr)
  {
    return -1;
  }
  if (address->sa_family == AF_INET6)
  {
    return ntohs(reinterpret_cast<const sockaddr_in6 *>(address)->sin6_port);
  }
  return ntohs(reinterpret_cast<const sockaddr_in *>(address)->sin_port);
}

vio::task_t<void> cancel_after(vio::event_loop_t &loop, vio::datagram_reader_t &reader, const bool &done, std::chrono::milliseconds limit)
{
  for (auto waited = 0ms; waited < limit && !done; waited += 10ms)
  {
    co_await vio::sleep(loop, 10ms);
  }
  if (!done)
  {
    reader.cancel();
  }
}

TEST_SUITE("datagram path")
{
TEST_CASE("a backlog larger than one wakeup drains without a new edge")
{
  constexpr int sent_count = 100;
  vio::event_loop_t event_loop;
  int received = 0;

  event_loop.run_in_loop([&] {
    return [](vio::event_loop_t &loop, int &received) -> vio::task_t<void>
      {
        {
          auto receiver_pair = get_udp_ephemeral_port(loop);
          REQUIRE_EXPECTED(receiver_pair);
          auto reader_or_err = vio::datagram_reader_t::create(loop, receiver_pair->first);
          REQUIRE_EXPECTED(reader_or_err);
          auto reader = std::move(reader_or_err.value());

          auto sender_pair = get_udp_ephemeral_port(loop);
          REQUIRE_EXPECTED(sender_pair);
          auto destination = make_ip4("127.0.0.1", receiver_pair->second);
          REQUIRE_EXPECTED(destination);
          for (int i = 0; i < sent_count; ++i)
          {
            REQUIRE_EXPECTED(vio::udp_try_send(sender_pair->first, text_bytes("backlog"), reinterpret_cast<const sockaddr *>(&destination.value())));
          }
          co_await vio::sleep(loop, 20ms);

          bool done = false;
          auto watchdog = cancel_after(loop, reader, done, 2000ms);
          while (received < sent_count)
          {
            auto first = co_await reader;
            if (!first.has_value())
            {
              break;
            }
            std::optional<std::expected<vio::datagram_t, vio::error_t>> next = std::move(first);
            for (; next.has_value() && next->has_value(); next = reader.try_next())
            {
              ++received;
            }
          }
          done = true;
          co_await std::move(watchdog);
          CHECK(reader.datagrams() == static_cast<std::uint64_t>(sent_count));
        }
        loop.stop();
      }(event_loop, received);
  });

  event_loop.run();
  CHECK(received == sent_count);
}

TEST_CASE("a datagram reader keeps its socket open after the udp_t is gone")
{
  vio::event_loop_t event_loop;
  std::vector<std::string> payloads;

  event_loop.run_in_loop([&] {
    return [](vio::event_loop_t &loop, std::vector<std::string> &payloads) -> vio::task_t<void>
      {
        {
          std::optional<vio::datagram_reader_t> reader;
          int port = 0;
          {
            auto receiver_pair = get_udp_ephemeral_port(loop);
            REQUIRE_EXPECTED(receiver_pair);
            port = receiver_pair->second;
            auto created = vio::datagram_reader_t::create(loop, receiver_pair->first);
            REQUIRE_EXPECTED(created);
            reader.emplace(std::move(created.value()));
          }
          co_await vio::sleep(loop, 5ms);

          auto sender_pair = get_udp_ephemeral_port(loop);
          REQUIRE_EXPECTED(sender_pair);
          auto destination = make_ip4("127.0.0.1", port);
          REQUIRE_EXPECTED(destination);
          for (const char *text : {"one", "two", "three"})
          {
            REQUIRE_EXPECTED(vio::udp_try_send(sender_pair->first, text_bytes(text), reinterpret_cast<const sockaddr *>(&destination.value())));
          }
          while (payloads.size() < 3)
          {
            auto received = co_await *reader;
            REQUIRE_EXPECTED(received);
            payloads.emplace_back(reinterpret_cast<const char *>(received->data.data()), received->data.size());
          }
        }
        loop.stop();
      }(event_loop, payloads);
  });

  event_loop.run();
  REQUIRE(payloads.size() == 3);
  CHECK(payloads[0] == "one");
  CHECK(payloads[1] == "two");
  CHECK(payloads[2] == "three");
}

TEST_CASE("receive yields a batch with peer, local address and codepoint")
{
  vio::event_loop_t event_loop;
  std::size_t batch_size = 0;
  std::vector<std::string> payloads;
  bool peers_match = true;
  bool locals_match = true;
  bool ecn_match = true;
  bool none_truncated = true;
  std::size_t second_batch = 0;

  event_loop.run_in_loop([&] {
    return [](vio::event_loop_t &loop, std::size_t &batch_size, std::vector<std::string> &payloads, bool &peers_match, bool &locals_match, bool &ecn_match, bool &none_truncated, std::size_t &second_batch) -> vio::task_t<void>
      {
        {
          auto receiver_pair = get_udp_ephemeral_port(loop);
          REQUIRE_EXPECTED(receiver_pair);
          auto reader_or_err = vio::datagram_reader_t::create(loop, receiver_pair->first);
          REQUIRE_EXPECTED(reader_or_err);
          auto reader = std::move(reader_or_err.value());
          REQUIRE_EXPECTED(reader.receive_ecn(true));
          REQUIRE_EXPECTED(reader.receive_local_address(true));

          auto sender_pair = get_udp_ephemeral_port(loop);
          REQUIRE_EXPECTED(sender_pair);
          auto destination = make_ip4("127.0.0.1", receiver_pair->second);
          REQUIRE_EXPECTED(destination);
          for (const char *text : {"alpha", "beta", "gamma"})
          {
            REQUIRE_EXPECTED(vio::send_datagram(sender_pair->first, text_bytes(text), reinterpret_cast<const sockaddr *>(&destination.value()), vio::udp_ecn_t::ect0));
          }
          co_await vio::sleep(loop, 20ms);

          auto batch = co_await reader.receive();
          REQUIRE_EXPECTED(batch);
          batch_size = batch->size();
          for (const vio::datagram_t &datagram : *batch)
          {
            payloads.emplace_back(reinterpret_cast<const char *>(datagram.data.data()), datagram.data.size());
            peers_match = peers_match && port_of(datagram.peer) == sender_pair->second;
            const bool local_ok = datagram.local != nullptr && datagram.local->sa_family == AF_INET && port_of(datagram.local) == receiver_pair->second &&
                                  reinterpret_cast<const sockaddr_in *>(datagram.local)->sin_addr.s_addr == htonl(INADDR_LOOPBACK);
            locals_match = locals_match && local_ok;
            ecn_match = ecn_match && datagram.ecn == vio::udp_ecn_t::ect0;
            none_truncated = none_truncated && !datagram.truncated && datagram.segment_size == 0;
          }
#if defined(VIO_TEST_ASAN)
          REQUIRE(batch->size() == 3);
          const auto *tail = batch->front().data.data() + batch->front().data.size();
          CHECK(__asan_address_is_poisoned(tail));
          const auto *stale = (*batch)[2].data.data();
#endif

          REQUIRE_EXPECTED(vio::send_datagram(sender_pair->first, text_bytes("delta"), reinterpret_cast<const sockaddr *>(&destination.value()), vio::udp_ecn_t::ect0));
          auto again = co_await reader.receive();
          REQUIRE_EXPECTED(again);
          second_batch = again->size();
#if defined(VIO_TEST_ASAN)
          CHECK(__asan_address_is_poisoned(stale));
#endif
        }
        loop.stop();
      }(event_loop, batch_size, payloads, peers_match, locals_match, ecn_match, none_truncated, second_batch);
  });

  event_loop.run();
  CHECK(batch_size == 3);
  REQUIRE(payloads.size() == 3);
  CHECK(payloads[0] == "alpha");
  CHECK(payloads[1] == "beta");
  CHECK(payloads[2] == "gamma");
  CHECK(peers_match);
  CHECK(locals_match);
  CHECK(ecn_match);
  CHECK(none_truncated);
  CHECK(second_batch == 1);
}

static int poison_state(const void *address)
{
#if defined(VIO_TEST_ASAN)
  return __asan_address_is_poisoned(address);
#else
  (void)address;
  return -1;
#endif
}

TEST_CASE("a view kept past the next receive lands on poisoned memory")
{
  vio::event_loop_t event_loop;
  std::string first_text;
  std::string second_text;
  std::string third_text;
  std::string fourth_text;
  int stale_single_data = -1;
  int stale_single_peer = -1;
  int stale_batch_data = -1;
  int stale_batch_peer = -1;

  event_loop.run_in_loop([&] {
    return [](vio::event_loop_t &loop, std::string &first_text, std::string &second_text, std::string &third_text, std::string &fourth_text, int &stale_single_data, int &stale_single_peer, int &stale_batch_data,
              int &stale_batch_peer) -> vio::task_t<void>
      {
        {
          auto receiver_pair = get_udp_ephemeral_port(loop);
          REQUIRE_EXPECTED(receiver_pair);
          auto reader_or_err = vio::datagram_reader_t::create(loop, receiver_pair->first);
          REQUIRE_EXPECTED(reader_or_err);
          auto reader = std::move(reader_or_err.value());
          auto sender_pair = get_udp_ephemeral_port(loop);
          REQUIRE_EXPECTED(sender_pair);
          auto destination = make_ip4("127.0.0.1", receiver_pair->second);
          REQUIRE_EXPECTED(destination);
          const auto *to = reinterpret_cast<const sockaddr *>(&destination.value());

          REQUIRE_EXPECTED(vio::udp_try_send(sender_pair->first, text_bytes("first-batch"), to));
          co_await vio::sleep(loop, 20ms);
          auto first = co_await reader;
          REQUIRE_EXPECTED(first);
          const vio::datagram_t kept = *first;
          first_text.assign(reinterpret_cast<const char *>(kept.data.data()), kept.data.size());

          REQUIRE_EXPECTED(vio::udp_try_send(sender_pair->first, text_bytes("SECOND-BATCH"), to));
          co_await vio::sleep(loop, 20ms);
          auto second = co_await reader;
          REQUIRE_EXPECTED(second);
          second_text.assign(reinterpret_cast<const char *>(second->data.data()), second->data.size());
          stale_single_data = poison_state(kept.data.data());
          stale_single_peer = poison_state(kept.peer);

          REQUIRE_EXPECTED(vio::udp_try_send(sender_pair->first, text_bytes("third"), to));
          co_await vio::sleep(loop, 20ms);
          auto third = co_await reader.receive();
          REQUIRE_EXPECTED(third);
          REQUIRE(third->size() == 1);
          const vio::datagram_t kept_front = third->front();
          third_text.assign(reinterpret_cast<const char *>(kept_front.data.data()), kept_front.data.size());

          REQUIRE_EXPECTED(vio::udp_try_send(sender_pair->first, text_bytes("FOURTH"), to));
          co_await vio::sleep(loop, 20ms);
          auto fourth = co_await reader.receive();
          REQUIRE_EXPECTED(fourth);
          REQUIRE(fourth->size() == 1);
          fourth_text.assign(reinterpret_cast<const char *>(fourth->front().data.data()), fourth->front().data.size());
          stale_batch_data = poison_state(kept_front.data.data());
          stale_batch_peer = poison_state(kept_front.peer);
        }
        loop.stop();
      }(event_loop, first_text, second_text, third_text, fourth_text, stale_single_data, stale_single_peer, stale_batch_data, stale_batch_peer);
  });

  event_loop.run();
  CHECK(first_text == "first-batch");
  CHECK(second_text == "SECOND-BATCH");
  CHECK(third_text == "third");
  CHECK(fourth_text == "FOURTH");
#if defined(VIO_TEST_ASAN)
  CHECK(stale_single_data == 1);
  CHECK(stale_single_peer == 1);
  CHECK(stale_batch_data == 1);
  CHECK(stale_batch_peer == 1);
#endif
}

TEST_CASE("a datagram larger than the reader's buffer is flagged in a batch and skipped one at a time")
{
  vio::event_loop_t event_loop;
  std::size_t batch_size = 0;
  bool first_truncated = false;
  std::size_t first_size = 0;
  bool second_truncated = true;
  std::string single;
  std::uint64_t truncated = 0;

  event_loop.run_in_loop([&] {
    return [](vio::event_loop_t &loop, std::size_t &batch_size, bool &first_truncated, std::size_t &first_size, bool &second_truncated, std::string &single, std::uint64_t &truncated) -> vio::task_t<void>
      {
        {
          auto receiver_pair = get_udp_ephemeral_port(loop);
          REQUIRE_EXPECTED(receiver_pair);
          auto reader_or_err = vio::datagram_reader_t::create(loop, receiver_pair->first);
          REQUIRE_EXPECTED(reader_or_err);
          auto reader = std::move(reader_or_err.value());
          REQUIRE_EXPECTED(reader.receive_datagram_size(512));
          CHECK(!reader.receive_datagram_size(100).has_value());

          auto sender_pair = get_udp_ephemeral_port(loop);
          REQUIRE_EXPECTED(sender_pair);
          auto destination = make_ip4("127.0.0.1", receiver_pair->second);
          REQUIRE_EXPECTED(destination);
          const auto *to = reinterpret_cast<const sockaddr *>(&destination.value());
          std::vector<std::uint8_t> large(1000, 0x41);

          REQUIRE_EXPECTED(vio::udp_try_send(sender_pair->first, large, to));
          REQUIRE_EXPECTED(vio::udp_try_send(sender_pair->first, text_bytes("small"), to));
          co_await vio::sleep(loop, 20ms);
          auto batch = co_await reader.receive();
          REQUIRE_EXPECTED(batch);
          batch_size = batch->size();
          REQUIRE(batch_size == 2);
          first_truncated = (*batch)[0].truncated;
          first_size = (*batch)[0].data.size();
          second_truncated = (*batch)[1].truncated;

          REQUIRE_EXPECTED(vio::udp_try_send(sender_pair->first, large, to));
          REQUIRE_EXPECTED(vio::udp_try_send(sender_pair->first, text_bytes("after"), to));
          co_await vio::sleep(loop, 20ms);
          auto received = co_await reader;
          REQUIRE_EXPECTED(received);
          single.assign(reinterpret_cast<const char *>(received->data.data()), received->data.size());
          truncated = reader.truncated();
        }
        loop.stop();
      }(event_loop, batch_size, first_truncated, first_size, second_truncated, single, truncated);
  });

  event_loop.run();
  CHECK(batch_size == 2);
  CHECK(first_truncated);
  CHECK(first_size == 512);
  CHECK_FALSE(second_truncated);
  CHECK(single == "after");
  CHECK(truncated == 2);
}

TEST_CASE("cancelling a waiting datagram reader resumes it before cancel returns")
{
  vio::event_loop_t event_loop;
  bool resumed_inside_cancel = false;
  bool got_cancelled = false;
  bool second_refused = false;

  event_loop.run_in_loop([&] {
    return [](vio::event_loop_t &loop, bool &resumed_inside_cancel, bool &got_cancelled, bool &second_refused) -> vio::task_t<void>
      {
        {
          auto receiver_pair = get_udp_ephemeral_port(loop);
          REQUIRE_EXPECTED(receiver_pair);
          auto reader_or_err = vio::datagram_reader_t::create(loop, receiver_pair->first);
          REQUIRE_EXPECTED(reader_or_err);
          auto reader = std::move(reader_or_err.value());

          bool finished = false;
          auto waiter = [](vio::datagram_reader_t &r, bool &cancelled, bool &finished) -> vio::task_t<void>
          {
            auto received = co_await r;
            cancelled = !received.has_value() && vio::is_cancelled(received.error());
            finished = true;
          }(reader, got_cancelled, finished);

          auto second = co_await reader;
          second_refused = !second.has_value() && second.error().code == vio::errc::already_in_progress;

          co_await vio::sleep(loop, 5ms);
          reader.cancel();
          resumed_inside_cancel = finished;
          co_await std::move(waiter);
        }
        loop.stop();
      }(event_loop, resumed_inside_cancel, got_cancelled, second_refused);
  });

  event_loop.run();
  CHECK(resumed_inside_cancel);
  CHECK(got_cancelled);
  CHECK(second_refused);
}

TEST_CASE("send errors arrive as vio codes rather than raw errno values")
{
  vio::event_loop_t event_loop;
  int datagram_code = 0;
  int try_code = 0;
  int segments_code = 0;
  int ce_code = 0;
  int oversized_segment_code = 0;

  event_loop.run_in_loop([&] {
    return [](vio::event_loop_t &loop, int &datagram_code, int &try_code, int &segments_code, int &ce_code, int &oversized_segment_code) -> vio::task_t<void>
      {
        {
          auto sender_pair = get_udp_ephemeral_port(loop);
          REQUIRE_EXPECTED(sender_pair);
          auto destination = make_ip4("127.0.0.1", 9);
          REQUIRE_EXPECTED(destination);
          const auto *to = reinterpret_cast<const sockaddr *>(&destination.value());
          std::vector<std::uint8_t> huge(70000, 0x42);

          auto sent = vio::send_datagram(sender_pair->first, huge, to, vio::udp_ecn_t::ect0);
          REQUIRE(!sent.has_value());
          datagram_code = sent.error().code;

          auto tried = vio::udp_try_send(sender_pair->first, huge, to);
          REQUIRE(!tried.has_value());
          try_code = tried.error().code;

          std::vector<std::uint8_t> run(64 * 1200, 0x43);
          auto segmented = vio::send_segments(sender_pair->first, run, 1200, to, vio::udp_ecn_t::not_ect);
          segments_code = segmented.has_value() ? 0 : segmented.error().code;

          auto marked = vio::send_datagram(sender_pair->first, text_bytes("ce"), to, vio::udp_ecn_t::ce);
          REQUIRE(!marked.has_value());
          ce_code = marked.error().code;

          auto oversized = vio::send_segments(sender_pair->first, run, 70000, to, vio::udp_ecn_t::not_ect);
          CHECK(oversized.has_value() == false);
          if (!oversized.has_value())
          {
            oversized_segment_code = oversized.error().code;
          }
        }
        loop.stop();
        co_return;
      }(event_loop, datagram_code, try_code, segments_code, ce_code, oversized_segment_code);
  });

  event_loop.run();
  CHECK(datagram_code == vio::errc::message_too_long);
  CHECK(try_code == vio::errc::message_too_long);
#if defined(__linux__)
  CHECK(segments_code == vio::errc::message_too_long);
#elif defined(_WIN32)
  CHECK((segments_code == 0 || segments_code == vio::errc::message_too_long || segments_code == vio::errc::not_supported));
#else
  CHECK(segments_code == vio::errc::not_supported);
#endif
  CHECK(ce_code == vio::errc::invalid_argument);
  CHECK(oversized_segment_code == vio::errc::invalid_argument);
}

TEST_CASE("the batch API splits a coalesced read into its segments")
{
  vio::event_loop_t event_loop;
  bool segmented = false;
  std::vector<std::string> pieces;
  std::size_t reported_segment = 0;

  event_loop.run_in_loop([&] {
    return [](vio::event_loop_t &loop, bool &segmented, std::vector<std::string> &pieces, std::size_t &reported_segment) -> vio::task_t<void>
      {
        {
          auto receiver_pair = get_udp_ephemeral_port(loop);
          REQUIRE_EXPECTED(receiver_pair);
          auto reader_or_err = vio::datagram_reader_t::create(loop, receiver_pair->first);
          REQUIRE_EXPECTED(reader_or_err);
          auto reader = std::move(reader_or_err.value());
          const bool coalescing = reader.receive_coalesced(65536).has_value();

          auto sender_pair = get_udp_ephemeral_port(loop);
          REQUIRE_EXPECTED(sender_pair);
          auto destination = make_ip4("127.0.0.1", receiver_pair->second);
          REQUIRE_EXPECTED(destination);
          constexpr std::size_t segment = 200;
          std::vector<std::uint8_t> run(segment * 3 + 50);
          for (std::size_t i = 0; i < run.size(); ++i)
          {
            run[i] = static_cast<std::uint8_t>('a' + i / segment);
          }
          auto sent = vio::send_segments(sender_pair->first, run, segment, reinterpret_cast<const sockaddr *>(&destination.value()), vio::udp_ecn_t::not_ect);
          if (sent.has_value())
          {
            segmented = true;
            while (pieces.size() < 4)
            {
              auto batch = co_await reader.receive();
              REQUIRE_EXPECTED(batch);
              for (const auto &datagram : *batch)
              {
                pieces.emplace_back(reinterpret_cast<const char *>(datagram.data.data()), datagram.data.size());
                if (coalescing && datagram.segment_size != 0)
                {
                  reported_segment = datagram.segment_size;
                }
              }
            }
          }
        }
        loop.stop();
      }(event_loop, segmented, pieces, reported_segment);
  });

  event_loop.run();
  if (segmented)
  {
    REQUIRE(pieces.size() == 4);
    CHECK(pieces[0] == std::string(200, 'a'));
    CHECK(pieces[1] == std::string(200, 'b'));
    CHECK(pieces[2] == std::string(200, 'c'));
    CHECK(pieces[3] == std::string(50, 'd'));
    CHECK((reported_segment == 0 || reported_segment == 200));
    MESSAGE("reported segment size " << reported_segment);
  }
}
}

TEST_SUITE("UDP sockets")
{
TEST_CASE("a socket exists only once it is bound, connected or used")
{
  vio::event_loop_t event_loop;
  int fileno_code = 0;
  int sockname_code = 0;
  int ttl_code = 0;
  bool open_after_send = false;

  event_loop.run_in_loop([&] {
    return [](vio::event_loop_t &loop, int &fileno_code, int &sockname_code, int &ttl_code, bool &open_after_send) -> vio::task_t<void>
      {
        {
          auto created = vio::udp_create(loop);
          REQUIRE_EXPECTED(created);
          auto socket = std::move(created.value());
          auto fd = vio::udp_fileno(socket);
          fileno_code = fd.has_value() ? 0 : fd.error().code;
          auto name = vio::udp_sockname(socket);
          sockname_code = name.has_value() ? 0 : name.error().code;
          auto ttl = vio::udp_set_ttl(socket, 64);
          ttl_code = ttl.has_value() ? 0 : ttl.error().code;

          auto destination = make_ip4("127.0.0.1", 9);
          REQUIRE_EXPECTED(destination);
          REQUIRE_EXPECTED(vio::udp_try_send(socket, text_bytes("x"), reinterpret_cast<const sockaddr *>(&destination.value())));
          auto after = vio::udp_fileno(socket);
          open_after_send = after.has_value() && *after != vio::invalid_native_socket;
        }
        loop.stop();
        co_return;
      }(event_loop, fileno_code, sockname_code, ttl_code, open_after_send);
  });

  event_loop.run();
  CHECK(fileno_code == vio::errc::bad_descriptor);
  CHECK(sockname_code == vio::errc::bad_descriptor);
  CHECK(ttl_code == vio::errc::bad_descriptor);
  CHECK(open_after_send);
}

TEST_CASE("connected and unconnected sockets refuse the wrong kind of send")
{
  vio::event_loop_t event_loop;
  std::vector<int> codes;

  event_loop.run_in_loop([&] {
    return [](vio::event_loop_t &loop, std::vector<int> &codes) -> vio::task_t<void>
      {
        {
          auto peer_pair = get_udp_ephemeral_port(loop);
          REQUIRE_EXPECTED(peer_pair);
          auto socket_pair = get_udp_ephemeral_port(loop);
          REQUIRE_EXPECTED(socket_pair);
          auto &socket = socket_pair->first;
          auto destination = make_ip4("127.0.0.1", peer_pair->second);
          REQUIRE_EXPECTED(destination);
          const auto *to = reinterpret_cast<const sockaddr *>(&destination.value());
          auto code = [](const auto &result) { return result.has_value() ? 0 : result.error().code; };

          codes.push_back(code(vio::udp_disconnect(socket)));
          codes.push_back(code(vio::udp_try_send(socket, text_bytes("x"), nullptr)));
          codes.push_back(code(vio::udp_connect(socket, to)));
          codes.push_back(code(vio::udp_connect(socket, to)));
          codes.push_back(code(vio::udp_try_send(socket, text_bytes("x"), to)));
          codes.push_back(code(vio::udp_try_send(socket, text_bytes("x"), nullptr)));
          codes.push_back(code(vio::udp_disconnect(socket)));
          codes.push_back(code(vio::udp_try_send(socket, text_bytes("x"), to)));
        }
        loop.stop();
        co_return;
      }(event_loop, codes);
  });

  event_loop.run();
  REQUIRE(codes.size() == 8);
  CHECK(codes[0] == vio::errc::not_connected);
  CHECK(codes[1] == vio::errc::destination_address_required);
  CHECK(codes[2] == 0);
  CHECK(codes[3] == vio::errc::already_connected);
  CHECK(codes[4] == vio::errc::already_connected);
  CHECK(codes[5] == 0);
  CHECK(codes[6] == 0);
  CHECK(codes[7] == 0);
}

TEST_CASE("bind flags are vio's own and behave per platform")
{
  vio::event_loop_t event_loop;
  int shared_port_code = -1;
  int plain_conflict_code = 0;
  int reuseaddr_code = -1;
  int v6only_on_v4_code = 0;

  event_loop.run_in_loop([&] {
    return [](vio::event_loop_t &loop, int &shared_port_code, int &plain_conflict_code, int &reuseaddr_code, int &v6only_on_v4_code) -> vio::task_t<void>
      {
        {
          auto code = [](const auto &result) { return result.has_value() ? 0 : result.error().code; };
          auto any = make_ip4("127.0.0.1", 0);
          REQUIRE_EXPECTED(any);

#if defined(__linux__)
          const auto shared = vio::udp_bind_flags::reuseport | vio::udp_bind_flags::reuseaddr;
#else
          const auto shared = vio::udp_bind_flags::reuseaddr;
#endif
          auto first = vio::udp_create(loop);
          REQUIRE_EXPECTED(first);
          REQUIRE_EXPECTED(vio::udp_bind(first.value(), reinterpret_cast<const sockaddr *>(&any.value()), shared));
          auto name = vio::udp_sockname(first.value());
          REQUIRE_EXPECTED(name);
          auto same = make_ip4("127.0.0.1", port_of(reinterpret_cast<const sockaddr *>(&name.value())));
          REQUIRE_EXPECTED(same);

          auto second = vio::udp_create(loop);
          REQUIRE_EXPECTED(second);
          shared_port_code = code(vio::udp_bind(second.value(), reinterpret_cast<const sockaddr *>(&same.value()), vio::udp_bind_flags::reuseport | vio::udp_bind_flags::reuseaddr));

          auto third = vio::udp_create(loop);
          REQUIRE_EXPECTED(third);
          plain_conflict_code = code(vio::udp_bind(third.value(), reinterpret_cast<const sockaddr *>(&same.value())));
          auto retry = vio::udp_bind(third.value(), reinterpret_cast<const sockaddr *>(&any.value()));
          CHECK(retry.has_value());

          auto fourth = vio::udp_create(loop);
          REQUIRE_EXPECTED(fourth);
          REQUIRE_EXPECTED(vio::udp_bind(fourth.value(), reinterpret_cast<const sockaddr *>(&any.value()), vio::udp_bind_flags::reuseaddr));
          auto fourth_name = vio::udp_sockname(fourth.value());
          REQUIRE_EXPECTED(fourth_name);
          auto fourth_address = make_ip4("127.0.0.1", port_of(reinterpret_cast<const sockaddr *>(&fourth_name.value())));
          REQUIRE_EXPECTED(fourth_address);
          auto fifth = vio::udp_create(loop);
          REQUIRE_EXPECTED(fifth);
          reuseaddr_code = code(vio::udp_bind(fifth.value(), reinterpret_cast<const sockaddr *>(&fourth_address.value()), vio::udp_bind_flags::reuseaddr));

          auto sixth = vio::udp_create(loop);
          REQUIRE_EXPECTED(sixth);
          v6only_on_v4_code = code(vio::udp_bind(sixth.value(), reinterpret_cast<const sockaddr *>(&any.value()), vio::udp_bind_flags::ipv6_only));
        }
        loop.stop();
        co_return;
      }(event_loop, shared_port_code, plain_conflict_code, reuseaddr_code, v6only_on_v4_code);
  });

  event_loop.run();
#if defined(__linux__)
  CHECK(shared_port_code == 0);
#else
  CHECK(shared_port_code == vio::errc::not_supported);
#endif
  CHECK(plain_conflict_code == vio::errc::address_in_use);
#if !defined(_WIN32)
  CHECK(reuseaddr_code == 0);
#endif
  CHECK(v6only_on_v4_code == vio::errc::invalid_argument);
}

TEST_CASE("socket options are set through the socket itself")
{
  vio::event_loop_t event_loop;
  std::vector<int> codes;
  int recv_size = 0;
  int send_size = 0;
  int membership_code = 0;
  int bad_group_code = 0;

  event_loop.run_in_loop([&] {
    return [](vio::event_loop_t &loop, std::vector<int> &codes, int &recv_size, int &send_size, int &membership_code, int &bad_group_code) -> vio::task_t<void>
      {
        {
          auto code = [](const auto &result) { return result.has_value() ? 0 : result.error().code; };
          auto socket_pair = get_udp_ephemeral_port(loop);
          REQUIRE_EXPECTED(socket_pair);
          auto &socket = socket_pair->first;
          codes.push_back(code(vio::udp_set_ttl(socket, 0)));
          codes.push_back(code(vio::udp_set_ttl(socket, 64)));
          codes.push_back(code(vio::udp_set_broadcast(socket, true)));
          codes.push_back(code(vio::udp_set_multicast_ttl(socket, 4)));
          codes.push_back(code(vio::udp_set_multicast_loop(socket, false)));
          codes.push_back(code(vio::udp_set_recv_buffer_size(socket, 256 * 1024)));
          codes.push_back(code(vio::udp_set_send_buffer_size(socket, 256 * 1024)));
          codes.push_back(code(vio::udp_set_recv_buffer_size(socket, 0)));
          auto recv = vio::udp_recv_buffer_size(socket);
          REQUIRE_EXPECTED(recv);
          recv_size = *recv;
          auto send = vio::udp_send_buffer_size(socket);
          REQUIRE_EXPECTED(send);
          send_size = *send;

          bad_group_code = code(vio::udp_set_membership(socket, "not an address", nullptr, vio::udp_membership_t::join_group));
          auto joined = vio::udp_set_membership(socket, "239.255.0.1", "127.0.0.1", vio::udp_membership_t::join_group);
          membership_code = code(joined);
          if (joined.has_value())
          {
            CHECK(vio::udp_set_membership(socket, "239.255.0.1", "127.0.0.1", vio::udp_membership_t::leave_group).has_value());
          }
        }
        loop.stop();
        co_return;
      }(event_loop, codes, recv_size, send_size, membership_code, bad_group_code);
  });

  event_loop.run();
  REQUIRE(codes.size() == 8);
  CHECK(codes[0] == vio::errc::invalid_argument);
  CHECK(codes[1] == 0);
  CHECK(codes[2] == 0);
  CHECK(codes[3] == 0);
  CHECK(codes[4] == 0);
  CHECK(codes[5] == 0);
  CHECK(codes[6] == 0);
  CHECK(codes[7] == vio::errc::invalid_argument);
  CHECK(recv_size > 0);
  CHECK(send_size > 0);
  MESSAGE("buffer sizes after asking for 256 KiB: receive " << recv_size << ", send " << send_size);
  CHECK(bad_group_code == vio::errc::invalid_argument);
  MESSAGE("joining 239.255.0.1 on loopback: " << (membership_code == 0 ? std::string("ok") : vio::error_message(membership_code)));
}
}
}
