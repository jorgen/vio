#include <ostream>

#include <doctest/doctest.h>
#include <string>
#include <string_view>
#include <vio/error.h>
#include <vio/event_loop.h>
#include <vio/operation/tcp.h>
#include <vio/operation/udp.h>
#include <vio/task.h>

#include "require_expected.h"

namespace
{

#define PROPAGATE_ERROR(x)                                                                                                                                                                                                 \
  if (!(x).has_value())                                                                                                                                                                                                    \
    return std::unexpected(std::move((x).error()));

std::expected<std::pair<vio::udp_t, int>, vio::error_t> get_udp_ephemeral_port(vio::event_loop_t &event_loop)
{
  auto addr_or_err = vio::ip4_addr("127.0.0.1", 0);
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

TEST_CASE("udp basic send and receive")
{
  vio::event_loop_t event_loop;
  bool verified = false;

  event_loop.run_in_loop(
    [&]() -> vio::task_t<void>
    {
      auto *ev = &event_loop;
      auto *v = &verified;

      auto receiver_pair = get_udp_ephemeral_port(*ev);
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
        std::string_view sv(datagram.data->base, datagram.data->len);
        REQUIRE(sv == "hello udp");
        REQUIRE(datagram.sender_port() > 0);
      }(std::move(receiver_pair->first));

      co_await [](vio::event_loop_t &el, int p) -> vio::task_t<void>
      {
        auto sender_or_err = vio::udp_create(el);
        REQUIRE_EXPECTED(sender_or_err);
        auto sender = std::move(sender_or_err.value());

        auto dest_addr = vio::ip4_addr("127.0.0.1", p);
        REQUIRE_EXPECTED(dest_addr);

        std::string msg = "hello udp";
        auto send_result = co_await vio::send_udp(sender, reinterpret_cast<const uint8_t *>(msg.data()), msg.size(), reinterpret_cast<const sockaddr *>(&dest_addr.value()));
        REQUIRE_EXPECTED(send_result);
      }(event_loop, port);

      co_await std::move(receiver_task);
      *v = true;
      {
        auto tmp = std::move(receiver_task);
      }
      ev->stop();
    });

  event_loop.run();
  REQUIRE(verified);
}

TEST_CASE("udp echo multiple datagrams")
{
  vio::event_loop_t event_loop;
  bool verified = false;

  event_loop.run_in_loop(
    [&]() -> vio::task_t<void>
    {
      auto *ev = &event_loop;

      auto echo_pair = get_udp_ephemeral_port(*ev);
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
          auto send_result = co_await vio::send_udp(echo_sock, reinterpret_cast<const uint8_t *>(datagram.data->base), datagram.data->len, datagram.get_sender());
          REQUIRE_EXPECTED(send_result);
        }
      }(std::move(echo_pair->first), num_datagrams);

      co_await [](vio::event_loop_t &el, int p, int count, bool &v) -> vio::task_t<void>
      {
        auto client_pair = get_udp_ephemeral_port(el);
        REQUIRE_EXPECTED(client_pair);
        auto client = std::move(client_pair->first);

        auto dest_addr = vio::ip4_addr("127.0.0.1", p);
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
          std::string str(datagram.data->base, datagram.data->len);
          REQUIRE(str == msg);
        }
        v = true;
      }(event_loop, echo_port, num_datagrams, verified);

      co_await std::move(echo_task);
      {
        auto tmp = std::move(echo_task);
      }
      ev->stop();
    });

  event_loop.run();
  REQUIRE(verified);
}

TEST_CASE("udp connected mode")
{
  vio::event_loop_t event_loop;
  bool verified = false;

  event_loop.run_in_loop(
    [&]() -> vio::task_t<void>
    {
      auto *ev = &event_loop;
      auto *v = &verified;

      auto receiver_pair = get_udp_ephemeral_port(*ev);
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
        std::string_view sv(datagram.data->base, datagram.data->len);
        REQUIRE(sv == "connected mode");
      }(std::move(receiver_pair->first));

      co_await [](vio::event_loop_t &el, int p) -> vio::task_t<void>
      {
        auto sender_or_err = vio::udp_create(el);
        REQUIRE_EXPECTED(sender_or_err);
        auto sender = std::move(sender_or_err.value());

        auto dest_addr = vio::ip4_addr("127.0.0.1", p);
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
      *v = true;
      ev->stop();
    });

  event_loop.run();
  REQUIRE(verified);
}

TEST_CASE("udp cancel reader")
{
  vio::event_loop_t event_loop;
  bool reader_cancelled = false;

  event_loop.run_in_loop(
    [&]() -> vio::task_t<void>
    {
      auto *ev = &event_loop;

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
        REQUIRE(recv_result.error().code == UV_ECANCELED);
        cancelled = true;
      }(event_loop, reader_cancelled);

      ev->stop();
    });

  event_loop.run();
  REQUIRE(reader_cancelled);
}

TEST_CASE("udp cannot create multiple active readers")
{
  vio::event_loop_t event_loop;
  bool error_caught = false;

  event_loop.run_in_loop(
    [&]() -> vio::task_t<void>
    {
      auto *ev = &event_loop;

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

      ev->stop();
    });

  event_loop.run();
  REQUIRE(error_caught);
}

TEST_CASE("udp ipv6 loopback")
{
  vio::event_loop_t event_loop;
  bool verified = false;

  event_loop.run_in_loop(
    [&]() -> vio::task_t<void>
    {
      auto *ev = &event_loop;
      auto *v = &verified;

      auto addr_or_err = vio::ip6_addr("::1", 0);
      REQUIRE_EXPECTED(addr_or_err);
      auto receiver_or_err = vio::udp_create(*ev);
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
        std::string_view sv(datagram.data->base, datagram.data->len);
        REQUIRE(sv == "ipv6_udp_test");
        REQUIRE(datagram.sender_addr.ss_family == AF_INET6);
      }(std::move(receiver_or_err.value()));

      co_await [](vio::event_loop_t &el, int p) -> vio::task_t<void>
      {
        auto sender_or_err = vio::udp_create(el);
        REQUIRE_EXPECTED(sender_or_err);
        auto sender = std::move(sender_or_err.value());

        auto dest_addr = vio::ip6_addr("::1", p);
        REQUIRE_EXPECTED(dest_addr);

        std::string msg = "ipv6_udp_test";
        auto send_result = co_await vio::send_udp(sender, reinterpret_cast<const uint8_t *>(msg.data()), msg.size(), reinterpret_cast<const sockaddr *>(&dest_addr.value()));
        REQUIRE_EXPECTED(send_result);
      }(event_loop, port);

      co_await std::move(receiver_task);
      { auto tmp = std::move(receiver_task); }
      *v = true;
      ev->stop();
    });

  event_loop.run();
  REQUIRE(verified);
}

TEST_CASE("udp sockname returns correct address")
{
  vio::event_loop_t event_loop;

  auto addr_or_err = vio::ip4_addr("127.0.0.1", 0);
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

} // namespace
