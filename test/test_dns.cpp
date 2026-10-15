#include <doctest/doctest.h>
#include <vio/event_loop.h>
#include <vio/loop/blocking_pool.h>
#include <vio/operation/dns.h>
#include <vio/task.h>

#include <condition_variable>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

#include "require_expected.h"

namespace
{

struct dns_gate_t
{
  std::mutex mutex;
  std::condition_variable wake;
  bool open = false;
  int finished = 0;
  std::vector<vio::detail::pool_job_t> jobs;

  explicit dns_gate_t(std::size_t count)
    : jobs(count)
  {
  }

  void block(vio::event_loop_t &event_loop)
  {
    for (auto &job : jobs)
    {
      job.owner = this;
      job.work = [](vio::detail::pool_job_t *raw) {
        auto *gate = static_cast<dns_gate_t *>(raw->owner);
        std::unique_lock lock(gate->mutex);
        gate->wake.wait(lock, [gate] { return gate->open; });
      };
      job.done = [](vio::detail::pool_job_t *raw, bool) { ++static_cast<dns_gate_t *>(raw->owner)->finished; };
      vio::detail::pool_submit(vio::detail::core(event_loop), job, vio::detail::pool_queue::dns);
    }
  }

  void release()
  {
    {
      std::lock_guard lock(mutex);
      open = true;
    }
    wake.notify_all();
  }
};

constexpr std::size_t more_than_any_pool = 1025;

vio::address_info_t ipv4_loopback(std::uint16_t port)
{
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_port = htons(port);
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  vio::address_info_t info;
  info.family = AF_INET;
  info.addr.resize(sizeof(address));
  std::memcpy(info.addr.data(), &address, sizeof(address));
  return info;
}

auto dns_lookup_localhost(vio::event_loop_t &event_loop, bool &test_completed) -> vio::task_t<void>
{
  vio::address_info_t hints;
  hints.family = AF_UNSPEC;
  hints.socktype = SOCK_STREAM;

  auto result = co_await vio::get_addrinfo(event_loop, "localhost", hints);

  REQUIRE_EXPECTED(result);
  REQUIRE(result->size());
  MESSAGE("Got " << result->size() << " address(es) for localhost");

  const auto &addr_info = (*result)[0];
  const bool is_net = addr_info.family == AF_INET || addr_info.family == AF_INET6;
  CHECK(is_net);
  CHECK(addr_info.socktype == SOCK_STREAM);
  CHECK(addr_info.get_sockaddr() != nullptr);
  MESSAGE("Successfully verified address info properties");

  for (auto &addr_info : *result)
  {
    auto name_info = co_await vio::get_nameinfo(event_loop, addr_info);
    REQUIRE_EXPECTED(name_info);
    MESSAGE("Found address: " << name_info->host);
  }

  test_completed = true;
  event_loop.stop();
};

auto dns_lookup_invalid(vio::event_loop_t &event_loop, bool &test_completed) -> vio::task_t<void>
{
  vio::address_info_t hints;
  hints.family = AF_UNSPEC;

  auto result = co_await get_addrinfo(event_loop, "invalid.hostname.that.does.not.exist", hints);

  CHECK(!result.has_value());
  CHECK(result.error().code != 0);
  MESSAGE("Correctly received error for invalid hostname: " << result.error().msg);

  test_completed = true;
  event_loop.stop();
}

auto dns_lookup_ipv4(vio::event_loop_t &event_loop, bool &test_completed) -> vio::task_t<void>
{
  vio::address_info_t hints;
  hints.family = AF_INET;
  hints.socktype = SOCK_STREAM;

  auto result = co_await get_addrinfo(event_loop, "localhost", hints);

  REQUIRE_EXPECTED(result);
  REQUIRE(!result->empty());
  MESSAGE("Got " << result->size() << " IPv4 address(es)");

  for (const auto &addr_info : *result)
  {
    CHECK(addr_info.family == AF_INET);
    MESSAGE("Verified IPv4 family for address");
  }

  test_completed = true;
  event_loop.stop();
}

auto dns_lookup_google(vio::event_loop_t &event_loop, bool &test_completed) -> vio::task_t<void>
{
  vio::address_info_t hints;
  hints.family = AF_UNSPEC;
  hints.socktype = SOCK_STREAM;
  hints.protocol = IPPROTO_TCP;

  auto result = co_await get_addrinfo(event_loop, "google.com", hints);

  REQUIRE_EXPECTED(result);
  REQUIRE(!result->empty());
  MESSAGE("Got " << result->size() << " Google address(es)");

  for (const auto &addr_info : *result)
  {
    auto name_info = co_await vio::get_nameinfo(event_loop, addr_info);
    REQUIRE_EXPECTED(name_info);
    MESSAGE("Google address is " << name_info->host);
  }

  test_completed = true;
  event_loop.stop();
}

TEST_SUITE("DNS")
{
TEST_CASE("DNS address info lookup")
{
  doctest::Context context;
  context.setOption("success", true);
  context.setOption("duration", true);

  vio::event_loop_t event_loop;

  SUBCASE("lookup valid hostname")
  {
    bool test_completed = false;
    INFO("Testing DNS resolution for localhost"); // NOLINT(misc-const-correctness) doctest macro

    event_loop.run_in_loop([&] { return dns_lookup_localhost(event_loop, test_completed); });

    event_loop.run();
    REQUIRE(test_completed);
  }

  SUBCASE("lookup invalid hostname")
  {
    bool test_completed = false;
    INFO("Testing DNS resolution for invalid hostname"); // NOLINT(misc-const-correctness) doctest macro

    event_loop.run_in_loop([&] { return dns_lookup_invalid(event_loop, test_completed); });

    event_loop.run();
    REQUIRE(test_completed);
  }

  SUBCASE("lookup with specific family (IPv4)")
  {
    bool test_completed = false;
    INFO("Testing IPv4-specific DNS resolution"); // NOLINT(misc-const-correctness) doctest macro

    event_loop.run_in_loop([&] { return dns_lookup_ipv4(event_loop, test_completed); });

    event_loop.run();
    REQUIRE(test_completed);
  }

  SUBCASE("lookup google")
  {
    bool test_completed = false;
    INFO("Testing that we can lookup google"); // NOLINT(misc-const-correctness) doctest macro

    event_loop.run_in_loop([&] { return dns_lookup_google(event_loop, test_completed); });

    event_loop.run();
    REQUIRE(test_completed);
  }
}

TEST_CASE("numeric lookups resolve and print without the network")
{
  vio::event_loop_t event_loop;
  bool completed = false;
  event_loop.run_in_loop([&] {
    return [](vio::event_loop_t &ev, bool &completed) -> vio::task_t<void> {
      vio::address_info_t hints;
      hints.family = AF_INET;
      hints.socktype = SOCK_DGRAM;
      hints.flags = AI_NUMERICHOST;
      auto resolved = co_await vio::get_addrinfo(ev, "127.0.0.1", hints);
      REQUIRE_EXPECTED(resolved);
      REQUIRE_FALSE(resolved->empty());
      CHECK(resolved->front().family == AF_INET);
      CHECK(resolved->front().socktype == SOCK_DGRAM);
      REQUIRE(resolved->front().addr.size() >= sizeof(sockaddr_in));

      auto named = co_await vio::get_nameinfo(ev, ipv4_loopback(8443));
      REQUIRE_EXPECTED(named);
      CHECK(named->host == "127.0.0.1");
      CHECK(named->service == "8443");

      auto refused = co_await vio::get_addrinfo(ev, "not a number", hints);
      REQUIRE_FALSE(refused.has_value());
      CHECK(refused.error().code == vio::errc::dns_no_name);
      CHECK(refused.error().msg == vio::error_message(vio::errc::dns_no_name));
      completed = true;
      ev.stop();
    }(event_loop, completed);
  });
  event_loop.run();
  CHECK(completed);
}

TEST_CASE("bad input fails at once without reaching the resolver")
{
  vio::event_loop_t event_loop;

  std::string with_nul = "localhost";
  with_nul.push_back('\0');
  with_nul += ".evil.example";
  auto nul_host = vio::get_addrinfo(event_loop, with_nul);
  REQUIRE(nul_host.state_ptr->done);
  REQUIRE_FALSE(nul_host.state_ptr->result.has_value());
  CHECK(nul_host.state_ptr->result.error().code == vio::errc::invalid_argument);

  auto bad_utf8 = vio::get_addrinfo(event_loop, "\xff\xff\xfe");
  REQUIRE(bad_utf8.state_ptr->done);
  CHECK(bad_utf8.state_ptr->result.error().code == vio::errc::invalid_argument);

  vio::address_info_t short_address = ipv4_loopback(80);
  short_address.addr.resize(3);
  auto too_short = vio::get_nameinfo(event_loop, short_address);
  REQUIRE(too_short.state_ptr->done);
  CHECK(too_short.state_ptr->result.error().code == vio::errc::invalid_argument);

  vio::address_info_t claims_ipv6 = ipv4_loopback(80);
  reinterpret_cast<sockaddr *>(claims_ipv6.addr.data())->sa_family = AF_INET6;
  auto over_read = vio::get_nameinfo(event_loop, claims_ipv6);
  REQUIRE(over_read.state_ptr->done);
  CHECK(over_read.state_ptr->result.error().code == vio::errc::invalid_argument);

  vio::address_info_t unix_family = ipv4_loopback(80);
  reinterpret_cast<sockaddr *>(unix_family.addr.data())->sa_family = AF_UNIX;
  auto wrong_family = vio::get_nameinfo(event_loop, unix_family);
  REQUIRE(wrong_family.state_ptr->done);
  CHECK(wrong_family.state_ptr->result.error().code == vio::errc::invalid_argument);
}

TEST_CASE("an international name is converted to its ASCII form before the lookup")
{
  vio::event_loop_t event_loop;
  bool completed = false;
  event_loop.run_in_loop([&] {
    return [](vio::event_loop_t &ev, bool &completed) -> vio::task_t<void> {
      auto lookup = vio::get_addrinfo(ev, "b\xc3\xbc" "cher.invalid");
      CHECK(lookup.state_ptr->host == "xn--bcher-kva.invalid");
      auto ascii = vio::get_addrinfo(ev, "LocalHost");
      CHECK(ascii.state_ptr->host == "LocalHost");
      co_await lookup;
      co_await ascii;
      completed = true;
      ev.stop();
    }(event_loop, completed);
  });
  event_loop.run();
  CHECK(completed);
}

TEST_CASE("a lookup cancelled while queued resumes at once with errc::canceled")
{
  vio::event_loop_t event_loop;
  dns_gate_t gate(more_than_any_pool);
  bool completed = false;
  event_loop.run_in_loop([&] {
    return [](vio::event_loop_t &ev, dns_gate_t &gate, bool &completed) -> vio::task_t<void> {
      gate.block(ev);

      vio::cancellation_t before_await;
      auto first = vio::get_addrinfo(ev, "localhost", {}, &before_await);
      CHECK_FALSE(first.state_ptr->done);
      before_await.cancel();
      CHECK(first.state_ptr->done);
      auto first_result = co_await first;
      CHECK_FALSE(first_result.has_value());
      if (!first_result.has_value())
      {
        CHECK(first_result.error().code == vio::errc::canceled);
        CHECK(vio::is_cancelled(first_result.error()));
      }

      vio::cancellation_t while_waiting;
      bool resumed = false;
      auto waiter = [](vio::event_loop_t &ev, vio::cancellation_t &cancel, bool &resumed) -> vio::task_t<void> {
        auto named = co_await vio::get_nameinfo(ev, ipv4_loopback(80), NI_NUMERICHOST | NI_NUMERICSERV, &cancel);
        CHECK_FALSE(named.has_value());
        if (!named.has_value())
          CHECK(named.error().code == vio::errc::canceled);
        resumed = true;
      }(ev, while_waiting, resumed);
      CHECK_FALSE(resumed);
      while_waiting.cancel();
      CHECK(resumed);
      co_await std::move(waiter);

      gate.release();
      completed = true;
      ev.stop();
    }(event_loop, gate, completed);
  });
  event_loop.run();
  CHECK(completed);
  CHECK(gate.finished == static_cast<int>(more_than_any_pool));
}

TEST_CASE("a lookup whose future is dropped still finishes before run returns")
{
  vio::event_loop_t event_loop;
  {
    auto dropped = vio::get_nameinfo(event_loop, ipv4_loopback(53));
    auto also_dropped = vio::get_addrinfo(event_loop, "127.0.0.1");
  }
  event_loop.stop();
  event_loop.run();
  CHECK(vio::detail::core(event_loop).in_flight() == 0);
}
} // TEST_SUITE

} // namespace
