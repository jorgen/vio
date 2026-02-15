#include <optional>
#include <doctest/doctest.h>
#include <vio/event_loop.h>
#include <vio/operation/dns.h>
#include <vio/task.h>

#include "require_expected.h"

namespace
{

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
    MESSAGE("Found address: " << name_info.value());
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
    MESSAGE("Google address is " << name_info.value());
  }

  test_completed = true;
  event_loop.stop();
}
// Add this at the start of your test cases to enable verbose output
TEST_SUITE("DNS")
{
TEST_CASE("DNS address info lookup")
{
  doctest::Context context;
  context.setOption("success", true);  // Show successful tests too
  context.setOption("duration", true); // Show how long each test took

  vio::event_loop_t event_loop;

  SUBCASE("lookup valid hostname")
  {
    bool test_completed = false;
    INFO("Testing DNS resolution for localhost"); // NOLINT(misc-const-correctness) doctest macro

    std::optional<vio::task_t<void>> task;
    event_loop.run_in_loop([&] { task.emplace(dns_lookup_localhost(event_loop, test_completed)); });

    event_loop.run();
    REQUIRE(test_completed);
  }

  SUBCASE("lookup invalid hostname")
  {
    bool test_completed = false;
    INFO("Testing DNS resolution for invalid hostname"); // NOLINT(misc-const-correctness) doctest macro

    std::optional<vio::task_t<void>> task;
    event_loop.run_in_loop([&] { task.emplace(dns_lookup_invalid(event_loop, test_completed)); });

    event_loop.run();
    REQUIRE(test_completed);
  }

  SUBCASE("lookup with specific family (IPv4)")
  {
    bool test_completed = false;
    INFO("Testing IPv4-specific DNS resolution"); // NOLINT(misc-const-correctness) doctest macro

    std::optional<vio::task_t<void>> task;
    event_loop.run_in_loop([&] { task.emplace(dns_lookup_ipv4(event_loop, test_completed)); });

    event_loop.run();
    REQUIRE(test_completed);
  }

  SUBCASE("lookup google")
  {
    bool test_completed = false;
    INFO("Testing that we can lookup google"); // NOLINT(misc-const-correctness) doctest macro

    std::optional<vio::task_t<void>> task;
    event_loop.run_in_loop([&] { task.emplace(dns_lookup_google(event_loop, test_completed)); });

    event_loop.run();
    REQUIRE(test_completed);
  }
}
} // TEST_SUITE

} // namespace