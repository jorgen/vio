#include <doctest/doctest.h>
#include <vio/operation/dns.h>

TEST_CASE("DNS resolution of localhost", "[dns]")
{
  auto task = vio::getaddrinfo("localhost");
  auto result = task.get_result();
  EQUIRE_FALSE(result.error);
  REQUIRE_FALSE(result.addresses.empty());
  REQUIRE(std::find(result.addresses.begin(), result.addresses.end(), "127.0.0.1") != result.addresses.end());
}

TEST_CASE("DNS resolution of invalid hostname", "[dns]")
{
  auto task = vio::getaddrinfo("this.domain.definitely.does.not.exist");
  auto result = task.get_result();
  EQUIRE(result.error);
  REQUIRE(result.addresses.empty());
}

TEST_CASE("Reverse DNS lookup", "[dns]")
{
  auto task = vio::getnameinfo("127.0.0.1");
  auto result = task.get_result();

  REQUIRE_FALSE(result.error);
  REQUIRE_FALSE(result.addresses.empty());
  REQUIRE(result.addresses[0].find("localhost") != std::string::npos);
}

TEST_CASE("DNS resolution with port", "[dns]")
{
  auto task = vio::getaddrinfo("localhost", "80");
  auto result = task.get_result();

  REQUIRE_FALSE(result.error);
  REQUIRE_FALSE(result.addresses.empty());
}