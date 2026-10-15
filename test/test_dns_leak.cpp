#include <doctest/doctest.h>

#include "leak_check.h"

#include <vio/event_loop.h>
#include <vio/operation/dns.h>

#include <string>

TEST_SUITE("dns leaks")
{
  TEST_CASE("get_nameinfo does not leak its parked ref on synchronous failure")
  {
    vio::event_loop_t loop;

    const vio::address_info_t empty_addr;

    {
      auto fut = vio::get_nameinfo(loop, empty_addr);
      REQUIRE(fut.state_ptr->done);
      REQUIRE_FALSE(fut.state_ptr->result.has_value());
    }

    for (int i = 0; i < 5; ++i)
    {
      auto f = vio::get_nameinfo(loop, empty_addr);
    }

    constexpr int iterations = 200;
    vio_test::leak_guard_t guard;
    for (int i = 0; i < iterations; ++i)
    {
      auto f = vio::get_nameinfo(loop, empty_addr);
    }
    CHECK_LT(guard.leaked_blocks(), iterations / 2);

    loop.stop();
    loop.run();
  }

  TEST_CASE("get_addrinfo does not leak its parked ref on synchronous failure")
  {
    vio::event_loop_t loop;
    const vio::address_info_t hints;

    const std::string bad_host = "\xff\xff\xfe";

    {
      auto fut = vio::get_addrinfo(loop, bad_host, hints);
      REQUIRE(fut.state_ptr->done);
      REQUIRE_FALSE(fut.state_ptr->result.has_value());
      CHECK(fut.state_ptr->result.error().code == vio::errc::invalid_argument);
    }

    for (int i = 0; i < 5; ++i)
    {
      auto f = vio::get_addrinfo(loop, bad_host, hints);
    }

    constexpr int iterations = 200;
    vio_test::leak_guard_t guard;
    for (int i = 0; i < iterations; ++i)
    {
      auto f = vio::get_addrinfo(loop, bad_host, hints);
    }
    CHECK_LT(guard.leaked_blocks(), iterations / 2);

    loop.stop();
    loop.run();
  }
}
