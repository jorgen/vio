#include <doctest/doctest.h>

#include "leak_check.h"

#include <vio/event_loop.h>
#include <vio/operation/dns.h>

#include <string>

// get_addrinfo/get_nameinfo park a strong ref into req->data and recover it
// only inside the uv callback. When uv_getaddrinfo/uv_getnameinfo fail
// synchronously (r < 0) the callback never runs, so the early return must
// recover the parked ref or the whole state storage leaks.
TEST_SUITE("dns leaks")
{
  TEST_CASE("get_nameinfo does not leak its parked ref on synchronous failure")
  {
    vio::event_loop_t loop;

    // An empty address makes get_sockaddr() == nullptr, so uv_getnameinfo
    // returns UV_EINVAL synchronously on every platform.
    const vio::address_info_t empty_addr;

    // Confirm the failure really is synchronous (parked-ref recovery is inline).
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
    // Pre-fix this leaks one state object per iteration (~`iterations` blocks);
    // post-fix only small one-time noise remains.
    CHECK_LT(guard.leaked_blocks(), iterations / 2);

    loop.stop();
    loop.run();
  }

  TEST_CASE("get_addrinfo does not leak its parked ref on synchronous failure")
  {
    vio::event_loop_t loop;
    const vio::address_info_t hints;

    // Invalid UTF-8 makes libuv fail during UTF-16/IDNA conversion before
    // queueing work (synchronous on Windows). Self-check and skip elsewhere.
    const std::string bad_host = "\xff\xff\xfe";

    bool is_sync = false;
    {
      auto fut = vio::get_addrinfo(loop, bad_host, hints);
      is_sync = fut.state_ptr->done;
    }

    if (is_sync)
    {
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
    }
    else
    {
      MESSAGE("get_addrinfo did not fail synchronously on this platform; skipping leak assertion");
    }

    loop.stop();
    loop.run();
  }
}
