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

#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>
#include <utility>
#include <doctest/doctest.h>
#include <vio/buffer_pool.h>
#include <vio/event_loop.h>
#include <vio/operation/sleep.h>
#include <vio/operation/udp.h>
#include <vio/task.h>

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

std::span<const std::uint8_t> as_bytes(std::string_view text)
{
  return {reinterpret_cast<const std::uint8_t *>(text.data()), text.size()};
}

std::expected<std::pair<vio::udp_t, int>, vio::error_t> bound_socket(vio::event_loop_t &loop)
{
  auto udp = vio::udp_create(loop);
  if (!udp.has_value())
  {
    return std::unexpected(udp.error());
  }
  auto addr = make_ip4("127.0.0.1", 0);
  if (!addr.has_value())
  {
    return std::unexpected(addr.error());
  }
  auto bound = vio::udp_bind(udp.value(), reinterpret_cast<const sockaddr *>(&addr.value()));
  if (!bound.has_value())
  {
    return std::unexpected(bound.error());
  }
  auto name = vio::udp_sockname(udp.value());
  if (!name.has_value())
  {
    return std::unexpected(name.error());
  }
  const auto *in = reinterpret_cast<const sockaddr_in *>(&name.value());
  return std::make_pair(std::move(udp.value()), static_cast<int>(ntohs(in->sin_port)));
}
} // namespace

TEST_SUITE("buffer pool")
{
TEST_CASE("a released block is handed out again")
{
  vio::buffer_pool_t pool(1024, 8);
  CHECK(pool.block_size() == 1024);

  auto first = pool.acquire();
  REQUIRE(first.data() != nullptr);
  CHECK(first.size() == 1024);
  CHECK(pool.allocations() == 1);
  CHECK(pool.reuses() == 0);

  std::byte *address = first.data();
  pool.release(first);
  CHECK(pool.retained() == 1);
#if defined(VIO_TEST_ASAN)
  CHECK(__asan_address_is_poisoned(address));
#endif

  auto second = pool.acquire();
  CHECK(second.data() == address);
  CHECK(pool.allocations() == 1);
  CHECK(pool.reuses() == 1);
#if defined(VIO_TEST_ASAN)
  CHECK_FALSE(__asan_address_is_poisoned(address));
#endif
  pool.release(second);
}

TEST_CASE("the free list is capped")
{
  constexpr std::size_t retain = 4;
  vio::buffer_pool_t pool(64, retain);

  std::array<std::span<std::byte>, retain + 6> buffers = {};
  for (auto &buffer : buffers)
  {
    buffer = pool.acquire();
    REQUIRE(buffer.data() != nullptr);
  }
  CHECK(pool.allocations() == buffers.size());

  for (auto &buffer : buffers)
  {
    pool.release(buffer);
  }
  CHECK(pool.retained() == retain);
}

TEST_CASE("zero_on_release wipes a block before it is reused")
{
  vio::buffer_pool_t plain(32, 4);
  vio::buffer_pool_t wiping(32, 4, true);

  auto fill_and_release = [](vio::buffer_pool_t &pool)
  {
    auto buf = pool.acquire();
    REQUIRE(buf.data() != nullptr);
    std::memset(buf.data(), 0x5a, 32);
    std::byte *address = buf.data();
    pool.release(buf);
    return address;
  };

  std::byte *plain_block = fill_and_release(plain);
  std::byte *wiped_block = fill_and_release(wiping);

  // The same block comes back out, so this reads what release() left behind.
  auto reused = plain.acquire();
  CHECK(reused.data() == plain_block);
  CHECK(reused[0] == std::byte{0x5a});
  plain.release(reused);

  auto clean = wiping.acquire();
  CHECK(clean.data() == wiped_block);
  CHECK(clean[0] == std::byte{0});
  CHECK(clean[31] == std::byte{0});
  wiping.release(clean);
}

TEST_CASE("the pool works as a unique_buf_t deallocator")
{
  vio::buffer_pool_t pool(128, 4);
  {
    vio::unique_buf_t buffer(vio::buffer_pool_t::alloc_cb(&pool, 65536), &vio::buffer_pool_t::dealloc_cb, &pool);
    REQUIRE(buffer.data() != nullptr);
    CHECK(buffer.capacity() == 128);
    buffer.resize(10);
    CHECK(buffer.size() == 10);
    CHECK(pool.retained() == 0);
  }
  CHECK(pool.retained() == 1);
  CHECK(pool.allocations() == 1);
}

TEST_CASE("a zero block size falls back to the default")
{
  vio::buffer_pool_t pool(0);
  CHECK(pool.block_size() == vio::default_pool_block_size);
}

TEST_CASE("a pooled socket stops allocating once it is warm")
{
  constexpr int datagram_count = 24;
  vio::event_loop_t event_loop;
  vio::buffer_pool_t pool(2048, 64);
  int received = 0;

  event_loop.run_in_loop(
    [&]
    {
      return [](vio::event_loop_t &loop, vio::buffer_pool_t &pool, int &received) -> vio::task_t<void>
      {
        auto receiver_pair = bound_socket(loop);
        REQUIRE_EXPECTED(receiver_pair);
        const int port = receiver_pair->second;
        REQUIRE_EXPECTED(vio::udp_use_buffer_pool(receiver_pair->first, pool));

        auto receiver_task = [](vio::udp_t receiver, int &received) -> vio::task_t<void>
        {
          auto reader_or_err = vio::udp_create_reader(receiver);
          REQUIRE_EXPECTED(reader_or_err);
          auto reader = std::move(reader_or_err.value());
          for (int i = 0; i < datagram_count; ++i)
          {
            auto datagram = co_await reader;
            REQUIRE_EXPECTED(datagram);
            ++received;
          }
        }(std::move(receiver_pair->first), received);

        co_await [](vio::event_loop_t &el, int p) -> vio::task_t<void>
        {
          auto sender_pair = bound_socket(el);
          REQUIRE_EXPECTED(sender_pair);
          auto dest = make_ip4("127.0.0.1", p);
          REQUIRE_EXPECTED(dest);
          for (int i = 0; i < datagram_count; ++i)
          {
            REQUIRE_EXPECTED(vio::udp_try_send(sender_pair->first, as_bytes("pooled"), reinterpret_cast<const sockaddr *>(&dest.value())));
            auto pause = vio::sleep(el, std::chrono::milliseconds(1));
            auto slept = co_await pause;
            REQUIRE_EXPECTED(slept);
          }
          co_return;
        }(loop, port);

        co_await std::move(receiver_task);
        {
          auto tmp = std::move(receiver_task);
        }
        loop.stop();
      }(event_loop, pool, received);
    });

  event_loop.run();

  CHECK(received == datagram_count);
  // Draining between sends keeps one block in flight at a time, so the pool
  // allocates for the first datagram and recycles for the rest. The default
  // allocator would have newed 64 KiB per datagram.
  CHECK(pool.allocations() < static_cast<std::uint64_t>(datagram_count));
  CHECK(pool.reuses() > 0);
  MESSAGE("allocations=" << pool.allocations() << " reuses=" << pool.reuses());
}
}
