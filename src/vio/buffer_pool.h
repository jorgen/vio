/*
  Copyright (c) 2025 Jørgen Lind

  Permission is hereby granted, free of charge, to any person obtaining a copy of
  this software and associated documentation files (the "Software"), to deal in
  the Software without restriction, including without limitation the rights to
  use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
  of the Software, and to permit persons to whom the Software is furnished to do
  so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
*/

#pragma once

// A free list of fixed-size read buffers.
//
// A recycled block still holds the previous datagram's bytes. Nothing reads
// past a datagram's length, so this is not a leak -- but QUIC decrypts in
// place, which means those bytes can be plaintext. Zeroing every block costs
// a memset per datagram on the receive path, so it is off by default and
// available to deployments that would rather pay it.
//
// Single-threaded, like the loop it serves. The pool must outlive every buffer
// handed out from it -- a unique_buf_t holds a pointer to it as its
// deallocator's user handle.

#include "vio/unique_buf.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>
#include <span>
#include <vector>

#if defined(__SANITIZE_ADDRESS__)
#define VIO_BUFFER_POOL_ASAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define VIO_BUFFER_POOL_ASAN 1
#endif
#endif

#if defined(VIO_BUFFER_POOL_ASAN)
extern "C" void __asan_poison_memory_region(void const volatile *address, std::size_t size);
extern "C" void __asan_unpoison_memory_region(void const volatile *address, std::size_t size);
#endif

namespace vio
{
namespace detail
{
inline void poison_memory(const void *address, std::size_t size) noexcept
{
#if defined(VIO_BUFFER_POOL_ASAN)
  __asan_poison_memory_region(address, size);
#else
  (void)address;
  (void)size;
#endif
}

inline void secure_zero(void *address, std::size_t size) noexcept
{
  static void *(*const volatile wipe)(void *, int, std::size_t) = std::memset;
  wipe(address, 0, size);
}

inline void unpoison_memory(const void *address, std::size_t size) noexcept
{
#if defined(VIO_BUFFER_POOL_ASAN)
  __asan_unpoison_memory_region(address, size);
#else
  (void)address;
  (void)size;
#endif
}
} // namespace detail

// Room for any datagram that survives the internet unfragmented (1500 byte
// Ethernet MTU) with slack, and a power of two.
inline constexpr std::size_t default_pool_block_size = 2048;
inline constexpr std::size_t default_pool_max_retained = 256;

class buffer_pool_t
{
public:
  explicit buffer_pool_t(std::size_t block_size = default_pool_block_size, std::size_t max_retained = default_pool_max_retained, bool zero_on_release = false)
    : _block_size(block_size == 0 ? default_pool_block_size : block_size)
    , _max_retained(max_retained)
    , _zero_on_release(zero_on_release)
  {
  }

  ~buffer_pool_t()
  {
    for (std::byte *block : _free)
    {
      detail::unpoison_memory(block, _block_size);
      delete[] block;
    }
  }

  buffer_pool_t(const buffer_pool_t &) = delete;
  buffer_pool_t &operator=(const buffer_pool_t &) = delete;
  buffer_pool_t(buffer_pool_t &&) = delete;
  buffer_pool_t &operator=(buffer_pool_t &&) = delete;

  [[nodiscard]] std::span<std::byte> acquire()
  {
    std::byte *block = nullptr;
    if (!_free.empty())
    {
      block = _free.back();
      _free.pop_back();
      detail::unpoison_memory(block, _block_size);
      ++_reuses;
    }
    else
    {
      block = new (std::nothrow) std::byte[_block_size];
      if (block == nullptr)
      {
        return {};
      }
      ++_allocations;
    }
    return {block, _block_size};
  }

  void release(std::span<std::byte> buffer)
  {
    if (buffer.data() == nullptr)
    {
      return;
    }
    if (buffer.size() != _block_size)
    {
      std::fprintf(stderr, "vio: buffer_pool_t was handed back a %zu byte block that it did not hand out (its blocks are %zu bytes)\n", buffer.size(), _block_size);
      std::abort();
    }
    if (_zero_on_release)
    {
      detail::secure_zero(buffer.data(), _block_size);
    }
    if (_free.size() < _max_retained)
    {
      detail::poison_memory(buffer.data(), _block_size);
      _free.push_back(buffer.data());
    }
    else
    {
      delete[] buffer.data();
    }
  }

  [[nodiscard]] std::size_t block_size() const
  {
    return _block_size;
  }

  [[nodiscard]] std::size_t retained() const
  {
    return _free.size();
  }

  [[nodiscard]] std::uint64_t allocations() const
  {
    return _allocations;
  }

  [[nodiscard]] std::uint64_t reuses() const
  {
    return _reuses;
  }

  static std::span<std::byte> alloc_cb(void *user, std::size_t /*suggested_size*/)
  {
    return static_cast<buffer_pool_t *>(user)->acquire();
  }

  static void dealloc_cb(void *user, std::span<std::byte> buffer)
  {
    static_cast<buffer_pool_t *>(user)->release(buffer);
  }

private:
  std::vector<std::byte *> _free;
  std::size_t _block_size;
  std::size_t _max_retained;
  bool _zero_on_release = false;
  std::uint64_t _allocations = 0;
  std::uint64_t _reuses = 0;
};
} // namespace vio
