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
// libuv asks the allocator for 64 KiB before every read, and default_alloc
// answers with new char[65536]. For a datagram socket that is a 64 KiB
// allocation and free per ~1.2 KiB packet. The pool answers with a block sized
// for the traffic and takes it back afterwards, so a steady-state read loop
// stops allocating entirely.
//
// Single-threaded, like the loop it serves. The pool must outlive every buffer
// handed out from it -- a unique_buf_t holds a pointer to it as its
// deallocator's user handle.

#include <uv.h>

#include "vio/unique_buf.h"

#include <cstddef>
#include <cstdint>
#include <new>
#include <vector>

namespace vio
{
// Room for any datagram that survives the internet unfragmented (1500 byte
// Ethernet MTU) with slack, and a power of two.
inline constexpr std::size_t default_pool_block_size = 2048;
inline constexpr std::size_t default_pool_max_retained = 256;

class buffer_pool_t
{
public:
  explicit buffer_pool_t(std::size_t block_size = default_pool_block_size, std::size_t max_retained = default_pool_max_retained)
    : _block_size(block_size == 0 ? default_pool_block_size : block_size)
    , _max_retained(max_retained)
  {
  }

  ~buffer_pool_t()
  {
    for (char *block : _free)
    {
      delete[] block;
    }
  }

  buffer_pool_t(const buffer_pool_t &) = delete;
  buffer_pool_t &operator=(const buffer_pool_t &) = delete;
  buffer_pool_t(buffer_pool_t &&) = delete;
  buffer_pool_t &operator=(buffer_pool_t &&) = delete;

  void acquire(uv_buf_t *buf)
  {
    if (buf == nullptr)
    {
      return;
    }
    char *block = nullptr;
    if (!_free.empty())
    {
      block = _free.back();
      _free.pop_back();
      ++_reuses;
    }
    else
    {
      block = new (std::nothrow) char[_block_size];
      ++_allocations;
    }
    buf->base = block;
    buf->len = block == nullptr ? 0 : static_cast<decltype(buf->len)>(_block_size);
  }

  void release(uv_buf_t *buf)
  {
    if (buf == nullptr || buf->base == nullptr)
    {
      return;
    }
    if (_free.size() < _max_retained)
    {
      _free.push_back(buf->base);
    }
    else
    {
      delete[] buf->base;
    }
    buf->base = nullptr;
    buf->len = 0;
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

  static void alloc_cb(void *user, std::size_t /*suggested_size*/, uv_buf_t *buf)
  {
    static_cast<buffer_pool_t *>(user)->acquire(buf);
  }

  static void dealloc_cb(void *user, uv_buf_t *buf)
  {
    static_cast<buffer_pool_t *>(user)->release(buf);
  }

private:
  std::vector<char *> _free;
  std::size_t _block_size;
  std::size_t _max_retained;
  std::uint64_t _allocations = 0;
  std::uint64_t _reuses = 0;
};
} // namespace vio
