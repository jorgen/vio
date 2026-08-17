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

// RFC 9000 section 5.1: a connection ID is 0 to 20 bytes. Inline storage, so
// a routing table can hold one per connection without a heap allocation and
// compare them by value.

#include <algorithm>
#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <optional>
#include <span>

namespace vio::quic
{
inline constexpr std::size_t max_connection_id_size = 20;

class connection_id_t
{
public:
  constexpr connection_id_t() = default;

  [[nodiscard]] static std::optional<connection_id_t> from_bytes(std::span<const std::uint8_t> bytes)
  {
    if (bytes.size() > max_connection_id_size)
    {
      return std::nullopt;
    }
    connection_id_t out;
    out._size = static_cast<std::uint8_t>(bytes.size());
    std::copy(bytes.begin(), bytes.end(), out._bytes.begin());
    return out;
  }

  [[nodiscard]] std::span<const std::uint8_t> bytes() const
  {
    return {_bytes.data(), _size};
  }

  [[nodiscard]] std::size_t size() const
  {
    return _size;
  }

  [[nodiscard]] bool empty() const
  {
    return _size == 0;
  }

  friend bool operator==(const connection_id_t &lhs, const connection_id_t &rhs)
  {
    return lhs._size == rhs._size && std::memcmp(lhs._bytes.data(), rhs._bytes.data(), lhs._size) == 0;
  }

private:
  std::array<std::uint8_t, max_connection_id_size> _bytes = {};
  std::uint8_t _size = 0;
};
} // namespace vio::quic

template <>
struct std::hash<vio::quic::connection_id_t>
{
  std::size_t operator()(const vio::quic::connection_id_t &id) const noexcept
  {
    // FNV-1a: connection IDs are short and already random for our own, but a
    // peer chooses its own and may not be.
    std::size_t value = 1469598103934665603ULL;
    for (std::uint8_t byte : id.bytes())
    {
      value ^= byte;
      value *= 1099511628211ULL;
    }
    return value;
  }
};
