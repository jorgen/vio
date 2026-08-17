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

// RFC 9000 appendices A.2 and A.3: packet numbers travel truncated to the
// fewest bytes that still let the peer recover them, and are reconstructed
// against the largest number seen so far.
//
// The window is the reason these two must agree exactly: encode too few bytes
// and the peer reconstructs a different number, decrypts with the wrong nonce,
// and drops the packet as unauthenticated -- with nothing to say why.

#include <bit>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace vio::quic
{
inline constexpr std::size_t max_packet_number_size = 4;

// A.2: enough bytes to cover twice the outstanding range, clamped to the 1..4
// the wire format allows.
[[nodiscard]] inline std::size_t packet_number_size(std::uint64_t full_packet_number, std::optional<std::uint64_t> largest_acked)
{
  const std::uint64_t unacked = largest_acked.has_value() && full_packet_number > *largest_acked ? full_packet_number - *largest_acked : full_packet_number + 1;
  const std::size_t min_bits = static_cast<std::size_t>(std::bit_width(unacked));
  const std::size_t size = (min_bits + 7) / 8;
  if (size == 0)
  {
    return 1;
  }
  return size > max_packet_number_size ? max_packet_number_size : size;
}

// Writes the low `size` bytes in network order. Returns bytes written, or zero
// when out is too small or size is outside 1..4.
[[nodiscard]] inline std::size_t packet_number_encode(std::span<std::uint8_t> out, std::uint64_t full_packet_number, std::size_t size)
{
  if (size == 0 || size > max_packet_number_size || out.size() < size)
  {
    return 0;
  }
  for (std::size_t i = 0; i < size; ++i)
  {
    out[size - 1 - i] = static_cast<std::uint8_t>((full_packet_number >> (8 * i)) & 0xff);
  }
  return size;
}

// A.3, transcribed. largest_packet_number is the largest successfully
// processed number in this space; pass it as it stands, the +1 is here.
[[nodiscard]] inline std::uint64_t packet_number_decode(std::uint64_t largest_packet_number, std::uint64_t truncated, std::size_t bits)
{
  const std::uint64_t expected = largest_packet_number + 1;
  const std::uint64_t window = std::uint64_t{1} << bits;
  const std::uint64_t half_window = window / 2;
  const std::uint64_t mask = window - 1;

  const std::uint64_t candidate = (expected & ~mask) | truncated;
  if (candidate + half_window <= expected && candidate < (std::uint64_t{1} << 62) - window)
  {
    return candidate + window;
  }
  if (candidate > expected + half_window && candidate >= window)
  {
    return candidate - window;
  }
  return candidate;
}
} // namespace vio::quic
