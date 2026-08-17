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

// RFC 9000 section 16: variable-length integers.
//
// The top two bits of the first byte give the length as 1 << prefix, and the
// remaining 62 bits carry the value. Encoding here is always minimal, but
// decoding accepts non-minimal forms -- the RFC's own example decodes 0x4025
// and 0x25 to the same 37, and a peer is free to send either.

#include <bit>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace vio::quic
{
inline constexpr std::uint64_t varint_max = (std::uint64_t{1} << 62) - 1;

[[nodiscard]] constexpr std::size_t varint_size(std::uint64_t value)
{
  if (value <= 63)
  {
    return 1;
  }
  if (value <= 16383)
  {
    return 2;
  }
  if (value <= 1073741823)
  {
    return 4;
  }
  return 8;
}

// Returns the number of bytes written, or zero when the value exceeds the
// 62-bit range or out is too small.
[[nodiscard]] inline std::size_t varint_encode(std::span<std::uint8_t> out, std::uint64_t value)
{
  if (value > varint_max)
  {
    return 0;
  }
  const std::size_t size = varint_size(value);
  if (out.size() < size)
  {
    return 0;
  }
  const std::uint8_t prefix = size == 1 ? 0x00 : size == 2 ? 0x40 : size == 4 ? 0x80 : 0xc0;
  for (std::size_t i = 0; i < size; ++i)
  {
    out[size - 1 - i] = static_cast<std::uint8_t>((value >> (8 * i)) & 0xff);
  }
  out[0] = static_cast<std::uint8_t>(out[0] | prefix);
  return size;
}

struct varint_t
{
  std::uint64_t value = 0;
  std::size_t size = 0;
};

// Returns nothing when the input is shorter than the encoded length says.
[[nodiscard]] inline std::optional<varint_t> varint_decode(std::span<const std::uint8_t> in)
{
  if (in.empty())
  {
    return std::nullopt;
  }
  const std::size_t size = std::size_t{1} << (in[0] >> 6);
  if (in.size() < size)
  {
    return std::nullopt;
  }
  std::uint64_t value = in[0] & 0x3f;
  for (std::size_t i = 1; i < size; ++i)
  {
    value = (value << 8) + in[i];
  }
  return varint_t{.value = value, .size = size};
}
} // namespace vio::quic
