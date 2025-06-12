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

#include <climits>
#include <cstdint>
#include <limits>
#include <vector>

#if defined(_MSC_VER)
#include <intrin.h>
static inline unsigned long find_first_set_bit_64(uint64_t mask)
{
  unsigned long index = 0;
  if (_BitScanForward64(&index, mask) != 0U)
  {
    return index;
  }
  return 64UL;
}

static inline unsigned long find_highest_set_bit_64(uint64_t mask)
{
  unsigned long index = 0;
  if (_BitScanReverse64(&index, mask) != 0U)
  {
    return index;
  }
  return 64UL;
}

#elif defined(__GNUC__) || defined(__clang__)
static inline unsigned long find_first_set_bit_64(uint64_t mask)
{
  // __builtin_ctzll(0) is undefined; handle zero mask carefully
  return (mask == 0ULL) ? 64UL : __builtin_ctzll(mask);
}

static inline unsigned long find_highest_set_bit_64(uint64_t mask)
{
  // __builtin_clzll(0) is undefined; handle zero mask carefully
  return (mask == 0ULL) ? 64UL : (63UL - __builtin_clzll(mask));
}
#else
static inline unsigned long find_first_set_bit_64(uint64_t mask)
{
  if (mask == 0ULL)
    return 64UL;
  for (unsigned long i = 0; i < 64; ++i)
  {
    if (mask & (1ULL << i))
      return i;
  }
  return 64UL;
}

static inline unsigned long find_highest_set_bit_64(uint64_t mask)
{
  if (mask == 0ULL)
    return 64UL;
  for (int i = 63; i >= 0; --i)
  {
    if (mask & (1ULL << i))
      return static_cast<unsigned long>(i);
  }
  return 64UL; // Should not happen
}
#endif

class dynamic_bitset_t
{
public:
  static constexpr std::size_t INVALID_INDEX = static_cast<std::size_t>(-1);

  dynamic_bitset_t() = default;

  explicit dynamic_bitset_t(std::size_t bit_count)
  {
    resize(bit_count);
  }

  void resize(std::size_t bit_count)
  {
    _block_count = block_count_for_bits(bit_count);
    _bits.resize(_block_count, 0ULL);
  }

  // Ensure we have room for at least bitCount bits
  void ensure_size(std::size_t bit_count)
  {
    const std::size_t required_blocks = block_count_for_bits(bit_count);
    if (required_blocks > _block_count)
    {
      _block_count = required_blocks;
      _bits.resize(_block_count, 0ULL);
    }
  }

  bool test(std::size_t idx) const
  {
    std::size_t block_index = 0;
    std::size_t bit_in_block = 0;
    if (!locate_bit(idx, block_index, bit_in_block))
    {
      return false;
    }
    return ((_bits[block_index] >> bit_in_block) & 1ULL) != 0ULL;
  }

  void set(std::size_t idx)
  {
    std::size_t block_index = 0;
    std::size_t bit_in_block = 0;
    if (!locate_bit(idx, block_index, bit_in_block))
    {
      ensure_size(idx + 1);
      locate_bit(idx, block_index, bit_in_block); // guaranteed success now
    }
    _bits[block_index] |= (1ULL << bit_in_block);
  }

  void clear(std::size_t idx)
  {
    std::size_t block_index = 0;
    std::size_t bit_in_block = 0;
    if (!locate_bit(idx, block_index, bit_in_block))
    {
      return;
    }
    _bits[block_index] &= ~(1ULL << bit_in_block);
  }

  [[nodiscard]] std::size_t find_first_clear_bit() const
  {
    for (std::size_t blk = 0; blk < _bits.size(); ++blk)
    {
      const uint64_t block = _bits[blk];
      if (block != std::numeric_limits<std::uint64_t>::max())
      {
        // Some zero bits exist
        const uint64_t inverted = ~block;
        // Find index of first "1" in 'inverted'
        if (const unsigned long bit_index = find_first_set_bit_64(inverted); bit_index < BITS_PER_BLOCK)
        {
          return (blk * BITS_PER_BLOCK) + bit_index;
        }
      }
    }
    return INVALID_INDEX;
  }

  [[nodiscard]] std::size_t find_rightmost_set_bit() const
  {
    // Start from the last block
    for (std::size_t blk = _bits.size(); blk > 0; --blk)
    {
      const uint64_t block = _bits[blk - 1];
      if (block != 0ULL)
      {
        // find highest set bit
        if (const unsigned long bit_index = find_highest_set_bit_64(block); bit_index < BITS_PER_BLOCK)
        {
          return ((blk - 1) * BITS_PER_BLOCK) + bit_index;
        }
      }
    }
    return INVALID_INDEX;
  }

private:
  static constexpr std::size_t BITS_PER_BLOCK = sizeof(std::uint64_t) * CHAR_BIT;

  std::size_t _block_count = 0;
  std::vector<std::uint64_t> _bits;

  static std::size_t block_count_for_bits(std::size_t bit_count)
  {
    return (bit_count + BITS_PER_BLOCK - 1) / BITS_PER_BLOCK;
  }

  bool locate_bit(std::size_t idx, std::size_t &block_index, std::size_t &bit_in_block) const
  {
    block_index = idx / BITS_PER_BLOCK;
    bit_in_block = idx % BITS_PER_BLOCK;
    if (block_index >= _block_count)
    {
      return false;
    }
    return true;
  }
};
