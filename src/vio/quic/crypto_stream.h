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

// Reassembly of the CRYPTO stream (RFC 9000 section 7.5), one per encryption
// level.
//
// CRYPTO frames carry an offset into a stream that has no length and no end,
// and the network is free to reorder them, duplicate them, and split or merge
// them differently on every retransmission. TLS wants none of that: it wants
// one ordered byte stream. This turns the former into the latter.
//
// The overlap cases are not hypothetical. A peer that retransmits after a
// timeout may repackage the same handshake bytes across different frame
// boundaries, so a chunk can partly duplicate what is already held, or bridge
// two chunks that were previously separate. Ranges are therefore merged on
// insert rather than stored as received.
//
// Buffering is bounded because it has to be: an endpoint that accepted
// out-of-order CRYPTO data without limit would let anyone who can send a
// packet allocate memory on its behalf, forever, without ever completing a
// handshake. Section 7.5 requires at least 4096 bytes be accepted and names
// CRYPTO_BUFFER_EXCEEDED for going over.

#include "vio/quic/varint.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <map>
#include <span>
#include <vector>

namespace vio::quic
{
// Section 7.5 sets the floor at 4096. This is the whole handshake's worth of
// slack, which is generous without being a lever.
inline constexpr std::size_t default_crypto_buffer_limit = 64 * 1024;

// The byte budget above says nothing about what holding those bytes costs. One
// byte at every other offset stays inside it and still buys a map node and a
// separate heap block per byte -- about a hundred times the accounted figure,
// and reachable before the handshake, where Initial keys come from a connection
// id anyone can read. So the runs are counted as well as the bytes.
inline constexpr std::size_t max_crypto_chunks = 64;

enum class crypto_insert_t : std::uint8_t
{
  ok,
  // The final offset exceeds 2^62-1: FRAME_ENCODING_ERROR.
  offset_overflow,
  // More out-of-order data than the limit allows: CRYPTO_BUFFER_EXCEEDED.
  buffer_exceeded,
};

class crypto_stream_t
{
public:
  explicit crypto_stream_t(std::size_t buffer_limit = default_crypto_buffer_limit)
    : _buffer_limit(buffer_limit)
  {
  }

  [[nodiscard]] crypto_insert_t insert(std::uint64_t offset, std::span<const std::uint8_t> data)
  {
    if (offset > varint_max || data.size() > varint_max - offset)
    {
      return crypto_insert_t::offset_overflow;
    }
    if (data.empty())
    {
      return crypto_insert_t::ok;
    }

    // Anything at or below what TLS has already consumed is a retransmission
    // of history and is dropped rather than rebuffered.
    std::uint64_t start = offset;
    std::size_t skip = 0;
    if (start < _read_offset)
    {
      const std::uint64_t behind = _read_offset - start;
      if (behind >= data.size())
      {
        return crypto_insert_t::ok;
      }
      skip = static_cast<std::size_t>(behind);
      start = _read_offset;
    }

    std::vector<std::uint8_t> incoming(data.begin() + static_cast<std::ptrdiff_t>(skip), data.end());
    std::uint64_t end = start + incoming.size();

    // Absorb every chunk this one touches or abuts, so what is stored stays a
    // set of disjoint, non-adjacent ranges and the first of them is always the
    // whole contiguous run.
    auto first = _chunks.upper_bound(start);
    if (first != _chunks.begin())
    {
      auto previous = std::prev(first);
      if (previous->first + previous->second.size() >= start)
      {
        first = previous;
      }
    }

    auto last = first;
    std::uint64_t merged_start = start;
    std::uint64_t merged_end = end;
    for (; last != _chunks.end() && last->first <= end; ++last)
    {
      merged_start = last->first < merged_start ? last->first : merged_start;
      const std::uint64_t chunk_end = last->first + last->second.size();
      merged_end = chunk_end > merged_end ? chunk_end : merged_end;
    }

    if (merged_start == start && merged_end == end && first == last)
    {
      if (_buffered + incoming.size() > _buffer_limit)
      {
        return crypto_insert_t::buffer_exceeded;
      }
      // The only path that adds a run without removing one, so the only place
      // the count can grow.
      if (_chunks.size() >= max_crypto_chunks)
      {
        return crypto_insert_t::buffer_exceeded;
      }
      _buffered += incoming.size();
      _chunks.emplace(start, std::move(incoming));
      return crypto_insert_t::ok;
    }

    // Rebuild the union. Existing bytes win over the new ones where they
    // overlap: the peer is obliged to send the same bytes for the same offsets,
    // and if it did not, the handshake transcript will fail anyway.
    const std::size_t merged_size = static_cast<std::size_t>(merged_end - merged_start);
    std::size_t releasing = 0;
    for (auto it = first; it != last; ++it)
    {
      releasing += it->second.size();
    }
    if (_buffered - releasing + merged_size > _buffer_limit)
    {
      return crypto_insert_t::buffer_exceeded;
    }

    std::vector<std::uint8_t> merged(merged_size);
    std::copy(incoming.begin(), incoming.end(), merged.begin() + static_cast<std::ptrdiff_t>(start - merged_start));
    for (auto it = first; it != last; ++it)
    {
      std::copy(it->second.begin(), it->second.end(), merged.begin() + static_cast<std::ptrdiff_t>(it->first - merged_start));
    }

    _buffered -= releasing;
    _chunks.erase(first, last);
    _buffered += merged_size;
    _chunks.emplace(merged_start, std::move(merged));
    return crypto_insert_t::ok;
  }

  // The bytes TLS can take right now: the run starting exactly where it left
  // off. Empty when the next byte has not arrived, however much is held behind
  // the gap.
  [[nodiscard]] std::span<const std::uint8_t> readable() const
  {
    auto it = _chunks.find(_read_offset);
    if (it == _chunks.end())
    {
      return {};
    }
    return it->second;
  }

  void consume(std::size_t bytes)
  {
    auto it = _chunks.find(_read_offset);
    if (it == _chunks.end() || bytes == 0)
    {
      return;
    }
    const std::size_t taken = bytes > it->second.size() ? it->second.size() : bytes;
    _read_offset += taken;
    _buffered -= taken;
    if (taken == it->second.size())
    {
      _chunks.erase(it);
      return;
    }
    std::vector<std::uint8_t> rest(it->second.begin() + static_cast<std::ptrdiff_t>(taken), it->second.end());
    _chunks.erase(it);
    _chunks.emplace(_read_offset, std::move(rest));
  }

  // How far TLS has consumed. Also the offset a sender would use next.
  [[nodiscard]] std::uint64_t read_offset() const
  {
    return _read_offset;
  }

  [[nodiscard]] std::size_t buffered() const
  {
    return _buffered;
  }

  [[nodiscard]] bool has_gap() const
  {
    return !_chunks.empty() && _chunks.begin()->first != _read_offset;
  }

  [[nodiscard]] std::size_t buffer_limit() const
  {
    return _buffer_limit;
  }

private:
  std::map<std::uint64_t, std::vector<std::uint8_t>> _chunks;
  std::uint64_t _read_offset = 0;
  std::size_t _buffered = 0;
  std::size_t _buffer_limit = default_crypto_buffer_limit;
};
} // namespace vio::quic
