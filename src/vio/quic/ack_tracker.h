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

// What has been received in one packet number space, and the ACK frame that
// says so (RFC 9000 sections 13.2 and 19.3).
//
// One of these per space -- Initial, Handshake, Application -- because packet
// numbers are per space and an ACK in one says nothing about another.
//
// The wire encoding is written backwards from how the data is kept. Received
// packets are naturally a set of ascending ranges; an ACK frame is a descending
// walk from the largest, where each step encodes how far *down* to jump. The
// two are the same information, and build_ack is where one becomes the other.
//
// Time arrives as a parameter, never from a clock, so the delay arithmetic can
// be driven exactly in a test.

#include "vio/quic/frame_codec.h"
#include "vio/quic/ecn.h"
#include "vio/tick.h"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <optional>
#include <vector>

namespace vio::quic
{
// Section 13.2.3 requires a bound, both to keep an ACK frame inside a packet
// and to stop a peer that sends every other packet number from turning the
// range list into unbounded state.
inline constexpr std::size_t default_max_ack_ranges = 32;

// Section 13.2.2: a receiver SHOULD acknowledge after two ack-eliciting
// packets.
inline constexpr std::uint64_t ack_eliciting_threshold = 2;

// Section 18.2 default, and the value assumed before transport parameters have
// been exchanged.
inline constexpr std::uint32_t default_ack_delay_exponent = 3;

struct ack_frame_t
{
  std::uint64_t largest_acknowledged = 0;
  // Already scaled by the ack delay exponent, ready for the wire.
  std::uint64_t ack_delay = 0;
  std::uint64_t first_ack_range = 0;
  std::vector<ack_range_t> ranges;
  // Section 13.4.2: what arrived carrying each codepoint, cumulative for the
  // life of the connection. Absent until something marked has been seen --
  // sending zeroes would tell the peer its marks are being erased.
  std::optional<ecn_counts_totals_t> ecn;
};

class ack_tracker_t
{
public:
  explicit ack_tracker_t(std::size_t max_ranges = default_max_ack_ranges)
    : _max_ranges(max_ranges == 0 ? 1 : max_ranges)
  {
  }

  // Whether this number has already been seen, or is so old it can no longer
  // be told apart from one that has. Either way the packet is a replay and the
  // caller drops it.
  [[nodiscard]] bool is_duplicate(std::uint64_t packet_number) const
  {
    if (packet_number < _minimum)
    {
      return true;
    }
    return find_containing(packet_number) != _ranges.end();
  }

  // Records a packet whose payload has been authenticated. Duplicates are
  // idempotent: they neither widen a range nor count toward the next ACK.
  void on_packet_received(std::uint64_t packet_number, bool ack_eliciting, tick_t now, ecn_codepoint_t ecn = ecn_codepoint_t::not_ect)
  {
    if (is_duplicate(packet_number))
    {
      return;
    }

    // Section 13.4.2: counted per packet, not per datagram, and only for
    // packets that authenticated -- an attacker who could make us count
    // forged CE marks could make us report congestion that never happened.
    switch (ecn)
    {
    case ecn_codepoint_t::ect0:
      ++_ecn.ect0;
      _saw_ecn = true;
      break;
    case ecn_codepoint_t::ect1:
      ++_ecn.ect1;
      _saw_ecn = true;
      break;
    case ecn_codepoint_t::ce:
      ++_ecn.ce;
      _saw_ecn = true;
      break;
    case ecn_codepoint_t::not_ect:
      break;
    }

    if (!_received_any || packet_number > _largest_received)
    {
      _largest_received = packet_number;
      _largest_received_at = now;
    }
    _received_any = true;

    insert(packet_number);
    trim();

    if (ack_eliciting)
    {
      ++_ack_eliciting_since_ack;
      if (!_ack_pending)
      {
        _ack_pending = true;
        _first_unacknowledged_at = now;
      }
    }
  }

  // Called once an ACK frame covering everything currently held has been sent.
  void on_ack_sent()
  {
    _ack_pending = false;
    _ack_eliciting_since_ack = 0;
  }

  // Section 13.2.1 and 13.2.2: two ack-eliciting packets, or one that has
  // waited out the delay this endpoint promised.
  [[nodiscard]] bool should_send_ack(tick_t now, std::chrono::nanoseconds max_ack_delay) const
  {
    if (!_ack_pending)
    {
      return false;
    }
    if (_ack_eliciting_since_ack >= ack_eliciting_threshold)
    {
      return true;
    }
    return now - _first_unacknowledged_at >= max_ack_delay;
  }

  // When an ACK must be sent by, so a caller can arm a timer instead of
  // polling. Nothing pending means no deadline.
  [[nodiscard]] std::optional<tick_t> ack_deadline(std::chrono::nanoseconds max_ack_delay) const
  {
    if (!_ack_pending)
    {
      return std::nullopt;
    }
    if (_ack_eliciting_since_ack >= ack_eliciting_threshold)
    {
      return _first_unacknowledged_at;
    }
    return _first_unacknowledged_at + max_ack_delay;
  }

  [[nodiscard]] std::optional<ack_frame_t> build_ack(tick_t now, std::uint32_t ack_delay_exponent = default_ack_delay_exponent) const
  {
    if (_ranges.empty())
    {
      return std::nullopt;
    }

    ack_frame_t frame;
    if (_saw_ecn)
    {
      frame.ecn = _ecn;
    }

    // Section 13.2.5: the delay is measured from the arrival of the packet
    // being reported as largest. A clock that ran backwards reports zero
    // rather than an enormous unsigned delay.
    const auto elapsed = now >= _largest_received_at ? now - _largest_received_at : std::chrono::nanoseconds::zero();
    const auto microseconds = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count());
    frame.ack_delay = ack_delay_exponent >= 63 ? 0 : microseconds >> ack_delay_exponent;

    // Ranges are held ascending; the wire wants a descending walk.
    auto it = _ranges.rbegin();
    frame.largest_acknowledged = it->largest;
    frame.first_ack_range = it->largest - it->smallest;
    std::uint64_t previous_smallest = it->smallest;

    for (++it; it != _ranges.rend(); ++it)
    {
      // Section 19.3.1: largest = previous_smallest - gap - 2, so the gap is
      // what makes that identity hold. Ranges are disjoint and never adjacent,
      // which is what keeps this from going negative.
      const std::uint64_t gap = previous_smallest - it->largest - 2;
      frame.ranges.push_back(ack_range_t{.gap = gap, .length = it->largest - it->smallest});
      previous_smallest = it->smallest;
    }
    return frame;
  }

  [[nodiscard]] bool ack_pending() const
  {
    return _ack_pending;
  }

  [[nodiscard]] bool has_received() const
  {
    return _received_any;
  }

  [[nodiscard]] std::uint64_t largest_received() const
  {
    return _largest_received;
  }

  [[nodiscard]] tick_t largest_received_at() const
  {
    return _largest_received_at;
  }

  // Packets below this can no longer be tracked and are refused. It only ever
  // rises, and only when a range is dropped (section 13.2.3).
  [[nodiscard]] std::uint64_t minimum_tracked() const
  {
    return _minimum;
  }

  [[nodiscard]] std::size_t range_count() const
  {
    return _ranges.size();
  }

  [[nodiscard]] std::uint64_t ack_eliciting_since_ack() const
  {
    return _ack_eliciting_since_ack;
  }

private:
  struct range_t
  {
    std::uint64_t smallest = 0;
    std::uint64_t largest = 0;
  };

  [[nodiscard]] std::vector<range_t>::const_iterator find_containing(std::uint64_t packet_number) const
  {
    auto after = std::upper_bound(_ranges.begin(), _ranges.end(), packet_number, [](std::uint64_t value, const range_t &range) { return value < range.smallest; });
    if (after == _ranges.begin())
    {
      return _ranges.end();
    }
    auto candidate = std::prev(after);
    return packet_number <= candidate->largest ? candidate : _ranges.end();
  }

  void insert(std::uint64_t packet_number)
  {
    auto after = std::upper_bound(_ranges.begin(), _ranges.end(), packet_number, [](std::uint64_t value, const range_t &range) { return value < range.smallest; });

    auto inserted = _ranges.end();
    if (after != _ranges.begin())
    {
      auto previous = std::prev(after);
      if (previous->largest + 1 == packet_number)
      {
        previous->largest = packet_number;
        inserted = previous;
      }
    }
    if (inserted == _ranges.end())
    {
      inserted = _ranges.insert(after, range_t{.smallest = packet_number, .largest = packet_number});
    }

    // The new number may have closed the gap to the range above it.
    auto next = std::next(inserted);
    if (next != _ranges.end() && next->smallest == inserted->largest + 1)
    {
      inserted->largest = next->largest;
      _ranges.erase(next);
    }
  }

  void trim()
  {
    while (_ranges.size() > _max_ranges)
    {
      // The oldest range goes, and the floor rises with it: having forgotten
      // those numbers, this endpoint must never accept them again, or it could
      // not tell a replay from a new packet.
      _ranges.erase(_ranges.begin());
      _minimum = _ranges.front().smallest;
    }
  }

  std::vector<range_t> _ranges;
  std::size_t _max_ranges = default_max_ack_ranges;
  std::uint64_t _minimum = 0;
  std::uint64_t _largest_received = 0;
  tick_t _largest_received_at;
  tick_t _first_unacknowledged_at;
  std::uint64_t _ack_eliciting_since_ack = 0;
  bool _ack_pending = false;
  bool _received_any = false;
  ecn_counts_totals_t _ecn;
  bool _saw_ecn = false;
};
} // namespace vio::quic
