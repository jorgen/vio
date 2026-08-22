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

// NewReno congestion control, RFC 9002 section 7, transcribed from the
// appendix B pseudocode.
//
// Three states and one number. In slow start the window grows by every byte
// acknowledged, doubling each round trip until something is lost. A loss halves
// it and starts a recovery period, during which further losses of packets sent
// before the period began change nothing -- that is the whole point of
// tracking when recovery started, and skipping it would make a single lost
// round trip collapse the window several times over. After recovery the window
// grows by roughly one datagram per round trip.
//
// Persistent congestion is the separate, harsher case: when everything sent
// over a span longer than several PTOs is lost, the path is not congested but
// broken, and the window drops to two datagrams rather than half.
//
// This holds no bytes-in-flight count of its own. That lives with the sent
// packet records in loss_recovery.h, because the two must never disagree.

#include "vio/quic/loss_recovery.h"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <vector>

namespace vio::quic
{
// Section 7.2: ten datagrams, bounded by the larger of 14720 bytes and two
// datagrams.
[[nodiscard]] constexpr std::size_t initial_congestion_window(std::size_t max_datagram_size)
{
  return std::min<std::size_t>(10 * max_datagram_size, std::max<std::size_t>(14720, 2 * max_datagram_size));
}

// Section 7.2: the floor a loss can drive the window to.
[[nodiscard]] constexpr std::size_t minimum_congestion_window(std::size_t max_datagram_size)
{
  return 2 * max_datagram_size;
}

// Section 7.6.1.
inline constexpr std::int64_t persistent_congestion_threshold = 3;

class congestion_control_t
{
public:
  explicit congestion_control_t(std::size_t max_datagram_size = 1200)
    : _max_datagram_size(max_datagram_size == 0 ? 1200 : max_datagram_size)
    , _window(initial_congestion_window(max_datagram_size == 0 ? 1200 : max_datagram_size))
  {
  }

  [[nodiscard]] std::size_t window() const
  {
    return _window;
  }

  [[nodiscard]] std::size_t slow_start_threshold() const
  {
    return _slow_start_threshold;
  }

  [[nodiscard]] std::size_t max_datagram_size() const
  {
    return _max_datagram_size;
  }

  [[nodiscard]] bool in_slow_start() const
  {
    return _window < _slow_start_threshold;
  }

  // Appendix B.5: a packet sent before the recovery period began carries no
  // new information about the path, so acknowledging it must not grow the
  // window.
  [[nodiscard]] bool in_recovery(tick_t sent_time) const
  {
    return _recovery_started && sent_time <= _recovery_start;
  }

  void on_packet_acked(const sent_packet_t &packet)
  {
    if (!packet.in_flight || in_recovery(packet.time_sent))
    {
      return;
    }
    if (_window < _slow_start_threshold)
    {
      _window += packet.size;
      return;
    }
    // Congestion avoidance: about one datagram per round trip. The division is
    // integer, so a remainder is carried rather than discarded -- dropping it
    // would stall growth entirely once the window exceeds the datagram size
    // times the acknowledged bytes.
    _avoidance_remainder += _max_datagram_size * packet.size;
    _window += _avoidance_remainder / _window;
    _avoidance_remainder %= _window;
  }

  // Appendix B.6.
  void on_congestion_event(tick_t sent_time, tick_t now)
  {
    if (in_recovery(sent_time))
    {
      return;
    }
    _recovery_start = now;
    _recovery_started = true;
    _slow_start_threshold = std::max(_window / 2, minimum_congestion_window(_max_datagram_size));
    _window = _slow_start_threshold;
    _avoidance_remainder = 0;
  }

  // Appendix B.8. first_rtt_sample is when the first RTT measurement arrived;
  // without one, section 7.6.2 forbids declaring persistent congestion at all,
  // because the PTO was armed from a guess that may be far too large.
  void on_packets_lost(const std::vector<sent_packet_t> &lost, tick_t now, const rtt_estimator_t &rtt, std::chrono::nanoseconds max_ack_delay, std::optional<tick_t> first_rtt_sample)
  {
    std::optional<tick_t> latest_loss;
    for (const auto &packet : lost)
    {
      if (!packet.in_flight)
      {
        continue;
      }
      latest_loss = latest_loss.has_value() ? std::max(*latest_loss, packet.time_sent) : packet.time_sent;
    }
    if (!latest_loss.has_value())
    {
      return;
    }
    on_congestion_event(*latest_loss, now);

    if (!first_rtt_sample.has_value())
    {
      return;
    }
    if (persistent_congestion(lost, rtt, max_ack_delay, *first_rtt_sample))
    {
      // Section 7.6: not congested, broken. Start over from the floor.
      _window = minimum_congestion_window(_max_datagram_size);
      _slow_start_threshold = _window;
      _recovery_started = false;
      _avoidance_remainder = 0;
    }
  }

  // Section 7.6.1: this one includes max_ack_delay whatever space the losses
  // were in, unlike the PTO of section 6.2.
  [[nodiscard]] static std::chrono::nanoseconds persistent_congestion_duration(const rtt_estimator_t &rtt, std::chrono::nanoseconds max_ack_delay)
  {
    return (rtt.pto_base() + max_ack_delay) * persistent_congestion_threshold;
  }

private:
  // Section 7.6.2: two ack-eliciting packets declared lost, sent far enough
  // apart, with nothing between them acknowledged and an RTT sample already in
  // hand when both went out.
  //
  // The RFC permits considering only the space that was acknowledged rather
  // than reconciling send times across all three, and that is what happens
  // here: the caller passes one space's losses. The consequence is spelled out
  // in 7.6.2 -- it may declare persistent congestion where a cross-space view
  // would not, never the reverse.
  [[nodiscard]] static bool persistent_congestion(const std::vector<sent_packet_t> &lost, const rtt_estimator_t &rtt, std::chrono::nanoseconds max_ack_delay, tick_t first_rtt_sample)
  {
    std::optional<tick_t> earliest;
    std::optional<tick_t> latest;
    std::size_t counted = 0;
    for (const auto &packet : lost)
    {
      if (!packet.ack_eliciting || packet.time_sent <= first_rtt_sample)
      {
        continue;
      }
      earliest = earliest.has_value() ? std::min(*earliest, packet.time_sent) : packet.time_sent;
      latest = latest.has_value() ? std::max(*latest, packet.time_sent) : packet.time_sent;
      ++counted;
    }
    if (counted < 2 || !earliest.has_value())
    {
      return false;
    }
    return (*latest - *earliest) > persistent_congestion_duration(rtt, max_ack_delay);
  }

  std::size_t _max_datagram_size = 1200;
  std::size_t _window = 0;
  // Section B.3 starts this at infinity so the connection begins in slow
  // start; the largest representable value is that, for this purpose.
  std::size_t _slow_start_threshold = std::numeric_limits<std::size_t>::max();
  std::size_t _avoidance_remainder = 0;
  tick_t _recovery_start;
  bool _recovery_started = false;
};
} // namespace vio::quic
