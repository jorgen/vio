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

// RFC 9002 section 7.7. The congestion window says how much may be outstanding;
// it says nothing about how fast it may leave. Handing a whole window to the
// network at once is a burst, and a burst is how a path that could have carried
// the traffic drops it anyway -- the queue at the narrowest hop overflows on the
// spike rather than on the average.
//
// A leaky bucket, as the section suggests: it fills at N * cwnd / smoothed_rtt
// bytes per second and is capped at the burst this endpoint is willing to send
// back to back, which section 7.2 puts at the initial window. N is 1.25, large
// enough that jitter in the RTT estimate does not leave the window unused.
class pacer_t
{
public:
  explicit pacer_t(std::size_t max_datagram_size = 1200)
    : _capacity(initial_congestion_window(max_datagram_size == 0 ? 1200 : max_datagram_size))
    , _tokens(static_cast<std::int64_t>(_capacity))
  {
  }

  [[nodiscard]] bool ready(tick_t now, std::size_t window, std::chrono::nanoseconds smoothed_rtt, std::size_t datagram_size)
  {
    refill(now, window, smoothed_rtt);
    return _tokens >= static_cast<std::int64_t>(datagram_size);
  }

  void on_sent(tick_t now, std::size_t bytes, std::size_t window, std::chrono::nanoseconds smoothed_rtt)
  {
    refill(now, window, smoothed_rtt);
    _tokens -= static_cast<std::int64_t>(bytes);
  }

  // When the bucket will hold enough for another datagram. Nothing means it
  // already does.
  [[nodiscard]] std::optional<tick_t> next_departure(tick_t now, std::size_t window, std::chrono::nanoseconds smoothed_rtt, std::size_t datagram_size) const
  {
    if (_tokens >= static_cast<std::int64_t>(datagram_size))
    {
      return std::nullopt;
    }
    const auto rate = fill_rate(window, smoothed_rtt);
    if (rate == 0)
    {
      return std::nullopt;
    }
    const auto needed = static_cast<std::uint64_t>(static_cast<std::int64_t>(datagram_size) - _tokens);
    // rate is bytes per second; invert without losing the sub-millisecond
    // resolution the whole exercise depends on.
    const auto wait = std::chrono::nanoseconds(static_cast<std::int64_t>((needed * 1000000000ULL) / rate));
    return now + wait;
  }

  void reset()
  {
    _tokens = static_cast<std::int64_t>(_capacity);
    _have_last = false;
  }

private:
  [[nodiscard]] static std::uint64_t fill_rate(std::size_t window, std::chrono::nanoseconds smoothed_rtt)
  {
    const auto rtt = smoothed_rtt.count();
    if (rtt <= 0 || window == 0)
    {
      return 0;
    }
    // N = 1.25, as 5/4, in bytes per second. The window is clamped first
    // because it is multiplied by a billion: an implausibly large one would
    // otherwise wrap and come back out as a tiny rate, which would stall
    // sending rather than merely mis-pace it.
    constexpr std::uint64_t window_ceiling = std::uint64_t{1} << 32;
    const auto bounded = std::min(static_cast<std::uint64_t>(window), window_ceiling);
    const auto numerator = bounded * 5ULL * 1000000000ULL;
    return numerator / (static_cast<std::uint64_t>(rtt) * 4ULL);
  }

  void refill(tick_t now, std::size_t window, std::chrono::nanoseconds smoothed_rtt)
  {
    if (!_have_last)
    {
      _last = now;
      _have_last = true;
      return;
    }
    if (now <= _last)
    {
      return;
    }
    auto elapsed = now - _last;
    _last = now;
    // A connection that has been idle would otherwise accumulate an unbounded
    // credit and spend it in one burst, which is the thing being prevented.
    // The cap is generous enough that ordinary scheduling jitter is absorbed.
    const auto ceiling = std::chrono::seconds(1);
    if (elapsed > ceiling)
    {
      elapsed = ceiling;
    }
    const auto rate = fill_rate(window, smoothed_rtt);
    if (rate == 0)
    {
      _tokens = static_cast<std::int64_t>(_capacity);
      return;
    }
    const auto gained = (static_cast<std::uint64_t>(elapsed.count()) * rate) / 1000000000ULL;
    _tokens += static_cast<std::int64_t>(gained);
    if (_tokens > static_cast<std::int64_t>(_capacity))
    {
      _tokens = static_cast<std::int64_t>(_capacity);
    }
  }

  std::size_t _capacity = 0;
  std::int64_t _tokens = 0;
  tick_t _last;
  bool _have_last = false;
};

class congestion_control_t
{
public:
  // Section 9.4 of RFC 9000: on confirming a peer's new address the controller
  // returns to initial values, because the capacity it learned belongs to the
  // path that is no longer in use. Sending at the old rate on a path that
  // cannot carry it is how a migration turns into a burst of loss.
  void reset()
  {
    const auto datagram_size = _max_datagram_size;
    *this = congestion_control_t(datagram_size);
  }

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
