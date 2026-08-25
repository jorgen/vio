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
#include <cmath>
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
  return (std::min<std::size_t>)(10 * max_datagram_size, (std::max<std::size_t>)(14720, 2 * max_datagram_size));
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
// How often the sender is in a position to spend pacing tokens. Sending is
// driven from the event loop's timers, whose resolution is a millisecond, so
// this is the grain the bucket has to be sized against rather than a knob.
inline constexpr std::chrono::milliseconds pacing_wakeup_interval{2};

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
  // Section 7.7 sets the rate the bucket fills at but leaves its depth -- the
  // largest burst allowed at once -- to the implementation, and the depth is
  // what decides whether pacing costs throughput or merely shapes it.
  //
  // A bucket is only drained when something looks at it, and here that is an
  // event loop whose timers resolve to a millisecond. Tokens the rate delivers
  // between two wakeups can never be spent if the depth is below them: the
  // sender empties the bucket, returns nothing, and waits for a timer while the
  // path sits idle. Measured on a loopback path -- 260us round trip, a bucket
  // of 29 KB against a rate of 800 MB/s -- it stalled with fewer than one
  // datagram of credit and cost 40% of the throughput.
  //
  // So the depth is what the rate delivers across one wakeup: on a path slower
  // than the timer that is a fraction of the window and pacing does its job,
  // and on a path faster than the timer it reaches the window, where the
  // congestion window is already the bound on a burst. Pacing below the grain
  // of the clock driving it is not something this loop can do, and pretending
  // otherwise only leaves the link empty.
  [[nodiscard]] std::size_t burst_capacity(std::size_t window, std::uint64_t rate) const
  {
    const auto per_wakeup = (rate / 1000) * static_cast<std::uint64_t>(pacing_wakeup_interval.count());
    const auto wanted = (std::max<std::uint64_t>)(_capacity, per_wakeup);
    return static_cast<std::size_t>((std::min<std::uint64_t>)(wanted, (std::max<std::uint64_t>)(window, _capacity)));
  }

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
    const auto bounded = (std::min)(static_cast<std::uint64_t>(window), window_ceiling);
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
      _tokens = static_cast<std::int64_t>(burst_capacity(window, 0));
      return;
    }
    const auto gained = (static_cast<std::uint64_t>(elapsed.count()) * rate) / 1000000000ULL;
    _tokens += static_cast<std::int64_t>(gained);
    const auto ceiling_bytes = static_cast<std::int64_t>(burst_capacity(window, rate));
    if (_tokens > ceiling_bytes)
    {
      _tokens = ceiling_bytes;
    }
  }

  std::size_t _capacity = 0;
  std::int64_t _tokens = 0;
  tick_t _last;
  bool _have_last = false;
};

// RFC 9406. Slow start doubles the window every round trip and only stops when
// something is lost, which on a path that does not drop -- a deep buffer, a
// loopback, a link with a large queue -- means it stops long after the window
// passed what the path can carry. Everything above that point sits in a queue,
// so the connection spends the rest of the transfer paying a round trip time it
// created itself. HyStart++ watches the round trip time instead of waiting for
// a loss: when the minimum RTT of a round rises meaningfully above the previous
// round's, the queue is filling, and slow start gives way to a slower growth
// while it checks whether the rise was real.
struct hystart_constants_t
{
  // RFC 9406 recommends 4ms here, and says an implementation may pick its own.
  // 4ms is a floor, and on a low latency path it is the term that wins: at a
  // 20ms round trip the eighth below is 2.5ms, so the floor -- not the path --
  // decides, and nothing is noticed until the queue is already several times
  // the bandwidth-delay product. 1ms lets the proportional term do the work it
  // was written to do. Detecting early is cheap because the conservative phase
  // has to confirm the rise before slow start actually ends: a false positive
  // costs a few rounds at quarter growth, not a lost window.
  static constexpr std::chrono::microseconds min_rtt_thresh{1000};
  static constexpr std::chrono::microseconds max_rtt_thresh{16000};
  static constexpr std::int64_t min_rtt_divisor = 8;
  // Fewer samples than this in a round says nothing about the path.
  static constexpr std::uint32_t samples_needed = 8;
  // Growth during the conservative phase, as a divisor of what slow start
  // would have added.
  static constexpr std::size_t css_growth_divisor = 4;
  // Rounds of conservative growth before the rise is believed.
  static constexpr std::uint32_t css_rounds = 5;
};

enum class congestion_algorithm_t : std::uint8_t
{
  // RFC 9002 appendix B: one datagram per round trip in congestion avoidance.
  // Safe, and slow to take back a window a loss removed.
  new_reno,
  // RFC 9438. Growth is a cubic curve through the window the path last refused,
  // so recovery is quick near it and cautious past it. What everything else
  // ships by default.
  cubic,
};

// RFC 9438 sections 4.6 and 5.1.
struct cubic_constants_t
{
  // What a congestion event leaves the window at, as a fraction.
  static constexpr double beta = 0.7;
  // How hard the curve pushes past the previous maximum.
  static constexpr double scale = 0.4;
  // Section 4.3: the growth of a Reno flow, expressed for this beta, so that
  // CUBIC is no slower than Reno would have been on a path where the cubic
  // curve is the more cautious of the two.
  static constexpr double alpha = 3.0 * (1.0 - beta) / (1.0 + beta);
  // Section 4.2: a target more than half again the window is not believed.
  static constexpr double target_ceiling = 1.5;
};

enum class hystart_phase_t : std::uint8_t
{
  // Growing at the full slow start rate, watching the round trip time.
  slow_start,
  // A rise was seen; growing at a quarter rate while it is confirmed.
  conservative,
  // Either confirmed, or slow start ended for some other reason.
  finished,
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

  explicit congestion_control_t(std::size_t max_datagram_size = 1200, congestion_algorithm_t algorithm = congestion_algorithm_t::new_reno)
    : _max_datagram_size(max_datagram_size == 0 ? 1200 : max_datagram_size)
    , _window(initial_congestion_window(max_datagram_size == 0 ? 1200 : max_datagram_size))
    , _algorithm(algorithm)
  {
  }

  [[nodiscard]] congestion_algorithm_t algorithm() const
  {
    return _algorithm;
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

  [[nodiscard]] hystart_phase_t hystart_phase() const
  {
    return _hystart;
  }

  // The largest packet number sent so far, which is what ends a round: a round
  // is over once something sent after it began has been acknowledged.
  void on_packet_sent(std::uint64_t packet_number)
  {
    _largest_sent = (std::max)(_largest_sent, packet_number);
  }

  // Section 4.2: an eighth of the round's minimum, held between the floor and
  // ceiling above so neither a very fast path nor a very slow one makes the
  // test meaningless.
  [[nodiscard]] static std::chrono::nanoseconds rise_threshold(std::chrono::nanoseconds base)
  {
    const auto eighth = base / hystart_constants_t::min_rtt_divisor;
    return (std::max<std::chrono::nanoseconds>)(hystart_constants_t::min_rtt_thresh, (std::min<std::chrono::nanoseconds>)(eighth, hystart_constants_t::max_rtt_thresh));
  }

  // One round trip sample, from the acknowledgement that produced it.
  void on_rtt_sample(std::chrono::nanoseconds latest)
  {
    if (latest <= std::chrono::nanoseconds::zero() || _hystart == hystart_phase_t::finished || !in_slow_start())
    {
      return;
    }
    _current_round_min_rtt = (std::min)(_current_round_min_rtt, latest);
    ++_rtt_samples;

    if (_hystart != hystart_phase_t::slow_start || _rtt_samples < hystart_constants_t::samples_needed || _last_round_min_rtt == unset_rtt || _current_round_min_rtt == unset_rtt)
    {
      return;
    }
    if (_current_round_min_rtt >= _last_round_min_rtt + rise_threshold(_last_round_min_rtt))
    {
      _css_baseline_min_rtt = _current_round_min_rtt;
      _hystart = hystart_phase_t::conservative;
      _css_rounds = 0;
    }
  }

  // A round ends when an acknowledgement covers something sent after it began.
  void on_ack_round_progress(std::uint64_t acknowledged_packet_number)
  {
    if (_hystart == hystart_phase_t::finished || !in_slow_start())
    {
      return;
    }
    if (!_round_started)
    {
      _round_started = true;
      _round_end = _largest_sent;
      return;
    }
    if (acknowledged_packet_number < _round_end)
    {
      return;
    }

    if (_hystart == hystart_phase_t::conservative)
    {
      ++_css_rounds;
      if (_current_round_min_rtt < _css_baseline_min_rtt)
      {
        // Section 4.2: the rise did not hold, so it was a transient rather
        // than a queue, and full growth resumes.
        _hystart = hystart_phase_t::slow_start;
      }
      else if (_css_baseline_min_rtt != unset_rtt && _current_round_min_rtt != unset_rtt && _current_round_min_rtt >= _css_baseline_min_rtt + rise_threshold(_css_baseline_min_rtt))
      {
        // Measured against the baseline this phase started from, not against
        // the round before it: the rise that opened the phase would otherwise
        // close it again on the same evidence. Past the baseline by a further
        // threshold means a further round's worth of queue arrived while the
        // phase was making up its mind, which is the confirmation it exists to
        // get. Serving out the remaining rounds would only add to the queue
        // being complained about.
        _slow_start_threshold = _window;
        _hystart = hystart_phase_t::finished;
      }
      else if (_css_rounds >= hystart_constants_t::css_rounds)
      {
        // Believed. Slow start is over at the window that found the queue,
        // rather than at the one that overflowed it.
        _slow_start_threshold = _window;
        _hystart = hystart_phase_t::finished;
      }
    }

    _last_round_min_rtt = _current_round_min_rtt;
    _current_round_min_rtt = unset_rtt;
    _rtt_samples = 0;
    _round_end = _largest_sent;
  }

  // Appendix B.5: a packet sent before the recovery period began carries no
  // new information about the path, so acknowledging it must not grow the
  // window.
  // Whether a recovery period is open at all, as opposed to whether a
  // particular packet predates it. Something deciding whether to add optional
  // traffic wants this one.
  [[nodiscard]] bool recovering() const
  {
    return _recovery_started;
  }

  [[nodiscard]] bool in_recovery(tick_t sent_time) const
  {
    return _recovery_started && sent_time <= _recovery_start;
  }

  void on_packet_acked(const sent_packet_t &packet, tick_t now = tick_t{}, std::chrono::nanoseconds smoothed_rtt = std::chrono::nanoseconds::zero())
  {
    if (!packet.in_flight || in_recovery(packet.time_sent))
    {
      return;
    }
    if (_window < _slow_start_threshold)
    {
      // Section 4.2: a quarter of the usual growth while a suspected queue is
      // being confirmed, so a real one is not made much worse by the checking.
      _window += _hystart == hystart_phase_t::conservative ? packet.size / hystart_constants_t::css_growth_divisor : packet.size;
      return;
    }
    if (_algorithm == congestion_algorithm_t::cubic)
    {
      grow_cubic(packet.size, now, smoothed_rtt);
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

  // RFC 9438 section 4. The window follows a cubic curve whose inflection sits
  // at the window the path last refused: growth is gentle as it approaches that
  // point and firm once past it, which is what makes CUBIC both quick to
  // recover what a loss took and cautious about asking for more than the path
  // ever gave. Below the curve sits a floor -- what a Reno flow would have had
  // by now -- so that on paths where the curve is the slower of the two,
  // choosing CUBIC costs nothing.
  void grow_cubic(std::size_t acknowledged, tick_t now, std::chrono::nanoseconds smoothed_rtt)
  {
    const auto mss = static_cast<double>(_max_datagram_size);
    if (!_epoch_started)
    {
      // Section 4.2: the epoch begins when congestion avoidance does, and the
      // curve is anchored to the window at that moment.
      _epoch_started = true;
      _epoch = now;
      _cwnd_epoch = static_cast<double>(_window);
      _w_est = _cwnd_epoch;
      const auto w_max = (std::max)(_w_max, _cwnd_epoch);
      // K is where the curve returns to the previous maximum. Already at or
      // past it means there is nothing to climb back to.
      _k = w_max <= _cwnd_epoch ? 0.0 : std::cbrt((w_max - _cwnd_epoch) / (cubic_constants_t::scale * mss));
    }

    const auto elapsed = std::chrono::duration<double>(now - _epoch).count();
    const auto rtt = std::chrono::duration<double>(smoothed_rtt).count();
    // Section 4.2: aim a round trip ahead, so the window is right when the
    // packets it allows actually arrive.
    const auto ahead = (std::max)(0.0, elapsed + rtt) - _k;
    const auto w_max = (std::max)(_w_max, _cwnd_epoch);
    double target = cubic_constants_t::scale * mss * ahead * ahead * ahead + w_max;

    const auto window = static_cast<double>(_window);
    if (target < window)
    {
      target = window;
    }
    else if (target > cubic_constants_t::target_ceiling * window)
    {
      target = cubic_constants_t::target_ceiling * window;
    }

    // Section 4.3: what a Reno flow would have reached over the same interval.
    _w_est += cubic_constants_t::alpha * static_cast<double>(acknowledged) / window * mss;
    if (_w_est > target)
    {
      target = _w_est;
    }

    if (target > window)
    {
      // Section 4.4: spread the distance to the target over a round trip
      // rather than jumping to it.
      const auto growth = (target - window) / window * static_cast<double>(acknowledged);
      _cubic_remainder += growth;
      if (_cubic_remainder >= 1.0)
      {
        const auto whole = static_cast<std::size_t>(_cubic_remainder);
        _window += whole;
        _cubic_remainder -= static_cast<double>(whole);
      }
    }
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
    // Slow start is over for the ordinary reason, so there is nothing left for
    // HyStart++ to decide.
    _hystart = hystart_phase_t::finished;
    if (_algorithm == congestion_algorithm_t::cubic)
    {
      const auto window = static_cast<double>(_window);
      // Section 4.7, fast convergence: a flow that had to give up before it
      // reached its previous maximum is meeting competition, and aims lower
      // next time so the newcomer has room to find its share.
      _w_max = _w_max != 0.0 && window < _w_max ? window * (1.0 + cubic_constants_t::beta) / 2.0 : window;
      _slow_start_threshold = (std::max)(static_cast<std::size_t>(window * cubic_constants_t::beta), minimum_congestion_window(_max_datagram_size));
      _window = _slow_start_threshold;
      _epoch_started = false;
      _cubic_remainder = 0.0;
      _avoidance_remainder = 0;
      return;
    }
    _slow_start_threshold = (std::max)(_window / 2, minimum_congestion_window(_max_datagram_size));
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
      latest_loss = latest_loss.has_value() ? (std::max)(*latest_loss, packet.time_sent) : packet.time_sent;
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
      earliest = earliest.has_value() ? (std::min)(*earliest, packet.time_sent) : packet.time_sent;
      latest = latest.has_value() ? (std::max)(*latest, packet.time_sent) : packet.time_sent;
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
  std::size_t _slow_start_threshold = (std::numeric_limits<std::size_t>::max)();
  std::size_t _avoidance_remainder = 0;
  tick_t _recovery_start;
  bool _recovery_started = false;

  // Parenthesised like every other max in this file: windows.h defines max as
  // a macro, vio does not force NOMINMAX on its consumers, and the parentheses
  // are what stop the macro from reaching the name.
  static constexpr std::chrono::nanoseconds unset_rtt = (std::chrono::nanoseconds::max)();
  congestion_algorithm_t _algorithm = congestion_algorithm_t::new_reno;
  // RFC 9438 state. Doubles because the curve is one; the window itself stays
  // an integer count of bytes and only whole bytes are ever added to it.
  double _w_max = 0.0;
  double _cwnd_epoch = 0.0;
  double _w_est = 0.0;
  double _k = 0.0;
  double _cubic_remainder = 0.0;
  tick_t _epoch;
  bool _epoch_started = false;

  hystart_phase_t _hystart = hystart_phase_t::slow_start;
  std::chrono::nanoseconds _last_round_min_rtt = unset_rtt;
  std::chrono::nanoseconds _current_round_min_rtt = unset_rtt;
  std::chrono::nanoseconds _css_baseline_min_rtt = unset_rtt;
  std::uint32_t _rtt_samples = 0;
  std::uint32_t _css_rounds = 0;
  std::uint64_t _largest_sent = 0;
  std::uint64_t _round_end = 0;
  bool _round_started = false;
};
} // namespace vio::quic
