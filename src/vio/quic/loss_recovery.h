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

// RTT estimation and loss detection, RFC 9002 sections 5 and 6, transcribed
// from the pseudocode in appendix A.
//
// The thing this records is not packets but *what packets meant*. Section 13.3
// of RFC 9000 opens by saying lost packets are not retransmitted whole, and
// frame.h froze the three consequences of that into loss_policy_t long before
// there was anything to lose. A sent packet here is therefore a list of
// sent_frame_t -- kind, offset, length -- and never the bytes that went out.
// Keeping the bytes would make the retransmit case trivially correct and the
// resend-current case silently wrong: MAX_DATA would be replayed with the
// limit that applied when it was first sent rather than the one that applies
// now, which is a stall the peer can do nothing about.
//
// Loss detection is per packet number space; RTT and congestion control are
// not, because they are properties of the path while loss detection also
// depends on which keys exist. Discarding a space (section A.11) therefore
// throws away its packets without disturbing the RTT estimate.
//
// Time enters as a parameter. Nothing here reads a clock.

#include "vio/quic/frame_codec.h"
#include "vio/tick.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <optional>
#include <utility>
#include <vector>

namespace vio::quic
{
// Section 6.1.1: three packets of reordering before a gap counts as loss.
inline constexpr std::uint64_t loss_packet_threshold = 3;

// Section 6.1.2, expressed as a fraction so the arithmetic stays integral.
inline constexpr std::int64_t loss_time_threshold_numerator = 9;
inline constexpr std::int64_t loss_time_threshold_denominator = 8;

// Section 6.1.2 and 6.2.1: the floor under both the loss delay and the PTO.
inline constexpr std::chrono::nanoseconds loss_granularity = std::chrono::milliseconds(1);

// Section 6.2.2: what to assume before there is a sample.
inline constexpr std::chrono::nanoseconds initial_rtt = std::chrono::milliseconds(333);

enum class pn_space_t : std::uint8_t
{
  initial,
  handshake,
  application,
};

inline constexpr std::size_t pn_space_count = 3;

[[nodiscard]] constexpr std::size_t pn_space_to_index(pn_space_t space)
{
  return static_cast<std::size_t>(space);
}

// Section 5. Held once for the connection: the estimate describes the path,
// not any one encryption level.
class rtt_estimator_t
{
public:
  [[nodiscard]] bool has_sample() const
  {
    return _has_sample;
  }

  [[nodiscard]] std::chrono::nanoseconds latest() const
  {
    return _latest;
  }

  [[nodiscard]] std::chrono::nanoseconds minimum() const
  {
    return _minimum;
  }

  [[nodiscard]] std::chrono::nanoseconds smoothed() const
  {
    return _smoothed;
  }

  [[nodiscard]] std::chrono::nanoseconds variation() const
  {
    return _variation;
  }

  // Appendix A.7, transcribed.
  void on_rtt_sample(std::chrono::nanoseconds latest, std::chrono::nanoseconds ack_delay, bool handshake_confirmed, std::chrono::nanoseconds max_ack_delay)
  {
    if (latest <= std::chrono::nanoseconds::zero())
    {
      return;
    }
    _latest = latest;

    if (!_has_sample)
    {
      _minimum = latest;
      _smoothed = latest;
      _variation = latest / 2;
      _has_sample = true;
      return;
    }

    // min_rtt deliberately ignores acknowledgment delay: it is the floor the
    // adjustment below is judged plausible against.
    _minimum = std::min(_minimum, latest);

    auto delay = ack_delay;
    if (handshake_confirmed)
    {
      // Before confirmation the peer has not yet promised a max_ack_delay, so
      // its claim cannot be held to one.
      delay = std::min(delay, max_ack_delay);
    }

    auto adjusted = latest;
    if (latest >= _minimum + delay)
    {
      adjusted = latest - delay;
    }

    const auto difference = _smoothed > adjusted ? _smoothed - adjusted : adjusted - _smoothed;
    _variation = (_variation * 3) / 4 + difference / 4;
    _smoothed = (_smoothed * 7) / 8 + adjusted / 8;
  }

  // Section 6.2.1, without the max_ack_delay term: that is added only for the
  // application space, and only once the handshake is confirmed.
  [[nodiscard]] std::chrono::nanoseconds pto_base() const
  {
    return _smoothed + std::max(_variation * 4, loss_granularity);
  }

  // Section 6.1.2.
  [[nodiscard]] std::chrono::nanoseconds loss_delay() const
  {
    const auto base = std::max(_latest, _smoothed);
    const auto scaled = (base * loss_time_threshold_numerator) / loss_time_threshold_denominator;
    return std::max(scaled, loss_granularity);
  }

private:
  bool _has_sample = false;
  std::chrono::nanoseconds _latest{};
  std::chrono::nanoseconds _minimum{};
  std::chrono::nanoseconds _smoothed = initial_rtt;
  std::chrono::nanoseconds _variation = initial_rtt / 2;
};

// What a packet meant, in the terms section 13.3 cares about. This is what a
// loss is repaired from.
struct sent_frame_t
{
  frame_kind_t kind = frame_kind_t::padding;
  // CRYPTO and STREAM: where in the stream, and how much.
  std::uint64_t offset = 0;
  std::uint64_t length = 0;
  std::uint64_t stream_id = 0;
};

struct sent_packet_t
{
  std::uint64_t packet_number = 0;
  tick_t time_sent;
  // Section 2: a packet is ack-eliciting if it contains any frame other than
  // ACK, PADDING or CONNECTION_CLOSE, and in flight if it is ack-eliciting or
  // otherwise counts against the congestion window.
  bool ack_eliciting = false;
  bool in_flight = false;
  std::size_t size = 0;
  std::vector<sent_frame_t> frames;
};

// The state the PTO calculation needs that lives outside loss recovery.
struct recovery_context_t
{
  bool handshake_confirmed = false;
  bool has_handshake_keys = false;
  // Appendix A.8: a client has not validated the server's address until it
  // has seen a Handshake ACK or confirmed the handshake. A server always has.
  bool peer_completed_address_validation = true;
  std::chrono::nanoseconds max_ack_delay = std::chrono::milliseconds(25);
  std::uint32_t ack_delay_exponent = 3;
};

struct ack_outcome_t
{
  std::vector<sent_packet_t> acknowledged;
  std::vector<sent_packet_t> lost;
  bool rtt_updated = false;
};

class loss_recovery_t
{
public:
  void on_packet_sent(pn_space_t space, sent_packet_t packet)
  {
    auto &state = _spaces[pn_space_to_index(space)];
    if (state.discarded)
    {
      return;
    }
    if (packet.in_flight)
    {
      _bytes_in_flight += packet.size;
    }
    if (packet.ack_eliciting)
    {
      state.time_of_last_ack_eliciting = packet.time_sent;
      state.has_ack_eliciting_sent = true;
    }
    const auto number = packet.packet_number;
    state.sent.insert_or_assign(number, std::move(packet));
  }

  // Appendix A.6. The frame is taken as decoded from the wire, so ack_delay is
  // still scaled by the peer's exponent.
  [[nodiscard]] ack_outcome_t on_ack_received(pn_space_t space, const frame_t &ack, tick_t now, const recovery_context_t &context)
  {
    ack_outcome_t outcome;
    auto &state = _spaces[pn_space_to_index(space)];
    if (state.discarded || ack.kind != frame_kind_t::ack)
    {
      return outcome;
    }

    const bool largest_was_unacked = state.sent.contains(ack.largest_acknowledged);
    if (!state.has_largest_acked || ack.largest_acknowledged > state.largest_acked)
    {
      state.largest_acked = ack.largest_acknowledged;
      state.has_largest_acked = true;
    }

    bool acked_ack_eliciting = false;
    for_each_acked(ack, [&](std::uint64_t number)
    {
      auto it = state.sent.find(number);
      if (it == state.sent.end())
      {
        return;
      }
      if (it->second.in_flight)
      {
        _bytes_in_flight -= std::min(_bytes_in_flight, it->second.size);
      }
      acked_ack_eliciting = acked_ack_eliciting || it->second.ack_eliciting;
      outcome.acknowledged.push_back(std::move(it->second));
      state.sent.erase(it);
    });

    // Only the largest gives an RTT sample, and only when it is newly
    // acknowledged: a repeated ACK of an old packet would otherwise report a
    // round trip that never happened.
    if (largest_was_unacked && acked_ack_eliciting)
    {
      for (const auto &packet : outcome.acknowledged)
      {
        if (packet.packet_number != ack.largest_acknowledged)
        {
          continue;
        }
        const std::uint64_t scale = context.ack_delay_exponent >= 63 ? 0 : ack.ack_delay << context.ack_delay_exponent;
        const auto delay = std::chrono::microseconds(static_cast<std::int64_t>(std::min<std::uint64_t>(scale, std::numeric_limits<std::int64_t>::max())));
        // Section 5.3: the application space is the only one whose ACK delay
        // is bounded by max_ack_delay, and only after confirmation.
        _rtt.on_rtt_sample(now - packet.time_sent, delay, context.handshake_confirmed && space == pn_space_t::application, context.max_ack_delay);
        outcome.rtt_updated = true;
        break;
      }
    }

    if (acked_ack_eliciting)
    {
      // Section 6.2.1: a successful acknowledgement means the path is working,
      // so the backoff starts over.
      _pto_count = 0;
    }

    outcome.lost = detect_lost_packets(space, now);
    return outcome;
  }

  // Appendix A.10.
  [[nodiscard]] std::vector<sent_packet_t> detect_lost_packets(pn_space_t space, tick_t now)
  {
    std::vector<sent_packet_t> lost;
    auto &state = _spaces[pn_space_to_index(space)];
    if (state.discarded || !state.has_largest_acked)
    {
      return lost;
    }

    state.loss_time.reset();
    const auto delay = _rtt.loss_delay();
    const auto lost_send_time = now - delay;

    for (auto it = state.sent.begin(); it != state.sent.end();)
    {
      if (it->first > state.largest_acked)
      {
        ++it;
        continue;
      }
      const bool by_time = it->second.time_sent <= lost_send_time;
      const bool by_order = state.largest_acked >= it->first + loss_packet_threshold;
      if (by_time || by_order)
      {
        if (it->second.in_flight)
        {
          _bytes_in_flight -= std::min(_bytes_in_flight, it->second.size);
        }
        lost.push_back(std::move(it->second));
        it = state.sent.erase(it);
        continue;
      }
      // Not lost yet, but it will be if nothing acknowledges it: remember the
      // earliest moment that becomes true so a timer can be set for it.
      const auto when = it->second.time_sent + delay;
      state.loss_time = state.loss_time.has_value() ? std::min(*state.loss_time, when) : when;
      ++it;
    }
    return lost;
  }

  // Appendix A.8. The earlier of time-threshold loss detection and the PTO.
  [[nodiscard]] std::optional<tick_t> loss_detection_timer(tick_t now, const recovery_context_t &context) const
  {
    if (auto loss = earliest_loss_time(); loss.has_value())
    {
      return loss;
    }
    if (_bytes_in_flight == 0 && context.peer_completed_address_validation)
    {
      // Nothing to lose and nobody waiting on us.
      return std::nullopt;
    }
    return pto_time(now, context).first;
  }

  // Which space the timer belongs to, so a caller knows where to probe.
  [[nodiscard]] std::optional<pn_space_t> loss_detection_space(tick_t now, const recovery_context_t &context) const
  {
    if (auto loss = earliest_loss_space(); loss.has_value())
    {
      return loss;
    }
    if (_bytes_in_flight == 0 && context.peer_completed_address_validation)
    {
      return std::nullopt;
    }
    return pto_time(now, context).second;
  }

  // Appendix A.9. Returns the space to send a probe in, if the expiry was a
  // PTO rather than time-threshold loss detection.
  [[nodiscard]] std::optional<pn_space_t> on_loss_detection_timeout(tick_t now, const recovery_context_t &context, std::vector<sent_packet_t> &lost)
  {
    if (auto space = earliest_loss_space(); space.has_value())
    {
      lost = detect_lost_packets(*space, now);
      return std::nullopt;
    }
    ++_pto_count;
    return loss_detection_space(now, context);
  }

  // Appendix A.11: the packets go, the RTT estimate stays. It described the
  // path, and the path has not changed.
  void discard_space(pn_space_t space)
  {
    auto &state = _spaces[pn_space_to_index(space)];
    for (const auto &entry : state.sent)
    {
      if (entry.second.in_flight)
      {
        _bytes_in_flight -= std::min(_bytes_in_flight, entry.second.size);
      }
    }
    state = space_state_t{};
    state.discarded = true;
    _pto_count = 0;
  }

  [[nodiscard]] const rtt_estimator_t &rtt() const
  {
    return _rtt;
  }

  [[nodiscard]] std::size_t bytes_in_flight() const
  {
    return _bytes_in_flight;
  }

  [[nodiscard]] std::uint64_t pto_count() const
  {
    return _pto_count;
  }

  [[nodiscard]] bool ack_eliciting_in_flight() const
  {
    for (const auto &state : _spaces)
    {
      for (const auto &entry : state.sent)
      {
        if (entry.second.ack_eliciting)
        {
          return true;
        }
      }
    }
    return false;
  }

  [[nodiscard]] std::size_t unacknowledged(pn_space_t space) const
  {
    return _spaces[pn_space_to_index(space)].sent.size();
  }

private:
  struct space_state_t
  {
    std::map<std::uint64_t, sent_packet_t> sent;
    std::uint64_t largest_acked = 0;
    bool has_largest_acked = false;
    std::optional<tick_t> loss_time;
    tick_t time_of_last_ack_eliciting;
    bool has_ack_eliciting_sent = false;
    bool discarded = false;
  };

  // Walks the packet numbers an ACK frame covers, newest range first.
  template <typename Fn>
  static void for_each_acked(const frame_t &ack, Fn &&callback)
  {
    std::uint64_t largest = ack.largest_acknowledged;
    if (ack.first_ack_range > largest)
    {
      return;
    }
    std::uint64_t smallest = largest - ack.first_ack_range;
    for (std::uint64_t number = smallest; number <= largest; ++number)
    {
      callback(number);
    }

    ack_range_reader_t reader(ack.ack_ranges);
    while (auto range = reader.next())
    {
      // Section 19.3.1: largest = previous_smallest - gap - 2.
      if (smallest < range->gap + 2)
      {
        return;
      }
      largest = smallest - range->gap - 2;
      if (range->length > largest)
      {
        return;
      }
      smallest = largest - range->length;
      for (std::uint64_t number = smallest; number <= largest; ++number)
      {
        callback(number);
      }
    }
  }

  [[nodiscard]] std::optional<tick_t> earliest_loss_time() const
  {
    std::optional<tick_t> earliest;
    for (const auto &state : _spaces)
    {
      if (state.discarded || !state.loss_time.has_value())
      {
        continue;
      }
      earliest = earliest.has_value() ? std::min(*earliest, *state.loss_time) : *state.loss_time;
    }
    return earliest;
  }

  [[nodiscard]] std::optional<pn_space_t> earliest_loss_space() const
  {
    std::optional<tick_t> earliest;
    std::optional<pn_space_t> which;
    for (std::size_t i = 0; i < pn_space_count; ++i)
    {
      const auto &state = _spaces[i];
      if (state.discarded || !state.loss_time.has_value())
      {
        continue;
      }
      if (!earliest.has_value() || *state.loss_time < *earliest)
      {
        earliest = *state.loss_time;
        which = static_cast<pn_space_t>(i);
      }
    }
    return which;
  }

  [[nodiscard]] std::pair<std::optional<tick_t>, std::optional<pn_space_t>> pto_time(tick_t now, const recovery_context_t &context) const
  {
    auto duration = _rtt.pto_base() * (std::int64_t{1} << std::min<std::uint64_t>(_pto_count, 20));

    if (!ack_eliciting_in_flight())
    {
      // The anti-deadlock PTO: a client with nothing in flight that has not
      // yet had its address validated must still probe, or a server that is
      // waiting on it will wait forever.
      const auto space = context.has_handshake_keys ? pn_space_t::handshake : pn_space_t::initial;
      return {now + duration, space};
    }

    std::optional<tick_t> earliest;
    std::optional<pn_space_t> which;
    for (std::size_t i = 0; i < pn_space_count; ++i)
    {
      const auto &state = _spaces[i];
      if (state.discarded || !state.has_ack_eliciting_sent || state.sent.empty())
      {
        continue;
      }
      bool eliciting = false;
      for (const auto &entry : state.sent)
      {
        if (entry.second.ack_eliciting)
        {
          eliciting = true;
          break;
        }
      }
      if (!eliciting)
      {
        continue;
      }

      auto space_duration = duration;
      if (static_cast<pn_space_t>(i) == pn_space_t::application)
      {
        if (!context.handshake_confirmed)
        {
          // Section 6.2.1: the application space cannot be probed before the
          // handshake is confirmed, and nothing above it can be either.
          break;
        }
        space_duration += context.max_ack_delay * (std::int64_t{1} << std::min<std::uint64_t>(_pto_count, 20));
      }

      const auto candidate = state.time_of_last_ack_eliciting + space_duration;
      if (!earliest.has_value() || candidate < *earliest)
      {
        earliest = candidate;
        which = static_cast<pn_space_t>(i);
      }
    }
    return {earliest, which};
  }

  std::array<space_state_t, pn_space_count> _spaces;
  rtt_estimator_t _rtt;
  std::size_t _bytes_in_flight = 0;
  std::uint64_t _pto_count = 0;
};
} // namespace vio::quic
