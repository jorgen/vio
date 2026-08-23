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
    _minimum = (std::min)(_minimum, latest);

    auto delay = ack_delay;
    if (handshake_confirmed)
    {
      // Before confirmation the peer has not yet promised a max_ack_delay, so
      // its claim cannot be held to one.
      delay = (std::min)(delay, max_ack_delay);
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

  // Section 9.4 of RFC 9000: a new path is a different network, and an
  // estimate built from the old one describes nothing about it.
  void reset()
  {
    *this = rtt_estimator_t{};
  }

  // Section 6.2.1, without the max_ack_delay term: that is added only for the
  // application space, and only once the handshake is confirmed.
  [[nodiscard]] std::chrono::nanoseconds pto_base() const
  {
    return _smoothed + (std::max)(_variation * 4, loss_granularity);
  }

  // Section 6.1.2.
  [[nodiscard]] std::chrono::nanoseconds loss_delay() const
  {
    const auto base = (std::max)(_latest, _smoothed);
    const auto scaled = (base * loss_time_threshold_numerator) / loss_time_threshold_denominator;
    return (std::max)(scaled, loss_granularity);
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
  // NEW_CONNECTION_ID and RETIRE_CONNECTION_ID: which connection ID, since
  // section 13.3 has both retransmitted carrying the same sequence number.
  std::uint64_t sequence = 0;
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

// The packets a space still has outstanding.
//
// Packet numbers are handed out in order and never reused, so this is a sorted
// sequence by construction and there is nothing for a tree to order. What a
// tree did buy was cheap removal from the middle, which acknowledgement needs:
// an ACK frame names ranges, and the packets it covers can be anywhere in the
// window. So removal marks the slot dead and the storage is compacted when the
// dead outnumber the living -- O(1) per removal, amortised O(1) per packet
// overall, and one allocation per growth instead of one per packet sent.
//
// The gain is not really the allocation. It is that acknowledgement and loss
// detection both walk the whole window, and walking a contiguous array is a
// different thing from chasing a pointer per packet.
class sent_packets_t
{
public:
  void insert(std::uint64_t number, sent_packet_t packet)
  {
    if (_entries.empty() || number > _entries.back().number)
    {
      _entries.push_back(entry_t{.number = number, .packet = std::move(packet), .live = true});
      ++_live;
      return;
    }
    // Out of order, which a sender does not do to itself. Kept correct rather
    // than fast: find the slot and replace it.
    const auto found = std::lower_bound(_entries.begin(), _entries.end(), number, [](const entry_t &entry, std::uint64_t value) { return entry.number < value; });
    if (found != _entries.end() && found->number == number)
    {
      if (!found->live)
      {
        ++_live;
      }
      found->packet = std::move(packet);
      found->live = true;
      return;
    }
    _entries.insert(found, entry_t{.number = number, .packet = std::move(packet), .live = true});
    ++_live;
  }

  [[nodiscard]] bool contains(std::uint64_t number) const
  {
    const auto found = std::lower_bound(_entries.begin(), _entries.end(), number, [](const entry_t &entry, std::uint64_t value) { return entry.number < value; });
    return found != _entries.end() && found->number == number && found->live;
  }

  [[nodiscard]] bool empty() const
  {
    return _live == 0;
  }

  [[nodiscard]] std::size_t size() const
  {
    return _live;
  }

  void clear()
  {
    _entries.clear();
    _live = 0;
  }

  // Slots, not packets: a walk runs over these and asks live() about each.
  [[nodiscard]] std::size_t slots() const
  {
    return _entries.size();
  }

  [[nodiscard]] bool live(std::size_t index) const
  {
    return _entries[index].live;
  }

  [[nodiscard]] std::uint64_t number_at(std::size_t index) const
  {
    return _entries[index].number;
  }

  [[nodiscard]] sent_packet_t &at(std::size_t index)
  {
    return _entries[index].packet;
  }

  [[nodiscard]] const sent_packet_t &at(std::size_t index) const
  {
    return _entries[index].packet;
  }

  void remove(std::size_t index)
  {
    if (!_entries[index].live)
    {
      return;
    }
    _entries[index].live = false;
    --_live;
  }

  // Called once a walk has finished rather than per removal, so a pass that
  // acknowledges half the window costs one move of the survivors instead of
  // one per packet.
  void compact()
  {
    if (_live * 2 >= _entries.size())
    {
      return;
    }
    _entries.erase(std::remove_if(_entries.begin(), _entries.end(), [](const entry_t &entry) { return !entry.live; }), _entries.end());
  }

private:
  struct entry_t
  {
    std::uint64_t number = 0;
    sent_packet_t packet;
    bool live = false;
  };

  std::vector<entry_t> _entries;
  std::size_t _live = 0;
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
  // Section 13.1 of RFC 9000: acknowledging a packet that was never sent is a
  // PROTOCOL_VIOLATION. It is also the shape a confused or hostile peer takes,
  // so the caller is told rather than left to notice the numbers drifting.
  bool acknowledged_unsent = false;
  // Section 19.3.1: a range that computes a packet number below zero is a
  // FRAME_ENCODING_ERROR. Absorbing it silently would let a peer move this
  // endpoint's largest-acknowledged forward with a frame that acknowledges
  // nothing, which drives loss detection off a number the peer invented.
  bool malformed = false;
};

// What the loss detection timer expiring turned out to mean. Exactly one of
// the two spaces is set: either packets have been declared lost and want
// repairing, or a probe is owed in a space that has gone quiet.
struct timeout_outcome_t
{
  std::optional<pn_space_t> loss_space;
  std::optional<pn_space_t> probe_space;
  std::vector<sent_packet_t> lost;
};

class loss_recovery_t
{
public:
  struct ack_span_t
  {
    std::uint64_t smallest = 0;
    std::uint64_t largest = 0;
  };

  void on_packet_sent(pn_space_t space, sent_packet_t packet)
  {
    auto &state = _spaces[pn_space_to_index(space)];
    if (state.discarded)
    {
      return;
    }
    state.largest_sent = state.has_sent ? (std::max)(state.largest_sent, packet.packet_number) : packet.packet_number;
    state.has_sent = true;
    if (packet.in_flight)
    {
      _bytes_in_flight += packet.size;
    }
    if (packet.ack_eliciting)
    {
      state.time_of_last_ack_eliciting = packet.time_sent;
      state.has_ack_eliciting_sent = true;
      ++_ack_eliciting_in_flight;
    }
    const auto number = packet.packet_number;
    state.sent.insert(number, std::move(packet));
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

    if (!state.has_sent || ack.largest_acknowledged > state.largest_sent)
    {
      outcome.acknowledged_unsent = true;
      return outcome;
    }

    // Decoded before anything is believed: a frame whose ranges do not add up
    // must not be allowed to move largest_acked.
    bool well_formed = true;
    decode_ack_spans(ack, _ack_spans, well_formed);
    const auto &spans = _ack_spans;
    if (!well_formed)
    {
      outcome.malformed = true;
      return outcome;
    }

    const bool largest_was_unacked = state.sent.contains(ack.largest_acknowledged);
    if (!state.has_largest_acked || ack.largest_acknowledged > state.largest_acked)
    {
      state.largest_acked = ack.largest_acknowledged;
      state.has_largest_acked = true;
    }

    // Walk what was actually sent, not the numbers the frame names. A single
    // ACK frame may legitimately describe up to 2^62 packet numbers in twenty
    // bytes, so iterating the number space is a hang the peer chooses; the
    // packets in flight are bounded by the congestion window.
    bool acked_ack_eliciting = false;
    for (std::size_t index = 0; index < state.sent.slots(); ++index)
    {
      if (!state.sent.live(index) || !covered(spans, state.sent.number_at(index)))
      {
        continue;
      }
      auto &packet = state.sent.at(index);
      if (packet.in_flight)
      {
        _bytes_in_flight -= (std::min)(_bytes_in_flight, packet.size);
      }
      if (packet.ack_eliciting)
      {
        acked_ack_eliciting = true;
        --_ack_eliciting_in_flight;
      }
      outcome.acknowledged.push_back(std::move(packet));
      state.sent.remove(index);
    }
    state.sent.compact();

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
        const auto delay = std::chrono::microseconds(static_cast<std::int64_t>((std::min<std::uint64_t>)(scale, (std::numeric_limits<std::int64_t>::max)())));
        // Section 5.3: the application space is the only one whose ACK delay
        // is bounded by max_ack_delay, and only after confirmation.
        _rtt.on_rtt_sample(now - packet.time_sent, delay, context.handshake_confirmed && space == pn_space_t::application, context.max_ack_delay);
        if (!_first_rtt_sample.has_value())
        {
          _first_rtt_sample = now;
        }
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

    for (std::size_t index = 0; index < state.sent.slots(); ++index)
    {
      if (!state.sent.live(index))
      {
        continue;
      }
      const auto number = state.sent.number_at(index);
      if (number > state.largest_acked)
      {
        continue;
      }
      auto &packet = state.sent.at(index);
      const bool by_time = packet.time_sent <= lost_send_time;
      const bool by_order = state.largest_acked >= number + loss_packet_threshold;
      if (by_time || by_order)
      {
        if (packet.in_flight)
        {
          _bytes_in_flight -= (std::min)(_bytes_in_flight, packet.size);
        }
        if (packet.ack_eliciting)
        {
          --_ack_eliciting_in_flight;
        }
        lost.push_back(std::move(packet));
        state.sent.remove(index);
        continue;
      }
      // Not lost yet, but it will be if nothing acknowledges it: remember the
      // earliest moment that becomes true so a timer can be set for it.
      const auto when = packet.time_sent + delay;
      state.loss_time = state.loss_time.has_value() ? (std::min)(*state.loss_time, when) : when;
    }
    state.sent.compact();
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

  // Appendix A.9.
  [[nodiscard]] timeout_outcome_t on_loss_detection_timeout(tick_t now, const recovery_context_t &context)
  {
    timeout_outcome_t outcome;
    if (auto space = earliest_loss_space(); space.has_value())
    {
      outcome.loss_space = space;
      outcome.lost = detect_lost_packets(*space, now);
      return outcome;
    }
    ++_pto_count;
    outcome.probe_space = loss_detection_space(now, context);
    return outcome;
  }

  // Appendix A.11: the packets go, the RTT estimate stays. It described the
  // path, and the path has not changed.
  void discard_space(pn_space_t space)
  {
    auto &state = _spaces[pn_space_to_index(space)];
    for (std::size_t index = 0; index < state.sent.slots(); ++index)
    {
      if (!state.sent.live(index))
      {
        continue;
      }
      const auto &packet = state.sent.at(index);
      if (packet.in_flight)
      {
        _bytes_in_flight -= (std::min)(_bytes_in_flight, packet.size);
      }
      if (packet.ack_eliciting)
      {
        --_ack_eliciting_in_flight;
      }
    }
    state = space_state_t{};
    state.discarded = true;
    _pto_count = 0;
  }

  void reset_rtt()
  {
    _rtt.reset();
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

  // When the first round trip measurement arrived. Section 7.6.2 forbids
  // declaring persistent congestion before there is one, because until then
  // the PTO is armed from a guess.
  [[nodiscard]] std::optional<tick_t> first_rtt_sample() const
  {
    return _first_rtt_sample;
  }

  // Kept as a count rather than discovered by walking. This sits on the
  // poll_send path via the PTO calculation, so scanning every packet in flight
  // made sending cost a pass over the congestion window each time.
  [[nodiscard]] bool ack_eliciting_in_flight() const
  {
    return _ack_eliciting_in_flight > 0;
  }

  [[nodiscard]] std::size_t unacknowledged(pn_space_t space) const
  {
    return _spaces[pn_space_to_index(space)].sent.size();
  }

  // What is still outstanding in a space, oldest first. Section 6.2.4 says a
  // probe should carry data rather than a bare PING when there is any, and
  // for a handshake that is the difference between recovering and deadlocking:
  // a PING tells the peer nothing it needs.
  [[nodiscard]] std::vector<sent_frame_t> unacknowledged_frames(pn_space_t space) const
  {
    std::vector<sent_frame_t> out;
    const auto &sent = _spaces[pn_space_to_index(space)].sent;
    for (std::size_t index = 0; index < sent.slots(); ++index)
    {
      if (!sent.live(index))
      {
        continue;
      }
      const auto &frames = sent.at(index).frames;
      out.insert(out.end(), frames.begin(), frames.end());
    }
    return out;
  }

private:
  struct space_state_t
  {
    sent_packets_t sent;
    std::uint64_t largest_acked = 0;
    bool has_largest_acked = false;
    std::optional<tick_t> loss_time;
    tick_t time_of_last_ack_eliciting;
    std::uint64_t largest_sent = 0;
    bool has_sent = false;
    bool has_ack_eliciting_sent = false;
    bool discarded = false;
  };

  // The ranges an ACK frame names, as intervals rather than as the numbers
  // inside them. There are at most as many as the frame had room to encode,
  // which the frame codec already bounded against the packet.
  // Fills a caller-owned buffer rather than returning one: this is on the
  // receive path of every ACK, and the buffer is the same shape every time.
  static void decode_ack_spans(const frame_t &ack, std::vector<ack_span_t> &spans, bool &well_formed)
  {
    well_formed = true;
    spans.clear();
    if (ack.first_ack_range > ack.largest_acknowledged)
    {
      well_formed = false;
      return;
    }
    std::uint64_t largest = ack.largest_acknowledged;
    std::uint64_t smallest = largest - ack.first_ack_range;
    spans.push_back(ack_span_t{.smallest = smallest, .largest = largest});

    ack_range_reader_t reader(ack.ack_ranges);
    while (auto range = reader.next())
    {
      // Section 19.3.1: largest = previous_smallest - gap - 2. A computed
      // number below zero is malformed, and the walk stops rather than
      // wrapping around into a range that acknowledges everything.
      if (smallest < range->gap + 2)
      {
        well_formed = false;
        break;
      }
      largest = smallest - range->gap - 2;
      if (range->length > largest)
      {
        well_formed = false;
        break;
      }
      smallest = largest - range->length;
      spans.push_back(ack_span_t{.smallest = smallest, .largest = largest});
    }
    // Descending on the wire; ascending is easier to search.
    std::reverse(spans.begin(), spans.end());
  }

  [[nodiscard]] static bool covered(const std::vector<ack_span_t> &spans, std::uint64_t number)
  {
    auto after = std::upper_bound(spans.begin(), spans.end(), number, [](std::uint64_t value, const ack_span_t &span) { return value < span.smallest; });
    if (after == spans.begin())
    {
      return false;
    }
    return number <= std::prev(after)->largest;
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
      earliest = earliest.has_value() ? (std::min)(*earliest, *state.loss_time) : *state.loss_time;
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
    auto duration = _rtt.pto_base() * (std::int64_t{1} << (std::min<std::uint64_t>)(_pto_count, 20));

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
      for (std::size_t index = 0; index < state.sent.slots() && !eliciting; ++index)
      {
        eliciting = state.sent.live(index) && state.sent.at(index).ack_eliciting;
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
        space_duration += context.max_ack_delay * (std::int64_t{1} << (std::min<std::uint64_t>)(_pto_count, 20));
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
  // Reused across acknowledgements so the receive path does not allocate.
  std::vector<ack_span_t> _ack_spans;
  std::size_t _bytes_in_flight = 0;
  std::size_t _ack_eliciting_in_flight = 0;
  std::uint64_t _pto_count = 0;
  std::optional<tick_t> _first_rtt_sample;
};
} // namespace vio::quic
