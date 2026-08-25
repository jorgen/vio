/*
Copyright vio contributors.

Delivery rate estimation, after draft-cheng-iccrg-delivery-rate-estimation.
*/

#ifndef VIO_QUIC_DELIVERY_RATE_H
#define VIO_QUIC_DELIVERY_RATE_H

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>

#include <vio/tick.h>

namespace vio::quic
{

// How fast the path is actually delivering, which is not something the
// congestion window can be asked. The window says how much may be outstanding;
// whether those bytes are moving or sitting in a queue is exactly the thing a
// window-based controller cannot see, and it is why slow start has to double
// blindly to find the operating point rather than being told where it is.
//
// The method is the one BBR uses. Every packet carries a stamp of what had been
// delivered when it was sent; acknowledging it says how much arrived in the
// interval since, and dividing gives a rate. The subtlety is which interval:
// the time the acknowledgements took to come back, or the time the packets took
// to go out. Taking the larger of the two is what keeps a sender that dribbled
// its packets out slowly -- or one whose acknowledgements were bunched up by
// the path -- from reading back a rate the path never carried.
// The maximum of what has been seen recently, kept without keeping the samples.
// Three estimates are held -- the best, and the best of the window's later
// parts -- so that when the best expires there is already a successor measured
// over the interval since, and the filter does not have to fall back to whatever
// the next sample happens to be. Nichols' algorithm, as BBR uses it.
template <typename value_t, typename time_t_>
class windowed_max_t
{
public:
  explicit windowed_max_t(time_t_ window)
    : _window(window)
  {
  }

  void update(value_t sample, time_t_ now)
  {
    if (_estimates[0].value == value_t{} || sample >= _estimates[0].value || now - _estimates[2].when > _window)
    {
      reset(sample, now);
      return;
    }
    if (sample >= _estimates[1].value)
    {
      _estimates[1] = entry_t{sample, now};
      _estimates[2] = _estimates[1];
    }
    else if (sample >= _estimates[2].value)
    {
      _estimates[2] = entry_t{sample, now};
    }

    if (now - _estimates[0].when > _window)
    {
      // The best has aged out; the successors are already measured over later
      // parts of the window, which is what they are for.
      _estimates[0] = _estimates[1];
      _estimates[1] = _estimates[2];
      _estimates[2] = entry_t{sample, now};
      if (now - _estimates[0].when > _window)
      {
        _estimates[0] = _estimates[1];
        _estimates[1] = _estimates[2];
      }
      return;
    }
    if (_estimates[1].value == _estimates[0].value && now - _estimates[1].when > _window / 4)
    {
      _estimates[2] = _estimates[1] = entry_t{sample, now};
    }
  }

  [[nodiscard]] value_t get() const
  {
    return _estimates[0].value;
  }

  void reset(value_t sample, time_t_ now)
  {
    _estimates[0] = _estimates[1] = _estimates[2] = entry_t{sample, now};
  }

private:
  struct entry_t
  {
    value_t value{};
    time_t_ when{};
  };
  time_t_ _window{};
  entry_t _estimates[3];
};

class delivery_rate_estimator_t
{
public:
  // How long a bandwidth sample stays in the running, in round trips. Long
  // enough to survive a few rounds of a sender that had nothing to send, short
  // enough that a path which genuinely slowed down is believed.
  static constexpr std::uint64_t bandwidth_window_rounds = 10;

  // What a packet remembers about delivery at the moment it was sent. Rides on
  // the sent packet and comes back when it is acknowledged.
  struct stamp_t
  {
    std::uint64_t delivered = 0;
    tick_t delivered_time;
    tick_t first_sent_time;
    bool app_limited = false;
  };

  struct sample_t
  {
    // Bytes per second.
    std::uint64_t rate = 0;
    std::uint64_t delivered = 0;
    std::chrono::nanoseconds interval{0};
    // Whether the sender, rather than the path, was what limited this sample.
    // A rate measured while there was nothing to send is a measure of the
    // application and says nothing about the path.
    bool app_limited = false;
  };

  // A connection with nothing outstanding has an idle period behind it that is
  // not part of any delivery interval, so the clock restarts here.
  [[nodiscard]] stamp_t on_packet_sent(tick_t now, bool nothing_in_flight, std::uint64_t packet_number)
  {
    if (nothing_in_flight)
    {
      _first_sent_time = now;
      _delivered_time = now;
    }
    _last_sent = packet_number;
    _have_last_sent = true;
    return stamp_t{.delivered = _delivered, .delivered_time = _delivered_time, .first_sent_time = _first_sent_time, .app_limited = _app_limited};
  }

  // One acknowledged packet. The newest of a batch is the one that carries the
  // interval, which is why this keeps the largest rather than the last.
  void on_packet_acked(const stamp_t &stamp, tick_t sent_time, std::size_t size, tick_t now, std::uint64_t packet_number)
  {
    _delivered += size;
    _delivered_time = now;

    // A round trip has passed once something sent after the last one began is
    // acknowledged. This is what the bandwidth filter's window is measured in:
    // round trips describe a path, where wall clock describes the machine.
    if (_have_round_end && packet_number > _round_end)
    {
      ++_round;
      _round_end = _have_last_sent ? _last_sent : packet_number;
    }
    else if (!_have_round_end)
    {
      _have_round_end = true;
      _round_end = _have_last_sent ? _last_sent : packet_number;
    }

    // The phase ends when something sent after it began comes back, rather
    // than when the sender happens to have data again: everything sent while
    // the application was the limit has to be marked, or a sample spanning the
    // boundary is read as a statement about the path.
    if (_app_limited && _have_app_limited_end && packet_number > _app_limited_end)
    {
      _app_limited = false;
    }

    if (_have_prior && stamp.delivered <= _prior_delivered)
    {
      return;
    }
    _have_prior = true;
    _prior_delivered = stamp.delivered;
    _app_limited_sample = stamp.app_limited;
    _send_elapsed = sent_time - stamp.first_sent_time;
    _ack_elapsed = _delivered_time - stamp.delivered_time;
    _first_sent_time = sent_time;
  }

  // The rate this batch of acknowledgements measured, if it measured one. An
  // interval shorter than a round trip is not a measurement of the path -- it
  // is a measurement of one burst arriving -- so it is refused rather than
  // reported as an enormous rate.
  [[nodiscard]] std::optional<sample_t> take(std::chrono::nanoseconds min_rtt)
  {
    if (!_have_prior)
    {
      return std::nullopt;
    }
    _have_prior = false;

    const auto interval = (std::max)(_send_elapsed, _ack_elapsed);
    if (interval <= std::chrono::nanoseconds::zero() || interval < min_rtt)
    {
      return std::nullopt;
    }
    if (_delivered <= _prior_delivered)
    {
      return std::nullopt;
    }

    sample_t sample;
    sample.delivered = _delivered - _prior_delivered;
    sample.interval = interval;
    sample.app_limited = _app_limited_sample;
    // Bytes times a billion stays inside 64 bits for any sample a connection
    // could actually produce: it would take eighteen gigabytes acknowledged in
    // one batch to overflow, which is more than a window can hold.
    sample.rate = (sample.delivered * 1000000000ULL) / static_cast<std::uint64_t>(interval.count());

    // A rate the application produced is a floor on what the path can carry,
    // never a statement about its ceiling, so it does not raise the peak.
    if (!sample.app_limited)
    {
      _bandwidth.update(sample.rate, _round);
    }
    return sample;
  }

  // The fastest the path has been seen to deliver recently, in bytes per
  // second. Recently rather than ever: a path that slows down has to be
  // believed, and an all-time maximum never is.
  [[nodiscard]] std::uint64_t peak() const
  {
    return _bandwidth.get();
  }

  [[nodiscard]] std::uint64_t round() const
  {
    return _round;
  }

  [[nodiscard]] std::uint64_t delivered() const
  {
    return _delivered;
  }

  // Whether the sender is currently the limit rather than the path. Set when
  // there is window to spare and nothing to put in it.
  void set_app_limited(bool limited)
  {
    if (!limited)
    {
      _app_limited = false;
      return;
    }
    _app_limited = true;
    _have_app_limited_end = _have_last_sent;
    _app_limited_end = _last_sent;
  }

  [[nodiscard]] bool app_limited() const
  {
    return _app_limited;
  }

  // Section 9.4: everything measured belongs to the path that measured it.
  void reset()
  {
    *this = delivery_rate_estimator_t{};
  }

private:
  std::uint64_t _delivered = 0;
  tick_t _delivered_time;
  tick_t _first_sent_time;
  bool _app_limited = false;

  windowed_max_t<std::uint64_t, std::uint64_t> _bandwidth{bandwidth_window_rounds};
  std::uint64_t _round = 0;
  std::uint64_t _round_end = 0;
  bool _have_round_end = false;
  std::uint64_t _last_sent = 0;
  bool _have_last_sent = false;
  std::uint64_t _app_limited_end = 0;
  bool _have_app_limited_end = false;

  // The pending sample, filled in as a batch of acknowledgements is processed
  // and read out once at the end of it.
  bool _have_prior = false;
  std::uint64_t _prior_delivered = 0;
  std::chrono::nanoseconds _send_elapsed{0};
  std::chrono::nanoseconds _ack_elapsed{0};
  bool _app_limited_sample = false;
};

} // namespace vio::quic

#endif
