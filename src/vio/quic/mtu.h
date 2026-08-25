/*
Copyright vio contributors.

Path MTU discovery, RFC 8899 as QUIC applies it in RFC 9000 section 14.3.
*/

#ifndef VIO_QUIC_MTU_H
#define VIO_QUIC_MTU_H

#include <cstddef>
#include <chrono>
#include <cstdint>
#include <optional>

#include <vio/tick.h>

namespace vio::quic
{

// Section 14: every path is required to carry this much, so it is where a
// connection starts and the floor it can always fall back to.
inline constexpr std::size_t smallest_maximum_datagram_size = 1200;

// A 1500 byte link less the larger of the two IP headers and UDP. Probing
// beyond it is possible but rarely rewarded, and the search is cheaper for
// having a sensible ceiling.
inline constexpr std::size_t common_path_datagram_size = 1452;

// Section 14.3 leaves the search to the implementation. This is a binary
// search between what is known to work and what is known not to: each probe is
// a PING padded to the candidate size, which either arrives -- and is
// acknowledged, raising the floor -- or does not, lowering the ceiling. It
// converges in about five probes over the range above, and every packet that is
// not a probe keeps using the size already validated, so a failed search costs
// nothing but the probes.
class mtu_discovery_t
{
public:
  // How many times one candidate is tried before the path is taken to have
  // refused it. Probes are unreliable by design -- they are the largest thing
  // on the path -- so a single loss is not an answer.
  static constexpr int attempts_per_candidate = 3;
  // Below this the remaining range is not worth a round trip.
  static constexpr std::size_t granularity = 16;
  // Consecutive timeouts at a validated size that mean the path stopped
  // carrying it. Section 14.3 asks that this be noticed rather than left to
  // stall the connection.
  static constexpr int timeouts_before_retreat = 3;
  // RFC 8899 section 5.1.1, PROBE_TIMER. A probe the path swallowed is not
  // acknowledged and, on a connection with nothing else outstanding, is never
  // declared lost either -- there is no later acknowledgement to reveal the
  // gap. Without a deadline of its own the search would wait on it forever.
  static constexpr std::chrono::milliseconds probe_timeout{1000};

  void configure(std::size_t floor, std::size_t ceiling)
  {
    _floor = floor < smallest_maximum_datagram_size ? smallest_maximum_datagram_size : floor;
    _validated = _floor;
    _ceiling = ceiling < _floor ? _floor : ceiling;
    _candidate = 0;
    _outstanding.reset();
    _deadline.reset();
    _attempts = 0;
    _timeouts = 0;
    _refused = false;
    _enabled = false;
  }

  // The peer's max_udp_payload_size is a promise about what it will read, so it
  // bounds the search from above however large the path turns out to be.
  void limit(std::size_t ceiling)
  {
    if (ceiling < _ceiling)
    {
      _ceiling = ceiling < _validated ? _validated : ceiling;
    }
  }

  // Searching starts once the handshake is confirmed: before that the packets
  // that matter are the handshake's own, and a probe would only compete with
  // them for a window that is still tiny.
  void enable()
  {
    _enabled = true;
  }

  [[nodiscard]] std::size_t datagram_size() const
  {
    return _validated;
  }

  [[nodiscard]] bool searching() const
  {
    return _enabled && _ceiling - _validated >= granularity;
  }

  [[nodiscard]] bool wants_probe() const
  {
    return searching() && !_outstanding.has_value();
  }

  // Optimistic first, then bisecting. Most paths carry the ceiling, and asking
  // for it outright reaches it in one round trip where a bisection from the
  // floor takes five -- which matters because the window is doubling while the
  // search runs, and a size arrived at after slow start has ended has missed
  // the part of the transfer it would have helped most. Once something has
  // actually been refused there is a real upper bound to bisect against, and
  // the search becomes the ordinary one.
  [[nodiscard]] std::size_t probe_size() const
  {
    if (!_refused)
    {
      return _ceiling;
    }
    return _validated + ((_ceiling - _validated + 1) / 2);
  }

  void on_probe_sent(std::uint64_t packet_number, std::size_t size, tick_t now, std::chrono::nanoseconds smoothed_rtt)
  {
    _outstanding = packet_number;
    _candidate = size;
    const auto wait = (std::max<std::chrono::nanoseconds>)(probe_timeout, smoothed_rtt * 3);
    _deadline = now + wait;
  }

  // When the outstanding probe stops being worth waiting for.
  [[nodiscard]] std::optional<tick_t> probe_deadline() const
  {
    return _outstanding.has_value() ? _deadline : std::nullopt;
  }

  // Treats an unconfirmed probe as refused once its deadline passes, so a path
  // that silently swallows the size cannot stall the search.
  void expire(tick_t now)
  {
    if (!_outstanding.has_value() || !_deadline.has_value() || now < *_deadline)
    {
      return;
    }
    on_lost(*_outstanding);
  }

  [[nodiscard]] bool is_probe(std::uint64_t packet_number) const
  {
    return _outstanding.has_value() && *_outstanding == packet_number;
  }

  void on_acked(std::uint64_t packet_number)
  {
    if (!is_probe(packet_number))
    {
      // Anything acknowledged at the current size says the path still carries
      // it, which is what the retreat below is watching for.
      _timeouts = 0;
      return;
    }
    _validated = _candidate;
    _outstanding.reset();
    _attempts = 0;
    _timeouts = 0;
  }

  void on_lost(std::uint64_t packet_number)
  {
    if (!is_probe(packet_number))
    {
      return;
    }
    _outstanding.reset();
    // The optimistic first guess is disproved by a single loss. It is the
    // largest thing the path will ever be asked for and there is a bisection
    // waiting behind it, so spending three round trips to confirm what the
    // fallback would find anyway only delays the size that does work. Once
    // bisecting, a candidate is worth retrying: there the loss is as likely to
    // have been ordinary as to have been the size.
    const int allowed = _refused ? attempts_per_candidate : 1;
    if (++_attempts < allowed)
    {
      return;
    }
    // Taken as a refusal. Everything above the candidate is refused with it.
    _ceiling = _candidate > _floor ? _candidate - 1 : _floor;
    _attempts = 0;
    _refused = true;
  }

  // A timeout with nothing acknowledged. Section 14.3: a path that quietly
  // stops carrying the size in use will otherwise stall the connection until it
  // times out, so after a few of these the connection goes back to the size
  // every path is required to carry and stops searching.
  void on_timeout()
  {
    if (_validated == _floor)
    {
      return;
    }
    if (++_timeouts < timeouts_before_retreat)
    {
      return;
    }
    _ceiling = _validated > _floor ? _validated - 1 : _floor;
    _validated = _floor;
    _outstanding.reset();
    _attempts = 0;
    _timeouts = 0;
  }

private:
  std::size_t _floor = smallest_maximum_datagram_size;
  std::size_t _validated = smallest_maximum_datagram_size;
  std::size_t _ceiling = smallest_maximum_datagram_size;
  std::size_t _candidate = 0;
  std::optional<std::uint64_t> _outstanding;
  std::optional<tick_t> _deadline;
  int _attempts = 0;
  int _timeouts = 0;
  // Whether the path has turned anything down yet, which is what turns the
  // optimistic first guess into a bisection.
  bool _refused = false;
  bool _enabled = false;
};

} // namespace vio::quic

#endif
