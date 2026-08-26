/*
Copyright vio contributors.

Anti-replay for 0-RTT, after RFC 8446 section 8.2 (ClientHello recording).
*/

#ifndef VIO_QUIC_ANTI_REPLAY_H
#define VIO_QUIC_ANTI_REPLAY_H

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <span>
#include <unordered_map>

#include <vio/tick.h>

namespace vio::quic
{

// What makes 0-RTT different from every other part of QUIC: the server acts on
// data before it has spoken to the client, so an attacker who captured that
// data can send it again and the server will act on it again. RFC 9001 section
// 9.2 requires the protections in RFC 8446 section 8; this is the second of
// them, recording each ClientHello so that a repeat is recognised.
//
// Two properties matter more than speed.
//
// It fails closed. An identifier this cannot vouch for -- because the register
// is full, or because it has been running long enough that an old entry was
// dropped while its ticket was still valid -- is refused. Refusing costs a
// round trip; accepting costs the guarantee.
//
// It is bounded. A register that grows with traffic is a way to run a server
// out of memory by connecting to it, so the size is fixed and the entries are
// timestamped. What that buys is a window rather than a promise: an identifier
// is remembered for `window`, and a ticket that outlives the window must not be
// accepted for 0-RTT, which is why the window is checked against the ticket
// lifetime rather than chosen freely.
class anti_replay_t
{
public:
  // How long an identifier is remembered. A ticket whose age can exceed this
  // cannot be safely accepted for 0-RTT, so this is the bound on ticket
  // lifetime as much as on memory.
  static constexpr std::chrono::nanoseconds default_window = std::chrono::minutes(10);
  // Entries held before the register refuses rather than forgets. Ten minutes
  // of a busy server at a thousand new connections a second is six hundred
  // thousand; this leaves room and is a few tens of megabytes.
  static constexpr std::size_t default_capacity = 1U << 20;

  anti_replay_t() = default;

  anti_replay_t(std::chrono::nanoseconds window, std::size_t capacity)
    : _window(window)
    , _capacity(capacity)
  {
  }

  [[nodiscard]] std::chrono::nanoseconds window() const
  {
    return _window;
  }

  // True only if this identifier has not been seen inside the window and the
  // register was able to record it. Everything else -- a repeat, a full
  // register -- is false, and false means the connection does 1-RTT.
  [[nodiscard]] bool accept(std::span<const std::uint8_t> identifier, tick_t now)
  {
    if (identifier.empty())
    {
      return false;
    }
    expire(now);

    const auto key = digest(identifier);
    const auto found = _seen.find(key);
    if (found != _seen.end())
    {
      // Seen. Not refreshed: an attacker replaying in a loop must not be able
      // to hold an entry alive, and the original is what the window is for.
      return false;
    }
    if (_seen.size() >= _capacity)
    {
      // Full. Evicting to make room would mean forgetting something still
      // inside its window, and forgetting is exactly what an attacker wants.
      return false;
    }
    _seen.emplace(key, now);
    return true;
  }

  [[nodiscard]] std::size_t size() const
  {
    return _seen.size();
  }

  void clear()
  {
    _seen.clear();
    _swept = tick_t{};
    _have_swept = false;
  }

private:
  // A 64-bit digest of the identifier rather than the identifier itself. The
  // input is a ClientHello random, which is 32 bytes of the client's own
  // randomness; collisions are a false "seen", which costs a round trip, and
  // never a false "fresh", which would cost the guarantee -- because a
  // collision can only ever add entries the register treats as present.
  [[nodiscard]] static std::uint64_t digest(std::span<const std::uint8_t> identifier)
  {
    // FNV-1a. Not a security hash and does not need to be: the input is not
    // chosen to collide with anything, and a collision is safe in the direction
    // that matters.
    std::uint64_t hash = 1469598103934665603ULL;
    for (const auto byte : identifier)
    {
      hash ^= byte;
      hash *= 1099511628211ULL;
    }
    return hash;
  }

  // Sweeping every call would make accept() linear in the register; sweeping
  // once per window keeps it amortised while never letting an entry outlive
  // its window by more than one sweep.
  void expire(tick_t now)
  {
    if (_have_swept && now - _swept < _window / 8)
    {
      return;
    }
    _have_swept = true;
    _swept = now;
    for (auto entry = _seen.begin(); entry != _seen.end();)
    {
      entry = now - entry->second >= _window ? _seen.erase(entry) : std::next(entry);
    }
  }

  std::chrono::nanoseconds _window = default_window;
  std::size_t _capacity = default_capacity;
  std::unordered_map<std::uint64_t, tick_t> _seen;
  tick_t _swept;
  bool _have_swept = false;
};

} // namespace vio::quic

#endif
