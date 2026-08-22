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

// RFC 9000 section 8.2, path validation: proving that whoever is sending from
// an address can also receive at it.
//
// This is the mechanism only. What it is used *for* -- deciding to migrate,
// deciding a path is dead -- is policy, and lives in the connection. Keeping
// them apart matters because the same exchange serves three purposes that want
// different answers: validating a peer's new address after migration, checking
// a quiet peer is still there, and probing a path's MTU.
//
// Two rules shape the design:
//
//   The data must be unpredictable (section 8.2.1), because the echo is the
//   only evidence. Anything guessable lets an off-path attacker answer a
//   challenge it never received and claim an address it does not hold.
//
//   A response validates the path the *challenge* was sent on, no matter which
//   path it arrives by (section 8.2.3), and every challenge sent carries fresh
//   data (section 13.3). So an outstanding challenge is not one value but a
//   small set, and any of them matching is success.

#include "vio/crypto.h"
#include "vio/error.h"
#include "vio/tick.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <vector>

namespace vio::quic
{
inline constexpr std::size_t path_challenge_data_size = 8;
using path_challenge_data_t = std::array<std::uint8_t, path_challenge_data_size>;

enum class path_state_t : std::uint8_t
{
  // Nothing has been asked of this path.
  unknown,
  // A challenge is outstanding.
  validating,
  validated,
  // Abandoned on the timer of section 8.2.4. Not an error: the path is
  // unusable, which the connection may survive.
  failed,
};

// How many challenge payloads stay eligible for a match. Section 8.2.1 permits
// sending several to survive loss, and each carries different data, so a
// response to any of them is a valid answer. Four covers a handful of PTOs
// without letting a peer that never answers grow the set.
inline constexpr std::size_t max_outstanding_challenges = 4;

class path_validator_t
{
public:
  // Opens an attempt without minting anything. The challenges themselves are
  // issued by the send path, which is the only place that knows a packet is
  // really going out and how much room is left in it; starting the clock here
  // keeps the deadline tied to the decision to probe rather than to whenever
  // the first packet happened to leave.
  void begin(tick_t now, std::chrono::nanoseconds abandon_after)
  {
    if (_state == path_state_t::validating)
    {
      return;
    }
    _state = path_state_t::validating;
    _deadline = now + abandon_after;
    _outstanding.clear();
    _have_last_sent = false;
  }

  // Section 8.2.1. The caller decides when to probe; this only mints the data
  // and records that an answer is owed.
  [[nodiscard]] std::expected<path_challenge_data_t, error_t> issue(tick_t now, std::chrono::nanoseconds abandon_after)
  {
    path_challenge_data_t data = {};
    if (auto r = crypto::random_bytes(data); !r.has_value())
    {
      return std::unexpected(r.error());
    }
    if (_outstanding.size() == max_outstanding_challenges)
    {
      _outstanding.erase(_outstanding.begin());
    }
    _outstanding.push_back(data);
    if (_state != path_state_t::validating)
    {
      // The deadline covers the whole attempt, not each challenge in it, so it
      // is set once when probing starts.
      _state = path_state_t::validating;
      _deadline = now + abandon_after;
    }
    _last_sent = now;
    _have_last_sent = true;
    return data;
  }

  // Section 8.2.3. Returns whether this response completed a validation, so
  // the caller can act on the transition rather than poll for it.
  [[nodiscard]] bool on_response(std::span<const std::uint8_t> data)
  {
    if (data.size() != path_challenge_data_size)
    {
      return false;
    }
    const auto match = std::find_if(_outstanding.begin(), _outstanding.end(), [data](const path_challenge_data_t &sent) { return std::equal(sent.begin(), sent.end(), data.begin()); });
    if (match == _outstanding.end())
    {
      // Unsolicited, or an echo of a challenge already retired. Section 8.2.3
      // makes this a non-event rather than an error: an endpoint has no way to
      // tell a stale echo from a forged one, and neither is worth a close.
      return false;
    }
    _outstanding.clear();
    _have_last_sent = false;
    if (_state == path_state_t::validated)
    {
      return false;
    }
    _state = path_state_t::validated;
    return true;
  }

  // Section 8.2.4. Abandoning is the only way validation fails.
  void on_timeout(tick_t now)
  {
    if (_state == path_state_t::validating && now >= _deadline)
    {
      _state = path_state_t::failed;
      _outstanding.clear();
      _have_last_sent = false;
    }
  }

  // Whether another PATH_CHALLENGE is due. Section 8.2.1 asks that a path be
  // probed no more often than an Initial would be retried, so the caller
  // passes the current PTO and gets back whether that long has passed.
  [[nodiscard]] bool challenge_due(tick_t now, std::chrono::nanoseconds interval) const
  {
    if (_state != path_state_t::validating)
    {
      return false;
    }
    return !_have_last_sent || now >= _last_sent + interval;
  }

  [[nodiscard]] std::optional<tick_t> deadline() const
  {
    if (_state != path_state_t::validating)
    {
      return std::nullopt;
    }
    return _deadline;
  }

  [[nodiscard]] path_state_t state() const
  {
    return _state;
  }

  [[nodiscard]] bool validating() const
  {
    return _state == path_state_t::validating;
  }

  // Used when a path is adopted through some other proof, and to re-arm a
  // validator that is being pointed at a new address.
  void reset()
  {
    _state = path_state_t::unknown;
    _outstanding.clear();
    _have_last_sent = false;
  }

  void mark_validated()
  {
    _state = path_state_t::validated;
    _outstanding.clear();
    _have_last_sent = false;
  }

private:
  std::vector<path_challenge_data_t> _outstanding;
  path_state_t _state = path_state_t::unknown;
  tick_t _deadline;
  tick_t _last_sent;
  bool _have_last_sent = false;
};

// Section 8.2.2: an endpoint MUST echo the data of every PATH_CHALLENGE it
// receives, and MUST NOT answer one challenge twice.
//
// The queue is bounded because a peer can produce challenges faster than this
// endpoint produces packets, and an unbounded echo buffer is a peer-controlled
// allocation. Dropping is safe in a way that most dropping is not: section
// 13.3 says the peer re-challenges when no response arrives, so a dropped
// entry costs a round trip and nothing else. The newest is kept in preference
// to the oldest, since an old challenge is the one most likely to have been
// re-sent already.
inline constexpr std::size_t max_queued_path_responses = 4;

class path_response_queue_t
{
public:
  void push(std::span<const std::uint8_t> data)
  {
    if (data.size() != path_challenge_data_size)
    {
      return;
    }
    path_challenge_data_t entry = {};
    std::copy(data.begin(), data.end(), entry.begin());
    if (_pending.size() == max_queued_path_responses)
    {
      _pending.erase(_pending.begin());
    }
    _pending.push_back(entry);
  }

  [[nodiscard]] bool empty() const
  {
    return _pending.empty();
  }

  [[nodiscard]] const path_challenge_data_t &front() const
  {
    return _pending.front();
  }

  void pop()
  {
    _pending.erase(_pending.begin());
  }

private:
  std::vector<path_challenge_data_t> _pending;
};
} // namespace vio::quic
