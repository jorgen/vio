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

// RFC 9000 section 5.1: the two pools of connection IDs a connection keeps.
//
// They are not symmetric, and conflating them is the easy mistake. One pool is
// the set of IDs this endpoint *issued* and must therefore keep accepting as a
// destination until the peer retires them (section 5.1.1). The other is the set
// the *peer* issued, which this endpoint may put in the packets it sends and
// may retire when it stops using them (section 5.1.2). Each side owns the
// retirement of the other's pool, which is why a RETIRE_CONNECTION_ID names a
// sequence number rather than a value.
//
// Why the pools exist at all: an observer that sees the same connection ID on
// two paths learns those paths belong to the same client. Rotating the ID on
// migration is what stops that, so the peer needs spare IDs *before* it moves
// (section 9.5). A pool that runs dry silently prevents migration.

#include "vio/quic/connection_id.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace vio::quic
{
enum class cid_error_t : std::uint8_t
{
  none,
  // Section 19.15: Retire Prior To above Sequence Number.
  frame_encoding,
  // Section 19.15 and 19.16: a reused sequence number, a retire of something
  // never issued, or a frame that may not be sent at all on this connection.
  protocol_violation,
  // Section 5.1.1: more active IDs than this endpoint advertised it would keep.
  limit_exceeded,
};

struct connection_id_entry_t
{
  std::uint64_t sequence = 0;
  connection_id_t id;
  stateless_reset_token_t token = {};
  // Whether token holds a value the peer actually supplied. The connection ID
  // from the handshake arrives without one -- a server's token for it comes
  // through the transport parameters instead, and a client never sends one at
  // all. Treating the zero-filled placeholder as real would mean any datagram
  // ending in sixteen zero bytes reads as a stateless reset, which is a way
  // for anyone to end the connection.
  bool has_token = false;
};

// Section 5.1.1: what this endpoint issued and must keep accepting.
class local_connection_ids_t
{
public:
  // The one carried in the long header during the handshake, sequence 0.
  void install_initial(const connection_id_t &id, const stateless_reset_token_t &token)
  {
    _entries.clear();
    _entries.push_back(connection_id_entry_t{.sequence = 0, .id = id, .token = token, .has_token = true});
    _next_sequence = 1;
  }

  // Section 5.1.1: an endpoint MUST NOT provide more connection IDs than the
  // peer's limit, counting the ones already active.
  [[nodiscard]] bool can_issue(std::uint64_t peer_limit) const
  {
    // A zero-length connection ID cannot be replaced: every packet toward this
    // endpoint carries no ID at all, so there is nothing to vary.
    if (_entries.empty() || _entries.front().id.empty())
    {
      return false;
    }
    return static_cast<std::uint64_t>(_entries.size()) < peer_limit;
  }

  [[nodiscard]] const connection_id_entry_t &add(const connection_id_t &id, const stateless_reset_token_t &token)
  {
    _entries.push_back(connection_id_entry_t{.sequence = _next_sequence, .id = id, .token = token, .has_token = true});
    ++_next_sequence;
    return _entries.back();
  }

  // Section 19.16. The destination of the packet carrying the frame is passed
  // because retiring the very ID the packet was addressed to is a protocol
  // violation -- it would leave the peer having disowned the only ID it just
  // demonstrated it was using.
  [[nodiscard]] cid_error_t on_retire(std::uint64_t sequence, const connection_id_t &packet_destination)
  {
    if (sequence >= _next_sequence)
    {
      // Retiring something never issued: section 19.16 makes this an error
      // rather than a no-op, because the sequence space is the only thing
      // tying the two pools together.
      return cid_error_t::protocol_violation;
    }
    const auto found = std::find_if(_entries.begin(), _entries.end(), [sequence](const connection_id_entry_t &entry) { return entry.sequence == sequence; });
    if (found == _entries.end())
    {
      // Already retired. Section 19.15 says a repeated frame must not be an
      // error, and a retransmitted RETIRE_CONNECTION_ID looks exactly like
      // this.
      return cid_error_t::none;
    }
    if (found->id == packet_destination)
    {
      return cid_error_t::protocol_violation;
    }
    _entries.erase(found);
    return cid_error_t::none;
  }

  [[nodiscard]] std::span<const connection_id_entry_t> active() const
  {
    return _entries;
  }

  [[nodiscard]] std::uint64_t next_sequence() const
  {
    return _next_sequence;
  }

  [[nodiscard]] const connection_id_entry_t *find(std::uint64_t sequence) const
  {
    const auto found = std::find_if(_entries.begin(), _entries.end(), [sequence](const connection_id_entry_t &entry) { return entry.sequence == sequence; });
    return found == _entries.end() ? nullptr : &*found;
  }

  [[nodiscard]] bool accepts(const connection_id_t &id) const
  {
    return std::any_of(_entries.begin(), _entries.end(), [&id](const connection_id_entry_t &entry) { return entry.id == id; });
  }

private:
  std::vector<connection_id_entry_t> _entries;
  std::uint64_t _next_sequence = 0;
};

// Section 5.1.2: what the peer issued, which this endpoint spends.
class remote_connection_ids_t
{
public:
  void install_initial(const connection_id_t &id)
  {
    _entries.clear();
    _entries.push_back(connection_id_entry_t{.sequence = 0, .id = id, .token = {}});
    _current = 0;
    _have_current = true;
  }

  // Section 19.15. local_limit is this endpoint's own
  // active_connection_id_limit: the peer must not leave more than that many
  // active, and exceeding it is a CONNECTION_ID_LIMIT_ERROR.
  [[nodiscard]] cid_error_t on_new(std::uint64_t sequence, std::uint64_t retire_prior_to, const connection_id_t &id, std::span<const std::uint8_t> token, std::uint64_t local_limit)
  {
    if (retire_prior_to > sequence)
    {
      return cid_error_t::frame_encoding;
    }
    if (token.size() != stateless_reset_token_size)
    {
      return cid_error_t::frame_encoding;
    }

    // A repeat must be harmless (section 19.15), but the same sequence number
    // carrying a different value is the peer contradicting itself.
    const auto existing = std::find_if(_entries.begin(), _entries.end(), [sequence](const connection_id_entry_t &entry) { return entry.sequence == sequence; });
    if (existing != _entries.end())
    {
      if (!(existing->id == id) || !std::equal(existing->token.begin(), existing->token.end(), token.begin()))
      {
        return cid_error_t::protocol_violation;
      }
      return cid_error_t::none;
    }
    // The same value under a second sequence number is the same contradiction
    // seen from the other side.
    if (std::any_of(_entries.begin(), _entries.end(), [&id](const connection_id_entry_t &entry) { return entry.id == id; }))
    {
      return cid_error_t::protocol_violation;
    }

    // Section 19.15: Retire Prior To only ever moves forward, and a smaller
    // value in a later frame is ignored rather than obeyed -- otherwise a
    // reordered frame would resurrect retired IDs.
    if (retire_prior_to > _largest_retire_prior_to)
    {
      _largest_retire_prior_to = retire_prior_to;
      for (auto it = _entries.begin(); it != _entries.end();)
      {
        if (it->sequence < _largest_retire_prior_to)
        {
          retire(it->sequence);
          it = _entries.erase(it);
          continue;
        }
        ++it;
      }
    }

    if (sequence < _largest_retire_prior_to)
    {
      // Section 19.15: an ID that arrives already covered by a Retire Prior To
      // is never added, but must still be retired explicitly so the peer knows
      // it was seen and can stop counting it as active.
      retire(sequence);
      return cid_error_t::none;
    }

    if (_seen_sequences.size() > sequence && _seen_sequences[static_cast<std::size_t>(sequence)])
    {
      // Retired earlier, then retransmitted. Not an error, and not re-added.
      return cid_error_t::none;
    }

    _entries.push_back(connection_id_entry_t{.sequence = sequence, .id = id, .token = {}, .has_token = true});
    std::copy(token.begin(), token.end(), _entries.back().token.begin());
    mark_seen(sequence);

    if (static_cast<std::uint64_t>(_entries.size()) > local_limit)
    {
      return cid_error_t::limit_exceeded;
    }
    return cid_error_t::none;
  }

  // Sequence numbers this endpoint owes the peer a RETIRE_CONNECTION_ID for.
  [[nodiscard]] const std::vector<std::uint64_t> &pending_retires() const
  {
    return _pending_retires;
  }

  void clear_pending_retire(std::uint64_t sequence)
  {
    _pending_retires.erase(std::remove(_pending_retires.begin(), _pending_retires.end(), sequence), _pending_retires.end());
  }

  // Puts one back after the packet carrying it was lost. Section 13.3 lists
  // RETIRE_CONNECTION_ID as retransmitted on loss.
  void requeue_retire(std::uint64_t sequence)
  {
    if (std::find(_pending_retires.begin(), _pending_retires.end(), sequence) == _pending_retires.end())
    {
      _pending_retires.push_back(sequence);
    }
  }

  [[nodiscard]] const connection_id_t *current() const
  {
    const auto found = std::find_if(_entries.begin(), _entries.end(), [this](const connection_id_entry_t &entry) { return entry.sequence == _current; });
    return _have_current && found != _entries.end() ? &found->id : nullptr;
  }

  // Section 9.5: a new path wants an ID that has never been seen on the old
  // one, or the two paths are trivially linkable.
  [[nodiscard]] bool switch_to_unused()
  {
    const auto found = std::find_if(_entries.begin(), _entries.end(), [this](const connection_id_entry_t &entry) { return entry.sequence != _current; });
    if (found == _entries.end())
    {
      return false;
    }
    const auto retiring = _current;
    _current = found->sequence;
    _have_current = true;
    retire(retiring);
    _entries.erase(std::remove_if(_entries.begin(), _entries.end(), [retiring](const connection_id_entry_t &entry) { return entry.sequence == retiring; }), _entries.end());
    return true;
  }

  [[nodiscard]] std::size_t active_count() const
  {
    return _entries.size();
  }

  [[nodiscard]] bool has_unused() const
  {
    return std::any_of(_entries.begin(), _entries.end(), [this](const connection_id_entry_t &entry) { return entry.sequence != _current; });
  }

  [[nodiscard]] std::span<const connection_id_entry_t> active() const
  {
    return _entries;
  }

private:
  void retire(std::uint64_t sequence)
  {
    mark_seen(sequence);
    if (std::find(_pending_retires.begin(), _pending_retires.end(), sequence) == _pending_retires.end())
    {
      _pending_retires.push_back(sequence);
    }
  }

  void mark_seen(std::uint64_t sequence)
  {
    // Bounded by the peer's own issuance, which the limit check above caps;
    // the vector only ever grows to the largest sequence number accepted.
    if (sequence > max_tracked_sequence)
    {
      return;
    }
    if (_seen_sequences.size() <= sequence)
    {
      _seen_sequences.resize(static_cast<std::size_t>(sequence) + 1, false);
    }
    _seen_sequences[static_cast<std::size_t>(sequence)] = true;
  }

  static constexpr std::uint64_t max_tracked_sequence = std::uint64_t{1} << 20;

  std::vector<connection_id_entry_t> _entries;
  std::vector<bool> _seen_sequences;
  std::vector<std::uint64_t> _pending_retires;
  std::uint64_t _largest_retire_prior_to = 0;
  std::uint64_t _current = 0;
  bool _have_current = false;
};
} // namespace vio::quic
