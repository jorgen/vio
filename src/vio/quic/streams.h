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

// Every stream on a connection, plus the two limits that apply across all of
// them: how much data may be in flight in total (RFC 9000 section 4.1) and how
// many streams the peer may open (section 4.6).
//
// Both limits exist for the same reason and are enforced the same way: an
// endpoint advertises what it is willing to receive, and a peer that exceeds
// it has committed a connection error rather than merely been rude. Without
// them a peer could make this endpoint allocate without bound by opening
// streams or by sending on one, which is the cheapest denial of service there
// is against a transport that buffers for reassembly.
//
// Opening is implicit. Section 3.2: receiving a frame for a stream that has
// not been seen opens it, along with every lower-numbered stream of the same
// type -- a peer may legitimately use stream 8 before stream 4 arrives, and
// both must count against the limit.

#include "vio/quic/stream.h"
#include "vio/quic/transport_parameters.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <unordered_map>
#include <vector>

namespace vio::quic
{
enum class streams_error_t : std::uint8_t
{
  none,
  flow_control,
  stream_limit,
  stream_state,
  final_size,
};

[[nodiscard]] constexpr streams_error_t from_stream_error(stream_error_t error)
{
  switch (error)
  {
  case stream_error_t::none:
    return streams_error_t::none;
  case stream_error_t::flow_control:
    return streams_error_t::flow_control;
  case stream_error_t::stream_state:
    return streams_error_t::stream_state;
  case stream_error_t::final_size:
    return streams_error_t::final_size;
  }
  return streams_error_t::none;
}

// RFC 9000 section 20.1.
[[nodiscard]] constexpr std::uint64_t streams_error_code(streams_error_t error)
{
  switch (error)
  {
  case streams_error_t::flow_control:
    return 0x03;
  case streams_error_t::stream_limit:
    return 0x04;
  case streams_error_t::stream_state:
    return 0x05;
  case streams_error_t::final_size:
    return 0x06;
  case streams_error_t::none:
    break;
  }
  return 0x00;
}

struct stream_t
{
  std::uint64_t id = 0;
  receive_stream_t receive;
  send_stream_t send;
  bool has_receive = false;
  bool has_send = false;
  // A STOP_SENDING arrived: the peer wants nothing more, and section 3.5 says
  // to answer with RESET_STREAM.
  std::optional<std::uint64_t> stop_sending_error;
  bool reset_pending = false;
  // A MAX_STREAM_DATA is owed: the application has taken enough that the peer
  // should be told it may send more.
  bool pending_max_stream_data = false;
  // How much has been read since the last window update, so the policy can
  // decide when one is worth a frame.
  std::uint64_t consumed_since_update = 0;
  // A STOP_SENDING this endpoint owes the peer.
  std::optional<std::uint64_t> stop_sending_pending;
  // Whether this stream is currently on the sendable list. A hint in one
  // direction only: the list may still name a stream that has gone quiet,
  // which the next sweep drops, but a stream with work must always be on it.
  bool in_sendable = false;
};

// Everything that would put a frame for this stream into a packet.
[[nodiscard]] inline bool stream_has_sendable_work(const stream_t &stream)
{
  return stream.reset_pending || (stream.has_send && stream.send.has_pending()) || stream.pending_max_stream_data || stream.stop_sending_pending.has_value();
}

struct streams_config_t
{
  stream_initiator_t local_initiator = stream_initiator_t::client;
  // What this endpoint advertised, from its own transport parameters.
  std::uint64_t initial_max_data = 0;
  std::uint64_t initial_max_stream_data_bidi_local = 0;
  std::uint64_t initial_max_stream_data_bidi_remote = 0;
  std::uint64_t initial_max_stream_data_uni = 0;
  std::uint64_t initial_max_streams_bidi = 0;
  std::uint64_t initial_max_streams_uni = 0;
};

class streams_t
{
public:
  explicit streams_t(const streams_config_t &config = {})
    : _config(config)
    , _local_max_data(config.initial_max_data)
    , _local_max_streams_bidi(config.initial_max_streams_bidi)
    , _local_max_streams_uni(config.initial_max_streams_uni)
  {
  }

  // The peer's transport parameters, once the handshake produced them.
  void apply_peer_parameters(const transport_parameters_t &parameters)
  {
    _peer_max_data = std::max(_peer_max_data, parameters.initial_max_data);
    _peer_max_streams_bidi = std::max(_peer_max_streams_bidi, parameters.initial_max_streams_bidi);
    _peer_max_streams_uni = std::max(_peer_max_streams_uni, parameters.initial_max_streams_uni);
    _peer_initial_max_stream_data_bidi_local = parameters.initial_max_stream_data_bidi_local;
    _peer_initial_max_stream_data_bidi_remote = parameters.initial_max_stream_data_bidi_remote;
    _peer_initial_max_stream_data_uni = parameters.initial_max_stream_data_uni;

    // Streams opened before the parameters arrived were created with a zero
    // send limit; give them the one the peer actually advertised.
    for (auto &entry : _streams)
    {
      if (entry.second.has_send)
      {
        entry.second.send.set_max_data(peer_initial_stream_limit(entry.first));
      }
    }
  }

  [[nodiscard]] std::uint64_t local_max_data() const
  {
    return _local_max_data;
  }

  [[nodiscard]] std::uint64_t peer_max_data() const
  {
    return _peer_max_data;
  }

  [[nodiscard]] std::uint64_t data_received() const
  {
    return _data_received;
  }

  [[nodiscard]] std::uint64_t data_sent() const
  {
    return _data_sent;
  }

  // What is left of the peer's connection-level limit.
  [[nodiscard]] std::uint64_t connection_send_window() const
  {
    return _peer_max_data > _data_sent ? _peer_max_data - _data_sent : 0;
  }

  void set_peer_max_data(std::uint64_t value)
  {
    _peer_max_data = std::max(_peer_max_data, value);
  }

  void set_local_max_data(std::uint64_t value)
  {
    _local_max_data = std::max(_local_max_data, value);
  }

  void set_peer_max_streams(stream_direction_t direction, std::uint64_t value)
  {
    auto &target = direction == stream_direction_t::bidirectional ? _peer_max_streams_bidi : _peer_max_streams_uni;
    target = std::max(target, value);
  }

  [[nodiscard]] std::uint64_t peer_max_streams(stream_direction_t direction) const
  {
    return direction == stream_direction_t::bidirectional ? _peer_max_streams_bidi : _peer_max_streams_uni;
  }

  [[nodiscard]] stream_t *find(std::uint64_t id)
  {
    auto it = _streams.find(id);
    return it == _streams.end() ? nullptr : &it->second;
  }

  // Streams that may have something to send. Building a packet walks this
  // rather than every stream the connection holds open, which is the
  // difference between paying for the streams that are busy and paying for a
  // cache miss on each of the thousand that are not.
  //
  // Every place that gives a stream work marks it here. A stale entry costs
  // one check and is dropped; a missing one would be a stream that never
  // sends, so the debug build re-derives the list the slow way and complains
  // if the two disagree.
  void mark_sendable(stream_t &stream)
  {
    if (stream.in_sendable)
    {
      return;
    }
    stream.in_sendable = true;
    _sendable.push_back(stream.id);
  }

  [[nodiscard]] bool has_sendable()
  {
    // Answering the question only requires reaching the first stream that
    // still has work. Entries ahead of it have gone quiet or been reaped and
    // are dropped on the way past, which is what keeps the list from growing
    // without bound; the rest are left alone, because on a connection with a
    // thousand busy streams the rest is nearly all of them.
    std::size_t dead = 0;
    while (dead < _sendable.size())
    {
      auto *stream = find(_sendable[dead]);
      if (stream != nullptr)
      {
        if (stream_has_sendable_work(*stream))
        {
          break;
        }
        stream->in_sendable = false;
      }
      ++dead;
    }
    _sendable.erase(_sendable.begin(), _sendable.begin() + static_cast<std::ptrdiff_t>(dead));
#ifndef NDEBUG
    for (const auto &entry : _streams)
    {
      assert(!stream_has_sendable_work(entry.second) || entry.second.in_sendable);
    }
#endif
    return !_sendable.empty();
  }

  [[nodiscard]] const std::vector<std::uint64_t> &sendable() const
  {
    return _sendable;
  }

  // Moves the streams a packet has already served to the back, so the next one
  // starts where it left off. Without this the head of the list would hold the
  // connection for as long as it had anything to send, and a stream further
  // down would wait however long that took.
  void rotate_sendable(std::size_t served)
  {
    served = std::min(served, _sendable.size());
    std::rotate(_sendable.begin(), _sendable.begin() + static_cast<std::ptrdiff_t>(served), _sendable.end());
  }

  [[nodiscard]] std::unordered_map<std::uint64_t, stream_t> &all()
  {
    return _streams;
  }

  // Opens the next stream this endpoint may initiate, or nothing when the
  // peer's limit is reached. Section 4.6: exceeding it is not permitted, so a
  // caller is told to wait rather than allowed to break the rule.
  [[nodiscard]] std::optional<std::uint64_t> open(stream_direction_t direction)
  {
    auto &next = direction == stream_direction_t::bidirectional ? _next_local_bidi : _next_local_uni;
    if (next >= peer_max_streams(direction))
    {
      return std::nullopt;
    }
    const auto id = make_stream_id(_config.local_initiator, direction, next);
    ++next;
    auto &stream = _streams[id];
    stream.id = id;
    stream.has_send = true;
    stream.send = send_stream_t(peer_initial_stream_limit(id));
    if (direction == stream_direction_t::bidirectional)
    {
      stream.has_receive = true;
      stream.receive = receive_stream_t(_config.initial_max_stream_data_bidi_local);
    }
    return id;
  }

  // Section 19.8: a STREAM frame both delivers data and, if the stream has not
  // been seen, opens it.
  [[nodiscard]] streams_error_t receive_stream_frame(std::uint64_t id, std::uint64_t offset, std::span<const std::uint8_t> data, bool fin)
  {
    auto *stream = ensure_remote(id);
    if (stream == nullptr)
    {
      return _last_open_error;
    }
    if (!stream->has_receive)
    {
      // A unidirectional stream this endpoint opened has no receiving half.
      return streams_error_t::stream_state;
    }

    std::uint64_t consumed = 0;
    const auto error = stream->receive.receive(offset, data, fin, consumed);
    if (error != stream_error_t::none)
    {
      return from_stream_error(error);
    }
    return charge_connection(consumed);
  }

  [[nodiscard]] streams_error_t receive_reset_stream(std::uint64_t id, std::uint64_t error_code, std::uint64_t final_size)
  {
    (void)error_code;
    auto *stream = ensure_remote(id);
    if (stream == nullptr)
    {
      return _last_open_error;
    }
    if (!stream->has_receive)
    {
      return streams_error_t::stream_state;
    }
    std::uint64_t consumed = 0;
    const auto error = stream->receive.receive_reset(final_size, consumed);
    if (error != stream_error_t::none)
    {
      return from_stream_error(error);
    }
    return charge_connection(consumed);
  }

  // Section 3.5: the peer is no longer interested, and the correct answer is a
  // RESET_STREAM rather than continuing to send into a void.
  [[nodiscard]] streams_error_t receive_stop_sending(std::uint64_t id, std::uint64_t error_code)
  {
    auto *stream = ensure_remote(id);
    if (stream == nullptr)
    {
      return _last_open_error;
    }
    if (!stream->has_send)
    {
      return streams_error_t::stream_state;
    }
    stream->stop_sending_error = error_code;
    if (stream->send.state() != send_state_t::reset_sent && stream->send.state() != send_state_t::data_received)
    {
      stream->send.reset(error_code);
      stream->reset_pending = true;
      mark_sendable(*stream);
    }
    return streams_error_t::none;
  }

  [[nodiscard]] streams_error_t receive_max_stream_data(std::uint64_t id, std::uint64_t value)
  {
    auto *stream = ensure_remote(id);
    if (stream == nullptr)
    {
      return _last_open_error;
    }
    if (!stream->has_send)
    {
      return streams_error_t::stream_state;
    }
    stream->send.set_max_data(value);
    return streams_error_t::none;
  }

  // Charges the connection-level limit and reports the error if it is blown.
  [[nodiscard]] streams_error_t charge_connection(std::uint64_t bytes)
  {
    if (bytes == 0)
    {
      return streams_error_t::none;
    }
    if (_data_received > max_stream_id - bytes)
    {
      return streams_error_t::flow_control;
    }
    _data_received += bytes;
    if (_data_received > _local_max_data)
    {
      return streams_error_t::flow_control;
    }
    return streams_error_t::none;
  }

  void on_data_sent(std::uint64_t bytes)
  {
    _data_sent += bytes;
  }

  [[nodiscard]] std::uint64_t next_local_index(stream_direction_t direction) const
  {
    return direction == stream_direction_t::bidirectional ? _next_local_bidi : _next_local_uni;
  }

  [[nodiscard]] std::uint64_t remote_streams_opened(stream_direction_t direction) const
  {
    return direction == stream_direction_t::bidirectional ? _remote_bidi_opened : _remote_uni_opened;
  }

  [[nodiscard]] std::uint64_t local_max_streams(stream_direction_t direction) const
  {
    return direction == stream_direction_t::bidirectional ? _local_max_streams_bidi : _local_max_streams_uni;
  }

  // Section 4.6: the limit is cumulative, so credit is returned by raising it
  // rather than by decrementing anything. Without this a peer that reaches the
  // limit is stuck there for the life of the connection however many streams
  // it finishes.
  void grant_streams(stream_direction_t direction, std::uint64_t additional)
  {
    auto &limit = direction == stream_direction_t::bidirectional ? _local_max_streams_bidi : _local_max_streams_uni;
    if (additional > max_stream_count - limit)
    {
      limit = max_stream_count;
      return;
    }
    limit += additional;
  }

  struct reaped_t
  {
    std::uint64_t bidirectional = 0;
    std::uint64_t unidirectional = 0;
  };

  // Peer-initiated streams that have been fully dealt with and can be
  // forgotten, which is what makes room for the credit above. Both directions
  // are settled in a single pass: this walks every open stream, and asking
  // twice made a connection holding many of them cost twice as much for
  // nothing.
  [[nodiscard]] reaped_t reap_finished(stream_initiator_t remote_initiator)
  {
    reaped_t reaped;
    for (auto it = _streams.begin(); it != _streams.end();)
    {
      const auto id = it->first;
      if (stream_initiator(id) != remote_initiator)
      {
        ++it;
        continue;
      }
      const auto &stream = it->second;
      const bool receive_done = !stream.has_receive || stream.receive.state() == receive_state_t::data_read || stream.receive.state() == receive_state_t::reset_read;
      const bool send_done = !stream.has_send || stream.send.state() == send_state_t::data_received || stream.send.state() == send_state_t::reset_sent;
      if (receive_done && send_done)
      {
        (stream_direction(id) == stream_direction_t::bidirectional ? reaped.bidirectional : reaped.unidirectional) += 1;
        it = _streams.erase(it);
        continue;
      }
      ++it;
    }
    return reaped;
  }

private:
  [[nodiscard]] std::uint64_t peer_initial_stream_limit(std::uint64_t id) const
  {
    if (stream_direction(id) == stream_direction_t::unidirectional)
    {
      return _peer_initial_max_stream_data_uni;
    }
    // Section 18.2: which of the two bidirectional limits applies depends on
    // who opened the stream, from the perspective of the endpoint that set it.
    return stream_initiator(id) == _config.local_initiator ? _peer_initial_max_stream_data_bidi_remote : _peer_initial_max_stream_data_bidi_local;
  }

  [[nodiscard]] std::uint64_t local_initial_stream_limit(std::uint64_t id) const
  {
    if (stream_direction(id) == stream_direction_t::unidirectional)
    {
      return _config.initial_max_stream_data_uni;
    }
    return stream_initiator(id) == _config.local_initiator ? _config.initial_max_stream_data_bidi_local : _config.initial_max_stream_data_bidi_remote;
  }

  // Opens a peer-initiated stream, and every lower-numbered one of its type:
  // section 3.2 makes them all open at once, and all of them count.
  stream_t *ensure_remote(std::uint64_t id)
  {
    _last_open_error = streams_error_t::none;
    if (id > max_stream_id)
    {
      _last_open_error = streams_error_t::stream_limit;
      return nullptr;
    }

    auto existing = _streams.find(id);
    if (existing != _streams.end())
    {
      return &existing->second;
    }

    const auto direction = stream_direction(id);
    const auto initiator = stream_initiator(id);

    if (initiator == _config.local_initiator)
    {
      // A frame for a stream this endpoint would have opened itself, but has
      // not: section 19.8 makes that a STREAM_STATE_ERROR, not an open.
      auto &next = direction == stream_direction_t::bidirectional ? _next_local_bidi : _next_local_uni;
      if (stream_index(id) >= next)
      {
        _last_open_error = streams_error_t::stream_state;
        return nullptr;
      }
      // It existed and was already cleaned up; nothing to deliver to.
      _last_open_error = streams_error_t::none;
      return nullptr;
    }

    if (!stream_index_within_limit(id, local_max_streams(direction)))
    {
      _last_open_error = streams_error_t::stream_limit;
      return nullptr;
    }

    // Section 3.2 opens every lower-numbered stream of the same type as well,
    // and all of them count against the limit -- but only the high-water mark
    // is recorded. Materialising state for streams that have never carried a
    // frame would let a peer that advertised nothing but a single frame for a
    // high index force an allocation per implied stream, which with a
    // generous advertised limit is millions of objects from one packet.
    auto &opened = direction == stream_direction_t::bidirectional ? _remote_bidi_opened : _remote_uni_opened;
    const std::uint64_t index = stream_index(id);
    opened = std::max(opened, index + 1);

    auto &stream = _streams[id];
    stream.id = id;
    stream.has_receive = true;
    stream.receive = receive_stream_t(local_initial_stream_limit(id));
    if (direction == stream_direction_t::bidirectional)
    {
      stream.has_send = true;
      stream.send = send_stream_t(peer_initial_stream_limit(id));
    }
    return &stream;
  }

  streams_config_t _config;
  // Keyed by stream id, and nothing reads it in order: the send path works
  // from the sendable list and everything else is a lookup by id. Ordering it
  // only bought a comparison chain and a cache miss per node.
  std::unordered_map<std::uint64_t, stream_t> _streams;
  std::vector<std::uint64_t> _sendable;

  std::uint64_t _local_max_data = 0;
  std::uint64_t _peer_max_data = 0;
  std::uint64_t _data_received = 0;
  std::uint64_t _data_sent = 0;

  std::uint64_t _local_max_streams_bidi = 0;
  std::uint64_t _local_max_streams_uni = 0;
  std::uint64_t _peer_max_streams_bidi = 0;
  std::uint64_t _peer_max_streams_uni = 0;

  std::uint64_t _next_local_bidi = 0;
  std::uint64_t _next_local_uni = 0;
  std::uint64_t _remote_bidi_opened = 0;
  std::uint64_t _remote_uni_opened = 0;

  std::uint64_t _peer_initial_max_stream_data_bidi_local = 0;
  std::uint64_t _peer_initial_max_stream_data_bidi_remote = 0;
  std::uint64_t _peer_initial_max_stream_data_uni = 0;
  streams_error_t _last_open_error = streams_error_t::none;
};
} // namespace vio::quic
