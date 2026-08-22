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

// One QUIC stream: RFC 9000 sections 2 through 4.
//
// A stream is two independent halves that happen to share an identifier. The
// sending half has its own state machine and its own flow control limit set by
// the peer; the receiving half has another of each, set by us. A unidirectional
// stream simply has one of the two halves missing, which is why they are
// modelled separately rather than as one object with a direction flag.
//
// Final size is the idea that ties the halves to connection-level accounting.
// Section 4.5: a sender always communicates it, whether the stream ends with a
// FIN or a RESET_STREAM, so both endpoints agree on exactly how much
// connection flow control credit the stream consumed. Once known it cannot
// change -- a later frame implying a different value is a FINAL_SIZE_ERROR,
// because otherwise a peer could quietly desynchronise the two endpoints'
// accounting and stall the connection.

#include "vio/quic/varint.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <map>
#include <optional>
#include <span>
#include <vector>

namespace vio::quic
{
// Section 2.1: the low two bits of a stream ID say who opened it and whether
// it carries data both ways.
inline constexpr std::uint64_t stream_initiator_mask = 0x01;
inline constexpr std::uint64_t stream_direction_mask = 0x02;
inline constexpr std::uint64_t max_stream_id = varint_max;

enum class stream_initiator_t : std::uint8_t
{
  client,
  server,
};

enum class stream_direction_t : std::uint8_t
{
  bidirectional,
  unidirectional,
};

[[nodiscard]] constexpr stream_initiator_t stream_initiator(std::uint64_t id)
{
  return (id & stream_initiator_mask) == 0 ? stream_initiator_t::client : stream_initiator_t::server;
}

[[nodiscard]] constexpr stream_direction_t stream_direction(std::uint64_t id)
{
  return (id & stream_direction_mask) == 0 ? stream_direction_t::bidirectional : stream_direction_t::unidirectional;
}

[[nodiscard]] constexpr std::uint64_t stream_index(std::uint64_t id)
{
  return id >> 2;
}

[[nodiscard]] constexpr std::uint64_t make_stream_id(stream_initiator_t initiator, stream_direction_t direction, std::uint64_t index)
{
  return (index << 2) | (direction == stream_direction_t::unidirectional ? stream_direction_mask : 0) | (initiator == stream_initiator_t::server ? stream_initiator_mask : 0);
}

// Section 4.6: only stream IDs below max_streams * 4 + first_of_type may be
// opened, which is the same as saying the index must be under the limit.
[[nodiscard]] constexpr bool stream_index_within_limit(std::uint64_t id, std::uint64_t max_streams)
{
  return stream_index(id) < max_streams;
}

// Section 3.1. The sending half, from the perspective of the endpoint that
// owns it.
enum class send_state_t : std::uint8_t
{
  // Nothing sent yet.
  ready,
  // Data has been sent and more may follow.
  send,
  // The FIN has been sent; the final size is settled.
  data_sent,
  // Everything, including the FIN, has been acknowledged.
  data_received,
  // A RESET_STREAM has been sent instead.
  reset_sent,
  reset_received,
};

// Section 3.2. The receiving half.
enum class receive_state_t : std::uint8_t
{
  receive,
  // A FIN or RESET_STREAM has arrived, so the final size is known, but not
  // every byte below it has.
  size_known,
  data_received,
  data_read,
  reset_received,
  reset_read,
};

enum class stream_error_t : std::uint8_t
{
  none,
  // Section 4.1: more data than the advertised limit allowed.
  flow_control,
  // Section 3: a frame arrived for a half that cannot accept it.
  stream_state,
  // Section 4.5: a final size that contradicts one already established.
  final_size,
};

// The receiving half: reassembly plus the limit this endpoint advertised.
class receive_stream_t
{
public:
  explicit receive_stream_t(std::uint64_t initial_max_data = 0)
    : _max_data(initial_max_data)
  {
  }

  [[nodiscard]] receive_state_t state() const
  {
    return _state;
  }

  [[nodiscard]] std::uint64_t max_data() const
  {
    return _max_data;
  }

  // The highest offset seen, which is what this stream has consumed from the
  // connection-level limit.
  [[nodiscard]] std::uint64_t highest_offset() const
  {
    return _highest_offset;
  }

  [[nodiscard]] std::optional<std::uint64_t> final_size() const
  {
    return _final_size;
  }

  [[nodiscard]] std::uint64_t read_offset() const
  {
    return _read_offset;
  }

  // How much more the peer may send before it needs a bigger limit.
  [[nodiscard]] std::uint64_t available_window() const
  {
    return _max_data > _highest_offset ? _max_data - _highest_offset : 0;
  }

  void set_max_data(std::uint64_t value)
  {
    // A limit only ever moves up: section 4.1 makes them cumulative, and
    // honouring a smaller one would strand data already in flight.
    _max_data = std::max(_max_data, value);
  }

  // Returns how much new data this contributed, so the caller can charge it
  // against the connection-level limit.
  [[nodiscard]] stream_error_t receive(std::uint64_t offset, std::span<const std::uint8_t> data, bool fin, std::uint64_t &connection_credit_consumed)
  {
    connection_credit_consumed = 0;
    if (_state == receive_state_t::reset_received || _state == receive_state_t::reset_read)
    {
      // After a reset the data is meaningless, but it is not an error: the
      // peer may simply not have seen the reset yet.
      return stream_error_t::none;
    }
    if (offset > max_stream_id || data.size() > max_stream_id - offset)
    {
      return stream_error_t::final_size;
    }

    const std::uint64_t end = offset + data.size();
    if (_final_size.has_value())
    {
      // Section 4.5: nothing may arrive at or beyond a settled final size, and
      // a FIN that claims a different one is a contradiction.
      if (end > *_final_size || (fin && end != *_final_size))
      {
        return stream_error_t::final_size;
      }
    }
    else if (fin && end < _highest_offset)
    {
      // A final size below data already received is equally impossible.
      return stream_error_t::final_size;
    }

    if (end > _max_data)
    {
      return stream_error_t::flow_control;
    }

    if (end > _highest_offset)
    {
      connection_credit_consumed = end - _highest_offset;
      _highest_offset = end;
    }

    if (fin && !_final_size.has_value())
    {
      _final_size = end;
      _state = receive_state_t::size_known;
    }

    insert(offset, data);

    if (_final_size.has_value() && _state != receive_state_t::data_read && contiguous_end() >= *_final_size)
    {
      _state = receive_state_t::data_received;
    }
    return stream_error_t::none;
  }

  // Section 4.5: a reset settles the final size too, so the connection-level
  // accounting stays consistent whichever way the stream ended.
  [[nodiscard]] stream_error_t receive_reset(std::uint64_t final_size, std::uint64_t &connection_credit_consumed)
  {
    connection_credit_consumed = 0;
    if (final_size > max_stream_id)
    {
      return stream_error_t::final_size;
    }
    if (_final_size.has_value() && *_final_size != final_size)
    {
      return stream_error_t::final_size;
    }
    if (final_size < _highest_offset)
    {
      return stream_error_t::final_size;
    }
    if (final_size > _max_data)
    {
      return stream_error_t::flow_control;
    }
    if (final_size > _highest_offset)
    {
      connection_credit_consumed = final_size - _highest_offset;
      _highest_offset = final_size;
    }
    _final_size = final_size;
    _chunks.clear();
    if (_state != receive_state_t::reset_read)
    {
      _state = receive_state_t::reset_received;
    }
    return stream_error_t::none;
  }

  // Contiguous bytes the application can take right now.
  [[nodiscard]] std::span<const std::uint8_t> readable() const
  {
    auto it = _chunks.find(_read_offset);
    if (it == _chunks.end())
    {
      return {};
    }
    return it->second;
  }

  void consume(std::size_t bytes)
  {
    auto it = _chunks.find(_read_offset);
    if (it == _chunks.end() || bytes == 0)
    {
      return;
    }
    const std::size_t taken = std::min(bytes, it->second.size());
    _read_offset += taken;
    if (taken == it->second.size())
    {
      _chunks.erase(it);
    }
    else
    {
      std::vector<std::uint8_t> rest(it->second.begin() + static_cast<std::ptrdiff_t>(taken), it->second.end());
      _chunks.erase(it);
      _chunks.emplace(_read_offset, std::move(rest));
    }
    if (_final_size.has_value() && _read_offset >= *_final_size)
    {
      _state = receive_state_t::data_read;
    }
  }

  [[nodiscard]] bool finished() const
  {
    return _state == receive_state_t::data_read || _state == receive_state_t::reset_read;
  }

  void mark_reset_read()
  {
    if (_state == receive_state_t::reset_received)
    {
      _state = receive_state_t::reset_read;
    }
  }

private:
  [[nodiscard]] std::uint64_t contiguous_end() const
  {
    auto it = _chunks.find(_read_offset);
    return it == _chunks.end() ? _read_offset : _read_offset + it->second.size();
  }

  // The same merge-on-insert as the CRYPTO stream: a peer may repackage the
  // same bytes across different frame boundaries on every retransmission.
  void insert(std::uint64_t offset, std::span<const std::uint8_t> data)
  {
    if (data.empty())
    {
      return;
    }
    std::uint64_t start = offset;
    std::size_t skip = 0;
    if (start < _read_offset)
    {
      const std::uint64_t behind = _read_offset - start;
      if (behind >= data.size())
      {
        return;
      }
      skip = static_cast<std::size_t>(behind);
      start = _read_offset;
    }

    std::vector<std::uint8_t> incoming(data.begin() + static_cast<std::ptrdiff_t>(skip), data.end());
    const std::uint64_t end = start + incoming.size();

    auto first = _chunks.upper_bound(start);
    if (first != _chunks.begin())
    {
      auto previous = std::prev(first);
      if (previous->first + previous->second.size() >= start)
      {
        first = previous;
      }
    }

    auto last = first;
    std::uint64_t merged_start = start;
    std::uint64_t merged_end = end;
    for (; last != _chunks.end() && last->first <= end; ++last)
    {
      merged_start = std::min(merged_start, last->first);
      merged_end = std::max(merged_end, last->first + last->second.size());
    }

    if (merged_start == start && merged_end == end && first == last)
    {
      _chunks.emplace(start, std::move(incoming));
      return;
    }

    std::vector<std::uint8_t> merged(static_cast<std::size_t>(merged_end - merged_start));
    std::copy(incoming.begin(), incoming.end(), merged.begin() + static_cast<std::ptrdiff_t>(start - merged_start));
    for (auto it = first; it != last; ++it)
    {
      std::copy(it->second.begin(), it->second.end(), merged.begin() + static_cast<std::ptrdiff_t>(it->first - merged_start));
    }
    _chunks.erase(first, last);
    _chunks.emplace(merged_start, std::move(merged));
  }

  std::map<std::uint64_t, std::vector<std::uint8_t>> _chunks;
  receive_state_t _state = receive_state_t::receive;
  std::uint64_t _max_data = 0;
  std::uint64_t _highest_offset = 0;
  std::uint64_t _read_offset = 0;
  std::optional<std::uint64_t> _final_size;
};

// The sending half: a byte queue, the limit the peer advertised, and the
// ranges that need sending again.
class send_stream_t
{
public:
  struct range_t
  {
    std::uint64_t offset = 0;
    std::uint64_t length = 0;
  };

  explicit send_stream_t(std::uint64_t initial_max_data = 0)
    : _max_data(initial_max_data)
  {
  }

  [[nodiscard]] send_state_t state() const
  {
    return _state;
  }

  [[nodiscard]] std::uint64_t max_data() const
  {
    return _max_data;
  }

  [[nodiscard]] std::uint64_t sent_offset() const
  {
    return _sent_offset;
  }

  [[nodiscard]] std::uint64_t queued() const
  {
    return _base + _data.size();
  }

  [[nodiscard]] bool fin_queued() const
  {
    return _fin;
  }

  void set_max_data(std::uint64_t value)
  {
    _max_data = std::max(_max_data, value);
  }

  // Whether the peer's limit, not the connection's, is what is holding this
  // stream up. STREAM_DATA_BLOCKED exists to tell the peer exactly this.
  [[nodiscard]] bool blocked_by_flow_control() const
  {
    return _sent_offset >= _max_data && queued() > _sent_offset;
  }

  [[nodiscard]] bool write(std::span<const std::uint8_t> data, bool fin)
  {
    if (_fin || _state == send_state_t::reset_sent || _state == send_state_t::reset_received)
    {
      // Section 4.5: nothing may be written at or beyond the final size, and
      // queueing the FIN is what settles it.
      return false;
    }
    if (queued() > max_stream_id - data.size())
    {
      return false;
    }
    _data.insert(_data.end(), data.begin(), data.end());
    _fin = fin;
    if (_state == send_state_t::ready)
    {
      _state = send_state_t::send;
    }
    return true;
  }

  // The next range to put in a STREAM frame, bounded by what the peer's limit
  // and the caller's space allow. Retransmissions go first (section 13.3).
  struct chunk_t
  {
    std::uint64_t offset = 0;
    std::span<const std::uint8_t> data;
    bool fin = false;
    bool retransmit = false;
  };

  [[nodiscard]] std::optional<chunk_t> next_chunk(std::size_t limit, std::uint64_t connection_window)
  {
    if (_state == send_state_t::reset_sent || _state == send_state_t::reset_received)
    {
      return std::nullopt;
    }

    if (!_retransmit.empty())
    {
      const auto &range = _retransmit.front();
      const std::size_t amount = static_cast<std::size_t>(std::min<std::uint64_t>(range.length, limit));
      if (amount == 0)
      {
        return std::nullopt;
      }
      chunk_t chunk;
      chunk.offset = range.offset;
      chunk.data = window(range.offset, amount);
      // The FIN rides only with the range that actually reaches the end.
      chunk.fin = _fin && range.offset + amount == queued();
      chunk.retransmit = true;
      return chunk;
    }

    const std::uint64_t allowed = std::min(_max_data, _sent_offset + connection_window);
    const std::uint64_t remaining = queued() > _sent_offset ? queued() - _sent_offset : 0;
    const std::uint64_t permitted = allowed > _sent_offset ? allowed - _sent_offset : 0;
    const std::size_t amount = static_cast<std::size_t>(std::min<std::uint64_t>(std::min(remaining, permitted), limit));

    // An empty STREAM frame is still worth sending if it carries the FIN and
    // everything before it has gone.
    const bool fin_only = _fin && amount == 0 && _sent_offset == queued() && _state == send_state_t::send;
    if (amount == 0 && !fin_only)
    {
      return std::nullopt;
    }

    chunk_t chunk;
    chunk.offset = _sent_offset;
    chunk.data = window(_sent_offset, amount);
    chunk.fin = _fin && _sent_offset + amount == queued();
    return chunk;
  }

  // Section 4.1: there is a difference between having nothing to send and
  // having something to send and no permission. Only the second is worth a
  // frame -- it tells the peer its limit, and not its own capacity, is what
  // has stopped the flow.
  [[nodiscard]] bool blocked_by_stream_limit() const
  {
    return _retransmit.empty() && queued() > _sent_offset && _sent_offset >= _max_data;
  }

  [[nodiscard]] bool blocked_by_connection_limit(std::uint64_t connection_window) const
  {
    return _retransmit.empty() && queued() > _sent_offset && connection_window == 0 && _sent_offset < _max_data;
  }

  [[nodiscard]] std::uint64_t stream_limit() const
  {
    return _max_data;
  }

  void on_chunk_sent(const chunk_t &chunk)
  {
    if (chunk.retransmit)
    {
      auto &front = _retransmit.front();
      const std::uint64_t taken = chunk.data.size();
      front.offset += taken;
      front.length -= std::min(front.length, taken);
      if (front.length == 0)
      {
        _retransmit.erase(_retransmit.begin());
      }
      return;
    }
    _sent_offset = chunk.offset + chunk.data.size();
    if (chunk.fin)
    {
      _state = send_state_t::data_sent;
    }
  }

  void on_range_lost(std::uint64_t offset, std::uint64_t length)
  {
    if (length == 0 || _state == send_state_t::reset_sent || _state == send_state_t::reset_received)
    {
      return;
    }
    // A range the peer has already acknowledged is not lost, however late the
    // loss declaration arrives; resending it would be pure waste and the
    // bytes may no longer be held.
    if (offset + length <= acknowledged_prefix_end())
    {
      return;
    }
    for (const auto &pending : _retransmit)
    {
      if (pending.offset == offset && pending.length == length)
      {
        return;
      }
    }
    _retransmit.push_back(range_t{.offset = offset, .length = length});
  }

  // Acknowledgements arrive out of order and repeat, so counting bytes is not
  // enough: a duplicate would make the stream look complete before it was.
  // They are merged into ranges, and the contiguous prefix is what decides
  // both completion and how much of the buffer can go.
  void on_range_acknowledged(std::uint64_t offset, std::uint64_t length)
  {
    if (length == 0)
    {
      return;
    }
    insert_acknowledged(offset, offset + length);

    // Anything acknowledged can never be asked for again. Without this a
    // stream holds every byte it ever sent for the life of the connection,
    // which on a long-lived stream is unbounded growth rather than a leak
    // only in the sense that it is reachable.
    const std::uint64_t prefix = acknowledged_prefix_end();
    if (prefix > _base)
    {
      const std::size_t drop = static_cast<std::size_t>(std::min<std::uint64_t>(prefix - _base, _data.size()));
      _data.erase(_data.begin(), _data.begin() + static_cast<std::ptrdiff_t>(drop));
      _base += drop;
    }

    if (_state == send_state_t::data_sent && prefix >= queued())
    {
      _state = send_state_t::data_received;
    }
  }

  [[nodiscard]] std::uint64_t acknowledged_prefix() const
  {
    return acknowledged_prefix_end();
  }

  // Section 3.1: a reset abandons everything not yet delivered.
  void reset(std::uint64_t error_code)
  {
    if (_state == send_state_t::data_received)
    {
      return;
    }
    _reset_error = error_code;
    _state = send_state_t::reset_sent;
    _retransmit.clear();
  }

  [[nodiscard]] std::optional<std::uint64_t> reset_error() const
  {
    return _reset_error;
  }

  // The final size a RESET_STREAM must carry: everything queued, whether or
  // not it was ever sent.
  [[nodiscard]] std::uint64_t final_size() const
  {
    return queued();
  }

  [[nodiscard]] bool has_pending() const
  {
    return !_retransmit.empty() || queued() > _sent_offset || (_fin && _state == send_state_t::send);
  }

private:
  [[nodiscard]] std::span<const std::uint8_t> window(std::uint64_t offset, std::size_t amount) const
  {
    if (offset < _base || amount == 0)
    {
      return {};
    }
    const std::size_t index = static_cast<std::size_t>(offset - _base);
    if (index >= _data.size())
    {
      return {};
    }
    return std::span<const std::uint8_t>(_data).subspan(index, std::min(amount, _data.size() - index));
  }

  void insert_acknowledged(std::uint64_t start, std::uint64_t end)
  {
    auto first = _acknowledged.upper_bound(start);
    if (first != _acknowledged.begin())
    {
      auto previous = std::prev(first);
      if (previous->second >= start)
      {
        first = previous;
      }
    }
    auto last = first;
    std::uint64_t merged_start = start;
    std::uint64_t merged_end = end;
    for (; last != _acknowledged.end() && last->first <= end; ++last)
    {
      merged_start = std::min(merged_start, last->first);
      merged_end = std::max(merged_end, last->second);
    }
    _acknowledged.erase(first, last);
    _acknowledged.emplace(merged_start, merged_end);
  }

  [[nodiscard]] std::uint64_t acknowledged_prefix_end() const
  {
    auto it = _acknowledged.begin();
    return it != _acknowledged.end() && it->first == 0 ? it->second : 0;
  }

  std::vector<std::uint8_t> _data;
  std::vector<range_t> _retransmit;
  // Offset to end, merged and disjoint.
  std::map<std::uint64_t, std::uint64_t> _acknowledged;
  send_state_t _state = send_state_t::ready;
  std::uint64_t _base = 0;
  std::uint64_t _sent_offset = 0;
  std::uint64_t _max_data = 0;
  std::optional<std::uint64_t> _reset_error;
  bool _fin = false;
};
} // namespace vio::quic
