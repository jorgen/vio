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

// How many discontiguous runs a receive half will hold. Flow control bounds the
// bytes; this bounds the bookkeeping, which is the larger number when a peer
// sends one byte at every other offset. Sixty-four is far more reordering than
// any real path produces and still a fixed, small cost.
inline constexpr std::size_t max_receive_chunks = 64;

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
    _max_data = (std::max)(_max_data, value);
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

    if (!insert(offset, data))
    {
      return stream_error_t::flow_control;
    }

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
    // Section 4.5 charges the final size against connection flow control, and
    // that is right -- but these bytes are now never going to be delivered to
    // anyone, so the receiver has to release the credit for them. Advancing the
    // read offset is what says so: there is nothing left between here and the
    // final size, and the connection reads the difference back out.
    _read_offset = final_size;
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
    // Settled first, and unconditionally. A stream that ended with nothing left
    // to take -- an empty frame carrying FIN, a reset, or a read that happened
    // to take the last byte before the FIN arrived -- reaches the early return
    // below, and with the terminal check only after it those streams never
    // finished, were never reaped, and never returned their MAX_STREAMS credit.
    settle();
    auto it = _chunks.find(_read_offset);
    if (it == _chunks.end() || bytes == 0)
    {
      return;
    }
    const std::size_t taken = (std::min)(bytes, it->second.size());
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
    settle();
  }

  // The one place a receive half becomes terminal, so that every path that can
  // finish one goes through it.
  void settle()
  {
    if (_state == receive_state_t::reset_received)
    {
      _state = receive_state_t::reset_read;
      return;
    }
    if (_state != receive_state_t::data_read && _final_size.has_value() && _read_offset >= *_final_size)
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
  // Flow control bounds the highest offset reached, which is not the same as
  // bounding what is held: one byte at every other offset stays inside any
  // window and still costs a map node plus its own heap block per byte, which
  // is fifty to a hundred times the advertised budget in real memory. So the
  // fragments are counted as well as the bytes.
  [[nodiscard]] bool insert(std::uint64_t offset, std::span<const std::uint8_t> data)
  {
    if (data.empty())
    {
      return true;
    }
    std::uint64_t start = offset;
    std::size_t skip = 0;
    if (start < _read_offset)
    {
      const std::uint64_t behind = _read_offset - start;
      if (behind >= data.size())
      {
        return true;
      }
      skip = static_cast<std::size_t>(behind);
      start = _read_offset;
    }

    std::vector<std::uint8_t> incoming(data.begin() + static_cast<std::ptrdiff_t>(skip), data.end());
    const std::uint64_t end = start + incoming.size();

    // The ordinary case, and the one worth spending code on: bytes that
    // continue a run already held. Appending to that run keeps it in one piece
    // for readable() at the cost of what arrived, where the general path below
    // builds the whole run again for every arrival -- allocating it, zeroing
    // it, and copying into it. On a stream being read more slowly than it is
    // filled, which is every bulk transfer, that is quadratic in the amount
    // waiting: 8 MB spent three quarters of its instructions in memset.
    auto run = _chunks.end();
    if (!_chunks.empty())
    {
      auto candidate = _chunks.lower_bound(start);
      if (candidate == _chunks.end() || candidate->first > start)
      {
        if (candidate != _chunks.begin())
        {
          --candidate;
          if (candidate->first + candidate->second.size() == start)
          {
            run = candidate;
          }
        }
      }
    }
    if (run != _chunks.end())
    {
      run->second.insert(run->second.end(), incoming.begin(), incoming.end());
      // Whatever now continues it joins it, which is how an out-of-order gap
      // that this arrival closed gets stitched back together.
      for (auto next = std::next(run); next != _chunks.end();)
      {
        const std::uint64_t run_end = run->first + run->second.size();
        if (next->first > run_end)
        {
          break;
        }
        if (next->first + next->second.size() > run_end)
        {
          const auto overlap = static_cast<std::size_t>(run_end - next->first);
          run->second.insert(run->second.end(), next->second.begin() + static_cast<std::ptrdiff_t>(overlap), next->second.end());
        }
        next = _chunks.erase(next);
      }
      return true;
    }

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
      merged_start = (std::min)(merged_start, last->first);
      merged_end = (std::max)(merged_end, last->first + last->second.size());
    }

    if (merged_start == start && merged_end == end && first == last)
    {
      // A fragment that merges with nothing is a new node. This is the only
      // path that grows the map without also removing from it, so it is the
      // only place the count has to be defended.
      if (_chunks.size() >= max_receive_chunks)
      {
        return false;
      }
      _chunks.emplace(start, std::move(incoming));
      return true;
    }

    std::vector<std::uint8_t> merged(static_cast<std::size_t>(merged_end - merged_start));
    std::copy(incoming.begin(), incoming.end(), merged.begin() + static_cast<std::ptrdiff_t>(start - merged_start));
    for (auto it = first; it != last; ++it)
    {
      std::copy(it->second.begin(), it->second.end(), merged.begin() + static_cast<std::ptrdiff_t>(it->first - merged_start));
    }
    _chunks.erase(first, last);
    _chunks.emplace(merged_start, std::move(merged));
    return true;
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
    return _base + queued_bytes();
  }

  [[nodiscard]] bool fin_queued() const
  {
    return _fin;
  }

  void set_max_data(std::uint64_t value)
  {
    _max_data = (std::max)(_max_data, value);
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

    // A queued range whose bytes have since been acknowledged and retired has
    // nothing left behind it: window() returns empty, the frame goes out with no
    // data, and nothing about the queue advances -- so it goes out again, for
    // ever, at congestion-window rate, and if the FIN rides along it lands at
    // the wrong offset and the peer is obliged to close. Dropping them here is
    // what on_range_acknowledged cannot do, since it never prunes the queue.
    while (!_retransmit.empty() && _retransmit.front().offset < _base)
    {
      const auto &stale = _retransmit.front();
      const std::uint64_t stale_end = stale.offset + stale.length;
      if (stale_end <= _base)
      {
        _retransmit.erase(_retransmit.begin());
        continue;
      }
      // Partly retired: keep only the part that still has bytes behind it.
      auto trimmed = range_t{.offset = _base, .length = stale_end - _base};
      _retransmit.front() = trimmed;
      break;
    }

    if (!_retransmit.empty())
    {
      const auto &range = _retransmit.front();
      const std::size_t amount = static_cast<std::size_t>((std::min<std::uint64_t>)(range.length, limit));
      if (amount == 0)
      {
        return std::nullopt;
      }
      chunk_t chunk;
      chunk.offset = range.offset;
      chunk.data = window(range.offset, amount);
      if (chunk.data.empty())
      {
        // Nothing behind it after all. Refusing beats emitting an empty frame
        // that makes no progress and is therefore repeated indefinitely.
        _retransmit.erase(_retransmit.begin());
        return std::nullopt;
      }
      // The FIN rides only with the range that actually reaches the end.
      chunk.fin = _fin && range.offset + amount == queued();
      chunk.retransmit = true;
      return chunk;
    }

    const std::uint64_t allowed = (std::min)(_max_data, _sent_offset + connection_window);
    const std::uint64_t remaining = queued() > _sent_offset ? queued() - _sent_offset : 0;
    const std::uint64_t permitted = allowed > _sent_offset ? allowed - _sent_offset : 0;
    const std::size_t amount = static_cast<std::size_t>((std::min<std::uint64_t>)((std::min)(remaining, permitted), limit));

    // An empty STREAM frame is still worth sending if it carries the FIN and
    // everything before it has gone.
    //
    // Gated on _fin_sent rather than on the state, and that is what makes a
    // lost bare FIN recoverable: the state is data_sent the moment the FIN goes
    // out and never returns to send, so a state test offered it exactly once
    // and the peer that missed it waited for an end of stream that was never
    // sent again.
    const bool fin_only = _fin && amount == 0 && _sent_offset == queued() && !_fin_sent && (_state == send_state_t::send || _state == send_state_t::data_sent);
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
    // Before the retransmit branch's early return, because a retransmitted
    // chunk can be the one carrying the FIN.
    if (chunk.fin)
    {
      _fin_sent = true;
    }
    if (chunk.retransmit)
    {
      auto &front = _retransmit.front();
      const std::uint64_t taken = chunk.data.size();
      front.offset += taken;
      front.length -= (std::min)(front.length, taken);
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

  void on_range_lost(std::uint64_t offset, std::uint64_t length, bool fin)
  {
    if (_state == send_state_t::reset_sent || _state == send_state_t::reset_received)
    {
      return;
    }
    // The FIN is put back before the length test, because a FIN sent with no
    // bytes behind it is a zero-length range and would otherwise fall straight
    // through. If it rode with bytes, the retransmit of those bytes carries it
    // again; if it rode alone, the fin_only branch above offers it again.
    if (fin)
    {
      _fin_sent = false;
    }
    if (length == 0)
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
  void on_range_acknowledged(std::uint64_t offset, std::uint64_t length, bool fin)
  {
    if (fin)
    {
      _fin_acknowledged = true;
    }
    if (length > 0)
    {
      insert_acknowledged(offset, offset + length);

      // Anything acknowledged can never be asked for again. Without this a
      // stream holds every byte it ever sent for the life of the connection,
      // which on a long-lived stream is unbounded growth rather than a leak
      // only in the sense that it is reachable.
      const std::uint64_t acknowledged = acknowledged_prefix_end();
      if (acknowledged > _base)
      {
        const std::size_t drop = static_cast<std::size_t>((std::min<std::uint64_t>)(acknowledged - _base, queued_bytes()));
        retire(drop);
      }
    }

    // Section 3.1: Data Sent becomes Data Recvd when all the stream data *and
    // the FIN* have been acknowledged. Both halves of that are load-bearing.
    //
    // The byte test alone left a stream in data_sent for ever when the FIN
    // carried no bytes -- a half-close after the last write, which is the
    // ordinary end of a request. It was then never reaped, and if the peer had
    // opened it, its MAX_STREAMS credit was never returned: a peer that had
    // spent its allowance waited for a MAX_STREAMS that waited on a request it
    // could not send.
    //
    // The FIN test alone is missing is the other error, and it is the quieter
    // one. queued() counts bytes and a FIN adds none, so acknowledging the last
    // byte satisfied the byte test whether or not the FIN itself had arrived.
    // A stream whose data was acknowledged and whose separately-sent FIN was
    // lost went to data_received, became reapable, and took the retransmit of
    // that FIN with it -- so the peer waited out its idle timeout with no end
    // of stream.
    if (_state == send_state_t::data_sent && _fin_acknowledged && acknowledged_prefix_end() >= queued())
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
    return !_retransmit.empty() || queued() > _sent_offset || (_fin && !_fin_sent);
  }

  // Whether the peer has confirmed the end of the stream, as opposed to merely
  // every byte before it.
  [[nodiscard]] bool fin_acknowledged() const
  {
    return _fin_acknowledged;
  }

private:
  [[nodiscard]] std::span<const std::uint8_t> window(std::uint64_t offset, std::size_t amount) const
  {
    if (offset < _base || amount == 0)
    {
      return {};
    }
    const std::size_t index = static_cast<std::size_t>(offset - _base);
    const std::size_t available = queued_bytes();
    if (index >= available)
    {
      return {};
    }
    return std::span<const std::uint8_t>(_data).subspan(_head + index, (std::min)(amount, available - index));
  }

  [[nodiscard]] std::size_t queued_bytes() const
  {
    return _data.size() - _head;
  }

  // Acknowledged bytes can never be asked for again, but dropping them by
  // erasing from the front moves everything still queued -- once per
  // acknowledgement. On a body handed over in one write that is quadratic in
  // its size: a 20 MB response spent seconds of CPU moving its own tail
  // around, which showed up as a transfer running two orders of magnitude
  // slower than the peer's. The retired prefix is left where it is and the
  // buffer is compacted only once it is at least half dead, which is O(1) per
  // byte amortised.
  void retire(std::size_t drop)
  {
    _head += drop;
    _base += drop;
    if (_head * 2 >= _data.size())
    {
      _data.erase(_data.begin(), _data.begin() + static_cast<std::ptrdiff_t>(_head));
      _head = 0;
    }
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
      merged_start = (std::min)(merged_start, last->first);
      merged_end = (std::max)(merged_end, last->second);
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
  std::size_t _head = 0;
  std::vector<range_t> _retransmit;
  // Offset to end, merged and disjoint.
  std::map<std::uint64_t, std::uint64_t> _acknowledged;
  send_state_t _state = send_state_t::ready;
  std::uint64_t _base = 0;
  std::uint64_t _sent_offset = 0;
  std::uint64_t _max_data = 0;
  std::optional<std::uint64_t> _reset_error;
  bool _fin = false;
  // The FIN is not a byte, so it cannot be tracked by the range bookkeeping
  // beside it: sent and acknowledged both have to be their own flag.
  bool _fin_sent = false;
  bool _fin_acknowledged = false;
};
} // namespace vio::quic
