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

// Streams, as an application sees them: open one, accept one the peer opened,
// read it, write it, end it.
//
// The state and the edge drain live in quic_endpoint.h, because
// quic_connection_state_t owns the registry and a ref_ptr_t member needs its
// type complete. This file is the face: handles, awaitables, the reader, and
// the accessors that keep answering after the stream is gone.
//
// Two ideas carry most of it.
//
// **An ending is an ordinary entry, not a flag to test on the side.** A read
// yields bytes until there are none left, and then yields
// `vio_quic_stream_finished` or `vio_quic_stream_reset`. A loop that reads until
// it gets an error has by definition seen every byte first and knows which of
// the two happened -- which the transport's `stream_receive_finished()` cannot
// tell you, since it answers true for both. That is the same distinction
// `vio_tls_clean_shutdown` and `vio_tls_truncated` already draw for TLS.
//
// **Nothing is buffered on the application's behalf.** Bytes stay in the
// transport's reassembly until an await takes them, and taking them is the call
// that returns MAX_STREAM_DATA credit. So a stream nobody is reading stops the
// peer through the mechanism the protocol already has, and the memory a
// connection commits to receiving is exactly `initial_max_data` with nothing
// added on top.
//
// What this step does *not* do yet: writes are unbounded. `quic_stream_write`
// hands everything to the transport and resolves at once, so a program that
// writes faster than the peer reads grows the send queue rather than being
// suspended. The awaitable shape is here so that the write layer can add the
// backpressure without moving a single call site.

#include "vio/operation/quic_endpoint.h"
#include "vio/unique_buf.h"

#include <algorithm>
#include <coroutine>
#include <cstdint>
#include <cstring>
#include <expected>
#include <optional>
#include <span>
#include <utility>

namespace vio
{
// The application's handle on one stream. Copyable, and safe to hold past the
// stream's ending: it keeps answering what it latched, which is what lets a
// coroutine that wakes late learn whether its stream finished or was reset
// instead of finding a null pointer.
struct quic_stream_t
{
  ref_ptr_t<detail::quic_stream_state_t> handle = ref_ptr_t<detail::quic_stream_state_t>::null();
};

// The awaitable an open and an accept both return -- the same two-hold protocol
// quic_connection_awaitable_t uses, and a separate type only because it resolves
// to a stream.
class quic_stream_awaitable_t
{
public:
  explicit quic_stream_awaitable_t(detail::quic_stream_op_t *op)
    : _op(op)
  {
  }

  quic_stream_awaitable_t(quic_stream_awaitable_t &&other) noexcept
    : _op(std::exchange(other._op, nullptr))
  {
  }

  quic_stream_awaitable_t &operator=(quic_stream_awaitable_t &&other) noexcept
  {
    if (this != &other)
    {
      detail::quic_stream_op_release(_op);
      _op = std::exchange(other._op, nullptr);
    }
    return *this;
  }

  quic_stream_awaitable_t(const quic_stream_awaitable_t &) = delete;
  quic_stream_awaitable_t &operator=(const quic_stream_awaitable_t &) = delete;

  ~quic_stream_awaitable_t()
  {
    detail::quic_stream_op_release(_op);
  }

  [[nodiscard]] bool await_ready() const noexcept
  {
    return _op == nullptr || _op->resolved;
  }

  void await_suspend(std::coroutine_handle<> continuation) noexcept
  {
    _op->continuation = continuation;
  }

  [[nodiscard]] std::expected<quic_stream_t, error_t> await_resume() noexcept
  {
    if (_op == nullptr)
    {
      return std::unexpected(error_t{.code = -1, .msg = "the operation names nothing"});
    }
    if (_op->failed)
    {
      return std::unexpected(_op->failure);
    }
    return quic_stream_t{_op->result};
  }

private:
  detail::quic_stream_op_t *_op = nullptr;
};

// Writes resolve immediately at this step, so the awaitable carries its result
// rather than an operation. The shape is what matters: when the write layer
// makes this suspend over a high-water mark, no call site moves.
class quic_stream_write_awaitable_t
{
public:
  explicit quic_stream_write_awaitable_t(std::expected<void, error_t> result)
    : _result(std::move(result))
  {
  }

  [[nodiscard]] bool await_ready() const noexcept
  {
    return true;
  }

  void await_suspend(std::coroutine_handle<>) noexcept
  {
  }

  [[nodiscard]] std::expected<void, error_t> await_resume() noexcept
  {
    return std::move(_result);
  }

private:
  std::expected<void, error_t> _result;
};

namespace detail
{
// The transport this stream can still act through, or null once it cannot.
// Every operation goes through here, so a stale handle, a severed connection
// and a released endpoint are one test rather than three at every call site.
[[nodiscard]] inline vio::quic::connection_t *quic_stream_transport(const quic_stream_t &stream)
{
  if (stream.handle.ref_counted() == nullptr)
  {
    return nullptr;
  }
  auto *connection = stream.handle->connection;
  return connection == nullptr ? nullptr : connection->transport;
}

[[nodiscard]] inline error_t quic_stream_gone(const quic_stream_t &stream)
{
  if (stream.handle.ref_counted() == nullptr)
  {
    return error_t{.code = -1, .msg = "the stream names nothing"};
  }
  if (stream.handle->stale)
  {
    return error_t{.code = vio_quic_stream_stale, .msg = "the peer has reopened this stream id"};
  }
  return error_t{.code = vio_quic_connection_closed, .msg = "the connection ended"};
}

// Whether a stream of this id has each half at this endpoint. A unidirectional
// stream this endpoint opened has no receiving half and one the peer opened has
// no sending half -- and the transport answers a read on the first with an empty
// span and a write on the second with zero, neither of which is distinguishable
// from a slow peer.
[[nodiscard]] inline bool quic_stream_has_receive(const quic_stream_state_t &state)
{
  return state.direction == vio::quic::stream_direction_t::bidirectional || state.peer_initiated;
}

[[nodiscard]] inline bool quic_stream_has_send(const quic_stream_state_t &state)
{
  return state.direction == vio::quic::stream_direction_t::bidirectional || !state.peer_initiated;
}

inline void quic_stream_mark(const quic_stream_t &stream)
{
  auto *connection = stream.handle->connection;
  if (connection == nullptr || connection->endpoint == nullptr)
  {
    return;
  }
  // The bytes go out on this turn's beat rather than the next one, which is
  // what makes a write immediately followed by a close still reach the peer.
  auto found = connection->endpoint->by_connection.find(connection->transport);
  if (found != connection->endpoint->by_connection.end())
  {
    quic_mark_dirty(*connection->endpoint, found->second);
  }
}
} // namespace detail

// -----------------------------------------------------------------------------
// Opening and accepting
// -----------------------------------------------------------------------------

// Opens the next stream this endpoint may initiate, suspending while the peer's
// limit is reached rather than returning nothing and leaving the caller to
// invent a retry loop.
//
// Section 4.6 forbids exceeding the limit, so waiting is the only correct
// behaviour, and the transport knows the exact moment a MAX_STREAMS arrives --
// `open_stream` returning `std::optional` was not a simpler API, it was the same
// wait pushed onto every caller with no event to wait on. When credit exists,
// which is the ordinary case, this resolves in its own factory and nothing
// suspends.
//
// The suspension is real backpressure and worth understanding: a peer returns
// stream credit as its application finishes with the streams this one opened,
// so a client that opens faster than the server retires is throttled by the
// server. Use quic_try_open_stream when failing is better than queueing.
[[nodiscard]] inline quic_stream_awaitable_t quic_open_stream(quic_connection_t &connection, vio::quic::stream_direction_t direction = vio::quic::stream_direction_t::bidirectional,
                                                              cancellation_t *cancel = nullptr)
{
  const auto failed = [](error_t reason)
  {
    auto *op = detail::quic_stream_op_create(nullptr);
    detail::quic_stream_op_finish(*op, std::move(reason));
    return quic_stream_awaitable_t{op};
  };

  if (connection.handle.ref_counted() == nullptr)
  {
    return failed(error_t{.code = -1, .msg = "the connection names nothing"});
  }
  auto &state = connection.handle.data();
  if (state.transport == nullptr)
  {
    return failed(error_t{.code = vio_quic_connection_closed, .msg = "the connection has ended"});
  }
  if (cancel != nullptr && cancel->is_cancelled())
  {
    return failed(error_t{.code = vio_cancelled, .msg = "the open was cancelled before it began"});
  }

  if (const auto opened = state.transport->open_stream(direction); opened.has_value())
  {
    auto *op = detail::quic_stream_op_create(&state);
    auto stream = ref_ptr_t<detail::quic_stream_state_t>(&state, *opened, false);
    state.streams.emplace(*opened, stream);
    detail::quic_stream_op_finish(*op, std::move(stream));
    return quic_stream_awaitable_t{op};
  }

  auto *op = detail::quic_stream_op_create(&state);
  op->direction = direction;
  state.stream_ops.push_back(op);
  quic_stream_awaitable_t out{op};
  if (cancel != nullptr)
  {
    op->cancel_registration = cancel->register_callback(
      [op]()
      {
        if (op->resolved)
        {
          return;
        }
        auto *owner = op->connection;
        detail::quic_stream_op_finish(*op, error_t{.code = vio_cancelled, .msg = "the operation was cancelled"});
        if (owner != nullptr)
        {
          const auto found = std::find(owner->stream_ops.begin(), owner->stream_ops.end(), op);
          if (found != owner->stream_ops.end())
          {
            owner->stream_ops.erase(found);
            owner->pending_stream_ops.push_back(op);
            if (owner->endpoint != nullptr)
            {
              const auto entry = owner->endpoint->by_connection.find(owner->transport);
              if (entry != owner->endpoint->by_connection.end())
              {
                detail::quic_mark_pending(*owner->endpoint, entry->second);
              }
            }
          }
        }
      });
  }
  return out;
}

// The same, without the wait: nothing is what a caller gets when the peer's
// limit is reached, and it is expected to do something other than queue.
[[nodiscard]] inline std::expected<quic_stream_t, error_t> quic_try_open_stream(quic_connection_t &connection, vio::quic::stream_direction_t direction = vio::quic::stream_direction_t::bidirectional)
{
  if (connection.handle.ref_counted() == nullptr)
  {
    return std::unexpected(error_t{.code = -1, .msg = "the connection names nothing"});
  }
  auto &state = connection.handle.data();
  if (state.transport == nullptr)
  {
    return std::unexpected(error_t{.code = vio_quic_connection_closed, .msg = "the connection has ended"});
  }
  const auto opened = state.transport->open_stream(direction);
  if (!opened.has_value())
  {
    return std::unexpected(error_t{.code = vio_quic_busy, .msg = "the peer has granted no more stream credit"});
  }
  auto stream = ref_ptr_t<detail::quic_stream_state_t>(&state, *opened, false);
  state.streams.emplace(*opened, stream);
  return quic_stream_t{std::move(stream)};
}

// Resolves once per stream the peer opens, in the order their first frames
// arrive. Two coroutines may accept at once and both are served, oldest first.
//
// This replaces `readable_streams()`, which could not do the job: that is a list
// of streams with unread bytes *right now* -- a level, not an edge -- so a stream
// that carried a zero-length FIN, or was reset before anything was read, or
// whose bytes have just been consumed, is invisible through it. A stream is
// reported here exactly once, when its first frame arrives, whether or not it
// ever carries a byte.
//
// One caveat worth knowing rather than discovering: the order is first-frame
// arrival, not open order. Section 3.2 opens every lower-numbered stream of the
// same type implicitly, and the transport deliberately materialises state only
// for the id that actually carried a frame -- otherwise one packet naming a high
// index would force an allocation per implied stream. So reordering on the wire
// is visible here.
[[nodiscard]] inline quic_stream_awaitable_t quic_accept_stream(quic_connection_t &connection, cancellation_t *cancel = nullptr)
{
  const auto failed = [](error_t reason)
  {
    auto *op = detail::quic_stream_op_create(nullptr);
    detail::quic_stream_op_finish(*op, std::move(reason));
    return quic_stream_awaitable_t{op};
  };

  if (connection.handle.ref_counted() == nullptr)
  {
    return failed(error_t{.code = -1, .msg = "the connection names nothing"});
  }
  auto &state = connection.handle.data();
  if (state.transport == nullptr)
  {
    return failed(error_t{.code = vio_quic_connection_closed, .msg = "the connection has ended"});
  }
  if (cancel != nullptr && cancel->is_cancelled())
  {
    return failed(error_t{.code = vio_cancelled, .msg = "the accept was cancelled before it began"});
  }

  auto *op = detail::quic_stream_op_create(&state);
  op->accepting = true;
  if (!state.stream_accept_queue.empty())
  {
    // Resolved in the factory, which is the difference between draining a burst
    // of streams on one stack and taking a loop turn for each of them.
    auto stream = std::move(state.stream_accept_queue.front());
    state.stream_accept_queue.pop_front();
    detail::quic_stream_op_finish(*op, std::move(stream));
    return quic_stream_awaitable_t{op};
  }

  state.stream_ops.push_back(op);
  quic_stream_awaitable_t out{op};
  if (cancel != nullptr)
  {
    op->cancel_registration = cancel->register_callback(
      [op]()
      {
        if (op->resolved)
        {
          return;
        }
        auto *owner = op->connection;
        detail::quic_stream_op_finish(*op, error_t{.code = vio_cancelled, .msg = "the operation was cancelled"});
        if (owner != nullptr)
        {
          const auto found = std::find(owner->stream_ops.begin(), owner->stream_ops.end(), op);
          if (found != owner->stream_ops.end())
          {
            owner->stream_ops.erase(found);
            owner->pending_stream_ops.push_back(op);
            if (owner->endpoint != nullptr)
            {
              const auto entry = owner->endpoint->by_connection.find(owner->transport);
              if (entry != owner->endpoint->by_connection.end())
              {
                detail::quic_mark_pending(*owner->endpoint, entry->second);
              }
            }
          }
        }
      });
  }
  return out;
}

// -----------------------------------------------------------------------------
// What a stream is
// -----------------------------------------------------------------------------

[[nodiscard]] inline std::uint64_t quic_stream_id(const quic_stream_t &stream)
{
  return stream.handle.ref_counted() == nullptr ? 0 : stream.handle.data().id;
}

[[nodiscard]] inline vio::quic::stream_direction_t quic_stream_direction(const quic_stream_t &stream)
{
  return stream.handle.ref_counted() == nullptr ? vio::quic::stream_direction_t::bidirectional : stream.handle.data().direction;
}

[[nodiscard]] inline bool quic_stream_is_peer_initiated(const quic_stream_t &stream)
{
  return stream.handle.ref_counted() != nullptr && stream.handle.data().peer_initiated;
}

// Which halves this stream has at this endpoint. Asking is how a protocol that
// uses unidirectional streams avoids suspending for ever on a half that does not
// exist; the operations themselves also refuse rather than pretending to work.
[[nodiscard]] inline bool quic_stream_can_read(const quic_stream_t &stream)
{
  return stream.handle.ref_counted() != nullptr && detail::quic_stream_has_receive(stream.handle.data());
}

[[nodiscard]] inline bool quic_stream_can_write(const quic_stream_t &stream)
{
  return stream.handle.ref_counted() != nullptr && detail::quic_stream_has_send(stream.handle.data());
}

// The connection this stream belongs to, so a coroutine handed nothing but a
// stream can still close, name the peer or read the round trip time. A handle
// naming nothing once the connection's state is gone.
[[nodiscard]] inline quic_connection_t quic_stream_connection(const quic_stream_t &stream)
{
  if (stream.handle.ref_counted() == nullptr || stream.handle->connection == nullptr)
  {
    return {};
  }
  auto *connection = stream.handle->connection;
  if (connection->endpoint == nullptr)
  {
    return {};
  }
  const auto found = connection->endpoint->by_connection.find(connection->transport);
  return found == connection->endpoint->by_connection.end() ? quic_connection_t{} : quic_connection_t{found->second};
}

// The peer's own 62-bit code from a RESET_STREAM or a STOP_SENDING it sent.
// error_t carries an int and is shared across all of vio, so a QUIC application
// error code cannot ride in it: the error says what happened and these say what
// the peer called it, which is what an application protocol branches on --
// H3_REQUEST_CANCELLED means the request may be retried elsewhere and every
// other code does not. Latched, so they survive the stream being reaped.
[[nodiscard]] inline std::optional<std::uint64_t> quic_stream_peer_reset_error(const quic_stream_t &stream)
{
  return stream.handle.ref_counted() == nullptr ? std::nullopt : stream.handle.data().peer_reset_error;
}

[[nodiscard]] inline std::optional<std::uint64_t> quic_stream_peer_stop_sending_error(const quic_stream_t &stream)
{
  return stream.handle.ref_counted() == nullptr ? std::nullopt : stream.handle.data().peer_stop_sending_error;
}

// -----------------------------------------------------------------------------
// Writing
// -----------------------------------------------------------------------------

namespace detail
{
[[nodiscard]] inline quic_stream_write_awaitable_t quic_stream_submit(quic_stream_t &stream, std::span<const std::uint8_t> data, bool fin)
{
  auto *transport = quic_stream_transport(stream);
  if (transport == nullptr)
  {
    return quic_stream_write_awaitable_t{std::unexpected(quic_stream_gone(stream))};
  }
  auto &state = stream.handle.data();
  if (!quic_stream_has_send(state))
  {
    return quic_stream_write_awaitable_t{std::unexpected(error_t{.code = vio_quic_busy, .msg = "this stream has no sending half at this endpoint"})};
  }
  if (state.peer_stop_sending_error.has_value())
  {
    return quic_stream_write_awaitable_t{std::unexpected(error_t{.code = vio_quic_stream_stopped, .msg = "the peer asked this endpoint to stop sending"})};
  }
  if (state.send_ended)
  {
    return quic_stream_write_awaitable_t{std::unexpected(error_t{.code = vio_quic_stream_finished, .msg = "the sending half is already finished"})};
  }

  const auto accepted = transport->write_stream(state.id, data, fin);
  if (accepted != data.size())
  {
    return quic_stream_write_awaitable_t{std::unexpected(error_t{.code = vio_quic_stream_finished, .msg = "the sending half would not take the bytes"})};
  }
  state.bytes_written += accepted;
  state.send_ended = state.send_ended || fin;
  quic_stream_mark(stream);
  return quic_stream_write_awaitable_t{std::expected<void, error_t>{}};
}
} // namespace detail

// Queues bytes on the sending half.
//
// Resolving means the transport owns every byte, not that the peer has them --
// the same sense in which write_tcp resolving means libuv took the bytes. There
// is no useful "sent" in QUIC, since a sent packet may be lost and sent again,
// so the only two honest milestones are "the transport owns it" and "the peer
// acknowledged it".
//
// It resolves with void rather than a byte count, and that is a deliberate
// narrowing rather than a lost feature: connection_t::write_stream returns
// data.size() whether or not anything can be sent, and returns zero for five
// different failures as well as for the success of a FIN-only write. A count
// that means all of it or nothing is the only status a caller can act on.
//
// At this step it never suspends. The awaitable exists so that the write layer
// can add the high-water marks without moving a call site.
[[nodiscard]] inline quic_stream_write_awaitable_t quic_stream_write(quic_stream_t &stream, std::span<const std::uint8_t> data)
{
  return detail::quic_stream_submit(stream, data, false);
}

// The same, and then the FIN.
//
// There is a separate function rather than a bool argument, and the reason is
// not taste: a defaulted bool in front of a trailing cancellation_t* makes
// quic_stream_write(stream, data, &cancel) compile, bind the pointer to the flag
// through the standard conversion, half-close the stream and silently drop the
// cancellation.
//
// Prefer this to a bare quic_stream_finish after the last write: a FIN that
// rides with the bytes it terminates costs no packet, and it removes the window
// in which the peer has the last chunk and does not yet know it was the last.
[[nodiscard]] inline quic_stream_write_awaitable_t quic_stream_write_final(quic_stream_t &stream, std::span<const std::uint8_t> data)
{
  return detail::quic_stream_submit(stream, data, true);
}

// Ends the sending half with a FIN and nothing behind it: the half-close
// ssl_client_shutdown performs, and for the same reason. The receiving half
// stays open.
[[nodiscard]] inline quic_stream_write_awaitable_t quic_stream_finish(quic_stream_t &stream)
{
  return detail::quic_stream_submit(stream, {}, true);
}

// Abandons the sending half; the peer is told with RESET_STREAM and everything
// queued is dropped. Not awaitable, because a reset is a statement and not a
// request. The receiving half is untouched.
inline void quic_stream_reset(quic_stream_t &stream, std::uint64_t error_code)
{
  auto *transport = detail::quic_stream_transport(stream);
  if (transport == nullptr || !quic_stream_can_write(stream))
  {
    return;
  }
  stream.handle->send_ended = true;
  transport->reset_stream(stream.handle->id, error_code);
  detail::quic_stream_mark(stream);
}

// Asks the peer to stop sending, and ends this endpoint's receiving half at
// once: a suspended read resolves immediately with vio_quic_stream_stopped
// rather than waiting a round trip for the peer's answering RESET_STREAM, and
// nothing more is consumed, so the window closes.
//
// That is honest -- the application has said it wants nothing more -- and it is
// what makes a read cancellable in bounded time from a coroutine that does not
// own the reader, which STOP_SENDING alone cannot promise because a peer that
// ignores it keeps sending.
inline void quic_stream_stop_sending(quic_stream_t &stream, std::uint64_t error_code)
{
  auto *transport = detail::quic_stream_transport(stream);
  if (transport == nullptr || !quic_stream_can_read(stream))
  {
    return;
  }
  auto &state = stream.handle.data();
  transport->stop_sending(state.id, error_code);
  state.receive_ended = true;
  state.reader_cancelled = true;
  detail::quic_stream_mark(stream);
  if (state.read_continuation)
  {
    // The reader is parked on this very stack in the ordinary case -- a
    // coroutine that decided mid-read to give up -- so it is queued for the beat
    // rather than resumed here.
    auto *connection = state.connection;
    connection->pending_readers.push_back(std::exchange(state.read_continuation, {}));
    if (connection->endpoint != nullptr)
    {
      const auto found = connection->endpoint->by_connection.find(connection->transport);
      if (found != connection->endpoint->by_connection.end())
      {
        detail::quic_mark_pending(*connection->endpoint, found->second);
      }
    }
  }
}

// -----------------------------------------------------------------------------
// Reading
// -----------------------------------------------------------------------------

namespace detail
{
// Whether a read can be answered right now: bytes waiting, or an ending to
// report. Asked of the transport directly rather than of a queue this layer
// keeps, which is also what stops a reader created inside the beat -- the usual
// case, since that is where an accepted stream is handed over -- from suspending
// past bytes that have already arrived.
[[nodiscard]] inline bool quic_stream_readable(quic_stream_state_t &state)
{
  if (state.reader_cancelled || state.stale || state.connection == nullptr)
  {
    return true;
  }
  auto *transport = state.connection->transport;
  if (transport == nullptr)
  {
    return true;
  }
  return !transport->readable_stream(state.id).empty() || state.receive_ended;
}

[[nodiscard]] inline error_t quic_stream_ending(const quic_stream_state_t &state)
{
  if (state.stale)
  {
    return error_t{.code = vio_quic_stream_stale, .msg = "the peer has reopened this stream id"};
  }
  if (state.reader_cancelled)
  {
    return error_t{.code = vio_quic_stream_stopped, .msg = "this endpoint stopped reading the stream"};
  }
  if (state.receive_reset)
  {
    return error_t{.code = vio_quic_stream_reset, .msg = "the peer reset the stream"};
  }
  if (state.receive_ended)
  {
    return error_t{.code = vio_quic_stream_finished, .msg = "the peer finished the stream"};
  }
  return error_t{.code = vio_quic_connection_closed, .msg = "the connection ended"};
}
} // namespace detail

// One reader per stream, move-only, constructible only through
// quic_stream_create_reader -- the tcp_reader_t shape, down to a destructor that
// undoes exactly what the constructor did.
//
// A read yields one contiguous run, which is what reassembly can hand over
// without a gap, and not everything that has arrived. A loop, not a single call,
// is how a message is read.
//
// One thing to know about resets: a RESET_STREAM discards bytes that arrived in
// the same batch and had not yet been taken. That is what RESET_STREAM means and
// the peer chose it, but it is the one place where the ending does not strictly
// follow every byte the peer ever sent.
class quic_stream_reader_t
{
public:
  quic_stream_reader_t(quic_stream_reader_t &&other) noexcept
    : _handle(std::move(other._handle))
    , _valid(std::exchange(other._valid, false))
  {
  }

  quic_stream_reader_t &operator=(quic_stream_reader_t &&other) noexcept
  {
    if (this != &other)
    {
      detach();
      _handle = std::move(other._handle);
      _valid = std::exchange(other._valid, false);
    }
    return *this;
  }

  quic_stream_reader_t(const quic_stream_reader_t &) = delete;
  quic_stream_reader_t &operator=(const quic_stream_reader_t &) = delete;

  ~quic_stream_reader_t()
  {
    detach();
  }

  // The awaiter holds its own reference to the stream state, so a reader
  // destroyed while a read is suspended does not take the state with it.
  struct awaiter_t
  {
    ref_ptr_t<detail::quic_stream_state_t> state;

    [[nodiscard]] bool await_ready() const noexcept
    {
      return state.ref_counted() == nullptr || detail::quic_stream_readable(const_cast<detail::quic_stream_state_t &>(state.data()));
    }

    void await_suspend(std::coroutine_handle<> continuation) noexcept
    {
      state->read_continuation = continuation;
    }

    [[nodiscard]] std::expected<unique_buf_t, error_t> await_resume() noexcept
    {
      if (state.ref_counted() == nullptr)
      {
        return std::unexpected(error_t{.code = -1, .msg = "the reader names nothing"});
      }
      auto &self = state.data();
      auto *transport = self.connection == nullptr ? nullptr : self.connection->transport;
      if (transport != nullptr && !self.reader_cancelled && !self.stale)
      {
        // Bytes before the ending, always: a loop that reads until it fails has
        // by definition seen everything the peer delivered.
        const auto readable = transport->readable_stream(self.id);
        if (!readable.empty())
        {
          uv_buf_t buffer{};
          default_alloc(nullptr, readable.size(), &buffer);
          std::memcpy(buffer.base, readable.data(), readable.size());
          buffer.len = static_cast<decltype(buffer.len)>(readable.size());
          // Consuming is what returns MAX_STREAM_DATA credit, which is why
          // nothing is taken until an await asks for it.
          transport->consume_stream(self.id, readable.size());
          self.bytes_read += readable.size();
          detail::quic_stream_mark(quic_stream_t{state});
          return unique_buf_t{buffer, default_dealloc, nullptr};
        }
      }
      return std::unexpected(detail::quic_stream_ending(self));
    }
  };

  [[nodiscard]] awaiter_t operator co_await()
  {
    return awaiter_t{_handle};
  }

  // Copies the next contiguous run into the caller's buffer and consumes exactly
  // that much, so a caller with its own storage does not pay for a second one.
  // Zero means the peer finished cleanly, the EOF convention
  // tcp_reader_t::read_into uses; a reset is an error rather than a zero, which
  // is the distinction a byte count alone could never carry.
  //
  // It is not the true scatter read tcp_reader_t::read_into performs, and naming
  // it the same while quietly copying would be worse than saying so: QUIC
  // decrypts in place in the datagram and reassembles out of order into its own
  // storage, so there is no moment at which the kernel could be handed the
  // caller's buffer. What this saves is the allocation, not the copy.
  struct read_into_awaiter_t
  {
    ref_ptr_t<detail::quic_stream_state_t> state;
    std::span<std::uint8_t> destination;

    [[nodiscard]] bool await_ready() const noexcept
    {
      return state.ref_counted() == nullptr || detail::quic_stream_readable(const_cast<detail::quic_stream_state_t &>(state.data()));
    }

    void await_suspend(std::coroutine_handle<> continuation) noexcept
    {
      state->read_continuation = continuation;
    }

    [[nodiscard]] std::expected<std::size_t, error_t> await_resume() noexcept
    {
      if (state.ref_counted() == nullptr)
      {
        return std::unexpected(error_t{.code = -1, .msg = "the reader names nothing"});
      }
      auto &self = state.data();
      auto *transport = self.connection == nullptr ? nullptr : self.connection->transport;
      if (transport != nullptr && !self.reader_cancelled && !self.stale)
      {
        const auto readable = transport->readable_stream(self.id);
        if (!readable.empty() && !destination.empty())
        {
          const auto taken = (std::min)(readable.size(), destination.size());
          std::memcpy(destination.data(), readable.data(), taken);
          transport->consume_stream(self.id, taken);
          self.bytes_read += taken;
          detail::quic_stream_mark(quic_stream_t{state});
          return taken;
        }
      }
      const auto ending = detail::quic_stream_ending(self);
      if (ending.code == vio_quic_stream_finished)
      {
        return std::size_t{0};
      }
      return std::unexpected(ending);
    }
  };

  [[nodiscard]] read_into_awaiter_t read_into(std::span<std::uint8_t> destination)
  {
    return read_into_awaiter_t{_handle, destination};
  }

  // Resolves a suspended read with its ending rather than as a flag the awaiter
  // has to remember to test. Idempotent, and it mirrors the destructor, so
  // calling both is safe.
  void cancel()
  {
    if (_handle.ref_counted() == nullptr)
    {
      return;
    }
    _handle->reader_cancelled = true;
    if (_handle->read_continuation)
    {
      const auto continuation = std::exchange(_handle->read_continuation, {});
      continuation.resume();
    }
  }

  [[nodiscard]] bool is_cancelled() const
  {
    return _handle.ref_counted() != nullptr && _handle->reader_cancelled;
  }

private:
  friend std::expected<quic_stream_reader_t, error_t> quic_stream_create_reader(quic_stream_t &stream);

  explicit quic_stream_reader_t(ref_ptr_t<detail::quic_stream_state_t> handle)
    : _handle(std::move(handle))
    , _valid(true)
  {
    _handle->reader_attached = true;
  }

  void detach()
  {
    if (!_valid || _handle.ref_counted() == nullptr)
    {
      return;
    }
    _valid = false;
    _handle->reader_attached = false;
    _handle->read_continuation = {};
  }

  ref_ptr_t<detail::quic_stream_state_t> _handle = ref_ptr_t<detail::quic_stream_state_t>::null();
  bool _valid = false;
};

// One reader at a time, refused with a message that says what to do about it in
// the style tcp_create_reader uses. Also refused for a stream with no receiving
// half, and for one whose id the peer has reopened.
//
// Until a reader exists nothing is taken out of reassembly, so an accepted
// stream that nobody is reading holds its own credit rather than quietly
// buffering on the application's behalf.
[[nodiscard]] inline std::expected<quic_stream_reader_t, error_t> quic_stream_create_reader(quic_stream_t &stream)
{
  if (stream.handle.ref_counted() == nullptr)
  {
    return std::unexpected(error_t{.code = -1, .msg = "the stream names nothing"});
  }
  auto &state = stream.handle.data();
  if (!detail::quic_stream_has_receive(state))
  {
    return std::unexpected(error_t{.code = vio_quic_busy, .msg = "this stream has no receiving half at this endpoint"});
  }
  if (state.stale)
  {
    return std::unexpected(error_t{.code = vio_quic_stream_stale, .msg = "the peer has reopened this stream id"});
  }
  if (detail::quic_stream_transport(stream) == nullptr)
  {
    // Nothing is buffered on the application's behalf, so once the connection
    // is gone there is nowhere left for a read to come from. Refusing here
    // beats handing back a reader whose every read reports the same ending.
    return std::unexpected(error_t{.code = vio_quic_connection_closed, .msg = "the connection has ended"});
  }
  if (state.reader_attached)
  {
    return std::unexpected(error_t{.code = vio_quic_busy, .msg = "this stream already has a reader; move it rather than making a second one"});
  }
  return quic_stream_reader_t{stream.handle};
}

// -----------------------------------------------------------------------------
// Accounting
// -----------------------------------------------------------------------------

// The accounting the old API could not report at all. queued minus acknowledged
// is how far ahead of the peer this sender has run; blocked_by_stream_credit and
// blocked_by_connection_credit are the answer to "why did my write not leave",
// and they are different answers with different fixes -- one wants a bigger
// initial_max_stream_data_* from the peer, the other a bigger initial_max_data.
struct quic_stream_stats_t
{
  std::uint64_t bytes_written = 0;      // handed to this API
  std::uint64_t bytes_queued = 0;       // handed to the transport
  std::uint64_t bytes_sent = 0;         // on the wire at least once
  std::uint64_t bytes_acknowledged = 0; // the peer has them
  std::uint64_t bytes_read = 0;         // delivered to this application
  std::uint64_t peer_window = 0;        // MAX_STREAM_DATA the peer has granted
  bool blocked_by_stream_credit = false;
  bool blocked_by_connection_credit = false;
  bool fin_queued = false;
};

[[nodiscard]] inline quic_stream_stats_t quic_stream_stats(const quic_stream_t &stream)
{
  quic_stream_stats_t out;
  if (stream.handle.ref_counted() == nullptr)
  {
    return out;
  }
  const auto &state = stream.handle.data();
  out.bytes_written = state.bytes_written;
  out.bytes_read = state.bytes_read;
  auto *transport = detail::quic_stream_transport(stream);
  if (transport == nullptr)
  {
    return out;
  }
  const auto send = transport->stream_send_stats(state.id);
  out.bytes_queued = send.queued;
  out.bytes_sent = send.sent;
  out.bytes_acknowledged = send.acknowledged;
  out.peer_window = send.max_data;
  out.blocked_by_stream_credit = send.blocked_by_stream_limit;
  out.blocked_by_connection_credit = send.blocked_by_connection_limit;
  out.fin_queued = send.fin_queued;
  return out;
}
} // namespace vio
