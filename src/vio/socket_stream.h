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

// uv_tls_stream_t is the TLS byte-duplex driver. It rides libuv's stream API
// (uv_read_start / uv_write on a uv_tcp_t) -- vio issues NO raw recv/send, so
// io_uring/IOCP under libuv is invisible here -- and drives a socket-free
// ssl_engine_t (memory BIOs) as a pure codec:
//
//   inbound:  read_cb -> engine.feed_ciphertext(rbio) -> SSL_read -> plaintext buffer_queue
//   outbound: ssl_*_write -> SSL_write -> drain wbio ciphertext -> uv_write
//
// It presents exactly the member surface the coroutine awaitables below
// (stream_reader_t / stream_read_awaitable_t / stream_write_awaitable_t) need,
// so the public reader/writer API and its semantics (co_await, reader.read(buf)
// exact-fill, cancel/UV_ECANCELED, concurrent per-slot writes) are preserved.

#include <coroutine>
#include <cstring>
#include <expected>
#include <functional>
#include <optional>
#include <queue>
#include <vector>

#include <uv.h>

#include <vio/cancellation.h>
#include <vio/elastic_index_storage.h>
#include <vio/error.h>
#include <vio/ref_counted_wrapper.h>
#include <vio/ring_buffer.h>
#include <vio/ssl_engine.h>
#include <vio/unique_buf.h>

namespace vio
{

// A single application write. The plaintext `buf` is borrowed from the caller
// and kept alive by the suspended awaiter. `ref` is released by the awaitable
// (once) and by the in-flight uv_write (once), so the slot is freed only after
// both are done -- in either order.
struct stream_write_state_t
{
  uv_buf_t buf = {};
  size_t bytes_written = 0; // plaintext consumed by SSL_write
  int error_code = 0;
  // Two holds: one for the awaitable (released in its destructor) and one for the
  // write operation (released exactly once -- by write_cb for an async write, or
  // by finish_write_ok/finish_write_error for a synchronous completion). The slot
  // is deactivated only when both reach zero, so a synchronous completion cannot
  // free the slot out from under the not-yet-constructed awaitable.
  int8_t ref = 2;
  bool done = false;
  bool in_flight = false;
  bool pending_handshake = false;
  std::string error_msg;
  std::coroutine_handle<> continuation = {};
  registration_t cancel_registration; // fires cancel_write(idx) when the caller's cancellation triggers
  // For a vectored write, the coalesced plaintext is owned here so it survives
  // being parked for backpressure (a std::vector move preserves its heap pointer,
  // so this stays valid across write_queue reallocation). Empty for a scalar
  // write, whose plaintext is borrowed via `buf` and kept alive by the suspended
  // awaiter.
  std::vector<char> owned_plain;
};

struct stream_client_buffer_t
{
  uv_buf_t buf;
  size_t capacity;
  dealloc_cb_t dealloc_cb;
};

struct uv_tls_stream_t; // fwd

// One in-flight uv_write of ciphertext (an app write, a handshake flight, or a
// TLS control record). Heap-allocated so it (and its owned ciphertext + the
// uv_write_t) outlive the write regardless of write_queue reallocation.
struct tls_write_op_t
{
  uv_write_t req = {};
  std::vector<uint8_t> cipher;
  uv_tls_stream_t *stream = nullptr;
  bool has_slot = false;
  size_t slot = 0;
};

// ---- exact-fill read awaitable (reader.read(uv_buf_t)) --------------------

template <typename REF_PTR_T, typename STREAM>
struct stream_read_awaitable_t
{
  REF_PTR_T ref_ptr;
  STREAM *stream;

  bool await_ready() noexcept
  {
    assert(ref_ptr && "Invalid state in await_ready");
    return stream->bytes_read == stream->read_buffer.len || stream->read_buffer_error.code;
  }

  void await_suspend(std::coroutine_handle<> continuation) noexcept
  {
    assert(ref_ptr && "Invalid state in await_suspend");
    stream->read_buffer_continuation = continuation;
  }

  auto await_resume() noexcept
  {
    assert(stream && "Invalid state in await_resume");
    std::expected<std::pair<uv_buf_t, dealloc_cb_t>, error_t> ret =
      stream->read_buffer_error.code ? std::expected<std::pair<uv_buf_t, dealloc_cb_t>, error_t>{std::unexpect, stream->read_buffer_error} : std::expected<std::pair<uv_buf_t, dealloc_cb_t>, error_t>{{stream->read_buffer, nullptr}};
    // Leave exact-fill mode so a subsequent plain `co_await reader` uses the queue path.
    stream->read_buffer = uv_buf_t{};
    stream->bytes_read = 0;
    return ret;
  }
};

template <typename REF_PTR_T, typename STREAM>
struct stream_reader_t
{
  REF_PTR_T ref_ptr;
  STREAM *stream;

  stream_reader_t(const REF_PTR_T &ref_ptr, STREAM *stream);
  stream_reader_t(stream_reader_t &&other) noexcept;
  ~stream_reader_t();

  stream_reader_t(const stream_reader_t &) = delete;
  stream_reader_t &operator=(const stream_reader_t &) = delete;

  stream_reader_t &operator=(stream_reader_t &&other) noexcept;

  bool await_ready() noexcept;
  void await_suspend(std::coroutine_handle<> continuation) noexcept;
  auto await_resume() noexcept -> std::expected<unique_buf_t, error_t>;
  void cancel() noexcept;
  [[nodiscard]] bool is_cancelled() const noexcept;
  stream_read_awaitable_t<REF_PTR_T, STREAM> read(uv_buf_t buf);
};

template <typename REF_PTR_T, typename STREAM>
struct stream_write_awaitable_t
{
  REF_PTR_T ref_ptr;
  STREAM *stream;
  size_t write_state_index;

  stream_write_awaitable_t(const REF_PTR_T &ref_ptr, STREAM *stream, size_t write_state_index);
  ~stream_write_awaitable_t();

  stream_write_awaitable_t(const stream_write_awaitable_t &) = delete;
  stream_write_awaitable_t &operator=(const stream_write_awaitable_t &) = delete;

  stream_write_awaitable_t(stream_write_awaitable_t &&) noexcept = default;
  stream_write_awaitable_t &operator=(stream_write_awaitable_t &&) noexcept = default;

  [[nodiscard]] bool await_ready() const noexcept;
  void await_suspend(std::coroutine_handle<> h) noexcept;
  std::expected<void, error_t> await_resume() noexcept;
};

// ---------------------------------------------------------------------------
// uv_tls_stream_t
// ---------------------------------------------------------------------------

struct uv_tls_stream_t
{
  static constexpr size_t read_chunk = 65536;
  static constexpr size_t write_high_water = 1u << 20; // 1 MiB
  static constexpr size_t write_low_water = 1u << 18;  // 256 KiB

  ssl_engine_t &engine;
  alloc_cb_t alloc_cb;
  dealloc_cb_t dealloc_cb;
  void *user_alloc_ptr;

  // Bound after construction (the uv_tcp handle and owning ref-count live in the
  // connection state, which finishes constructing this stream first).
  uv_stream_t *tcp_stream = nullptr;
  reference_counted_t *rc = nullptr;

  // reader-facing state consumed by the awaitables:
  bool reader_active = false;
  bool read_cancelled = false;
  std::coroutine_handle<> read_continuation = {};
  std::coroutine_handle<> read_buffer_continuation = {};
  uv_buf_t read_buffer = {};
  size_t bytes_read = 0;
  error_t read_buffer_error = {};
  ring_buffer_t<std::expected<stream_client_buffer_t, error_t>, 10> buffer_queue;
  elastic_index_storage_t<stream_write_state_t> write_queue;

  // driver state:
  bool read_armed = false;
  bool read_paused = false;
  bool handshaking = false;
  bool peer_closed = false;
  bool closed = false; // teardown started
  std::function<void(std::optional<error_t>)> on_handshake_complete;
  std::vector<size_t> pending_handshake_writes;
  std::queue<size_t> submit_waiters;

  uv_tls_stream_t(ssl_engine_t &engine, alloc_cb_t alloc_cb, dealloc_cb_t dealloc_cb, void *user_alloc_ptr)
    : engine(engine)
    , alloc_cb(alloc_cb)
    , dealloc_cb(dealloc_cb)
    , user_alloc_ptr(user_alloc_ptr)
  {
  }
  uv_tls_stream_t(const uv_tls_stream_t &) = delete;
  uv_tls_stream_t &operator=(const uv_tls_stream_t &) = delete;
  uv_tls_stream_t(uv_tls_stream_t &&) = delete;
  uv_tls_stream_t &operator=(uv_tls_stream_t &&) = delete;

  ~uv_tls_stream_t()
  {
    while (!buffer_queue.empty())
    {
      auto item = buffer_queue.pop_front();
      if (item.has_value() && item.value().dealloc_cb && item.value().buf.base)
      {
        item.value().dealloc_cb(user_alloc_ptr, &item.value().buf);
      }
    }
  }

  void bind(uv_stream_t *stream, reference_counted_t *ref_count)
  {
    tcp_stream = stream;
    rc = ref_count;
    tcp_stream->data = this;
  }

  [[nodiscard]] bool has_buffer_with_data_or_error() const
  {
    if (buffer_queue.empty())
    {
      return false;
    }
    const auto &b = buffer_queue.front();
    if (b.has_value() && b.value().buf.len > 0)
    {
      return true;
    }
    if (!b.has_value() && b.error().code != 0)
    {
      return true;
    }
    return false;
  }

  // ---- reader-driver glue expected by stream_reader_t --------------------

  // Called by the reader constructor. Begin/continue delivering plaintext.
  bool read()
  {
    if (engine.initialized())
    {
      arm_reads();
      pump();
    }
    return true;
  }

  void set_poll_state() {} // no-op under the libuv stream model

  // Called by the reader on every consume (pop / exact-fill drain): decrypt any
  // ciphertext still buffered in rbio into the freed capacity and re-arm socket
  // reads. Does NOT resume continuations (we are inside the consuming coroutine).
  void on_consume()
  {
    if (!engine.initialized() || closed)
    {
      return;
    }
    pump();
    const bool exact_fill_pending = read_buffer.len > 0 && bytes_read < read_buffer.len;
    if (reader_active && read_paused && (!buffer_queue.full() || exact_fill_pending))
    {
      read_paused = false;
      arm_reads();
    }
  }

  // ---- handshake ---------------------------------------------------------

  void begin_handshake()
  {
    handshaking = true;
    arm_reads();
    pump();
  }

  // The reader object was destroyed: stop pulling ciphertext with no consumer.
  void on_reader_gone()
  {
    disarm_reads();
    read_paused = false;
  }

  // Called from the owning state's on_destroy. Best-effort one-way close_notify
  // (its fire-and-forget uv_write parks a ref, deferring final destruction until
  // the flush completes), then stop reads. The engine's SSL*/BIOs are freed by
  // the ssl_engine_t destructor when the state's storage is deleted -- after the
  // close_notify ciphertext has already been copied out of wbio.
  void begin_teardown()
  {
    if (closed)
    {
      return;
    }
    closed = true;
    reader_active = false;
    if (engine.initialized() && engine.is_init_finished() && !engine.shutdown_sent && tcp_stream != nullptr && !uv_is_closing(reinterpret_cast<uv_handle_t *>(tcp_stream)))
    {
      engine.shutdown();
      flush_output();
    }
    disarm_reads();
  }

  // ---- writes ------------------------------------------------------------

  void begin_write(size_t idx)
  {
    if (!engine.initialized())
    {
      finish_write_error(idx, error_t{.code = vio_tls_error, .msg = "TLS engine not initialized"});
      return;
    }
    if (handshaking || !engine.is_init_finished())
    {
      // A write issued before the handshake completes: SSL_write returns
      // WANT_READ; the slot is retried once the handshake finishes.
      pump_write(idx);
      return;
    }
    if (tcp_stream != nullptr && uv_stream_get_write_queue_size(tcp_stream) >= write_high_water)
    {
      submit_waiters.push(idx); // producer backpressure -- awaitable stays suspended
      return;
    }
    pump_write(idx);
  }

  // Vectored write: coalesce several plaintext buffers into a single TLS record
  // (one SSL_write) and one uv_write -- useful for HTTP/2 frame batching. The
  // plaintext is consumed synchronously, so the caller's buffers need not outlive
  // the call.
  void begin_writev(size_t idx, const uv_buf_t *bufs, size_t n)
  {
    if (!engine.initialized() || !engine.is_init_finished())
    {
      finish_write_error(idx, error_t{.code = vio_tls_error, .msg = "Can not writev before the handshake completes"});
      return;
    }
    auto &ws = write_queue[idx];
    ws.buf = uv_buf_t{};
    ws.bytes_written = 0;
    ws.owned_plain.clear();
    size_t total = 0;
    for (size_t i = 0; i < n; ++i)
    {
      total += bufs[i].len;
    }
    if (total == 0)
    {
      finish_write_ok(idx);
      return;
    }
    ws.owned_plain.reserve(total);
    for (size_t i = 0; i < n; ++i)
    {
      ws.owned_plain.insert(ws.owned_plain.end(), bufs[i].base, bufs[i].base + bufs[i].len);
    }
    // Same producer backpressure as begin_write: the coalesced plaintext is owned
    // in the slot, so the write can be parked over the high-water mark and
    // encrypted only when the socket drains -- no unbounded ciphertext buildup.
    if (tcp_stream != nullptr && uv_stream_get_write_queue_size(tcp_stream) >= write_high_water)
    {
      submit_waiters.push(idx);
      return;
    }
    pump_write(idx);
  }

  // Register a cancellation for an in-progress write. Call after begin_write/
  // begin_writev. If the write already completed synchronously, this is a no-op.
  void arm_write_cancel(size_t idx, cancellation_t &cancel)
  {
    if (!write_queue.is_active(idx) || write_queue[idx].done)
    {
      return;
    }
    auto *self = this;
    write_queue[idx].cancel_registration = cancel.register_callback([self, idx]() { self->cancel_write(idx); });
  }

  // Resolve a pending write with vio_cancelled. If a uv_write is already in flight
  // its owned ciphertext stays alive until write_cb (which releases the operation
  // hold); otherwise this releases it. A cancelled TLS write leaves a partial
  // record on the wire, so the caller is expected to close the connection.
  void cancel_write(size_t idx)
  {
    if (!write_queue.is_active(idx) || write_queue[idx].done)
    {
      return;
    }
    bool in_flight = false;
    std::coroutine_handle<> c = {};
    {
      auto &ws = write_queue[idx];
      ws.error_code = vio_cancelled;
      ws.error_msg = "cancelled";
      ws.done = true;
      // Deregister before the caller's coroutine (which owns the cancellation_t)
      // can resume and destroy that token -- otherwise the registration's later
      // destructor would dereference a freed cancellation_t.
      ws.cancel_registration.reset();
      in_flight = ws.in_flight;
      c = ws.continuation;
      ws.continuation = {};
    }
    if (c)
    {
      c.resume(); // may reallocate write_queue -- re-index afterwards
    }
    // A submitted write's operation hold is released by write_cb; for a deferred
    // or never-submitted write, release it here.
    if (!in_flight && write_queue.is_active(idx) && --write_queue[idx].ref == 0)
    {
      write_queue.deactivate(idx);
    }
  }

  // Half-close: send a one-way close_notify and keep reading (HTTP/2 GOAWAY /
  // graceful shutdown). The awaitable resolves when the close_notify is on the wire.
  void begin_shutdown(size_t idx)
  {
    if (!engine.initialized() || !engine.is_init_finished())
    {
      finish_write_error(idx, error_t{.code = vio_tls_error, .msg = "Can not shut down before the handshake completes"});
      return;
    }
    engine.shutdown();
    write_queue[idx].buf = uv_buf_t{};
    write_queue[idx].bytes_written = 0;
    submit_app_write(idx);
  }

private:
  // ---- read pump ---------------------------------------------------------

  void arm_reads()
  {
    if (read_armed || closed || tcp_stream == nullptr)
    {
      return;
    }
    tcp_stream->data = this;
    if (uv_read_start(tcp_stream, alloc_trampoline, read_cb) >= 0)
    {
      read_armed = true;
    }
  }

  void disarm_reads()
  {
    if (!read_armed || tcp_stream == nullptr)
    {
      return;
    }
    uv_read_stop(tcp_stream);
    read_armed = false;
  }

  stream_client_buffer_t *current_read_target()
  {
    if (!buffer_queue.empty())
    {
      auto &last = buffer_queue.back();
      if (last.has_value() && last->buf.len < last->capacity)
      {
        return &last.value();
      }
    }
    if (buffer_queue.full())
    {
      return nullptr;
    }
    uv_buf_t rb;
    alloc_cb(user_alloc_ptr, read_chunk, &rb);
    const auto capacity = rb.len;
    rb.len = 0;
    return &buffer_queue.push(std::expected<stream_client_buffer_t, error_t>{stream_client_buffer_t{rb, capacity, dealloc_cb}}).value();
  }

  void push_read_error(error_t err)
  {
    if (!buffer_queue.empty() && buffer_queue.back().has_value() && buffer_queue.back()->buf.len == 0)
    {
      auto &b = buffer_queue.back().value();
      if (b.dealloc_cb && b.buf.base)
      {
        b.dealloc_cb(user_alloc_ptr, &b.buf);
      }
      buffer_queue.replace_back(std::unexpected(std::move(err)));
    }
    else if (!buffer_queue.full())
    {
      buffer_queue.push(std::unexpected(std::move(err)));
    }
    // else: queue full -- reads are paused; re-detected on the next pump() after consume.
  }

  // Drive the handshake one step. Returns true if the handshake is (now) finished.
  bool drive_handshake()
  {
    const ssl_status st = engine.do_handshake();
    flush_output(); // send any handshake flight
    if (engine.is_init_finished())
    {
      handshaking = false;
      if (on_handshake_complete)
      {
        auto cb = std::move(on_handshake_complete);
        on_handshake_complete = nullptr;
        cb(std::nullopt);
      }
      auto pend = std::move(pending_handshake_writes);
      pending_handshake_writes.clear();
      for (size_t idx : pend)
      {
        if (write_queue.is_active(idx) && !write_queue[idx].done)
        {
          write_queue[idx].pending_handshake = false;
          pump_write(idx);
        }
      }
      if (!reader_active)
      {
        disarm_reads();
      }
      return true;
    }
    if (st == ssl_status::fatal)
    {
      handshaking = false;
      auto err = engine.make_error();
      if (on_handshake_complete)
      {
        auto cb = std::move(on_handshake_complete);
        on_handshake_complete = nullptr;
        cb(err);
      }
      read_buffer_error = err;
      push_read_error(err);
      fail_pending_handshake_writes(err);
    }
    return false; // want_read (or fatal handled above)
  }

  // Decrypt as much plaintext as possible into the exact-fill target or the queue.
  void drive_reads()
  {
    for (;;)
    {
      if (read_buffer.len > 0 && bytes_read < read_buffer.len)
      {
        int n = 0;
        const ssl_status st = engine.read_plaintext(read_buffer.base + bytes_read, static_cast<int>(read_buffer.len - bytes_read), n);
        flush_output();
        if (st == ssl_status::ok)
        {
          bytes_read += static_cast<size_t>(n);
          if (bytes_read == read_buffer.len)
          {
            return;
          }
          continue;
        }
        if (st == ssl_status::want_read)
        {
          return;
        }
        if (st == ssl_status::closed)
        {
          peer_closed = true;
          if (!read_buffer_error.code)
          {
            read_buffer_error = error_t{.code = vio_tls_clean_shutdown, .msg = "TLS connection closed"};
          }
          return;
        }
        read_buffer_error = engine.make_error();
        return;
      }

      stream_client_buffer_t *cur = current_read_target();
      if (cur == nullptr) // queue full -> backpressure
      {
        if (read_armed && !read_paused)
        {
          disarm_reads();
          read_paused = true;
        }
        return;
      }
      int n = 0;
      const ssl_status st = engine.read_plaintext(cur->buf.base + cur->buf.len, static_cast<int>(cur->capacity - cur->buf.len), n);
      flush_output();
      if (st == ssl_status::ok)
      {
        cur->buf.len += static_cast<size_t>(n);
        continue;
      }
      if (st == ssl_status::want_read)
      {
        return;
      }
      if (st == ssl_status::closed)
      {
        peer_closed = true;
        push_read_error(error_t{.code = vio_tls_clean_shutdown, .msg = "TLS connection closed"});
        return;
      }
      push_read_error(engine.make_error());
      return;
    }
  }

  // Handshake-then-fall-through: after the handshake completes inside a read_cb,
  // trailing application data in the same segment is decrypted in the SAME pass.
  void pump()
  {
    if (!engine.initialized())
    {
      return;
    }
    if (handshaking)
    {
      if (!drive_handshake())
      {
        return; // still handshaking or handshake failed
      }
    }
    drive_reads();
  }

  void resume_readers()
  {
    if (read_buffer_continuation && ((read_buffer.len > 0 && bytes_read == read_buffer.len) || read_buffer_error.code))
    {
      auto c = read_buffer_continuation;
      read_buffer_continuation = {};
      c.resume();
      return;
    }
    if (read_buffer.len == 0 && read_continuation && (has_buffer_with_data_or_error() || read_cancelled))
    {
      auto c = read_continuation;
      read_continuation = {};
      c.resume();
    }
  }

  void on_read_error(ssize_t nread)
  {
    error_t err;
    if (nread == UV_EOF)
    {
      err = peer_closed ? error_t{.code = vio_tls_clean_shutdown, .msg = "TLS connection closed"} : error_t{.code = vio_tls_truncated, .msg = "Connection closed by peer"};
    }
    else
    {
      err = error_t{.code = static_cast<int>(nread), .msg = uv_strerror(static_cast<int>(nread))};
    }
    peer_closed = true;
    if (handshaking)
    {
      handshaking = false;
      if (on_handshake_complete)
      {
        auto cb = std::move(on_handshake_complete);
        on_handshake_complete = nullptr;
        cb(err);
      }
    }
    read_buffer_error = err;
    fail_pending_handshake_writes(err);
    push_read_error(std::move(err));
  }

  // ---- write pump --------------------------------------------------------

  void pump_write(size_t idx)
  {
    auto &ws = write_queue[idx];
    // Scalar writes borrow `buf`; vectored writes own the coalesced plaintext.
    const char *src = ws.owned_plain.empty() ? ws.buf.base : ws.owned_plain.data();
    const size_t src_len = ws.owned_plain.empty() ? ws.buf.len : ws.owned_plain.size();
    int n = 0;
    const ssl_status st = engine.write_plaintext(src + ws.bytes_written, static_cast<int>(src_len - ws.bytes_written), n);
    if (st == ssl_status::want_read)
    {
      // Handshake not finished yet -- retry after it completes.
      if (!ws.pending_handshake)
      {
        ws.pending_handshake = true;
        pending_handshake_writes.push_back(idx);
      }
      flush_output();
      if (!handshaking && !engine.is_init_finished())
      {
        handshaking = true;
        arm_reads();
        pump();
      }
      return;
    }
    if (st == ssl_status::fatal)
    {
      finish_write_error(idx, engine.make_error());
      return;
    }
    if (st == ssl_status::closed)
    {
      finish_write_error(idx, error_t{.code = vio_tls_clean_shutdown, .msg = "TLS connection closed"});
      return;
    }
    ws.bytes_written += static_cast<size_t>(n);
    submit_app_write(idx);
  }

  void submit_app_write(size_t idx)
  {
    auto *op = new tls_write_op_t();
    op->stream = this;
    op->has_slot = true;
    op->slot = idx;
    engine.drain_into(op->cipher);
    if (op->cipher.empty())
    {
      // Nothing produced (should not happen for a real write) -- complete it.
      delete op;
      finish_write_ok(idx);
      return;
    }
    op->req.data = op;
    uv_buf_t b = uv_buf_init(reinterpret_cast<char *>(op->cipher.data()), static_cast<unsigned int>(op->cipher.size()));
    write_queue[idx].in_flight = true;
    rc->inc(); // keep the state alive until write_cb (which releases the op hold)
    if (uv_write(&op->req, tcp_stream, &b, 1, write_cb) < 0)
    {
      rc->dec();
      write_queue[idx].in_flight = false;
      delete op;
      finish_write_error(idx, error_t{.code = vio_tls_error, .msg = "uv_write failed"});
    }
  }

  void flush_output()
  {
    if (!engine.has_output() || tcp_stream == nullptr)
    {
      return;
    }
    auto *op = new tls_write_op_t();
    op->stream = this;
    op->has_slot = false;
    engine.drain_into(op->cipher);
    if (op->cipher.empty())
    {
      delete op;
      return;
    }
    op->req.data = op;
    uv_buf_t b = uv_buf_init(reinterpret_cast<char *>(op->cipher.data()), static_cast<unsigned int>(op->cipher.size()));
    rc->inc();
    if (uv_write(&op->req, tcp_stream, &b, 1, write_cb) < 0)
    {
      rc->dec();
      delete op;
    }
  }

  void finish_write_ok(size_t idx)
  {
    auto &ws = write_queue[idx];
    ws.done = true;
    ws.cancel_registration.reset();
    std::coroutine_handle<> c = ws.continuation;
    ws.continuation = {};
    if (c)
    {
      c.resume();
    }
    if (write_queue.is_active(idx) && --write_queue[idx].ref == 0)
    {
      write_queue.deactivate(idx);
    }
  }

  void finish_write_error(size_t idx, error_t err)
  {
    auto &ws = write_queue[idx];
    ws.error_code = err.code != 0 ? err.code : vio_tls_error;
    ws.error_msg = std::move(err.msg);
    ws.done = true;
    ws.cancel_registration.reset();
    std::coroutine_handle<> c = ws.continuation;
    ws.continuation = {};
    if (c)
    {
      c.resume();
    }
    if (write_queue.is_active(idx) && --write_queue[idx].ref == 0)
    {
      write_queue.deactivate(idx);
    }
  }

  // Fail every write parked awaiting handshake completion. Called when the
  // handshake fails or the transport dies before it finishes, so a server that
  // wrote before the handshake completed does not hang forever.
  void fail_pending_handshake_writes(const error_t &err)
  {
    if (pending_handshake_writes.empty())
    {
      return;
    }
    auto pend = std::move(pending_handshake_writes);
    pending_handshake_writes.clear();
    for (size_t idx : pend)
    {
      if (write_queue.is_active(idx) && !write_queue[idx].done)
      {
        write_queue[idx].pending_handshake = false;
        finish_write_error(idx, err);
      }
    }
  }

  void drain_waiters()
  {
    if (closed)
    {
      return;
    }
    while (!submit_waiters.empty() && tcp_stream != nullptr && uv_stream_get_write_queue_size(tcp_stream) < write_low_water)
    {
      const size_t idx = submit_waiters.front();
      submit_waiters.pop();
      if (write_queue.is_active(idx) && !write_queue[idx].done)
      {
        pump_write(idx);
      }
    }
  }

  // ---- libuv trampolines -------------------------------------------------

  static void alloc_trampoline(uv_handle_t *h, size_t suggested, uv_buf_t *buf)
  {
    auto *self = static_cast<uv_tls_stream_t *>(h->data);
    self->alloc_cb(self->user_alloc_ptr, suggested, buf);
  }

  static void read_cb(uv_stream_t *h, ssize_t nread, const uv_buf_t *buf)
  {
    auto *self = static_cast<uv_tls_stream_t *>(h->data);
    if (self == nullptr)
    {
      return;
    }
    self->rc->inc(); // keep the state alive for the whole callback
    if (nread == 0)
    {
      if (buf != nullptr && buf->base != nullptr)
      {
        self->dealloc_cb(self->user_alloc_ptr, const_cast<uv_buf_t *>(buf));
      }
      self->rc->dec();
      return;
    }
    if (nread < 0)
    {
      if (buf != nullptr && buf->base != nullptr)
      {
        self->dealloc_cb(self->user_alloc_ptr, const_cast<uv_buf_t *>(buf));
      }
      self->disarm_reads();
      self->on_read_error(nread);
      self->resume_readers();
      self->rc->dec();
      return;
    }
    self->engine.feed_ciphertext(buf->base, static_cast<size_t>(nread));
    if (buf != nullptr && buf->base != nullptr)
    {
      self->dealloc_cb(self->user_alloc_ptr, const_cast<uv_buf_t *>(buf));
    }
    self->pump();
    self->resume_readers();
    self->rc->dec(); // final -- may destroy the state
  }

  static void write_cb(uv_write_t *req, int status)
  {
    auto *op = static_cast<tls_write_op_t *>(req->data);
    auto *self = op->stream;
    reference_counted_t *rc = self->rc;

    if (op->has_slot)
    {
      const size_t idx = op->slot;
      if (self->write_queue.is_active(idx))
      {
        {
          auto &ws = self->write_queue[idx];
          ws.in_flight = false;
          if (status < 0 && ws.error_code == 0)
          {
            ws.error_code = status;
            ws.error_msg = uv_strerror(status);
          }
          ws.done = true;
          ws.cancel_registration.reset();
        }
        std::coroutine_handle<> c = {};
        {
          auto &ws = self->write_queue[idx];
          c = ws.continuation;
          ws.continuation = {};
        }
        if (c)
        {
          c.resume(); // may reallocate write_queue -- do not hold a slot ref across this
        }
        if (self->write_queue.is_active(idx) && --self->write_queue[idx].ref == 0)
        {
          self->write_queue.deactivate(idx);
        }
      }
    }
    // Re-evaluate producer backpressure after ANY write completes -- including a
    // control/handshake (has_slot == false) write, which may be what drops the
    // uv write queue below the low-water mark.
    self->drain_waiters();

    delete op;
    rc->dec(); // final -- may destroy the state
  }

};

// ---- stream_reader_t definitions ------------------------------------------

template <typename REF_PTR_T, typename STREAM>
stream_reader_t<REF_PTR_T, STREAM>::stream_reader_t(const REF_PTR_T &ref_ptr, STREAM *stream)
  : ref_ptr(ref_ptr)
  , stream(stream)
{
  stream->reader_active = true;
  stream->read();
  stream->set_poll_state();
}

template <typename REF_PTR_T, typename STREAM>
stream_reader_t<REF_PTR_T, STREAM>::stream_reader_t(stream_reader_t &&other) noexcept
  : ref_ptr(std::move(other.ref_ptr))
  , stream(other.stream)
{
  assert(ref_ptr && "Invalid state in move constructor");
  other.stream = nullptr;
}

template <typename REF_PTR_T, typename STREAM>
stream_reader_t<REF_PTR_T, STREAM> &stream_reader_t<REF_PTR_T, STREAM>::operator=(stream_reader_t<REF_PTR_T, STREAM> &&other) noexcept
{
  if (this != &other)
  {
    assert(other.ref_ptr && "Invalid state in move assignment");
    ref_ptr = std::move(other.ref_ptr);
    stream = other.stream;
    other.stream = nullptr;
  }
  return *this;
}

template <typename REF_PTR_T, typename STREAM>
stream_reader_t<REF_PTR_T, STREAM>::~stream_reader_t()
{
  if (!ref_ptr)
  {
    return;
  }
  stream->reader_active = false;
  stream->on_reader_gone();
}

template <typename REF_PTR_T, typename STREAM>
bool stream_reader_t<REF_PTR_T, STREAM>::await_ready() noexcept
{
  assert(ref_ptr && "Invalid state in await_ready");
  return stream->read_cancelled || stream->has_buffer_with_data_or_error();
}

template <typename REF_PTR_T, typename STREAM>
void stream_reader_t<REF_PTR_T, STREAM>::await_suspend(std::coroutine_handle<> continuation) noexcept
{
  assert(ref_ptr && "Invalid state in await_suspend");
  stream->read_continuation = continuation;
}

template <typename REF_PTR_T, typename STREAM>
auto stream_reader_t<REF_PTR_T, STREAM>::await_resume() noexcept -> std::expected<unique_buf_t, error_t>
{
  assert(ref_ptr && "Invalid state in await_resume");
  if (stream->read_cancelled)
  {
    return std::unexpected(error_t{.code = UV_ECANCELED, .msg = "Operation was cancelled"});
  }
  assert(stream->has_buffer_with_data_or_error() && "Empty buffer in await_resume");
  auto ret = stream->buffer_queue.pop_front();
  stream->on_consume();
  if (!ret.has_value())
  {
    return std::unexpected(ret.error());
  }
  return unique_buf_t(ret.value().buf, ret.value().dealloc_cb, stream->user_alloc_ptr);
}

template <typename REF_PTR_T, typename STREAM>
void stream_reader_t<REF_PTR_T, STREAM>::cancel() noexcept
{
  assert(ref_ptr && "Invalid state in cancel");
  if (stream->read_cancelled)
  {
    return;
  }
  stream->read_cancelled = true;
  if (stream->read_continuation)
  {
    auto continuation = stream->read_continuation;
    stream->read_continuation = {};
    continuation.resume();
  }
}

template <typename REF_PTR_T, typename STREAM>
bool stream_reader_t<REF_PTR_T, STREAM>::is_cancelled() const noexcept
{
  assert(ref_ptr && "Invalid state in is_cancelled");
  return stream->read_cancelled;
}

template <typename REF_PTR_T, typename STREAM>
stream_read_awaitable_t<REF_PTR_T, STREAM> stream_reader_t<REF_PTR_T, STREAM>::read(uv_buf_t buf)
{
  stream->read_buffer = buf;
  stream->bytes_read = 0;

  while (!stream->buffer_queue.empty() && stream->bytes_read < buf.len)
  {
    if (!stream->buffer_queue.front().has_value())
    {
      break; // an error entry -- leave it to be surfaced by the next co_await
    }
    auto &queued = stream->buffer_queue.front().value();
    using to_copy_t = decltype(buf.len);
    auto to_copy = std::min(queued.buf.len, buf.len - to_copy_t(stream->bytes_read));
    std::memcpy(buf.base + stream->bytes_read, queued.buf.base, to_copy);
    stream->bytes_read += to_copy;

    if (to_copy == queued.buf.len)
    {
      if (queued.dealloc_cb)
      {
        queued.dealloc_cb(stream->user_alloc_ptr, &queued.buf);
      }
      stream->buffer_queue.discard_front();
    }
    else
    {
      queued.buf.base += to_copy;
      queued.buf.len -= to_copy;
    }
  }

  stream->on_consume();
  return {ref_ptr, stream};
}

// ---- stream_write_awaitable_t definitions ---------------------------------

template <typename REF_PTR_T, typename STREAM>
stream_write_awaitable_t<REF_PTR_T, STREAM>::stream_write_awaitable_t(const REF_PTR_T &ref_ptr, STREAM *stream, size_t write_state_index)
  : ref_ptr(ref_ptr)
  , stream(stream)
  , write_state_index(write_state_index)
{
}

template <typename REF_PTR_T, typename STREAM>
stream_write_awaitable_t<REF_PTR_T, STREAM>::~stream_write_awaitable_t()
{
  if (!ref_ptr)
  {
    return;
  }
  if (!stream->write_queue.is_active(write_state_index))
  {
    return;
  }
  auto &write_state = stream->write_queue[write_state_index];
  // Never resume a coroutine whose awaiter is going away (the write may still be
  // in flight -- write_cb will release the op's ref and free the slot).
  write_state.continuation = {};
  if (--write_state.ref == 0)
  {
    stream->write_queue.deactivate(write_state_index);
  }
}

template <typename REF_PTR_T, typename STREAM>
[[nodiscard]] bool stream_write_awaitable_t<REF_PTR_T, STREAM>::await_ready() const noexcept
{
  if (!ref_ptr)
  {
    return true;
  }
  auto &write_state = stream->write_queue[write_state_index];
  return write_state.done || write_state.error_code != 0;
}

template <typename REF_PTR_T, typename STREAM>
void stream_write_awaitable_t<REF_PTR_T, STREAM>::await_suspend(std::coroutine_handle<> h) noexcept
{
  if (!ref_ptr)
  {
    return;
  }
  stream->write_queue[write_state_index].continuation = h;
}

template <typename REF_PTR_T, typename STREAM>
std::expected<void, error_t> stream_write_awaitable_t<REF_PTR_T, STREAM>::await_resume() noexcept
{
  if (!ref_ptr)
  {
    return {};
  }
  auto &write_state = stream->write_queue[write_state_index];
  if (write_state.error_code != 0)
  {
    return std::unexpected(error_t{write_state.error_code, write_state.error_msg});
  }
  return {};
}

} // namespace vio
