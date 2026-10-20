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

#include <algorithm>
#include <cassert>
#include <coroutine>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <functional>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include <vio/cancellation.h>
#include <vio/detail/exceptions.h>
#include <vio/detail/sys.h>
#include <vio/errc.h>
#include <vio/error.h>
#include <vio/loop/loop_core.h>
#include <vio/loop/socket.h>
#include <vio/ref_counted_wrapper.h>
#include <vio/ring_buffer.h>
#include <vio/ssl_engine.h>
#include <vio/unique_buf.h>

namespace vio
{
enum class stream_write_kind : std::uint8_t
{
  data,
  shutdown
};

struct stream_write_state_t
{
  const std::byte *data = nullptr;
  std::size_t size = 0;
  std::size_t bytes_written = 0;
  std::uint64_t cipher_end = 0;
  std::vector<std::byte> owned_plain;
  int error_code = 0;
  std::int8_t ref = 2;
  bool done = false;
  bool active = false;
  stream_write_kind kind = stream_write_kind::data;
  std::string error_msg;
  std::coroutine_handle<> continuation = {};
  registration_t cancel_registration;
};

class stream_write_slots_t
{
public:
  std::size_t activate()
  {
    std::size_t index = 0;
    if (!_free.empty())
    {
      index = _free.back();
      _free.pop_back();
    }
    else
    {
      index = _slots.size();
      _slots.emplace_back();
    }
    _slots[index].active = true;
    return index;
  }

  void deactivate(std::size_t index)
  {
    _slots[index] = stream_write_state_t{};
    _free.push_back(index);
  }

  [[nodiscard]] bool is_active(std::size_t index) const noexcept
  {
    return index < _slots.size() && _slots[index].active;
  }

  stream_write_state_t &operator[](std::size_t index) noexcept
  {
    assert(is_active(index) && "Invalid write slot");
    return _slots[index];
  }

  const stream_write_state_t &operator[](std::size_t index) const noexcept
  {
    assert(is_active(index) && "Invalid write slot");
    return _slots[index];
  }

  [[nodiscard]] std::size_t size() const noexcept
  {
    return _slots.size();
  }

private:
  std::vector<stream_write_state_t> _slots;
  std::vector<std::size_t> _free;
};

class stream_index_fifo_t
{
public:
  [[nodiscard]] bool empty() const noexcept
  {
    return _head == _items.size();
  }

  [[nodiscard]] std::size_t front() const noexcept
  {
    return _items[_head];
  }

  void push(std::size_t value)
  {
    _items.push_back(value);
  }

  void pop() noexcept
  {
    ++_head;
    settle();
  }

  bool remove(std::size_t value) noexcept
  {
    auto it = std::find(_items.begin() + static_cast<std::ptrdiff_t>(_head), _items.end(), value);
    if (it == _items.end())
      return false;
    _items.erase(it);
    settle();
    return true;
  }

  void clear() noexcept
  {
    _items.clear();
    _head = 0;
  }

private:
  void settle() noexcept
  {
    if (_head == _items.size())
    {
      _items.clear();
      _head = 0;
    }
    else if (_head >= 64 && _head * 2 >= _items.size())
    {
      _items.erase(_items.begin(), _items.begin() + static_cast<std::ptrdiff_t>(_head));
      _head = 0;
    }
  }

  std::vector<std::size_t> _items;
  std::size_t _head = 0;
};

template <typename REF_PTR_T, typename STREAM>
struct stream_read_awaitable_t
{
  REF_PTR_T ref_ptr;
  STREAM *stream = nullptr;
  std::span<std::byte> target;

  stream_read_awaitable_t(const REF_PTR_T &ref_ptr, STREAM *stream, std::span<std::byte> target)
    : ref_ptr(ref_ptr)
    , stream(stream)
    , target(target)
  {
  }

  stream_read_awaitable_t(stream_read_awaitable_t &&other) noexcept
    : ref_ptr(std::move(other.ref_ptr))
    , stream(std::exchange(other.stream, nullptr))
    , target(other.target)
  {
  }

  stream_read_awaitable_t(const stream_read_awaitable_t &) = delete;
  stream_read_awaitable_t &operator=(const stream_read_awaitable_t &) = delete;
  stream_read_awaitable_t &operator=(stream_read_awaitable_t &&) = delete;

  ~stream_read_awaitable_t()
  {
    if (ref_ptr && stream != nullptr)
      stream->abandon_exact_fill(target);
  }

  bool await_ready() noexcept
  {
    return stream == nullptr || stream->exact_fill_ready();
  }

  void await_suspend(std::coroutine_handle<> continuation) noexcept
  {
    stream->read_buffer_continuation = continuation;
    stream->on_wait();
  }

  std::expected<std::span<std::byte>, error_t> await_resume() noexcept
  {
    if (stream == nullptr)
      return std::unexpected(make_error(errc::bad_descriptor));
    auto *owner = std::exchange(stream, nullptr);
    return owner->finish_exact_fill();
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
  stream_read_awaitable_t<REF_PTR_T, STREAM> read(std::span<std::byte> buf);
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

  stream_write_awaitable_t(stream_write_awaitable_t &&other) noexcept;
  stream_write_awaitable_t &operator=(stream_write_awaitable_t &&other) noexcept;

  [[nodiscard]] bool await_ready() const noexcept;
  void await_suspend(std::coroutine_handle<> h) noexcept;
  std::expected<void, error_t> await_resume() noexcept;

private:
  void release() noexcept;
};

struct tls_stream_t
{
  static constexpr size_t read_chunk = 65536;
  static constexpr size_t write_high_water = 1u << 20;
  static constexpr size_t write_low_water = 1u << 18;
  static constexpr size_t write_slice = 65536;
  static constexpr int read_budget = 16;
  static constexpr std::int64_t teardown_linger_ns = 10'000'000'000;
  static constexpr std::int64_t linger_after_fin_ns = 2'000'000'000;
  static constexpr size_t linger_discard_chunk = 16384;
  static constexpr int linger_discard_budget = 64;
  static constexpr std::int64_t output_trim_ns = 1'000'000'000;
  static_assert(ssl_engine_t::output_retain >= write_slice + write_slice / 16 + 1024);

  ssl_engine_t &engine;
  alloc_cb_t alloc_cb;
  dealloc_cb_t dealloc_cb;
  void *user_alloc_ptr;

  detail::socket_resource_t *socket = nullptr;
  reference_counted_t *rc = nullptr;

  bool reader_active = false;
  bool read_cancelled = false;
  std::coroutine_handle<> read_continuation = {};
  std::coroutine_handle<> read_buffer_continuation = {};
  std::span<std::byte> read_buffer = {};
  size_t bytes_read = 0;
  std::optional<error_t> read_error;
  ring_buffer_t<unique_buf_t, 10> buffer_queue;
  size_t front_offset = 0;
  stream_write_slots_t write_queue;

  bool handshaking = false;
  bool peer_closed = false;
  bool closed = false;
  std::function<void(std::optional<error_t>)> on_handshake_complete;

  tls_stream_t(ssl_engine_t &engine, alloc_cb_t alloc_cb, dealloc_cb_t dealloc_cb, void *user_alloc_ptr)
    : engine(engine)
    , alloc_cb(alloc_cb)
    , dealloc_cb(dealloc_cb)
    , user_alloc_ptr(user_alloc_ptr)
  {
    _read_op.owner = this;
    _read_op.complete = &tls_stream_t::on_read_ready;
    _write_op.owner = this;
    _write_op.complete = &tls_stream_t::on_write_ready;
    _kick.owner = this;
    _kick.run = &tls_stream_t::on_kick;
    _kick.discard = &tls_stream_t::on_kick_discard;
    _linger.owner = this;
    _linger.fire = &tls_stream_t::on_linger;
    _output_trim.owner = this;
    _output_trim.fire = &tls_stream_t::on_output_trim;
    _output_trim.keeps_alive = false;
  }
  tls_stream_t(const tls_stream_t &) = delete;
  tls_stream_t &operator=(const tls_stream_t &) = delete;
  tls_stream_t(tls_stream_t &&) = delete;
  tls_stream_t &operator=(tls_stream_t &&) = delete;

  ~tls_stream_t()
  {
    if (socket != nullptr)
    {
      if (_read_op.parked)
        socket->cancel(_read_op);
      if (_write_op.parked)
        socket->cancel(_write_op);
    }
    if (_core != nullptr && _linger.armed())
      _core->remove_timer(_linger);
    std::int64_t trim_due = 0;
    if (_core != nullptr && _output_trim.armed())
    {
      trim_due = _output_trim.deadline;
      _core->remove_timer(_output_trim);
    }
    if (_pooled)
    {
      unlink_pooled();
      auto &pool = detail::ssl_output_pool();
      if (pool.release_trim(this) && _pooled_core->tls_streams() != nullptr)
        static_cast<tls_stream_t *>(_pooled_core->tls_streams())->arm_output_trim(trim_due);
      pool.detach();
    }
  }

  void bind(detail::socket_resource_t &resource, reference_counted_t *ref_count)
  {
    socket = &resource;
    rc = ref_count;
    _core = &resource.loop();
    if (!_pooled)
    {
      _pooled = true;
      detail::ssl_output_pool().attach();
    }
    else if (_pooled_core == _core)
      return;
    else
      unlink_pooled();
    _pooled_core = _core;
    auto *head = static_cast<tls_stream_t *>(_core->tls_streams());
    _pooled_prev = nullptr;
    _pooled_next = head;
    if (head != nullptr)
      head->_pooled_prev = this;
    _core->tls_streams() = this;
  }

  [[nodiscard]] bool has_front_data() const
  {
    return !buffer_queue.empty() && buffer_queue.front().size() > front_offset;
  }

  [[nodiscard]] bool has_buffer_with_data_or_error() const
  {
    return has_front_data() || read_error.has_value();
  }

  [[nodiscard]] size_t pending_write_bytes() const noexcept
  {
    return engine.output_size();
  }

  void start_reading()
  {
    if (!engine.initialized() || closed)
      return;
    user_progress();
  }

  void on_consume()
  {
    if (!engine.initialized() || closed)
      return;
    user_progress();
  }

  void on_wait()
  {
    if (closed || socket == nullptr)
      return;
    if (_read_op.parked)
    {
      if (!_read_op.keeps_alive)
      {
        socket->cancel(_read_op);
        park_read();
      }
      return;
    }
    if (wants_socket_read())
      schedule();
  }

  void begin_handshake()
  {
    handshaking = true;
    user_progress();
  }

  void on_reader_gone()
  {
    reader_active = false;
    read_continuation = {};
    abandon_exact_fill();
    stop_reading_if_unwanted();
  }

  void cancel_reads()
  {
    if (read_cancelled)
      return;
    read_cancelled = true;
    stop_reading_if_unwanted();
    auto plain = std::exchange(read_continuation, {});
    auto exact = std::exchange(read_buffer_continuation, {});
    if (plain)
      plain.resume();
    if (exact)
      exact.resume();
  }

  [[nodiscard]] bool exact_fill_ready() const noexcept
  {
    return read_cancelled || bytes_read >= read_buffer.size() || read_error.has_value();
  }

  void abandon_exact_fill() noexcept
  {
    read_buffer = {};
    bytes_read = 0;
    read_buffer_continuation = {};
  }

  void abandon_exact_fill(std::span<std::byte> target) noexcept
  {
    if (read_buffer.data() == target.data() && read_buffer.size() == target.size())
      abandon_exact_fill();
  }

  std::expected<std::span<std::byte>, error_t> finish_exact_fill()
  {
    auto target = read_buffer;
    bool filled = bytes_read >= target.size();
    abandon_exact_fill();
    if (filled)
      return target;
    if (read_cancelled)
      return std::unexpected(error_t{.code = errc::canceled, .msg = "Operation was cancelled"});
    if (read_error)
      return std::unexpected(*read_error);
    return std::unexpected(make_error(errc::canceled));
  }

  void begin_exact_fill(std::span<std::byte> target)
  {
    read_buffer = target;
    bytes_read = 0;
    while (bytes_read < target.size() && has_front_data())
    {
      auto &queued = buffer_queue.front();
      auto available = queued.size() - front_offset;
      auto to_copy = (std::min)(available, target.size() - bytes_read);
      std::memcpy(target.data() + bytes_read, queued.data() + front_offset, to_copy);
      bytes_read += to_copy;
      if (to_copy == available)
      {
        buffer_queue.discard_front();
        front_offset = 0;
      }
      else
      {
        front_offset += to_copy;
      }
    }
    on_consume();
  }

  unique_buf_t take_front()
  {
    auto buffer = buffer_queue.pop_front();
    if (front_offset > 0)
    {
      auto remaining = buffer.size() - front_offset;
      std::memmove(buffer.data(), buffer.data() + front_offset, remaining);
      buffer.resize(remaining);
      front_offset = 0;
    }
    return buffer;
  }

  void begin_teardown()
  {
    if (closed)
      return;
    closed = true;
    reader_active = false;
    read_continuation = {};
    abandon_exact_fill();
    on_handshake_complete = nullptr;
    _handshake_notify = false;
    _completed.clear();
    if (socket == nullptr)
      return;
    if (_read_op.parked)
      socket->cancel(_read_op);
    if (!socket->is_open() || _write_error != 0 || !engine.initialized())
    {
      drop_writes();
      return;
    }
    if (!engine.is_init_finished())
      drop_backlog();
    pump_writes();
    flush_out();
    if (teardown_settled())
    {
      drop_writes();
      discard_inbound();
      return;
    }
    _lingering = true;
    rc->inc();
    _core->add_timer(_linger, detail::loop_core_t::deadline_after(teardown_linger_ns));
    linger_read();
  }

  void abandon_handshake()
  {
    if (closed)
      return;
    handshaking = false;
    on_handshake_complete = nullptr;
    _handshake_notify = false;
    if (_write_error == 0)
      on_write_failure(errc::not_connected);
    set_read_error(make_error(errc::not_connected));
    after_user_call();
  }

  void begin_write(size_t idx)
  {
    auto &ws = write_queue[idx];
    if (!engine.initialized())
    {
      complete_slot(idx, vio_tls_error, "TLS engine not initialized");
      return;
    }
    if (closed || _write_error != 0)
    {
      complete_slot(idx, _write_error != 0 ? _write_error : errc::bad_descriptor, error_message(_write_error != 0 ? _write_error : errc::bad_descriptor));
      return;
    }
    if (ws.size == 0)
    {
      complete_slot(idx, 0, {});
      return;
    }
    _backlog.push(idx);
    pump_writes();
    after_user_call();
  }

  void begin_writev(size_t idx, std::span<const std::span<const std::byte>> buffers)
  {
    if (!engine.initialized() || !engine.is_init_finished())
    {
      complete_slot(idx, vio_tls_error, "Can not writev before the handshake completes");
      return;
    }
    size_t total = 0;
    for (const auto &buffer : buffers)
    {
      if (buffer.size() > (std::numeric_limits<size_t>::max)() - total)
      {
        complete_slot(idx, errc::invalid_argument, error_message(errc::invalid_argument));
        return;
      }
      total += buffer.size();
    }
    auto &ws = write_queue[idx];
    ws.owned_plain.clear();
    ws.owned_plain.reserve(total);
    for (const auto &buffer : buffers)
      ws.owned_plain.insert(ws.owned_plain.end(), buffer.begin(), buffer.end());
    ws.data = ws.owned_plain.data();
    ws.size = ws.owned_plain.size();
    ws.bytes_written = 0;
    begin_write(idx);
  }

  void arm_write_cancel(size_t idx, cancellation_t &cancel)
  {
    if (!write_queue.is_active(idx))
      return;
    auto *self = this;
    write_queue[idx].cancel_registration = cancel.register_callback([self, idx]() { self->cancel_write(idx); });
  }

  void cancel_write(size_t idx)
  {
    if (!write_queue.is_active(idx))
      return;
    std::coroutine_handle<> continuation = {};
    bool queued = false;
    {
      auto &ws = write_queue[idx];
      ws.cancel_registration.reset();
      if (ws.done && ws.continuation)
        return;
      if (ws.error_code == 0)
      {
        ws.error_code = vio_cancelled;
        ws.error_msg = "cancelled";
      }
      continuation = std::exchange(ws.continuation, {});
      if (!ws.done)
      {
        ws.done = true;
        queued = _backlog.remove(idx);
        if (!queued && !in_flight(idx))
          queued = true;
      }
    }
    auto *count = continuation ? rc : nullptr;
    if (count != nullptr)
      count->inc();
    if (continuation)
      continuation.resume();
    if (queued && write_queue.is_active(idx))
      release_op_hold(idx);
    if (count != nullptr)
      count->dec();
  }

  void begin_shutdown(size_t idx)
  {
    if (!engine.initialized() || !engine.is_init_finished())
    {
      complete_slot(idx, vio_tls_error, "Can not shut down before the handshake completes");
      return;
    }
    if (closed || _write_error != 0)
    {
      complete_slot(idx, _write_error != 0 ? _write_error : errc::bad_descriptor, error_message(_write_error != 0 ? _write_error : errc::bad_descriptor));
      return;
    }
    write_queue[idx].kind = stream_write_kind::shutdown;
    _backlog.push(idx);
    pump_writes();
    after_user_call();
  }

  void abandon_write(size_t idx)
  {
    auto &ws = write_queue[idx];
    ws.continuation = {};
    ws.cancel_registration.reset();
    if (!ws.done && ws.kind == stream_write_kind::data && ws.bytes_written < ws.size && (ws.owned_plain.empty() || ws.data != ws.owned_plain.data()))
    {
      VIO_TRY
      {
        std::vector<std::byte> copy(ws.data + ws.bytes_written, ws.data + ws.size);
        ws.owned_plain = std::move(copy);
        ws.data = ws.owned_plain.data();
        ws.size = ws.owned_plain.size();
        ws.bytes_written = 0;
      }
      VIO_CATCH_ALL
      {
        _backlog.remove(idx);
        ws.done = true;
        ws.ref--;
      }
    }
    release_op_hold(idx);
  }

private:
  [[nodiscard]] bool exact_fill_pending() const noexcept
  {
    return bytes_read < read_buffer.size() && !read_cancelled;
  }

  [[nodiscard]] bool read_is_awaited() const noexcept
  {
    return handshaking || _write_wants_read || static_cast<bool>(read_continuation) || static_cast<bool>(read_buffer_continuation);
  }

  [[nodiscard]] bool wants_socket_read() const
  {
    if (closed || _read_eof || read_error || socket == nullptr || !socket->is_open() || !engine.initialized())
      return false;
    if (handshaking || _write_wants_read || exact_fill_pending())
      return true;
    return reader_active && !read_cancelled && !buffer_queue.full();
  }

  [[nodiscard]] bool in_flight(size_t idx) const noexcept
  {
    return write_queue[idx].cipher_end != 0 || write_queue[idx].kind == stream_write_kind::shutdown;
  }

  void stop_reading_if_unwanted()
  {
    if (socket != nullptr && _read_op.parked && !wants_socket_read())
      socket->cancel(_read_op);
  }

  void set_read_error(error_t error)
  {
    if (!read_error)
      read_error = std::move(error);
    stop_reading_if_unwanted();
  }

  void park_read()
  {
    if (_read_op.parked)
      return;
    _read_op.keeps_alive = read_is_awaited();
    socket->wait(detail::interest_read, _read_op);
  }

  void park_write()
  {
    if (_write_op.parked)
      return;
    _write_op.keeps_alive = true;
    socket->wait(detail::interest_write, _write_op);
  }

  void schedule()
  {
    if (_core == nullptr || rc == nullptr || _kick.queued)
      return;
    rc->inc();
    _core->defer(_kick);
  }

  void user_progress()
  {
    process_inbound();
    after_user_call();
  }

  void after_user_call()
  {
    if (closed)
      return;
    if (wants_socket_read() && !_read_op.parked)
    {
      schedule();
      return;
    }
    if (!_notifying && has_eligible())
      schedule();
  }

  [[nodiscard]] bool has_eligible() const
  {
    if (_handshake_notify || !_completed.empty())
      return true;
    if (read_buffer_continuation && exact_fill_ready())
      return true;
    return read_continuation && (read_cancelled || has_buffer_with_data_or_error());
  }

  void service()
  {
    if (closed)
    {
      linger_read();
      flush_out();
      pump_writes();
      if (_lingering && teardown_settled())
        settle_linger();
      return;
    }
    flush_out();
    pump_writes();
    read_socket();
    notify();
  }

  void read_socket()
  {
    process_inbound();
    int budget = read_budget;
    while (wants_socket_read() && !_read_op.parked)
    {
      if (budget-- == 0)
      {
        schedule();
        return;
      }
      auto space = engine.inbound_space(read_chunk);
      if (space.empty())
        return;
      auto received = detail::socket_recv(socket->native(), space);
      if (received == errc::again)
      {
        engine.release_inbound_if_empty();
        park_read();
        return;
      }
      if (received <= 0)
      {
        on_read_end(static_cast<int>(received));
        return;
      }
      engine.commit_inbound(static_cast<size_t>(received));
      process_inbound();
    }
  }

  void process_inbound()
  {
    if (!engine.initialized() || closed)
      return;
    if (handshaking && !drive_handshake())
    {
      flush_out();
      return;
    }
    if (_write_wants_read)
    {
      _write_wants_read = false;
      pump_writes();
    }
    drive_reads();
    flush_out();
  }

  bool drive_handshake()
  {
    const ssl_status status = engine.do_handshake();
    if (engine.is_init_finished())
    {
      handshaking = false;
      _handshake_notify = true;
      _handshake_error.reset();
      pump_writes();
      return true;
    }
    if (status == ssl_status::fatal)
    {
      handshaking = false;
      auto error = engine.make_error();
      _handshake_notify = true;
      _handshake_error = error;
      fail_backlog(error);
      set_read_error(std::move(error));
    }
    return false;
  }

  static int clamp_int(size_t value) noexcept
  {
    return static_cast<int>((std::min)(value, static_cast<size_t>((std::numeric_limits<int>::max)())));
  }

  bool on_plaintext_status(ssl_status status)
  {
    if (status == ssl_status::closed)
    {
      peer_closed = true;
      set_read_error(error_t{.code = vio_tls_clean_shutdown, .msg = "TLS connection closed"});
      return false;
    }
    if (status == ssl_status::fatal)
    {
      set_read_error(engine.make_error());
      return false;
    }
    return status == ssl_status::ok;
  }

  void drive_reads()
  {
    while (!read_error && engine.has_input())
    {
      if (exact_fill_pending())
      {
        int count = 0;
        auto status = engine.read_plaintext(read_buffer.data() + bytes_read, clamp_int(read_buffer.size() - bytes_read), count);
        if (!on_plaintext_status(status))
          return;
        bytes_read += static_cast<size_t>(count);
        continue;
      }
      if (!reader_active || read_cancelled)
        return;
      if (!buffer_queue.empty() && buffer_queue.back().size() < buffer_queue.back().capacity())
      {
        auto &back = buffer_queue.back();
        int count = 0;
        auto status = engine.read_plaintext(back.data() + back.size(), clamp_int(back.capacity() - back.size()), count);
        if (!on_plaintext_status(status))
          return;
        back.resize(back.size() + static_cast<size_t>(count));
        continue;
      }
      if (buffer_queue.full())
        return;
      auto memory = alloc_cb(user_alloc_ptr, read_chunk);
      if (memory.empty())
      {
        if (memory.data() != nullptr)
          dealloc_cb(user_alloc_ptr, memory);
        set_read_error(make_error(errc::no_buffer_space));
        return;
      }
      unique_buf_t chunk(memory, dealloc_cb, user_alloc_ptr);
      chunk.resize(0);
      int count = 0;
      auto status = engine.read_plaintext(chunk.data(), clamp_int(chunk.capacity()), count);
      if (!on_plaintext_status(status))
        return;
      chunk.resize(static_cast<size_t>(count));
      buffer_queue.push(std::move(chunk));
    }
  }

  void on_read_end(int received)
  {
    _read_eof = true;
    error_t error = received == 0 ? (peer_closed ? error_t{.code = vio_tls_clean_shutdown, .msg = "TLS connection closed"} : error_t{.code = vio_tls_truncated, .msg = "Connection closed by peer"})
                                  : make_error(received);
    peer_closed = true;
    if (handshaking)
    {
      handshaking = false;
      _handshake_notify = true;
      _handshake_error = error;
    }
    if (!engine.is_init_finished() || _write_wants_read)
      fail_backlog(error);
    set_read_error(std::move(error));
  }

  void pump_writes()
  {
    while (!_backlog.empty())
    {
      if (_write_error != 0)
      {
        fail_backlog(make_error(_write_error));
        return;
      }
      if (!engine.is_init_finished())
      {
        if (handshaking)
          return;
        if (!closed && !read_error && !_read_eof)
        {
          handshaking = true;
          after_user_call();
          return;
        }
        fail_backlog(read_error ? *read_error : make_error(errc::not_connected));
        return;
      }
      auto pending = engine.output_size();
      if (_throttled)
      {
        if (pending >= write_low_water)
          return;
        _throttled = false;
      }
      if (pending >= write_high_water)
      {
        _throttled = true;
        return;
      }
      auto idx = _backlog.front();
      auto &ws = write_queue[idx];
      if (ws.kind == stream_write_kind::shutdown)
      {
        _backlog.pop();
        engine.shutdown();
        ws.cipher_end = engine.output_total();
        _inflight.push(idx);
        flush_out();
        continue;
      }
      auto slice = (std::min)(ws.size - ws.bytes_written, write_slice);
      if (slice > 0)
      {
        engine.reserve_output(slice + slice / 16 + 1024);
        int count = 0;
        auto status = engine.write_plaintext(ws.data + ws.bytes_written, static_cast<int>(slice), count);
        if (status == ssl_status::want_read)
        {
          _write_wants_read = true;
          flush_out();
          after_user_call();
          return;
        }
        if (status != ssl_status::ok)
        {
          _backlog.pop();
          auto error = status == ssl_status::closed ? error_t{.code = vio_tls_clean_shutdown, .msg = "TLS connection closed"} : engine.make_error();
          complete_slot(idx, error.code, std::move(error.msg));
          flush_out();
          continue;
        }
        ws.bytes_written += static_cast<size_t>(count);
      }
      if (ws.bytes_written >= ws.size)
      {
        _backlog.pop();
        ws.cipher_end = engine.output_total();
        _inflight.push(idx);
      }
      flush_out();
    }
    if (closed && engine.is_init_finished() && !engine.shutdown_sent && _write_error == 0)
    {
      engine.shutdown();
      flush_out();
    }
  }

  void flush_out()
  {
    if (_write_error != 0)
    {
      engine.discard_output();
      arm_output_trim();
      return;
    }
    if (socket != nullptr && socket->is_open() && !_write_op.parked)
    {
      while (engine.has_output())
      {
        auto sent = detail::socket_send(socket->native(), engine.pending_output());
        if (sent == errc::again || sent == 0)
        {
          park_write();
          break;
        }
        if (sent < 0)
        {
          on_write_failure(static_cast<int>(sent));
          return;
        }
        engine.consume_output(static_cast<size_t>(sent));
      }
    }
    if (!engine.has_output())
      arm_output_trim();
    complete_inflight();
  }

  void arm_output_trim(std::int64_t due = 0)
  {
    if (_core == nullptr || !detail::ssl_output_pool().claim_trim(this))
      return;
    _core->add_timer(_output_trim, due != 0 ? due : detail::loop_core_t::deadline_after(output_trim_ns));
  }

  void unlink_pooled() noexcept
  {
    if (_pooled_prev != nullptr)
      _pooled_prev->_pooled_next = _pooled_next;
    else
      _pooled_core->tls_streams() = _pooled_next;
    if (_pooled_next != nullptr)
      _pooled_next->_pooled_prev = _pooled_prev;
  }

  void complete_inflight()
  {
    auto sent = engine.output_sent();
    while (!_inflight.empty())
    {
      auto idx = _inflight.front();
      if (write_queue[idx].cipher_end > sent)
        return;
      _inflight.pop();
      complete_slot(idx, 0, {});
    }
  }

  void on_write_failure(int code)
  {
    _write_error = code;
    engine.discard_output();
    if (_write_op.parked)
      socket->cancel(_write_op);
    auto error = make_error(code);
    while (!_inflight.empty())
    {
      auto idx = _inflight.front();
      _inflight.pop();
      complete_slot(idx, error.code, error.msg);
    }
    fail_backlog(error);
  }

  void complete_slot(size_t idx, int code, std::string message)
  {
    auto &ws = write_queue[idx];
    if (!ws.done)
    {
      ws.done = true;
      if (code != 0 && ws.error_code == 0)
      {
        ws.error_code = code;
        ws.error_msg = std::move(message);
      }
    }
    if (ws.continuation)
      _completed.push(idx);
    else
      release_op_hold(idx);
  }

  void release_op_hold(size_t idx)
  {
    if (--write_queue[idx].ref <= 0)
      write_queue.deactivate(idx);
  }

  void fail_backlog(const error_t &error)
  {
    _write_wants_read = false;
    _throttled = false;
    while (!_backlog.empty())
    {
      auto idx = _backlog.front();
      _backlog.pop();
      complete_slot(idx, error.code != 0 ? error.code : vio_tls_error, error.msg);
    }
  }

  void drop_backlog()
  {
    while (!_backlog.empty())
    {
      auto idx = _backlog.front();
      _backlog.pop();
      complete_slot(idx, errc::canceled, error_message(errc::canceled));
    }
  }

  void drop_writes()
  {
    drop_backlog();
    if (socket != nullptr && _write_op.parked)
      socket->cancel(_write_op);
  }

  [[nodiscard]] bool teardown_settled() const
  {
    if (_write_error != 0 || socket == nullptr || !socket->is_open())
      return true;
    return !engine.has_output() && _backlog.empty();
  }

  void settle_linger()
  {
    if (_write_error != 0 || socket == nullptr || !socket->is_open() || _read_eof)
    {
      finish_linger();
      return;
    }
    if (_linger_fin_sent)
      return;
    _linger_fin_sent = true;
    if (detail::socket_shutdown_write(socket->native()) != 0)
    {
      finish_linger();
      return;
    }
    auto deadline = detail::loop_core_t::deadline_after(linger_after_fin_ns);
    if (_linger.armed() && deadline < _linger.deadline)
    {
      _core->remove_timer(_linger);
      _core->add_timer(_linger, deadline);
    }
    linger_read();
    if (_read_eof)
      finish_linger();
  }

  void finish_linger()
  {
    _lingering = false;
    if (_linger.armed())
      _core->remove_timer(_linger);
    if (socket != nullptr && _read_op.parked)
      socket->cancel(_read_op);
    drop_writes();
    engine.discard_output();
    discard_inbound();
    rc->dec();
  }

  void linger_read()
  {
    if (!_lingering || _read_eof || _read_op.parked || socket == nullptr || !socket->is_open())
      return;
    std::byte scratch[linger_discard_chunk];
    for (int i = 0; i < linger_discard_budget; ++i)
    {
      auto received = detail::socket_recv(socket->native(), std::span<std::byte>(scratch));
      if (received == errc::again)
      {
        _read_op.keeps_alive = false;
        socket->wait(detail::interest_read, _read_op);
        return;
      }
      if (received <= 0)
      {
        _read_eof = true;
        return;
      }
    }
    schedule();
  }

  void discard_inbound() noexcept
  {
    if (socket == nullptr || !socket->is_open() || _read_eof)
      return;
    std::byte scratch[4096];
    for (int i = 0; i < 64; ++i)
    {
      if (detail::socket_recv(socket->native(), std::span<std::byte>(scratch)) <= 0)
        return;
    }
  }

  void notify()
  {
    if (_notifying)
      return;
    _notifying = true;
    while (!closed)
    {
      if (_handshake_notify)
      {
        _handshake_notify = false;
        auto callback = std::move(on_handshake_complete);
        on_handshake_complete = nullptr;
        if (callback)
          callback(_handshake_error);
        continue;
      }
      if (!_completed.empty())
      {
        auto idx = _completed.front();
        _completed.pop();
        if (!write_queue.is_active(idx))
          continue;
        auto continuation = std::exchange(write_queue[idx].continuation, {});
        if (continuation)
          continuation.resume();
        if (write_queue.is_active(idx))
          release_op_hold(idx);
        continue;
      }
      if (read_buffer_continuation && exact_fill_ready())
      {
        std::exchange(read_buffer_continuation, {}).resume();
        continue;
      }
      if (read_continuation && (read_cancelled || has_buffer_with_data_or_error()))
      {
        std::exchange(read_continuation, {}).resume();
        continue;
      }
      break;
    }
    _notifying = false;
  }

  static void on_read_ready(detail::io_op_t *op)
  {
    auto *self = static_cast<tls_stream_t *>(op->owner);
    auto *count = self->rc;
    count->inc();
    self->service();
    count->dec();
  }

  static void on_write_ready(detail::io_op_t *op)
  {
    auto *self = static_cast<tls_stream_t *>(op->owner);
    auto *count = self->rc;
    count->inc();
    self->service();
    count->dec();
  }

  static void on_kick(detail::posted_t *node)
  {
    auto *self = static_cast<tls_stream_t *>(node->owner);
    auto *count = self->rc;
    self->service();
    count->dec();
  }

  static void on_kick_discard(detail::posted_t *node)
  {
    static_cast<tls_stream_t *>(node->owner)->rc->dec();
  }

  static void on_linger(detail::timer_node_t *node)
  {
    auto *self = static_cast<tls_stream_t *>(node->owner);
    if (self->_lingering)
      self->finish_linger();
  }

  static void on_output_trim(detail::timer_node_t *node)
  {
    auto *self = static_cast<tls_stream_t *>(node->owner);
    auto &pool = detail::ssl_output_pool();
    pool.release_trim(self);
    pool.trim();
    self->arm_output_trim();
  }

  detail::loop_core_t *_core = nullptr;
  detail::io_op_t _read_op;
  detail::io_op_t _write_op;
  detail::posted_t _kick;
  detail::timer_node_t _linger;
  detail::timer_node_t _output_trim;
  detail::loop_core_t *_pooled_core = nullptr;
  tls_stream_t *_pooled_prev = nullptr;
  tls_stream_t *_pooled_next = nullptr;
  stream_index_fifo_t _backlog;
  stream_index_fifo_t _inflight;
  stream_index_fifo_t _completed;
  std::optional<error_t> _handshake_error;
  int _write_error = 0;
  bool _handshake_notify = false;
  bool _throttled = false;
  bool _write_wants_read = false;
  bool _read_eof = false;
  bool _lingering = false;
  bool _linger_fin_sent = false;
  bool _notifying = false;
  bool _pooled = false;
};

template <typename REF_PTR_T, typename STREAM>
stream_reader_t<REF_PTR_T, STREAM>::stream_reader_t(const REF_PTR_T &ref_ptr, STREAM *stream)
  : ref_ptr(ref_ptr)
  , stream(stream)
{
  stream->reader_active = true;
  stream->start_reading();
}

template <typename REF_PTR_T, typename STREAM>
stream_reader_t<REF_PTR_T, STREAM>::stream_reader_t(stream_reader_t &&other) noexcept
  : ref_ptr(std::move(other.ref_ptr))
  , stream(std::exchange(other.stream, nullptr))
{
}

template <typename REF_PTR_T, typename STREAM>
stream_reader_t<REF_PTR_T, STREAM> &stream_reader_t<REF_PTR_T, STREAM>::operator=(stream_reader_t<REF_PTR_T, STREAM> &&other) noexcept
{
  if (this != &other)
  {
    if (ref_ptr && stream != nullptr && stream != other.stream)
      stream->on_reader_gone();
    ref_ptr = std::move(other.ref_ptr);
    stream = std::exchange(other.stream, nullptr);
  }
  return *this;
}

template <typename REF_PTR_T, typename STREAM>
stream_reader_t<REF_PTR_T, STREAM>::~stream_reader_t()
{
  if (!ref_ptr || stream == nullptr)
  {
    return;
  }
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
  stream->on_wait();
}

template <typename REF_PTR_T, typename STREAM>
auto stream_reader_t<REF_PTR_T, STREAM>::await_resume() noexcept -> std::expected<unique_buf_t, error_t>
{
  assert(ref_ptr && "Invalid state in await_resume");
  if (stream->read_cancelled)
  {
    return std::unexpected(error_t{.code = errc::canceled, .msg = "Operation was cancelled"});
  }
  if (stream->has_front_data())
  {
    auto buffer = stream->take_front();
    stream->on_consume();
    return buffer;
  }
  if (stream->read_error)
  {
    return std::unexpected(*stream->read_error);
  }
  return std::unexpected(make_error(errc::canceled));
}

template <typename REF_PTR_T, typename STREAM>
void stream_reader_t<REF_PTR_T, STREAM>::cancel() noexcept
{
  assert(ref_ptr && "Invalid state in cancel");
  stream->cancel_reads();
}

template <typename REF_PTR_T, typename STREAM>
bool stream_reader_t<REF_PTR_T, STREAM>::is_cancelled() const noexcept
{
  assert(ref_ptr && "Invalid state in is_cancelled");
  return stream->read_cancelled;
}

template <typename REF_PTR_T, typename STREAM>
stream_read_awaitable_t<REF_PTR_T, STREAM> stream_reader_t<REF_PTR_T, STREAM>::read(std::span<std::byte> buf)
{
  stream->begin_exact_fill(buf);
  return {ref_ptr, stream, buf};
}

template <typename REF_PTR_T, typename STREAM>
stream_write_awaitable_t<REF_PTR_T, STREAM>::stream_write_awaitable_t(const REF_PTR_T &ref_ptr, STREAM *stream, size_t write_state_index)
  : ref_ptr(ref_ptr)
  , stream(stream)
  , write_state_index(write_state_index)
{
}

template <typename REF_PTR_T, typename STREAM>
stream_write_awaitable_t<REF_PTR_T, STREAM>::stream_write_awaitable_t(stream_write_awaitable_t &&other) noexcept
  : ref_ptr(std::move(other.ref_ptr))
  , stream(std::exchange(other.stream, nullptr))
  , write_state_index(other.write_state_index)
{
}

template <typename REF_PTR_T, typename STREAM>
stream_write_awaitable_t<REF_PTR_T, STREAM> &stream_write_awaitable_t<REF_PTR_T, STREAM>::operator=(stream_write_awaitable_t &&other) noexcept
{
  if (this != &other)
  {
    release();
    ref_ptr = std::move(other.ref_ptr);
    stream = std::exchange(other.stream, nullptr);
    write_state_index = other.write_state_index;
  }
  return *this;
}

template <typename REF_PTR_T, typename STREAM>
void stream_write_awaitable_t<REF_PTR_T, STREAM>::release() noexcept
{
  if (!ref_ptr || stream == nullptr)
    return;
  if (stream->write_queue.is_active(write_state_index))
    stream->abandon_write(write_state_index);
  stream = nullptr;
}

template <typename REF_PTR_T, typename STREAM>
stream_write_awaitable_t<REF_PTR_T, STREAM>::~stream_write_awaitable_t()
{
  release();
}

template <typename REF_PTR_T, typename STREAM>
[[nodiscard]] bool stream_write_awaitable_t<REF_PTR_T, STREAM>::await_ready() const noexcept
{
  if (!ref_ptr || stream == nullptr)
  {
    return true;
  }
  return stream->write_queue[write_state_index].done;
}

template <typename REF_PTR_T, typename STREAM>
void stream_write_awaitable_t<REF_PTR_T, STREAM>::await_suspend(std::coroutine_handle<> h) noexcept
{
  stream->write_queue[write_state_index].continuation = h;
}

template <typename REF_PTR_T, typename STREAM>
std::expected<void, error_t> stream_write_awaitable_t<REF_PTR_T, STREAM>::await_resume() noexcept
{
  if (!ref_ptr || stream == nullptr)
  {
    return std::unexpected(error_t{.code = errc::bad_descriptor, .msg = "Can not write to a closed TLS stream"});
  }
  auto &write_state = stream->write_queue[write_state_index];
  write_state.cancel_registration.reset();
  if (write_state.error_code != 0)
  {
    return std::unexpected(error_t{write_state.error_code, write_state.error_msg});
  }
  return {};
}

} // namespace vio
