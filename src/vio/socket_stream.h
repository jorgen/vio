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

#include <coroutine>
#include <expected>

#include <uv.h>
#include <vio/elastic_index_storage.h>
#include <vio/error.h>
#include <vio/ring_buffer.h>
#include <vio/ssl_config_t.h>
#include <vio/unique_buf.h>

namespace vio
{
struct stream_write_state_t
{
  uv_buf_t buf = {};
  size_t bytes_written = 0;
  int error_code = 0;
  int8_t ref = 2;
  bool done = false;
  std::string error_msg;
  std::coroutine_handle<> continuation = {};
};

struct stream_client_buffer_t
{
  uv_buf_t buf;
  size_t capacity;
  dealloc_cb_t dealloc_cb;
};

enum class stream_io_result_t
{
  ok,
  poll_in,
  poll_out,
};

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
    assert(stream->bytes_read == stream->read_buffer.len || stream->read_buffer_error.code);
    return std::expected<std::pair<uv_buf_t, dealloc_cb_t>, error_t>{{stream->read_buffer, nullptr}};
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

template <typename NATIVE_SOCKET_STREAM_T>
struct socket_stream_t
{
  socket_stream_t(NATIVE_SOCKET_STREAM_T &native_socket_stream, event_loop_t &event_loop, alloc_cb_t alloc_cb, dealloc_cb_t dealloc_cb, void *user_alloc_ptr)
    : native_socket_stream(native_socket_stream)
    , event_loop(event_loop)
    , alloc_cb(alloc_cb)
    , dealloc_cb(dealloc_cb)
    , user_alloc_ptr(user_alloc_ptr)
  {
    poll_req.data = this;
  }

  ~socket_stream_t() = default;
  socket_stream_t(socket_stream_t &) = delete;
  socket_stream_t &operator=(socket_stream_t &) = delete;
  socket_stream_t(socket_stream_t &&) = delete;
  socket_stream_t &operator=(socket_stream_t &&) = delete;

  error_t connect(int socket);
  void close(std::function<void()> continuation);
  [[nodiscard]] bool has_buffer_with_data_or_error() const;

  void set_poll_state();
  static void on_poll_event(uv_poll_t *handle, int status, int events);

  bool read();
  void write();

  NATIVE_SOCKET_STREAM_T &native_socket_stream;
  event_loop_t &event_loop;
  uv_poll_t poll_req = {};
  bool connected = false;
  bool poll_read_active = false;
  bool poll_write_active = false;
  bool read_got_poll_out = false;
  bool write_got_poll_in = false;
  bool poll_running = false;
  bool reader_active = false;
  bool closed = false;
  std::function<void()> close_continuation = {};
  std::coroutine_handle<> read_continuation = {};
  std::coroutine_handle<> read_buffer_continuation = {};
  alloc_cb_t alloc_cb = nullptr;
  dealloc_cb_t dealloc_cb = nullptr;
  void *user_alloc_ptr = nullptr;

  ring_buffer_t<std::expected<stream_client_buffer_t, error_t>, 10> buffer_queue;

  uv_buf_t read_buffer = {};
  size_t bytes_read = 0;
  error_t read_buffer_error = {};

  elastic_index_storage_t<stream_write_state_t> write_queue;
};

template <typename NATIVE_SOCKET_STREAM_T>
bool socket_stream_t<NATIVE_SOCKET_STREAM_T>::has_buffer_with_data_or_error() const
{
  if (buffer_queue.empty())
  {
    return false;
  }
  const auto &buffer = buffer_queue.front();
  if (buffer.has_value() && buffer.value().buf.len > 0)
  {
    return true;
  }
  if (!buffer.has_value() && (buffer.error().code != 0))
  {
    return true;
  }
  return false;
}

template <typename NATIVE_SOCKET_STREAM_T>
error_t socket_stream_t<NATIVE_SOCKET_STREAM_T>::connect(int socket)
{
  error_t err = {};
  if (int result = uv_poll_init_socket(event_loop.loop(), &poll_req, socket); result < 0)
  {
    err = error_t{.code = 1, .msg = std::string("Failed to initialize poll, ") + uv_strerror(result)};
    return err;
  }
  connected = true;
  return err;
}

template <typename NATIVE_SOCKET_STREAM_T>
void socket_stream_t<NATIVE_SOCKET_STREAM_T>::close(std::function<void()> continuation)
{
  native_socket_stream.close();
  close_continuation = std::move(continuation);

  poll_read_active = false;
  poll_write_active = false;
  closed = true;
  uv_poll_stop(&poll_req);
  auto close_poll_cb = [](uv_handle_t *handle)
  {
    auto self = static_cast<socket_stream_t<NATIVE_SOCKET_STREAM_T> *>(handle->data);
    self->close_continuation();
    handle->data = nullptr;
  };
  uv_close((uv_handle_t *)&poll_req, close_poll_cb);
}

template <typename NATIVE_SOCKET_STREAM_T>
void socket_stream_t<NATIVE_SOCKET_STREAM_T>::set_poll_state()
{
  if (closed)
  {
    return;
  }
  int events = 0;
  if (poll_read_active && (write_got_poll_in || reader_active))
  {
    events |= UV_READABLE;
  }
  if (poll_write_active)
  {
    events |= UV_WRITABLE;
  }

  if (events == 0)
  {
    uv_poll_stop(&poll_req);
    poll_running = false;
  }
  else
  {
    uv_poll_start(&poll_req, events, on_poll_event);
    poll_running = true;
  }
}

template <typename NATIVE_SOCKET_STREAM_T>
void socket_stream_t<NATIVE_SOCKET_STREAM_T>::on_poll_event(uv_poll_t *handle, int status, int events)
{
  if (uv_is_closing(reinterpret_cast<uv_handle_t *>(handle)))
  {
    return;
  }
  auto state = static_cast<socket_stream_t<NATIVE_SOCKET_STREAM_T> *>(handle->data);
  assert(handle == &state->poll_req && "Invalid state in on_poll_event");

  if ((events & UV_DISCONNECT) != 0)
  {
    state->connected = false;
    state->poll_read_active = false;
    state->poll_write_active = false;
    uv_poll_stop(&state->poll_req);
    return;
  }
  if (status < 0)
  {
    fprintf(stderr, "on_poll_event: error %s\n", uv_strerror(status));
    return;
  }

  assert(state->connected && "on_poll_event: client not connected");

  if ((events & UV_WRITABLE) != 0)
  {
    if (state->read_got_poll_out)
    {
      state->read_got_poll_out = false;
      state->read();
    }
    else
    {
      state->write();
    }
  }
  if (state->closed)
  {
    return;
  }
  if ((events & UV_READABLE) != 0)
  {
    if (state->write_got_poll_in)
    {
      state->write_got_poll_in = false;
      state->write();
      if (state->closed)
      {
        return;
      }
    }
    state->read();
  }
  if (state->closed)
  {
    return;
  }
  if ((events & (UV_WRITABLE | UV_READABLE)) == 0)
  {
    fprintf(stderr, "on_poll_event: unexpected events %d\n", events);
  }
  state->set_poll_state();
}

template <typename NATIVE_SOCKET_STREAM_T>
bool socket_stream_t<NATIVE_SOCKET_STREAM_T>::read()
{
  // NOLINTNEXTLINE(cppcoreguidelines-special-member-functions)
  struct call_read_resume_on_exit_t
  {
    socket_stream_t<NATIVE_SOCKET_STREAM_T> &state;
    explicit call_read_resume_on_exit_t(socket_stream_t<NATIVE_SOCKET_STREAM_T> &state)
      : state(state)
    {
    }

    ~call_read_resume_on_exit_t()
    {
      if (state.read_buffer_continuation && (state.read_buffer.len > 0 && state.bytes_read == state.read_buffer.len || state.read_buffer_error.code))
      {
        state.read_buffer_continuation.resume();
      }
      if (state.read_buffer.len == 0 && state.read_continuation && state.has_buffer_with_data_or_error())
      {
        state.read_continuation.resume();
      }
    }
  };
  call_read_resume_on_exit_t call_read_resume_on_exit(*this);

  read_got_poll_out = false;
  if (read_buffer.len > 0)
  {
    while (bytes_read < read_buffer.len)
    {
      auto remaining = read_buffer.len - bytes_read;

      std::expected<std::pair<stream_io_result_t, int64_t>, error_t> read_result = native_socket_stream.read(read_buffer.base + bytes_read, remaining);
      if (!read_result.has_value())
      {
        read_buffer_error = read_result.error();
        poll_read_active = false;
        return false;
      }
      auto result = read_result.value();
      bytes_read += result.second;
      if (result.first == stream_io_result_t::poll_out)
      {
        read_got_poll_out = true;
        poll_write_active = true;
      }
      if (result.first == stream_io_result_t::poll_in)
      {
        poll_read_active = true;
        return true;
      }
    }
    return true;
  }

  while (!buffer_queue.full())
  {
    stream_client_buffer_t *current_buffer = nullptr;
    if (!buffer_queue.empty())
    {
      auto &last = buffer_queue.back();
      if (last.has_value() && last->buf.len < last->capacity)
      {
        current_buffer = &last.value();
      }
    }

    if (current_buffer == nullptr)
    {
      uv_buf_t read_buf;
      alloc_cb(user_alloc_ptr, 65536, &read_buf);
      auto capacity = read_buf.len;
      read_buf.len = 0;
      current_buffer = &buffer_queue.push(stream_client_buffer_t{read_buf, capacity, dealloc_cb}).value();
    }

    auto remaining = current_buffer->capacity - current_buffer->buf.len;
    auto result_or_error = native_socket_stream.read(current_buffer->buf.base + current_buffer->buf.len, remaining);
    if (!result_or_error.has_value())
    {
      if (current_buffer->buf.len == 0)
      {
        current_buffer->dealloc_cb(user_alloc_ptr, &current_buffer->buf);
        buffer_queue.replace_back(std::unexpected(std::move(result_or_error.error())));
      }
      else if (!buffer_queue.full())
      {
        buffer_queue.push(std::unexpected(std::move(result_or_error.error())));
      }
      if (!closed)
      {
        uv_poll_stop(&poll_req);
      }
      poll_read_active = false;
      return false;
    }

    auto result = result_or_error.value();
    current_buffer->buf.len += result.second;
    if (result.first == stream_io_result_t::poll_in || result.second == 0)
    {
      poll_read_active = true;
      return true;
    }
    if (result.first == stream_io_result_t::poll_out)
    {
      poll_write_active = true;
      read_got_poll_out = true;
      return true;
    }
  }

  poll_read_active = false;

  return true;
}

template <typename NATIVE_SOCKET_STREAM_T>
void socket_stream_t<NATIVE_SOCKET_STREAM_T>::write()
{
  if (!write_queue.current_item_is_active() && !write_queue.next())
  {
    return;
  }

  while (write_queue.current_item_is_active())
  {
    auto &write_state = write_queue.current_item();
    auto remaining = write_state.buf.len - write_state.bytes_written;

    auto write_result = native_socket_stream.write(write_state.buf.base + write_state.bytes_written, remaining);
    if (write_result.has_value())
    {
      auto &result = write_result.value();
      if (result.second > 0)
      {
        write_state.bytes_written += result.second;
        if (write_state.bytes_written == write_state.buf.len)
        {
          write_state.done = true;
          if (write_state.continuation)
          {
            write_state.continuation.resume();
          }
          if (--write_state.ref == 0)
          {
            write_queue.deactivate_current();
          }
          write_queue.next();
        }
      }
      if (result.first == stream_io_result_t::poll_out)
      {
        poll_write_active = true;
        return;
      }
      if (result.first == stream_io_result_t::poll_in)
      {
        poll_read_active = true;
        write_got_poll_in = true;
        return;
      }
    }
    else
    {
      auto &error = write_result.error();
      write_state.error_code = error.code;
      write_state.error_msg = std::move(error.msg);
      write_state.done = true;
      if (write_state.continuation)
      {
        write_state.continuation.resume();
      }
      if (--write_state.ref == 0)
      {
        write_queue.deactivate_current();
      }
      write_queue.next();
    }
  }
  poll_write_active = false;
}

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
}

template <typename REF_PTR_T, typename STREAM>
bool stream_reader_t<REF_PTR_T, STREAM>::await_ready() noexcept
{
  assert(ref_ptr && "Invalid state in await_ready");
  return stream->has_buffer_with_data_or_error();
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
  assert(stream->has_buffer_with_data_or_error() && "Empty buffer in await_resume");
  auto ret = stream->buffer_queue.pop_front();

  if (!ret.has_value())
  {
    return std::unexpected(ret.error());
  }
  return unique_buf_t(ret.value().buf, ret.value().dealloc_cb, stream->user_alloc_ptr);
}

template <typename REF_PTR_T, typename STREAM>
stream_read_awaitable_t<REF_PTR_T, STREAM> stream_reader_t<REF_PTR_T, STREAM>::read(uv_buf_t buf)
{
  stream->read_buffer = buf;
  stream->bytes_read = 0;

  while (!stream->buffer_queue.empty() && stream->bytes_read < buf.len)
  {
    auto &queued = stream->buffer_queue.front().value();
    using to_copy_t = decltype(buf.len);
    auto to_copy = std::min(queued.buf.len, buf.len - to_copy_t(stream->bytes_read));
    std::memcpy(buf.base + stream->bytes_read, queued.buf.base, to_copy);
    stream->bytes_read += to_copy;

    if (to_copy == queued.buf.len)
    {
      if (queued.dealloc_cb)
      {
        queued.dealloc_cb(nullptr, &queued.buf);
      }
      stream->buffer_queue.discard_front();
    }
    else
    {
      queued.buf.base += to_copy;
      queued.buf.len -= to_copy;
    }
  }

  return {ref_ptr, stream};
}

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
  auto &write_state = stream->write_queue[write_state_index];
  if (--write_state.ref == 0)
  {
    write_state.done = false;
    stream->write_queue.deactivate(write_state_index);
  };
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
  auto &write_state = stream->write_queue[write_state_index];
  write_state.continuation = h;
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
    return std::unexpected(error_t{-1, write_state.error_msg});
  }
  return {};
}
} // namespace vio