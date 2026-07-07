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

#include "vio/cancellation.h"
#include "vio/error.h"
#include "vio/event_loop.h"
#include "vio/unique_buf.h"
#include "vio/uv_coro.h"

#include <algorithm>
#include <concepts>
#include <coroutine>
#include <cstdint>
#include <cstring>
#include <expected>
#include <memory>
#include <ranges>
#include <span>
#include <string>
#include <type_traits>
#include <utility>
#include <uv.h>

namespace vio
{
struct tcp_listen_state_t
{
  std::coroutine_handle<> continuation;
  std::expected<void, error_t> result;
  registration_t cancel_registration;
  bool done = false;
};

struct tcp_connect_state_t
{
  uv_connect_t req = {};
  std::coroutine_handle<> continuation;
  std::expected<void, error_t> result;
  registration_t cancel_registration;
  bool started = false;
  bool done = false;
};

// A cancellable write resumes its awaiter early while the in-flight uv_write is
// still reading the buffer, so vio must keep the bytes alive until the real
// write callback fires. owned_payload_t type-erases the lifetime of an arbitrary
// moved-in buffer (std::string, std::vector, or any owning contiguous byte
// range); the write reads a uv_buf_t computed from it at submit time.
struct owned_payload_t
{
  virtual ~owned_payload_t() = default;
};

template <typename T>
struct owned_payload_impl_t : owned_payload_t
{
  T value;
  explicit owned_payload_impl_t(T &&v)
    : value(std::move(v))
  {
  }
};

template <typename T>
concept owned_byte_range = std::ranges::contiguous_range<T> && std::ranges::sized_range<T> && std::move_constructible<T> && sizeof(std::ranges::range_value_t<T>) == 1 &&
                           std::is_trivially_copyable_v<std::ranges::range_value_t<T>> && !std::ranges::view<std::remove_cvref_t<T>>;

struct tcp_write_state_t
{
  uv_write_t req = {};
  std::coroutine_handle<> continuation;
  std::expected<void, error_t> result;
  registration_t cancel_registration;
  std::unique_ptr<owned_payload_t> owned;
  bool started = false;
  bool done = false;
};
struct tcp_read_state_t
{
  bool active = false;
  bool started = false;
  bool paused = false;
  bool is_cancelled = false;
  std::vector<std::expected<unique_buf_t, error_t>> buffer_queue;
  std::size_t front_consumed = 0;
  std::coroutine_handle<> continuation;
  alloc_cb_t alloc_buffer_cb = default_alloc;
  dealloc_cb_t dealloc_buffer_cb = default_dealloc;
  void *alloc_cb_data = nullptr;
};
struct tcp_state_t
{
  event_loop_t &event_loop;
  uv_tcp_t uv_handle = {};
  uv_tcp_t *get_tcp()
  {
    return &uv_handle;
  }

  uv_stream_t *get_stream()
  {
    return reinterpret_cast<uv_stream_t *>(&uv_handle);
  }
  uv_handle_t *get_handle()
  {
    return reinterpret_cast<uv_handle_t *>(&uv_handle);
  }
  tcp_listen_state_t listen;
  tcp_connect_state_t connect;
  tcp_write_state_t write;
  tcp_read_state_t read;
};

template <typename State>
struct tcp_future_t
{
  ref_ptr_t<tcp_state_t> handle;
  State *state;
  tcp_future_t(ref_ptr_t<tcp_state_t> handle, State &state)
    : handle(std::move(handle))
    , state(&state)
  {
  }
  bool await_ready() noexcept
  {
    return state->done;
  }

  bool await_suspend(std::coroutine_handle<> continuation) noexcept
  {
    if (state->done)
    {
      return false;
    }
    state->continuation = continuation;
    return true;
  }

  auto await_resume() noexcept
  {
    return state->result;
  }
};

struct tcp_t
{
  ref_ptr_t<tcp_state_t> handle;

  uv_tcp_t *get_tcp()
  {
    if (handle.ref_counted() == nullptr)
    {
      return nullptr;
    }
    return handle->get_tcp();
  }

  uv_stream_t *get_stream()
  {
    if (handle.ref_counted() == nullptr)
    {
      return nullptr;
    }
    return handle->get_stream();
  }
  uv_handle_t *get_handle()
  {
    if (handle.ref_counted() == nullptr)
    {
      return nullptr;
    }
    return handle->get_handle();
  }
};

inline std::expected<sockaddr_in, error_t> ip4_addr(const std::string &ip, int port)
{
  sockaddr_in addr;
  const int r = uv_ip4_addr(ip.c_str(), port, &addr);
  if (r != 0)
  {
    return std::unexpected(error_t{.code = r, .msg = uv_strerror(r)});
  }
  return addr;
}

inline std::expected<sockaddr_in6, error_t> ip6_addr(const std::string &ip, int port)
{
  sockaddr_in6 addr;
  const int r = uv_ip6_addr(ip.c_str(), port, &addr);
  if (r != 0)
  {
    return std::unexpected(error_t{.code = r, .msg = uv_strerror(r)});
  }
  return addr;
}

inline std::expected<tcp_t, error_t> tcp_create(event_loop_t &loop)
{
  tcp_t tcp{ref_ptr_t<tcp_state_t>(loop)};
  if (auto r = uv_tcp_init(loop.loop(), tcp.get_tcp()); r < 0)
  {
    return std::unexpected(error_t{.code = r, .msg = uv_strerror(r)});
  }
  tcp.handle.register_handle(tcp.get_tcp());
  return tcp;
}

using tcp_connect_future_t = tcp_future_t<tcp_connect_state_t>;
inline tcp_connect_future_t tcp_connect(tcp_t &tcp, const sockaddr *addr, cancellation_t *cancel = nullptr)
{
  tcp_connect_future_t ret(tcp.handle, tcp.handle->connect);
  if (cancel && cancel->is_cancelled())
  {
    ret.handle->connect.done = true;
    ret.handle->connect.result = std::unexpected(error_t{.code = vio_cancelled, .msg = "cancelled"});
    return ret;
  }
  if (ret.handle->connect.started)
  {
    ret.handle->connect.done = true;
    ret.handle->connect.result = std::unexpected(error_t{.code = -1, .msg = "It's  an error to listen to more than one connect at a socket at the time"});
    return ret;
  }
  ret.handle->connect.started = true;
  ret.handle->connect.done = false;
  auto callback = [](uv_connect_t *req, int status)
  {
    auto state_ref = ref_ptr_t<tcp_state_t>::from_raw(req->data);
    state_ref->connect.cancel_registration.reset();
    if (state_ref->connect.done)
      return;
    if (status < 0)
    {
      state_ref->connect.result = std::unexpected(error_t{.code = status, .msg = uv_strerror(status)});
    }

    state_ref->connect.done = true;
    state_ref->connect.started = false;

    if (state_ref->connect.continuation)
    {
      auto continuation = state_ref->connect.continuation;
      state_ref->connect.continuation = {};
      continuation.resume();
    }
  };
  auto copy = ret.handle;
  ret.handle->connect.req.data = copy.release_to_raw();
  auto r = uv_tcp_connect(&ret.handle->connect.req, tcp.get_tcp(), addr, callback);
  if (r < 0)
  {
    ret.handle->connect.done = true;
    ret.handle->connect.result = std::unexpected(error_t{.code = r, .msg = uv_strerror(r)});
    ref_ptr_t<tcp_state_t>::from_raw(ret.handle->connect.req.data);
  }
  else if (cancel)
  {
    auto *state_raw = &ret.handle.data();
    ret.handle->connect.cancel_registration = cancel->register_callback(
      [state_raw]()
      {
        if (state_raw->connect.done)
          return;
        state_raw->connect.done = true;
        state_raw->connect.started = false;
        state_raw->connect.result = std::unexpected(error_t{.code = vio_cancelled, .msg = "cancelled"});
        state_raw->connect.cancel_registration.reset();
        if (state_raw->connect.continuation)
        {
          auto cont = state_raw->connect.continuation;
          state_raw->connect.continuation = {};
          cont.resume();
        }
      });
  }
  return ret;
}

inline std::expected<sockaddr_storage, error_t> sockname(tcp_t &tcp)
{
  sockaddr_storage sa_storage{};
  int name_len = sizeof(sa_storage);
  if (auto r = uv_tcp_getsockname(tcp.get_tcp(), reinterpret_cast<sockaddr *>(&sa_storage), &name_len); r < 0)
  {
    return std::unexpected(error_t{.code = r, .msg = uv_strerror(r)});
  }
  return sa_storage;
}

using tcp_write_future_t = tcp_future_t<tcp_write_state_t>;
inline bool write_tcp_begin(tcp_write_future_t &ret, cancellation_t *cancel)
{
  // tcp_state_t has a single embedded uv_write_t. Reject a second write while
  // one is physically in flight instead of overwriting the in-flight request
  // (UB) and leaking its parked ref. `started` is cleared only by the real
  // uv_write callback, so a cancelled-but-still-in-flight write (done==true,
  // started==true) is correctly rejected. For concurrent writes use
  // socket_stream, which gives each write its own state slot.
  if (ret.handle->write.started)
  {
    ret.handle->write.done = true;
    ret.handle->write.result = std::unexpected(error_t{.code = -1, .msg = "A write is already in progress on this socket"});
    return false;
  }

  ret.handle->write.started = true;
  ret.handle->write.done = false;
  ret.handle->write.result = {};

  if (cancel && cancel->is_cancelled())
  {
    ret.handle->write.started = false;
    ret.handle->write.done = true;
    ret.handle->write.result = std::unexpected(error_t{.code = vio_cancelled, .msg = "cancelled"});
    return false;
  }
  return true;
}

inline void write_tcp_arm(tcp_write_future_t &ret, tcp_t &tcp, uv_buf_t buf, cancellation_t *cancel)
{
  auto callback = [](uv_write_t *req, int status)
  {
    auto state_ref = ref_ptr_t<tcp_state_t>::from_raw(req->data);
    state_ref->write.cancel_registration.reset();
    state_ref->write.owned.reset();
    if (state_ref->write.done)
      return;
    if (status < 0)
    {
      state_ref->write.result = std::unexpected(error_t{.code = status, .msg = uv_strerror(status)});
    }
    state_ref->write.done = true;
    state_ref->write.started = false;
    if (state_ref->write.continuation)
    {
      auto continuation = state_ref->write.continuation;
      state_ref->write.continuation = {};
      continuation.resume();
    }
  };

  auto copy = ret.handle;
  ret.handle->write.req.data = copy.release_to_raw();
  auto r = uv_write(&ret.handle->write.req, tcp.get_stream(), &buf, 1, callback);

  if (r < 0)
  {
    ret.handle->write.done = true;
    ret.handle->write.started = false;
    ret.handle->write.result = std::unexpected(error_t{.code = r, .msg = uv_strerror(r)});
    ref_ptr_t<tcp_state_t>::from_raw(ret.handle->write.req.data);
  }
  else if (cancel)
  {
    auto *state_raw = &ret.handle.data();
    ret.handle->write.cancel_registration = cancel->register_callback(
      [state_raw]()
      {
        if (state_raw->write.done)
          return;
        state_raw->write.done = true;
        state_raw->write.result = std::unexpected(error_t{.code = vio_cancelled, .msg = "cancelled"});
        state_raw->write.cancel_registration.reset();
        if (state_raw->write.continuation)
        {
          auto cont = state_raw->write.continuation;
          state_raw->write.continuation = {};
          cont.resume();
        }
      });
  }
}

inline tcp_write_future_t write_tcp(tcp_t &tcp, const uint8_t *data, std::size_t length, cancellation_t *cancel = nullptr)
{
  tcp_write_future_t ret(tcp.handle, tcp.handle->write);
  if (!write_tcp_begin(ret, cancel))
  {
    return ret;
  }

  uv_buf_t buf;
  if (cancel != nullptr)
  {
    // The pointer is borrowed, so a cancellable write must copy into an owned
    // payload. Callers that already hold a movable buffer should use the owning
    // overload to transfer it without the copy.
    auto holder = std::make_unique<owned_payload_impl_t<std::string>>(std::string(reinterpret_cast<const char *>(data), length));
    buf = uv_buf_init(holder->value.data(), static_cast<unsigned int>(holder->value.size()));
    ret.handle->write.owned = std::move(holder);
  }
  else
  {
    buf = uv_buf_init(reinterpret_cast<char *>(const_cast<uint8_t *>(data)), static_cast<unsigned int>(length));
  }
  write_tcp_arm(ret, tcp, buf, cancel);
  return ret;
}

// Takes ownership of any moved-in contiguous byte range (std::string,
// std::vector<uint8_t>, std::vector<std::byte>, ...) and keeps it alive for the
// duration of the write, with no copy. Only rvalues bind: ownership must be
// transferred explicitly, which also keeps borrowed views (string_view, span)
// from matching.
template <typename Bytes>
  requires owned_byte_range<std::remove_cvref_t<Bytes>> && (!std::is_lvalue_reference_v<Bytes>) && (!std::is_const_v<std::remove_reference_t<Bytes>>)
tcp_write_future_t write_tcp(tcp_t &tcp, Bytes &&data, cancellation_t *cancel = nullptr)
{
  tcp_write_future_t ret(tcp.handle, tcp.handle->write);
  if (!write_tcp_begin(ret, cancel))
  {
    return ret;
  }

  auto holder = std::make_unique<owned_payload_impl_t<std::remove_cvref_t<Bytes>>>(std::forward<Bytes>(data));
  uv_buf_t buf = uv_buf_init(reinterpret_cast<char *>(std::ranges::data(holder->value)), static_cast<unsigned int>(std::ranges::size(holder->value)));
  ret.handle->write.owned = std::move(holder);
  write_tcp_arm(ret, tcp, buf, cancel);
  return ret;
}

class tcp_reader_t
{
public:
  tcp_reader_t(const tcp_reader_t &) = delete;
  tcp_reader_t &operator=(const tcp_reader_t &) = delete;

  tcp_reader_t(tcp_reader_t &&other) noexcept
    : handle(std::move(other.handle))
    , _is_valid(other._is_valid)
  {
    other._is_valid = false;
  }

  tcp_reader_t &operator=(tcp_reader_t &&other) noexcept
  {
    if (this != &other)
    {
      handle = std::move(other.handle);
      _is_valid = other._is_valid;
      other._is_valid = false;
    }
    return *this;
  }

  ~tcp_reader_t()
  {
    if (_is_valid && handle->read.started)
    {
      auto state = ref_ptr_t<tcp_state_t>::from_raw(handle->get_stream()->data);
      uv_read_stop(handle->get_stream());
      state->read.started = false;
      state->read.active = false;
    }
  }

  void cancel()
  {
    if (handle->read.is_cancelled)
    {
      return;
    }

    handle->read.is_cancelled = true;

    // Stop uv from delivering (and allocating buffers for) more data after the
    // reader is cancelled. Mirrors the destructor's teardown so the destructor's
    // started guard won't reclaim the parked ref a second time.
    if (handle->read.started)
    {
      auto state = ref_ptr_t<tcp_state_t>::from_raw(handle->get_stream()->data);
      uv_read_stop(handle->get_stream());
      state->read.started = false;
      state->read.active = false;
    }

    handle->read.buffer_queue.emplace_back(std::unexpected(error_t{.code = UV_ECANCELED, .msg = "Operation was cancelled"}));

    if (handle->read.continuation)
    {
      auto continuation = handle->read.continuation;
      handle->read.continuation = nullptr;
      continuation.resume();
    }
  }

  [[nodiscard]] bool is_cancelled() const
  {
    return handle->read.is_cancelled;
  }

  struct awaiter_t
  {
    ref_ptr_t<tcp_state_t> state;

    [[nodiscard]] bool await_ready() const
    {
      return !state->read.buffer_queue.empty();
    }

    void await_suspend(std::coroutine_handle<> handle)
    {
      state->read.continuation = handle;
    }

    std::expected<unique_buf_t, error_t> await_resume()
    {
      auto &front = state->read.buffer_queue.front();
      if (front.has_value() && state->read.front_consumed > 0)
      {
        // A prior read_into() partially drained this queued buffer. Hand back
        // only the remainder as a fresh owned buffer (we cannot shift the
        // original base pointer -- default_dealloc would delete[] the middle).
        uv_buf_t &src = front.value().buf;
        const std::size_t offset = state->read.front_consumed;
        const std::size_t remaining = src.len - offset;
        uv_buf_t copy_buf{};
        copy_buf.base = new char[remaining];
        copy_buf.len = static_cast<decltype(copy_buf.len)>(remaining);
        std::memcpy(copy_buf.base, src.base + offset, remaining);
        unique_buf_t out(copy_buf, default_dealloc, nullptr);
        state->read.front_consumed = 0;
        state->read.buffer_queue.erase(state->read.buffer_queue.begin());
        return out;
      }
      auto result = std::move(state->read.buffer_queue.front());
      state->read.buffer_queue.erase(state->read.buffer_queue.begin());
      return result;
    }
  };

  auto operator co_await()
  {
    return awaiter_t{this->handle};
  }

  // libuv alloc trampoline: forwards to the (swappable) read.alloc_buffer_cb.
  // Hoisted out of tcp_create_reader so resume() can re-arm uv_read_start with
  // the same callback pair.
  static void alloc_cb(uv_handle_t *handle, size_t size, uv_buf_t *buf)
  {
    auto tcp_state = ref_ptr_t<tcp_state_t>::from_raw(handle->data);
    tcp_state->read.alloc_buffer_cb(tcp_state->read.alloc_cb_data, size, buf);
    tcp_state.release_to_raw();
  }

  // Transient stop/start for backpressure. These MUST NOT reclaim the ref parked
  // in stream->data by tcp_create_reader -- only teardown (dtor/cancel) does,
  // gated on read.started, which stays true across pause/resume.
  static void pause_reading(ref_ptr_t<tcp_state_t> &handle)
  {
    if (handle->read.started && !handle->read.paused)
    {
      uv_read_stop(handle->get_stream());
      handle->read.paused = true;
    }
  }

  static void resume_reading(ref_ptr_t<tcp_state_t> &handle)
  {
    if (handle->read.started && handle->read.paused)
    {
      uv_read_start(handle->get_stream(), &tcp_reader_t::alloc_cb, &tcp_reader_t::read_cb);
      handle->read.paused = false;
    }
  }

  void pause()
  {
    if (_is_valid)
    {
      pause_reading(handle);
    }
  }

  void resume()
  {
    if (_is_valid)
    {
      resume_reading(handle);
    }
  }

  struct read_into_ctx_t
  {
    char *base = nullptr;
    std::size_t len = 0;
  };

  // Alloc that hands libuv the caller's buffer, so the socket read lands there
  // directly (true zero-copy). Paired with noop_dealloc.
  static void alloc_into(void *user, size_t /*suggested*/, uv_buf_t *buf)
  {
    auto *ctx = static_cast<read_into_ctx_t *>(user);
    buf->base = ctx->base;
    buf->len = static_cast<decltype(buf->len)>(ctx->len);
  }

  struct read_into_awaiter_t
  {
    ref_ptr_t<tcp_state_t> state;
    std::span<std::byte> dst;
    read_into_ctx_t ctx{};
    alloc_cb_t saved_alloc = nullptr;
    dealloc_cb_t saved_dealloc = nullptr;
    void *saved_alloc_data = nullptr;
    bool armed_into = false;

    [[nodiscard]] bool await_ready() const
    {
      return dst.empty() || !state->read.buffer_queue.empty();
    }

    void await_suspend(std::coroutine_handle<> h)
    {
      state->read.continuation = h;
      ctx.base = reinterpret_cast<char *>(dst.data());
      ctx.len = dst.size();
      saved_alloc = state->read.alloc_buffer_cb;
      saved_dealloc = state->read.dealloc_buffer_cb;
      saved_alloc_data = state->read.alloc_cb_data;
      state->read.alloc_buffer_cb = &tcp_reader_t::alloc_into;
      state->read.dealloc_buffer_cb = &noop_dealloc;
      state->read.alloc_cb_data = &ctx;
      armed_into = true;
      resume_reading(state);
    }

    std::expected<std::size_t, error_t> await_resume()
    {
      if (armed_into)
      {
        state->read.alloc_buffer_cb = saved_alloc;
        state->read.dealloc_buffer_cb = saved_dealloc;
        state->read.alloc_cb_data = saved_alloc_data;
        pause_reading(state);
        auto front = std::move(state->read.buffer_queue.front());
        state->read.buffer_queue.erase(state->read.buffer_queue.begin());
        if (!front.has_value())
        {
          if (front.error().code == UV_EOF)
          {
            return std::size_t{0};
          }
          return std::unexpected(front.error());
        }
        return static_cast<std::size_t>(front.value().buf.len);
      }

      if (dst.empty())
      {
        return std::size_t{0};
      }

      auto &front = state->read.buffer_queue.front();
      if (!front.has_value())
      {
        error_t err = front.error();
        state->read.buffer_queue.erase(state->read.buffer_queue.begin());
        state->read.front_consumed = 0;
        if (err.code == UV_EOF)
        {
          return std::size_t{0};
        }
        return std::unexpected(err);
      }
      uv_buf_t &src = front.value().buf;
      const std::size_t offset = state->read.front_consumed;
      const std::size_t avail = src.len - offset;
      const std::size_t n = std::min(avail, dst.size());
      std::memcpy(dst.data(), src.base + offset, n);
      state->read.front_consumed += n;
      if (state->read.front_consumed >= src.len)
      {
        state->read.front_consumed = 0;
        state->read.buffer_queue.erase(state->read.buffer_queue.begin());
      }
      return n;
    }
  };

  // Read up to dst.size() bytes into the caller's buffer. Returns the number of
  // bytes written (0 == EOF). When the reader's queue is empty this reads
  // directly into dst with no copy; if bytes are already queued it copies from
  // the front buffer (partial-consume tracked) and returns without a socket read
  // (the caller loops). After a direct read the reader is left paused, so libuv
  // does not buffer ahead -- the pull cadence is the backpressure.
  read_into_awaiter_t read_into(std::span<std::byte> dst)
  {
    return read_into_awaiter_t{this->handle, dst};
  }

  // NOLINTNEXTLINE(cppcoreguidelines-special-member-functions)
  struct ref_ptr_releaser_t
  {
    explicit ref_ptr_releaser_t(ref_ptr_t<tcp_state_t> &handle)
      : handle(handle)
    {
    }

    ~ref_ptr_releaser_t()
    {
      handle.release_to_raw();
    }
    ref_ptr_t<tcp_state_t> &handle;
  };

  static void read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
  {
    auto tcp_state = ref_ptr_t<tcp_state_t>::from_raw(stream->data);
    ref_ptr_releaser_t releaser(tcp_state);

    if (nread == 0)
    {
      // Per libuv's uv_read_cb contract, nread == 0 is equivalent to EAGAIN /
      // EWOULDBLOCK -- it does NOT indicate EOF or an error. Treat it as a
      // no-op (just release the buffer) instead of fabricating an end-of-stream.
      if (buf != nullptr && buf->base != nullptr)
      {
        tcp_state->read.dealloc_buffer_cb(tcp_state->read.alloc_cb_data, const_cast<uv_buf_t *>(buf));
      }
      return;
    }

    if (nread > 0)
    {
      uv_buf_t sized_buf = *buf;
      sized_buf.len = static_cast<decltype(sized_buf.len)>(nread);
      tcp_state->read.buffer_queue.emplace_back(unique_buf_t(sized_buf, tcp_state->read.dealloc_buffer_cb, tcp_state->read.alloc_cb_data));
    }
    else
    {
      int code = UV_EOF;
      if (nread < 0)
      {
        code = static_cast<int>(nread);
      }
      auto error = std::unexpected(error_t{.code = code, .msg = uv_strerror(static_cast<int>(nread))});
      tcp_state->read.buffer_queue.emplace_back(std::move(error));

      if (buf != nullptr && buf->base != nullptr)
      {
        tcp_state->read.dealloc_buffer_cb(tcp_state->read.alloc_cb_data, const_cast<uv_buf_t *>(buf));
      }
    }

    if (tcp_state->read.continuation)
    {
      auto continuation = tcp_state->read.continuation;
      tcp_state->read.continuation = nullptr;
      continuation.resume();
    }
  }

  ref_ptr_t<tcp_state_t> handle;
  friend std::expected<tcp_reader_t, error_t> tcp_create_reader(tcp_t &tcp);

private:
  explicit tcp_reader_t(const tcp_t &tcp)
    : handle(tcp.handle)
    , _is_valid(true)
  {
  }
  bool _is_valid = false;
};

inline std::expected<tcp_reader_t, error_t> tcp_create_reader(tcp_t &tcp)
{
  if (tcp.handle.ref_counted() == nullptr)
  {
    return std::unexpected(error_t{.code = 1, .msg = "Can not create a reader for a closed socket"});
  }
  if (tcp.handle->read.active)
  {
    return std::unexpected(error_t{.code = 1, .msg = "Can not create multiple active readers for a socket. Destroy other reader, before making a new one."});
  }

  auto copy = tcp.handle;
  tcp.get_stream()->data = copy.release_to_raw();
  if (const auto r = uv_read_start(tcp.get_stream(), &tcp_reader_t::alloc_cb, &tcp_reader_t::read_cb); r >= 0)
  {
    tcp.handle->read.active = true;
    tcp.handle->read.started = true;
  }
  else
  {
    auto tcp_state = ref_ptr_t<tcp_state_t>::from_raw(tcp.get_stream()->data);
    return std::unexpected(error_t{.code = r, .msg = uv_strerror(r)});
  }

  return tcp_reader_t{tcp};
}

} // namespace vio