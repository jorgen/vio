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

#include "vio/error.h"
#include "vio/event_loop.h"
#include "vio/uv_coro.h"

#include <coroutine>
#include <expected>
#include <string>
#include <utility>
#include <uv.h>

namespace vio
{

typedef void (*alloc_cb_t)(void *handle, size_t suggested_size, uv_buf_t *buf);
typedef void (*dealloc_cb_t)(void *handle, const char *base);

inline void default_tcp_alloc_cb(void *handle, size_t suggested_size, uv_buf_t *buf)
{
  (void)handle;
  auto *data = new uint8_t[suggested_size];
  *buf = uv_buf_init(reinterpret_cast<char *>(data), static_cast<unsigned int>(suggested_size));
}
inline void default_tcp_dealloc_cb(void *handle, const char *buf)
{
  (void)handle;
  delete[] reinterpret_cast<const uint8_t *>(buf);
}

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
  bool listen_done = false;
  std::coroutine_handle<> listen_continuation = {};
  std::expected<void, error_t> listen_result = {};

  uv_connect_t connect_req = {};
  bool connect_started = false;
  bool connect_done = false;
  std::coroutine_handle<> connect_continuation = {};
  std::expected<void, error_t> connect_result = {};

  uv_write_t write_req = {};
  bool write_started = false;
  bool write_done = false;
  std::coroutine_handle<> write_continuation = {};
  std::expected<void, error_t> write_result = {};

  bool reader_active = false;
  bool reader_started = false;
  bool reader_is_cancelled = false;
  bool reader_cancelled = false;
  std::vector<std::expected<std::pair<uv_buf_t, dealloc_cb_t>, error_t>> buffer_queue_;
  std::coroutine_handle<> read_continuation = {};
  alloc_cb_t alloc_read_buffer_cb = default_tcp_alloc_cb;
  dealloc_cb_t dealloc_read_buffer_cb = default_tcp_dealloc_cb;
  void *alloc_cb_data = nullptr;
};

struct tcp_read_buffer_t
{
  std::unique_ptr<uint8_t[], std::function<void(uint8_t *)>> data = nullptr;
  size_t size = 0;
};

struct tcp_t
{
  ref_ptr_t<tcp_state_t> handle;

  uv_tcp_t *get_tcp()
  {
    if (!handle.ptr())
      return nullptr;
    return handle->get_tcp();
  }

  uv_stream_t *get_stream()
  {
    if (!handle.ptr())
      return nullptr;
    return handle->get_stream();
  }
  uv_handle_t *get_handle()
  {
    if (!handle.ptr())
      return nullptr;
    return handle->get_handle();
  }
};

struct listen_state_t
{
  event_loop_t &event_loop;
};

inline std::expected<sockaddr_in, error_t> ip4_addr(const std::string &ip, int port)
{
  sockaddr_in addr;
  const int r = uv_ip4_addr(ip.c_str(), port, &addr);
  if (r != 0)
  {
    return std::unexpected(error_t{r, uv_strerror(r)});
  }
  return addr;
}

inline std::expected<sockaddr_in6, error_t> ip6_addr(const std::string &ip, int port)
{
  sockaddr_in6 addr;
  const int r = uv_ip6_addr(ip.c_str(), port, &addr);
  if (r != 0)
  {
    return std::unexpected(error_t{r, uv_strerror(r)});
  }
  return addr;
}

inline std::expected<tcp_t, error_t> create_tcp(event_loop_t &loop)
{
  tcp_t tcp{ref_ptr_t<tcp_state_t>(loop)};
  if (int r = uv_tcp_init(loop.loop(), tcp.get_tcp()); r < 0)
  {
    return std::unexpected(error_t{r, uv_strerror(r)});
  }
  auto to_close = [](ref_ptr_t<tcp_state_t> &handle)
  {
    if (!handle.ptr())
      return;
    auto copy = handle;
    handle->get_handle()->data = copy.release_to_raw();
    auto close_cb = [](uv_handle_t *handle)
    {
      if (handle->data)
      {
        auto stateRef = ref_ptr_t<tcp_state_t>::from_raw(handle->data);
      }
      handle->data = nullptr;
    };
    uv_close(handle->get_handle(), close_cb);
  };
  tcp.handle.set_close_guard(to_close);
  return tcp;
}

inline std::expected<void, error_t> tcp_bind(tcp_t &tcp, const sockaddr *addr, unsigned int flags = 0)
{
  const int r = uv_tcp_bind(tcp.get_tcp(), addr, flags);
  if (r < 0)
  {
    return std::unexpected(error_t{r, uv_strerror(r)});
  }
  return {};
}

struct tcp_listen_future_t
{
  ref_ptr_t<tcp_state_t> handle;
  tcp_listen_future_t(ref_ptr_t<tcp_state_t> handle)
    : handle(std::move(handle))
  {
  }
  bool await_ready() noexcept
  {
    return handle->listen_done;
  }

  void await_suspend(std::coroutine_handle<> continuation) noexcept
  {
    if (handle->listen_done)
    {
      continuation.resume();
    }
    else
    {
      handle->listen_continuation = continuation;
    }
  }

  std::expected<void, error_t> await_resume() noexcept
  {
    return handle->listen_result;
  }
};

inline tcp_listen_future_t tcp_listen(tcp_t &tcp, int backlog)
{
  tcp_listen_future_t ret(tcp.handle);

  auto on_connection = [](uv_stream_t *server, int status)
  {
    auto stateRef = ref_ptr_t<tcp_state_t>::from_raw(server->data);
    if (status < 0)
    {
      stateRef->listen_result = std::unexpected(error_t{status, uv_strerror(status)});
    }
    else
    {
    }
    stateRef->listen_done = true;
    if (stateRef->listen_continuation)
    {
      auto continuation = stateRef->listen_continuation;
      stateRef->listen_continuation = {};
      continuation.resume();
    }
  };

  auto copy = ret.handle;
  ret.handle->get_stream()->data = copy.release_to_raw();

  int r = uv_listen(tcp.get_stream(), backlog, on_connection);
  if (r < 0)
  {
    ret.handle->listen_done = true;
    ret.handle->listen_result = std::unexpected(error_t{r, uv_strerror(r)});
    ref_ptr_t<tcp_state_t>::from_raw(ret.handle->uv_handle.data);
  }

  return std::move(ret);
}

inline std::expected<tcp_t, error_t> tcp_accept(tcp_t &server)
{
  if (!server.handle.ptr())
    return std::unexpected(error_t{-1, "It's not possible to accept a connection on a closed socket"});

  auto tcp_client = create_tcp(server.handle->event_loop);
  if (!tcp_client.has_value())
  {
    return std::unexpected(tcp_client.error());
  }
  auto client = std::move(tcp_client.value());

  if (const int r = uv_accept(server.get_stream(), client.get_stream()); r < 0)
  {
    return std::unexpected(error_t{r, uv_strerror(r)});
  }
  return std::move(client);
}

struct tcp_connect_future_t
{
  ref_ptr_t<tcp_state_t> handle;
  explicit tcp_connect_future_t(ref_ptr_t<tcp_state_t> handle)
    : handle(std::move(handle))
  {
  }
  bool await_ready() noexcept
  {
    return handle->connect_done;
  }

  void await_suspend(std::coroutine_handle<> continuation) noexcept
  {
    if (handle->connect_done)
    {
      continuation.resume();
    }
    else
    {
      handle->connect_continuation = continuation;
    }
  }

  std::expected<void, error_t> await_resume() noexcept
  {
    return handle->connect_result;
  }
};
inline tcp_connect_future_t tcp_connect(tcp_t &tcp, const sockaddr *addr)
{
  tcp_connect_future_t ret(tcp.handle);
  if (ret.handle->connect_started)
  {
    ret.handle->connect_done = true;
    ret.handle->connect_result = std::unexpected(error_t{-1, "It's  an error to listen to more than one connect at a socket at the time"});
    return ret;
  }
  ret.handle->connect_started = true;
  ret.handle->connect_done = false;
  auto callback = [](uv_connect_t *req, int status)
  {
    auto state_ref = ref_ptr_t<tcp_state_t>::from_raw(req->data);
    if (status < 0)
    {
      state_ref->connect_result = std::unexpected(error_t{status, uv_strerror(status)});
    }

    state_ref->connect_done = true;
    state_ref->connect_started = false;

    if (state_ref->connect_continuation)
    {
      auto continuation = state_ref->connect_continuation;
      state_ref->connect_continuation = {};
      continuation.resume();
    }
  };
  auto copy = ret.handle;
  ret.handle->connect_req.data = copy.release_to_raw();
  int r = uv_tcp_connect(&ret.handle->connect_req, tcp.get_tcp(), addr, callback);
  if (r < 0)
  {
    ret.handle->connect_done = true;
    ret.handle->connect_result = std::unexpected(error_t{r, uv_strerror(r)});
    ref_ptr_t<tcp_state_t>::from_raw(ret.handle->connect_req.data);
  }
  return ret;
}

struct tcp_write_future_t
{
  ref_ptr_t<tcp_state_t> handle;
  explicit tcp_write_future_t(ref_ptr_t<tcp_state_t> handle)
    : handle(std::move(handle))
  {
  }
  bool await_ready() noexcept
  {
    return handle->write_done;
  }

  void await_suspend(std::coroutine_handle<> continuation) noexcept
  {
    if (handle->write_done)
    {
      continuation.resume();
    }
    else
    {
      handle->write_continuation = continuation;
    }
  }

  std::expected<void, error_t> await_resume() noexcept
  {
    return handle->write_result;
  }
};
inline tcp_write_future_t write_tcp(tcp_t &tcp, const uint8_t *data, std::size_t length)
{
  tcp_write_future_t ret(tcp.handle);

  uv_buf_t buf = uv_buf_init(reinterpret_cast<char *>(const_cast<uint8_t *>(data)), static_cast<unsigned int>(length));

  auto callback = [](uv_write_t *req, int status)
  {
    auto state_ref = ref_ptr_t<tcp_state_t>::from_raw(req->data);
    if (status < 0)
    {
      state_ref->write_result = std::unexpected(error_t{status, uv_strerror(status)});
    }
    state_ref->write_done = true;
    if (state_ref->write_continuation)
    {
      auto continuation = state_ref->write_continuation;
      state_ref->write_continuation = {};
      continuation.resume();
    }
  };

  auto copy = ret.handle;
  ret.handle->write_req.data = copy.release_to_raw();
  fprintf(stderr, "write_tcp: %p\n", ret.handle->get_stream());
  int r = uv_write(&ret.handle->write_req, tcp.get_stream(), &buf, 1, callback);

  if (r < 0)
  {
    ret.handle->write_done = true;
    ret.handle->write_result = std::unexpected(error_t{r, uv_strerror(r)});
    ref_ptr_t<tcp_state_t>::from_raw(ret.handle->write_req.data);
  }

  return ret;
}

class tcp_reader_t
{
public:
  tcp_reader_t(const tcp_reader_t &) = delete;
  tcp_reader_t &operator=(const tcp_reader_t &) = delete;

  tcp_reader_t(tcp_reader_t &&other) noexcept
    : handle(std::move(other.handle))
    , is_valid(other.is_valid)
  {
    other.is_valid = false;
  }

  tcp_reader_t &operator=(tcp_reader_t &&other) noexcept
  {
    if (this != &other)
    {
      handle = std::move(other.handle);
      is_valid = other.is_valid;
      other.is_valid = false;
    }
    return *this;
  }

  ~tcp_reader_t()
  {
    if (is_valid && handle->reader_started)
    {
      auto state = ref_ptr_t<tcp_state_t>::from_raw(handle->get_stream()->data);
      uv_read_stop(handle->get_stream());
      state->reader_started = false;
      state->reader_active = false;
    }
  }

  void cancel()
  {
    if (handle->reader_is_cancelled)
      return;

    handle->reader_is_cancelled = true;

    handle->buffer_queue_.emplace_back(std::unexpected(error_t{UV_ECANCELED, "Operation was cancelled"}));

    if (handle->read_continuation)
    {
      auto continuation = handle->read_continuation;
      handle->read_continuation = nullptr;
      continuation.resume();
    }
  }

  [[nodiscard]] bool is_cancelled() const
  {
    return handle->reader_is_cancelled;
  }

  struct awaiter
  {
    ref_ptr_t<tcp_state_t> state;

    bool await_ready() const
    {
      return !state->buffer_queue_.empty();
    }

    void await_suspend(std::coroutine_handle<> handle)
    {
      state->read_continuation = handle;
    }

    std::expected<tcp_read_buffer_t, error_t> await_resume()
    {
      auto result = std::move(state->buffer_queue_.front());
      state->buffer_queue_.erase(state->buffer_queue_.begin());
      if (!result.has_value())
      {
        return std::unexpected(result.error());
      }

      using unique_ptr_t = decltype(tcp_read_buffer_t::data);

      void *user_data = state->alloc_cb_data;
      dealloc_cb_t dealloc_cb = result.value().second;
      auto deallocator = [user_data, dealloc_cb](uint8_t *ptr)
      {
        char *char_ptr = reinterpret_cast<char *>(ptr);
        dealloc_cb(user_data, char_ptr);
      };
      unique_ptr_t ptr(reinterpret_cast<uint8_t *>(result.value().first.base), deallocator);

      return tcp_read_buffer_t{std::move(ptr), result.value().first.len};
    }
  };

  auto operator co_await()
  {
    return awaiter{this->handle};
  }

  struct ref_ptr_releaser
  {
    ref_ptr_releaser(ref_ptr_t<tcp_state_t> &handle)
      : handle(handle)
    {
    }

    ~ref_ptr_releaser()
    {
      handle.release_to_raw();
    }
    ref_ptr_t<tcp_state_t> &handle;
  };

  static void read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
  {
    auto tcp_state = ref_ptr_t<tcp_state_t>::from_raw(stream->data);
    ref_ptr_releaser releaser(tcp_state);

    if (nread > 0)
    {
      tcp_state->buffer_queue_.emplace_back(std::make_pair(*buf, tcp_state->dealloc_read_buffer_cb));
    }
    else
    {
      int code = UV_EOF;
      if (nread < 0)
        code = static_cast<int>(nread);
      auto error = std::unexpected(error_t{code, uv_strerror(static_cast<int>(nread))});
      tcp_state->buffer_queue_.emplace_back(std::move(error));

      if (buf && buf->base)
      {
        tcp_state->dealloc_read_buffer_cb(tcp_state->alloc_cb_data, buf->base);
      }
    }

    if (tcp_state->read_continuation)
    {
      auto continuation = tcp_state->read_continuation;
      tcp_state->read_continuation = nullptr;
      continuation.resume();
    }
  }

  ref_ptr_t<tcp_state_t> handle;
  friend std::expected<tcp_reader_t, error_t> tcp_create_reader(tcp_t &tcp);

private:
  tcp_reader_t(const tcp_t &tcp)
    : handle(tcp.handle)
    , is_valid(true)
  {
  }
  bool is_valid = false;
};

inline std::expected<tcp_reader_t, error_t> tcp_create_reader(tcp_t &tcp)
{
  if (tcp.handle.ptr() == nullptr)
  {
    return std::unexpected(error_t{1, "Can not create a reader for a closed socket"});
  }
  if (tcp.handle->reader_active)
  {
    return std::unexpected(error_t(1, "Can not create multiple active readers for a socket. Destroy other reader, before making a new one."));
  }

  auto alloc_cb = [](uv_handle_t *handle, size_t size, uv_buf_t *buf)
  {
    auto tcp_state = ref_ptr_t<tcp_state_t>::from_raw(handle->data);
    tcp_state->alloc_read_buffer_cb(tcp_state->alloc_cb_data, size, buf);
    tcp_state.release_to_raw();
  };
  fprintf(stderr, "tcp read start %p\n.", tcp.get_stream());
  auto copy = tcp.handle;
  tcp.get_stream()->data = copy.release_to_raw();
  if (const int r = uv_read_start(tcp.get_stream(), alloc_cb, &tcp_reader_t::read_cb); r >= 0)
  {

    tcp.handle->reader_active = true;
    tcp.handle->reader_started = true;
  }
  else
  {
    auto tcp_state = ref_ptr_t<tcp_state_t>::from_raw(tcp.get_stream()->data);
    return std::unexpected(error_t{r, uv_strerror(r)});
  }

  return tcp_reader_t{tcp};
}

} // namespace vio