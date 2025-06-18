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
#include "vio/unique_buf.h"
#include "vio/uv_coro.h"

#include <coroutine>
#include <expected>
#include <string>
#include <utility>
#include <uv.h>

namespace vio
{
struct tcp_listen_state_t
{
  std::coroutine_handle<> continuation;
  std::expected<void, error_t> result;
  bool done = false;
};

struct tcp_connect_state_t
{
  uv_connect_t req = {};
  std::coroutine_handle<> continuation;
  std::expected<void, error_t> result;
  bool started = false;
  bool done = false;
};

struct tcp_write_state_t
{
  uv_write_t req = {};
  std::coroutine_handle<> continuation;
  std::expected<void, error_t> result;
  bool started = false;
  bool done = false;
};
struct tcp_read_state_t
{
  bool active = false;
  bool started = false;
  bool is_cancelled = false;
  bool cancelled = false;
  std::vector<std::expected<unique_buf_t, error_t>> buffer_queue;
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

  void await_suspend(std::coroutine_handle<> continuation) noexcept
  {
    if (state->done)
    {
      continuation.resume();
    }
    else
    {
      state->continuation = continuation;
    }
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

inline std::expected<tcp_t, error_t> tcp_create(event_loop_t &loop)
{
  tcp_t tcp{ref_ptr_t<tcp_state_t>(loop)};
  if (auto r = uv_tcp_init(loop.loop(), tcp.get_tcp()); r < 0)
  {
    return std::unexpected(error_t{r, uv_strerror(r)});
  }
  auto to_close = [](ref_ptr_t<tcp_state_t> &handle)
  {
    if (!handle.ptr())
    {
      return;
    }
    auto copy = handle;
    handle->get_handle()->data = copy.release_to_raw();
    auto close_cb = [](uv_handle_t *handle)
    {
      if (handle->data)
      {
        auto state_ref = ref_ptr_t<tcp_state_t>::from_raw(handle->data);
        handle->data = nullptr;
      }
      else
      {
        handle->data = nullptr;
      }
    };
    uv_close(handle->get_handle(), close_cb);
  };
  tcp.handle.set_close_guard(to_close);
  return tcp;
}

inline std::expected<void, error_t> tcp_bind(tcp_t &tcp, const sockaddr *addr, unsigned int flags = 0)
{
  const auto r = uv_tcp_bind(tcp.get_tcp(), addr, flags);
  if (r < 0)
  {
    return std::unexpected(error_t{r, uv_strerror(r)});
  }
  return {};
}

using tcp_listen_future_t = tcp_future_t<tcp_listen_state_t>;
inline tcp_listen_future_t tcp_listen(tcp_t &tcp, int backlog)
{
  tcp_listen_future_t ret(tcp.handle, tcp.handle->listen);

  auto on_connection = [](uv_stream_t *server, int status)
  {
    auto stateRef = ref_ptr_t<tcp_state_t>::from_raw(server->data);
    if (status < 0)
    {
      stateRef->listen.result = std::unexpected(error_t{status, uv_strerror(status)});
    }
    else
    {
    }
    stateRef->listen.done = true;
    if (stateRef->listen.continuation)
    {
      auto continuation = stateRef->listen.continuation;
      stateRef->listen.continuation = {};
      continuation.resume();
    }
  };

  auto copy = ret.handle;
  ret.handle->get_stream()->data = copy.release_to_raw();

  auto r = uv_listen(tcp.get_stream(), backlog, on_connection);
  if (r < 0)
  {
    ret.handle->listen.done = true;
    ret.handle->listen.result = std::unexpected(error_t{r, uv_strerror(r)});
    ref_ptr_t<tcp_state_t>::from_raw(ret.handle->uv_handle.data);
  }

  return std::move(ret);
}

inline std::expected<tcp_t, error_t> tcp_accept(tcp_t &server)
{
  if (!server.handle.ptr())
    return std::unexpected(error_t{-1, "It's not possible to accept a connection on a closed socket"});

  auto tcp_client = tcp_create(server.handle->event_loop);
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

using tcp_connect_future_t = tcp_future_t<tcp_connect_state_t>;
inline tcp_connect_future_t tcp_connect(tcp_t &tcp, const sockaddr *addr)
{
  tcp_connect_future_t ret(tcp.handle, tcp.handle->connect);
  if (ret.handle->connect.started)
  {
    ret.handle->connect.done = true;
    ret.handle->connect.result = std::unexpected(error_t{-1, "It's  an error to listen to more than one connect at a socket at the time"});
    return ret;
  }
  ret.handle->connect.started = true;
  ret.handle->connect.done = false;
  auto callback = [](uv_connect_t *req, int status)
  {
    auto state_ref = ref_ptr_t<tcp_state_t>::from_raw(req->data);
    if (status < 0)
    {
      state_ref->connect.result = std::unexpected(error_t{status, uv_strerror(status)});
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
    ret.handle->connect.result = std::unexpected(error_t{r, uv_strerror(r)});
    ref_ptr_t<tcp_state_t>::from_raw(ret.handle->connect.req.data);
  }
  return ret;
}

using tcp_write_future_t = tcp_future_t<tcp_write_state_t>;
inline tcp_write_future_t write_tcp(tcp_t &tcp, const uint8_t *data, std::size_t length)
{
  tcp_write_future_t ret(tcp.handle, tcp.handle->write);

  uv_buf_t buf = uv_buf_init(reinterpret_cast<char *>(const_cast<uint8_t *>(data)), static_cast<unsigned int>(length));

  auto callback = [](uv_write_t *req, int status)
  {
    auto state_ref = ref_ptr_t<tcp_state_t>::from_raw(req->data);
    if (status < 0)
    {
      state_ref->write.result = std::unexpected(error_t{status, uv_strerror(status)});
    }
    state_ref->write.done = true;
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
    ret.handle->write.result = std::unexpected(error_t{r, uv_strerror(r)});
    ref_ptr_t<tcp_state_t>::from_raw(ret.handle->write.req.data);
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
    if (is_valid && handle->read.started)
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
      return;

    handle->read.is_cancelled = true;

    handle->read.buffer_queue.emplace_back(std::unexpected(error_t{UV_ECANCELED, "Operation was cancelled"}));

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

  struct awaiter
  {
    ref_ptr_t<tcp_state_t> state;

    bool await_ready() const
    {
      return !state->read.buffer_queue.empty();
    }

    void await_suspend(std::coroutine_handle<> handle)
    {
      state->read.continuation = handle;
    }

    std::expected<unique_buf_t, error_t> await_resume()
    {
      auto result = std::move(state->read.buffer_queue.front());
      state->read.buffer_queue.erase(state->read.buffer_queue.begin());
      return result;
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
      tcp_state->read.buffer_queue.emplace_back(unique_buf_t(*buf, tcp_state->read.dealloc_buffer_cb, tcp_state->read.alloc_cb_data));
    }
    else
    {
      int code = UV_EOF;
      if (nread < 0)
        code = static_cast<int>(nread);
      auto error = std::unexpected(error_t{code, uv_strerror(static_cast<int>(nread))});
      tcp_state->read.buffer_queue.emplace_back(std::move(error));

      if (buf && buf->base)
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
  if (tcp.handle->read.active)
  {
    return std::unexpected(error_t(1, "Can not create multiple active readers for a socket. Destroy other reader, before making a new one."));
  }

  auto alloc_cb = [](uv_handle_t *handle, size_t size, uv_buf_t *buf)
  {
    auto tcp_state = ref_ptr_t<tcp_state_t>::from_raw(handle->data);
    tcp_state->read.alloc_buffer_cb(tcp_state->read.alloc_cb_data, size, buf);
    tcp_state.release_to_raw();
  };
  auto copy = tcp.handle;
  tcp.get_stream()->data = copy.release_to_raw();
  if (const auto r = uv_read_start(tcp.get_stream(), alloc_cb, &tcp_reader_t::read_cb); r >= 0)
  {
    tcp.handle->read.active = true;
    tcp.handle->read.started = true;
  }
  else
  {
    auto tcp_state = ref_ptr_t<tcp_state_t>::from_raw(tcp.get_stream()->data);
    return std::unexpected(error_t{r, uv_strerror(r)});
  }

  return tcp_reader_t{tcp};
}

} // namespace vio