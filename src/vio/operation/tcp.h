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

#include "vio/uv_coro.h"
#include "vio/event_loop.h"
#include "vio/auto_closer.h"

#include <expected>
#include <string>
#include <utility>
#include <uv.h>

namespace vio
{

struct tcp_t
{
  event_loop_t *event_loop;
  uv_tcp_t handle;
};

inline void close_tcp(tcp_t *tcp)
{
  if (tcp && !uv_is_closing(reinterpret_cast<uv_handle_t *>(&tcp->handle)))
  {
    uv_close(reinterpret_cast<uv_handle_t *>(&tcp->handle), nullptr);
  }
}

using auto_close_tcp_t = auto_close_t<tcp_t, decltype(&close_tcp)>;
auto_close_tcp_t make_auto_close_tcp(tcp_t &&tcp)
{
  return auto_close_tcp_t(std::move(tcp), close_tcp);
}

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

inline std::expected<auto_close_tcp_t, error_t> create_tcp(event_loop_t &loop)
{
  tcp_t tcpInstance{&loop, {}};
  if (int r = uv_tcp_init(loop.loop(), &tcpInstance.handle); r < 0)
  {
    return std::unexpected(error_t{r, uv_strerror(r)});
  }
  return auto_close_tcp_t(std::move(tcpInstance), close_tcp);
}

inline std::expected<void, error_t> tcp_bind(tcp_t &tcp, const sockaddr *addr, unsigned int flags = 0)
{
  const int r = uv_tcp_bind(&tcp.handle, addr, flags);
  if (r < 0)
  {
    return std::unexpected(error_t{r, uv_strerror(r)});
  }
  return {};
}

inline std::expected<void, error_t> tcp_listen(tcp_t &tcp, int backlog, std::function<void(int)> connection_callback)
{
  // The connection callback is called on the listen event to let you handle accept.
  struct callback_data_t
  {
    std::function<void(int)> cb;
  };
  auto *dataPtr = new callback_data_t{std::move(connection_callback)};

  auto on_connection = [](uv_stream_t *server, int status)
  {
    auto *localData = reinterpret_cast<callback_data_t *>(server->data);
    if (localData && localData->cb)
    {
      localData->cb(status);
    }
  };

  tcp.handle.data = dataPtr;
  const int r = uv_listen(reinterpret_cast<uv_stream_t *>(&tcp.handle), backlog, on_connection);
  if (r < 0)
  {
    delete dataPtr;
    return std::unexpected(error_t{r, uv_strerror(r)});
  }
  return {};
}

inline std::expected<auto_close_tcp_t, error_t> tcp_accept(tcp_t &server)
{
  // Create a new tcp handle to accept into
  auto tcpClientOrError = create_tcp(*server.event_loop);
  if (!tcpClientOrError.has_value())
  {
    return std::unexpected(tcpClientOrError.error());
  }
  auto client = std::move(tcpClientOrError.value());

  const int r = uv_accept(reinterpret_cast<uv_stream_t *>(&server.handle), reinterpret_cast<uv_stream_t *>(&client->handle));
  if (r < 0)
  {
    return std::unexpected(error_t{r, uv_strerror(r)});
  }
  return client;
}

inline uv_coro_awaitable<uv_connect_t, void> tcp_connect(event_loop_t &loop, tcp_t &tcp, const sockaddr *addr)
{
  uv_coro_awaitable<uv_connect_t, void> ret;

  auto callback = [](uv_connect_t *req, int status)
  {
    auto stateRef = ref_ptr_t<uv_coro_state<uv_connect_t, void>>::from_raw(req->data);
    if (status < 0)
    {
      stateRef->result = std::unexpected(error_t{status, uv_strerror(status)});
    }
    else
    {
      // no specific "value" to return, so just success
      stateRef->result = {};
    }
    stateRef->done = true;
    if (stateRef->continuation)
    {
      stateRef->continuation.resume();
    }
    delete req; // Clean up
  };

  // Set up the connect request
  auto copy = ret.state;
  ret.state->req.data = copy.release_to_raw();

  int r = uv_tcp_connect(&ret.state->req, &tcp.handle, addr, callback);
  if (r < 0)
  {
    ret.state->done = true;
    ret.state->result = std::unexpected(error_t{r, uv_strerror(r)});
    ref_ptr_t<uv_coro_state<uv_connect_t, void>>::from_raw(ret.state->req.data);
  }

  return ret;
}

inline uv_coro_awaitable<uv_write_t, void> write_tcp(event_loop_t &loop, tcp_t &tcp, const uint8_t *data, std::size_t length)
{
  uv_coro_awaitable<uv_write_t, void> ret;

  uv_buf_t buf = uv_buf_init(reinterpret_cast<char *>(const_cast<uint8_t *>(data)), static_cast<unsigned int>(length));

  auto callback = [](uv_write_t *req, int status)
  {
    auto stateRef = ref_ptr_t<uv_coro_state<uv_write_t, std::size_t>>::from_raw(req->data);
    if (status < 0)
    {
      stateRef->result = std::unexpected(error_t{status, uv_strerror(status)});
    }
    stateRef->done = true;
    if (stateRef->continuation)
      stateRef->continuation.resume();
  };

  auto copy = ret.state;
  ret.state->req.data = copy.release_to_raw();

  int r = uv_write(&ret.state->req, reinterpret_cast<uv_stream_t *>(&tcp.handle), &buf, 1, callback);

  if (r < 0)
  {
    ret.state->done = true;
    ret.state->result = std::unexpected(error_t{r, uv_strerror(r)});
    ref_ptr_t<uv_coro_state<uv_write_t, std::size_t>>::from_raw(ret.state->req.data);
  }

  return ret;
}

//--------------------------------------------------------------------------------
// TCP read start (example that calls a callback on data arrival)
//--------------------------------------------------------------------------------
inline std::expected<void, error_t> tcp_read_start(tcp_t &tcp, std::function<void(const uint8_t *, ssize_t)> data_callback)
{
  struct callback_data_t
  {
    std::function<void(const uint8_t *, ssize_t)> cb;
  };
  auto *dataPtr = new callback_data_t{std::move(data_callback)};
  tcp.handle.data = dataPtr;

  auto alloc_cb = [](uv_handle_t * /*handle*/, size_t suggested_size, uv_buf_t *buf)
  {
    buf->base = reinterpret_cast<char *>(malloc(suggested_size));
    buf->len = suggested_size;
  };

  auto read_cb = [](uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
  {
    auto *localData = reinterpret_cast<callback_data_t *>(stream->data);
    if (nread > 0)
    {
      if (localData && localData->cb)
      {
        localData->cb(reinterpret_cast<const uint8_t *>(buf->base), nread);
      }
    }
    if (buf->base)
    {
      free(buf->base);
    }
  };

  const int r = uv_read_start(reinterpret_cast<uv_stream_t *>(&tcp.handle), alloc_cb, read_cb);
  if (r < 0)
  {
    delete dataPtr;
    return std::unexpected(error_t{r, uv_strerror(r)});
  }
  return {};
}

inline std::expected<void, error_t> tcp_read_stop(tcp_t &tcp)
{
  const int r = uv_read_stop(reinterpret_cast<uv_stream_t *>(&tcp.handle));
  if (r < 0)
  {
    return std::unexpected(error_t{r, uv_strerror(r)});
  }
  return {};
}

} // namespace vio