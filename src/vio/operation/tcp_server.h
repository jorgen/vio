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
#include "tcp.h"
#include "vio/error.h"

#include "vio/event_loop.h"

#include <expected>

namespace vio
{
struct tcp_server_t
{
  tcp_t tcp;
};

inline std::expected<tcp_server_t, error_t> tcp_create_server(event_loop_t &event_loop)
{
  auto tcp = tcp_create(event_loop);
  if (!tcp.has_value())
  {
    return std::unexpected(tcp.error());
  }
  tcp_server_t ret{std::move(tcp.value())};
  return ret;
}

inline std::expected<void, error_t> tcp_bind(tcp_server_t &server, const sockaddr *addr, unsigned int flags = 0)
{
  const auto r = uv_tcp_bind(server.tcp.get_tcp(), addr, flags);
  if (r < 0)
  {
    return std::unexpected(error_t{r, uv_strerror(r)});
  }
  return {};
}

using tcp_listen_future_t = tcp_future_t<tcp_listen_state_t>;
inline tcp_listen_future_t tcp_listen(tcp_server_t &server, int backlog)
{
  tcp_listen_future_t ret(server.tcp.handle, server.tcp.handle->listen);

  auto on_connection = [](uv_stream_t *stream, int status)
  {
    auto stateRef = ref_ptr_t<tcp_state_t>::from_raw(stream->data);
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

  auto r = uv_listen(server.tcp.get_stream(), backlog, on_connection);
  if (r < 0)
  {
    ret.handle->listen.done = true;
    ret.handle->listen.result = std::unexpected(error_t{r, uv_strerror(r)});
    ref_ptr_t<tcp_state_t>::from_raw(ret.handle->uv_handle.data);
  }

  return std::move(ret);
}

inline std::expected<tcp_t, error_t> tcp_accept(tcp_server_t &server)
{
  if (!server.tcp.handle.ref_counted())
    return std::unexpected(error_t{-1, "It's not possible to accept a connection on a closed socket"});

  auto tcp_client = tcp_create(server.tcp.handle->event_loop);
  if (!tcp_client.has_value())
  {
    return std::unexpected(tcp_client.error());
  }
  auto client = std::move(tcp_client.value());

  if (const int r = uv_accept(server.tcp.get_stream(), client.get_stream()); r < 0)
  {
    return std::unexpected(error_t{r, uv_strerror(r)});
  }
  return std::move(client);
}

} // namespace vio
