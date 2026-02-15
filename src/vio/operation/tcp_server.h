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
    return std::unexpected(error_t{.code = r, .msg = uv_strerror(r)});
  }
  return {};
}

using tcp_listen_future_t = tcp_future_t<tcp_listen_state_t>;
inline tcp_listen_future_t tcp_listen(tcp_server_t &server, int backlog, cancellation_t *cancel = nullptr)
{
  tcp_listen_future_t ret(server.tcp.handle, server.tcp.handle->listen);

  if (cancel && cancel->is_cancelled())
  {
    ret.handle->listen.done = true;
    ret.handle->listen.result = std::unexpected(error_t{.code = vio_cancelled, .msg = "cancelled"});
    return std::move(ret);
  }

  auto on_connection = [](uv_stream_t *stream, int status)
  {
    if (!stream->data)
      return;
    auto state_ref = ref_ptr_t<tcp_state_t>::from_raw(stream->data);
    state_ref->listen.cancel_registration.reset();
    if (state_ref->listen.done)
      return;
    if (status < 0)
    {
      state_ref->listen.result = std::unexpected(error_t{.code = status, .msg = uv_strerror(status)});
    }
    state_ref->listen.done = true;
    if (state_ref->listen.continuation)
    {
      auto continuation = state_ref->listen.continuation;
      state_ref->listen.continuation = {};
      continuation.resume();
    }
  };

  auto copy = ret.handle;
  ret.handle->get_stream()->data = copy.release_to_raw();

  auto r = uv_listen(server.tcp.get_stream(), backlog, on_connection);
  if (r < 0)
  {
    ret.handle->listen.done = true;
    ret.handle->listen.result = std::unexpected(error_t{.code = r, .msg = uv_strerror(r)});
    ref_ptr_t<tcp_state_t>::from_raw(ret.handle->uv_handle.data);
  }
  else if (cancel)
  {
    auto *state_raw = &ret.handle.data();
    ret.handle->listen.cancel_registration = cancel->register_callback(
      [state_raw]()
      {
        if (state_raw->listen.done)
          return;
        state_raw->listen.done = true;
        state_raw->listen.result = std::unexpected(error_t{.code = vio_cancelled, .msg = "cancelled"});
        state_raw->listen.cancel_registration.reset();
        // Consume the raw ref stored by tcp_listen so the handle can be cleaned up
        auto *stream = state_raw->get_stream();
        if (stream->data)
        {
          auto consumed = ref_ptr_t<tcp_state_t>::from_raw(stream->data);
          stream->data = nullptr;
        }
        if (state_raw->listen.continuation)
        {
          auto cont = state_raw->listen.continuation;
          state_raw->listen.continuation = {};
          cont.resume();
        }
      });
  }

  return std::move(ret);
}

inline std::expected<tcp_t, error_t> tcp_accept(tcp_server_t &server)
{
  if (!server.tcp.handle.ref_counted())
    return std::unexpected(error_t{.code = -1, .msg = "It's not possible to accept a connection on a closed socket"});

  auto tcp_client = tcp_create(server.tcp.handle->event_loop);
  if (!tcp_client.has_value())
  {
    return std::unexpected(tcp_client.error());
  }
  auto client = std::move(tcp_client.value());

  if (const int r = uv_accept(server.tcp.get_stream(), client.get_stream()); r < 0)
  {
    return std::unexpected(error_t{.code = r, .msg = uv_strerror(r)});
  }
  return std::move(client);
}

} // namespace vio
