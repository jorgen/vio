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
#include "tcp_server.h"
#include "tls_client.h"
#include "tls_common.h"
#include "vio/error.h"
#include "vio/event_loop.h"
#include "vio/ref_counted_wrapper.h"
#include "vio/ssl_config_t.h"

#include <expected>
#include <tls.h>

namespace vio
{

struct tls_server_client_tls_t
{
  tls *stream_tls_ctx = nullptr;
  void close()
  {
    tls_close(stream_tls_ctx);
    tls_free(stream_tls_ctx);
  }
};

struct tls_native_server_ctx_t
{
  error_t initialize(const ssl_config_t &config)
  {
    tls_ctx = tls_server();
    if (tls_ctx == nullptr)
    {
      return error_t{.code = -1, .msg = "failed to create tls_server handle."};
    }
    return apply_ssl_config_to_tls_ctx(config, get_default_ca_certificates(), tls_ctx);
  }

  std::expected<tls_server_client_tls_t, error_t> accept(int socket_fd)
  {
    tls *client = nullptr;
    if (auto result = tls_accept_socket(tls_ctx, &client, socket_fd); result < 0)
    {
      return std::unexpected(error_t{.code = result, .msg = tls_error(tls_ctx)});
    }
    return tls_server_client_tls_t{client};
  }

  tls *tls_ctx = nullptr;
};

template <typename NATIVE_SERVER_CTX>
struct ssl_server_state_t
{
  event_loop_t &event_loop;
  vio::tcp_server_t tcp;
  std::string host;
  alloc_cb_t alloc_cb;
  dealloc_cb_t dealloc_cb;
  void *user_alloc_ptr;
  NATIVE_SERVER_CTX tls_ctx;
};

using tls_server_state_t = ssl_server_state_t<tls_native_server_ctx_t>;

using tls_native_server_stream_t = tls_stream_t<tls_server_client_tls_t>;
using tls_server_socket_stream_t = vio::socket_stream_t<tls_native_server_stream_t>;
struct ssl_server_client_state_t
{
  ssl_server_client_state_t(event_loop_t &event_loop, tcp_t &&tcp, tls_server_client_tls_t &&tls, alloc_cb_t alloc_cb, dealloc_cb_t dealloc_cb, void *user_alloc_ptr)
    : event_loop(event_loop)
    , tcp(std::move(tcp))
    , connection_handler(tls)
    , native_stream(connection_handler)
    , socket_stream(native_stream, event_loop, alloc_cb, dealloc_cb, user_alloc_ptr)
  {
  }
  event_loop_t &event_loop;
  tcp_t tcp;

  tls_server_client_tls_t connection_handler;
  tls_native_server_stream_t native_stream;
  tls_server_socket_stream_t socket_stream;
};

struct ssl_server_t
{
  ref_ptr_t<tls_server_state_t> handle;
};

struct ssl_server_client_t
{
  ref_ptr_t<ssl_server_client_state_t> handle;
};

inline std::expected<ssl_server_t, error_t> ssl_server_create(vio::event_loop_t &event_loop, vio::tcp_server_t &&server, const std::string &host, const ssl_config_t &config = {}, alloc_cb_t alloc_cb = default_alloc,
                                                              dealloc_cb_t dealloc_cb = default_dealloc, void *user_alloc_ptr = nullptr)
{
  auto ret = ssl_server_t{ref_ptr_t<tls_server_state_t>(event_loop, std::move(server), host, alloc_cb, dealloc_cb, user_alloc_ptr)};
  if (auto error = ret.handle->tls_ctx.initialize(config); error.code != 0)
  {
    return std::unexpected(std::move(error));
  }

  ret.handle.on_destroy(
    [state_raw = &ret.handle.data()]()
    {
      // Cancel any pending listen operation
      auto &tcp_handle = state_raw->tcp.tcp.handle;
      auto &listen = tcp_handle->listen;
      if (!listen.done)
      {
        listen.done = true;
        listen.result = std::unexpected(error_t{-1, "Server destroyed while listening"});
        if (listen.continuation)
        {
          auto cont = listen.continuation;
          listen.continuation = {};
          cont.resume();
        }
        // Consume the raw ref stored by tcp_listen in stream->data
        auto *stream = tcp_handle->get_stream();
        if (stream->data)
        {
          auto consumed = ref_ptr_t<tcp_state_t>::from_raw(stream->data);
          stream->data = nullptr;
        }
      }
    });

  return std::move(ret);
}

inline tcp_listen_future_t ssl_server_listen(ssl_server_t &server, int backlog)
{
  return tcp_listen(server.handle->tcp, backlog);
}

inline std::expected<ssl_server_client_t, error_t> ssl_server_accept(ssl_server_t &server)
{
  if (server.handle.ref_counted() == nullptr)
  {
    return std::unexpected(error_t{.code = -1, .msg = "It's not possible to accept a connection on a closed TLS socket"});
  }

  auto tcp_accept_result = tcp_accept(server.handle->tcp);
  if (!tcp_accept_result.has_value())
  {
    return std::unexpected(tcp_accept_result.error());
  }

  auto client_tcp = std::move(tcp_accept_result.value());
  uv_os_fd_t socket;
  if (uv_fileno(client_tcp.get_handle(), &socket) != 0)
  {
    return std::unexpected(error_t{.code = -1, .msg = "Failed to get socket file descriptor"});
  }
  int socket_fd = *reinterpret_cast<int *>(&socket);

  auto tls_client = server.handle->tls_ctx.accept(socket_fd);

  if (!tls_client.has_value())
  {
    return std::unexpected(tls_client.error());
  }

  auto server_client = ssl_server_client_t{
    ref_ptr_t<ssl_server_client_state_t>(server.handle->event_loop, std::move(client_tcp), std::move(tls_client.value()), server.handle->alloc_cb, server.handle->dealloc_cb, server.handle->user_alloc_ptr)};
  server_client.handle->socket_stream.connect(socket_fd);

  server_client.handle.on_destroy(
    [state_raw = &server_client.handle.data(), rc = server_client.handle.ref_counted()]()
    {
      state_raw->connection_handler.close();
      if (state_raw->socket_stream.connected)
      {
        state_raw->socket_stream.closed = true;
        uv_poll_stop(&state_raw->socket_stream.poll_req);
        rc->register_closable_handle(reinterpret_cast<uv_handle_t *>(&state_raw->socket_stream.poll_req));
      }
    });
  return std::move(server_client);
}

using tls_server_client_reader_t = stream_reader_t<ref_ptr_t<ssl_server_client_state_t>, tls_server_socket_stream_t>;
inline std::expected<tls_server_client_reader_t, error_t> ssl_server_client_create_reader(ssl_server_client_t &client)
{
  if (client.handle.ref_counted() == nullptr)
  {
    return std::unexpected(error_t{1, "Can not create a reader for a closed client"});
  }
  if (client.handle->socket_stream.reader_active)
  {
    return std::unexpected(error_t{1, "Can not create a reader for a client that already has a reader active"});
  }

  return tls_server_client_reader_t{client.handle, &client.handle->socket_stream};
}

using tls_server_client_write_awaitable_t = stream_write_awaitable_t<ref_ptr_t<ssl_server_client_state_t>, tls_server_socket_stream_t>;
inline tls_server_client_write_awaitable_t ssl_server_client_write(ssl_server_client_t &client, uv_buf_t buffer)
{
  assert(client.handle.ref_counted() != nullptr && "Can not write to a closed client");

  auto write_state_index = client.handle->socket_stream.write_queue.activate();
  client.handle->socket_stream.write_queue[write_state_index].buf = buffer;

  client.handle->socket_stream.write();
  client.handle->socket_stream.set_poll_state();
  return {client.handle, &client.handle->socket_stream, write_state_index};
}

} // namespace vio
