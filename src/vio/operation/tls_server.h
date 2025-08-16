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
#include "vio/ref_ptr.h"
#include "vio/ssl_config_t.h"

#include <expected>
#include <tls.h>

namespace vio
{
struct ssl_server_state_t
{
  event_loop_t &event_loop;
  vio::tcp_server_t tcp = {};
  std::string host;
  tls *tls_ctx = nullptr;
  alloc_cb_t alloc_cb = {};
  dealloc_cb_t dealloc_cb = {};
  void *user_alloc_ptr = nullptr;
};

struct tls_server_client_tls_t : tls_client_stream_t
{
  error_t initialize(const ssl_config_t &_config)
  {
    return {};
  }
};

struct ssl_server_client_state_t
{
  ssl_server_client_state_t(event_loop_t &event_loop, tls *tls_ctx, tcp_t &&tcp, int socket_fd, alloc_cb_t alloc_cb, dealloc_cb_t dealloc_cb, void *user_alloc_ptr)
    : event_loop(event_loop)
    , tls_ctx(tls_ctx)
    , tcp(std::move(tcp))
    , socket_fd(socket_fd)
    , socket_stream(event_loop, alloc_cb, dealloc_cb, user_alloc_ptr)
  {
  }
  event_loop_t &event_loop;
  tls *tls_ctx;
  tcp_t tcp;
  int socket_fd;
  socket_stream_t<tls_server_client_tls_t> socket_stream;
};

struct ssl_server_t
{
  ref_ptr_t<ssl_server_state_t> handle;
};

struct ssl_server_client_t
{
  ref_ptr_t<ssl_server_client_state_t> handle;
};

inline std::expected<ssl_server_t, error_t> ssl_server_create(vio::event_loop_t &event_loop, vio::tcp_server_t &&server, const std::string &host, const ssl_config_t &config = {}, alloc_cb_t alloc_cb = default_alloc,
                                                              dealloc_cb_t dealloc_cb = default_dealloc, void *user_alloc_ptr = nullptr)
{
  auto tls_server_handle = tls_server();
  if (!tls_server_handle)
  {
    return std::unexpected(error_t{-1, "failed to create tls_server handle."});
  }
  auto apply_ssl_config_result = apply_ssl_config_to_tls_ctx(config, get_default_ca_certificates(), tls_server_handle);
  if (apply_ssl_config_result.code != 0)
  {
    return std::unexpected(apply_ssl_config_result);
  }

  return ssl_server_t{ref_ptr_t<ssl_server_state_t>(event_loop, std::move(server), host, tls_server_handle, alloc_cb, dealloc_cb, user_alloc_ptr)};
}

inline tcp_listen_future_t ssl_server_listen(ssl_server_t &server, int backlog)
{
  return tcp_listen(server.handle->tcp, backlog);
}

inline std::expected<ssl_server_client_t, error_t> ssl_server_accept(ssl_server_t &server)
{
  if (server.handle.ptr() == nullptr)
  {
    return std::unexpected(error_t{.code = -1, .msg = "It's not possible to accept a connection on a closed TLS socket"});
  }

  auto tcp_client = tcp_accept(server.handle->tcp);
  if (!tcp_client.has_value())
  {
    return std::unexpected(tcp_client.error());
  }
  auto server_client = ssl_server_client_t{
    ref_ptr_t<ssl_server_client_state_t>(server.handle->event_loop, server.handle->tls_ctx, std::move(tcp_client.value()), -1, server.handle->alloc_cb, server.handle->dealloc_cb, server.handle->user_alloc_ptr)};

  uv_os_fd_t socket;
  if (uv_fileno(server_client.handle->tcp.get_handle(), &socket) == 0)
  {
    server_client.handle->socket_fd = *reinterpret_cast<int *>(&socket);
    if (auto socket_err = server_client.handle->socket_stream.connect(server_client.handle->socket_fd, server.handle->host); socket_err.code == 0)
    {
      return std::unexpected(socket_err);
    }
  }
  tls *client = {};
  if (auto client_handle = tls_accept_socket(server.handle->tls_ctx, &client, server_client.handle->socket_fd))
  {
    return std::unexpected(error_t{.code = client_handle, .msg = tls_error(server.handle->tls_ctx)});
  }

  return std::move(server_client);
}

} // namespace vio
