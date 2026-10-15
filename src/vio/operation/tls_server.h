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
#include "vio/errc.h"
#include "vio/error.h"
#include "vio/event_loop.h"
#include "vio/ref_counted_wrapper.h"
#include "vio/socket_stream.h"
#include "vio/ssl_config_t.h"
#include "vio/ssl_context.h"
#include "vio/ssl_engine.h"

#include <coroutine>
#include <expected>
#include <optional>
#include <span>
#include <string>

namespace vio
{

struct tls_server_state_t
{
  event_loop_t &event_loop;
  vio::tcp_server_t tcp;
  std::string host;
  alloc_cb_t alloc_cb;
  dealloc_cb_t dealloc_cb;
  void *user_alloc_ptr;
  ssl_context_t ssl_ctx = {};
};

using tls_server_socket_stream_t = tls_stream_t;

struct ssl_server_client_state_t
{
  ssl_server_client_state_t(event_loop_t &event_loop, tcp_t &&tcp, alloc_cb_t alloc_cb, dealloc_cb_t dealloc_cb, void *user_alloc_ptr)
    : event_loop(event_loop)
    , tcp(std::move(tcp))
    , socket_stream(engine, alloc_cb, dealloc_cb, user_alloc_ptr)
  {
  }
  event_loop_t &event_loop;
  tcp_t tcp;

  ssl_engine_t engine;
  tls_stream_t socket_stream;

  bool handshake_done = false;
  std::coroutine_handle<> handshake_continuation;
  std::expected<void, error_t> handshake_result;
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
  if (auto error = ret.handle->ssl_ctx.init(true, config, get_default_ca_certificates()); error.code != 0)
  {
    return std::unexpected(std::move(error));
  }

  ret.handle.on_destroy([state_raw = &ret.handle.data()]() { tcp_listen_abort(state_raw->tcp, error_t{.code = errc::canceled, .msg = "Server destroyed while listening"}); });

  return ret;
}

inline tcp_listen_future_t ssl_server_listen(ssl_server_t &server, int backlog, cancellation_t *cancel = nullptr)
{
  if (!server.handle)
  {
    tcp_server_t closed{tcp_t{ref_ptr_t<tcp_state_t>::null()}};
    return tcp_listen(closed, backlog, cancel);
  }
  return tcp_listen(server.handle->tcp, backlog, cancel);
}

inline std::expected<ssl_server_client_t, error_t> ssl_server_accept(ssl_server_t &server)
{
  if (!server.handle)
  {
    return std::unexpected(error_t{.code = errc::bad_descriptor, .msg = "It's not possible to accept a connection on a closed TLS socket"});
  }

  auto tcp_accept_result = tcp_accept(server.handle->tcp);
  if (!tcp_accept_result.has_value())
  {
    return std::unexpected(tcp_accept_result.error());
  }

  auto server_client = ssl_server_client_t{ref_ptr_t<ssl_server_client_state_t>(server.handle->event_loop, std::move(tcp_accept_result.value()), server.handle->alloc_cb, server.handle->dealloc_cb, server.handle->user_alloc_ptr)};

  auto &state = server_client.handle;
  if (auto err = state->engine.init(server.handle->ssl_ctx, true, std::string{}); err.code != 0)
  {
    return std::unexpected(std::move(err));
  }
  state->socket_stream.bind(state->tcp.handle->socket, state.ref_counted());

  auto *state_raw = &state.data();
  state->socket_stream.on_handshake_complete = [state_raw](std::optional<error_t> err) {
    state_raw->handshake_done = true;
    state_raw->handshake_result = err ? std::expected<void, error_t>{std::unexpect, std::move(*err)} : std::expected<void, error_t>{};
    if (auto continuation = std::exchange(state_raw->handshake_continuation, {}))
    {
      continuation.resume();
    }
  };
  state.on_destroy([state_raw]() { state_raw->socket_stream.begin_teardown(); });
  state->socket_stream.begin_handshake();
  return server_client;
}

// Finish the TLS handshake (SSL_accept) before reading, so the negotiated ALPN
// protocol and client-certificate verification are known up front. Optional --
// a reader created before completion drives the handshake lazily.
struct tls_server_client_handshake_future_t
{
  ref_ptr_t<ssl_server_client_state_t> handle;

  bool await_ready() noexcept
  {
    return !handle || handle->handshake_done;
  }
  void await_suspend(std::coroutine_handle<> continuation) noexcept
  {
    handle->handshake_continuation = continuation;
  }
  std::expected<void, error_t> await_resume() noexcept
  {
    if (!handle)
    {
      return std::unexpected(error_t{.code = vio_tls_error, .msg = "Closed"});
    }
    return handle->handshake_result;
  }
};

inline tls_server_client_handshake_future_t ssl_server_client_handshake(ssl_server_client_t &client)
{
  return {client.handle};
}

using tls_server_client_reader_t = stream_reader_t<ref_ptr_t<ssl_server_client_state_t>, tls_server_socket_stream_t>;
inline std::expected<tls_server_client_reader_t, error_t> ssl_server_client_create_reader(ssl_server_client_t &client)
{
  if (!client.handle)
  {
    return std::unexpected(error_t{.code = errc::bad_descriptor, .msg = "Can not create a reader for a closed client"});
  }
  if (client.handle->socket_stream.reader_active)
  {
    return std::unexpected(error_t{.code = errc::busy, .msg = "Can not create a reader for a client that already has a reader active"});
  }

  return tls_server_client_reader_t{client.handle, &client.handle->socket_stream};
}

using tls_server_client_write_awaitable_t = stream_write_awaitable_t<ref_ptr_t<ssl_server_client_state_t>, tls_server_socket_stream_t>;

inline tls_server_client_write_awaitable_t ssl_server_client_write(ssl_server_client_t &client, std::span<const std::byte> buffer, cancellation_t *cancel = nullptr)
{
  if (!client.handle)
  {
    return {ref_ptr_t<ssl_server_client_state_t>::null(), nullptr, 0};
  }
  auto &ss = client.handle->socket_stream;
  auto idx = ss.write_queue.activate();
  ss.write_queue[idx].data = buffer.data();
  ss.write_queue[idx].size = buffer.size();
  tls_server_client_write_awaitable_t ret{client.handle, &ss, idx};
  if (cancel != nullptr && cancel->is_cancelled())
  {
    ss.cancel_write(idx);
    return ret;
  }
  if (cancel != nullptr)
  {
    ss.arm_write_cancel(idx, *cancel);
  }
  ss.begin_write(idx);
  return ret;
}

inline tls_server_client_write_awaitable_t ssl_server_client_write(ssl_server_client_t &client, const void *data, std::size_t length, cancellation_t *cancel = nullptr)
{
  return ssl_server_client_write(client, std::span<const std::byte>(static_cast<const std::byte *>(data), length), cancel);
}

inline tls_server_client_write_awaitable_t ssl_server_client_writev(ssl_server_client_t &client, std::span<const std::span<const std::byte>> buffers, cancellation_t *cancel = nullptr)
{
  if (!client.handle)
  {
    return {ref_ptr_t<ssl_server_client_state_t>::null(), nullptr, 0};
  }
  auto &ss = client.handle->socket_stream;
  auto idx = ss.write_queue.activate();
  tls_server_client_write_awaitable_t ret{client.handle, &ss, idx};
  if (cancel != nullptr && cancel->is_cancelled())
  {
    ss.cancel_write(idx);
    return ret;
  }
  if (cancel != nullptr)
  {
    ss.arm_write_cancel(idx, *cancel);
  }
  ss.begin_writev(idx, buffers);
  return ret;
}

inline tls_server_client_write_awaitable_t ssl_server_client_shutdown(ssl_server_client_t &client)
{
  if (!client.handle)
  {
    return {ref_ptr_t<ssl_server_client_state_t>::null(), nullptr, 0};
  }
  auto &ss = client.handle->socket_stream;
  auto idx = ss.write_queue.activate();
  tls_server_client_write_awaitable_t ret{client.handle, &ss, idx};
  ss.begin_shutdown(idx);
  return ret;
}

inline std::optional<std::string> ssl_server_client_alpn_selected(const ssl_server_client_t &client)
{
  if (!client.handle || !client.handle->handshake_done)
  {
    return std::nullopt;
  }
  auto s = client.handle->engine.alpn_selected();
  if (s.empty())
  {
    return std::nullopt;
  }
  return s;
}

inline std::string ssl_server_client_peer_ip(ssl_server_client_t &client)
{
  if (!client.handle)
  {
    return {};
  }
  return peer_ip(client.handle->tcp);
}

} // namespace vio
