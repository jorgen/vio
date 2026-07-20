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

#include "vio/operation/tcp.h"
#include "tcp.h"
#include "tcp_server.h"
#include "tls_client.h"
#include "tls_common.h"
#include "vio/error.h"
#include "vio/event_loop.h"
#include "vio/ref_counted_wrapper.h"
#include "vio/ssl_config_t.h"
#include "vio/ssl_context.h"
#include "vio/ssl_engine.h"

#include <coroutine>
#include <expected>
#include <optional>

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
  ssl_context_t ssl_ctx; // shared server SSL_CTX; the accepted SSL* references it
};

using tls_server_socket_stream_t = uv_tls_stream_t;

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
  uv_tls_stream_t socket_stream;

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

  ret.handle.on_destroy(
    [state_raw = &ret.handle.data()]()
    {
      // Cancel any pending listen operation (the SSL_CTX is freed by ssl_ctx's
      // destructor). Preserved verbatim from the libtls path.
      auto &tcp_handle = state_raw->tcp.tcp.handle;
      auto &listen = tcp_handle->listen;
      if (!listen.done)
      {
        listen.done = true;
        listen.result = std::unexpected(error_t{.code = -1, .msg = "Server destroyed while listening"});
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

inline tcp_listen_future_t ssl_server_listen(ssl_server_t &server, int backlog, cancellation_t *cancel = nullptr)
{
  return tcp_listen(server.handle->tcp, backlog, cancel);
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

  auto server_client = ssl_server_client_t{ref_ptr_t<ssl_server_client_state_t>(server.handle->event_loop, std::move(client_tcp), server.handle->alloc_cb, server.handle->dealloc_cb, server.handle->user_alloc_ptr)};

  auto &state = server_client.handle;
  if (auto err = state->engine.init(server.handle->ssl_ctx, true, std::string{}); err.code != 0)
  {
    return std::unexpected(std::move(err));
  }
  state->socket_stream.bind(state->tcp.get_stream(), state.ref_counted());

  auto *state_raw = &state.data();
  state->socket_stream.on_handshake_complete = [state_raw](std::optional<error_t> err)
  {
    state_raw->handshake_done = true;
    state_raw->handshake_result = err ? std::expected<void, error_t>{std::unexpect, std::move(*err)} : std::expected<void, error_t>{};
    if (state_raw->handshake_continuation)
    {
      auto cont = state_raw->handshake_continuation;
      state_raw->handshake_continuation = {};
      cont.resume();
    }
  };
  // Drive the handshake lazily: reads are armed and the handshake advances as the
  // ClientHello arrives. A write or reader issued before completion still works
  // (server-speaks-first) because SSL_write is retried once the handshake finishes.
  state->socket_stream.begin_handshake();

  state.on_destroy([state_raw]() { state_raw->socket_stream.begin_teardown(); });
  return std::move(server_client);
}

// Finish the TLS handshake (SSL_accept) before reading, so the negotiated ALPN
// protocol and client-certificate verification are known up front. Optional --
// a reader created before completion drives the handshake lazily.
struct tls_server_client_handshake_future_t
{
  ref_ptr_t<ssl_server_client_state_t> handle;

  bool await_ready() noexcept
  {
    return handle.ref_counted() == nullptr || handle->handshake_done;
  }
  void await_suspend(std::coroutine_handle<> continuation) noexcept
  {
    handle->handshake_continuation = continuation;
  }
  std::expected<void, error_t> await_resume() noexcept
  {
    if (handle.ref_counted() == nullptr)
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
  if (client.handle.ref_counted() == nullptr)
  {
    return std::unexpected(error_t{.code = 1, .msg = "Can not create a reader for a closed client"});
  }
  if (client.handle->socket_stream.reader_active)
  {
    return std::unexpected(error_t{.code = 1, .msg = "Can not create a reader for a client that already has a reader active"});
  }

  return tls_server_client_reader_t{client.handle, &client.handle->socket_stream};
}

using tls_server_client_write_awaitable_t = stream_write_awaitable_t<ref_ptr_t<ssl_server_client_state_t>, tls_server_socket_stream_t>;

// A cancellation resolves the write with vio_cancelled (e.g. a write_timeout
// bounding a slow reader). A cancelled TLS write may leave a partial record on
// the wire, so the caller should close the connection afterwards.
inline tls_server_client_write_awaitable_t ssl_server_client_write(ssl_server_client_t &client, uv_buf_t buffer, cancellation_t *cancel = nullptr)
{
  assert(client.handle.ref_counted() != nullptr && "Can not write to a closed client");

  auto &ss = client.handle->socket_stream;
  auto idx = ss.write_queue.activate();
  ss.write_queue[idx].buf = buffer;
  if (cancel != nullptr && cancel->is_cancelled())
  {
    ss.cancel_write(idx);
    return {client.handle, &ss, idx};
  }
  ss.begin_write(idx);
  if (cancel != nullptr)
  {
    ss.arm_write_cancel(idx, *cancel);
  }
  return {client.handle, &ss, idx};
}

// Vectored write: coalesce several buffers into one TLS record + one uv_write.
inline tls_server_client_write_awaitable_t ssl_server_client_writev(ssl_server_client_t &client, std::span<const uv_buf_t> buffers, cancellation_t *cancel = nullptr)
{
  assert(client.handle.ref_counted() != nullptr && "Can not write to a closed client");
  auto &ss = client.handle->socket_stream;
  auto idx = ss.write_queue.activate();
  if (cancel != nullptr && cancel->is_cancelled())
  {
    ss.cancel_write(idx);
    return {client.handle, &ss, idx};
  }
  ss.begin_writev(idx, buffers.data(), buffers.size());
  if (cancel != nullptr)
  {
    ss.arm_write_cancel(idx, *cancel);
  }
  return {client.handle, &ss, idx};
}

// Half-close: send close_notify but keep reading. Resolves when it is on the wire.
inline tls_server_client_write_awaitable_t ssl_server_client_shutdown(ssl_server_client_t &client)
{
  assert(client.handle.ref_counted() != nullptr && "Can not shut down a closed client");
  auto write_state_index = client.handle->socket_stream.write_queue.activate();
  client.handle->socket_stream.begin_shutdown(write_state_index);
  return {client.handle, &client.handle->socket_stream, write_state_index};
}

inline std::optional<std::string> ssl_server_client_alpn_selected(const ssl_server_client_t &client)
{
  if (client.handle.ref_counted() == nullptr || !client.handle->handshake_done)
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

// The remote peer's IP address for an accepted TLS client (its underlying TCP
// connection). Empty if unavailable.
inline std::string ssl_server_client_peer_ip(ssl_server_client_t &client)
{
  if (client.handle.ref_counted() == nullptr)
  {
    return {};
  }
  return peer_ip(client.handle->tcp.get_tcp());
}

} // namespace vio
