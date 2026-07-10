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

#include "dns.h"
#include "vio/cancellation.h"
#include "vio/elastic_index_storage.h"
#include "vio/error.h"
#include "vio/operation/tcp.h"
#include "vio/operation/tls_common.h"
#include "vio/ref_counted_wrapper.h"
#include "vio/socket_stream.h"
#include "vio/ssl_config_t.h"
#include "vio/ssl_context.h"
#include "vio/ssl_engine.h"
#include "vio/unique_buf.h"

#include <coroutine>
#include <cstring>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <uv.h>

namespace vio
{
using tls_client_socket_stream_t = uv_tls_stream_t;

struct ssl_client_state_t
{
  uv_tcp_t tcp_handle = {};

  ssl_client_state_t(event_loop_t &event_loop, alloc_cb_t alloc_cb, dealloc_cb_t dealloc_cb, void *user_alloc_ptr)
    : event_loop(event_loop)
    , socket_stream(engine, alloc_cb, dealloc_cb, user_alloc_ptr)
  {
  }

  event_loop_t &event_loop;
  std::string host;
  std::string port;
  uv_getaddrinfo_t getaddrinfo_req = {};
  uv_connect_t connect_req = {};

  std::coroutine_handle<> connect_continuation;
  std::expected<void, error_t> connect_result;

  address_info_list_t addresses;
  int address_index = 0;
  bool connected = false;
  bool connecting = false;
  bool resolved_done = false;
  registration_t cancel_registration;

  // ssl_ctx built once from config; engine is the per-connection codec; declared
  // before socket_stream, which binds engine by reference.
  ssl_context_t ssl_ctx;
  ssl_engine_t engine;
  uv_tls_stream_t socket_stream;

  // Set only on the ssl_client_upgrade path, where an already-connected socket is
  // adopted instead of the embedded tcp_handle. Keeps the adopted uv handle alive.
  std::optional<tcp_t> adopted;

  uv_tcp_t *get_tcp()
  {
    return &tcp_handle;
  }

  uv_stream_t *get_tcp_stream()
  {
    return reinterpret_cast<uv_stream_t *>(&tcp_handle);
  }

  uv_handle_t *get_tcp_handle()
  {
    return reinterpret_cast<uv_handle_t *>(&tcp_handle);
  }

  static void connect_to_current_index(ref_ptr_t<ssl_client_state_t> &state)
  {
    if (!state->connecting)
      return;
    state.inc_ref_and_store_in_handle(state->connect_req);
    auto on_connect = [](uv_connect_t *req, int status)
    {
      auto state = ref_ptr_t<ssl_client_state_t>::from_raw(req->data);
      if (!state->connecting)
        return;
      if (status < 0)
      {
        state->address_index++;
        if (state->address_index < state->addresses.size())
        {
          connect_to_current_index(state);
        }
        else
        {
          state->cancel_registration.reset();
          state->connect_result = std::unexpected(error_t{.code = status, .msg = uv_strerror(status)});
          state->connecting = false;
          if (state->connect_continuation)
          {
            state->connect_continuation.resume();
          }
        }
        return;
      }

      // TCP is connected. Bring up the TLS engine and drive the handshake to
      // completion; connect only resolves once the handshake finishes (so ALPN
      // and certificate verification are known to the caller at connect time).
      if (auto err = state->engine.init(state->ssl_ctx, false, state->host); err.code != 0)
      {
        state->cancel_registration.reset();
        state->connecting = false;
        state->connect_result = std::unexpected(std::move(err));
        if (state->connect_continuation)
        {
          state->connect_continuation.resume();
        }
        return;
      }

      auto *state_raw = &state.data();
      state->socket_stream.on_handshake_complete = [state_raw](std::optional<error_t> err)
      {
        if (!state_raw->connecting)
          return;
        state_raw->cancel_registration.reset();
        state_raw->connecting = false;
        if (err)
        {
          state_raw->connect_result = std::unexpected(std::move(*err));
        }
        else
        {
          state_raw->connected = true;
          state_raw->connect_result = {};
        }
        if (state_raw->connect_continuation)
        {
          auto cont = state_raw->connect_continuation;
          state_raw->connect_continuation = {};
          cont.resume();
        }
      };
      state->socket_stream.begin_handshake();
    };
    auto connect_result = uv_tcp_connect(&state->connect_req, state->get_tcp(), state->addresses[state->address_index].get_sockaddr(), on_connect);
    if (connect_result < 0)
    {
      ref_ptr_t<ssl_client_state_t>::from_raw(state->connect_req.data);
      if (!state->connecting)
        return;
      state->address_index++;
      if (state->address_index < state->addresses.size())
      {
        connect_to_current_index(state);
      }
      else
      {
        state->cancel_registration.reset();
        state->connecting = false;
        state->connect_result = std::unexpected(error_t{.code = connect_result, .msg = uv_strerror(connect_result)});
        if (state->connect_continuation)
        {
          state->connect_continuation.resume();
        }
      }
    }
  }

  static void on_resolve_done(ref_ptr_t<ssl_client_state_t> &state, std::expected<address_info_list_t, error_t> &&result)
  {
    state->resolved_done = true;
    if (!state->connecting)
      return;
    if (!result.has_value())
    {
      state->cancel_registration.reset();
      state->connecting = false;
      state->connect_result = std::unexpected(std::move(result.error()));
      if (state->connect_continuation)
      {
        state->connect_continuation.resume();
      }
      return;
    }

    state->addresses = std::move(result.value());
    state->address_index = 0;
    connect_to_current_index(state);
  };
};

struct ssl_client_t
{
  ref_ptr_t<ssl_client_state_t> state;
};

inline std::expected<ssl_client_t, error_t> ssl_client_create(event_loop_t &event_loop, const ssl_config_t &config = {}, alloc_cb_t alloc_cb = default_alloc, dealloc_cb_t dealloc_cb = default_dealloc,
                                                              void *user_alloc_ptr = nullptr)
{
  ssl_client_t ret{ref_ptr_t<ssl_client_state_t>{event_loop, alloc_cb, dealloc_cb, user_alloc_ptr}};
  if (auto error = ret.state->ssl_ctx.init(false, config, get_default_ca_certificates()); error.code != 0)
  {
    return std::unexpected(std::move(error));
  }

  if (auto r = uv_tcp_init(event_loop.loop(), &ret.state->tcp_handle); r < 0)
  {
    return std::unexpected(error_t{.code = r, .msg = uv_strerror(r)});
  }
  ret.state.register_handle(&ret.state->tcp_handle);
  ret.state->socket_stream.bind(ret.state->get_tcp_stream(), ret.state.ref_counted());

  ret.state.on_destroy([state_raw = &ret.state.data()]() { state_raw->socket_stream.begin_teardown(); });

  return ret;
}

inline void impl_ssl_client_resolve_host(ssl_client_t &client)
{
  if (client.state.ref_counted() == nullptr)
  {
    ssl_client_state_t::on_resolve_done(client.state, std::unexpected(error_t{.code = 1, .msg = "Can not resolve host, client is closed"}));
  }

  if (client.state->host.empty())
  {
    ssl_client_state_t::on_resolve_done(client.state, std::unexpected(error_t{.code = 1, .msg = "Can not resolve host, host is empty"}));
  }

  client.state.inc_ref_and_store_in_handle(client.state->getaddrinfo_req);
  auto callback = [](uv_getaddrinfo_t *req, int status, addrinfo *res)
  {
    auto state = ref_ptr_t<ssl_client_state_t>::from_raw(req->data);
    std::expected<address_info_list_t, error_t> result;
    state->resolved_done = true;
    if (status < 0)
    {
      const error_t err = {.code = status, .msg = std::string(uv_strerror(status))};
      result = std::unexpected(err);
    }
    else
    {
      result = convert_addrinfo_list(res);
    }

    uv_freeaddrinfo(res);

    ssl_client_state_t::on_resolve_done(state, std::move(result));
  };

  addrinfo hints = {};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  if (const auto r = uv_getaddrinfo(client.state->event_loop.loop(), &client.state->getaddrinfo_req, callback, client.state->host.c_str(), client.state->port.c_str(), &hints); r < 0)
  {
    ref_ptr_t<ssl_client_state_t>::from_raw(client.state->getaddrinfo_req.data);
    ssl_client_state_t::on_resolve_done(client.state, std::unexpected(error_t{.code = r, .msg = uv_strerror(r)}));
  }
}

struct ssl_client_connecting_future_t
{
  ref_ptr_t<ssl_client_state_t> state;

  bool await_ready() noexcept
  {
    return state->connected || !state->connecting;
  }

  void await_suspend(std::coroutine_handle<> continuation) noexcept
  {
    state->connect_continuation = continuation;
  }

  auto await_resume() noexcept
  {
    return std::move(state->connect_result);
  }
};

inline ssl_client_connecting_future_t ssl_client_connect(ssl_client_t &client, const std::string &host, uint16_t port, cancellation_t *cancel = nullptr)
{
  if (client.state.ref_counted() == nullptr)
  {
    return {ref_ptr_t<ssl_client_state_t>::null()};
  }
  if (cancel && cancel->is_cancelled())
  {
    client.state->connecting = false;
    client.state->connect_result = std::unexpected(error_t{.code = vio_cancelled, .msg = "cancelled"});
    return {client.state};
  }
  client.state->host = host;
  client.state->port = std::to_string(port);
  client.state->connecting = true;
  client.state->resolved_done = false;
  impl_ssl_client_resolve_host(client);
  if (cancel && client.state->connecting)
  {
    auto *state_raw = &client.state.data();
    client.state->cancel_registration = cancel->register_callback(
      [state_raw]()
      {
        if (!state_raw->connecting)
          return;
        state_raw->connecting = false;
        state_raw->connect_result = std::unexpected(error_t{.code = vio_cancelled, .msg = "cancelled"});
        state_raw->cancel_registration.reset();
        if (!state_raw->resolved_done)
        {
          uv_cancel(reinterpret_cast<uv_req_t *>(&state_raw->getaddrinfo_req));
        }
        if (state_raw->connect_continuation)
        {
          auto cont = state_raw->connect_continuation;
          state_raw->connect_continuation = {};
          cont.resume();
        }
      });
  }
  return {client.state};
}

inline ssl_client_connecting_future_t ssl_client_connect(ssl_client_t &client, const std::string &host, uint16_t port, const std::string &ip, cancellation_t *cancel = nullptr)
{
  if (client.state.ref_counted() == nullptr)
  {
    return {ref_ptr_t<ssl_client_state_t>::null()};
  }
  if (cancel && cancel->is_cancelled())
  {
    client.state->connecting = false;
    client.state->connect_result = std::unexpected(error_t{.code = vio_cancelled, .msg = "cancelled"});
    return {client.state};
  }
  client.state->host = host;
  client.state->port = std::to_string(port);
  client.state->connecting = true;
  client.state->resolved_done = true;

  struct sockaddr_storage storage;
  int r = uv_ip4_addr(ip.c_str(), port, (struct sockaddr_in *)&storage);
  if (r < 0)
  {
    r = uv_ip6_addr(ip.c_str(), port, (struct sockaddr_in6 *)&storage);
  }
  if (r < 0)
  {
    client.state->connect_result = std::unexpected(error_t{.code = r, .msg = uv_strerror(r)});
    return {client.state};
  }

  struct addrinfo ai;
  std::memset(&ai, 0, sizeof(ai));
  ai.ai_family = storage.ss_family;
  ai.ai_socktype = SOCK_STREAM;
  ai.ai_protocol = IPPROTO_TCP;
  ai.ai_addr = (struct sockaddr *)&storage;
  ai.ai_addrlen = sizeof(storage);

  client.state->addresses.emplace_back(ai);
  client.state->address_index = 0;
  ssl_client_state_t::connect_to_current_index(client.state);
  if (cancel && client.state->connecting)
  {
    auto *state_raw = &client.state.data();
    client.state->cancel_registration = cancel->register_callback(
      [state_raw]()
      {
        if (!state_raw->connecting)
          return;
        state_raw->connecting = false;
        state_raw->connect_result = std::unexpected(error_t{.code = vio_cancelled, .msg = "cancelled"});
        state_raw->cancel_registration.reset();
        if (state_raw->connect_continuation)
        {
          auto cont = state_raw->connect_continuation;
          state_raw->connect_continuation = {};
          cont.resume();
        }
      });
  }
  return {client.state};
}

struct ssl_client_upgrade_future_t
{
  ssl_client_t client;

  bool await_ready() noexcept
  {
    return client.state->connected || !client.state->connecting;
  }

  void await_suspend(std::coroutine_handle<> continuation) noexcept
  {
    client.state->connect_continuation = continuation;
  }

  std::expected<ssl_client_t, error_t> await_resume() noexcept
  {
    if (!client.state->connect_result.has_value())
    {
      return std::unexpected(std::move(client.state->connect_result.error()));
    }
    return std::move(client);
  }
};

// Upgrade an already-connected plaintext tcp_t to a TLS client stream in place
// (PostgreSQL sslmode: plaintext SSLRequest + 'S'/'N', then TLS on the same
// socket). The caller MUST have torn down any plaintext tcp_reader_t on this
// socket first (bind() overwrites stream->data). host drives SNI + certificate
// hostname verification. Resolves after the handshake, so ALPN / verification are
// known when co_await returns.
inline ssl_client_upgrade_future_t ssl_client_upgrade(tcp_t &&tcp, const ssl_config_t &config, const std::string &host, cancellation_t *cancel = nullptr, alloc_cb_t alloc_cb = default_alloc,
                                                       dealloc_cb_t dealloc_cb = default_dealloc, void *user_alloc_ptr = nullptr)
{
  event_loop_t &event_loop = tcp.handle->event_loop;
  ssl_client_t ret{ref_ptr_t<ssl_client_state_t>{event_loop, alloc_cb, dealloc_cb, user_alloc_ptr}};

  if (auto error = ret.state->ssl_ctx.init(false, config, get_default_ca_certificates()); error.code != 0)
  {
    ret.state->connect_result = std::unexpected(std::move(error));
    return {std::move(ret)};
  }

  ret.state->host = host;
  ret.state->adopted.emplace(std::move(tcp));
  ret.state->connecting = true;

  if (cancel != nullptr && cancel->is_cancelled())
  {
    ret.state->connecting = false;
    ret.state->connect_result = std::unexpected(error_t{.code = vio_cancelled, .msg = "cancelled"});
    return {std::move(ret)};
  }

  if (auto error = ret.state->engine.init(ret.state->ssl_ctx, false, ret.state->host); error.code != 0)
  {
    ret.state->connecting = false;
    ret.state->connect_result = std::unexpected(std::move(error));
    return {std::move(ret)};
  }

  auto *state_raw = &ret.state.data();
  ret.state->socket_stream.on_handshake_complete = [state_raw](std::optional<error_t> err)
  {
    if (!state_raw->connecting)
      return;
    state_raw->cancel_registration.reset();
    state_raw->connecting = false;
    if (err)
    {
      state_raw->connect_result = std::unexpected(std::move(*err));
    }
    else
    {
      state_raw->connected = true;
      state_raw->connect_result = {};
    }
    if (state_raw->connect_continuation)
    {
      auto cont = state_raw->connect_continuation;
      state_raw->connect_continuation = {};
      cont.resume();
    }
  };
  ret.state.on_destroy([state_raw]() { state_raw->socket_stream.begin_teardown(); });
  ret.state->socket_stream.bind(ret.state->adopted->get_stream(), ret.state.ref_counted());
  ret.state->socket_stream.begin_handshake();

  if (cancel != nullptr && ret.state->connecting)
  {
    ret.state->cancel_registration = cancel->register_callback(
      [state_raw]()
      {
        if (!state_raw->connecting)
          return;
        state_raw->connecting = false;
        state_raw->connect_result = std::unexpected(error_t{.code = vio_cancelled, .msg = "cancelled"});
        state_raw->cancel_registration.reset();
        if (state_raw->connect_continuation)
        {
          auto cont = state_raw->connect_continuation;
          state_raw->connect_continuation = {};
          cont.resume();
        }
      });
  }

  return {std::move(ret)};
}

using tls_client_reader_t = stream_reader_t<ref_ptr_t<ssl_client_state_t>, tls_client_socket_stream_t>;
inline std::expected<tls_client_reader_t, error_t> ssl_client_create_reader(ssl_client_t &client)
{
  if (client.state.ref_counted() == nullptr)
  {
    return std::unexpected(error_t{.code = 1, .msg = "Can not create a reader for a closed client"});
  }
  if (client.state->socket_stream.reader_active)
  {
    return std::unexpected(error_t{.code = 1, .msg = "Can not create a reader for a client that already has a reader active"});
  }
  if (!client.state->connected)
  {
    return std::unexpected(error_t{.code = 1, .msg = "Can not create a reader for a client that is not connected"});
  }

  return tls_client_reader_t{client.state, &client.state->socket_stream};
}

using tls_client_write_awaitable_t = stream_write_awaitable_t<ref_ptr_t<ssl_client_state_t>, tls_client_socket_stream_t>;

// A cancellation resolves the write with vio_cancelled (e.g. a write_timeout
// bounding a slow reader). Because a cancelled TLS write may leave a partial
// record on the wire, the caller should close the connection afterwards.
inline tls_client_write_awaitable_t ssl_client_write(ssl_client_t &client, uv_buf_t buffer, cancellation_t *cancel = nullptr)
{
  assert(client.state.ref_counted() != nullptr && "Can not write to a closed client");
  assert(client.state->connected && "Can not write to a client that is not connected");

  auto &ss = client.state->socket_stream;
  auto idx = ss.write_queue.activate();
  ss.write_queue[idx].buf = buffer;
  if (cancel != nullptr && cancel->is_cancelled())
  {
    ss.cancel_write(idx);
    return {client.state, &ss, idx};
  }
  ss.begin_write(idx);
  if (cancel != nullptr)
  {
    ss.arm_write_cancel(idx, *cancel);
  }
  return {client.state, &ss, idx};
}

// Vectored write: coalesce several buffers into one TLS record + one uv_write.
inline tls_client_write_awaitable_t ssl_client_writev(ssl_client_t &client, std::span<const uv_buf_t> buffers, cancellation_t *cancel = nullptr)
{
  assert(client.state.ref_counted() != nullptr && "Can not write to a closed client");
  assert(client.state->connected && "Can not write to a client that is not connected");
  auto &ss = client.state->socket_stream;
  auto idx = ss.write_queue.activate();
  if (cancel != nullptr && cancel->is_cancelled())
  {
    ss.cancel_write(idx);
    return {client.state, &ss, idx};
  }
  ss.begin_writev(idx, buffers.data(), buffers.size());
  if (cancel != nullptr)
  {
    ss.arm_write_cancel(idx, *cancel);
  }
  return {client.state, &ss, idx};
}

// Half-close: send close_notify but keep reading. Resolves when it is on the wire.
inline tls_client_write_awaitable_t ssl_client_shutdown(ssl_client_t &client)
{
  assert(client.state.ref_counted() != nullptr && "Can not shut down a closed client");
  auto write_state_index = client.state->socket_stream.write_queue.activate();
  client.state->socket_stream.begin_shutdown(write_state_index);
  return {client.state, &client.state->socket_stream, write_state_index};
}

// Negotiated ALPN protocol, available after the handshake (i.e. after connect
// resolves). Returns nullopt if none was negotiated.
inline std::optional<std::string> ssl_client_alpn_selected(const ssl_client_t &client)
{
  if (client.state.ref_counted() == nullptr || !client.state->connected)
  {
    return std::nullopt;
  }
  auto s = client.state->engine.alpn_selected();
  if (s.empty())
  {
    return std::nullopt;
  }
  return s;
}

// True if the connection resumed a cached TLS session (requires a session_cache
// in the config and a prior connection to the same host). Valid after connect.
inline bool ssl_client_session_reused(const ssl_client_t &client)
{
  return client.state.ref_counted() != nullptr && client.state->connected && client.state->engine.session_reused();
}

// The server's stapled OCSP response (requires request_ocsp_staple in the config).
// Empty if none was received. Valid after connect.
inline std::vector<uint8_t> ssl_client_ocsp_response(const ssl_client_t &client)
{
  if (client.state.ref_counted() == nullptr || !client.state->connected)
  {
    return {};
  }
  return client.state->engine.ocsp_response();
}

} // namespace vio
