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
#include "vio/detail/exceptions.h"
#include "vio/detail/sys.h"
#include "vio/errc.h"
#include "vio/error.h"
#include "vio/loop/blocking_pool.h"
#include "vio/loop/socket.h"
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
#include <utility>

#if !defined(_WIN32)
#include <netdb.h>
#endif

namespace vio
{
using tls_client_socket_stream_t = tls_stream_t;

struct ssl_client_state_t
{
  ssl_client_state_t(event_loop_t &event_loop, alloc_cb_t alloc_cb, dealloc_cb_t dealloc_cb, void *user_alloc_ptr)
    : event_loop(event_loop)
    , tcp{ref_ptr_t<tcp_state_t>::null()}
    , socket_stream(engine, alloc_cb, dealloc_cb, user_alloc_ptr)
  {
    connect_op.owner = this;
    connect_op.complete = &ssl_client_state_t::on_connect_ready;
  }

  ssl_client_state_t(const ssl_client_state_t &) = delete;
  ssl_client_state_t &operator=(const ssl_client_state_t &) = delete;

  event_loop_t &event_loop;
  std::string host;
  std::string port;

  std::coroutine_handle<> connect_continuation;
  std::expected<void, error_t> connect_result;

  address_info_list_t addresses;
  size_t address_index = 0;
  bool connected = false;
  bool connecting = false;
  bool resolved_done = false;
  registration_t cancel_registration;
  reference_counted_t *ref_count = nullptr;

  tcp_t tcp;
  ssl_context_t ssl_ctx;
  ssl_engine_t engine;
  tls_stream_t socket_stream;

  void finish_connect(std::expected<void, error_t> result)
  {
    cancel_registration.reset();
    connecting = false;
    if (result.has_value())
      connected = true;
    connect_result = std::move(result);
    if (auto continuation = std::exchange(connect_continuation, {}))
      continuation.resume();
  }

  void cancel_connect()
  {
    if (!connecting)
      return;
    if (resolving)
      detail::pool_cancel(resolve_job);
    abandon_connect();
    if (engine.initialized())
      socket_stream.abandon_handshake();
    finish_connect(std::unexpected(error_t{.code = vio_cancelled, .msg = "cancelled"}));
  }

  void abandon_connect() noexcept
  {
    if (connect_op.parked && tcp.handle)
      tcp.handle->socket.cancel(connect_op);
  }

  void start_resolve(ref_ptr_t<ssl_client_state_t> &self)
  {
    if (host.empty())
    {
      finish_connect(std::unexpected(error_t{.code = errc::invalid_argument, .msg = "Can not resolve host, host is empty"}));
      return;
    }
    if (int code = detail::dns_prepare_host(host, resolve_name); code < 0)
    {
      finish_connect(std::unexpected(make_error(code)));
      return;
    }
    resolve_status = 0;
    resolved.clear();
    resolve_job.owner = this;
    resolve_job.work = &ssl_client_state_t::resolve_work;
    resolve_job.done = &ssl_client_state_t::resolve_done;
    auto parked = self;
    resolve_parked = parked.release_to_raw();
    resolving = true;
    detail::pool_submit(detail::core(event_loop), resolve_job, detail::pool_queue::dns);
  }

  void connect_next()
  {
    while (connecting && address_index < addresses.size())
    {
      auto &candidate = addresses[address_index];
      const sockaddr *address = candidate.get_sockaddr();
      int length = detail::tcp_address_length(address);
      if (length == 0 || static_cast<size_t>(length) > candidate.addr.size())
      {
        last_error = errc::address_family_not_supported;
        ++address_index;
        continue;
      }
      if (!tcp.handle || tcp.handle->socket.native() != invalid_native_socket || tcp.handle->socket.closing())
      {
        abandon_connect();
        auto fresh = tcp_create(event_loop);
        if (!fresh.has_value())
        {
          finish_connect(std::unexpected(fresh.error()));
          return;
        }
        tcp = std::move(fresh.value());
      }
      auto &socket = tcp.handle->socket;
      if (int result = socket.open(address->sa_family, SOCK_STREAM, IPPROTO_TCP); result < 0)
      {
        last_error = result;
        ++address_index;
        continue;
      }
      int result = detail::socket_connect(socket.native(), address, length);
      if (result == 0)
      {
        on_tcp_connected();
        return;
      }
      if (result == errc::in_progress || result == errc::again)
      {
        socket.wait(detail::interest_write, connect_op);
        return;
      }
      last_error = result;
      ++address_index;
    }
    if (connecting)
      finish_connect(std::unexpected(make_error(last_error != 0 ? last_error : errc::invalid_argument)));
  }

private:
  void on_tcp_connected()
  {
    tcp.handle->connected = true;
    if (auto error = engine.init(ssl_ctx, false, host); error.code != 0)
    {
      finish_connect(std::unexpected(std::move(error)));
      return;
    }
    socket_stream.bind(tcp.handle->socket, ref_count);
    auto *self = this;
    socket_stream.on_handshake_complete = [self](std::optional<error_t> error) {
      if (!self->connecting)
        return;
      if (error)
        self->finish_connect(std::unexpected(std::move(*error)));
      else
        self->finish_connect({});
    };
    socket_stream.begin_handshake();
  }

  void on_connect_progress()
  {
    auto native = tcp.handle->socket.native();
    int code = detail::socket_pending_error(native);
    if (code == 0)
    {
      sockaddr_storage peer{};
      int length = static_cast<int>(sizeof(peer));
      if (detail::socket_peer_name(native, peer, length) == errc::not_connected)
      {
        tcp.handle->socket.wait(detail::interest_write, connect_op);
        return;
      }
    }
    if (!connecting)
      return;
    if (code != 0)
    {
      last_error = code;
      ++address_index;
      connect_next();
      return;
    }
    on_tcp_connected();
  }

  static void on_connect_ready(detail::io_op_t *op)
  {
    auto *self = static_cast<ssl_client_state_t *>(op->owner);
    auto *count = self->ref_count;
    count->inc();
    self->on_connect_progress();
    count->dec();
  }

  static void resolve_work(detail::pool_job_t *job)
  {
    auto *self = static_cast<ssl_client_state_t *>(job->owner);
#if defined(_WIN32)
    detail::ensure_winsock();
#endif
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    addrinfo *list = nullptr;
    const int code = ::getaddrinfo(self->resolve_name.c_str(), self->port.c_str(), &hints, &list);
    if (code != 0)
    {
      self->resolve_status = detail::errc_from_gai(code);
      return;
    }
    VIO_TRY
    {
      self->resolved = convert_addrinfo_list(list);
    }
    VIO_CATCH_ALL
    {
      self->resolve_status = errc::dns_memory;
    }
    ::freeaddrinfo(list);
  }

  static void resolve_done(detail::pool_job_t *job, bool)
  {
    auto *self = static_cast<ssl_client_state_t *>(job->owner);
    auto owned = ref_ptr_t<ssl_client_state_t>::from_raw(std::exchange(self->resolve_parked, nullptr));
    self->resolving = false;
    self->resolved_done = true;
    if (!self->connecting)
    {
      address_info_list_t().swap(self->resolved);
      return;
    }
    if (self->resolve_status < 0)
    {
      self->finish_connect(std::unexpected(make_error(self->resolve_status)));
      return;
    }
    self->addresses = std::move(self->resolved);
    self->address_index = 0;
    if (self->addresses.empty())
    {
      self->finish_connect(std::unexpected(make_error(errc::dns_no_data)));
      return;
    }
    self->connect_next();
  }

  detail::io_op_t connect_op;
  detail::pool_job_t resolve_job;
  std::string resolve_name;
  address_info_list_t resolved;
  void *resolve_parked = nullptr;
  int resolve_status = 0;
  int last_error = 0;
  bool resolving = false;
};

struct ssl_client_t
{
  ref_ptr_t<ssl_client_state_t> state;
};

inline std::expected<ssl_client_t, error_t> ssl_client_create(event_loop_t &event_loop, const ssl_config_t &config = {}, alloc_cb_t alloc_cb = default_alloc, dealloc_cb_t dealloc_cb = default_dealloc,
                                                              void *user_alloc_ptr = nullptr)
{
  ssl_client_t ret{ref_ptr_t<ssl_client_state_t>{event_loop, alloc_cb, dealloc_cb, user_alloc_ptr}};
  auto &state = ret.state.data();
  state.ref_count = ret.state.ref_counted();
  ret.state.on_destroy([raw = &state]() {
    raw->abandon_connect();
    raw->socket_stream.begin_teardown();
  });
  if (auto error = state.ssl_ctx.init(false, config, get_default_ca_certificates()); error.code != 0)
  {
    return std::unexpected(std::move(error));
  }
  auto tcp = tcp_create(event_loop);
  if (!tcp.has_value())
  {
    return std::unexpected(tcp.error());
  }
  state.tcp = std::move(tcp.value());
  return ret;
}

inline void impl_ssl_client_resolve_host(ssl_client_t &client)
{
  if (!client.state)
    return;
  client.state->start_resolve(client.state);
}

struct ssl_client_connecting_future_t
{
  ref_ptr_t<ssl_client_state_t> state;

  bool await_ready() noexcept
  {
    return !state || state->connected || !state->connecting;
  }

  void await_suspend(std::coroutine_handle<> continuation) noexcept
  {
    state->connect_continuation = continuation;
  }

  std::expected<void, error_t> await_resume() noexcept
  {
    if (!state)
      return std::unexpected(error_t{.code = errc::bad_descriptor, .msg = "Can not connect a closed client"});
    return std::move(state->connect_result);
  }
};

namespace detail
{
inline bool ssl_client_begin_connect(ssl_client_t &client, const std::string &host, uint16_t port, cancellation_t *cancel)
{
  auto &state = client.state.data();
  if (state.connecting)
    return false;
  if (cancel && cancel->is_cancelled())
  {
    state.connect_result = std::unexpected(error_t{.code = vio_cancelled, .msg = "cancelled"});
    return false;
  }
  if (state.connected)
  {
    state.connect_result = std::unexpected(make_error(errc::already_connected));
    return false;
  }
  if (state.engine.initialized())
  {
    state.connect_result = std::unexpected(error_t{.code = errc::already_connected, .msg = "A TLS client can not connect again once a handshake has started; create a new client"});
    return false;
  }
  state.host = host;
  state.port = std::to_string(port);
  state.connecting = true;
  state.connect_result = {};
  state.addresses.clear();
  state.address_index = 0;
  return true;
}

inline void ssl_client_arm_connect_cancel(ssl_client_t &client, cancellation_t *cancel)
{
  if (cancel == nullptr || !client.state->connecting)
    return;
  auto *raw = &client.state.data();
  client.state->cancel_registration = cancel->register_callback([raw]() { raw->cancel_connect(); });
}
} // namespace detail

inline ssl_client_connecting_future_t ssl_client_connect(ssl_client_t &client, const std::string &host, uint16_t port, cancellation_t *cancel = nullptr)
{
  if (!client.state)
  {
    return {ref_ptr_t<ssl_client_state_t>::null()};
  }
  if (!detail::ssl_client_begin_connect(client, host, port, cancel))
  {
    return {client.state};
  }
  client.state->resolved_done = false;
  impl_ssl_client_resolve_host(client);
  detail::ssl_client_arm_connect_cancel(client, cancel);
  return {client.state};
}

inline ssl_client_connecting_future_t ssl_client_connect(ssl_client_t &client, const std::string &host, uint16_t port, const std::string &ip, cancellation_t *cancel = nullptr)
{
  if (!client.state)
  {
    return {ref_ptr_t<ssl_client_state_t>::null()};
  }
  if (!detail::ssl_client_begin_connect(client, host, port, cancel))
  {
    return {client.state};
  }
  auto &state = client.state.data();
  state.resolved_done = true;

  sockaddr_storage storage{};
  int length = 0;
  if (auto v4 = ip4_addr(ip, port); v4.has_value())
  {
    std::memcpy(&storage, &v4.value(), sizeof(sockaddr_in));
    length = static_cast<int>(sizeof(sockaddr_in));
  }
  else if (auto v6 = ip6_addr(ip, port); v6.has_value())
  {
    std::memcpy(&storage, &v6.value(), sizeof(sockaddr_in6));
    length = static_cast<int>(sizeof(sockaddr_in6));
  }
  else
  {
    state.connecting = false;
    state.connect_result = std::unexpected(v6.error());
    return {client.state};
  }

  addrinfo ai{};
  ai.ai_family = storage.ss_family;
  ai.ai_socktype = SOCK_STREAM;
  ai.ai_protocol = IPPROTO_TCP;
  ai.ai_addr = reinterpret_cast<sockaddr *>(&storage);
  ai.ai_addrlen = static_cast<decltype(ai.ai_addrlen)>(length);
  state.addresses.emplace_back(ai);
  state.address_index = 0;
  state.connect_next();
  detail::ssl_client_arm_connect_cancel(client, cancel);
  return {client.state};
}

struct ssl_client_upgrade_future_t
{
  ssl_client_t client;

  bool await_ready() noexcept
  {
    return !client.state || client.state->connected || !client.state->connecting;
  }

  void await_suspend(std::coroutine_handle<> continuation) noexcept
  {
    client.state->connect_continuation = continuation;
  }

  std::expected<ssl_client_t, error_t> await_resume() noexcept
  {
    if (!client.state)
    {
      return std::unexpected(error_t{.code = errc::bad_descriptor, .msg = "Can not upgrade a closed socket"});
    }
    if (!client.state->connect_result.has_value())
    {
      return std::unexpected(std::move(client.state->connect_result.error()));
    }
    return std::move(client);
  }
};

inline ssl_client_upgrade_future_t ssl_client_upgrade(tcp_t &&tcp, const ssl_config_t &config, const std::string &host, cancellation_t *cancel = nullptr, alloc_cb_t alloc_cb = default_alloc,
                                                       dealloc_cb_t dealloc_cb = default_dealloc, void *user_alloc_ptr = nullptr)
{
  if (!tcp.handle)
  {
    return {ssl_client_t{ref_ptr_t<ssl_client_state_t>::null()}};
  }
  event_loop_t &event_loop = tcp.handle->event_loop;
  ssl_client_t ret{ref_ptr_t<ssl_client_state_t>{event_loop, alloc_cb, dealloc_cb, user_alloc_ptr}};
  auto &state = ret.state.data();
  state.ref_count = ret.state.ref_counted();
  ret.state.on_destroy([raw = &state]() {
    raw->abandon_connect();
    raw->socket_stream.begin_teardown();
  });

  if (auto error = state.ssl_ctx.init(false, config, get_default_ca_certificates()); error.code != 0)
  {
    state.connect_result = std::unexpected(std::move(error));
    return {std::move(ret)};
  }

  if (cancel != nullptr && cancel->is_cancelled())
  {
    state.connect_result = std::unexpected(error_t{.code = vio_cancelled, .msg = "cancelled"});
    return {std::move(ret)};
  }

  auto &tcp_state = tcp.handle.data();
  if (!tcp_state.socket.is_open() || !tcp_state.connected)
  {
    state.connect_result = std::unexpected(error_t{.code = errc::not_connected, .msg = "Can not upgrade a socket that is not connected"});
    return {std::move(ret)};
  }
  if (tcp_state.read.waiter != nullptr || tcp_write_queue_size(tcp) > 0)
  {
    state.connect_result = std::unexpected(error_t{.code = errc::busy, .msg = "Can not upgrade a socket with a pending plaintext read or write"});
    return {std::move(ret)};
  }

  state.host = host;
  state.tcp = std::move(tcp);
  state.connecting = true;

  if (auto error = state.engine.init(state.ssl_ctx, false, state.host); error.code != 0)
  {
    state.connecting = false;
    state.connect_result = std::unexpected(std::move(error));
    return {std::move(ret)};
  }

  state.socket_stream.bind(state.tcp.handle->socket, state.ref_count);
  auto *raw = &state;
  state.socket_stream.on_handshake_complete = [raw](std::optional<error_t> error) {
    if (!raw->connecting)
      return;
    if (error)
      raw->finish_connect(std::unexpected(std::move(*error)));
    else
      raw->finish_connect({});
  };
  state.socket_stream.begin_handshake();
  detail::ssl_client_arm_connect_cancel(ret, cancel);
  return {std::move(ret)};
}

using tls_client_reader_t = stream_reader_t<ref_ptr_t<ssl_client_state_t>, tls_client_socket_stream_t>;
inline std::expected<tls_client_reader_t, error_t> ssl_client_create_reader(ssl_client_t &client)
{
  if (!client.state)
  {
    return std::unexpected(error_t{.code = errc::bad_descriptor, .msg = "Can not create a reader for a closed client"});
  }
  if (client.state->socket_stream.reader_active)
  {
    return std::unexpected(error_t{.code = errc::busy, .msg = "Can not create a reader for a client that already has a reader active"});
  }
  if (!client.state->connected)
  {
    return std::unexpected(error_t{.code = errc::not_connected, .msg = "Can not create a reader for a client that is not connected"});
  }

  return tls_client_reader_t{client.state, &client.state->socket_stream};
}

using tls_client_write_awaitable_t = stream_write_awaitable_t<ref_ptr_t<ssl_client_state_t>, tls_client_socket_stream_t>;

inline tls_client_write_awaitable_t ssl_client_write(ssl_client_t &client, std::span<const std::byte> buffer, cancellation_t *cancel = nullptr)
{
  if (!client.state)
  {
    return {ref_ptr_t<ssl_client_state_t>::null(), nullptr, 0};
  }
  auto &ss = client.state->socket_stream;
  auto idx = ss.write_queue.activate();
  ss.write_queue[idx].data = buffer.data();
  ss.write_queue[idx].size = buffer.size();
  tls_client_write_awaitable_t ret{client.state, &ss, idx};
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

inline tls_client_write_awaitable_t ssl_client_write(ssl_client_t &client, const void *data, std::size_t length, cancellation_t *cancel = nullptr)
{
  return ssl_client_write(client, std::span<const std::byte>(static_cast<const std::byte *>(data), length), cancel);
}

inline tls_client_write_awaitable_t ssl_client_writev(ssl_client_t &client, std::span<const std::span<const std::byte>> buffers, cancellation_t *cancel = nullptr)
{
  if (!client.state)
  {
    return {ref_ptr_t<ssl_client_state_t>::null(), nullptr, 0};
  }
  auto &ss = client.state->socket_stream;
  auto idx = ss.write_queue.activate();
  tls_client_write_awaitable_t ret{client.state, &ss, idx};
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

inline tls_client_write_awaitable_t ssl_client_shutdown(ssl_client_t &client)
{
  if (!client.state)
  {
    return {ref_ptr_t<ssl_client_state_t>::null(), nullptr, 0};
  }
  auto &ss = client.state->socket_stream;
  auto idx = ss.write_queue.activate();
  tls_client_write_awaitable_t ret{client.state, &ss, idx};
  ss.begin_shutdown(idx);
  return ret;
}

// Negotiated ALPN protocol, available after the handshake (i.e. after connect
// resolves). Returns nullopt if none was negotiated.
inline std::optional<std::string> ssl_client_alpn_selected(const ssl_client_t &client)
{
  if (!client.state || !client.state->connected)
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
  return client.state && client.state->connected && client.state->engine.session_reused();
}

// The server's stapled OCSP response (requires request_ocsp_staple in the config).
// Empty if none was received. Valid after connect.
inline std::vector<uint8_t> ssl_client_ocsp_response(const ssl_client_t &client)
{
  if (!client.state || !client.state->connected)
  {
    return {};
  }
  return client.state->engine.ocsp_response();
}

inline std::string ssl_client_peer_ip(ssl_client_t &client)
{
  if (!client.state)
  {
    return {};
  }
  return peer_ip(client.state->tcp);
}

} // namespace vio
