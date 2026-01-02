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
#include "vio/elastic_index_storage.h"
#include "vio/error.h"
#include "vio/handle_closer.h"
#include "vio/operation/tls_common.h"
#include "vio/ref_counted_wrapper.h"
#include "vio/socket_stream.h"
#include "vio/ssl_config_t.h"
#include "vio/unique_buf.h"

#include <coroutine>
#include <expected>
#include <filesystem>
#include <span>
#include <string>
#include <tls.h>
#include <uv.h>
#include <vector>

namespace vio
{
struct tls_client_connection_handler_t
{
  std::string cert_data;
  tls *stream_tls_ctx = nullptr;

  error_t initialize(const ssl_config_t &config)
  {
    stream_tls_ctx = tls_client();
    if (!stream_tls_ctx)
    {
      return error_t{-1, "Failed to create TLS client"};
    }

    cert_data = get_default_ca_certificates();
    return apply_ssl_config_to_tls_ctx(config, cert_data, stream_tls_ctx);
  }

  error_t connect(int socket_fd, const std::string &host)
  {
    auto tls_result = tls_connect_socket(stream_tls_ctx, socket_fd, host.c_str());
    if (tls_result != 0)
    {
      return error_t{.code = tls_result, .msg = tls_error(stream_tls_ctx)};
    }
    return {};
  }

  void close()
  {
    assert(stream_tls_ctx);
    tls_close(stream_tls_ctx);
    tls_free(stream_tls_ctx);
  }
};

using tls_native_client_stream_t = tls_stream_t<tls_client_connection_handler_t>;
using tls_client_socket_stream_t = vio::socket_stream_t<tls_native_client_stream_t>;
struct ssl_client_state_t
{
  reference_counted_t internal_ref_count;
  inline_wrapper_t<closable_handle_t<uv_tcp_t>> tcp_handle;

  static reference_counted_t *compute_parent_for_owned_wrapper(void *this_ptr)
  {
    using storage_t = owned_wrapper_t<ssl_client_state_t>::storage_t;
    return reinterpret_cast<reference_counted_t *>(
      reinterpret_cast<char *>(this_ptr) - offsetof(storage_t, data));
  }

  ssl_client_state_t(event_loop_t &event_loop, alloc_cb_t alloc_cb, dealloc_cb_t dealloc_cb, void *user_alloc_ptr)
    : internal_ref_count([]() {})
    , tcp_handle(compute_parent_for_owned_wrapper(this))
    , event_loop(event_loop)
    , native_stream(connection_handler)
    , socket_stream(native_stream, event_loop, alloc_cb, dealloc_cb, user_alloc_ptr)
  {
  }

  ~ssl_client_state_t()
  {
  }

  event_loop_t &event_loop;
  std::string host;
  std::string port;
  uv_getaddrinfo_t getaddrinfo_req = {};
  uv_connect_t connect_req = {};
  int socket_fd = -1;

  std::coroutine_handle<> connect_continuation;
  std::expected<void, error_t> connect_result;

  address_info_list_t addresses;
  int address_index = 0;
  bool connected = false;
  bool connecting = false;
  bool resolved_done = false;

  tls_client_connection_handler_t connection_handler;
  tls_native_client_stream_t native_stream;
  tls_client_socket_stream_t socket_stream;

  uv_tcp_t *get_tcp()
  {
    return static_cast<uv_tcp_t *>(&tcp_handle.data());
  }

  uv_stream_t *get_tcp_stream()
  {
    return reinterpret_cast<uv_stream_t *>(static_cast<uv_tcp_t *>(&tcp_handle.data()));
  }

  uv_handle_t *get_tcp_handle()
  {
    return reinterpret_cast<uv_handle_t *>(static_cast<uv_tcp_t *>(&tcp_handle.data()));
  }

  static void connect_to_current_index(owned_wrapper_t<ssl_client_state_t> &state)
  {
    state.inc_ref_and_store_in_handle(state->connect_req);
    auto on_connect = [](uv_connect_t *req, int status)
    {
      auto state = owned_wrapper_t<ssl_client_state_t>::from_raw(req->data);
      if (status < 0)
      {
        state->address_index++;
        if (state->address_index < state->addresses.size())
        {
          connect_to_current_index(state);
        }
        else
        {
          state->connect_result = std::unexpected(error_t{status, uv_strerror(status)});
          state->connecting = false;
          if (state->connect_continuation)
          {
            state->connect_continuation.resume();
          }
        }
        return;
      }

      state->connecting = false;
      uv_os_fd_t socket;
      if (uv_fileno(state->get_tcp_handle(), &socket) == 0)
      {
        state->socket_fd = *reinterpret_cast<int *>(&socket);
        if (auto socket_err = state->connection_handler.connect(state->socket_fd, state->host); socket_err.code == 0)
        {
          state->connected = true;
          state->connect_result = {};
          state->socket_stream.connect(state->socket_fd);
        }
        else
        {
          state->connect_result = std::unexpected(std::move(socket_err));
        }
      }
      else
      {
        state->connect_result = std::unexpected(error_t{.code = -1, .msg = "Failed to get socket fd"});
      }

      if (state->connect_continuation)
      {
        state->connect_continuation.resume();
      }
    };
    auto connect_result = uv_tcp_connect(&state->connect_req, state->get_tcp(), state->addresses[state->address_index].get_sockaddr(), on_connect);
    if (connect_result < 0)
    {
      owned_wrapper_t<ssl_client_state_t>::from_raw(state->connect_req.data);
      state->address_index++;
      if (state->address_index < state->addresses.size())
      {
        connect_to_current_index(state);
      }
      else
      {
        state->connecting = false;
        state->connect_result = std::unexpected(error_t{connect_result, uv_strerror(connect_result)});
        if (state->connect_continuation)
        {
          state->connect_continuation.resume();
        }
      }
    }
  }

  static void on_resolve_done(owned_wrapper_t<ssl_client_state_t> &state, std::expected<address_info_list_t, error_t> &&result)
  {
    state->resolved_done = true;
    if (!result.has_value())
    {
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
  owned_wrapper_t<ssl_client_state_t> state;
};

void set_poll_state(ssl_client_state_t &state);

inline std::expected<ssl_client_t, error_t> ssl_client_create(event_loop_t &event_loop, const ssl_config_t &config = {}, alloc_cb_t alloc_cb = default_alloc, dealloc_cb_t dealloc_cb = default_dealloc,
                                                              void *user_alloc_ptr = nullptr)
{
  ssl_client_t ret{owned_wrapper_t<ssl_client_state_t>{event_loop, alloc_cb, dealloc_cb, user_alloc_ptr}};
  if (auto error = ret.state->connection_handler.initialize(config); error.code != 0)
  {
    return std::unexpected(std::move(error));
  }

  if (auto r = uv_tcp_init(event_loop.loop(), static_cast<uv_tcp_t *>(&ret.state->tcp_handle.data())); r < 0)
  {
    return std::unexpected(error_t{r, uv_strerror(r)});
  }
  ret.state->tcp_handle.data().call_close = true;

  ret.state.ref_counted()->register_destroy_callback(
    [state_copy = ret.state]() mutable
    {
      if (!state_copy.ref_counted())
      {
        return;
      }
      state_copy->socket_stream.close([]() {});
    });

  return ret;
}

inline void impl_ssl_client_resolve_host(ssl_client_t &client)
{
  if (client.state.ref_counted() == nullptr)
  {
    ssl_client_state_t::on_resolve_done(client.state, std::unexpected(error_t{1, "Can not resolve host, client is closed"}));
  }

  if (client.state->host.empty())
  {
    ssl_client_state_t::on_resolve_done(client.state, std::unexpected(error_t{1, "Can not resolve host, host is empty"}));
  }

  client.state.inc_ref_and_store_in_handle(client.state->getaddrinfo_req);
  auto callback = [](uv_getaddrinfo_t *req, int status, addrinfo *res)
  {
    auto state = owned_wrapper_t<ssl_client_state_t>::from_raw(req->data);
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
    owned_wrapper_t<ssl_client_state_t>::from_raw(client.state->getaddrinfo_req.data);
    ssl_client_state_t::on_resolve_done(client.state, std::unexpected(error_t{.code = r, .msg = uv_strerror(r)}));
  }
}

struct ssl_client_connecting_future_t
{
  owned_wrapper_t<ssl_client_state_t> state;

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

inline ssl_client_connecting_future_t ssl_client_connect(ssl_client_t &client, const std::string &host, uint16_t port)
{
  if (client.state.ref_counted() == nullptr)
  {
    return {owned_wrapper_t<ssl_client_state_t>::null()};
  }
  client.state->host = host;
  client.state->port = std::to_string(port);
  client.state->connecting = true;
  client.state->resolved_done = false;
  impl_ssl_client_resolve_host(client);
  return {client.state};
}

inline ssl_client_connecting_future_t ssl_client_connect(ssl_client_t &client, const std::string &host, uint16_t port, const std::string &ip)
{
  if (client.state.ref_counted() == nullptr)
  {
    return {owned_wrapper_t<ssl_client_state_t>::null()};
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
    client.state->connect_result = std::unexpected(error_t{r, uv_strerror(r)});
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
  return {client.state};
}

using tls_client_reader_t = stream_reader_t<owned_wrapper_t<ssl_client_state_t>, tls_client_socket_stream_t>;
inline std::expected<tls_client_reader_t, error_t> ssl_client_create_reader(ssl_client_t &client)
{
  if (client.state.ref_counted() == nullptr)
  {
    return std::unexpected(error_t{1, "Can not create a reader for a closed client"});
  }
  if (client.state->socket_stream.reader_active)
  {
    return std::unexpected(error_t{1, "Can not create a reader for a client that already has a reader active"});
  }
  if (!client.state->connected)
  {
    return std::unexpected(error_t{1, "Can not create a reader for a client that is not connected"});
  }

  return tls_client_reader_t{client.state, &client.state->socket_stream};
}

using tls_client_write_awaitable_t = stream_write_awaitable_t<owned_wrapper_t<ssl_client_state_t>, tls_client_socket_stream_t>;
inline tls_client_write_awaitable_t ssl_client_write(ssl_client_t &client, uv_buf_t buffer)
{
  assert(client.state.ref_counted() != nullptr && "Can not write to a closed client");
  assert(client.state->connected && "Can not write to a client that is not connected");

  auto write_state_index = client.state->socket_stream.write_queue.activate();
  client.state->socket_stream.write_queue[write_state_index].buf = buffer;

  client.state->socket_stream.write();
  client.state->socket_stream.set_poll_state();
  return {client.state, &client.state->socket_stream, write_state_index};
}

} // namespace vio