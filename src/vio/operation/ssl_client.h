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
#include "vio/operation/ssl_common.h"
#include "vio/ref_ptr.h"
#include "vio/socket_stream.h"
#include "vio/ssl_config.h"
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

struct ssl_stream
{
  tls *tls_ctx = nullptr;
  std::string cert_data;

  error_t initialize(ssl_config &config)
  {
    tls_ctx = tls_client();
    if (!tls_ctx)
    {
      return error_t{-1, "Failed to create TLS client"};
    }

    cert_data = get_default_ca_certificates();
    return apply_ssl_config_to_tls_ctx(config, cert_data, tls_ctx);
  }

  error_t connect(int socket_fd, const std::string &host)
  {
    auto tls_result = tls_connect_socket(tls_ctx, socket_fd, host.c_str());
    if (tls_result != 0)
    {
      return error_t{.code = tls_result, .msg = tls_error(tls_ctx)};
    }
  }

  std::expected<std::pair<stream_io_result_t, uint32_t>, error_t> read(void *target, uint32_t size)
  {
    auto r = tls_read(tls_ctx, target, size);
    if (r == TLS_WANT_POLLIN)
    {
      return std::make_pair(stream_io_result_t::poll_in, uint32_t(0));
    }
    if (r == TLS_WANT_POLLOUT)
    {
      return std::make_pair(stream_io_result_t::poll_out, uint32_t(0));
    }
    if (r < 0)
    {
      return std::unexpected(error_t{int(r), tls_error(tls_ctx)});
    }
    return std::make_pair(stream_io_result_t::ok, uint32_t(r));
  }

  void close()
  {
    tls_close(tls_ctx);
    tls_free(tls_ctx);
  }
};

struct ssl_client_state_t
{
  ssl_client_state_t(event_loop_t &event_loop, alloc_cb_t alloc_cb, dealloc_cb_t dealloc_cb, void *user_alloc_ptr)
    : event_loop(event_loop)
    , socket_stream(event_loop, alloc_cb, dealloc_cb, user_alloc_ptr)
  {
    fprintf(stderr, "ssl_client_state_t constructor\n");
  }
  ~ssl_client_state_t()
  {
    fprintf(stderr, "ssl_client_state_t destructor\n");
  }
  event_loop_t &event_loop;
  std::string host;
  std::string port;
  uv_getaddrinfo_t getaddrinfo_req = {};
  uv_connect_t connect_req = {};
  uv_tcp_t tcp_req = {};
  int socket_fd = -1;

  std::coroutine_handle<> connect_continuation;
  std::expected<void, error_t> connect_result;

  address_info_list_t addresses;
  int address_index = 0;
  bool connected = false;
  bool connecting = false;
  bool resolved_done = false;

  socket_stream_t<ssl_stream> socket_stream;

  uv_tcp_t *get_tcp()
  {
    return &tcp_req;
  }

  uv_stream_t *get_tcp_stream()
  {
    return reinterpret_cast<uv_stream_t *>(&tcp_req);
  }

  uv_handle_t *get_tcp_handle()
  {
    return reinterpret_cast<uv_handle_t *>(&tcp_req);
  }

  static void connect_to_current_index(ref_ptr_t<ssl_client_state_t> &state)
  {
    state.inc_ref_and_store_in_handle(state->connect_req);
    auto on_connect = [](uv_connect_t *req, int status)
    {
      auto state = ref_ptr_t<ssl_client_state_t>::from_raw(req->data);
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
        if (auto socket_err = state->socket_stream.initialize(state->socket_fd, state->host, state->port); socket_err.code == 0)
        {
          state->connected = true;
          state->connect_result = {};
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
      ref_ptr_t<ssl_client_state_t>::from_raw(state->connect_req.data);
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

  static void on_resolve_done(ref_ptr_t<ssl_client_state_t> &state, std::expected<address_info_list_t, error_t> &&result)
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
  ref_ptr_t<ssl_client_state_t> state;
};

void set_poll_state(ssl_client_state_t &state);

inline std::expected<ssl_client_t, error_t> ssl_client_create(event_loop_t &event_loop, const ssl_config &config = {}, alloc_cb_t alloc_cb = default_alloc, dealloc_cb_t dealloc_cb = default_dealloc,
                                                              void *user_alloc_ptr = nullptr)
{
  ssl_client_t ret{ref_ptr_t<ssl_client_state_t>{event_loop, alloc_cb, dealloc_cb, user_alloc_ptr}};
  if (auto r = uv_tcp_init(event_loop.loop(), &ret.state->tcp_req); r < 0)
  {
    return std::unexpected(error_t{r, uv_strerror(r)});
  }
  auto to_close = [](ref_ptr_t<ssl_client_state_t> &state)
  {
    if (!state.ptr())
    {
      return;
    }

    state.inc_ref_and_store_in_handle(state->tcp_req);
    auto state_ptr = state.ptr();
    auto closure = [state_ptr]()
    {
      auto close_cb = [](uv_handle_t *handle)
      {
        if (handle->data)
        {
          auto state_ref = ref_ptr_t<ssl_client_state_t>::from_raw(handle->data);
          handle->data = nullptr;
        }
        else
        {
          handle->data = nullptr;
        }
      };
      uv_close(state_ptr->get_tcp_handle(), close_cb);
    };
    state->socket_stream.close(std::move(closure));
  };
  ret.state.set_close_guard(to_close);

  return ret;
}

inline void impl_ssl_client_resolve_host(ssl_client_t &client)
{
  if (client.state.ptr() == nullptr)
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

inline ssl_client_connecting_future_t ssl_client_connect(ssl_client_t &client, const std::string &host, uint16_t port)
{
  if (client.state.ptr() == nullptr)
  {
    return {{}};
  }
  client.state->host = host;
  client.state->port = std::to_string(port);
  client.state->connecting = true;
  client.state->resolved_done = false;
  impl_ssl_client_resolve_host(client);
  return {client.state};
}

struct ssl_client_read_awaitable_t
{
  ref_ptr_t<ssl_client_state_t> state;

  bool await_ready() noexcept
  {
    assert(state && "Invalid state in await_ready");
    return state->socket_stream.bytes_read == state->socket_stream.read_buffer.len || state->socket_stream.read_buffer_error.code;
  }

  void await_suspend(std::coroutine_handle<> continuation) noexcept
  {
    assert(state && "Invalid state in await_suspend");
    state->socket_stream.read_buffer_continuation = continuation;
  }

  auto await_resume() noexcept
  {
    assert(state && "Invalid state in await_resume");
    assert(state->socket_stream.bytes_read == state->socket_stream.read_buffer.len || state->socket_stream.read_buffer_error.code);
    return std::expected<std::pair<uv_buf_t, dealloc_cb_t>, error_t>{{state->socket_stream.read_buffer, nullptr}};
  }
};

inline std::expected<ssl_client_reader_t, error_t> ssl_client_create_reader(ssl_client_t &client)
{
  if (client.state.ptr() == nullptr)
  {
    return std::unexpected(error_t{1, "Can not create a reader for a closed client"});
  }
  if (client.state->reader_active)
  {
    return std::unexpected(error_t{1, "Can not create a reader for a client that already has a reader active"});
  }
  if (!client.state->connected)
  {
    return std::unexpected(error_t{1, "Can not create a reader for a client that is not connected"});
  }
  client.state->reader_active = true;

  read_from_tls_context(*client.state);
  set_poll_state(*client.state);

  return {ssl_client_reader_t{client.state}};
}

struct ssl_client_write_awaitable_t
{
  ref_ptr_t<ssl_client_state_t> state;
  size_t write_state_index;

  ssl_client_write_awaitable_t(ref_ptr_t<ssl_client_state_t> state, size_t write_state_index)
    : state(state)
    , write_state_index(write_state_index)
  {
  }
  ~ssl_client_write_awaitable_t()
  {
    if (!state)
    {
      return;
    }
    auto &write_state = state->write_queue[write_state_index];
    if (--write_state.ref == 0)
    {
      write_state.done = false;
      state->write_queue.deactivate(write_state_index);
    };
  }

  ssl_client_write_awaitable_t(const ssl_client_write_awaitable_t &) = delete;
  ssl_client_write_awaitable_t &operator=(const ssl_client_write_awaitable_t &) = delete;

  ssl_client_write_awaitable_t(ssl_client_write_awaitable_t &&) noexcept = default;
  ssl_client_write_awaitable_t &operator=(ssl_client_write_awaitable_t &&) noexcept = default;

  [[nodiscard]] bool await_ready() const noexcept
  {
    if (!state)
    {
      return true;
    }
    auto &write_state = state->write_queue[write_state_index];
    return write_state.done || write_state.error_code != 0;
  }
  void await_suspend(std::coroutine_handle<> h) noexcept
  {
    if (!state)
    {
      return;
    }
    auto &write_state = state->write_queue[write_state_index];
    write_state.continuation = h;
  }
  std::expected<void, error_t> await_resume() noexcept
  {
    if (!state)
    {
      return {};
    }
    auto &write_state = state->write_queue[write_state_index];
    if (write_state.error_code != 0)
    {
      return std::unexpected(error_t{-1, write_state.error_msg});
    }
    return {};
  }
};
static void try_write_queue(ssl_client_state_t &state)
{
  if (!state.write_queue.current_item_is_active() && !state.write_queue.next())
  {
    return;
  }

  while (state.write_queue.current_item_is_active())
  {
    auto &write_state = state.write_queue.current_item();
    auto remaining = write_state.buf.len - write_state.bytes_written;
    auto written = tls_write(state.tls_ctx, write_state.buf.base + write_state.bytes_written, remaining);
    if (written == TLS_WANT_POLLOUT)
    {
      state.poll_write_active = true;
      return;
    }
    if (written == TLS_WANT_POLLIN)
    {
      state.poll_read_active = true;
      state.write_got_poll_in = true;
      return;
    }
    if (written >= 0)
    {
      write_state.bytes_written += written;
      if (write_state.bytes_written == write_state.buf.len)
      {
        write_state.done = true;
        if (write_state.continuation)
          write_state.continuation.resume();
        if (--write_state.ref == 0)
        {
          state.write_queue.deactivate_current();
        }
        state.write_queue.next();
      }
    }
    else
    {
      write_state.error_code = int(written);
      write_state.error_msg = tls_error(state.tls_ctx);
      write_state.done = true;
      if (write_state.continuation)
        write_state.continuation.resume();
      if (--write_state.ref == 0)
      {
        state.write_queue.deactivate_current();
      }
      state.write_queue.next();
    }
  }
  state.poll_write_active = false;
};

static void on_writable(ssl_client_state_t &state)
{
  try_write_queue(state);
}

inline ssl_client_write_awaitable_t ssl_client_write(ssl_client_t &client, uv_buf_t buffer)
{
  assert(client.state.ptr() != nullptr && "Can not write to a closed client");
  assert(client.state->connected && "Can not write to a client that is not connected");

  auto write_state_index = client.state->write_queue.activate();
  client.state->write_queue[write_state_index].buf = buffer;

  try_write_queue(*client.state);
  set_poll_state(*client.state);
  return ssl_client_write_awaitable_t(client.state, write_state_index);
}

} // namespace vio