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
#include "tcp.h"
#include "vio/error.h"
#include "vio/ref_ptr.h"

#include <array>
#include <coroutine>
#include <expected>
#include <openssl/bio.h>
#include <span>
#include <string>
#include <tls.h>
#include <uv.h>
#include <vector>

namespace vio
{

using ssl_client_dealloc_cb_t = void (*)(void *user_ptr, uv_buf_t *buf);
using ssl_client_alloc_cb_t = void (*)(void *user_ptr, size_t suggested_size, uv_buf_t *buf);

struct ssl_config
{
  std::optional<std::string> ca_file;
  std::optional<std::string> ca_path;
  std::optional<std::string> cert_file;
  std::optional<std::string> key_file;
  std::optional<std::string> ocsp_staple_file;
  std::optional<std::vector<uint8_t>> ca_mem;
  std::optional<std::vector<uint8_t>> cert_mem;
  std::optional<std::vector<uint8_t>> key_mem;
  std::optional<std::vector<uint8_t>> ocsp_staple_mem;
  std::optional<std::string> ciphers;
  std::optional<std::string> alpn;
  std::optional<bool> verify_client;
  std::optional<bool> verify_depth;
  std::optional<bool> verify_optional;
  std::optional<uint32_t> protocols;
  std::optional<uint32_t> dheparams;
  std::optional<uint32_t> ecdhecurve;
};

struct ssl_write_state_t
{
  uv_buf_t buf = {};
  size_t bytes_written = 0;
  bool done = false;
  bool error = false;
  std::string error_msg;
  std::coroutine_handle<> continuation;
};

struct ssl_client_state_t
{
  event_loop_t &event_loop;
  std::string host;
  std::string port;
  uv_getaddrinfo_t getaddrinfo_req = {};
  uv_connect_t connect_req = {};
  uv_tcp_t tcp_req = {};
  tls *tls_ctx = nullptr;
  int socket_fd = -1;
  std::vector<uint8_t> cert_data;

  std::coroutine_handle<> connect_continuation;
  std::expected<void, error_t> connect_result;

  address_info_list_t addresses;
  int address_index = 0;
  bool connected = false;
  bool connecting = false;
  bool resolved_done = false;

  uv_poll_t poll_req = {};
  bool poll_active = false;
  bool reader_active = false;
  std::coroutine_handle<> read_continuation;
  ssl_client_alloc_cb_t alloc_cb;
  ssl_client_dealloc_cb_t dealloc_cb;
  int buffer_front = 0;
  int buffer_back = 0;
  std::array<std::expected<std::pair<uv_buf_t, ssl_client_dealloc_cb_t>, error_t>, 10> buffer_queue;

  std::queue<ssl_write_state_t> write_queue;

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
        state->socket_fd = reinterpret_cast<int>(socket);
        BIO_socket_nbio(state->socket_fd, 0);

        if (auto tls_result = tls_connect_socket(state->tls_ctx, state->socket_fd, "localhost"); tls_result == 0)
        {
          state->connected = true;
          state->connect_result = {};
          if (auto error_code = tls_handshake(state->tls_ctx); error_code != 0)
          {
            auto error = tls_error(state->tls_ctx);
            if (error)
            {
              state->connect_result = std::unexpected(error_t{-1, tls_error(state->tls_ctx)});
            }
            else
            {
              state->connect_result = std::unexpected(error_t{-1, "TLS handshake failed"});
            }
            state->connecting = false;
          }
        }
        else
        {
          state->connect_result = std::unexpected(error_t{.code = tls_result, .msg = tls_error(state->tls_ctx)});
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

std::span<const uint8_t> get_default_ca_certificates();

inline std::expected<ssl_client_t, error_t> ssl_client_create(event_loop_t &event_loop, const ssl_config &config = {})
{
  ssl_client_t ret{ref_ptr_t<ssl_client_state_t>{event_loop}};
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
    uv_close(state->get_tcp_handle(), close_cb);
  };
  ret.state.set_close_guard(to_close);
  ret.state->tls_ctx = tls_client();
  if (!ret.state->tls_ctx)
  {
    return std::unexpected(error_t{-1, "Failed to create TLS client"});
  }

  auto cert_data = get_default_ca_certificates();
  ret.state->cert_data.assign(cert_data.begin(), cert_data.end());

  using tls_config_ptr_t = std::unique_ptr<tls_config, decltype(&tls_config_free)>;
  tls_config_ptr_t tls_config(tls_config_new(), &tls_config_free);
  if (!tls_config)
  {
    return std::unexpected(error_t{-1, "Failed to create TLS config"});
  }

  if (config.ca_mem)
  {
    if (auto result = tls_config_set_ca_mem(tls_config.get(), config.ca_mem->data(), config.ca_mem->size()); result < 0)
      return std::unexpected(error_t{result, tls_error(ret.state->tls_ctx)});
  }
  else if (config.ca_file || config.ca_path)
  {
    if (auto result = tls_config_set_ca_file(tls_config.get(), config.ca_file ? config.ca_file->c_str() : nullptr); result < 0)
      return std::unexpected(error_t{result, tls_error(ret.state->tls_ctx)});
    if (auto result = tls_config_set_ca_path(tls_config.get(), config.ca_path ? config.ca_path->c_str() : nullptr); result < 0)
      return std::unexpected(error_t{result, tls_error(ret.state->tls_ctx)});
  }
  else
  {
    if (auto result = tls_config_set_ca_mem(tls_config.get(), ret.state->cert_data.data(), ret.state->cert_data.size()); result < 0)
      return std::unexpected(error_t{result, tls_error(ret.state->tls_ctx)});
  }

  if (config.cert_mem && config.key_mem)
  {
    if (auto result = tls_config_set_cert_mem(tls_config.get(), config.cert_mem->data(), config.cert_mem->size()); result < 0)
      return std::unexpected(error_t{result, tls_error(ret.state->tls_ctx)});
    if (auto result = tls_config_set_key_mem(tls_config.get(), config.key_mem->data(), config.key_mem->size()); result < 0)
      return std::unexpected(error_t{result, tls_error(ret.state->tls_ctx)});
  }
  else if (config.cert_file && config.key_file)
  {
    if (auto result = tls_config_set_cert_file(tls_config.get(), config.cert_file->c_str()); result < 0)
      return std::unexpected(error_t{result, tls_error(ret.state->tls_ctx)});
    if (auto result = tls_config_set_key_file(tls_config.get(), config.key_file->c_str()); result < 0)
      return std::unexpected(error_t{result, tls_error(ret.state->tls_ctx)});
  }

  if (config.ocsp_staple_mem)
  {
    if (auto result = tls_config_set_ocsp_staple_mem(tls_config.get(), config.ocsp_staple_mem->data(), config.ocsp_staple_mem->size()); result < 0)
      return std::unexpected(error_t{result, tls_error(ret.state->tls_ctx)});
  }
  else if (config.ocsp_staple_file)
  {
    if (auto result = tls_config_set_ocsp_staple_file(tls_config.get(), config.ocsp_staple_file->c_str()); result < 0)
      return std::unexpected(error_t{result, tls_error(ret.state->tls_ctx)});
  }

  if (config.ciphers)
    if (auto result = tls_config_set_ciphers(tls_config.get(), config.ciphers->c_str()); result < 0)
      return std::unexpected(error_t{result, tls_error(ret.state->tls_ctx)});

  if (config.alpn)
    if (auto result = tls_config_set_alpn(tls_config.get(), config.alpn->c_str()); result < 0)
      return std::unexpected(error_t{result, tls_error(ret.state->tls_ctx)});

  if (config.protocols)
    if (auto result = tls_config_set_protocols(tls_config.get(), *config.protocols); result < 0)
      return std::unexpected(error_t{result, tls_error(ret.state->tls_ctx)});

  if (config.dheparams)
    // if (auto result = tls_config_set_dheparams(tls_config.get(), *config.dheparams); result < 0)
    //   return std::unexpected(error_t{result, tls_error(ret.state->tls_ctx)});

    if (config.ecdhecurve)
      // if (auto result = tls_config_set_ecdhecurve(tls_config.get(), *config.ecdhecurve); result < 0)
      //   return std::unexpected(error_t{result, tls_error(ret.state->tls_ctx)});

      if (config.verify_client)
        tls_config_verify_client(tls_config.get());

  if (config.verify_depth)
    tls_config_set_verify_depth(tls_config.get(), *config.verify_depth);

  if (config.verify_optional)
    tls_config_verify(tls_config.get());

  if (auto result = tls_configure(ret.state->tls_ctx, tls_config.get()); result < 0)
  {
    return std::unexpected(error_t{result, tls_error(ret.state->tls_ctx)});
  }

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

inline void default_dealloc(void *, uv_buf_t *data)
{
  delete[] data->base;
  data->base = nullptr;
  data->len = 0;
}

inline void default_alloc(void *, size_t suggested_size, uv_buf_t *buf)
{
  if (buf == nullptr)
  {
    return;
  }
  buf->base = new char[suggested_size];
  buf->len = suggested_size;
}

inline void on_readable(uv_poll_t *handle, int status, int events);

bool read_from_tls_context(ref_ptr_t<ssl_client_state_t> state)
{
  struct call_read_resume_on_exit_t
  {
    ref_ptr_t<ssl_client_state_t> &state;
    call_read_resume_on_exit_t(ref_ptr_t<ssl_client_state_t> &state)
      : state(state)
    {
    }

    ~call_read_resume_on_exit_t()
    {
      if (state->read_continuation && state->buffer_front != state->buffer_back)
      {
        state->read_continuation.resume();
      }
    }
  };
  call_read_resume_on_exit_t call_read_resume_on_exit{state};
  while ((state->buffer_back + 1) % state->buffer_queue.size() != state->buffer_front)
  {
    uv_buf_t read_buf;
    state->alloc_cb(nullptr, 4096, &read_buf);

    auto r = tls_read(state->tls_ctx, read_buf.base, read_buf.len);
    if (r == TLS_WANT_POLLIN || r == 0)
    {
      state->dealloc_cb(nullptr, &read_buf);
      if (!state->poll_active)
      {
        state->poll_active = true;
        uv_poll_start(&state->poll_req, UV_READABLE, on_readable);
      }
      return true;
    }

    if (r < 0)
    {
      state->dealloc_cb(nullptr, &read_buf);
      state->buffer_queue[state->buffer_back] = std::unexpected(error_t{int(r), tls_error(state->tls_ctx)});
      state->buffer_back = (state->buffer_back + 1) % state->buffer_queue.size();
      uv_poll_stop(&state->poll_req);
      state->poll_active = false;
      return false;
    }

    read_buf.len = size_t(r);
    state->buffer_queue[state->buffer_back] = std::make_pair(read_buf, state->dealloc_cb);
    state->buffer_back = (state->buffer_back + 1) % state->buffer_queue.size();
  }

  state->poll_active = false;
  uv_poll_stop(&state->poll_req);

  return true;
}

inline void on_readable(uv_poll_t *handle, int status, int events)
{
  auto state = ref_ptr_t<ssl_client_state_t>::from_raw(handle->data);
  if (status < 0)
  {
    return;
  }

  if (!(events & UV_READABLE))
  {
    return;
  }
  if (!(events & UV_READABLE))
  {
    return;
  }

  read_from_tls_context(state);
}

struct ssl_client_reader_t
{
  ref_ptr_t<ssl_client_state_t> state;

  ssl_client_reader_t(const ref_ptr_t<ssl_client_state_t> &state)
    : state(state)
  {
  }

  ssl_client_reader_t(const ssl_client_reader_t &) = delete;
  ssl_client_reader_t &operator=(const ssl_client_reader_t &) = delete;

  ssl_client_reader_t(ssl_client_reader_t &&other) noexcept
    : state(std::move(other.state))
  {
    assert(state.ptr() && "Invalid state in move constructor");
  }

  ssl_client_reader_t &operator=(ssl_client_reader_t &&other) noexcept
  {
    if (this != &other)
    {
      assert(other.state.ptr() && "Invalid state in move assignment");
      state = std::move(other.state);
    }
    return *this;
  }

  ~ssl_client_reader_t()
  {
    if (!state.ptr())
    {
      return;
    }
    state->reader_active = false;
    if (state->poll_active)
    {
      uv_poll_stop(&state->poll_req);
      state->poll_active = false;
    }
    state.inc_ref_and_store_in_handle(state->poll_req);
    auto close_cb = [](uv_handle_t *handle)
    {
      if (handle->data)
      {
        auto state_ref = ref_ptr_t<ssl_client_state_t>::from_raw(handle->data);
        handle->data = nullptr;
      }
    };
    uv_close((uv_handle_t *)&state->poll_req, close_cb);
  }

  bool await_ready() noexcept
  {
    if (!state.ptr())
    {
      throw std::runtime_error("Invalid state in await_ready");
    }
    return state->buffer_front != state->buffer_back;
  }

  void await_suspend(std::coroutine_handle<> continuation) noexcept
  {
    assert(state.ptr() && "Invalid state in await_suspend");
    state->read_continuation = continuation;
  }

  auto await_resume() noexcept
  {
    assert(state.ptr() && "Invalid state in await_resume");
    auto ret = std::move(state->buffer_queue[state->buffer_front]);
    state->buffer_front = (state->buffer_front + 1) % state->buffer_queue.size();
    return ret;
  }
};

inline std::expected<ssl_client_reader_t, error_t> ssl_client_create_reader(ssl_client_t &client, ssl_client_alloc_cb_t alloc_cb = default_alloc, ssl_client_dealloc_cb_t dealloc_cb = default_dealloc,
                                                                            void *user_alloc_ptr = nullptr)
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
  client.state->buffer_front = 0;
  client.state->buffer_back = 0;

  uv_poll_init_socket(client.state->event_loop.loop(), &client.state->poll_req, client.state->socket_fd);
  client.state->alloc_cb = alloc_cb;
  client.state->dealloc_cb = dealloc_cb;

  read_from_tls_context(client.state);

  return {ssl_client_reader_t{client.state}};
}

struct ssl_client_write_awaitable_t
{
  ref_ptr_t<ssl_client_state_t> state;
  ssl_write_state_t &write_state;

  ssl_client_write_awaitable_t(ref_ptr_t<ssl_client_state_t> state, ssl_write_state_t &write_state)
    : state(state)
    , write_state(write_state)
  {
  }

  ssl_client_write_awaitable_t(const ssl_client_write_awaitable_t &) = delete;
  ssl_client_write_awaitable_t &operator=(const ssl_client_write_awaitable_t &) = delete;

  ssl_client_write_awaitable_t(ssl_client_write_awaitable_t &&) noexcept = default;
  ssl_client_write_awaitable_t &operator=(ssl_client_write_awaitable_t &&) noexcept = default;

  bool await_ready() const noexcept
  {
    return write_state.done || write_state.error;
  }
  void await_suspend(std::coroutine_handle<> h) noexcept
  {
    write_state.continuation = h;
  }
  std::expected<void, error_t> await_resume() noexcept
  {
    if (write_state.error)
      return std::unexpected(error_t{-1, write_state.error_msg});
    return {};
  }
};

inline std::expected<ssl_client_write_awaitable_t, error_t> ssl_client_write(ssl_client_t &client, uv_buf_t buffer)
{
  assert(client.state.ptr() != nullptr && "Can not write to a closed client");
  assert(client.state->connected && "Can not write to a client that is not connected");

  auto &write_state = client.state->write_queue.emplace();
  write_state.buf = buffer;
  return ssl_client_write_awaitable_t(client.state, write_state);
}

} // namespace vio