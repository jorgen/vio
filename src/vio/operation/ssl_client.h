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
#include "vio/elastic_index_storage.h"
#include "vio/error.h"
#include "vio/operation/ssl_common.h"
#include "vio/ref_ptr.h"
#include "vio/unique_buf.h"

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
struct ssl_write_state_t
{
  uv_buf_t buf = {};
  size_t bytes_written = 0;
  int ref = 2;
  bool done = false;
  int error_code = 0;
  std::string error_msg;
  std::coroutine_handle<> continuation = {};
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
  std::string cert_data;

  std::coroutine_handle<> connect_continuation;
  std::expected<void, error_t> connect_result;

  address_info_list_t addresses;
  int address_index = 0;
  bool connected = false;
  bool connecting = false;
  bool resolved_done = false;

  uv_poll_t poll_req = {};
  bool poll_read_active = false;
  bool poll_write_active = false;
  bool poll_running = false;
  bool reader_active = false;
  std::coroutine_handle<> read_continuation;
  std::coroutine_handle<> read_buffer_continuation;
  alloc_cb_t alloc_cb;
  dealloc_cb_t dealloc_cb;
  void *user_alloc_ptr = nullptr;

  int buffer_front = 0;
  int buffer_back = 0;
  struct ssl_client_buffer_t
  {
    uv_buf_t buf;
    size_t capacity;
    dealloc_cb_t dealloc_cb;
  };
  std::array<std::expected<ssl_client_buffer_t, error_t>, 10> buffer_queue;
  [[nodiscard]] bool has_buffer_with_error_or_data() const
  {
    if (buffer_front == buffer_back)
      return false;
    auto &buffer = buffer_queue[buffer_front];
    if (!buffer.has_value() && buffer.error().code)
      return true;
    if (buffer.has_value() && buffer.value().buf.len > 0)
      return true;
    return false;
  }

  uv_buf_t read_buffer = {};
  size_t bytes_read = 0;
  error_t read_buffer_error = {};

  elastic_index_storage_t<ssl_write_state_t> write_queue;

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
        BIO_socket_nbio(state->socket_fd, 0);

        if (auto tls_result = tls_connect_socket(state->tls_ctx, state->socket_fd, state->host.c_str()); tls_result == 0)
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

      if (int result = uv_poll_init_socket(state->event_loop.loop(), &state->poll_req, state->socket_fd); result < 0)
      {
        state->connect_result = std::unexpected(error_t{.code = -1, .msg = std::string("Failed to initialize poll, ") + uv_strerror(result)});
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
    tls_close(state->tls_ctx);
    tls_free(state->tls_ctx);

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

  ret.state->cert_data = get_default_ca_certificates();
  auto apply = apply_ssl_config_to_tls_ctx(config, ret.state->cert_data, ret.state->tls_ctx);
  if (!apply.has_value())
  {
    return std::unexpected(apply.error());
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

static void on_readable(uv_poll_t *handle, int status, int events);
static void on_writable(uv_poll_t *handle, int status, int events);

static void on_poll_event(uv_poll_t *handle, int status, int events)
{
  if (events & UV_WRITABLE)
  {
    on_writable(handle, status, events);
  }
  if (events & UV_READABLE)
  {
    on_readable(handle, status, events);
  }
  if (!(events & (UV_WRITABLE | UV_READABLE)))
  {
    fprintf(stderr, "on_poll_event: unexpected events %d\n", events);
  }
}

void set_poll_state(ref_ptr_t<ssl_client_state_t> &state)
{
  int events = 0;
  if (state->poll_read_active)
    events |= UV_READABLE;
  if (state->poll_write_active)
    events |= UV_WRITABLE;

  if (events)
  {
    uv_poll_start(&state->poll_req, events, on_poll_event);
    state->poll_running = true;
  }
  else if (state->poll_running)
  {
    uv_poll_stop(&state->poll_req);
    state->poll_running = false;
  }
}

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
      if (state->read_buffer_continuation && (state->read_buffer.len > 0 && state->bytes_read == state->read_buffer.len || state->read_buffer_error.code))
      {
        state->read_buffer_continuation.resume();
      }
      if (state->read_buffer.len == 0 && state->read_continuation && state->has_buffer_with_error_or_data())
      {
        state->read_continuation.resume();
      }
    }
  };
  call_read_resume_on_exit_t call_read_resume_on_exit{state};

  if (state->read_buffer.len > 0)
  {
    while (state->bytes_read < state->read_buffer.len)
    {
      auto remaining = state->read_buffer.len - state->bytes_read;
      auto r = tls_read(state->tls_ctx, state->read_buffer.base + state->bytes_read, remaining);
      if (r == TLS_WANT_POLLIN || r == 0)
      {
        if (!state->poll_read_active)
        {
          state->poll_read_active = true;
          set_poll_state(state);
        }
        return true;
      }
      if (r < 0)
      {
        state->read_buffer_error = error_t{int(r), tls_error(state->tls_ctx)};
        state->poll_read_active = false;
        set_poll_state(state);
        return false;
      }
      state->bytes_read += r;
    }
    return true;
  }

  while ((state->buffer_back + 1) % state->buffer_queue.size() != state->buffer_front)
  {
    ssl_client_state_t::ssl_client_buffer_t *current_buffer = nullptr;
    if (state->buffer_back > 0)
    {
      auto &last = state->buffer_queue[state->buffer_back - 1];
      if (last.has_value() && last->buf.len < last->capacity)
      {
        current_buffer = &last.value();
      }
    }

    if (!current_buffer)
    {
      uv_buf_t read_buf;
      state->alloc_cb(state->user_alloc_ptr, 65536, &read_buf);
      auto capacity = read_buf.len;
      read_buf.len = 0;
      state->buffer_queue[state->buffer_back] = ssl_client_state_t::ssl_client_buffer_t{read_buf, capacity, state->dealloc_cb};
      current_buffer = &state->buffer_queue[state->buffer_back].value();
      state->buffer_back = (state->buffer_back + 1) % state->buffer_queue.size();
    }

    auto remaining = current_buffer->capacity - current_buffer->buf.len;
    auto r = tls_read(state->tls_ctx, current_buffer->buf.base + current_buffer->buf.len, remaining);
    if (r == TLS_WANT_POLLIN || r == 0)
    {
      if (!state->poll_read_active)
      {
        state->poll_read_active = true;
        set_poll_state(state);
      }
      return true;
    }

    if (r < 0)
    {
      if (current_buffer->buf.len == 0)
      {
        current_buffer->dealloc_cb(nullptr, &current_buffer->buf);
        state->buffer_queue[state->buffer_back - 1] = std::unexpected(error_t{int(r), tls_error(state->tls_ctx)});
      }
      uv_poll_stop(&state->poll_req);
      state->poll_read_active = false;
      return false;
    }

    current_buffer->buf.len += r;
  }

  state->poll_read_active = false;
  set_poll_state(state);

  return true;
}

inline void on_readable(uv_poll_t *handle, int status, int events)
{
  auto state = ref_ptr_t<ssl_client_state_t>::from_raw(handle->data);
  assert(state && "Invalid state in on_readable");

  if (!(events & UV_READABLE))
  {
    return;
  }

  read_from_tls_context(state);
  if (state->poll_read_active)
    state.inc_ref_and_store_in_handle(state->poll_req);
}

struct ssl_client_read_awaitable_t
{
  ref_ptr_t<ssl_client_state_t> state;

  bool await_ready() noexcept
  {
    assert(state && "Invalid state in await_ready");
    return state->bytes_read == state->read_buffer.len || state->read_buffer_error.code;
  }

  void await_suspend(std::coroutine_handle<> continuation) noexcept
  {
    assert(state.ptr() && "Invalid state in await_suspend");
    state->read_buffer_continuation = continuation;
    read_from_tls_context(state);
  }

  auto await_resume() noexcept
  {
    assert(state.ptr() && "Invalid state in await_resume");
    assert(state->bytes_read == state->read_buffer.len || state->read_buffer_error.code);
    return std::expected<std::pair<uv_buf_t, dealloc_cb_t>, error_t>{{state->read_buffer, nullptr}};
  }
};

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
    if (state->poll_read_active)
    {
      uv_poll_stop(&state->poll_req);
      state->poll_read_active = false;
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
    assert(state && "Invalid state in await_ready");
    return state->has_buffer_with_error_or_data();
  }

  void await_suspend(std::coroutine_handle<> continuation) noexcept
  {
    assert(state.ptr() && "Invalid state in await_suspend");
    state->read_continuation = continuation;
  }

  auto await_resume() noexcept -> std::expected<unique_buf_t, error_t>
  {
    assert(state.ptr() && "Invalid state in await_resume");
    assert(state->has_buffer_with_error_or_data() && "Empty buffer in await_resume");
    auto ret = std::move(state->buffer_queue[state->buffer_front]);
    state->buffer_front = (state->buffer_front + 1) % state->buffer_queue.size();

    if (!ret.has_value())
    {
      return std::unexpected(ret.error());
    }
    return unique_buf_t(ret.value().buf, ret.value().dealloc_cb, state->user_alloc_ptr);
  }

  ssl_client_read_awaitable_t read(uv_buf_t buf)
  {
    state->read_buffer = buf;
    state->bytes_read = 0;

    while (state->buffer_front != state->buffer_back && state->bytes_read < buf.len)
    {
      auto &queued = state->buffer_queue[state->buffer_front].value();
      auto to_copy = std::min(queued.buf.len, buf.len - ULONG(state->bytes_read));
      std::memcpy(buf.base + state->bytes_read, queued.buf.base, to_copy);
      state->bytes_read += to_copy;

      if (to_copy == queued.buf.len)
      {
        if (queued.dealloc_cb)
          queued.dealloc_cb(nullptr, &queued.buf);
        state->buffer_front = (state->buffer_front + 1) % state->buffer_queue.size();
      }
      else
      {
        queued.buf.base += to_copy;
        queued.buf.len -= to_copy;
      }
    }

    return {state};
  }
};

inline std::expected<ssl_client_reader_t, error_t> ssl_client_create_reader(ssl_client_t &client, alloc_cb_t alloc_cb = default_alloc, dealloc_cb_t dealloc_cb = default_dealloc, void *user_alloc_ptr = nullptr)
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

  client.state->alloc_cb = alloc_cb;
  client.state->dealloc_cb = dealloc_cb;
  client.state->user_alloc_ptr = user_alloc_ptr;

  read_from_tls_context(client.state);
  if (client.state->poll_read_active)
    client.state.inc_ref_and_store_in_handle(client.state->poll_req);

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
static void try_write_queue(ref_ptr_t<ssl_client_state_t> &state)
{
  if (!state->write_queue.current_item_is_active() && !state->write_queue.next())
  {
    return;
  }

  while (state->write_queue.current_item_is_active())
  {
    auto &write_state = state->write_queue.current_item();
    auto remaining = write_state.buf.len - write_state.bytes_written;
    auto written = tls_write(state->tls_ctx, write_state.buf.base + write_state.bytes_written, remaining);
    if (written == TLS_WANT_POLLOUT)
    {
      if (!state->poll_write_active)
      {
        state->poll_write_active = true;
        set_poll_state(state);
      }
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
          state->write_queue.deactivate_current();
        }
        state->write_queue.next();
      }
    }
    else
    {
      write_state.error_code = int(written);
      write_state.error_msg = tls_error(state->tls_ctx);
      write_state.done = true;
      if (write_state.continuation)
        write_state.continuation.resume();
      if (--write_state.ref == 0)
      {
        state->write_queue.deactivate_current();
      }
      state->write_queue.next();
    }
  }
  state->poll_write_active = false;
  set_poll_state(state);
};

static void on_writable(uv_poll_t *handle, int status, int events)
{
  if (status < 0 || !(events & UV_WRITABLE))
  {
    fprintf(stderr, "on_writable: unexpected events %d\n", events);
  }
  auto state = ref_ptr_t<ssl_client_state_t>::from_raw(handle->data);
  assert(state && "Invalid state in on_writable");
  try_write_queue(state);
  if (state->poll_write_active)
    state.inc_ref_and_store_in_handle(state->poll_req);
}

inline ssl_client_write_awaitable_t ssl_client_write(ssl_client_t &client, uv_buf_t buffer)
{
  assert(client.state.ptr() != nullptr && "Can not write to a closed client");
  assert(client.state->connected && "Can not write to a client that is not connected");

  auto write_state_index = client.state->write_queue.activate();
  client.state->write_queue[write_state_index].buf = buffer;

  try_write_queue(client.state);
  if (client.state->poll_write_active)
    client.state.inc_ref_and_store_in_handle(client.state->poll_req);
  return ssl_client_write_awaitable_t(client.state, write_state_index);
}

} // namespace vio