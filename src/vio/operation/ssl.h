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
#include <tls.h>

#include <uv.h>
#include <vio/error.h>
#include <vio/event_loop.h>
#include <vio/operation/tcp.h>
#include <vio/ref_ptr.h>

namespace vio
{

struct ssl_tcp_state_t;

class ssl_tcp_t
{
public:
  ssl_tcp_t(ref_ptr_t<ssl_tcp_state_t> handle)
    : handle(std::move(handle))
  {
  }

  uv_tcp_t *get_tcp();
  uv_stream_t *get_stream();
  uv_handle_t *get_handle();

private:
  ref_ptr_t<ssl_tcp_state_t> handle;
};

struct ssl_tcp_state_t
{
  event_loop_t &event_loop;
  uv_tcp_t uv_handle;
  tls *tls_context = nullptr;
  uv_poll_t poll_handle;

  uv_connect_t connect_req;
  bool connect_started = false;
  bool connect_done = false;
  std::coroutine_handle<> connect_continuation;
  std::expected<void, error_t> connect_result;

  // Add other states similar to tcp_state_t for read/write

  ssl_tcp_state_t(event_loop_t &loop)
    : event_loop(loop)
  {
    uv_tcp_init(event_loop.loop(), &uv_handle);
    uv_handle.data = this;
  }

  ~ssl_tcp_state_t()
  {
    if (tls_context)
    {
      tls_close(tls_context);
      tls_free(tls_context);
    }
    if (!uv_is_closing(reinterpret_cast<uv_handle_t *>(&poll_handle)))
    {
      uv_close(reinterpret_cast<uv_handle_t *>(&poll_handle), nullptr);
    }
    if (!uv_is_closing(reinterpret_cast<uv_handle_t *>(&uv_handle)))
    {
      uv_close(reinterpret_cast<uv_handle_t *>(&uv_handle), nullptr);
    }
  }
};

inline uv_tcp_t *ssl_tcp_t::get_tcp()
{
  return &handle->uv_handle;
}

inline uv_stream_t *ssl_tcp_t::get_stream()
{
  return reinterpret_cast<uv_stream_t *>(&handle->uv_handle);
}

inline uv_handle_t *ssl_tcp_t::get_handle()
{
  return reinterpret_cast<uv_handle_t *>(&handle->uv_handle);
}

inline std::expected<ssl_tcp_t, error_t> create_ssl_tcp(event_loop_t &loop)
{
  auto state = make_ref_ptr<ssl_tcp_state_t>(loop);

  // Initialize libtls context
  if (tls_init() < 0)
  {
    // Handle libtls initialization error
    return std::unexpected(error_t{.code = -1, .msg = "Failed to initialize tls"});
  }

  state->tls_context = tls_client();
  if (state->tls_context == nullptr)
  {
    // Handle tls_client() error
    return std::unexpected(error_t{.code = -1, .msg = "Failed to create tls client state"});
  }

  return ssl_tcp_t(std::move(state));
}

} // namespace vio