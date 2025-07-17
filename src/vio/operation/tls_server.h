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
#include "vio/error.h"
#include "vio/event_loop.h"
#include "vio/ref_ptr.h"

#include <expected>
#include <tls.h>

struct ssl_server_state_t
{
  uv_tcp_t tcp_req = {};
  tls *tls_ctx = nullptr;
};

struct ssl_server_t
{
  ref_ptr_t<ssl_server_state_t> handle;
};

inline std::expected<ssl_server_t, error_t> ssl_server_create(event_loop_t &event_loop, const ssl_config &config = {})
{
  ssl_server_t ret{ref_ptr_t<ssl_server_state_t>{event_loop}};
  if (auto r = uv_tcp_init(event_loop.loop(), &ret.handle->tcp_req); r < 0)
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
        auto state_ref = ref_ptr_t<ssl_server_state_t>::from_raw(handle->data);
        handle->data = nullptr;
      }
      else
      {
        handle->data = nullptr;
      }
    };
    uv_close(state->get_tcp_handle(), close_cb);
  };
  ret.state.close_guard(to_close);
  ret.state->tls_ctx = tls_server();
  if (!ret.state->tls_ctx)
  {
    return std::unexpected(error_t{-1, "Failed to create TLS server"});
  }
  return ret;
}