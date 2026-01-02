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

#include "vio/ref_counted_wrapper.h"
#include <uv.h>

namespace vio
{

template <typename UVHandleType>
struct closable_handle_t : UVHandleType
{
  closable_handle_t(reference_counted_t *parent)
    : UVHandleType{}
    , parent(parent)
  {
    parent->register_destroy_callback(
      [parent, this]()
      {
        if (!call_close)
        {
          return;
        }

        parent->inc();
        uv_close(this->handle(), on_close_callback);
      });
  }

  uv_handle_t *handle()
  {
    return reinterpret_cast<uv_handle_t *>(this);
  }
  const uv_handle_t *handle() const
  {
    return reinterpret_cast<const uv_handle_t *>(this);
  }

  reference_counted_t *parent;
  bool call_close = false;

private:
  static void on_close_callback(uv_handle_t *uv_handle)
  {
    auto *closable_handle = reinterpret_cast<closable_handle_t *>(uv_handle);
    closable_handle->parent->dec();
  }
};

using async_t = closable_handle_t<uv_async_t>;
using check_t = closable_handle_t<uv_check_t>;
using fs_event_t = closable_handle_t<uv_fs_event_t>;
using fs_poll_t = closable_handle_t<uv_fs_poll_t>;
using idle_t = closable_handle_t<uv_idle_t>;
using pipe_t = closable_handle_t<uv_pipe_t>;
using poll_t = closable_handle_t<uv_poll_t>;
using prepare_t = closable_handle_t<uv_prepare_t>;
using process_t = closable_handle_t<uv_process_t>;
using signal_t = closable_handle_t<uv_signal_t>;
using stream_t = closable_handle_t<uv_stream_t>;
// using tcp_t = closable_handle_t<uv_tcp_t>;  // Conflicts with tcp_t in operation/tcp.h
using timer_t = closable_handle_t<uv_timer_t>;
using tty_t = closable_handle_t<uv_tty_t>;
using udp_t = closable_handle_t<uv_udp_t>;

} // namespace vio
