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

#include "vio/auto_closer.h"
#include "vio/event_loop.h"
#include "vio/uv_coro.h"

#include <expected>
#include <string>
#include <utility>
#include <uv.h>

namespace vio
{

struct stream_t
{
  event_loop_t *event_loop;
  uv_stream_t handle;
};

struct tcp_t
{
  event_loop_t *event_loop;
  std::unique_ptr<uv_tcp_t> handle;

  uv_stream_t *get_stream() const
  {
    return reinterpret_cast<uv_stream_t *>(handle.get());
  }
  uv_handle_t *get_handle() const
  {
    return reinterpret_cast<uv_handle_t *>(handle.get());
  }
};

struct listen_state_t
{
  event_loop_t &event_loop;
};

inline void close_tcp(tcp_t *tcp)
{
  if (tcp && !uv_is_closing(reinterpret_cast<uv_handle_t *>(tcp->handle.get())))
  {
    uv_close(tcp->get_handle(), nullptr);
  }
}

using auto_close_tcp_t = auto_close_t<tcp_t, decltype(&close_tcp)>;
auto_close_tcp_t make_auto_close_tcp(tcp_t &&tcp)
{
  return auto_close_tcp_t(std::move(tcp), close_tcp);
}

inline std::expected<sockaddr_in, error_t> ip4_addr(const std::string &ip, int port)
{
  sockaddr_in addr;
  const int r = uv_ip4_addr(ip.c_str(), port, &addr);
  if (r != 0)
  {
    return std::unexpected(error_t{r, uv_strerror(r)});
  }
  return addr;
}

inline std::expected<sockaddr_in6, error_t> ip6_addr(const std::string &ip, int port)
{
  sockaddr_in6 addr;
  const int r = uv_ip6_addr(ip.c_str(), port, &addr);
  if (r != 0)
  {
    return std::unexpected(error_t{r, uv_strerror(r)});
  }
  return addr;
}

inline std::expected<tcp_t, error_t> create_tcp(event_loop_t &loop)
{
  tcp_t tcpInstance{&loop, std::make_unique<uv_tcp_t>()};
  if (int r = uv_tcp_init(loop.loop(), tcpInstance.handle.get()); r < 0)
  {
    return std::unexpected(error_t{r, uv_strerror(r)});
  }
  // Now returning a raw tcp_t, not auto_close_tcp_t
  return tcpInstance;
}

inline std::expected<void, error_t> tcp_bind(tcp_t &tcp, const sockaddr *addr, unsigned int flags = 0)
{
  const int r = uv_tcp_bind(tcp.handle.get(), addr, flags);
  if (r < 0)
  {
    return std::unexpected(error_t{r, uv_strerror(r)});
  }
  return {};
}

inline future<void, void> tcp_listen(event_loop_t &event_loop, tcp_t &tcp, int backlog)
{
  future<void, void> ret;

  auto statePtr = ret.state;
  tcp.handle->data = statePtr.release_to_raw();

  auto on_connection = [](uv_stream_t *server, int status)
  {
    auto stateRef = ref_ptr_t<uv_coro_state<void, void>>::from_raw(server->data);
    if (status < 0)
    {
      stateRef->result = std::unexpected(error_t{status, uv_strerror(status)});
    }
    else
    {
    }
    stateRef->done = true;
    if (stateRef->continuation)
    {
      stateRef->continuation.resume();
    }
  };

  int r = uv_listen(tcp.get_stream(), backlog, on_connection);
  if (r < 0)
  {
    ret.state->done = true;
    ret.state->result = std::unexpected(error_t{r, uv_strerror(r)});
    ref_ptr_t<uv_coro_state<void, void>>::from_raw(tcp.handle->data);
  }

  return ret;
}

inline std::expected<auto_close_tcp_t, error_t> tcp_accept(tcp_t &server)
{
  auto tcpClientOrError = create_tcp(*server.event_loop);
  if (!tcpClientOrError.has_value())
  {
    return std::unexpected(tcpClientOrError.error());
  }
  auto client = std::move(tcpClientOrError.value());

  const int r = uv_accept(server.get_stream(), reinterpret_cast<uv_stream_t *>(client.handle.get()));
  if (r < 0)
  {
    return std::unexpected(error_t{r, uv_strerror(r)});
  }
  return make_auto_close_tcp(std::move(client));
}

inline future<uv_connect_t, void> tcp_connect(event_loop_t &loop, tcp_t &tcp, const sockaddr *addr)
{
  future<uv_connect_t, void> ret;

  auto callback = [](uv_connect_t *req, int status)
  {
    auto stateRef = ref_ptr_t<uv_coro_state<uv_connect_t, void>>::from_raw(req->data);
    if (status < 0)
    {
      stateRef->result = std::unexpected(error_t{status, uv_strerror(status)});
    }
    else
    {
      // no specific "value" to return, so just success
      stateRef->result = {};
    }
    stateRef->done = true;
    if (stateRef->continuation)
    {
      stateRef->continuation.resume();
    }
  };

  // Set up the connect request
  auto copy = ret.state;
  ret.state->req.data = copy.release_to_raw();

  int r = uv_tcp_connect(&ret.state->req, tcp.handle.get(), addr, callback);
  if (r < 0)
  {
    ret.state->done = true;
    ret.state->result = std::unexpected(error_t{r, uv_strerror(r)});
    ref_ptr_t<uv_coro_state<uv_connect_t, void>>::from_raw(ret.state->req.data);
  }

  return ret;
}

inline future<uv_write_t, void> write_tcp(event_loop_t &loop, tcp_t &tcp, const uint8_t *data, std::size_t length)
{
  future<uv_write_t, void> ret;

  uv_buf_t buf = uv_buf_init(reinterpret_cast<char *>(const_cast<uint8_t *>(data)), static_cast<unsigned int>(length));

  auto callback = [](uv_write_t *req, int status)
  {
    auto stateRef = ref_ptr_t<uv_coro_state<uv_write_t, std::size_t>>::from_raw(req->data);
    if (status < 0)
    {
      stateRef->result = std::unexpected(error_t{status, uv_strerror(status)});
    }
    stateRef->done = true;
    if (stateRef->continuation)
      stateRef->continuation.resume();
  };

  auto copy = ret.state;
  ret.state->req.data = copy.release_to_raw();

  int r = uv_write(&ret.state->req, tcp.get_stream(), &buf, 1, callback);

  if (r < 0)
  {
    ret.state->done = true;
    ret.state->result = std::unexpected(error_t{r, uv_strerror(r)});
    ref_ptr_t<uv_coro_state<uv_write_t, std::size_t>>::from_raw(ret.state->req.data);
  }

  return ret;
}

// Buffer struct with unique_ptr and size
template <typename Deleter = std::default_delete<uint8_t[]>>
struct tcp_read_buffer_t
{
  std::unique_ptr<uint8_t[], Deleter> data;
  size_t size;
};

// The reader needs to be a template to handle the custom deleter
template <typename Deleter = std::default_delete<uint8_t[]>>
class tcp_reader_t
{
public:
  // Constructor takes tcp, allocation callback (libuv style), and a deleter
  tcp_reader_t(tcp_t &tcp, uv_alloc_cb alloc_cb, Deleter deleter = Deleter{})
    : tcp_(&tcp)
    , alloc_cb_(alloc_cb)
    , deleter_(std::move(deleter))
  {
  }

  // Initialize method that can fail and returns error information
  error_t initialize()
  {
    if (is_initialized_)
      return error_t{0, ""}; // Already initialized successfully

    // Register our read callback and store the reader in the tcp handle's data field
    tcp_->get_stream()->data = this;

    // Start the read operation using libuv style
    int r = uv_read_start(tcp_->get_stream(),
                          alloc_cb_, // Use the libuv style alloc callback directly
                          &tcp_reader_t::read_cb);

    // Check for errors
    if (r < 0)
    {
      return error_t{r, uv_strerror(r)};
    }

    is_initialized_ = true;
    return error_t{0, ""}; // Success
  }

  ~tcp_reader_t()
  {
    if (is_initialized_ && tcp_ && !uv_is_closing(tcp_->get_handle()))
    {
      uv_read_stop(tcp_->get_stream());
      tcp_->get_stream()->data = nullptr;
    }
  }

  // Check if the reader was initialized correctly
  [[nodiscard]] bool is_initialized() const
  {
    return is_initialized_;
  }

  // Cancel any pending read operation
  void cancel()
  {
    if (is_cancelled_)
      return; // Already cancelled

    is_cancelled_ = true;

    // Add a cancellation error to the queue
    buffer_queue_.emplace_back(std::unexpected(error_t{UV_ECANCELED, "Operation was cancelled"}));

    // If there's a waiting coroutine, resume it so it can handle the cancellation
    if (waiting_coroutine_)
    {
      auto handle = waiting_coroutine_;
      waiting_coroutine_ = nullptr;
      handle.resume();
    }
  }

  [[nodiscard]] bool is_cancelled() const
  {
    return is_cancelled_;
  }

  struct awaiter
  {
    tcp_reader_t *reader;

    bool await_ready() const
    {
      return !reader->buffer_queue_.empty() || reader->is_cancelled_;
    }

    void await_suspend(std::coroutine_handle<> handle)
    {
      reader->waiting_coroutine_ = handle;
    }

    std::expected<tcp_read_buffer_t<Deleter>, error_t> await_resume()
    {
      // Check for cancellation first (if queue is empty but cancelled)
      if (reader->is_cancelled_ && reader->buffer_queue_.empty())
      {
        return std::unexpected(error_t{UV_ECANCELED, "Operation was cancelled"});
      }

      // Get the first item from the queue
      auto result = std::move(reader->buffer_queue_.front());
      reader->buffer_queue_.erase(reader->buffer_queue_.begin());

      // Simply return the expected (which may contain value or error)
      return result;
    }
  };

  auto operator co_await()
  {
    return awaiter{this};
  }

private:
  static void read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
  {
    auto *self = static_cast<tcp_reader_t *>(stream->data);
    if (!self)
      return;

    if (self->is_cancelled_)
    {
      if (buf && buf->base)
        self->deleter_(reinterpret_cast<uint8_t *>(buf->base));
      return;
    }

    if (nread > 0)
    {
      tcp_read_buffer_t<Deleter> read_buffer;
      read_buffer.data = std::unique_ptr<uint8_t[], Deleter>(reinterpret_cast<uint8_t *>(buf->base), self->deleter_);
      read_buffer.size = static_cast<size_t>(nread);

      self->buffer_queue_.emplace_back(std::move(read_buffer));
    }
    else if (nread < 0)
    {
      auto error = std::unexpected(error_t{static_cast<int>(nread), uv_strerror(static_cast<int>(nread))});
      self->buffer_queue_.emplace_back(std::move(error));

      if (buf && buf->base)
        self->deleter_(reinterpret_cast<uint8_t *>(buf->base));
    }
    else
    {
      // nread == 0, EOF or empty read
      // Clean up buffer
      if (buf && buf->base)
        self->deleter_(reinterpret_cast<uint8_t *>(buf->base));
    }

    // If we have a waiting coroutine, resume it
    if (self->waiting_coroutine_)
    {
      auto handle = self->waiting_coroutine_;
      self->waiting_coroutine_ = nullptr;
      handle.resume();
    }
  }

  tcp_t *tcp_;
  uv_alloc_cb alloc_cb_;
  Deleter deleter_;
  std::vector<std::expected<tcp_read_buffer_t<Deleter>, error_t>> buffer_queue_;
  std::coroutine_handle<> waiting_coroutine_{nullptr};
  bool is_cancelled_{false};
  bool is_initialized_{false};
};

inline void default_tcp_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
{
  // Allocate memory with new[]
  auto *data = new uint8_t[suggested_size];

  *buf = uv_buf_init(reinterpret_cast<char *>(data), static_cast<unsigned int>(suggested_size));
}

template <typename Deleter = std::default_delete<uint8_t[]>>
inline std::expected<tcp_reader_t<Deleter>, error_t> create_tcp_reader(tcp_t &tcp, uv_alloc_cb alloc_cb = default_tcp_alloc_cb, Deleter deleter = Deleter{})
{
  tcp_reader_t<Deleter> reader(tcp, alloc_cb, std::move(deleter));

  error_t err = reader.initialize();
  if (err.code != 0)
  {
    return std::unexpected(err);
  }

  return std::expected<tcp_reader_t<Deleter>, error_t>(std::move(reader));
}

} // namespace vio