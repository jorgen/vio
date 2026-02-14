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
#include "vio/unique_buf.h"
#include "vio/uv_coro.h"

#include <coroutine>
#include <cstring>
#include <expected>
#include <string>
#include <utility>
#include <uv.h>

namespace vio
{

struct udp_datagram_t
{
  unique_buf_t data;
  sockaddr_storage sender_addr = {};

  const sockaddr *get_sender() const
  {
    return reinterpret_cast<const sockaddr *>(&sender_addr);
  }

  int sender_port() const
  {
    if (sender_addr.ss_family == AF_INET)
    {
      return ntohs(reinterpret_cast<const sockaddr_in *>(&sender_addr)->sin_port);
    }
    if (sender_addr.ss_family == AF_INET6)
    {
      return ntohs(reinterpret_cast<const sockaddr_in6 *>(&sender_addr)->sin6_port);
    }
    return -1;
  }
};

struct udp_send_state_t
{
  uv_udp_send_t req = {};
  std::coroutine_handle<> continuation;
  std::expected<void, error_t> result;
  bool started = false;
  bool done = false;
};

struct udp_recv_state_t
{
  bool active = false;
  bool started = false;
  bool is_cancelled = false;
  bool cancelled = false;
  std::vector<std::expected<udp_datagram_t, error_t>> buffer_queue;
  std::coroutine_handle<> continuation;
  alloc_cb_t alloc_buffer_cb = default_alloc;
  dealloc_cb_t dealloc_buffer_cb = default_dealloc;
  void *alloc_cb_data = nullptr;
};

struct udp_state_t
{
  event_loop_t &event_loop;
  uv_udp_t uv_handle = {};

  uv_udp_t *get_udp()
  {
    return &uv_handle;
  }

  uv_handle_t *get_handle()
  {
    return reinterpret_cast<uv_handle_t *>(&uv_handle);
  }

  udp_send_state_t send;
  udp_recv_state_t recv;
};

template <typename State>
struct udp_future_t
{
  ref_ptr_t<udp_state_t> handle;
  State *state;
  udp_future_t(ref_ptr_t<udp_state_t> handle, State &state)
    : handle(std::move(handle))
    , state(&state)
  {
  }
  bool await_ready() noexcept
  {
    return state->done;
  }

  bool await_suspend(std::coroutine_handle<> continuation) noexcept
  {
    if (state->done)
    {
      return false;
    }
    state->continuation = continuation;
    return true;
  }

  auto await_resume() noexcept
  {
    return state->result;
  }
};

struct udp_t
{
  ref_ptr_t<udp_state_t> handle;

  uv_udp_t *get_udp()
  {
    if (handle.ref_counted() == nullptr)
    {
      return nullptr;
    }
    return handle->get_udp();
  }

  uv_handle_t *get_handle()
  {
    if (handle.ref_counted() == nullptr)
    {
      return nullptr;
    }
    return handle->get_handle();
  }
};

inline std::expected<udp_t, error_t> udp_create(event_loop_t &loop)
{
  udp_t udp{ref_ptr_t<udp_state_t>(loop)};
  if (auto r = uv_udp_init(loop.loop(), udp.get_udp()); r < 0)
  {
    return std::unexpected(error_t{.code = r, .msg = uv_strerror(r)});
  }
  udp.handle.register_handle(udp.get_udp());
  return udp;
}

inline std::expected<void, error_t> udp_bind(udp_t &udp, const sockaddr *addr, unsigned int flags = 0)
{
  auto r = uv_udp_bind(udp.get_udp(), addr, flags);
  if (r < 0)
  {
    return std::unexpected(error_t{.code = r, .msg = uv_strerror(r)});
  }
  return {};
}

inline std::expected<void, error_t> udp_connect(udp_t &udp, const sockaddr *addr)
{
  auto r = uv_udp_connect(udp.get_udp(), addr);
  if (r < 0)
  {
    return std::unexpected(error_t{.code = r, .msg = uv_strerror(r)});
  }
  return {};
}

inline std::expected<void, error_t> udp_disconnect(udp_t &udp)
{
  auto r = uv_udp_connect(udp.get_udp(), nullptr);
  if (r < 0)
  {
    return std::unexpected(error_t{.code = r, .msg = uv_strerror(r)});
  }
  return {};
}

inline std::expected<sockaddr_storage, error_t> udp_sockname(udp_t &udp)
{
  sockaddr_storage sa_storage{};
  int name_len = sizeof(sa_storage);
  if (auto r = uv_udp_getsockname(udp.get_udp(), reinterpret_cast<sockaddr *>(&sa_storage), &name_len); r < 0)
  {
    return std::unexpected(error_t{.code = r, .msg = uv_strerror(r)});
  }
  return sa_storage;
}

inline std::expected<void, error_t> udp_set_broadcast(udp_t &udp, bool on)
{
  auto r = uv_udp_set_broadcast(udp.get_udp(), on ? 1 : 0);
  if (r < 0)
  {
    return std::unexpected(error_t{.code = r, .msg = uv_strerror(r)});
  }
  return {};
}

inline std::expected<void, error_t> udp_set_ttl(udp_t &udp, int ttl)
{
  auto r = uv_udp_set_ttl(udp.get_udp(), ttl);
  if (r < 0)
  {
    return std::unexpected(error_t{.code = r, .msg = uv_strerror(r)});
  }
  return {};
}

inline std::expected<void, error_t> udp_set_multicast_loop(udp_t &udp, bool on)
{
  auto r = uv_udp_set_multicast_loop(udp.get_udp(), on ? 1 : 0);
  if (r < 0)
  {
    return std::unexpected(error_t{.code = r, .msg = uv_strerror(r)});
  }
  return {};
}

inline std::expected<void, error_t> udp_set_multicast_ttl(udp_t &udp, int ttl)
{
  auto r = uv_udp_set_multicast_ttl(udp.get_udp(), ttl);
  if (r < 0)
  {
    return std::unexpected(error_t{.code = r, .msg = uv_strerror(r)});
  }
  return {};
}

inline std::expected<void, error_t> udp_set_membership(udp_t &udp, const char *multicast_addr, const char *interface_addr, uv_membership membership)
{
  auto r = uv_udp_set_membership(udp.get_udp(), multicast_addr, interface_addr, membership);
  if (r < 0)
  {
    return std::unexpected(error_t{.code = r, .msg = uv_strerror(r)});
  }
  return {};
}

using udp_send_future_t = udp_future_t<udp_send_state_t>;
inline udp_send_future_t send_udp(udp_t &udp, const uint8_t *data, std::size_t length, const sockaddr *addr)
{
  udp_send_future_t ret(udp.handle, udp.handle->send);
  if (ret.handle->send.started)
  {
    ret.handle->send.done = true;
    ret.handle->send.result = std::unexpected(error_t{.code = -1, .msg = "It's an error to have more than one send in flight at a time"});
    return ret;
  }
  ret.handle->send.started = true;
  ret.handle->send.done = false;
  ret.handle->send.result = {};

  uv_buf_t buf = uv_buf_init(reinterpret_cast<char *>(const_cast<uint8_t *>(data)), static_cast<unsigned int>(length));

  auto callback = [](uv_udp_send_t *req, int status)
  {
    auto state_ref = ref_ptr_t<udp_state_t>::from_raw(req->data);
    if (status < 0)
    {
      state_ref->send.result = std::unexpected(error_t{.code = status, .msg = uv_strerror(status)});
    }
    state_ref->send.done = true;
    state_ref->send.started = false;
    if (state_ref->send.continuation)
    {
      auto continuation = state_ref->send.continuation;
      state_ref->send.continuation = {};
      continuation.resume();
    }
  };

  auto copy = ret.handle;
  ret.handle->send.req.data = copy.release_to_raw();
  auto r = uv_udp_send(&ret.handle->send.req, udp.get_udp(), &buf, 1, addr, callback);

  if (r < 0)
  {
    ret.handle->send.done = true;
    ret.handle->send.started = false;
    ret.handle->send.result = std::unexpected(error_t{.code = r, .msg = uv_strerror(r)});
    ref_ptr_t<udp_state_t>::from_raw(ret.handle->send.req.data);
  }

  return ret;
}

inline udp_send_future_t send_udp(udp_t &udp, const uint8_t *data, std::size_t length)
{
  return send_udp(udp, data, length, nullptr);
}

class udp_reader_t
{
public:
  udp_reader_t(const udp_reader_t &) = delete;
  udp_reader_t &operator=(const udp_reader_t &) = delete;

  udp_reader_t(udp_reader_t &&other) noexcept
    : handle(std::move(other.handle))
    , _is_valid(other._is_valid)
  {
    other._is_valid = false;
  }

  udp_reader_t &operator=(udp_reader_t &&other) noexcept
  {
    if (this != &other)
    {
      if (_is_valid && handle->recv.started)
      {
        auto state = ref_ptr_t<udp_state_t>::from_raw(handle->get_udp()->data);
        uv_udp_recv_stop(handle->get_udp());
        state->recv.started = false;
        state->recv.active = false;
      }
      handle = std::move(other.handle);
      _is_valid = other._is_valid;
      other._is_valid = false;
    }
    return *this;
  }

  ~udp_reader_t()
  {
    if (_is_valid && handle->recv.started)
    {
      auto state = ref_ptr_t<udp_state_t>::from_raw(handle->get_udp()->data);
      uv_udp_recv_stop(handle->get_udp());
      state->recv.started = false;
      state->recv.active = false;
    }
  }

  void cancel()
  {
    if (handle->recv.is_cancelled)
    {
      return;
    }

    handle->recv.is_cancelled = true;

    handle->recv.buffer_queue.emplace_back(std::unexpected(error_t{.code = UV_ECANCELED, .msg = "Operation was cancelled"}));

    if (handle->recv.continuation)
    {
      auto continuation = handle->recv.continuation;
      handle->recv.continuation = nullptr;
      continuation.resume();
    }
  }

  [[nodiscard]] bool is_cancelled() const
  {
    return handle->recv.is_cancelled;
  }

  struct awaiter_t
  {
    ref_ptr_t<udp_state_t> state;

    [[nodiscard]] bool await_ready() const
    {
      return !state->recv.buffer_queue.empty();
    }

    void await_suspend(std::coroutine_handle<> h)
    {
      state->recv.continuation = h;
    }

    std::expected<udp_datagram_t, error_t> await_resume()
    {
      auto result = std::move(state->recv.buffer_queue.front());
      state->recv.buffer_queue.erase(state->recv.buffer_queue.begin());
      return result;
    }
  };

  auto operator co_await()
  {
    return awaiter_t{this->handle};
  }

  // NOLINTNEXTLINE(cppcoreguidelines-special-member-functions)
  struct ref_ptr_releaser_t
  {
    explicit ref_ptr_releaser_t(ref_ptr_t<udp_state_t> &handle)
      : handle(handle)
    {
    }

    ~ref_ptr_releaser_t()
    {
      handle.release_to_raw();
    }
    ref_ptr_t<udp_state_t> &handle;
  };

  static void recv_cb(uv_udp_t *udp_handle, ssize_t nread, const uv_buf_t *buf, const sockaddr *addr, unsigned int /*flags*/)
  {
    auto udp_state = ref_ptr_t<udp_state_t>::from_raw(udp_handle->data);
    ref_ptr_releaser_t releaser(udp_state);

    if (nread == 0 && addr == nullptr)
    {
      if (buf != nullptr && buf->base != nullptr)
      {
        udp_state->recv.dealloc_buffer_cb(udp_state->recv.alloc_cb_data, const_cast<uv_buf_t *>(buf));
      }
      return;
    }

    if (nread > 0)
    {
      uv_buf_t sized_buf = *buf;
      sized_buf.len = static_cast<decltype(sized_buf.len)>(nread);

      udp_datagram_t datagram;
      datagram.data = unique_buf_t(sized_buf, udp_state->recv.dealloc_buffer_cb, udp_state->recv.alloc_cb_data);
      if (addr != nullptr)
      {
        std::memcpy(&datagram.sender_addr, addr, addr->sa_family == AF_INET6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in));
      }
      udp_state->recv.buffer_queue.emplace_back(std::move(datagram));
    }
    else
    {
      auto error = std::unexpected(error_t{.code = static_cast<int>(nread), .msg = uv_strerror(static_cast<int>(nread))});
      udp_state->recv.buffer_queue.emplace_back(std::move(error));

      if (buf != nullptr && buf->base != nullptr)
      {
        udp_state->recv.dealloc_buffer_cb(udp_state->recv.alloc_cb_data, const_cast<uv_buf_t *>(buf));
      }
    }

    if (udp_state->recv.continuation)
    {
      auto continuation = udp_state->recv.continuation;
      udp_state->recv.continuation = nullptr;
      continuation.resume();
    }
  }

  ref_ptr_t<udp_state_t> handle;
  friend std::expected<udp_reader_t, error_t> udp_create_reader(udp_t &udp);

private:
  explicit udp_reader_t(const udp_t &udp)
    : handle(udp.handle)
    , _is_valid(true)
  {
  }
  bool _is_valid = false;
};

inline std::expected<udp_reader_t, error_t> udp_create_reader(udp_t &udp)
{
  if (udp.handle.ref_counted() == nullptr)
  {
    return std::unexpected(error_t{.code = 1, .msg = "Can not create a reader for a closed udp socket"});
  }
  if (udp.handle->recv.active)
  {
    return std::unexpected(error_t{.code = 1, .msg = "Can not create multiple active readers for a udp socket. Destroy other reader, before making a new one."});
  }

  auto alloc_cb = [](uv_handle_t *h, size_t size, uv_buf_t *buf)
  {
    auto udp_state = ref_ptr_t<udp_state_t>::from_raw(h->data);
    udp_state->recv.alloc_buffer_cb(udp_state->recv.alloc_cb_data, size, buf);
    udp_state.release_to_raw();
  };
  auto copy = udp.handle;
  udp.get_udp()->data = copy.release_to_raw();
  if (const auto r = uv_udp_recv_start(udp.get_udp(), alloc_cb, &udp_reader_t::recv_cb); r >= 0)
  {
    udp.handle->recv.active = true;
    udp.handle->recv.started = true;
  }
  else
  {
    auto udp_state = ref_ptr_t<udp_state_t>::from_raw(udp.get_udp()->data);
    return std::unexpected(error_t{.code = r, .msg = uv_strerror(r)});
  }

  return udp_reader_t{udp};
}

} // namespace vio
