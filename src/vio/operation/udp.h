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

#include "vio/cancellation.h"
#include "vio/owned_payload.h"
#include "vio/buffer_pool.h"
#include "vio/error.h"
#include "vio/event_loop.h"
#include "vio/unique_buf.h"
#include "vio/uv_coro.h"

#include <array>
#include <coroutine>
#include <cstdint>
#include <cstring>
#include <deque>
#include <expected>
#include <memory>
#include <ranges>
#include <type_traits>
#include <span>
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

// Datagrams a reader has taken off the socket but the consumer has not yet
// collected. Bounded: a peer that sends faster than the consumer drains must
// cost bounded memory, so arrivals past the limit are dropped and counted
// rather than queued. Tail drop, like the kernel's own receive buffer, so the
// datagrams that are kept stay in arrival order.
inline constexpr std::size_t udp_default_recv_queue_limit = 1024;

struct udp_recv_state_t
{
  bool active = false;
  bool started = false;
  bool is_cancelled = false;
  bool cancelled = false;
  std::deque<std::expected<udp_datagram_t, error_t>> buffer_queue;
  std::size_t recv_queue_limit = udp_default_recv_queue_limit;
  std::uint64_t dropped_datagrams = 0;
  std::uint64_t truncated_datagrams = 0;
  std::uint64_t recv_errors = 0;
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

// recvmmsg reads several datagrams per syscall. It is a Linux/BSD facility;
// libuv ignores the request elsewhere, so asking for it unconditionally is
// safe and uv_udp_using_recvmmsg reports what was actually obtained.
enum class udp_recvmmsg_t : std::uint8_t
{
  off,
  on,
};

inline std::expected<udp_t, error_t> udp_create(event_loop_t &loop, udp_recvmmsg_t recvmmsg = udp_recvmmsg_t::off)
{
  udp_t udp{ref_ptr_t<udp_state_t>(loop)};
  const int r = recvmmsg == udp_recvmmsg_t::on ? uv_udp_init_ex(loop.loop(), udp.get_udp(), AF_UNSPEC | UV_UDP_RECVMMSG) : uv_udp_init(loop.loop(), udp.get_udp());
  if (r < 0)
  {
    return std::unexpected(error_t{.code = r, .msg = uv_strerror(r)});
  }
  udp.handle.register_handle(udp.get_udp());
  return udp;
}

inline bool udp_using_recvmmsg(udp_t &udp)
{
  return uv_udp_using_recvmmsg(udp.get_udp()) != 0;
}

// libuv slices a recvmmsg buffer into fixed 64 KiB chunks and reads
// buf.len / 64 KiB datagrams at a time (src/unix/udp.c, UV__UDP_DGRAM_MAXSIZE).
// An allocator handing back less than one chunk yields zero slots, so the
// socket reads nothing at all -- silently, and forever.
inline constexpr std::size_t udp_recvmmsg_chunk_size = 64 * 1024;

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

// An owning, awaitable send. Unlike send_udp above there is one of these per
// call rather than one per socket, so any number may be in flight at once.
//
// The payload is moved in and held until libuv's completion callback fires,
// which is what makes early resumption safe: a cancelled send hands its
// awaiter an answer immediately while uv is still reading the bytes, and the
// operation stays alive underneath until uv is done with them.
struct udp_send_op_t
{
  uv_udp_send_t req = {};
  ref_ptr_t<udp_state_t> socket = ref_ptr_t<udp_state_t>::null();
  std::unique_ptr<owned_payload_t> payload;
  std::coroutine_handle<> continuation;
  std::expected<void, error_t> result;
  registration_t cancel_registration;
  bool completed = false;
  bool detached = false;
};

namespace detail
{
// The op outlives whichever of the two finishes first. Whoever is last to let
// go frees it: the callback when the awaiter has already been answered or
// abandoned, the awaiter when the callback has already fired.
inline void udp_send_release(udp_send_op_t *op)
{
  if (op->completed)
  {
    delete op;
    return;
  }
  op->detached = true;
}

inline void udp_send_cb(uv_udp_send_t *req, int status)
{
  auto *op = static_cast<udp_send_op_t *>(req->data);
  op->completed = true;
  op->cancel_registration.reset();
  if (op->detached)
  {
    delete op;
    return;
  }
  if (status < 0)
  {
    op->result = std::unexpected(error_t{.code = status, .msg = uv_strerror(status)});
  }
  if (op->continuation)
  {
    auto continuation = op->continuation;
    op->continuation = {};
    continuation.resume();
  }
}
} // namespace detail

// NOLINTNEXTLINE(cppcoreguidelines-special-member-functions)
struct udp_send_awaitable_t
{
  udp_send_op_t *op = nullptr;

  explicit udp_send_awaitable_t(udp_send_op_t *operation)
    : op(operation)
  {
  }

  udp_send_awaitable_t(const udp_send_awaitable_t &) = delete;
  udp_send_awaitable_t &operator=(const udp_send_awaitable_t &) = delete;

  udp_send_awaitable_t(udp_send_awaitable_t &&other) noexcept
    : op(std::exchange(other.op, nullptr))
  {
  }

  ~udp_send_awaitable_t()
  {
    if (op != nullptr)
    {
      detail::udp_send_release(op);
    }
  }

  [[nodiscard]] bool await_ready() const noexcept
  {
    return op->completed || op->detached;
  }

  void await_suspend(std::coroutine_handle<> continuation) noexcept
  {
    op->continuation = continuation;
  }

  std::expected<void, error_t> await_resume() noexcept
  {
    auto result = std::move(op->result);
    detail::udp_send_release(op);
    op = nullptr;
    return result;
  }
};

// Cancelling does not stop the datagram; it stops the caller waiting for it.
template <typename Bytes>
  requires owned_byte_range<Bytes>
udp_send_awaitable_t send_udp(udp_t &udp, Bytes &&bytes, const sockaddr *addr, cancellation_t *cancel = nullptr)
{
  using payload_t = std::remove_cvref_t<Bytes>;
  auto *op = new udp_send_op_t();
  op->socket = udp.handle;

  if (cancel != nullptr && cancel->is_cancelled())
  {
    op->completed = true;
    op->result = std::unexpected(error_t{.code = vio_cancelled, .msg = "cancelled"});
    return udp_send_awaitable_t(op);
  }

  auto owned = std::make_unique<owned_payload_impl_t<payload_t>>(std::forward<Bytes>(bytes));
  uv_buf_t buf = uv_buf_init(reinterpret_cast<char *>(const_cast<char *>(reinterpret_cast<const char *>(std::ranges::data(owned->value)))), static_cast<unsigned int>(std::ranges::size(owned->value)));
  op->payload = std::move(owned);
  op->req.data = op;

  if (const int r = uv_udp_send(&op->req, udp.get_udp(), &buf, 1, addr, &detail::udp_send_cb); r < 0)
  {
    op->completed = true;
    op->result = std::unexpected(error_t{.code = r, .msg = uv_strerror(r)});
    return udp_send_awaitable_t(op);
  }

  if (cancel != nullptr)
  {
    op->cancel_registration = cancel->register_callback(
      [op]()
      {
        if (op->completed || op->detached)
        {
          return;
        }
        op->result = std::unexpected(error_t{.code = vio_cancelled, .msg = "cancelled"});
        op->detached = true;
        if (op->continuation)
        {
          auto continuation = op->continuation;
          op->continuation = {};
          continuation.resume();
        }
      });
  }

  return udp_send_awaitable_t(op);
}

// Synchronous send. Unlike send_udp above there is no request object, no completion
// callback and no reference parked for the duration, so any number of these
// may be issued back to back -- which is what a server talking to many peers
// from one socket needs, and what send_udp explicitly refuses.
//
// A full socket buffer surfaces as an error with code UV_EAGAIN; that is the
// caller's signal to stop draining and retry later, not a failure.
inline std::expected<std::size_t, error_t> udp_try_send(udp_t &udp, std::span<const uint8_t> bytes, const sockaddr *addr)
{
  uv_buf_t buf = uv_buf_init(reinterpret_cast<char *>(const_cast<uint8_t *>(bytes.data())), static_cast<unsigned int>(bytes.size()));
  const int r = uv_udp_try_send(udp.get_udp(), &buf, 1, addr);
  if (r < 0)
  {
    return std::unexpected(error_t{.code = r, .msg = uv_strerror(r)});
  }
  return static_cast<std::size_t>(r);
}

struct udp_out_datagram_t
{
  std::span<const uint8_t> bytes;
  const sockaddr *addr = nullptr;
};

inline constexpr std::size_t udp_max_batch_size = 64;

// Sends up to udp_max_batch_size datagrams in one call, mapping to sendmmsg
// where the platform has it. Returns how many were accepted, which may be
// fewer than requested; the caller resumes from that offset.
inline std::expected<unsigned int, error_t> udp_try_send_batch(udp_t &udp, std::span<const udp_out_datagram_t> datagrams)
{
  if (datagrams.empty())
  {
    return 0u;
  }
  const unsigned int count = static_cast<unsigned int>(datagrams.size() < udp_max_batch_size ? datagrams.size() : udp_max_batch_size);

  std::array<uv_buf_t, udp_max_batch_size> storage = {};
  std::array<uv_buf_t *, udp_max_batch_size> bufs = {};
  std::array<unsigned int, udp_max_batch_size> nbufs = {};
  std::array<struct sockaddr *, udp_max_batch_size> addrs = {};

  for (unsigned int i = 0; i < count; ++i)
  {
    storage[i] = uv_buf_init(reinterpret_cast<char *>(const_cast<uint8_t *>(datagrams[i].bytes.data())), static_cast<unsigned int>(datagrams[i].bytes.size()));
    bufs[i] = &storage[i];
    nbufs[i] = 1;
    addrs[i] = const_cast<struct sockaddr *>(datagrams[i].addr);
  }

  const int r = uv_udp_try_send2(udp.get_udp(), count, bufs.data(), nbufs.data(), addrs.data(), 0);
  if (r < 0)
  {
    return std::unexpected(error_t{.code = r, .msg = uv_strerror(r)});
  }
  return static_cast<unsigned int>(r);
}

inline std::expected<uv_os_fd_t, error_t> udp_fileno(udp_t &udp)
{
  uv_os_fd_t fd = {};
  const int r = uv_fileno(udp.get_handle(), &fd);
  if (r < 0)
  {
    return std::unexpected(error_t{.code = r, .msg = uv_strerror(r)});
  }
  return fd;
}

// Binds one socket that accepts both IPv6 and IPv4-mapped peers. libuv clears
// IPV6_V6ONLY when UV_UDP_IPV6ONLY is absent, so binding [::] is enough; hosts
// without IPv6 fall back to 0.0.0.0.
inline std::expected<void, error_t> udp_bind_dual_stack(udp_t &udp, std::uint16_t port)
{
  sockaddr_in6 addr6 = {};
  if (const int r = uv_ip6_addr("::", static_cast<int>(port), &addr6); r == 0)
  {
    if (const int bound = uv_udp_bind(udp.get_udp(), reinterpret_cast<const sockaddr *>(&addr6), 0); bound == 0)
    {
      return {};
    }
  }

  sockaddr_in addr4 = {};
  if (const int r = uv_ip4_addr("0.0.0.0", static_cast<int>(port), &addr4); r < 0)
  {
    return std::unexpected(error_t{.code = r, .msg = uv_strerror(r)});
  }
  if (const int r = uv_udp_bind(udp.get_udp(), reinterpret_cast<const sockaddr *>(&addr4), 0); r < 0)
  {
    return std::unexpected(error_t{.code = r, .msg = uv_strerror(r)});
  }
  return {};
}

// Must be called before udp_create_reader: the reader allocates through these
// on every datagram, and the default allocator takes a fresh 64 KiB block for
// what is usually a ~1200 byte packet.
inline void udp_set_allocator(udp_t &udp, alloc_cb_t alloc, dealloc_cb_t dealloc, void *user_data)
{
  udp.handle->recv.alloc_buffer_cb = alloc;
  udp.handle->recv.dealloc_buffer_cb = dealloc;
  udp.handle->recv.alloc_cb_data = user_data;
}

// The pool must outlive the socket: every datagram still in the receive queue
// holds a pointer to it as its deallocator's user handle.
inline void udp_use_buffer_pool(udp_t &udp, buffer_pool_t &pool)
{
  udp_set_allocator(udp, &buffer_pool_t::alloc_cb, &buffer_pool_t::dealloc_cb, &pool);
}

inline void udp_set_recv_queue_limit(udp_t &udp, std::size_t datagrams)
{
  udp.handle->recv.recv_queue_limit = datagrams == 0 ? 1 : datagrams;
}

struct udp_recv_stats_t
{
  std::size_t queued = 0;
  std::uint64_t dropped_datagrams = 0;
  std::uint64_t truncated_datagrams = 0;
  std::uint64_t recv_errors = 0;
};

// Drops and errors are silent by design -- neither should tear a socket down --
// so this is the only way to notice them.
inline udp_recv_stats_t udp_recv_stats(udp_t &udp)
{
  return udp_recv_stats_t{.queued = udp.handle->recv.buffer_queue.size(),
                          .dropped_datagrams = udp.handle->recv.dropped_datagrams,
                          .truncated_datagrams = udp.handle->recv.truncated_datagrams,
                          .recv_errors = udp.handle->recv.recv_errors};
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

    // Stop uv from delivering (and allocating buffers for) more datagrams after
    // the reader is cancelled. Mirrors the destructor so its started guard won't
    // reclaim the parked ref a second time.
    if (handle->recv.started)
    {
      auto state = ref_ptr_t<udp_state_t>::from_raw(handle->get_udp()->data);
      uv_udp_recv_stop(handle->get_udp());
      state->recv.started = false;
      state->recv.active = false;
    }

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
      state->recv.buffer_queue.pop_front();
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

  static void alloc_cb(uv_handle_t *h, size_t size, uv_buf_t *buf)
  {
    auto udp_state = ref_ptr_t<udp_state_t>::from_raw(h->data);
    udp_state->recv.alloc_buffer_cb(udp_state->recv.alloc_cb_data, size, buf);
    udp_state.release_to_raw();
  }

  // Under recvmmsg libuv fills one allocation with several datagrams and hands
  // each out as a slice tagged UV_UDP_MMSG_CHUNK, then asks for the whole
  // allocation back once with UV_UDP_MMSG_FREE. A slice must therefore never
  // be adopted by a unique_buf_t -- N datagrams would each free the same
  // block. Slices are copied into a buffer of their own; the copy comes from
  // the same allocator, so a pooled socket still does not reach the heap.
  static void recv_cb(uv_udp_t *udp_handle, ssize_t nread, const uv_buf_t *buf, const sockaddr *addr, unsigned int flags)
  {
    auto udp_state = ref_ptr_t<udp_state_t>::from_raw(udp_handle->data);
    ref_ptr_releaser_t releaser(udp_state);

    const bool is_chunk = (flags & UV_UDP_MMSG_CHUNK) != 0;
    const bool owns_buffer = !is_chunk;

    auto release_buffer = [&]()
    {
      if (owns_buffer && buf != nullptr && buf->base != nullptr)
      {
        udp_state->recv.dealloc_buffer_cb(udp_state->recv.alloc_cb_data, const_cast<uv_buf_t *>(buf));
      }
    };

    if ((flags & UV_UDP_MMSG_FREE) != 0)
    {
      if (buf != nullptr && buf->base != nullptr)
      {
        udp_state->recv.dealloc_buffer_cb(udp_state->recv.alloc_cb_data, const_cast<uv_buf_t *>(buf));
      }
      return;
    }

    if (nread == 0 && addr == nullptr)
    {
      release_buffer();
      return;
    }

    if (nread > 0)
    {
      // A truncated datagram is not a short datagram; the remainder is gone.
      // Handing back a prefix would have the caller parse garbage.
      if ((flags & UV_UDP_PARTIAL) != 0)
      {
        ++udp_state->recv.truncated_datagrams;
        release_buffer();
        return;
      }

      if (udp_state->recv.buffer_queue.size() >= udp_state->recv.recv_queue_limit)
      {
        ++udp_state->recv.dropped_datagrams;
        release_buffer();
        return;
      }

      udp_datagram_t datagram;
      if (is_chunk)
      {
        uv_buf_t copy = {};
        udp_state->recv.alloc_buffer_cb(udp_state->recv.alloc_cb_data, static_cast<size_t>(nread), &copy);
        if (copy.base == nullptr || copy.len < static_cast<decltype(copy.len)>(nread))
        {
          ++udp_state->recv.dropped_datagrams;
          if (copy.base != nullptr)
          {
            udp_state->recv.dealloc_buffer_cb(udp_state->recv.alloc_cb_data, &copy);
          }
          return;
        }
        std::memcpy(copy.base, buf->base, static_cast<size_t>(nread));
        copy.len = static_cast<decltype(copy.len)>(nread);
        datagram.data = unique_buf_t(copy, udp_state->recv.dealloc_buffer_cb, udp_state->recv.alloc_cb_data);
      }
      else
      {
        uv_buf_t sized_buf = *buf;
        sized_buf.len = static_cast<decltype(sized_buf.len)>(nread);
        datagram.data = unique_buf_t(sized_buf, udp_state->recv.dealloc_buffer_cb, udp_state->recv.alloc_cb_data);
      }

      if (addr != nullptr)
      {
        std::memcpy(&datagram.sender_addr, addr, addr->sa_family == AF_INET6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in));
      }
      udp_state->recv.buffer_queue.emplace_back(std::move(datagram));
    }
    else
    {
      // One peer must not be able to kill the socket. libuv stops the read
      // before reporting a real error, so recovery means restarting it; the
      // error is counted, not delivered. Only a failed restart is terminal,
      // and that leaves recv.started alone so the destructor still reclaims
      // the reference parked in the handle.
      ++udp_state->recv.recv_errors;
      if (buf != nullptr && buf->base != nullptr)
      {
        udp_state->recv.dealloc_buffer_cb(udp_state->recv.alloc_cb_data, const_cast<uv_buf_t *>(buf));
      }

      if (udp_state->recv.is_cancelled || !udp_state->recv.started)
      {
        return;
      }

      const int restarted = uv_udp_recv_start(udp_handle, udp_reader_t::alloc_cb, &udp_reader_t::recv_cb);
      if (restarted >= 0 || restarted == UV_EALREADY)
      {
        return;
      }
      udp_state->recv.buffer_queue.emplace_back(std::unexpected(error_t{.code = restarted, .msg = uv_strerror(restarted)}));
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

// Drains what has already arrived without suspending, so a read loop can take
// a whole batch per wake-up instead of one datagram per resume. Returns how
// many entries were written; zero means nothing is queued and the caller
// should co_await the reader.
inline std::size_t udp_reader_take_batch(udp_reader_t &reader, std::span<std::expected<udp_datagram_t, error_t>> out)
{
  auto &queue = reader.handle->recv.buffer_queue;
  std::size_t taken = 0;
  while (taken < out.size() && !queue.empty())
  {
    out[taken] = std::move(queue.front());
    queue.pop_front();
    ++taken;
  }
  return taken;
}

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

  // Fail here rather than let the socket go quiet: ask the allocator for what
  // libuv is about to ask for, and refuse if it cannot cover a single chunk.
  if (uv_udp_using_recvmmsg(udp.get_udp()) != 0)
  {
    uv_buf_t probe = {};
    udp.handle->recv.alloc_buffer_cb(udp.handle->recv.alloc_cb_data, udp_recvmmsg_chunk_size, &probe);
    const std::size_t offered = probe.base == nullptr ? 0 : static_cast<std::size_t>(probe.len);
    if (probe.base != nullptr)
    {
      udp.handle->recv.dealloc_buffer_cb(udp.handle->recv.alloc_cb_data, &probe);
    }
    if (offered < udp_recvmmsg_chunk_size)
    {
      return std::unexpected(error_t{.code = UV_ENOBUFS,
                                     .msg = "recvmmsg needs an allocator that yields at least " + std::to_string(udp_recvmmsg_chunk_size) + " bytes per buffer, but it offered " + std::to_string(offered) +
                                            "; size the buffer pool to a multiple of the chunk size or create the socket without recvmmsg"});
    }
  }

  auto copy = udp.handle;
  udp.get_udp()->data = copy.release_to_raw();
  if (const auto r = uv_udp_recv_start(udp.get_udp(), &udp_reader_t::alloc_cb, &udp_reader_t::recv_cb); r >= 0)
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
