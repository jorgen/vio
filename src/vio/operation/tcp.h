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
#include "vio/detail/sys.h"
#include "vio/errc.h"
#include "vio/error.h"
#include "vio/event_loop.h"
#include "vio/future.h"
#include "vio/loop/socket.h"
#include "vio/owned_payload.h"
#include "vio/unique_buf.h"

#include <algorithm>
#include <array>
#include <coroutine>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <expected>
#include <memory>
#include <ranges>
#include <span>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#if !defined(_WIN32)
#include <net/if.h>
#endif

namespace vio
{
struct tcp_state_t;
struct tcp_connect_future_t;
struct tcp_write_future_t;
struct tcp_listen_future_t;

inline constexpr std::size_t tcp_read_buffer_size = 65536;
inline constexpr std::int64_t tcp_teardown_linger_ns = 10'000'000'000;

namespace detail
{
inline void tcp_on_read_ready(io_op_t *op);
inline void tcp_on_read_kick(posted_t *node);
inline void tcp_on_read_kick_discard(posted_t *node);
inline void tcp_on_write_ready(io_op_t *op);
inline void tcp_on_connect_ready(io_op_t *op);
inline void tcp_on_linger(timer_node_t *node);
inline void tcp_shutdown(tcp_state_t &state) noexcept;
inline void tcp_begin_teardown(tcp_state_t &state);

inline int tcp_address_length(const sockaddr *address) noexcept
{
  if (address == nullptr)
    return 0;
  if (address->sa_family == AF_INET)
    return static_cast<int>(sizeof(sockaddr_in));
  if (address->sa_family == AF_INET6)
    return static_cast<int>(sizeof(sockaddr_in6));
  return 0;
}

inline error_t tcp_cancelled_error()
{
  return error_t{.code = vio_cancelled, .msg = "cancelled"};
}
} // namespace detail

struct tcp_read_waiter_t
{
  virtual bool attempt(tcp_state_t &state) = 0;
  virtual void fail(int code) = 0;

  std::coroutine_handle<> continuation = {};
  bool into = false;

protected:
  tcp_read_waiter_t() = default;
  tcp_read_waiter_t(const tcp_read_waiter_t &) = default;
  tcp_read_waiter_t &operator=(const tcp_read_waiter_t &) = default;
  ~tcp_read_waiter_t() = default;
};

struct tcp_read_state_t
{
  detail::io_op_t op;
  detail::posted_t kick;
  tcp_read_waiter_t *waiter = nullptr;
  alloc_cb_t alloc_buffer_cb = default_alloc;
  dealloc_cb_t dealloc_buffer_cb = default_dealloc;
  void *alloc_cb_data = nullptr;
  std::uint64_t generation = 0;
  std::uint32_t drained_epoch = 0;
  int pending = 0;
  bool drained = false;
  bool active = false;
  bool started = false;
  bool paused = false;
  bool is_cancelled = false;
};

struct tcp_write_entry_t
{
  const std::byte *data = nullptr;
  std::size_t size = 0;
  std::unique_ptr<owned_payload_t> owned;
  tcp_write_future_t *waiter = nullptr;
  std::uint64_t id = 0;
  bool started = false;
};

struct tcp_write_state_t
{
  detail::io_op_t op;
  std::vector<tcp_write_entry_t> entries;
  std::size_t head = 0;
  std::size_t count = 0;
  std::size_t queued_bytes = 0;
  std::uint64_t next_id = 1;
  std::uint64_t failed_from = 0;
  int error = 0;

  [[nodiscard]] std::uint64_t front_id() const noexcept
  {
    return count > 0 ? entries[head].id : next_id;
  }

  [[nodiscard]] tcp_write_entry_t &at(std::size_t index) noexcept
  {
    return entries[(head + index) % entries.size()];
  }

  [[nodiscard]] tcp_write_entry_t &front() noexcept
  {
    return entries[head];
  }

  [[nodiscard]] tcp_write_entry_t *find(std::uint64_t id) noexcept
  {
    if (count == 0 || id < entries[head].id)
      return nullptr;
    auto offset = id - entries[head].id;
    if (offset >= count)
      return nullptr;
    return &at(static_cast<std::size_t>(offset));
  }

  tcp_write_entry_t &push()
  {
    if (count == entries.size())
    {
      std::vector<tcp_write_entry_t> grown((std::max)(std::size_t{8}, entries.size() * 2));
      for (std::size_t i = 0; i < count; ++i)
        grown[i] = std::move(at(i));
      entries.swap(grown);
      head = 0;
    }
    auto &entry = entries[(head + count) % entries.size()];
    ++count;
    entry.id = next_id++;
    return entry;
  }

  void pop() noexcept
  {
    entries[head] = tcp_write_entry_t{};
    head = (head + 1) % entries.size();
    if (--count == 0)
      head = 0;
  }
};

struct tcp_connect_state_t
{
  detail::io_op_t op;
  tcp_connect_future_t *waiter = nullptr;
  int result = 0;
  bool in_progress = false;
};

struct tcp_listen_state_t
{
  detail::io_op_t op;
  tcp_listen_future_t *head = nullptr;
  tcp_listen_future_t *tail = nullptr;
  std::vector<native_socket_t> accepted;
  std::size_t accepted_head = 0;
  std::size_t claimed = 0;
  bool listening = false;

  [[nodiscard]] std::size_t ready() const noexcept
  {
    return accepted.size() - accepted_head;
  }

  [[nodiscard]] std::size_t unclaimed() const noexcept
  {
    auto available = ready();
    return available > claimed ? available - claimed : 0;
  }

  native_socket_t take() noexcept
  {
    auto socket = accepted[accepted_head++];
    if (accepted_head == accepted.size())
    {
      accepted.clear();
      accepted_head = 0;
    }
    if (claimed > 0)
      --claimed;
    return socket;
  }
};

struct tcp_state_t
{
  explicit tcp_state_t(event_loop_t &loop)
    : event_loop(loop)
    , socket(detail::core(loop), "tcp")
  {
    read.op.owner = this;
    read.op.complete = &detail::tcp_on_read_ready;
    read.kick.run = &detail::tcp_on_read_kick;
    read.kick.discard = &detail::tcp_on_read_kick_discard;
    write.op.owner = this;
    write.op.complete = &detail::tcp_on_write_ready;
    connect.op.owner = this;
    connect.op.complete = &detail::tcp_on_connect_ready;
    listen.op.owner = this;
    linger.owner = this;
    linger.fire = &detail::tcp_on_linger;
  }

  tcp_state_t(const tcp_state_t &) = delete;
  tcp_state_t &operator=(const tcp_state_t &) = delete;
  tcp_state_t(tcp_state_t &&) = delete;
  tcp_state_t &operator=(tcp_state_t &&) = delete;

  ~tcp_state_t()
  {
    detail::tcp_shutdown(*this);
  }

  event_loop_t &event_loop;
  detail::socket_resource_t socket;
  tcp_listen_state_t listen;
  tcp_connect_state_t connect;
  tcp_write_state_t write;
  tcp_read_state_t read;
  detail::timer_node_t linger;
  void *storage = nullptr;
  int bind_error = 0;
  bool connected = false;
  bool closed = false;
  bool lingering = false;
};

namespace detail
{
inline void tcp_shutdown(tcp_state_t &state) noexcept
{
  state.closed = true;
  state.lingering = false;
  if (state.linger.armed())
    state.socket.loop().remove_timer(state.linger);
  for (auto *op : {&state.read.op, &state.write.op, &state.connect.op, &state.listen.op})
  {
    if (op->parked)
      state.socket.cancel(*op);
  }
  state.read.waiter = nullptr;
  state.connect.waiter = nullptr;
  state.connect.in_progress = false;
  while (state.write.count > 0)
    state.write.pop();
  state.write.queued_bytes = 0;
  while (state.listen.ready() > 0)
    socket_close(state.listen.take());
  state.listen.claimed = 0;
}

inline ref_ptr_t<tcp_state_t> tcp_state_ref(tcp_state_t &state)
{
  auto adopted = ref_ptr_t<tcp_state_t>::from_raw(state.storage);
  auto strong = adopted;
  adopted.release_to_raw();
  return strong;
}

inline void tcp_discard_inbound(tcp_state_t &state) noexcept
{
  if (!state.socket.is_open())
    return;
  std::array<std::byte, 4096> scratch;
  for (int i = 0; i < 64; ++i)
  {
    if (socket_recv(state.socket.native(), scratch) <= 0)
      return;
  }
}

inline void tcp_end_linger(tcp_state_t &state) noexcept
{
  if (!state.lingering)
    return;
  tcp_discard_inbound(state);
  tcp_shutdown(state);
  auto released = ref_ptr_t<tcp_state_t>::from_raw(state.storage);
}

inline void tcp_on_linger(timer_node_t *node)
{
  tcp_end_linger(*static_cast<tcp_state_t *>(node->owner));
}
} // namespace detail

struct tcp_t
{
  ref_ptr_t<tcp_state_t> handle;
};

inline std::expected<sockaddr_in, error_t> ip4_addr(const std::string &ip, int port)
{
#if defined(_WIN32)
  detail::ensure_winsock();
#endif
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_port = htons(static_cast<std::uint16_t>(port));
  if (inet_pton(AF_INET, ip.c_str(), &address.sin_addr) != 1)
    return std::unexpected(make_error(errc::invalid_argument));
  return address;
}

inline std::expected<sockaddr_in6, error_t> ip6_addr(const std::string &ip, int port)
{
#if defined(_WIN32)
  detail::ensure_winsock();
#endif
  sockaddr_in6 address{};
  address.sin6_family = AF_INET6;
  address.sin6_port = htons(static_cast<std::uint16_t>(port));
  auto zone = ip.find('%');
  std::string host = ip.substr(0, zone);
  if (zone != std::string::npos)
  {
    std::string name = ip.substr(zone + 1);
    unsigned long index = 0;
#if !defined(_WIN32)
    index = if_nametoindex(name.c_str());
#endif
    if (index == 0)
      index = std::strtoul(name.c_str(), nullptr, 10);
    address.sin6_scope_id = static_cast<decltype(address.sin6_scope_id)>(index);
  }
  if (inet_pton(AF_INET6, host.c_str(), &address.sin6_addr) != 1)
    return std::unexpected(make_error(errc::invalid_argument));
  return address;
}

inline std::string peer_ip(tcp_t &tcp)
{
  if (!tcp.handle || !tcp.handle->socket.is_open())
    return {};
  sockaddr_storage storage{};
  int length = static_cast<int>(sizeof(storage));
  if (detail::socket_peer_name(tcp.handle->socket.native(), storage, length) != 0)
    return {};
  char buffer[64] = {};
  if (storage.ss_family == AF_INET)
    inet_ntop(AF_INET, &reinterpret_cast<const sockaddr_in *>(&storage)->sin_addr, buffer, sizeof(buffer));
  else if (storage.ss_family == AF_INET6)
    inet_ntop(AF_INET6, &reinterpret_cast<const sockaddr_in6 *>(&storage)->sin6_addr, buffer, sizeof(buffer));
  return std::string(buffer);
}

inline std::expected<sockaddr_storage, error_t> sockname(tcp_t &tcp)
{
  if (!tcp.handle || !tcp.handle->socket.is_open())
    return std::unexpected(make_error(errc::bad_descriptor));
  sockaddr_storage storage{};
  int length = static_cast<int>(sizeof(storage));
  if (int result = detail::socket_name(tcp.handle->socket.native(), storage, length); result < 0)
    return std::unexpected(make_error(result));
  return storage;
}

inline std::expected<tcp_t, error_t> tcp_create(event_loop_t &loop)
{
  tcp_t tcp{ref_ptr_t<tcp_state_t>(loop)};
  auto &state = tcp.handle.data();
  tcp.handle.register_resource(state.socket);
  {
    auto parked = tcp.handle;
    state.storage = parked.release_to_raw();
    auto balance = ref_ptr_t<tcp_state_t>::from_raw(state.storage);
  }
  tcp.handle.on_destroy([raw = &state] { detail::tcp_begin_teardown(*raw); });
  return tcp;
}

inline std::size_t tcp_write_queue_size(tcp_t &tcp) noexcept
{
  return tcp.handle ? tcp.handle->write.queued_bytes : 0;
}

struct tcp_connect_future_t
{
  tcp_connect_future_t(ref_ptr_t<tcp_state_t> handle, cancellation_t *cancel) noexcept
    : handle(std::move(handle))
    , cancel(cancel)
  {
  }

  tcp_connect_future_t(tcp_connect_future_t &&other) noexcept
    : handle(std::move(other.handle))
    , cancel(other.cancel)
    , result(std::move(other.result))
    , done(other.done)
  {
  }

  tcp_connect_future_t(const tcp_connect_future_t &) = delete;
  tcp_connect_future_t &operator=(const tcp_connect_future_t &) = delete;
  tcp_connect_future_t &operator=(tcp_connect_future_t &&) = delete;

  ~tcp_connect_future_t()
  {
    if (handle && handle->connect.waiter == this)
      handle->connect.waiter = nullptr;
  }

  [[nodiscard]] bool await_ready() noexcept;
  void await_suspend(std::coroutine_handle<> handle_to_resume) noexcept;
  std::expected<void, error_t> await_resume() noexcept
  {
    cancel_registration.reset();
    return std::move(result);
  }

  void finish(int code)
  {
    done = true;
    if (code != 0)
      result = std::unexpected(make_error(code));
  }

  ref_ptr_t<tcp_state_t> handle;
  cancellation_t *cancel = nullptr;
  registration_t cancel_registration;
  std::coroutine_handle<> continuation = {};
  std::expected<void, error_t> result = {};
  bool done = false;

private:
  void on_cancel();
};

namespace detail
{
inline void tcp_read_kick(tcp_state_t &state);

inline void tcp_read_rearm(tcp_state_t &state)
{
  auto &read = state.read;
  if (read.waiter == nullptr || !read.op.parked)
    return;
  state.socket.cancel(read.op);
  tcp_read_kick(state);
}

inline void tcp_connect_abandon(tcp_state_t &state) noexcept
{
  auto &connect = state.connect;
  if (connect.op.parked)
    state.socket.cancel(connect.op);
  connect.in_progress = false;
  connect.result = errc::canceled;
  connect.waiter = nullptr;
}

inline void tcp_on_connect_ready(io_op_t *op)
{
  auto &state = *static_cast<tcp_state_t *>(op->owner);
  auto socket = state.socket.native();
  int code = socket_pending_error(socket);
  if (code == 0)
  {
    sockaddr_storage peer{};
    int length = static_cast<int>(sizeof(peer));
    if (socket_peer_name(socket, peer, length) == errc::not_connected)
    {
      state.socket.wait(interest_write, state.connect.op);
      return;
    }
  }
  state.connect.in_progress = false;
  state.connect.result = code;
  state.connected = code == 0;
  tcp_read_rearm(state);
  auto *waiter = state.connect.waiter;
  if (waiter == nullptr)
    return;
  state.connect.waiter = nullptr;
  waiter->finish(code);
  waiter->cancel_registration.reset();
  waiter->continuation.resume();
}
} // namespace detail

inline bool tcp_connect_future_t::await_ready() noexcept
{
  if (cancel && cancel->is_cancelled())
  {
    if (!done)
      detail::tcp_connect_abandon(handle.data());
    done = true;
    result = std::unexpected(detail::tcp_cancelled_error());
    return true;
  }
  if (done)
    return true;
  if (!handle->connect.in_progress)
  {
    finish(handle->connect.result);
    return true;
  }
  return false;
}

inline void tcp_connect_future_t::await_suspend(std::coroutine_handle<> handle_to_resume) noexcept
{
  continuation = handle_to_resume;
  handle->connect.waiter = this;
  if (cancel)
    cancel_registration = cancel->register_callback([this] { on_cancel(); });
}

inline void tcp_connect_future_t::on_cancel()
{
  if (done)
    return;
  detail::tcp_connect_abandon(handle.data());
  done = true;
  result = std::unexpected(detail::tcp_cancelled_error());
  cancel_registration.reset();
  continuation.resume();
}

inline tcp_connect_future_t tcp_connect(tcp_t &tcp, const sockaddr *addr, cancellation_t *cancel = nullptr)
{
  tcp_connect_future_t ret(tcp.handle, cancel);
  if (!ret.handle)
  {
    ret.done = true;
    ret.result = std::unexpected(error_t{.code = errc::bad_descriptor, .msg = "It's not possible to connect a closed socket"});
    return ret;
  }
  if (cancel && cancel->is_cancelled())
  {
    ret.done = true;
    ret.result = std::unexpected(detail::tcp_cancelled_error());
    return ret;
  }
  auto &state = ret.handle.data();
  if (state.connect.in_progress)
  {
    ret.done = true;
    ret.result = std::unexpected(error_t{.code = errc::already_in_progress, .msg = "A connect is already in progress on this socket"});
    return ret;
  }
  int length = detail::tcp_address_length(addr);
  if (length == 0)
  {
    ret.finish(errc::invalid_argument);
    return ret;
  }
  if (!state.socket.is_open())
  {
    if (int result = state.socket.open(addr->sa_family, SOCK_STREAM, IPPROTO_TCP); result < 0)
    {
      ret.finish(result);
      return ret;
    }
  }
  int result = detail::socket_connect(state.socket.native(), addr, length);
  if (result == 0)
  {
    state.connected = true;
    ret.done = true;
    return ret;
  }
  if (result != errc::in_progress && result != errc::again)
  {
    ret.finish(result);
    return ret;
  }
  state.connect.in_progress = true;
  state.connect.result = 0;
  state.socket.wait(detail::interest_write, state.connect.op);
  return ret;
}

struct tcp_write_future_t
{
  tcp_write_future_t(ref_ptr_t<tcp_state_t> handle, cancellation_t *cancel) noexcept
    : handle(std::move(handle))
    , cancel(cancel)
  {
  }

  tcp_write_future_t(tcp_write_future_t &&other) noexcept
    : handle(std::move(other.handle))
    , cancel(other.cancel)
    , result(std::move(other.result))
    , id(std::exchange(other.id, 0))
    , done(other.done)
  {
  }

  tcp_write_future_t(const tcp_write_future_t &) = delete;
  tcp_write_future_t &operator=(const tcp_write_future_t &) = delete;
  tcp_write_future_t &operator=(tcp_write_future_t &&) = delete;

  ~tcp_write_future_t();

  [[nodiscard]] bool await_ready() noexcept;
  void await_suspend(std::coroutine_handle<> handle_to_resume) noexcept;
  std::expected<void, error_t> await_resume() noexcept
  {
    cancel_registration.reset();
    return std::move(result);
  }

  ref_ptr_t<tcp_state_t> handle;
  cancellation_t *cancel = nullptr;
  registration_t cancel_registration;
  std::coroutine_handle<> continuation = {};
  std::expected<void, error_t> result = {};
  std::uint64_t id = 0;
  bool done = false;

private:
  void on_cancel();
};

namespace detail
{
inline void tcp_write_resolve(tcp_write_future_t &waiter, int code)
{
  waiter.id = 0;
  waiter.done = true;
  if (code != 0)
    waiter.result = std::unexpected(make_error(code));
  waiter.cancel_registration.reset();
  waiter.continuation.resume();
}

inline void tcp_write_fail(tcp_state_t &state, int code)
{
  auto &write = state.write;
  if (write.error == 0)
  {
    write.error = code;
    write.failed_from = write.front_id();
  }
  while (write.count > 0 && !state.closed)
  {
    auto *waiter = write.front().waiter;
    write.queued_bytes -= write.front().size;
    write.pop();
    if (waiter)
      tcp_write_resolve(*waiter, code);
  }
  if (write.op.parked)
    state.socket.cancel(write.op);
  tcp_end_linger(state);
}

inline void tcp_write_trim(tcp_state_t &state) noexcept
{
  auto &write = state.write;
  while (write.count > 0 && write.front().size == 0 && write.front().waiter == nullptr)
    write.pop();
  if (write.count == 0 && write.op.parked)
    state.socket.cancel(write.op);
}

inline void tcp_write_abandon(tcp_state_t &state, std::uint64_t id, bool cancelled)
{
  auto &write = state.write;
  auto *entry = write.find(id);
  if (entry == nullptr)
    return;
  entry->waiter = nullptr;
  if (cancelled && !entry->started)
  {
    write.queued_bytes -= entry->size;
    entry->size = 0;
    entry->data = nullptr;
    entry->owned.reset();
    tcp_write_trim(state);
    return;
  }
  if (!entry->owned && entry->size > 0)
  {
    auto holder = std::make_unique<owned_payload_impl_t<std::vector<std::byte>>>(std::vector<std::byte>(entry->data, entry->data + entry->size));
    entry->data = holder->value.data();
    entry->owned = std::move(holder);
  }
}

inline void tcp_write_advance(tcp_write_state_t &write, std::size_t sent) noexcept
{
  for (std::size_t i = 0; sent > 0 && i < write.count; ++i)
  {
    auto &entry = write.at(i);
    auto take = (std::min)(entry.size, sent);
    if (take == 0)
      continue;
    entry.data += take;
    entry.size -= take;
    entry.started = true;
    write.queued_bytes -= take;
    sent -= take;
  }
}

inline void tcp_write_drain(tcp_state_t &state)
{
  auto keep = tcp_state_ref(state);
  auto &write = state.write;
  while (!state.closed)
  {
    if (write.count > 0 && write.front().size == 0)
    {
      auto *waiter = write.front().waiter;
      write.pop();
      if (waiter)
        tcp_write_resolve(*waiter, 0);
      continue;
    }
    if (write.count == 0)
    {
      if (write.op.parked)
        state.socket.cancel(write.op);
      tcp_end_linger(state);
      return;
    }
    if (state.connect.in_progress)
    {
      if (!write.op.parked)
        state.socket.wait(interest_write, write.op);
      return;
    }
    std::array<const_bytes_t, 16> buffers;
    std::size_t used = 0;
    for (std::size_t i = 0; i < write.count && used < buffers.size(); ++i)
    {
      auto &entry = write.at(i);
      if (entry.size > 0)
        buffers[used++] = const_bytes_t(entry.data, entry.size);
    }
    auto sent = used == 1 ? socket_send(state.socket.native(), buffers[0]) : socket_sendv(state.socket.native(), buffers.data(), used);
    if (sent == errc::again || sent == 0)
    {
      if (!write.op.parked)
        state.socket.wait(interest_write, write.op);
      return;
    }
    if (sent < 0)
    {
      tcp_write_fail(state, static_cast<int>(sent));
      return;
    }
    tcp_write_advance(write, static_cast<std::size_t>(sent));
  }
}

inline void tcp_on_write_ready(io_op_t *op)
{
  tcp_write_drain(*static_cast<tcp_state_t *>(op->owner));
}

inline void tcp_begin_teardown(tcp_state_t &state)
{
  if (state.closed || state.lingering)
    return;
  tcp_write_trim(state);
  auto &write = state.write;
  if (write.count == 0 || write.error != 0 || !state.socket.is_open() || (!state.connected && !state.connect.in_progress))
  {
    tcp_shutdown(state);
    return;
  }
  if (state.read.op.parked)
    state.socket.cancel(state.read.op);
  state.read.waiter = nullptr;
  state.lingering = true;
  tcp_state_ref(state).release_to_raw();
  state.socket.loop().add_timer(state.linger, loop_core_t::deadline_after(tcp_teardown_linger_ns));
  if (!write.op.parked)
    tcp_write_drain(state);
}

inline bool tcp_write_begin(tcp_write_future_t &ret, std::size_t length)
{
  if (!ret.handle)
  {
    ret.done = true;
    ret.result = std::unexpected(error_t{.code = errc::bad_descriptor, .msg = "It's not possible to write to a closed socket"});
    return false;
  }
  if (ret.cancel && ret.cancel->is_cancelled())
  {
    ret.done = true;
    ret.result = std::unexpected(tcp_cancelled_error());
    return false;
  }
  auto &state = ret.handle.data();
  if (state.write.error != 0)
  {
    ret.done = true;
    ret.result = std::unexpected(make_error(state.write.error));
    return false;
  }
  if (!state.socket.is_open() || (!state.connected && !state.connect.in_progress))
  {
    ret.done = true;
    ret.result = std::unexpected(make_error(errc::not_connected));
    return false;
  }
  if (length == 0)
  {
    ret.done = true;
    return false;
  }
  return true;
}

inline std::size_t tcp_write_try(tcp_write_future_t &ret, std::span<const std::byte> data)
{
  auto &state = ret.handle.data();
  if (state.write.count > 0 || state.connect.in_progress)
    return 0;
  std::size_t sent = 0;
  while (sent < data.size())
  {
    auto result = socket_send(state.socket.native(), data.subspan(sent));
    if (result == errc::again || result == 0)
      break;
    if (result < 0)
    {
      tcp_write_fail(state, static_cast<int>(result));
      ret.done = true;
      ret.result = std::unexpected(make_error(static_cast<int>(result)));
      return sent;
    }
    sent += static_cast<std::size_t>(result);
  }
  if (sent == data.size())
    ret.done = true;
  return sent;
}

inline void tcp_write_enqueue(tcp_write_future_t &ret, std::span<const std::byte> rest, bool started, std::unique_ptr<owned_payload_t> owned)
{
  auto &state = ret.handle.data();
  auto &entry = state.write.push();
  entry.data = rest.data();
  entry.size = rest.size();
  entry.owned = std::move(owned);
  entry.started = started;
  state.write.queued_bytes += rest.size();
  ret.id = entry.id;
  if (!state.write.op.parked)
    state.socket.wait(interest_write, state.write.op);
}
} // namespace detail

inline tcp_write_future_t::~tcp_write_future_t()
{
  if (handle && id != 0)
    detail::tcp_write_abandon(handle.data(), id, false);
}

inline bool tcp_write_future_t::await_ready() noexcept
{
  if (cancel && cancel->is_cancelled())
  {
    if (id != 0)
      detail::tcp_write_abandon(handle.data(), id, true);
    id = 0;
    done = true;
    result = std::unexpected(detail::tcp_cancelled_error());
    return true;
  }
  if (done)
    return true;
  auto &write = handle->write;
  if (id < write.front_id())
  {
    done = true;
    if (write.error != 0 && id >= write.failed_from)
      result = std::unexpected(make_error(write.error));
    id = 0;
    return true;
  }
  return false;
}

inline void tcp_write_future_t::await_suspend(std::coroutine_handle<> handle_to_resume) noexcept
{
  continuation = handle_to_resume;
  if (auto *entry = handle->write.find(id))
    entry->waiter = this;
  if (cancel)
    cancel_registration = cancel->register_callback([this] { on_cancel(); });
}

inline void tcp_write_future_t::on_cancel()
{
  if (done)
    return;
  detail::tcp_write_abandon(handle.data(), id, true);
  id = 0;
  done = true;
  result = std::unexpected(detail::tcp_cancelled_error());
  cancel_registration.reset();
  continuation.resume();
}

inline tcp_write_future_t write_tcp(tcp_t &tcp, std::span<const std::byte> data, cancellation_t *cancel = nullptr)
{
  tcp_write_future_t ret(tcp.handle, cancel);
  if (!detail::tcp_write_begin(ret, data.size()))
    return ret;
  auto sent = detail::tcp_write_try(ret, data);
  if (!ret.done)
    detail::tcp_write_enqueue(ret, data.subspan(sent), sent > 0, nullptr);
  return ret;
}

inline tcp_write_future_t write_tcp(tcp_t &tcp, const uint8_t *data, std::size_t length, cancellation_t *cancel = nullptr)
{
  return write_tcp(tcp, std::span<const std::byte>(reinterpret_cast<const std::byte *>(data), length), cancel);
}

template <typename Bytes>
  requires owned_byte_range<std::remove_cvref_t<Bytes>> && (!std::is_lvalue_reference_v<Bytes>) && (!std::is_const_v<std::remove_reference_t<Bytes>>)
tcp_write_future_t write_tcp(tcp_t &tcp, Bytes &&data, cancellation_t *cancel = nullptr)
{
  tcp_write_future_t ret(tcp.handle, cancel);
  auto view = std::as_bytes(std::span(std::ranges::data(data), std::ranges::size(data)));
  if (!detail::tcp_write_begin(ret, view.size()))
    return ret;
  auto sent = detail::tcp_write_try(ret, view);
  if (ret.done)
    return ret;
  auto holder = std::make_unique<owned_payload_impl_t<std::remove_cvref_t<Bytes>>>(std::forward<Bytes>(data));
  auto owned_view = std::as_bytes(std::span(std::ranges::data(holder->value), std::ranges::size(holder->value)));
  detail::tcp_write_enqueue(ret, owned_view.subspan(sent), sent > 0, std::move(holder));
  return ret;
}

namespace detail
{
inline bool tcp_read_try(tcp_state_t &state, tcp_read_waiter_t &waiter)
{
  if (state.connect.in_progress)
    return false;
  return waiter.attempt(state);
}

inline void tcp_read_park(tcp_state_t &state)
{
  if (!state.read.op.parked)
    state.socket.wait(interest_read, state.read.op);
}

inline void tcp_read_detach(ref_ptr_t<tcp_state_t> &state, tcp_read_waiter_t *waiter) noexcept
{
  if (!state || state->read.waiter != waiter)
    return;
  state->read.waiter = nullptr;
  if (state->read.op.parked)
    state->socket.cancel(state->read.op);
}

inline void tcp_read_progress(tcp_state_t &state)
{
  auto &read = state.read;
  auto *waiter = read.waiter;
  if (waiter == nullptr || read.op.parked || state.closed)
    return;
  if (read.is_cancelled || !read.active)
  {
    read.waiter = nullptr;
    waiter->fail(errc::canceled);
    waiter->continuation.resume();
    return;
  }
  if (read.paused && !waiter->into)
    return;
  if (!tcp_read_try(state, *waiter))
  {
    tcp_read_park(state);
    return;
  }
  read.waiter = nullptr;
  waiter->continuation.resume();
}

inline void tcp_on_read_ready(io_op_t *op)
{
  tcp_read_progress(*static_cast<tcp_state_t *>(op->owner));
}

inline void tcp_read_kick(tcp_state_t &state)
{
  auto &kick = state.read.kick;
  if (kick.queued || state.closed)
    return;
  auto strong = tcp_state_ref(state);
  if (!strong)
    return;
  kick.owner = strong.release_to_raw();
  state.socket.loop().defer(kick);
}

inline void tcp_on_read_kick(posted_t *node)
{
  auto state = ref_ptr_t<tcp_state_t>::from_raw(node->owner);
  node->owner = nullptr;
  tcp_read_progress(state.data());
}

inline void tcp_on_read_kick_discard(posted_t *node)
{
  auto state = ref_ptr_t<tcp_state_t>::from_raw(node->owner);
  node->owner = nullptr;
}
} // namespace detail

class tcp_reader_t
{
public:
  tcp_reader_t(const tcp_reader_t &) = delete;
  tcp_reader_t &operator=(const tcp_reader_t &) = delete;

  tcp_reader_t(tcp_reader_t &&other) noexcept
    : handle(std::move(other.handle))
    , _generation(other._generation)
    , _is_valid(std::exchange(other._is_valid, false))
  {
  }

  tcp_reader_t &operator=(tcp_reader_t &&other) noexcept
  {
    if (this != &other)
    {
      stop();
      handle = std::move(other.handle);
      _generation = other._generation;
      _is_valid = std::exchange(other._is_valid, false);
    }
    return *this;
  }

  ~tcp_reader_t()
  {
    stop();
  }

  void cancel()
  {
    if (!owns())
      return;
    auto &read = handle->read;
    if (read.is_cancelled)
      return;
    read.is_cancelled = true;
    read.started = false;
    read.active = false;
    if (read.op.parked)
      handle->socket.cancel(read.op);
    auto *waiter = read.waiter;
    if (waiter == nullptr)
      return;
    read.waiter = nullptr;
    waiter->fail(errc::canceled);
    waiter->continuation.resume();
  }

  [[nodiscard]] bool is_cancelled() const
  {
    return handle && (handle->read.is_cancelled || handle->read.generation != _generation);
  }

  struct awaiter_t final : tcp_read_waiter_t
  {
    awaiter_t(ref_ptr_t<tcp_state_t> state, std::uint64_t generation) noexcept
      : state(std::move(state))
      , generation(generation)
    {
    }

    awaiter_t(awaiter_t &&other) noexcept
      : tcp_read_waiter_t(other)
      , state(std::move(other.state))
      , generation(other.generation)
      , result(std::move(other.result))
    {
    }

    awaiter_t(const awaiter_t &) = delete;
    awaiter_t &operator=(const awaiter_t &) = delete;
    awaiter_t &operator=(awaiter_t &&) = delete;

    ~awaiter_t()
    {
      detail::tcp_read_detach(state, this);
    }

    [[nodiscard]] bool await_ready()
    {
      if (!state)
      {
        fail(errc::bad_descriptor);
        return true;
      }
      auto &read = state->read;
      if (read.is_cancelled || !read.active || read.generation != generation)
      {
        fail(errc::canceled);
        return true;
      }
      if (read.waiter != nullptr)
      {
        result = std::unexpected(error_t{.code = errc::already_in_progress, .msg = "A read is already pending on this socket"});
        return true;
      }
      if (read.paused)
        return false;
      return detail::tcp_read_try(state.data(), *this);
    }

    void await_suspend(std::coroutine_handle<> handle_to_resume)
    {
      continuation = handle_to_resume;
      state->read.waiter = this;
      if (!state->read.paused)
        detail::tcp_read_park(state.data());
    }

    std::expected<unique_buf_t, error_t> await_resume()
    {
      return std::move(result);
    }

    bool attempt(tcp_state_t &socket_state) override
    {
      auto &read = socket_state.read;
      if (read.pending != 0)
      {
        fail(std::exchange(read.pending, 0));
        return true;
      }
      auto epoch = socket_state.socket.watch.epoch;
      if (read.drained && read.drained_epoch == epoch)
        return false;
      read.drained = false;
      auto memory = read.alloc_buffer_cb(read.alloc_cb_data, tcp_read_buffer_size);
      if (memory.empty())
      {
        if (memory.data() != nullptr)
          read.dealloc_buffer_cb(read.alloc_cb_data, memory);
        fail(errc::no_buffer_space);
        return true;
      }
      unique_buf_t buffer(memory, read.dealloc_buffer_cb, read.alloc_cb_data);
      auto native = socket_state.socket.native();
      auto received = detail::socket_recv(native, memory);
      if (received == errc::again)
      {
        read.drained = true;
        read.drained_epoch = epoch;
        return false;
      }
      if (received <= 0)
      {
        fail(received == 0 ? errc::eof : static_cast<int>(received));
        return true;
      }
      auto filled = static_cast<std::size_t>(received);
      while (filled < memory.size())
      {
        auto more = detail::socket_recv(native, memory.subspan(filled));
        if (more == errc::again)
        {
          read.drained = true;
          read.drained_epoch = epoch;
          break;
        }
        if (more <= 0)
        {
          read.pending = more == 0 ? errc::eof : static_cast<int>(more);
          break;
        }
        filled += static_cast<std::size_t>(more);
      }
      buffer.resize(filled);
      result = std::move(buffer);
      return true;
    }

    void fail(int code) override
    {
      result = std::unexpected(make_error(code));
    }

    ref_ptr_t<tcp_state_t> state;
    std::uint64_t generation = 0;
    std::expected<unique_buf_t, error_t> result;
  };

  auto operator co_await()
  {
    return awaiter_t{_is_valid ? handle : ref_ptr_t<tcp_state_t>::null(), _generation};
  }

  static void pause_reading(ref_ptr_t<tcp_state_t> &handle)
  {
    auto &read = handle->read;
    if (!read.started || read.paused)
      return;
    read.paused = true;
    if (read.waiter != nullptr && !read.waiter->into && read.op.parked)
      handle->socket.cancel(read.op);
  }

  static void resume_reading(ref_ptr_t<tcp_state_t> &handle)
  {
    auto &read = handle->read;
    if (!read.started || !read.paused)
      return;
    read.paused = false;
    if (read.waiter != nullptr && !read.op.parked)
      detail::tcp_read_kick(handle.data());
  }

  void pause()
  {
    if (owns())
      pause_reading(handle);
  }

  void resume()
  {
    if (owns())
      resume_reading(handle);
  }

  struct read_into_awaiter_t final : tcp_read_waiter_t
  {
    read_into_awaiter_t(ref_ptr_t<tcp_state_t> state, std::span<std::byte> dst, std::uint64_t generation) noexcept
      : state(std::move(state))
      , dst(dst)
      , generation(generation)
    {
      into = true;
    }

    read_into_awaiter_t(read_into_awaiter_t &&other) noexcept
      : tcp_read_waiter_t(other)
      , state(std::move(other.state))
      , dst(other.dst)
      , generation(other.generation)
      , result(std::move(other.result))
    {
    }

    read_into_awaiter_t(const read_into_awaiter_t &) = delete;
    read_into_awaiter_t &operator=(const read_into_awaiter_t &) = delete;
    read_into_awaiter_t &operator=(read_into_awaiter_t &&) = delete;

    ~read_into_awaiter_t()
    {
      detail::tcp_read_detach(state, this);
    }

    [[nodiscard]] bool await_ready()
    {
      if (!state)
      {
        fail(errc::bad_descriptor);
        return true;
      }
      if (dst.empty())
      {
        result = std::size_t{0};
        return true;
      }
      auto &read = state->read;
      if (read.is_cancelled || !read.active || read.generation != generation)
      {
        fail(errc::canceled);
        return true;
      }
      if (read.waiter != nullptr)
      {
        result = std::unexpected(error_t{.code = errc::already_in_progress, .msg = "A read is already pending on this socket"});
        return true;
      }
      return detail::tcp_read_try(state.data(), *this);
    }

    void await_suspend(std::coroutine_handle<> handle_to_resume)
    {
      continuation = handle_to_resume;
      state->read.waiter = this;
      detail::tcp_read_park(state.data());
    }

    std::expected<std::size_t, error_t> await_resume()
    {
      return std::move(result);
    }

    bool attempt(tcp_state_t &socket_state) override
    {
      auto &read = socket_state.read;
      if (read.pending != 0)
      {
        auto code = std::exchange(read.pending, 0);
        if (code == errc::eof)
          result = std::size_t{0};
        else
          fail(code);
        return true;
      }
      auto received = detail::socket_recv(socket_state.socket.native(), dst);
      if (received == errc::again)
      {
        read.drained = true;
        read.drained_epoch = socket_state.socket.watch.epoch;
        return false;
      }
      read.drained = false;
      if (received >= 0)
      {
        result = static_cast<std::size_t>(received);
        return true;
      }
      fail(static_cast<int>(received));
      return true;
    }

    void fail(int code) override
    {
      result = std::unexpected(make_error(code));
    }

    ref_ptr_t<tcp_state_t> state;
    std::span<std::byte> dst;
    std::uint64_t generation = 0;
    std::expected<std::size_t, error_t> result = std::size_t{0};
  };

  read_into_awaiter_t read_into(std::span<std::byte> dst)
  {
    return read_into_awaiter_t{_is_valid ? handle : ref_ptr_t<tcp_state_t>::null(), dst, _generation};
  }

  ref_ptr_t<tcp_state_t> handle;
  friend std::expected<tcp_reader_t, error_t> tcp_create_reader(tcp_t &tcp);

private:
  explicit tcp_reader_t(const tcp_t &tcp)
    : handle(tcp.handle)
    , _generation(tcp.handle->read.generation)
    , _is_valid(true)
  {
  }

  [[nodiscard]] bool owns() const noexcept
  {
    return _is_valid && handle && handle->read.generation == _generation;
  }

  void stop() noexcept
  {
    if (!owns())
    {
      _is_valid = false;
      return;
    }
    _is_valid = false;
    auto &read = handle->read;
    read.active = false;
    read.started = false;
    if (read.op.parked)
      handle->socket.cancel(read.op);
    if (read.waiter != nullptr)
      detail::tcp_read_kick(handle.data());
  }

  std::uint64_t _generation = 0;
  bool _is_valid = false;
};

inline std::expected<tcp_reader_t, error_t> tcp_create_reader(tcp_t &tcp)
{
  if (!tcp.handle)
    return std::unexpected(error_t{.code = errc::bad_descriptor, .msg = "Can not create a reader for a closed socket"});
  auto &read = tcp.handle->read;
  if (read.active || read.waiter != nullptr)
    return std::unexpected(error_t{.code = errc::busy, .msg = "Can not create multiple active readers for a socket. Destroy other reader, before making a new one."});
  if (!tcp.handle->socket.is_open() || (!tcp.handle->connected && !tcp.handle->connect.in_progress))
    return std::unexpected(make_error(errc::not_connected));
  read.active = true;
  read.started = true;
  read.paused = false;
  read.is_cancelled = false;
  ++read.generation;
  return tcp_reader_t{tcp};
}
} // namespace vio
