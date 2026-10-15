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
#include "tcp.h"
#include "vio/error.h"

#include "vio/event_loop.h"

#include <coroutine>
#include <expected>
#include <utility>

namespace vio
{
struct tcp_server_t
{
  tcp_t tcp;
};

enum class tcp_bind_flags : unsigned int
{
  none = 0,
  ipv6_only = 1,
  reuse_port = 2
};

constexpr tcp_bind_flags operator|(tcp_bind_flags left, tcp_bind_flags right) noexcept
{
  return static_cast<tcp_bind_flags>(static_cast<unsigned int>(left) | static_cast<unsigned int>(right));
}

constexpr tcp_bind_flags operator&(tcp_bind_flags left, tcp_bind_flags right) noexcept
{
  return static_cast<tcp_bind_flags>(static_cast<unsigned int>(left) & static_cast<unsigned int>(right));
}

inline std::expected<tcp_server_t, error_t> tcp_create_server(event_loop_t &event_loop)
{
  auto tcp = tcp_create(event_loop);
  if (!tcp.has_value())
  {
    return std::unexpected(tcp.error());
  }
  tcp_server_t ret{std::move(tcp.value())};
  return ret;
}

inline std::expected<void, error_t> tcp_bind(tcp_server_t &server, const sockaddr *addr, tcp_bind_flags flags = tcp_bind_flags::none)
{
  if (!server.tcp.handle)
    return std::unexpected(make_error(errc::bad_descriptor));
  constexpr auto known = static_cast<unsigned int>(tcp_bind_flags::ipv6_only | tcp_bind_flags::reuse_port);
  if ((static_cast<unsigned int>(flags) & ~known) != 0)
    return std::unexpected(make_error(errc::invalid_argument));
  int length = detail::tcp_address_length(addr);
  if (length == 0)
    return std::unexpected(make_error(errc::invalid_argument));
  const bool ipv6_only = (flags & tcp_bind_flags::ipv6_only) != tcp_bind_flags::none;
  const bool reuse_port = (flags & tcp_bind_flags::reuse_port) != tcp_bind_flags::none;
  if (ipv6_only && addr->sa_family != AF_INET6)
    return std::unexpected(make_error(errc::invalid_argument));
#if !defined(__linux__)
  if (reuse_port)
    return std::unexpected(make_error(errc::not_supported));
#endif

  auto &state = server.tcp.handle.data();
  if (!state.socket.is_open())
  {
    if (int result = state.socket.open(addr->sa_family, SOCK_STREAM, IPPROTO_TCP); result < 0)
      return std::unexpected(make_error(result));
  }
  auto socket = state.socket.native();
  int on = 1;
#if !defined(_WIN32)
  if (int result = detail::socket_set_option(socket, SOL_SOCKET, SO_REUSEADDR, &on, static_cast<int>(sizeof(on))); result < 0)
    return std::unexpected(make_error(result));
#endif
  if (addr->sa_family == AF_INET6)
  {
    int only = ipv6_only ? 1 : 0;
    int result = detail::socket_set_option(socket, IPPROTO_IPV6, IPV6_V6ONLY, &only, static_cast<int>(sizeof(only)));
#if !defined(_WIN32)
    if (result < 0)
      return std::unexpected(make_error(result));
#else
    (void)result;
#endif
  }
#if defined(__linux__)
  if (reuse_port)
  {
    if (int result = detail::socket_set_option(socket, SOL_SOCKET, SO_REUSEPORT, &on, static_cast<int>(sizeof(on))); result < 0)
      return std::unexpected(make_error(result));
  }
#else
  (void)on;
  (void)reuse_port;
#endif
  if (int result = detail::socket_bind(socket, addr, length); result < 0)
    return std::unexpected(make_error(result));
  return {};
}

struct tcp_listen_future_t
{
  tcp_listen_future_t(ref_ptr_t<tcp_state_t> handle, cancellation_t *cancel) noexcept
    : handle(std::move(handle))
    , cancel(cancel)
  {
  }

  tcp_listen_future_t(tcp_listen_future_t &&other) noexcept
    : handle(std::move(other.handle))
    , cancel(other.cancel)
    , result(std::move(other.result))
    , done(other.done)
    , claim(std::exchange(other.claim, false))
  {
  }

  tcp_listen_future_t(const tcp_listen_future_t &) = delete;
  tcp_listen_future_t &operator=(const tcp_listen_future_t &) = delete;
  tcp_listen_future_t &operator=(tcp_listen_future_t &&) = delete;

  ~tcp_listen_future_t();

  [[nodiscard]] bool await_ready() noexcept;
  void await_suspend(std::coroutine_handle<> handle_to_resume) noexcept;
  std::expected<void, error_t> await_resume() noexcept
  {
    cancel_registration.reset();
    claim = false;
    return std::move(result);
  }

  ref_ptr_t<tcp_state_t> handle;
  cancellation_t *cancel = nullptr;
  registration_t cancel_registration;
  std::coroutine_handle<> continuation = {};
  std::expected<void, error_t> result = {};
  tcp_listen_future_t *next = nullptr;
  tcp_listen_future_t *previous = nullptr;
  bool done = false;
  bool queued = false;
  bool claim = false;

private:
  void on_cancel();
};

namespace detail
{
inline void tcp_listen_link(tcp_listen_state_t &listen, tcp_listen_future_t &waiter) noexcept
{
  waiter.next = nullptr;
  waiter.previous = listen.tail;
  if (listen.tail)
    listen.tail->next = &waiter;
  else
    listen.head = &waiter;
  listen.tail = &waiter;
  waiter.queued = true;
}

inline void tcp_listen_unlink(tcp_listen_state_t &listen, tcp_listen_future_t &waiter) noexcept
{
  if (!waiter.queued)
    return;
  if (waiter.previous)
    waiter.previous->next = waiter.next;
  else
    listen.head = waiter.next;
  if (waiter.next)
    waiter.next->previous = waiter.previous;
  else
    listen.tail = waiter.previous;
  waiter.next = nullptr;
  waiter.previous = nullptr;
  waiter.queued = false;
}

inline void tcp_listen_idle(tcp_state_t &state) noexcept
{
  if (state.listen.head == nullptr && state.listen.op.parked)
    state.socket.cancel(state.listen.op);
}

inline bool tcp_accept_transient(int code) noexcept
{
  switch (code)
  {
  case errc::connection_aborted:
  case errc::connection_reset:
  case errc::protocol_error:
  case errc::network_down:
  case errc::network_unreachable:
  case errc::host_unreachable:
  case errc::no_protocol_option:
  case errc::interrupted:
    return true;
  default:
    return false;
  }
}

inline int tcp_accept_one(tcp_state_t &state, native_socket_t &out) noexcept
{
  for (;;)
  {
    int code = socket_accept(state.socket.native(), out, nullptr, nullptr);
    if (code == 0 || !tcp_accept_transient(code))
      return code;
  }
}

inline int tcp_accept_pending(tcp_state_t &state)
{
  native_socket_t socket = invalid_native_socket;
  if (int code = tcp_accept_one(state, socket); code < 0)
    return code;
  state.listen.accepted.push_back(socket);
  return 0;
}

inline void tcp_listen_resolve(tcp_listen_future_t &waiter, error_t *error)
{
  waiter.done = true;
  if (error)
    waiter.result = std::unexpected(std::move(*error));
  waiter.cancel_registration.reset();
  waiter.continuation.resume();
}

inline void tcp_on_listen_ready(io_op_t *op)
{
  auto &state = *static_cast<tcp_state_t *>(op->owner);
  auto keep = tcp_state_ref(state);
  auto &listen = state.listen;
  while (!state.closed && listen.head != nullptr)
  {
    int code = 0;
    if (listen.unclaimed() == 0)
      code = tcp_accept_pending(state);
    if (code == errc::again)
    {
      if (!listen.op.parked)
        state.socket.wait(interest_read, listen.op);
      return;
    }
    auto *waiter = listen.head;
    tcp_listen_unlink(listen, *waiter);
    if (code < 0)
    {
      auto error = make_error(code);
      tcp_listen_resolve(*waiter, &error);
      continue;
    }
    ++listen.claimed;
    waiter->claim = true;
    tcp_listen_resolve(*waiter, nullptr);
  }
  tcp_listen_idle(state);
}
} // namespace detail

inline tcp_listen_future_t::~tcp_listen_future_t()
{
  if (!handle)
    return;
  auto &state = handle.data();
  if (queued)
  {
    detail::tcp_listen_unlink(state.listen, *this);
    detail::tcp_listen_idle(state);
  }
  if (claim && state.listen.claimed > 0)
    --state.listen.claimed;
}

inline bool tcp_listen_future_t::await_ready() noexcept
{
  if (cancel && cancel->is_cancelled())
  {
    if (claim && handle && handle->listen.claimed > 0)
      --handle->listen.claimed;
    claim = false;
    done = true;
    result = std::unexpected(detail::tcp_cancelled_error());
    return true;
  }
  if (done)
    return true;
  auto &state = handle.data();
  auto &listen = state.listen;
  if (listen.head != nullptr)
    return false;
  int code = 0;
  if (listen.unclaimed() == 0)
    code = detail::tcp_accept_pending(state);
  if (code == errc::again)
    return false;
  done = true;
  if (code < 0)
  {
    result = std::unexpected(make_error(code));
    return true;
  }
  ++listen.claimed;
  claim = true;
  return true;
}

inline void tcp_listen_future_t::await_suspend(std::coroutine_handle<> handle_to_resume) noexcept
{
  continuation = handle_to_resume;
  auto &state = handle.data();
  detail::tcp_listen_link(state.listen, *this);
  if (cancel)
    cancel_registration = cancel->register_callback([this] { on_cancel(); });
  if (!state.listen.op.parked)
    state.socket.wait(detail::interest_read, state.listen.op);
}

inline void tcp_listen_future_t::on_cancel()
{
  if (done)
    return;
  auto &state = handle.data();
  detail::tcp_listen_unlink(state.listen, *this);
  detail::tcp_listen_idle(state);
  done = true;
  result = std::unexpected(detail::tcp_cancelled_error());
  cancel_registration.reset();
  continuation.resume();
}

inline tcp_listen_future_t tcp_listen(tcp_server_t &server, int backlog, cancellation_t *cancel = nullptr)
{
  tcp_listen_future_t ret(server.tcp.handle, cancel);
  if (!ret.handle)
  {
    ret.done = true;
    ret.result = std::unexpected(error_t{.code = errc::bad_descriptor, .msg = "It's not possible to listen on a closed socket"});
    return ret;
  }
  if (cancel && cancel->is_cancelled())
  {
    ret.done = true;
    ret.result = std::unexpected(detail::tcp_cancelled_error());
    return ret;
  }
  auto &state = ret.handle.data();
  state.listen.op.complete = &detail::tcp_on_listen_ready;
  if (!state.listen.listening)
  {
    if (!state.socket.is_open())
    {
      if (int result = state.socket.open(AF_INET, SOCK_STREAM, IPPROTO_TCP); result < 0)
      {
        ret.done = true;
        ret.result = std::unexpected(make_error(result));
        return ret;
      }
    }
    if (int result = detail::socket_listen(state.socket.native(), backlog); result < 0)
    {
      ret.done = true;
      ret.result = std::unexpected(make_error(result));
      return ret;
    }
    state.listen.listening = true;
  }
  return ret;
}

inline void tcp_listen_abort(tcp_server_t &server, const error_t &error)
{
  if (!server.tcp.handle)
    return;
  auto keep = server.tcp.handle;
  auto &state = keep.data();
  while (state.listen.head != nullptr)
  {
    auto *waiter = state.listen.head;
    detail::tcp_listen_unlink(state.listen, *waiter);
    auto copy = error;
    detail::tcp_listen_resolve(*waiter, &copy);
  }
  detail::tcp_listen_idle(state);
}

inline std::expected<tcp_t, error_t> tcp_accept(tcp_server_t &server)
{
  if (!server.tcp.handle)
    return std::unexpected(error_t{.code = errc::bad_descriptor, .msg = "It's not possible to accept a connection on a closed socket"});
  auto &state = server.tcp.handle.data();
  native_socket_t socket = invalid_native_socket;
  if (state.listen.ready() > 0)
    socket = state.listen.take();
  else if (int code = detail::tcp_accept_one(state, socket); code < 0)
    return std::unexpected(make_error(code));
  auto client = tcp_create(state.event_loop);
  if (!client)
  {
    detail::socket_close(socket);
    return std::unexpected(client.error());
  }
  if (int code = client->handle->socket.adopt(socket); code < 0)
    return std::unexpected(make_error(code));
  client->handle->connected = true;
  return std::move(client.value());
}

} // namespace vio
