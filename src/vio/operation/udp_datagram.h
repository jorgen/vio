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

// Reading datagrams ourselves, with libuv only telling us when to.
//
// libuv's own UDP read is fine until you want anything the kernel reports
// alongside the payload. Its recvmsg leaves msg_control null, so it never asks
// for control messages and cannot surface them -- and the ECN codepoint, the
// GRO segment size, the destination address of a wildcard socket all arrive
// exactly there. No option makes them appear; the read has to be ours.
//
// So the split is: libuv keeps the socket, the binding and the event loop, and
// hands back readiness through uv_poll_t. The recvmsg is ours, and with it the
// control messages, the batching, and later the segmentation offloads.
//
// This is also the seam that matters if the loop is ever replaced. Everything
// below reads from a descriptor and is told when to look; what does the telling
// is one call. An io_uring or IOCP backend changes that call and nothing else.

#include "vio/error.h"
#include "vio/event_loop.h"
#include "vio/operation/udp.h"

#include <array>
#include <coroutine>
#include <cstdint>
#include <cstring>
#include <deque>
#include <expected>
#include <memory>
#include <span>
#include <vector>

#if defined(_WIN32)
#include <mswsock.h>
#else
#include <cerrno>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

namespace vio
{
// What arrived, and what the kernel said about it.
struct datagram_t
{
  std::vector<std::uint8_t> data;
  sockaddr_storage from = {};
  // RFC 3168. The codepoint the datagram carried when it reached this host,
  // which is the whole reason for taking over the read.
  udp_ecn_t ecn = udp_ecn_t::not_ect;

  [[nodiscard]] const sockaddr *sender() const
  {
    return reinterpret_cast<const sockaddr *>(&from);
  }
};

namespace detail
{
// How many datagrams one wakeup will take before yielding. A readable socket
// usually has more than one waiting, and the syscall is the expensive part.
inline constexpr std::size_t datagram_batch = 32;
inline constexpr std::size_t datagram_capacity = 1500;
// Room for the control messages a datagram can carry. Generous: the kernel
// truncates rather than fails, and a truncated control buffer silently loses
// the codepoint.
inline constexpr std::size_t datagram_control_capacity = 256;

struct datagram_reader_state_t
{
  uv_poll_t poll = {};
  bool poll_started = false;
  bool closing = false;
#if defined(_WIN32)
  SOCKET socket = INVALID_SOCKET;
  LPFN_WSARECVMSG recvmsg_fn = nullptr;
#else
  int fd = -1;
#endif
  std::deque<std::expected<datagram_t, error_t>> ready;
  std::coroutine_handle<> continuation;
  bool cancelled = false;
  std::shared_ptr<datagram_reader_state_t> self;
};

// The two bits at the bottom of the IPv4 TOS byte and the IPv6 traffic class
// byte are the ECN field; the six above them are DSCP and none of our business.
[[nodiscard]] inline udp_ecn_t ecn_from_traffic_class(int value)
{
  return static_cast<udp_ecn_t>(static_cast<unsigned>(value) & 0x03u);
}

inline void deliver(datagram_reader_state_t &state, std::expected<datagram_t, error_t> item)
{
  state.ready.push_back(std::move(item));
  if (state.continuation)
  {
    auto continuation = state.continuation;
    state.continuation = nullptr;
    continuation.resume();
  }
}
} // namespace detail

// Sends one datagram with an explicit ECN codepoint.
//
// The codepoint goes in a control message, per datagram, rather than on the
// socket. That is not a stylistic choice: Windows has no socket option for the
// outgoing codepoint at all -- IP_ECN is a control message type there, and
// IP_RECVECN, the only related socket option, governs receiving. Marking per
// datagram is also the better shape, because a socket carrying several
// connections would otherwise have to mark all of them the same way and give
// up ECN for all of them when one path failed validation.
//
// RFC 3168 forbids an endpoint from setting CE itself -- only a router may --
// and Windows enforces it with WSAEINVAL. Nothing here should ever ask for it.
[[nodiscard]] inline std::expected<std::size_t, error_t> send_datagram(udp_t &udp, std::span<const std::uint8_t> bytes, const sockaddr *address, udp_ecn_t ecn)
{
  auto fd = udp_fileno(udp);
  if (!fd.has_value())
  {
    return std::unexpected(fd.error());
  }
  if (ecn == udp_ecn_t::ce)
  {
    return std::unexpected(error_t{.code = UV_EINVAL, .msg = "only a router may set the congestion experienced codepoint"});
  }
  const bool ipv6 = address != nullptr && address->sa_family == AF_INET6;
  const int value = static_cast<int>(ecn);

#if defined(_WIN32)
  const auto socket_handle = reinterpret_cast<SOCKET>(*fd);
  static LPFN_WSASENDMSG sendmsg_fn = nullptr;
  if (sendmsg_fn == nullptr)
  {
    GUID id = WSAID_WSASENDMSG;
    DWORD returned = 0;
    if (WSAIoctl(socket_handle, SIO_GET_EXTENSION_FUNCTION_POINTER, &id, sizeof(id), &sendmsg_fn, sizeof(sendmsg_fn), &returned, nullptr, nullptr) != 0)
    {
      return std::unexpected(error_t{.code = WSAGetLastError(), .msg = "could not resolve WSASendMsg"});
    }
  }

  WSABUF buffer = {};
  buffer.buf = reinterpret_cast<CHAR *>(const_cast<std::uint8_t *>(bytes.data()));
  buffer.len = static_cast<ULONG>(bytes.size());

  std::array<char, WSA_CMSG_SPACE(sizeof(INT))> control = {};
  WSAMSG message = {};
  message.name = const_cast<LPSOCKADDR>(address);
  message.namelen = ipv6 ? static_cast<INT>(sizeof(sockaddr_in6)) : static_cast<INT>(sizeof(sockaddr_in));
  message.lpBuffers = &buffer;
  message.dwBufferCount = 1;

  if (ecn != udp_ecn_t::not_ect)
  {
    message.Control.buf = control.data();
    message.Control.len = static_cast<ULONG>(control.size());
    WSACMSGHDR *header = WSA_CMSG_FIRSTHDR(&message);
    header->cmsg_len = WSA_CMSG_LEN(sizeof(INT));
    header->cmsg_level = ipv6 ? IPPROTO_IPV6 : IPPROTO_IP;
    header->cmsg_type = ipv6 ? IPV6_ECN : IP_ECN;
    const INT codepoint = value;
    std::memcpy(WSA_CMSG_DATA(header), &codepoint, sizeof(codepoint));
  }

  DWORD sent = 0;
  if (sendmsg_fn(socket_handle, &message, 0, &sent, nullptr, nullptr) != 0)
  {
    return std::unexpected(error_t{.code = WSAGetLastError(), .msg = "sendmsg failed"});
  }
  return static_cast<std::size_t>(sent);
#else
  iovec vector = {};
  vector.iov_base = const_cast<std::uint8_t *>(bytes.data());
  vector.iov_len = bytes.size();

  alignas(cmsghdr) std::array<std::uint8_t, CMSG_SPACE(sizeof(int))> control = {};
  msghdr message = {};
  message.msg_name = const_cast<sockaddr *>(address);
  message.msg_namelen = ipv6 ? static_cast<socklen_t>(sizeof(sockaddr_in6)) : static_cast<socklen_t>(sizeof(sockaddr_in));
  message.msg_iov = &vector;
  message.msg_iovlen = 1;

  if (ecn != udp_ecn_t::not_ect)
  {
    message.msg_control = control.data();
    message.msg_controllen = static_cast<decltype(message.msg_controllen)>(control.size());
    cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_len = CMSG_LEN(sizeof(int));
    header->cmsg_level = ipv6 ? IPPROTO_IPV6 : IPPROTO_IP;
#if defined(IPV6_TCLASS)
    header->cmsg_type = ipv6 ? IPV6_TCLASS : IP_TOS;
#else
    header->cmsg_type = IP_TOS;
#endif
    std::memcpy(CMSG_DATA(header), &value, sizeof(value));
  }

  const ssize_t sent = ::sendmsg(static_cast<int>(*fd), &message, 0);
  if (sent < 0)
  {
    return std::unexpected(error_t{.code = -errno, .msg = "sendmsg failed"});
  }
  return static_cast<std::size_t>(sent);
#endif
}

// Reads datagrams from a socket libuv owns, using our own recvmsg so the
// control messages survive.
//
// The socket must not also be read by libuv: calling udp_create_reader on the
// same udp_t would have two readers racing for the same bytes.
class datagram_reader_t
{
public:
  datagram_reader_t(const datagram_reader_t &) = delete;
  datagram_reader_t &operator=(const datagram_reader_t &) = delete;

  datagram_reader_t(datagram_reader_t &&other) noexcept
    : _state(std::move(other._state))
  {
  }

  datagram_reader_t &operator=(datagram_reader_t &&other) noexcept
  {
    if (this != &other)
    {
      stop();
      _state = std::move(other._state);
    }
    return *this;
  }

  ~datagram_reader_t()
  {
    stop();
  }

  [[nodiscard]] static std::expected<datagram_reader_t, error_t> create(event_loop_t &loop, udp_t &udp)
  {
    auto fd = udp_fileno(udp);
    if (!fd.has_value())
    {
      return std::unexpected(fd.error());
    }

    auto state = std::make_shared<detail::datagram_reader_state_t>();

#if defined(_WIN32)
    state->socket = reinterpret_cast<SOCKET>(*fd);
    // WSARecvMsg is only reachable through an extension pointer; there is no
    // import for it.
    GUID id = WSAID_WSARECVMSG;
    DWORD returned = 0;
    if (WSAIoctl(state->socket, SIO_GET_EXTENSION_FUNCTION_POINTER, &id, sizeof(id), &state->recvmsg_fn, sizeof(state->recvmsg_fn), &returned, nullptr, nullptr) != 0)
    {
      return std::unexpected(error_t{.code = WSAGetLastError(), .msg = "could not resolve WSARecvMsg"});
    }
    if (const int r = uv_poll_init_socket(loop.loop(), &state->poll, state->socket); r < 0)
    {
      return std::unexpected(error_t{.code = r, .msg = uv_strerror(r)});
    }
#else
    state->fd = static_cast<int>(*fd);
    if (const int r = uv_poll_init(loop.loop(), &state->poll, state->fd); r < 0)
    {
      return std::unexpected(error_t{.code = r, .msg = uv_strerror(r)});
    }
#endif

    state->poll.data = state.get();
    if (const int r = uv_poll_start(&state->poll, UV_READABLE, &on_readable); r < 0)
    {
      uv_close(reinterpret_cast<uv_handle_t *>(&state->poll), nullptr);
      return std::unexpected(error_t{.code = r, .msg = uv_strerror(r)});
    }
    state->poll_started = true;

    datagram_reader_t reader;
    reader._state = std::move(state);
    return reader;
  }

  // Asks the kernel to report the ECN codepoint of arriving datagrams. Without
  // this the control message never appears and every datagram reads as not_ect.
  [[nodiscard]] std::expected<void, error_t> receive_ecn(bool on)
  {
    if (!_state)
    {
      return std::unexpected(error_t{.code = UV_EINVAL, .msg = "reader is not open"});
    }
    const int value = on ? 1 : 0;

#if defined(_WIN32)
#if defined(IP_RECVECN) && defined(IPV6_RECVECN)
    // A dual-stack socket needs both: the option is per address family, and a
    // wildcard bind receives on either.
    const int v4 = setsockopt(_state->socket, IPPROTO_IP, IP_RECVECN, reinterpret_cast<const char *>(&value), sizeof(value));
    const int v6 = setsockopt(_state->socket, IPPROTO_IPV6, IPV6_RECVECN, reinterpret_cast<const char *>(&value), sizeof(value));
    if (v4 != 0 && v6 != 0)
    {
      return std::unexpected(error_t{.code = WSAGetLastError(), .msg = "could not ask for the ECN codepoint"});
    }
    return {};
#else
    return std::unexpected(error_t{.code = UV_ENOTSUP, .msg = "this Windows SDK has no IP_RECVECN"});
#endif
#else
    const int v4 = setsockopt(_state->fd, IPPROTO_IP, IP_RECVTOS, &value, sizeof(value));
#if defined(IPV6_RECVTCLASS)
    const int v6 = setsockopt(_state->fd, IPPROTO_IPV6, IPV6_RECVTCLASS, &value, sizeof(value));
#else
    const int v6 = -1;
#endif
    if (v4 != 0 && v6 != 0)
    {
      return std::unexpected(error_t{.code = -errno, .msg = "could not ask for the ECN codepoint"});
    }
    return {};
#endif
  }

  void cancel()
  {
    if (!_state || _state->cancelled)
    {
      return;
    }
    _state->cancelled = true;
    detail::deliver(*_state, std::unexpected(error_t{.code = UV_ECANCELED, .msg = "Operation was cancelled"}));
  }

  struct awaiter_t
  {
    std::shared_ptr<detail::datagram_reader_state_t> state;

    [[nodiscard]] bool await_ready() const
    {
      return !state->ready.empty();
    }

    void await_suspend(std::coroutine_handle<> continuation)
    {
      state->continuation = continuation;
    }

    std::expected<datagram_t, error_t> await_resume()
    {
      auto front = std::move(state->ready.front());
      state->ready.pop_front();
      return front;
    }
  };

  awaiter_t operator co_await()
  {
    return awaiter_t{.state = _state};
  }

private:
  datagram_reader_t() = default;

  void stop()
  {
    if (!_state)
    {
      return;
    }
    auto state = std::move(_state);
    if (!state->poll_started || state->closing)
    {
      return;
    }
    state->closing = true;
    // The handle outlives this object: libuv only lets go of it in the close
    // callback, so the state keeps itself alive until then.
    state->self = state;
    uv_close(reinterpret_cast<uv_handle_t *>(&state->poll), &on_closed);
  }

  static void on_closed(uv_handle_t *handle)
  {
    auto *state = static_cast<detail::datagram_reader_state_t *>(handle->data);
    if (state != nullptr)
    {
      auto keep = std::move(state->self);
      state->self.reset();
      (void)keep;
    }
  }

  static void on_readable(uv_poll_t *handle, int status, int events);

  std::shared_ptr<detail::datagram_reader_state_t> _state;
};

namespace detail
{
// One wakeup's worth of reading. Everything platform-specific about pulling a
// datagram and its control messages out of the kernel is here.
inline void drain_socket(datagram_reader_state_t &state)
{
  for (std::size_t taken = 0; taken < datagram_batch; ++taken)
  {
    std::array<std::uint8_t, datagram_capacity> payload = {};
    std::array<std::uint8_t, datagram_control_capacity> control = {};
    sockaddr_storage from = {};
    udp_ecn_t ecn = udp_ecn_t::not_ect;

#if defined(_WIN32)
    WSABUF buffer = {};
    buffer.buf = reinterpret_cast<CHAR *>(payload.data());
    buffer.len = static_cast<ULONG>(payload.size());

    WSAMSG message = {};
    message.name = reinterpret_cast<LPSOCKADDR>(&from);
    message.namelen = sizeof(from);
    message.lpBuffers = &buffer;
    message.dwBufferCount = 1;
    message.Control.buf = reinterpret_cast<CHAR *>(control.data());
    message.Control.len = static_cast<ULONG>(control.size());

    DWORD received = 0;
    if (state.recvmsg_fn(state.socket, &message, &received, nullptr, nullptr) != 0)
    {
      const int error = WSAGetLastError();
      if (error == WSAEWOULDBLOCK)
      {
        return;
      }
      if (error == WSAECONNRESET || error == WSAEMSGSIZE)
      {
        // An ICMP port-unreachable reported against a previous send, or a
        // datagram larger than the buffer. Neither says anything about the
        // socket, so the next one is read instead.
        continue;
      }
      deliver(state, std::unexpected(error_t{.code = error, .msg = "recvmsg failed"}));
      return;
    }

    for (WSACMSGHDR *header = WSA_CMSG_FIRSTHDR(&message); header != nullptr; header = WSA_CMSG_NXTHDR(&message, header))
    {
#if defined(IP_ECN) && defined(IPV6_ECN)
      const bool is_ecn = (header->cmsg_level == IPPROTO_IP && header->cmsg_type == IP_ECN) || (header->cmsg_level == IPPROTO_IPV6 && header->cmsg_type == IPV6_ECN);
      if (is_ecn && header->cmsg_len >= WSA_CMSG_LEN(sizeof(INT)))
      {
        INT value = 0;
        std::memcpy(&value, WSA_CMSG_DATA(header), sizeof(value));
        ecn = ecn_from_traffic_class(value);
      }
#else
      (void)header;
#endif
    }
    const std::size_t length = static_cast<std::size_t>(received);
#else
    iovec vector = {};
    vector.iov_base = payload.data();
    vector.iov_len = payload.size();

    msghdr message = {};
    message.msg_name = &from;
    message.msg_namelen = sizeof(from);
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = static_cast<decltype(message.msg_controllen)>(control.size());

    const ssize_t received = ::recvmsg(state.fd, &message, MSG_DONTWAIT);
    if (received < 0)
    {
      const int error = errno;
      if (error == EAGAIN || error == EWOULDBLOCK)
      {
        return;
      }
      if (error == EINTR)
      {
        continue;
      }
      if (error == ECONNREFUSED)
      {
        // An ICMP error reported against an earlier send. Not this datagram's
        // problem, and not the socket's.
        continue;
      }
      deliver(state, std::unexpected(error_t{.code = -error, .msg = "recvmsg failed"}));
      return;
    }

    for (cmsghdr *header = CMSG_FIRSTHDR(&message); header != nullptr; header = CMSG_NXTHDR(&message, header))
    {
      const bool v4 = header->cmsg_level == IPPROTO_IP && header->cmsg_type == IP_TOS;
#if defined(IPV6_TCLASS)
      const bool v6 = header->cmsg_level == IPPROTO_IPV6 && header->cmsg_type == IPV6_TCLASS;
#else
      const bool v6 = false;
#endif
      if (!v4 && !v6)
      {
        continue;
      }
      // IP_TOS arrives as a single byte on Linux and as an int on some other
      // systems; IPV6_TCLASS is an int. Reading the wrong width would take the
      // codepoint from the wrong end of the value.
      if (header->cmsg_len == CMSG_LEN(sizeof(int)))
      {
        int value = 0;
        std::memcpy(&value, CMSG_DATA(header), sizeof(value));
        ecn = ecn_from_traffic_class(value);
      }
      else if (header->cmsg_len == CMSG_LEN(sizeof(std::uint8_t)))
      {
        std::uint8_t value = 0;
        std::memcpy(&value, CMSG_DATA(header), sizeof(value));
        ecn = ecn_from_traffic_class(static_cast<int>(value));
      }
    }
    const std::size_t length = static_cast<std::size_t>(received);
#endif

    datagram_t datagram;
    datagram.data.assign(payload.begin(), payload.begin() + static_cast<std::ptrdiff_t>(length));
    datagram.from = from;
    datagram.ecn = ecn;
    deliver(state, std::move(datagram));
  }
}
} // namespace detail

inline void datagram_reader_t::on_readable(uv_poll_t *handle, int status, int events)
{
  auto *state = static_cast<detail::datagram_reader_state_t *>(handle->data);
  if (state == nullptr || state->cancelled || state->closing)
  {
    return;
  }
  if (status < 0)
  {
    detail::deliver(*state, std::unexpected(error_t{.code = status, .msg = uv_strerror(status)}));
    return;
  }
  if ((events & UV_READABLE) == 0)
  {
    return;
  }
  detail::drain_socket(*state);
}
} // namespace vio
