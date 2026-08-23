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
#include <optional>
#include <span>
#include <vector>

#if defined(_WIN32)
#include <mswsock.h>
#else
#include <cerrno>
#include <netinet/in.h>
#include <netinet/udp.h>
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
// With receive coalescing the kernel hands back many datagrams as one buffer,
// so the read has to be able to hold them. 64 KiB is the ceiling both Linux
// and Windows work to.
inline constexpr std::size_t coalesced_capacity = 65536;
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
  // Reused across reads rather than a stack buffer, because coalescing makes
  // it far too large to put on the stack once per datagram.
  std::vector<std::uint8_t> scratch = std::vector<std::uint8_t>(datagram_capacity);
  std::size_t coalescing = 0;
  // Calls made and datagrams they carried. The ratio is what receive
  // coalescing changes.
  std::uint64_t reads = 0;
  std::uint64_t datagrams = 0;
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
// An IPv4 destination as a dual-stack socket reports it: ::ffff:a.b.c.d. The
// datagram leaves as IPv4, which decides which options the kernel will read
// for it.
[[nodiscard]] inline bool is_ipv4_mapped(const sockaddr *address)
{
  if (address == nullptr || address->sa_family != AF_INET6)
  {
    return false;
  }
  static constexpr std::uint8_t prefix[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
  const auto *bytes = reinterpret_cast<const std::uint8_t *>(&reinterpret_cast<const sockaddr_in6 *>(address)->sin6_addr);
  return std::memcmp(bytes, prefix, sizeof(prefix)) == 0;
}

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
  // A dual-stack socket cannot be handed a bare IPv4 destination: sendmsg wants
  // the socket's family. libuv converts internally; doing our own send means
  // doing our own conversion to the IPv4-mapped form.
  sockaddr_storage mapped = {};
  auto name = udp_sockname(udp);
  if (name.has_value() && name->ss_family == AF_INET6 && address != nullptr && address->sa_family == AF_INET)
  {
    const auto *in4 = reinterpret_cast<const sockaddr_in *>(address);
    auto *in6 = reinterpret_cast<sockaddr_in6 *>(&mapped);
    in6->sin6_family = AF_INET6;
    in6->sin6_port = in4->sin_port;
    auto *bytes = reinterpret_cast<std::uint8_t *>(&in6->sin6_addr);
    bytes[10] = 0xff;
    bytes[11] = 0xff;
    std::memcpy(bytes + 12, &in4->sin_addr, 4);
    address = reinterpret_cast<const sockaddr *>(&mapped);
  }

  // The address handed to the kernel is whatever the mapping left behind, and
  // its length has to match that.
  const bool address_is_ipv6 = address != nullptr && address->sa_family == AF_INET6;
  // Which control message carries the codepoint is a different question: it
  // follows the family the datagram actually leaves as, and one addressed to
  // an IPv4-mapped address leaves as IPv4 however the socket is bound. That
  // path reads IP_TOS; IPV6_TCLASS is accepted there and quietly does nothing,
  // so marking it that way puts the packets on the wire unmarked. A dual-stack
  // socket sees every IPv4 peer in the mapped form, so this is the common case
  // rather than a corner of one.
  const bool ipv6 = address_is_ipv6 && !is_ipv4_mapped(address);
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
  message.msg_namelen = address_is_ipv6 ? static_cast<socklen_t>(sizeof(sockaddr_in6)) : static_cast<socklen_t>(sizeof(sockaddr_in));
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

// Sends several datagrams as one buffer, letting the kernel cut it into pieces
// of segment_size on the way out.
//
// This is the send-side offload -- UDP_SEGMENT on Linux, USO on Windows -- and
// it is the change that moves throughput most, because it divides the number of
// system calls per megabyte by however many segments fit in a batch.
//
// The shape it demands: every segment must be exactly segment_size except the
// last, which may be shorter. There is no length list, so that rule is the only
// thing that makes the batch decodable, and a caller that mixes sizes silently
// corrupts the stream rather than failing.
//
// Whether the kernel or the interface actually honours it is not knowable in
// advance; if it refuses, the error comes back and the caller falls back to
// sending one at a time.
[[nodiscard]] inline std::expected<std::size_t, error_t> send_segments(udp_t &udp, std::span<const std::uint8_t> bytes, std::size_t segment_size, const sockaddr *address, udp_ecn_t ecn)
{
  if (segment_size == 0 || bytes.empty())
  {
    return std::size_t{0};
  }
  if (bytes.size() <= segment_size)
  {
    // One segment is just a datagram; the offload has nothing to do.
    return send_datagram(udp, bytes, address, ecn);
  }

  auto fd = udp_fileno(udp);
  if (!fd.has_value())
  {
    return std::unexpected(fd.error());
  }
  if (ecn == udp_ecn_t::ce)
  {
    return std::unexpected(error_t{.code = UV_EINVAL, .msg = "only a router may set the congestion experienced codepoint"});
  }

  sockaddr_storage mapped = {};
  auto name = udp_sockname(udp);
  if (name.has_value() && name->ss_family == AF_INET6 && address != nullptr && address->sa_family == AF_INET)
  {
    const auto *in4 = reinterpret_cast<const sockaddr_in *>(address);
    auto *in6 = reinterpret_cast<sockaddr_in6 *>(&mapped);
    in6->sin6_family = AF_INET6;
    in6->sin6_port = in4->sin_port;
    auto *raw = reinterpret_cast<std::uint8_t *>(&in6->sin6_addr);
    raw[10] = 0xff;
    raw[11] = 0xff;
    std::memcpy(raw + 12, &in4->sin_addr, 4);
    address = reinterpret_cast<const sockaddr *>(&mapped);
  }
  // The address handed to the kernel is whatever the mapping left behind, and
  // its length has to match that.
  const bool address_is_ipv6 = address != nullptr && address->sa_family == AF_INET6;
  // Which control message carries the codepoint is a different question: it
  // follows the family the datagram actually leaves as, and one addressed to
  // an IPv4-mapped address leaves as IPv4 however the socket is bound. That
  // path reads IP_TOS; IPV6_TCLASS is accepted there and quietly does nothing,
  // so marking it that way puts the packets on the wire unmarked. A dual-stack
  // socket sees every IPv4 peer in the mapped form, so this is the common case
  // rather than a corner of one.
  const bool ipv6 = address_is_ipv6 && !is_ipv4_mapped(address);

#if defined(_WIN32)
#if defined(UDP_SEND_MSG_SIZE)
  const auto socket_handle = reinterpret_cast<SOCKET>(*fd);
  // Windows carries the segment size as a socket option rather than a control
  // message, so it is set for the send and cleared again -- anything else would
  // leave the next ordinary send being cut up.
  DWORD size = static_cast<DWORD>(segment_size);
  if (setsockopt(socket_handle, IPPROTO_UDP, UDP_SEND_MSG_SIZE, reinterpret_cast<const char *>(&size), sizeof(size)) != 0)
  {
    return std::unexpected(error_t{.code = WSAGetLastError(), .msg = "the socket would not segment sends"});
  }
  auto sent = send_datagram(udp, bytes, address, ecn);
  DWORD off = 0;
  (void)setsockopt(socket_handle, IPPROTO_UDP, UDP_SEND_MSG_SIZE, reinterpret_cast<const char *>(&off), sizeof(off));
  return sent;
#else
  return std::unexpected(error_t{.code = UV_ENOTSUP, .msg = "this Windows SDK has no UDP_SEND_MSG_SIZE"});
#endif
#else
#if defined(UDP_SEGMENT)
  iovec vector = {};
  vector.iov_base = const_cast<std::uint8_t *>(bytes.data());
  vector.iov_len = bytes.size();

  alignas(cmsghdr) std::array<std::uint8_t, CMSG_SPACE(sizeof(std::uint16_t)) + CMSG_SPACE(sizeof(int))> control = {};
  msghdr message = {};
  message.msg_name = const_cast<sockaddr *>(address);
  message.msg_namelen = address_is_ipv6 ? static_cast<socklen_t>(sizeof(sockaddr_in6)) : static_cast<socklen_t>(sizeof(sockaddr_in));
  message.msg_iov = &vector;
  message.msg_iovlen = 1;
  message.msg_control = control.data();
  message.msg_controllen = static_cast<decltype(message.msg_controllen)>(control.size());

  cmsghdr *header = CMSG_FIRSTHDR(&message);
  header->cmsg_len = CMSG_LEN(sizeof(std::uint16_t));
  header->cmsg_level = SOL_UDP;
  header->cmsg_type = UDP_SEGMENT;
  const std::uint16_t size = static_cast<std::uint16_t>(segment_size);
  std::memcpy(CMSG_DATA(header), &size, sizeof(size));
  std::size_t used = CMSG_SPACE(sizeof(std::uint16_t));

  if (ecn != udp_ecn_t::not_ect)
  {
    cmsghdr *next = CMSG_NXTHDR(&message, header);
    if (next != nullptr)
    {
      next->cmsg_len = CMSG_LEN(sizeof(int));
      next->cmsg_level = ipv6 ? IPPROTO_IPV6 : IPPROTO_IP;
#if defined(IPV6_TCLASS)
      next->cmsg_type = ipv6 ? IPV6_TCLASS : IP_TOS;
#else
      next->cmsg_type = IP_TOS;
#endif
      const int codepoint = static_cast<int>(ecn);
      std::memcpy(CMSG_DATA(next), &codepoint, sizeof(codepoint));
      used += CMSG_SPACE(sizeof(int));
    }
  }
  message.msg_controllen = static_cast<decltype(message.msg_controllen)>(used);

  const ssize_t sent = ::sendmsg(static_cast<int>(*fd), &message, 0);
  if (sent < 0)
  {
    return std::unexpected(error_t{.code = -errno, .msg = "segmented sendmsg failed"});
  }
  return static_cast<std::size_t>(sent);
#else
  return std::unexpected(error_t{.code = UV_ENOTSUP, .msg = "this system has no UDP_SEGMENT"});
#endif
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

  // Asks the kernel to hand back several datagrams in one read, coalesced into
  // a single buffer, and to report the segment size so they can be taken apart
  // again. Reading a megabyte then costs a fraction of the system calls.
  //
  // This is a receive-side offload -- UDP_GRO on Linux, URO on Windows -- so
  // whether it does anything depends on the kernel and the interface. Asking
  // for it and being refused is not a failure worth reporting upward; the
  // reads simply arrive one at a time as before.
  [[nodiscard]] std::expected<void, error_t> receive_coalesced(std::size_t max_size)
  {
    if (!_state)
    {
      return std::unexpected(error_t{.code = UV_EINVAL, .msg = "reader is not open"});
    }
    if (max_size == 0)
    {
      _state->coalescing = 0;
      _state->scratch.assign(detail::datagram_capacity, 0);
      return {};
    }

    const int value = static_cast<int>((std::min)(max_size, detail::coalesced_capacity));
#if defined(_WIN32)
#if defined(UDP_RECV_MAX_COALESCED_SIZE)
    if (setsockopt(_state->socket, IPPROTO_UDP, UDP_RECV_MAX_COALESCED_SIZE, reinterpret_cast<const char *>(&value), sizeof(value)) != 0)
    {
      return std::unexpected(error_t{.code = WSAGetLastError(), .msg = "the socket would not coalesce receives"});
    }
#else
    return std::unexpected(error_t{.code = UV_ENOTSUP, .msg = "this Windows SDK has no UDP_RECV_MAX_COALESCED_SIZE"});
#endif
#else
#if defined(UDP_GRO)
    const int on = 1;
    if (setsockopt(_state->fd, IPPROTO_UDP, UDP_GRO, &on, sizeof(on)) != 0)
    {
      return std::unexpected(error_t{.code = -errno, .msg = "the socket would not coalesce receives"});
    }
#else
    return std::unexpected(error_t{.code = UV_ENOTSUP, .msg = "this system has no UDP_GRO"});
#endif
#endif
    _state->coalescing = static_cast<std::size_t>(value);
    _state->scratch.assign(static_cast<std::size_t>(value) + detail::datagram_capacity, 0);
    return {};
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

  // The next datagram already in hand, without suspending. One wakeup usually
  // pulls a run of them off the socket, and a caller that wants to answer them
  // together has to be able to see the whole run first.
  [[nodiscard]] std::optional<std::expected<datagram_t, error_t>> try_next()
  {
    if (!_state || _state->ready.empty())
    {
      return std::nullopt;
    }
    auto front = std::move(_state->ready.front());
    _state->ready.pop_front();
    return front;
  }

  [[nodiscard]] std::uint64_t reads() const
  {
    return _state ? _state->reads : 0;
  }

  [[nodiscard]] std::uint64_t datagrams() const
  {
    return _state ? _state->datagrams : 0;
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
//
// A read may come back holding several datagrams at once when receive
// coalescing is on: the kernel concatenates consecutive datagrams from the same
// flow and reports the segment size in a control message. Every segment is
// full-length except possibly the last, which is what makes taking them apart
// again unambiguous.
inline void drain_socket(datagram_reader_state_t &state)
{
  for (std::size_t taken = 0; taken < datagram_batch; ++taken)
  {
    std::array<std::uint8_t, datagram_control_capacity> control = {};
    sockaddr_storage from = {};
    udp_ecn_t ecn = udp_ecn_t::not_ect;
    std::size_t segment = 0;
    std::size_t length = 0;

#if defined(_WIN32)
    WSABUF buffer = {};
    buffer.buf = reinterpret_cast<CHAR *>(state.scratch.data());
    buffer.len = static_cast<ULONG>(state.scratch.size());

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
        continue;
      }
#endif
#if defined(UDP_COALESCED_INFO)
      if (header->cmsg_level == IPPROTO_UDP && header->cmsg_type == UDP_COALESCED_INFO && header->cmsg_len >= WSA_CMSG_LEN(sizeof(DWORD)))
      {
        DWORD value = 0;
        std::memcpy(&value, WSA_CMSG_DATA(header), sizeof(value));
        segment = static_cast<std::size_t>(value);
      }
#endif
    }
    length = static_cast<std::size_t>(received);
#else
    iovec vector = {};
    vector.iov_base = state.scratch.data();
    vector.iov_len = state.scratch.size();

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
#if defined(UDP_GRO)
      if (header->cmsg_level == IPPROTO_UDP && header->cmsg_type == UDP_GRO && header->cmsg_len == CMSG_LEN(sizeof(int)))
      {
        int value = 0;
        std::memcpy(&value, CMSG_DATA(header), sizeof(value));
        segment = value > 0 ? static_cast<std::size_t>(value) : 0;
        continue;
      }
#endif
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
    length = static_cast<std::size_t>(received);
#endif

    ++state.reads;

    // Without a segment size the read holds exactly one datagram, which is the
    // ordinary case and the only one when coalescing is off.
    if (segment == 0 || segment >= length)
    {
      ++state.datagrams;
      datagram_t datagram;
      datagram.data.assign(state.scratch.begin(), state.scratch.begin() + static_cast<std::ptrdiff_t>(length));
      datagram.from = from;
      datagram.ecn = ecn;
      deliver(state, std::move(datagram));
      continue;
    }

    // Coalesced: every segment is full-length except the last. They came from
    // one flow, so they share a sender and a codepoint.
    for (std::size_t offset = 0; offset < length; offset += segment)
    {
      ++state.datagrams;
      const std::size_t piece = (std::min)(segment, length - offset);
      datagram_t datagram;
      datagram.data.assign(state.scratch.begin() + static_cast<std::ptrdiff_t>(offset), state.scratch.begin() + static_cast<std::ptrdiff_t>(offset + piece));
      datagram.from = from;
      datagram.ecn = ecn;
      deliver(state, std::move(datagram));
    }
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
