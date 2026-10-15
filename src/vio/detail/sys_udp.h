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

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "vio/detail/native.h"
#include "vio/detail/sys.h"
#include "vio/errc.h"

#if !defined(_WIN32)
#include <cerrno>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/uio.h>
#endif

namespace vio::detail
{
inline constexpr std::size_t udp_message_batch_limit = 64;

#if defined(__linux__)
inline constexpr int linux_udp_segment = 103;
inline constexpr int linux_udp_gro = 104;
#endif

#if defined(MSG_NOSIGNAL)
inline constexpr int udp_send_flags = MSG_NOSIGNAL;
#else
inline constexpr int udp_send_flags = 0;
#endif

struct udp_message_t
{
  std::byte *data = nullptr;
  std::size_t capacity = 0;
  sockaddr_storage *name = nullptr;
  std::byte *control = nullptr;
  std::size_t control_capacity = 0;
  std::size_t length = 0;
  std::size_t control_length = 0;
  int name_length = 0;
  bool truncated = false;
};

struct udp_out_message_t
{
  const_bytes_t bytes;
  const sockaddr *to = nullptr;
  int to_length = 0;
};

struct udp_send_options_t
{
  std::uint8_t ecn = 0;
  bool ecn_ipv6 = false;
  std::uint16_t segment_size = 0;
};

struct udp_control_t
{
  std::uint8_t ecn = 0;
  std::size_t segment_size = 0;
  bool has_local = false;
  sockaddr_storage local = {};
};

[[nodiscard]] inline int udp_address_length(const sockaddr *address) noexcept
{
  if (address == nullptr)
  {
    return 0;
  }
  if (address->sa_family == AF_INET)
  {
    return static_cast<int>(sizeof(sockaddr_in));
  }
  if (address->sa_family == AF_INET6)
  {
    return static_cast<int>(sizeof(sockaddr_in6));
  }
  return -1;
}

[[nodiscard]] inline bool udp_is_terminal_receive_error(std::int64_t code) noexcept
{
  return code == errc::bad_descriptor || code == errc::not_a_socket || code == errc::invalid_argument || code == errc::bad_address;
}

#if defined(_WIN32)
[[nodiscard]] inline LPFN_WSARECVMSG udp_wsa_recvmsg(native_socket_t socket) noexcept
{
  static std::atomic<LPFN_WSARECVMSG> cached{nullptr};
  LPFN_WSARECVMSG function = cached.load(std::memory_order_acquire);
  if (function != nullptr)
  {
    return function;
  }
  GUID id = WSAID_WSARECVMSG;
  DWORD returned = 0;
  if (WSAIoctl(socket, SIO_GET_EXTENSION_FUNCTION_POINTER, &id, sizeof(id), &function, sizeof(function), &returned, nullptr, nullptr) != 0)
  {
    return nullptr;
  }
  cached.store(function, std::memory_order_release);
  return function;
}

[[nodiscard]] inline LPFN_WSASENDMSG udp_wsa_sendmsg(native_socket_t socket) noexcept
{
  static std::atomic<LPFN_WSASENDMSG> cached{nullptr};
  LPFN_WSASENDMSG function = cached.load(std::memory_order_acquire);
  if (function != nullptr)
  {
    return function;
  }
  GUID id = WSAID_WSASENDMSG;
  DWORD returned = 0;
  if (WSAIoctl(socket, SIO_GET_EXTENSION_FUNCTION_POINTER, &id, sizeof(id), &function, sizeof(function), &returned, nullptr, nullptr) != 0)
  {
    return nullptr;
  }
  cached.store(function, std::memory_order_release);
  return function;
}
#endif

[[nodiscard]] inline std::int64_t udp_receive(native_socket_t socket, udp_message_t *messages, std::size_t count) noexcept
{
  if (count == 0)
  {
    return errc::invalid_argument;
  }
#if defined(_WIN32)
  LPFN_WSARECVMSG receive = udp_wsa_recvmsg(socket);
  if (receive == nullptr)
  {
    return errc::not_supported;
  }
  udp_message_t &message = messages[0];
  WSABUF buffer = {};
  buffer.buf = reinterpret_cast<CHAR *>(message.data);
  buffer.len = static_cast<ULONG>(message.capacity);
  WSAMSG header = {};
  header.name = reinterpret_cast<LPSOCKADDR>(message.name);
  header.namelen = message.name != nullptr ? static_cast<INT>(sizeof(sockaddr_storage)) : 0;
  header.lpBuffers = &buffer;
  header.dwBufferCount = 1;
  header.Control.buf = reinterpret_cast<CHAR *>(message.control);
  header.Control.len = static_cast<ULONG>(message.control_capacity);
  DWORD received = 0;
  if (receive(socket, &header, &received, nullptr, nullptr) != 0)
  {
    const int error = WSAGetLastError();
    if (error != WSAEMSGSIZE)
    {
      return errc_from_wsa(error);
    }
    message.length = message.capacity;
    message.truncated = true;
  }
  else
  {
    message.length = static_cast<std::size_t>(received);
    message.truncated = (header.dwFlags & MSG_TRUNC) != 0;
  }
  message.name_length = message.name != nullptr ? static_cast<int>(header.namelen) : 0;
  message.control_length = message.control != nullptr ? static_cast<std::size_t>(header.Control.len) : 0;
  return 1;
#else
#if defined(__linux__)
  if (count > 1)
  {
    if (count > udp_message_batch_limit)
    {
      count = udp_message_batch_limit;
    }
    mmsghdr headers[udp_message_batch_limit];
    iovec vectors[udp_message_batch_limit];
    for (std::size_t i = 0; i < count; ++i)
    {
      vectors[i].iov_base = messages[i].data;
      vectors[i].iov_len = messages[i].capacity;
      headers[i] = {};
      headers[i].msg_hdr.msg_name = messages[i].name;
      headers[i].msg_hdr.msg_namelen = messages[i].name != nullptr ? static_cast<socklen_t>(sizeof(sockaddr_storage)) : 0;
      headers[i].msg_hdr.msg_iov = &vectors[i];
      headers[i].msg_hdr.msg_iovlen = 1;
      headers[i].msg_hdr.msg_control = messages[i].control;
      headers[i].msg_hdr.msg_controllen = static_cast<decltype(headers[i].msg_hdr.msg_controllen)>(messages[i].control_capacity);
    }
    for (;;)
    {
      const int received = ::recvmmsg(socket, headers, static_cast<unsigned int>(count), MSG_DONTWAIT, nullptr);
      if (received > 0)
      {
        for (int i = 0; i < received; ++i)
        {
          auto &message = messages[i];
          message.length = headers[i].msg_len;
          message.name_length = message.name != nullptr ? static_cast<int>(headers[i].msg_hdr.msg_namelen) : 0;
          message.control_length = message.control != nullptr ? static_cast<std::size_t>(headers[i].msg_hdr.msg_controllen) : 0;
          message.truncated = (headers[i].msg_hdr.msg_flags & MSG_TRUNC) != 0;
        }
        return received;
      }
      if (received == 0)
      {
        return errc::again;
      }
      if (errno == EINTR)
      {
        continue;
      }
      return errc_from_errno(errno);
    }
  }
#endif
  udp_message_t &message = messages[0];
  iovec vector = {};
  vector.iov_base = message.data;
  vector.iov_len = message.capacity;
  msghdr header = {};
  header.msg_name = message.name;
  header.msg_namelen = message.name != nullptr ? static_cast<socklen_t>(sizeof(sockaddr_storage)) : 0;
  header.msg_iov = &vector;
  header.msg_iovlen = 1;
  header.msg_control = message.control;
  header.msg_controllen = static_cast<decltype(header.msg_controllen)>(message.control_capacity);
  for (;;)
  {
    const auto received = ::recvmsg(socket, &header, MSG_DONTWAIT);
    if (received >= 0)
    {
      message.length = static_cast<std::size_t>(received);
      message.name_length = message.name != nullptr ? static_cast<int>(header.msg_namelen) : 0;
      message.control_length = message.control != nullptr ? static_cast<std::size_t>(header.msg_controllen) : 0;
      message.truncated = (header.msg_flags & MSG_TRUNC) != 0;
      return 1;
    }
    if (errno == EINTR)
    {
      continue;
    }
    return errc_from_errno(errno);
  }
#endif
}

[[nodiscard]] inline std::int64_t udp_send(native_socket_t socket, const_bytes_t bytes, const sockaddr *to, int to_length, const udp_send_options_t &options) noexcept
{
#if defined(_WIN32)
  LPFN_WSASENDMSG send = udp_wsa_sendmsg(socket);
  if (send == nullptr)
  {
    return errc::not_supported;
  }
  WSABUF buffer = {};
  buffer.buf = reinterpret_cast<CHAR *>(const_cast<std::byte *>(bytes.data()));
  buffer.len = static_cast<ULONG>(bytes.size());
  alignas(WSACMSGHDR) char control[WSA_CMSG_SPACE(sizeof(INT))] = {};
  WSAMSG header = {};
  header.name = const_cast<LPSOCKADDR>(to);
  header.namelen = to != nullptr ? static_cast<INT>(to_length) : 0;
  header.lpBuffers = &buffer;
  header.dwBufferCount = 1;
  if (options.ecn != 0)
  {
#if defined(IP_ECN) && defined(IPV6_ECN)
    header.Control.buf = control;
    header.Control.len = static_cast<ULONG>(sizeof(control));
    WSACMSGHDR *entry = WSA_CMSG_FIRSTHDR(&header);
    entry->cmsg_len = WSA_CMSG_LEN(sizeof(INT));
    entry->cmsg_level = options.ecn_ipv6 ? IPPROTO_IPV6 : IPPROTO_IP;
    entry->cmsg_type = options.ecn_ipv6 ? IPV6_ECN : IP_ECN;
    const INT codepoint = options.ecn;
    std::memcpy(WSA_CMSG_DATA(entry), &codepoint, sizeof(codepoint));
#else
    return errc::not_supported;
#endif
  }
  if (options.segment_size != 0)
  {
#if defined(UDP_SEND_MSG_SIZE)
    DWORD size = options.segment_size;
    if (setsockopt(socket, IPPROTO_UDP, UDP_SEND_MSG_SIZE, reinterpret_cast<const char *>(&size), sizeof(size)) != 0)
    {
      return errc_from_wsa(WSAGetLastError());
    }
#else
    return errc::not_supported;
#endif
  }
  DWORD sent = 0;
  const int status = send(socket, &header, 0, &sent, nullptr, nullptr);
  const int error = status != 0 ? WSAGetLastError() : 0;
#if defined(UDP_SEND_MSG_SIZE)
  if (options.segment_size != 0)
  {
    DWORD off = 0;
    (void)setsockopt(socket, IPPROTO_UDP, UDP_SEND_MSG_SIZE, reinterpret_cast<const char *>(&off), sizeof(off));
  }
#endif
  if (status != 0)
  {
    return errc_from_wsa(error);
  }
  return static_cast<std::int64_t>(sent);
#else
  iovec vector = {};
  vector.iov_base = const_cast<std::byte *>(bytes.data());
  vector.iov_len = bytes.size();
#if defined(__FreeBSD__) || defined(__NetBSD__)
  using tos_t = unsigned char;
#else
  using tos_t = int;
#endif
  alignas(cmsghdr) unsigned char control[CMSG_SPACE(sizeof(std::uint16_t)) + CMSG_SPACE(sizeof(int))] = {};
  msghdr header = {};
  header.msg_name = const_cast<sockaddr *>(to);
  header.msg_namelen = to != nullptr ? static_cast<socklen_t>(to_length) : 0;
  header.msg_iov = &vector;
  header.msg_iovlen = 1;
  std::size_t used = 0;
  if (options.segment_size != 0)
  {
#if defined(__linux__)
    auto *entry = reinterpret_cast<cmsghdr *>(control);
    entry->cmsg_level = IPPROTO_UDP;
    entry->cmsg_type = linux_udp_segment;
    entry->cmsg_len = CMSG_LEN(sizeof(std::uint16_t));
    const std::uint16_t size = options.segment_size;
    std::memcpy(CMSG_DATA(entry), &size, sizeof(size));
    used += CMSG_SPACE(sizeof(std::uint16_t));
#else
    return errc::not_supported;
#endif
  }
  if (options.ecn != 0)
  {
    auto *entry = reinterpret_cast<cmsghdr *>(control + used);
    const bool ipv6 = options.ecn_ipv6;
#if defined(IPV6_TCLASS)
    entry->cmsg_level = ipv6 ? IPPROTO_IPV6 : IPPROTO_IP;
    entry->cmsg_type = ipv6 ? IPV6_TCLASS : IP_TOS;
#else
    if (ipv6)
    {
      return errc::not_supported;
    }
    entry->cmsg_level = IPPROTO_IP;
    entry->cmsg_type = IP_TOS;
#endif
    if (ipv6)
    {
      const int value = options.ecn;
      entry->cmsg_len = CMSG_LEN(sizeof(value));
      std::memcpy(CMSG_DATA(entry), &value, sizeof(value));
      used += CMSG_SPACE(sizeof(value));
    }
    else
    {
      const tos_t value = static_cast<tos_t>(options.ecn);
      entry->cmsg_len = CMSG_LEN(sizeof(value));
      std::memcpy(CMSG_DATA(entry), &value, sizeof(value));
      used += CMSG_SPACE(sizeof(value));
    }
  }
  if (used != 0)
  {
    header.msg_control = control;
    header.msg_controllen = static_cast<decltype(header.msg_controllen)>(used);
  }
  for (;;)
  {
    const auto sent = ::sendmsg(socket, &header, udp_send_flags);
    if (sent >= 0)
    {
      return static_cast<std::int64_t>(sent);
    }
    if (errno == EINTR)
    {
      continue;
    }
    return errc_from_errno(errno);
  }
#endif
}

[[nodiscard]] inline std::int64_t udp_send_many(native_socket_t socket, const udp_out_message_t *messages, std::size_t count) noexcept
{
  if (count == 0)
  {
    return 0;
  }
#if defined(__linux__)
  if (count > udp_message_batch_limit)
  {
    count = udp_message_batch_limit;
  }
  mmsghdr headers[udp_message_batch_limit];
  iovec vectors[udp_message_batch_limit];
  for (std::size_t i = 0; i < count; ++i)
  {
    vectors[i].iov_base = const_cast<std::byte *>(messages[i].bytes.data());
    vectors[i].iov_len = messages[i].bytes.size();
    headers[i] = {};
    headers[i].msg_hdr.msg_name = const_cast<sockaddr *>(messages[i].to);
    headers[i].msg_hdr.msg_namelen = messages[i].to != nullptr ? static_cast<socklen_t>(messages[i].to_length) : 0;
    headers[i].msg_hdr.msg_iov = &vectors[i];
    headers[i].msg_hdr.msg_iovlen = 1;
  }
  for (;;)
  {
    const int sent = ::sendmmsg(socket, headers, static_cast<unsigned int>(count), udp_send_flags);
    if (sent >= 0)
    {
      return sent;
    }
    if (errno == EINTR)
    {
      continue;
    }
    return errc_from_errno(errno);
  }
#else
  std::size_t sent = 0;
  for (; sent < count; ++sent)
  {
    const auto result = socket_sendto(socket, messages[sent].bytes, messages[sent].to, messages[sent].to_length);
    if (result < 0)
    {
      return sent == 0 ? result : static_cast<std::int64_t>(sent);
    }
  }
  return static_cast<std::int64_t>(sent);
#endif
}

[[nodiscard]] inline udp_control_t udp_parse_control(const udp_message_t &message) noexcept
{
  udp_control_t out;
  if (message.control == nullptr || message.control_length == 0)
  {
    return out;
  }
#if defined(_WIN32)
  WSAMSG header = {};
  header.Control.buf = reinterpret_cast<CHAR *>(message.control);
  header.Control.len = static_cast<ULONG>(message.control_length);
  for (WSACMSGHDR *entry = WSA_CMSG_FIRSTHDR(&header); entry != nullptr; entry = WSA_CMSG_NXTHDR(&header, entry))
  {
#if defined(IP_ECN) && defined(IPV6_ECN)
    const bool is_ecn = (entry->cmsg_level == IPPROTO_IP && entry->cmsg_type == IP_ECN) || (entry->cmsg_level == IPPROTO_IPV6 && entry->cmsg_type == IPV6_ECN);
    if (is_ecn && entry->cmsg_len >= WSA_CMSG_LEN(sizeof(INT)))
    {
      INT value = 0;
      std::memcpy(&value, WSA_CMSG_DATA(entry), sizeof(value));
      out.ecn = static_cast<std::uint8_t>(static_cast<unsigned>(value) & 0x03u);
      continue;
    }
#endif
#if defined(UDP_COALESCED_INFO)
    if (entry->cmsg_level == IPPROTO_UDP && entry->cmsg_type == UDP_COALESCED_INFO && entry->cmsg_len >= WSA_CMSG_LEN(sizeof(DWORD)))
    {
      DWORD value = 0;
      std::memcpy(&value, WSA_CMSG_DATA(entry), sizeof(value));
      out.segment_size = static_cast<std::size_t>(value);
      continue;
    }
#endif
    if (entry->cmsg_level == IPPROTO_IP && entry->cmsg_type == IP_PKTINFO && entry->cmsg_len >= WSA_CMSG_LEN(sizeof(IN_PKTINFO)))
    {
      IN_PKTINFO info = {};
      std::memcpy(&info, WSA_CMSG_DATA(entry), sizeof(info));
      auto *local = reinterpret_cast<sockaddr_in *>(&out.local);
      if (!out.has_local || out.local.ss_family != AF_INET6)
      {
        out.local = {};
        local->sin_family = AF_INET;
        local->sin_addr = info.ipi_addr;
        out.has_local = true;
      }
      continue;
    }
    if (entry->cmsg_level == IPPROTO_IPV6 && entry->cmsg_type == IPV6_PKTINFO && entry->cmsg_len >= WSA_CMSG_LEN(sizeof(IN6_PKTINFO)))
    {
      IN6_PKTINFO info = {};
      std::memcpy(&info, WSA_CMSG_DATA(entry), sizeof(info));
      out.local = {};
      auto *local = reinterpret_cast<sockaddr_in6 *>(&out.local);
      local->sin6_family = AF_INET6;
      local->sin6_addr = info.ipi6_addr;
      local->sin6_scope_id = static_cast<ULONG>(info.ipi6_ifindex);
      out.has_local = true;
    }
  }
#else
  msghdr header = {};
  header.msg_control = message.control;
  header.msg_controllen = static_cast<decltype(header.msg_controllen)>(message.control_length);
  for (cmsghdr *entry = CMSG_FIRSTHDR(&header); entry != nullptr; entry = CMSG_NXTHDR(&header, entry))
  {
#if defined(__linux__)
    if (entry->cmsg_level == IPPROTO_UDP && entry->cmsg_type == linux_udp_gro && entry->cmsg_len >= CMSG_LEN(sizeof(int)))
    {
      int value = 0;
      std::memcpy(&value, CMSG_DATA(entry), sizeof(value));
      out.segment_size = value > 0 ? static_cast<std::size_t>(value) : 0;
      continue;
    }
#endif
    if (entry->cmsg_level == IPPROTO_IP)
    {
#if defined(IP_RECVTOS)
      const bool is_tos = entry->cmsg_type == IP_TOS || entry->cmsg_type == IP_RECVTOS;
#else
      const bool is_tos = entry->cmsg_type == IP_TOS;
#endif
      if (is_tos)
      {
        if (entry->cmsg_len >= CMSG_LEN(sizeof(int)))
        {
          int value = 0;
          std::memcpy(&value, CMSG_DATA(entry), sizeof(value));
          out.ecn = static_cast<std::uint8_t>(static_cast<unsigned>(value) & 0x03u);
        }
        else if (entry->cmsg_len >= CMSG_LEN(sizeof(std::uint8_t)))
        {
          std::uint8_t value = 0;
          std::memcpy(&value, CMSG_DATA(entry), sizeof(value));
          out.ecn = static_cast<std::uint8_t>(value & 0x03u);
        }
        continue;
      }
#if defined(IP_PKTINFO) && defined(__linux__)
      if (entry->cmsg_type == IP_PKTINFO && entry->cmsg_len >= CMSG_LEN(sizeof(in_pktinfo)))
      {
        in_pktinfo info = {};
        std::memcpy(&info, CMSG_DATA(entry), sizeof(info));
        if (!out.has_local || out.local.ss_family != AF_INET6)
        {
          out.local = {};
          auto *local = reinterpret_cast<sockaddr_in *>(&out.local);
          local->sin_family = AF_INET;
          local->sin_addr = info.ipi_addr;
          out.has_local = true;
        }
        continue;
      }
#endif
#if defined(IP_RECVDSTADDR)
      if (entry->cmsg_type == IP_RECVDSTADDR && entry->cmsg_len >= CMSG_LEN(sizeof(in_addr)))
      {
        in_addr address = {};
        std::memcpy(&address, CMSG_DATA(entry), sizeof(address));
        if (!out.has_local || out.local.ss_family != AF_INET6)
        {
          out.local = {};
          auto *local = reinterpret_cast<sockaddr_in *>(&out.local);
          local->sin_family = AF_INET;
          local->sin_addr = address;
          out.has_local = true;
        }
        continue;
      }
#endif
      continue;
    }
    if (entry->cmsg_level == IPPROTO_IPV6)
    {
#if defined(IPV6_TCLASS)
      if (entry->cmsg_type == IPV6_TCLASS && entry->cmsg_len >= CMSG_LEN(sizeof(int)))
      {
        int value = 0;
        std::memcpy(&value, CMSG_DATA(entry), sizeof(value));
        out.ecn = static_cast<std::uint8_t>(static_cast<unsigned>(value) & 0x03u);
        continue;
      }
#endif
#if defined(IPV6_PKTINFO)
      if (entry->cmsg_type == IPV6_PKTINFO && entry->cmsg_len >= CMSG_LEN(sizeof(in6_pktinfo)))
      {
        in6_pktinfo info = {};
        std::memcpy(&info, CMSG_DATA(entry), sizeof(info));
        out.local = {};
        auto *local = reinterpret_cast<sockaddr_in6 *>(&out.local);
        local->sin6_family = AF_INET6;
        local->sin6_addr = info.ipi6_addr;
        if (IN6_IS_ADDR_LINKLOCAL(&info.ipi6_addr))
        {
          local->sin6_scope_id = info.ipi6_ifindex;
        }
        out.has_local = true;
      }
#endif
    }
  }
#endif
  return out;
}

[[nodiscard]] inline int udp_set_int_option(native_socket_t socket, int level, int name, int value) noexcept
{
#if defined(_WIN32)
  const DWORD option = static_cast<DWORD>(value);
  return socket_set_option(socket, level, name, &option, static_cast<int>(sizeof(option)));
#else
  return socket_set_option(socket, level, name, &value, static_cast<int>(sizeof(value)));
#endif
}

[[nodiscard]] inline int udp_set_receive_ecn(native_socket_t socket, bool on) noexcept
{
  const int value = on ? 1 : 0;
#if defined(_WIN32)
#if defined(IP_RECVECN) && defined(IPV6_RECVECN)
  const int v4 = udp_set_int_option(socket, IPPROTO_IP, IP_RECVECN, value);
  const int v6 = udp_set_int_option(socket, IPPROTO_IPV6, IPV6_RECVECN, value);
#else
  (void)socket;
  (void)value;
  const int v4 = errc::not_supported;
  const int v6 = errc::not_supported;
#endif
#else
  const int v4 = udp_set_int_option(socket, IPPROTO_IP, IP_RECVTOS, value);
#if defined(IPV6_RECVTCLASS)
  const int v6 = udp_set_int_option(socket, IPPROTO_IPV6, IPV6_RECVTCLASS, value);
#else
  const int v6 = errc::not_supported;
#endif
#endif
  if (v4 < 0 && v6 < 0)
  {
    return v6 == errc::not_supported ? v4 : v6;
  }
  return 0;
}

[[nodiscard]] inline int udp_set_receive_coalesced(native_socket_t socket, std::size_t size) noexcept
{
#if defined(_WIN32)
#if defined(UDP_RECV_MAX_COALESCED_SIZE)
  return udp_set_int_option(socket, IPPROTO_UDP, UDP_RECV_MAX_COALESCED_SIZE, static_cast<int>(size));
#else
  (void)socket;
  (void)size;
  return errc::not_supported;
#endif
#elif defined(__linux__)
  return udp_set_int_option(socket, IPPROTO_UDP, linux_udp_gro, size != 0 ? 1 : 0);
#else
  (void)socket;
  return size == 0 ? 0 : errc::not_supported;
#endif
}

[[nodiscard]] inline int udp_set_receive_local_address(native_socket_t socket, bool on) noexcept
{
  const int value = on ? 1 : 0;
#if defined(_WIN32)
  const int v4 = udp_set_int_option(socket, IPPROTO_IP, IP_PKTINFO, value);
  const int v6 = udp_set_int_option(socket, IPPROTO_IPV6, IPV6_PKTINFO, value);
#else
#if defined(IP_PKTINFO) && defined(__linux__)
  const int v4 = udp_set_int_option(socket, IPPROTO_IP, IP_PKTINFO, value);
#elif defined(IP_RECVDSTADDR)
  const int v4 = udp_set_int_option(socket, IPPROTO_IP, IP_RECVDSTADDR, value);
#else
  const int v4 = errc::not_supported;
#endif
#if defined(IPV6_RECVPKTINFO)
  const int v6 = udp_set_int_option(socket, IPPROTO_IPV6, IPV6_RECVPKTINFO, value);
#else
  const int v6 = errc::not_supported;
#endif
#endif
  if (v4 < 0 && v6 < 0)
  {
    return v6 == errc::not_supported ? v4 : v6;
  }
  return 0;
}
} // namespace vio::detail
