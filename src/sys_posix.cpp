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

#if !defined(_WIN32)

#include <cerrno>
#include <climits>

#include <fcntl.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include "vio/detail/sys.h"
#include "vio/errc.h"

#if defined(MSG_NOSIGNAL)
#define VIO_SEND_FLAGS MSG_NOSIGNAL
#else
#define VIO_SEND_FLAGS 0
#endif

namespace vio::detail
{
namespace
{
socklen_t normalized_length(const sockaddr *address, int length) noexcept
{
#if !defined(__linux__)
  if (address != nullptr)
  {
    int exact = 0;
    switch (address->sa_family)
    {
    case AF_INET:
      exact = static_cast<int>(sizeof(sockaddr_in));
      break;
    case AF_INET6:
      exact = static_cast<int>(sizeof(sockaddr_in6));
      break;
    case AF_UNIX:
      exact = static_cast<int>(sizeof(sockaddr_un));
      break;
    default:
      break;
    }
    if (exact > 0 && length > exact)
      length = exact;
  }
#else
  (void)address;
#endif
  return static_cast<socklen_t>(length);
}

std::size_t transfer_size(std::size_t size) noexcept
{
#if !defined(__linux__)
  constexpr std::size_t max_transfer = INT_MAX;
  if (size > max_transfer)
    return max_transfer;
#endif
  return size;
}
} // namespace

int last_socket_error() noexcept
{
  return errc_from_errno(errno);
}

int socket_set_nonblocking(native_socket_t socket) noexcept
{
#if defined(__linux__)
  int flags = ::fcntl(socket, F_GETFL, 0);
  if (flags < 0 || ::fcntl(socket, F_SETFL, flags | O_NONBLOCK) < 0)
    return errc_from_errno(errno);
#else
  int nonblocking = 1;
  if (::ioctl(socket, FIONBIO, &nonblocking) < 0)
    return errc_from_errno(errno);
#endif
  int fd_flags = ::fcntl(socket, F_GETFD, 0);
  if (fd_flags < 0 || ::fcntl(socket, F_SETFD, fd_flags | FD_CLOEXEC) < 0)
    return errc_from_errno(errno);
#if defined(SO_NOSIGPIPE)
  int one = 1;
  ::setsockopt(socket, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
  return 0;
}

int socket_open(int family, int type, int protocol, native_socket_t &out) noexcept
{
#if defined(SOCK_NONBLOCK) && defined(SOCK_CLOEXEC)
  int fd = ::socket(family, type | SOCK_NONBLOCK | SOCK_CLOEXEC, protocol);
  if (fd < 0)
    return errc_from_errno(errno);
#if defined(SO_NOSIGPIPE)
  int one = 1;
  ::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
#else
  int fd = ::socket(family, type, protocol);
  if (fd < 0)
    return errc_from_errno(errno);
  if (int result = socket_set_nonblocking(fd); result < 0)
  {
    ::close(fd);
    return result;
  }
#endif
  out = fd;
  return 0;
}

int socket_close(native_socket_t socket) noexcept
{
  if (socket < 0)
    return 0;
  if (::close(socket) != 0 && errno != EINTR)
    return errc_from_errno(errno);
  return 0;
}

int socket_bind(native_socket_t socket, const sockaddr *address, int length) noexcept
{
  if (::bind(socket, address, normalized_length(address, length)) != 0)
    return errc_from_errno(errno);
  return 0;
}

int socket_listen(native_socket_t socket, int backlog) noexcept
{
  if (::listen(socket, backlog) != 0)
    return errc_from_errno(errno);
  return 0;
}

int socket_accept(native_socket_t socket, native_socket_t &out, sockaddr_storage *address, int *length) noexcept
{
  socklen_t address_length = sizeof(sockaddr_storage);
  for (;;)
  {
#if defined(__linux__)
    int fd = ::accept4(socket, reinterpret_cast<sockaddr *>(address), address ? &address_length : nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
#else
    int fd = ::accept(socket, reinterpret_cast<sockaddr *>(address), address ? &address_length : nullptr);
#endif
    if (fd >= 0)
    {
#if !defined(__linux__)
      if (int result = socket_set_nonblocking(fd); result < 0)
      {
        ::close(fd);
        return result;
      }
#endif
      out = fd;
      if (length)
        *length = static_cast<int>(address_length);
      return 0;
    }
    if (errno == EINTR)
      continue;
    return errc_from_errno(errno);
  }
}

int socket_connect(native_socket_t socket, const sockaddr *address, int length) noexcept
{
  if (::connect(socket, address, normalized_length(address, length)) == 0)
    return 0;
  if (errno == EINPROGRESS || errno == EINTR)
    return errc::in_progress;
  return errc_from_errno(errno);
}

int socket_pending_error(native_socket_t socket) noexcept
{
  int error = 0;
  socklen_t length = sizeof(error);
  if (::getsockopt(socket, SOL_SOCKET, SO_ERROR, &error, &length) != 0)
    return errc_from_errno(errno);
  return errc_from_errno(error);
}

int socket_shutdown_write(native_socket_t socket) noexcept
{
  if (::shutdown(socket, SHUT_WR) != 0)
    return errc_from_errno(errno);
  return 0;
}

int socket_name(native_socket_t socket, sockaddr_storage &address, int &length) noexcept
{
  socklen_t address_length = sizeof(address);
  if (::getsockname(socket, reinterpret_cast<sockaddr *>(&address), &address_length) != 0)
    return errc_from_errno(errno);
  length = static_cast<int>(address_length);
  return 0;
}

int socket_peer_name(native_socket_t socket, sockaddr_storage &address, int &length) noexcept
{
  socklen_t address_length = sizeof(address);
  if (::getpeername(socket, reinterpret_cast<sockaddr *>(&address), &address_length) != 0)
    return errc_from_errno(errno);
  length = static_cast<int>(address_length);
  return 0;
}

int socket_set_option(native_socket_t socket, int level, int name, const void *value, int length) noexcept
{
  if (::setsockopt(socket, level, name, value, static_cast<socklen_t>(length)) != 0)
    return errc_from_errno(errno);
  return 0;
}

int socket_get_option(native_socket_t socket, int level, int name, void *value, int &length) noexcept
{
  socklen_t option_length = static_cast<socklen_t>(length);
  if (::getsockopt(socket, level, name, value, &option_length) != 0)
    return errc_from_errno(errno);
  length = static_cast<int>(option_length);
  return 0;
}

std::int64_t socket_recv(native_socket_t socket, mutable_bytes_t buffer) noexcept
{
  for (;;)
  {
    auto count = ::recv(socket, buffer.data(), transfer_size(buffer.size()), 0);
    if (count >= 0)
      return count;
    if (errno == EINTR)
      continue;
    return errc_from_errno(errno);
  }
}

std::int64_t socket_send(native_socket_t socket, const_bytes_t buffer) noexcept
{
  for (;;)
  {
    auto count = ::send(socket, buffer.data(), transfer_size(buffer.size()), VIO_SEND_FLAGS);
    if (count >= 0)
      return count;
    if (errno == EINTR)
      continue;
    return errc_from_errno(errno);
  }
}

std::int64_t socket_sendv(native_socket_t socket, const const_bytes_t *buffers, std::size_t count) noexcept
{
  constexpr std::size_t max_vectors = 64;
  iovec vectors[max_vectors];
  std::size_t limit = count < max_vectors ? count : max_vectors;
  std::size_t used = 0;
#if defined(__linux__)
  for (; used < limit; ++used)
  {
    vectors[used].iov_base = const_cast<std::byte *>(buffers[used].data());
    vectors[used].iov_len = buffers[used].size();
  }
#else
  std::size_t room = transfer_size(SIZE_MAX);
  for (; used < limit && room > 0; ++used)
  {
    std::size_t size = buffers[used].size() < room ? buffers[used].size() : room;
    vectors[used].iov_base = const_cast<std::byte *>(buffers[used].data());
    vectors[used].iov_len = size;
    room -= size;
  }
#endif
  msghdr message{};
  message.msg_iov = vectors;
  message.msg_iovlen = static_cast<decltype(message.msg_iovlen)>(used);
  for (;;)
  {
    auto sent = ::sendmsg(socket, &message, VIO_SEND_FLAGS);
    if (sent >= 0)
      return sent;
    if (errno == EINTR)
      continue;
    return errc_from_errno(errno);
  }
}

std::int64_t socket_recvfrom(native_socket_t socket, mutable_bytes_t buffer, sockaddr_storage *from, int *from_length) noexcept
{
  socklen_t length = sizeof(sockaddr_storage);
  for (;;)
  {
    auto count = ::recvfrom(socket, buffer.data(), transfer_size(buffer.size()), 0, reinterpret_cast<sockaddr *>(from), from ? &length : nullptr);
    if (count >= 0)
    {
      if (from_length)
        *from_length = static_cast<int>(length);
      return count;
    }
    if (errno == EINTR)
      continue;
    return errc_from_errno(errno);
  }
}

std::int64_t socket_sendto(native_socket_t socket, const_bytes_t buffer, const sockaddr *to, int to_length) noexcept
{
  for (;;)
  {
    auto count = ::sendto(socket, buffer.data(), transfer_size(buffer.size()), VIO_SEND_FLAGS, to, normalized_length(to, to_length));
    if (count >= 0)
      return count;
    if (errno == EINTR)
      continue;
    return errc_from_errno(errno);
  }
}
} // namespace vio::detail

#if defined(VIO_INTERNAL_TESTS)
#include <doctest/doctest.h>

#include <cstring>
#include <filesystem>
#include <span>
#include <string>

#include "vio/detail/sys_file.h"

namespace vio::detail
{
TEST_CASE("sys_posix: positional reads and writes leave the file position where it was")
{
  std::string path = (std::filesystem::temp_directory_path() / "vio-position-XXXXXX").string();
  native_file_t file = invalid_native_file;
  REQUIRE(fs_mkstemp(path, file) == 0);
  auto text = [](const char *value) { return std::span<const std::byte>(reinterpret_cast<const std::byte *>(value), std::strlen(value)); };
  std::byte buffer[16] = {};
  CHECK(fs_write(file, text("0123456789"), -1) == 10);
  CHECK(fs_read(file, std::span<std::byte>(buffer, 3), 7) == 3);
  CHECK(fs_read(file, std::span<std::byte>(buffer, 3), 0) == 3);
  CHECK(fs_write(file, text("AB"), 2) == 2);
  CHECK(fs_read(file, buffer, -1) == 0);
  CHECK(fs_write(file, text("Z"), -1) == 1);
  CHECK(fs_read(file, std::span<std::byte>(buffer, 11), 0) == 11);
  CHECK(std::string(reinterpret_cast<const char *>(buffer), 11) == "01AB456789Z");
  CHECK(fs_read(file, buffer, -1) == 0);
  CHECK(fs_close(file) == 0);
  CHECK(fs_unlink(path) == 0);
}
} // namespace vio::detail
#endif

#endif
