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

#include <cstddef>
#include <cstdint>
#include <span>

#include "vio/detail/native.h"
#include "vio/vio_export.h"

namespace vio::detail
{
using const_bytes_t = std::span<const std::byte>;
using mutable_bytes_t = std::span<std::byte>;

VIO_EXPORT int errc_from_errno(int error) noexcept;
VIO_EXPORT int errc_from_gai(int error) noexcept;
#if defined(_WIN32)
VIO_EXPORT int errc_from_win32(unsigned long error) noexcept;
VIO_EXPORT int errc_from_wsa(int error) noexcept;
VIO_EXPORT void ensure_winsock() noexcept;
#endif
VIO_EXPORT int last_socket_error() noexcept;

VIO_EXPORT int socket_open(int family, int type, int protocol, native_socket_t &out) noexcept;
VIO_EXPORT int socket_close(native_socket_t socket) noexcept;
VIO_EXPORT int socket_set_nonblocking(native_socket_t socket) noexcept;
VIO_EXPORT int socket_bind(native_socket_t socket, const sockaddr *address, int length) noexcept;
VIO_EXPORT int socket_listen(native_socket_t socket, int backlog) noexcept;
VIO_EXPORT int socket_accept(native_socket_t socket, native_socket_t &out, sockaddr_storage *address, int *length) noexcept;
VIO_EXPORT int socket_connect(native_socket_t socket, const sockaddr *address, int length) noexcept;
VIO_EXPORT int socket_pending_error(native_socket_t socket) noexcept;
VIO_EXPORT int socket_shutdown_write(native_socket_t socket) noexcept;
VIO_EXPORT int socket_name(native_socket_t socket, sockaddr_storage &address, int &length) noexcept;
VIO_EXPORT int socket_peer_name(native_socket_t socket, sockaddr_storage &address, int &length) noexcept;
VIO_EXPORT int socket_set_option(native_socket_t socket, int level, int name, const void *value, int length) noexcept;
VIO_EXPORT int socket_get_option(native_socket_t socket, int level, int name, void *value, int &length) noexcept;
VIO_EXPORT std::int64_t socket_recv(native_socket_t socket, mutable_bytes_t buffer) noexcept;
VIO_EXPORT std::int64_t socket_send(native_socket_t socket, const_bytes_t buffer) noexcept;
VIO_EXPORT std::int64_t socket_sendv(native_socket_t socket, const const_bytes_t *buffers, std::size_t count) noexcept;
VIO_EXPORT std::int64_t socket_recvfrom(native_socket_t socket, mutable_bytes_t buffer, sockaddr_storage *from, int *from_length) noexcept;
VIO_EXPORT std::int64_t socket_sendto(native_socket_t socket, const_bytes_t buffer, const sockaddr *to, int to_length) noexcept;
} // namespace vio::detail
