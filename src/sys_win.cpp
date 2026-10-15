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


#if defined(_WIN32)

#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>

#include "vio/detail/sys.h"
#include "vio/errc.h"

namespace vio::detail
{
namespace
{
constexpr DWORD sio_udp_connreset = 0x9800000C;
constexpr DWORD sio_udp_netreset = 0x9800000F;
constexpr DWORD no_handle_inherit_flag = 0x80;
constexpr std::size_t max_send_vectors = 64;

int translate(unsigned long error) noexcept
{
  switch (error)
  {
  case 0: return 0;
  case ERROR_INVALID_FUNCTION: return errc::is_a_directory;
  case ERROR_FILE_NOT_FOUND: return errc::no_such_file;
  case ERROR_PATH_NOT_FOUND: return errc::no_such_file;
  case ERROR_TOO_MANY_OPEN_FILES: return errc::too_many_open_files;
  case ERROR_ACCESS_DENIED: return errc::operation_not_permitted;
  case ERROR_INVALID_HANDLE: return errc::bad_descriptor;
  case ERROR_NOT_ENOUGH_MEMORY: return errc::out_of_memory;
  case ERROR_INVALID_DATA: return errc::invalid_argument;
  case ERROR_OUTOFMEMORY: return errc::out_of_memory;
  case ERROR_INVALID_DRIVE: return errc::no_such_file;
  case ERROR_NOT_SAME_DEVICE: return errc::cross_device_link;
  case ERROR_WRITE_PROTECT: return errc::read_only_file_system;
  case ERROR_CRC: return errc::io_error;
  case ERROR_GEN_FAILURE: return errc::io_error;
  case ERROR_SHARING_VIOLATION: return errc::resource_busy_or_locked;
  case ERROR_LOCK_VIOLATION: return errc::resource_busy_or_locked;
  case ERROR_HANDLE_EOF: return errc::eof;
  case ERROR_HANDLE_DISK_FULL: return errc::no_space;
  case ERROR_NOT_SUPPORTED: return errc::not_supported;
  case ERROR_DEV_NOT_EXIST: return errc::no_such_device;
  case ERROR_NETNAME_DELETED: return errc::connection_reset;
  case ERROR_FILE_EXISTS: return errc::file_exists;
  case ERROR_CANNOT_MAKE: return errc::no_space;
  case ERROR_INVALID_PARAMETER: return errc::invalid_argument;
  case ERROR_BROKEN_PIPE: return errc::eof;
  case ERROR_OPEN_FAILED: return errc::io_error;
  case ERROR_BUFFER_OVERFLOW: return errc::name_too_long;
  case ERROR_DISK_FULL: return errc::no_space;
  case ERROR_SEM_TIMEOUT: return errc::timed_out;
  case ERROR_INSUFFICIENT_BUFFER: return errc::invalid_argument;
  case ERROR_INVALID_NAME: return errc::no_such_file;
  case ERROR_MOD_NOT_FOUND: return errc::no_such_file;
  case ERROR_NEGATIVE_SEEK: return errc::invalid_argument;
  case ERROR_SEEK_ON_DEVICE: return errc::invalid_seek;
  case ERROR_DIR_NOT_EMPTY: return errc::directory_not_empty;
  case ERROR_SIGNAL_REFUSED: return errc::io_error;
  case ERROR_BAD_PATHNAME: return errc::no_such_file;
  case ERROR_BUSY: return errc::busy;
  case ERROR_ALREADY_EXISTS: return errc::file_exists;
  case ERROR_ENVVAR_NOT_FOUND: return errc::no_such_file;
  case ERROR_NO_SIGNAL_SENT: return errc::io_error;
  case ERROR_FILENAME_EXCED_RANGE: return errc::name_too_long;
  case ERROR_FILE_TOO_LARGE: return errc::file_too_large;
  case ERROR_BAD_PIPE: return errc::broken_pipe;
  case ERROR_PIPE_BUSY: return errc::busy;
  case ERROR_NO_DATA: return errc::broken_pipe;
  case ERROR_PIPE_NOT_CONNECTED: return errc::broken_pipe;
  case WAIT_TIMEOUT: return errc::timed_out;
  case ERROR_DIRECTORY: return errc::no_such_file;
  case ERROR_EA_TABLE_FULL: return errc::no_space;
  case ERROR_ELEVATION_REQUIRED: return errc::permission_denied;
  case ERROR_OPERATION_ABORTED: return errc::canceled;
  case ERROR_IO_PENDING: return errc::in_progress;
  case ERROR_NOACCESS: return errc::bad_address;
  case ERROR_INVALID_FLAGS: return errc::bad_descriptor;
  case ERROR_END_OF_MEDIA: return errc::no_space;
  case ERROR_FILEMARK_DETECTED: return errc::io_error;
  case ERROR_BEGINNING_OF_MEDIA: return errc::io_error;
  case ERROR_SETMARK_DETECTED: return errc::io_error;
  case ERROR_NO_DATA_DETECTED: return errc::io_error;
  case ERROR_INVALID_BLOCK_LENGTH: return errc::io_error;
  case ERROR_BUS_RESET: return errc::io_error;
  case ERROR_NO_UNICODE_TRANSLATION: return errc::invalid_argument;
  case ERROR_IO_DEVICE: return errc::io_error;
  case ERROR_EOM_OVERFLOW: return errc::io_error;
  case ERROR_TOO_MANY_LINKS: return errc::too_many_links;
  case ERROR_DEVICE_REQUIRES_CLEANING: return errc::io_error;
  case ERROR_DEVICE_DOOR_OPEN: return errc::io_error;
  case ERROR_CONNECTION_REFUSED: return errc::connection_refused;
  case ERROR_ADDRESS_ALREADY_ASSOCIATED: return errc::address_in_use;
  case ERROR_NETWORK_UNREACHABLE: return errc::network_unreachable;
  case ERROR_HOST_UNREACHABLE: return errc::host_unreachable;
  case ERROR_CONNECTION_ABORTED: return errc::connection_aborted;
  case ERROR_PRIVILEGE_NOT_HELD: return errc::operation_not_permitted;
  case ERROR_DISK_CORRUPT: return errc::io_error;
  case ERROR_TIMEOUT: return errc::timed_out;
  case ERROR_SYMLINK_NOT_SUPPORTED: return errc::invalid_argument;
  case ERROR_CANT_ACCESS_FILE: return errc::permission_denied;
  case ERROR_CANT_RESOLVE_FILENAME: return errc::too_many_symbolic_links;
  case ERROR_NOT_CONNECTED: return errc::not_connected;
  case ERROR_INVALID_REPARSE_DATA: return errc::no_such_file;
  case WSAEINTR: return errc::interrupted;
  case WSAEBADF: return errc::bad_descriptor;
  case WSAEACCES: return errc::permission_denied;
  case WSAEFAULT: return errc::bad_address;
  case WSAEINVAL: return errc::invalid_argument;
  case WSAEMFILE: return errc::too_many_open_files;
  case WSAEWOULDBLOCK: return errc::again;
  case WSAEINPROGRESS: return errc::in_progress;
  case WSAEALREADY: return errc::already_in_progress;
  case WSAENOTSOCK: return errc::not_a_socket;
  case WSAEDESTADDRREQ: return errc::destination_address_required;
  case WSAEMSGSIZE: return errc::message_too_long;
  case WSAEPROTOTYPE: return errc::protocol_not_supported;
  case WSAENOPROTOOPT: return errc::no_protocol_option;
  case WSAEPROTONOSUPPORT: return errc::protocol_not_supported;
  case WSAESOCKTNOSUPPORT: return errc::socket_type_not_supported;
  case WSAEOPNOTSUPP: return errc::not_supported;
  case WSAEPFNOSUPPORT: return errc::address_family_not_supported;
  case WSAEAFNOSUPPORT: return errc::address_family_not_supported;
  case WSAEADDRINUSE: return errc::address_in_use;
  case WSAEADDRNOTAVAIL: return errc::address_not_available;
  case WSAENETDOWN: return errc::network_down;
  case WSAENETUNREACH: return errc::network_unreachable;
  case WSAENETRESET: return errc::connection_reset;
  case WSAECONNABORTED: return errc::connection_aborted;
  case WSAECONNRESET: return errc::connection_reset;
  case WSAENOBUFS: return errc::no_buffer_space;
  case WSAEISCONN: return errc::already_connected;
  case WSAENOTCONN: return errc::not_connected;
  case WSAESHUTDOWN: return errc::broken_pipe;
  case WSAETIMEDOUT: return errc::timed_out;
  case WSAECONNREFUSED: return errc::connection_refused;
  case WSAELOOP: return errc::too_many_symbolic_links;
  case WSAENAMETOOLONG: return errc::name_too_long;
  case WSAEHOSTDOWN: return errc::host_unreachable;
  case WSAEHOSTUNREACH: return errc::host_unreachable;
  case WSAENOTEMPTY: return errc::directory_not_empty;
  case WSAEDQUOT: return errc::no_space;
  case WSASYSNOTREADY: return errc::network_down;
  case WSAVERNOTSUPPORTED: return errc::not_supported;
  case WSANOTINITIALISED: return errc::invalid_argument;
  case WSAEDISCON: return errc::eof;
  case WSAECANCELLED: return errc::canceled;
  case WSA_E_CANCELLED: return errc::canceled;
  case WSATYPE_NOT_FOUND: return errc::dns_service;
  case WSAHOST_NOT_FOUND: return errc::dns_no_name;
  case WSATRY_AGAIN: return errc::dns_again;
  case WSANO_RECOVERY: return errc::dns_fail;
  case WSANO_DATA: return errc::dns_no_data;
  default: return errc::unknown;
  }
}

int wsa_failure() noexcept
{
  return translate(static_cast<unsigned long>(::WSAGetLastError()));
}

int clamp_length(std::size_t size) noexcept
{
  return size > static_cast<std::size_t>(INT_MAX) ? INT_MAX : static_cast<int>(size);
}

int normalized_length(const sockaddr *address, int length) noexcept
{
  if (address == nullptr)
    return length;
  int exact = 0;
  if (address->sa_family == AF_INET)
    exact = static_cast<int>(sizeof(sockaddr_in));
  else if (address->sa_family == AF_INET6)
    exact = static_cast<int>(sizeof(sockaddr_in6));
  if (exact > 0 && length > exact)
    return exact;
  return length;
}

const sockaddr *routable_address(const sockaddr *address, int &length, sockaddr_storage &storage) noexcept
{
  if (address == nullptr)
    return address;
  if (address->sa_family == AF_INET && length >= static_cast<int>(sizeof(sockaddr_in)))
  {
    sockaddr_in in{};
    std::memcpy(&in, address, sizeof(in));
    if (in.sin_addr.s_addr != htonl(INADDR_ANY))
      return address;
    in.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    std::memcpy(&storage, &in, sizeof(in));
    length = static_cast<int>(sizeof(in));
    return reinterpret_cast<const sockaddr *>(&storage);
  }
  if (address->sa_family == AF_INET6 && length >= static_cast<int>(sizeof(sockaddr_in6)))
  {
    sockaddr_in6 in6{};
    std::memcpy(&in6, address, sizeof(in6));
    unsigned char bytes[16] = {};
    static_assert(sizeof(in6.sin6_addr) == sizeof(bytes));
    if (std::memcmp(&in6.sin6_addr, bytes, sizeof(bytes)) != 0)
      return address;
    bytes[15] = 1;
    std::memcpy(&in6.sin6_addr, bytes, sizeof(bytes));
    std::memcpy(&storage, &in6, sizeof(in6));
    length = static_cast<int>(sizeof(in6));
    return reinterpret_cast<const sockaddr *>(&storage);
  }
  return address;
}

void ignore_datagram_resets(native_socket_t socket) noexcept
{
  BOOL off = FALSE;
  DWORD returned = 0;
  ::WSAIoctl(socket, sio_udp_connreset, &off, sizeof(off), nullptr, 0, &returned, nullptr, nullptr);
  ::WSAIoctl(socket, sio_udp_netreset, &off, sizeof(off), nullptr, 0, &returned, nullptr, nullptr);
}

std::int64_t truncated_datagram(mutable_bytes_t buffer) noexcept
{
  return clamp_length(buffer.size());
}
} // namespace

int errc_from_win32(unsigned long error) noexcept
{
  return translate(error);
}

int errc_from_wsa(int error) noexcept
{
  if (error < 0)
    return errc::unknown;
  return translate(static_cast<unsigned long>(error));
}

void ensure_winsock() noexcept
{
  static std::once_flag once;
  std::call_once(once, [] {
    WSADATA data{};
    int result = ::WSAStartup(MAKEWORD(2, 2), &data);
    if (result != 0)
    {
      std::fprintf(stderr, "vio: WSAStartup failed (%d)\n", result);
      std::abort();
    }
    if (LOBYTE(data.wVersion) != 2 || HIBYTE(data.wVersion) != 2)
    {
      std::fprintf(stderr, "vio: Winsock 2.2 is not available (got %d.%d)\n", LOBYTE(data.wVersion), HIBYTE(data.wVersion));
      std::abort();
    }
  });
}

int last_socket_error() noexcept
{
  return wsa_failure();
}

int socket_set_nonblocking(native_socket_t socket) noexcept
{
  u_long nonblocking = 1;
  if (::ioctlsocket(socket, FIONBIO, &nonblocking) != 0)
    return wsa_failure();
  if (!::SetHandleInformation(reinterpret_cast<HANDLE>(socket), HANDLE_FLAG_INHERIT, 0))
    return translate(::GetLastError());
  return 0;
}

int socket_open(int family, int type, int protocol, native_socket_t &out) noexcept
{
  ensure_winsock();
  SOCKET socket = ::WSASocketW(family, type, protocol, nullptr, 0, WSA_FLAG_OVERLAPPED | no_handle_inherit_flag);
  bool inheritable = false;
  if (socket == INVALID_SOCKET)
  {
    int error = ::WSAGetLastError();
    if (error != WSAEINVAL)
      return translate(static_cast<unsigned long>(error));
    socket = ::WSASocketW(family, type, protocol, nullptr, 0, WSA_FLAG_OVERLAPPED);
    if (socket == INVALID_SOCKET)
      return wsa_failure();
    inheritable = true;
  }
  u_long nonblocking = 1;
  if (::ioctlsocket(socket, FIONBIO, &nonblocking) != 0)
  {
    int result = wsa_failure();
    ::closesocket(socket);
    return result;
  }
  if (inheritable && !::SetHandleInformation(reinterpret_cast<HANDLE>(socket), HANDLE_FLAG_INHERIT, 0))
  {
    int result = translate(::GetLastError());
    ::closesocket(socket);
    return result;
  }
  if (type == SOCK_DGRAM)
    ignore_datagram_resets(socket);
  out = socket;
  return 0;
}

int socket_close(native_socket_t socket) noexcept
{
  if (socket == INVALID_SOCKET)
    return 0;
  if (::closesocket(socket) != 0)
    return wsa_failure();
  return 0;
}

int socket_bind(native_socket_t socket, const sockaddr *address, int length) noexcept
{
  if (::bind(socket, address, normalized_length(address, length)) != 0)
    return wsa_failure();
  return 0;
}

int socket_listen(native_socket_t socket, int backlog) noexcept
{
  if (::listen(socket, backlog) != 0)
    return wsa_failure();
  return 0;
}

int socket_accept(native_socket_t socket, native_socket_t &out, sockaddr_storage *address, int *length) noexcept
{
  int address_length = static_cast<int>(sizeof(sockaddr_storage));
  SOCKET accepted = ::accept(socket, reinterpret_cast<sockaddr *>(address), address ? &address_length : nullptr);
  if (accepted == INVALID_SOCKET)
    return wsa_failure();
  if (int result = socket_set_nonblocking(accepted); result < 0)
  {
    ::closesocket(accepted);
    return result;
  }
  out = accepted;
  if (length)
    *length = address ? address_length : 0;
  return 0;
}

int socket_connect(native_socket_t socket, const sockaddr *address, int length) noexcept
{
  sockaddr_storage storage;
  length = normalized_length(address, length);
  const sockaddr *target = routable_address(address, length, storage);
  if (::connect(socket, target, length) == 0)
    return 0;
  int error = ::WSAGetLastError();
  if (error == WSAEWOULDBLOCK || error == WSAEINPROGRESS)
    return errc::in_progress;
  return translate(static_cast<unsigned long>(error));
}

int socket_pending_error(native_socket_t socket) noexcept
{
  int error = 0;
  int length = static_cast<int>(sizeof(error));
  if (::getsockopt(socket, SOL_SOCKET, SO_ERROR, reinterpret_cast<char *>(&error), &length) != 0)
    return wsa_failure();
  return errc_from_wsa(error);
}

int socket_shutdown_write(native_socket_t socket) noexcept
{
  if (::shutdown(socket, SD_SEND) != 0)
    return wsa_failure();
  return 0;
}

int socket_name(native_socket_t socket, sockaddr_storage &address, int &length) noexcept
{
  int address_length = static_cast<int>(sizeof(address));
  if (::getsockname(socket, reinterpret_cast<sockaddr *>(&address), &address_length) != 0)
    return wsa_failure();
  length = address_length;
  return 0;
}

int socket_peer_name(native_socket_t socket, sockaddr_storage &address, int &length) noexcept
{
  int address_length = static_cast<int>(sizeof(address));
  if (::getpeername(socket, reinterpret_cast<sockaddr *>(&address), &address_length) != 0)
    return wsa_failure();
  length = address_length;
  return 0;
}

int socket_set_option(native_socket_t socket, int level, int name, const void *value, int length) noexcept
{
  if (::setsockopt(socket, level, name, static_cast<const char *>(value), length) != 0)
    return wsa_failure();
  return 0;
}

int socket_get_option(native_socket_t socket, int level, int name, void *value, int &length) noexcept
{
  int option_length = length;
  if (::getsockopt(socket, level, name, static_cast<char *>(value), &option_length) != 0)
    return wsa_failure();
  length = option_length;
  return 0;
}

std::int64_t socket_recv(native_socket_t socket, mutable_bytes_t buffer) noexcept
{
  int count = ::recv(socket, reinterpret_cast<char *>(buffer.data()), clamp_length(buffer.size()), 0);
  if (count >= 0)
    return count;
  int error = ::WSAGetLastError();
  if (error == WSAEMSGSIZE)
    return truncated_datagram(buffer);
  if (error == WSAECONNABORTED)
    return errc::connection_reset;
  return translate(static_cast<unsigned long>(error));
}

std::int64_t socket_send(native_socket_t socket, const_bytes_t buffer) noexcept
{
  int count = ::send(socket, reinterpret_cast<const char *>(buffer.data()), clamp_length(buffer.size()), 0);
  if (count >= 0)
    return count;
  return wsa_failure();
}

std::int64_t socket_sendv(native_socket_t socket, const const_bytes_t *buffers, std::size_t count) noexcept
{
  WSABUF vectors[max_send_vectors];
  std::size_t limit = count < max_send_vectors ? count : max_send_vectors;
  std::size_t room = static_cast<std::size_t>(INT_MAX);
  DWORD used = 0;
  for (std::size_t i = 0; i < limit && room > 0; ++i)
  {
    std::size_t size = buffers[i].size() < room ? buffers[i].size() : room;
    vectors[used].buf = reinterpret_cast<CHAR *>(const_cast<std::byte *>(buffers[i].data()));
    vectors[used].len = static_cast<ULONG>(size);
    room -= size;
    ++used;
  }
  if (used == 0)
    return 0;
  DWORD sent = 0;
  if (::WSASend(socket, vectors, used, &sent, 0, nullptr, nullptr) != 0)
    return wsa_failure();
  return static_cast<std::int64_t>(sent);
}

std::int64_t socket_recvfrom(native_socket_t socket, mutable_bytes_t buffer, sockaddr_storage *from, int *from_length) noexcept
{
  int length = static_cast<int>(sizeof(sockaddr_storage));
  int count = ::recvfrom(socket, reinterpret_cast<char *>(buffer.data()), clamp_length(buffer.size()), 0, reinterpret_cast<sockaddr *>(from), from ? &length : nullptr);
  std::int64_t result = count;
  if (count < 0)
  {
    int error = ::WSAGetLastError();
    if (error != WSAEMSGSIZE)
      return translate(static_cast<unsigned long>(error));
    result = truncated_datagram(buffer);
  }
  if (from_length)
    *from_length = from ? length : 0;
  return result;
}

std::int64_t socket_sendto(native_socket_t socket, const_bytes_t buffer, const sockaddr *to, int to_length) noexcept
{
  sockaddr_storage storage;
  to_length = normalized_length(to, to_length);
  const sockaddr *target = routable_address(to, to_length, storage);
  int count = ::sendto(socket, reinterpret_cast<const char *>(buffer.data()), clamp_length(buffer.size()), 0, target, to_length);
  if (count >= 0)
    return count;
  return wsa_failure();
}
} // namespace vio::detail

#if defined(VIO_INTERNAL_TESTS)
#include <doctest/doctest.h>

#include <chrono>
#include <filesystem>
#include <span>
#include <string>
#include <thread>

#include "vio/detail/sys_file.h"

namespace vio::detail
{
namespace
{
struct sys_win_pair_t
{
  SOCKET client = INVALID_SOCKET;
  SOCKET server = INVALID_SOCKET;
};

sockaddr_in sys_win_loopback(unsigned long address = INADDR_LOOPBACK)
{
  sockaddr_in result{};
  result.sin_family = AF_INET;
  result.sin_addr.s_addr = htonl(address);
  return result;
}

SOCKET sys_win_listener(sockaddr_in &bound)
{
  SOCKET listener = INVALID_SOCKET;
  REQUIRE(socket_open(AF_INET, SOCK_STREAM, IPPROTO_TCP, listener) == 0);
  auto address = sys_win_loopback();
  REQUIRE(socket_bind(listener, reinterpret_cast<const sockaddr *>(&address), static_cast<int>(sizeof(address))) == 0);
  REQUIRE(socket_listen(listener, 16) == 0);
  sockaddr_storage storage{};
  int length = static_cast<int>(sizeof(storage));
  REQUIRE(socket_name(listener, storage, length) == 0);
  REQUIRE(length == static_cast<int>(sizeof(sockaddr_in)));
  std::memcpy(&bound, &storage, sizeof(bound));
  return listener;
}

int sys_win_accept(SOCKET listener, SOCKET &accepted)
{
  const auto give_up = std::chrono::steady_clock::now() + std::chrono::seconds(5);
  for (;;)
  {
    const int result = socket_accept(listener, accepted, nullptr, nullptr);
    if (result != errc::again || std::chrono::steady_clock::now() > give_up)
      return result;
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
}

sys_win_pair_t sys_win_connect(const sockaddr_in &target, SOCKET listener)
{
  sys_win_pair_t pair;
  REQUIRE(socket_open(AF_INET, SOCK_STREAM, IPPROTO_TCP, pair.client) == 0);
  const int connected = socket_connect(pair.client, reinterpret_cast<const sockaddr *>(&target), static_cast<int>(sizeof(target)));
  REQUIRE((connected == 0 || connected == errc::in_progress));
  REQUIRE(sys_win_accept(listener, pair.server) == 0);
  const auto give_up = std::chrono::steady_clock::now() + std::chrono::seconds(5);
  for (;;)
  {
    sockaddr_storage peer{};
    int peer_length = static_cast<int>(sizeof(peer));
    if (socket_peer_name(pair.client, peer, peer_length) == 0)
      break;
    REQUIRE(std::chrono::steady_clock::now() < give_up);
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  return pair;
}

std::int64_t sys_win_receive(SOCKET socket, mutable_bytes_t buffer, sockaddr_storage *from = nullptr, int *from_length = nullptr)
{
  const auto give_up = std::chrono::steady_clock::now() + std::chrono::seconds(5);
  for (;;)
  {
    const auto result = from ? socket_recvfrom(socket, buffer, from, from_length) : socket_recv(socket, buffer);
    if (result != errc::again || std::chrono::steady_clock::now() > give_up)
      return result;
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
}

bool sys_win_inheritable(SOCKET socket)
{
  DWORD flags = 0;
  REQUIRE(::GetHandleInformation(reinterpret_cast<HANDLE>(socket), &flags));
  return (flags & HANDLE_FLAG_INHERIT) != 0;
}
} // namespace

TEST_CASE("sys_win: Winsock and Win32 errors map to vio codes")
{
  CHECK(errc_from_wsa(0) == 0);
  CHECK(errc_from_wsa(WSAEWOULDBLOCK) == errc::again);
  CHECK(errc_from_wsa(WSAECONNRESET) == errc::connection_reset);
  CHECK(errc_from_wsa(WSAECONNREFUSED) == errc::connection_refused);
  CHECK(errc_from_wsa(WSAEMSGSIZE) == errc::message_too_long);
  CHECK(errc_from_wsa(WSAEADDRINUSE) == errc::address_in_use);
  CHECK(errc_from_wsa(WSAENOTSOCK) == errc::not_a_socket);
  CHECK(errc_from_wsa(WSAESHUTDOWN) == errc::broken_pipe);
  CHECK(errc_from_wsa(WSA_OPERATION_ABORTED) == errc::canceled);
  CHECK(errc_from_wsa(WSAHOST_NOT_FOUND) == errc::dns_no_name);
  CHECK(errc_from_wsa(-5) == errc::unknown);
  CHECK(errc_from_win32(ERROR_FILE_NOT_FOUND) == errc::no_such_file);
  CHECK(errc_from_win32(ERROR_ACCESS_DENIED) == errc::operation_not_permitted);
  CHECK(errc_from_win32(ERROR_SHARING_VIOLATION) == errc::resource_busy_or_locked);
  CHECK(errc_from_win32(ERROR_DISK_FULL) == errc::no_space);
  CHECK(errc_from_win32(0xFFFFu) == errc::unknown);
  ::WSASetLastError(WSAEWOULDBLOCK);
  CHECK(last_socket_error() == errc::again);
}

TEST_CASE("sys_win: sockets are non-blocking and not inherited, accepted ones too")
{
  sockaddr_in bound{};
  SOCKET listener = sys_win_listener(bound);
  CHECK_FALSE(sys_win_inheritable(listener));
  SOCKET none = INVALID_SOCKET;
  CHECK(socket_accept(listener, none, nullptr, nullptr) == errc::again);
  auto pair = sys_win_connect(bound, listener);
  CHECK_FALSE(sys_win_inheritable(pair.client));
  CHECK_FALSE(sys_win_inheritable(pair.server));
  std::byte buffer[4];
  CHECK(socket_recv(pair.server, buffer) == errc::again);
  CHECK(socket_close(pair.client) == 0);
  CHECK(socket_close(pair.server) == 0);
  CHECK(socket_close(listener) == 0);
  CHECK(socket_close(INVALID_SOCKET) == 0);
}

TEST_CASE("sys_win: connecting to the unspecified address reaches loopback")
{
  sockaddr_in bound{};
  SOCKET listener = sys_win_listener(bound);
  auto unspecified = sys_win_loopback(INADDR_ANY);
  unspecified.sin_port = bound.sin_port;
  auto pair = sys_win_connect(unspecified, listener);
  sockaddr_storage peer{};
  int peer_length = static_cast<int>(sizeof(peer));
  REQUIRE(socket_peer_name(pair.client, peer, peer_length) == 0);
  sockaddr_in reached{};
  std::memcpy(&reached, &peer, sizeof(reached));
  CHECK(reached.sin_addr.s_addr == htonl(INADDR_LOOPBACK));
  socket_close(pair.client);
  socket_close(pair.server);
  socket_close(listener);
}

TEST_CASE("sys_win: sendv gathers its buffers in order and recv sees a shutdown as end of stream")
{
  sockaddr_in bound{};
  SOCKET listener = sys_win_listener(bound);
  auto pair = sys_win_connect(bound, listener);
  const char first[] = "gather";
  const char second[] = "-";
  const char third[] = "write";
  const_bytes_t buffers[3] = {
    std::as_bytes(std::span(first, sizeof(first) - 1)),
    std::as_bytes(std::span(second, sizeof(second) - 1)),
    std::as_bytes(std::span(third, sizeof(third) - 1)),
  };
  CHECK(socket_sendv(pair.client, buffers, 3) == 12);
  CHECK(socket_sendv(pair.client, buffers, 0) == 0);
  CHECK(socket_shutdown_write(pair.client) == 0);
  std::string received;
  for (;;)
  {
    std::byte buffer[64];
    const auto got = sys_win_receive(pair.server, buffer);
    REQUIRE(got >= 0);
    if (got == 0)
      break;
    received.append(reinterpret_cast<const char *>(buffer), static_cast<std::size_t>(got));
  }
  CHECK(received == "gather-write");
  CHECK(socket_send(pair.client, buffers[0]) == errc::broken_pipe);
  socket_close(pair.client);
  socket_close(pair.server);
  socket_close(listener);
}

TEST_CASE("sys_win: a peer's abortive close reads as a reset")
{
  sockaddr_in bound{};
  SOCKET listener = sys_win_listener(bound);
  auto pair = sys_win_connect(bound, listener);
  linger abort_on_close{};
  abort_on_close.l_onoff = 1;
  abort_on_close.l_linger = 0;
  REQUIRE(socket_set_option(pair.client, SOL_SOCKET, SO_LINGER, &abort_on_close, static_cast<int>(sizeof(abort_on_close))) == 0);
  linger read_back{};
  int length = static_cast<int>(sizeof(read_back));
  REQUIRE(socket_get_option(pair.client, SOL_SOCKET, SO_LINGER, &read_back, length) == 0);
  CHECK(read_back.l_onoff != 0);
  CHECK(socket_close(pair.client) == 0);
  std::byte buffer[8];
  CHECK(sys_win_receive(pair.server, buffer) == errc::connection_reset);
  socket_close(pair.server);
  socket_close(listener);
}

TEST_CASE("sys_win: a datagram larger than the buffer returns the part that fit")
{
  SOCKET receiver = INVALID_SOCKET;
  SOCKET sender = INVALID_SOCKET;
  REQUIRE(socket_open(AF_INET, SOCK_DGRAM, IPPROTO_UDP, receiver) == 0);
  REQUIRE(socket_open(AF_INET, SOCK_DGRAM, IPPROTO_UDP, sender) == 0);
  CHECK_FALSE(sys_win_inheritable(receiver));
  auto address = sys_win_loopback();
  REQUIRE(socket_bind(receiver, reinterpret_cast<const sockaddr *>(&address), static_cast<int>(sizeof(sockaddr_storage))) == 0);
  sockaddr_storage bound{};
  int bound_length = static_cast<int>(sizeof(bound));
  REQUIRE(socket_name(receiver, bound, bound_length) == 0);
  std::byte payload[100];
  for (std::size_t i = 0; i < sizeof(payload); ++i)
    payload[i] = static_cast<std::byte>(i);
  CHECK(socket_sendto(sender, payload, reinterpret_cast<const sockaddr *>(&bound), bound_length) == 100);
  std::byte truncated[10] = {};
  sockaddr_storage from{};
  int from_length = 0;
  CHECK(sys_win_receive(receiver, truncated, &from, &from_length) == 10);
  CHECK(from_length == static_cast<int>(sizeof(sockaddr_in)));
  CHECK(truncated[9] == std::byte{9});
  socket_close(sender);
  socket_close(receiver);
}

TEST_CASE("sys_win: a datagram socket ignores port unreachable reports")
{
  SOCKET probe = INVALID_SOCKET;
  REQUIRE(socket_open(AF_INET, SOCK_DGRAM, IPPROTO_UDP, probe) == 0);
  auto address = sys_win_loopback();
  REQUIRE(socket_bind(probe, reinterpret_cast<const sockaddr *>(&address), static_cast<int>(sizeof(address))) == 0);
  sockaddr_storage closed{};
  int closed_length = static_cast<int>(sizeof(closed));
  REQUIRE(socket_name(probe, closed, closed_length) == 0);
  socket_close(probe);

  SOCKET socket = INVALID_SOCKET;
  REQUIRE(socket_open(AF_INET, SOCK_DGRAM, IPPROTO_UDP, socket) == 0);
  REQUIRE(socket_bind(socket, reinterpret_cast<const sockaddr *>(&address), static_cast<int>(sizeof(address))) == 0);
  std::byte payload[4] = {};
  CHECK(socket_sendto(socket, payload, reinterpret_cast<const sockaddr *>(&closed), closed_length) == 4);
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  std::byte buffer[16];
  sockaddr_storage from{};
  int from_length = 0;
  CHECK(socket_recvfrom(socket, buffer, &from, &from_length) == errc::again);
  socket_close(socket);
}

TEST_CASE("sys_win: positional reads and writes leave the file position where it was")
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
