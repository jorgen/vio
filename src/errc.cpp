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

#include <cerrno>

#if defined(_WIN32)
#include "vio/detail/native.h"
#else
#include <netdb.h>
#endif

#include "vio/detail/sys.h"
#include "vio/errc.h"
#include "vio/error.h"

namespace vio
{
const char *error_message(int code) noexcept
{
  switch (code)
  {
  case errc::eof: return "end of file";
  case errc::canceled: return "operation canceled";
  case errc::again: return "resource temporarily unavailable";
  case errc::interrupted: return "interrupted system call";
  case errc::timed_out: return "connection timed out";
  case errc::connection_reset: return "connection reset by peer";
  case errc::connection_refused: return "connection refused";
  case errc::connection_aborted: return "software caused connection abort";
  case errc::broken_pipe: return "broken pipe";
  case errc::address_in_use: return "address already in use";
  case errc::address_not_available: return "address not available";
  case errc::not_connected: return "socket is not connected";
  case errc::already_connected: return "socket is already connected";
  case errc::network_unreachable: return "network is unreachable";
  case errc::host_unreachable: return "host is unreachable";
  case errc::network_down: return "network is down";
  case errc::no_buffer_space: return "no buffer space available";
  case errc::message_too_long: return "message too long";
  case errc::invalid_argument: return "invalid argument";
  case errc::bad_descriptor: return "bad file descriptor";
  case errc::not_supported: return "operation not supported";
  case errc::permission_denied: return "permission denied";
  case errc::operation_not_permitted: return "operation not permitted";
  case errc::no_such_file: return "no such file or directory";
  case errc::file_exists: return "file already exists";
  case errc::not_a_directory: return "not a directory";
  case errc::is_a_directory: return "is a directory";
  case errc::directory_not_empty: return "directory not empty";
  case errc::no_space: return "no space left on device";
  case errc::too_many_open_files: return "too many open files";
  case errc::out_of_memory: return "not enough memory";
  case errc::address_family_not_supported: return "address family not supported";
  case errc::already_in_progress: return "connection already in progress";
  case errc::in_progress: return "operation in progress";
  case errc::name_too_long: return "name too long";
  case errc::read_only_file_system: return "read-only file system";
  case errc::cross_device_link: return "cross-device link not permitted";
  case errc::too_many_symbolic_links: return "too many symbolic links encountered";
  case errc::file_too_large: return "file too large";
  case errc::io_error: return "i/o error";
  case errc::invalid_seek: return "invalid seek";
  case errc::protocol_error: return "protocol error";
  case errc::not_implemented: return "function not implemented";
  case errc::no_such_device: return "no such device";
  case errc::busy: return "resource busy";
  case errc::bad_address: return "bad address in system call argument";
  case errc::protocol_not_supported: return "protocol not supported";
  case errc::socket_type_not_supported: return "socket type not supported";
  case errc::text_file_busy: return "text file is busy";
  case errc::too_many_links: return "too many links";
  case errc::no_such_process: return "no such process";
  case errc::not_a_socket: return "socket operation on non-socket";
  case errc::destination_address_required: return "destination address required";
  case errc::no_protocol_option: return "protocol not available";
  case errc::resource_busy_or_locked: return "resource busy or locked";
  case errc::dns_address_family: return "address family for hostname not supported";
  case errc::dns_again: return "temporary failure in name resolution";
  case errc::dns_bad_flags: return "bad ai_flags value";
  case errc::dns_fail: return "permanent failure in name resolution";
  case errc::dns_family: return "ai_family not supported";
  case errc::dns_memory: return "out of memory in name resolution";
  case errc::dns_no_data: return "no address associated with hostname";
  case errc::dns_no_name: return "unknown node or service";
  case errc::dns_service: return "service not available for socket type";
  case errc::dns_socket_type: return "socket type not supported";
  case errc::dns_overflow: return "argument buffer overflow";
  case errc::dns_protocol: return "resolved protocol is unknown";
  case errc::dns_canceled: return "request canceled";
  case errc::dns_bad_hints: return "invalid value for hints";
  case errc::unknown: return "unknown error";
  default: return "unknown error";
  }
}
} // namespace vio

namespace vio::detail
{
int errc_from_errno(int error) noexcept
{
  switch (error)
  {
  case 0: return 0;
  case EAGAIN: return errc::again;
#if defined(EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
  case EWOULDBLOCK: return errc::again;
#endif
  case EINTR: return errc::interrupted;
  case ECANCELED: return errc::canceled;
  case ETIMEDOUT: return errc::timed_out;
  case ECONNRESET: return errc::connection_reset;
  case ECONNREFUSED: return errc::connection_refused;
  case ECONNABORTED: return errc::connection_aborted;
  case EPIPE: return errc::broken_pipe;
  case EADDRINUSE: return errc::address_in_use;
  case EADDRNOTAVAIL: return errc::address_not_available;
  case ENOTCONN: return errc::not_connected;
  case EISCONN: return errc::already_connected;
  case ENETUNREACH: return errc::network_unreachable;
  case EHOSTUNREACH: return errc::host_unreachable;
  case ENETDOWN: return errc::network_down;
  case ENOBUFS: return errc::no_buffer_space;
  case EMSGSIZE: return errc::message_too_long;
  case EINVAL: return errc::invalid_argument;
  case EBADF: return errc::bad_descriptor;
  case ENOTSUP: return errc::not_supported;
#if defined(EOPNOTSUPP) && EOPNOTSUPP != ENOTSUP
  case EOPNOTSUPP: return errc::not_supported;
#endif
  case EACCES: return errc::permission_denied;
  case EPERM: return errc::operation_not_permitted;
  case ENOENT: return errc::no_such_file;
  case EEXIST: return errc::file_exists;
  case ENOTDIR: return errc::not_a_directory;
  case EISDIR: return errc::is_a_directory;
  case ENOTEMPTY: return errc::directory_not_empty;
  case ENOSPC: return errc::no_space;
  case EMFILE: return errc::too_many_open_files;
  case ENFILE: return errc::too_many_open_files;
  case ENOMEM: return errc::out_of_memory;
  case EAFNOSUPPORT: return errc::address_family_not_supported;
  case EALREADY: return errc::already_in_progress;
  case EINPROGRESS: return errc::in_progress;
  case ENAMETOOLONG: return errc::name_too_long;
  case EROFS: return errc::read_only_file_system;
  case EXDEV: return errc::cross_device_link;
  case ELOOP: return errc::too_many_symbolic_links;
  case EFBIG: return errc::file_too_large;
  case EIO: return errc::io_error;
  case ESPIPE: return errc::invalid_seek;
  case EPROTO: return errc::protocol_error;
  case ENOSYS: return errc::not_implemented;
  case ENODEV: return errc::no_such_device;
  case ENXIO: return errc::no_such_device;
  case EBUSY: return errc::busy;
  case EFAULT: return errc::bad_address;
  case EPROTONOSUPPORT: return errc::protocol_not_supported;
#if defined(ESOCKTNOSUPPORT)
  case ESOCKTNOSUPPORT: return errc::socket_type_not_supported;
#endif
  case ETXTBSY: return errc::text_file_busy;
  case EMLINK: return errc::too_many_links;
  case ESRCH: return errc::no_such_process;
  case ENOTSOCK: return errc::not_a_socket;
  case EDESTADDRREQ: return errc::destination_address_required;
  case ENOPROTOOPT: return errc::no_protocol_option;
  default: return errc::unknown;
  }
}

int errc_from_gai(int error) noexcept
{
  switch (error)
  {
  case 0: return 0;
#if defined(EAI_ADDRFAMILY)
  case EAI_ADDRFAMILY: return errc::dns_address_family;
#endif
  case EAI_AGAIN: return errc::dns_again;
  case EAI_BADFLAGS: return errc::dns_bad_flags;
  case EAI_FAIL: return errc::dns_fail;
  case EAI_FAMILY: return errc::dns_family;
  case EAI_MEMORY: return errc::dns_memory;
#if defined(EAI_NODATA) && EAI_NODATA != EAI_NONAME
  case EAI_NODATA: return errc::dns_no_data;
#endif
  case EAI_NONAME: return errc::dns_no_name;
  case EAI_SERVICE: return errc::dns_service;
  case EAI_SOCKTYPE: return errc::dns_socket_type;
#if defined(EAI_OVERFLOW)
  case EAI_OVERFLOW: return errc::dns_overflow;
#endif
#if defined(EAI_PROTOCOL)
  case EAI_PROTOCOL: return errc::dns_protocol;
#endif
#if defined(EAI_CANCELED)
  case EAI_CANCELED: return errc::dns_canceled;
#endif
#if defined(EAI_BADHINTS)
  case EAI_BADHINTS: return errc::dns_bad_hints;
#endif
#if defined(EAI_SYSTEM)
  case EAI_SYSTEM: return errc_from_errno(errno);
#endif
  default: return errc::dns_fail;
  }
}
} // namespace vio::detail
