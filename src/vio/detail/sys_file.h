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

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>
#include <string>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "vio/bit_mask.h"
#include "vio/detail/native.h"
#include "vio/detail/sys.h"
#include "vio/errc.h"

#if defined(_WIN32)
#include <io.h>
#include <random>
#else
#include <unistd.h>
#if defined(__linux__)
#include <atomic>
#include <sys/sendfile.h>
#include <sys/sysmacros.h>
#endif
#endif

namespace vio::detail::open_flag
{
inline constexpr int rdonly = 0;
inline constexpr int wronly = 1 << 0;
inline constexpr int rdwr = 1 << 1;
inline constexpr int append = 1 << 2;
inline constexpr int creat = 1 << 3;
inline constexpr int excl = 1 << 4;
inline constexpr int trunc = 1 << 5;
inline constexpr int direct = 1 << 6;
inline constexpr int directory = 1 << 7;
inline constexpr int dsync = 1 << 8;
inline constexpr int exlock = 1 << 9;
inline constexpr int noatime = 1 << 10;
inline constexpr int noctty = 1 << 11;
inline constexpr int nofollow = 1 << 12;
inline constexpr int nonblock = 1 << 13;
inline constexpr int symlink = 1 << 14;
inline constexpr int sync = 1 << 15;
inline constexpr int filemap = 1 << 16;
inline constexpr int random = 1 << 17;
inline constexpr int sequential = 1 << 18;
inline constexpr int short_lived = 1 << 19;
inline constexpr int temporary = 1 << 20;
} // namespace vio::detail::open_flag

namespace vio
{
enum class file_open_flag_t
{
  append = detail::open_flag::append,
  creat = detail::open_flag::creat,
  excl = detail::open_flag::excl,
  filemap = detail::open_flag::filemap,
  random = detail::open_flag::random,
  rdonly = detail::open_flag::rdonly,
  rdwr = detail::open_flag::rdwr,
  sequential = detail::open_flag::sequential,
  short_lived = detail::open_flag::short_lived,
  temporary = detail::open_flag::temporary,
  trunc = detail::open_flag::trunc,
  wronly = detail::open_flag::wronly,
  direct = detail::open_flag::direct,
  directory = detail::open_flag::directory,
  dsync = detail::open_flag::dsync,
  exlock = detail::open_flag::exlock,
  noatime = detail::open_flag::noatime,
  noctty = detail::open_flag::noctty,
  nofollow = detail::open_flag::nofollow,
  nonblock = detail::open_flag::nonblock,
  symlink = detail::open_flag::symlink,
  sync = detail::open_flag::sync,
};

using file_open_flags_t = bit_mask_t<file_open_flag_t>;

struct file_timespec_t
{
  std::int64_t tv_sec = 0;
  std::int64_t tv_nsec = 0;
};

struct file_stat_t
{
  std::uint64_t st_dev = 0;
  std::uint64_t st_mode = 0;
  std::uint64_t st_nlink = 0;
  std::uint64_t st_uid = 0;
  std::uint64_t st_gid = 0;
  std::uint64_t st_rdev = 0;
  std::uint64_t st_ino = 0;
  std::uint64_t st_size = 0;
  std::uint64_t st_blksize = 0;
  std::uint64_t st_blocks = 0;
  std::uint64_t st_flags = 0;
  std::uint64_t st_gen = 0;
  file_timespec_t st_atim;
  file_timespec_t st_mtim;
  file_timespec_t st_ctim;
  file_timespec_t st_birthtim;
};
} // namespace vio

namespace vio::detail
{
inline constexpr std::size_t max_file_io = 0x7ffff000;
inline constexpr int max_temp_attempts = 128;

[[nodiscard]] inline bool fs_path_ok(const std::string &path) noexcept
{
  return path.find('\0') == std::string::npos;
}

[[nodiscard]] inline bool fs_template_ok(const std::string &path) noexcept
{
  constexpr std::size_t suffix = 6;
  return fs_path_ok(path) && path.size() >= suffix && path.compare(path.size() - suffix, suffix, "XXXXXX") == 0;
}

#if defined(_WIN32)
[[nodiscard]] inline int fs_wide(const std::string &text, std::wstring &out) noexcept
{
  out.clear();
  if (!fs_path_ok(text))
    return errc::invalid_argument;
  if (text.empty())
    return 0;
  if (text.size() > static_cast<std::size_t>(INT_MAX))
    return errc::name_too_long;
  const int length = static_cast<int>(text.size());
  const int needed = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), length, nullptr, 0);
  if (needed <= 0)
    return errc::invalid_argument;
  try
  {
    out.resize(static_cast<std::size_t>(needed));
  }
  catch (...)
  {
    return errc::out_of_memory;
  }
  if (::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), length, out.data(), needed) != needed)
    return errc::invalid_argument;
  return 0;
}

[[nodiscard]] inline HANDLE fs_handle(native_file_t file) noexcept
{
  if (file < 0)
    return INVALID_HANDLE_VALUE;
  return reinterpret_cast<HANDLE>(::_get_osfhandle(file));
}

[[nodiscard]] inline file_timespec_t fs_from_filetime(const FILETIME &time) noexcept
{
  constexpr std::int64_t ticks_per_second = 10000000;
  constexpr std::int64_t unix_epoch = 116444736000000000LL;
  const auto raw = (static_cast<std::uint64_t>(time.dwHighDateTime) << 32) | time.dwLowDateTime;
  const std::int64_t ticks = static_cast<std::int64_t>(raw) - unix_epoch;
  std::int64_t seconds = ticks / ticks_per_second;
  std::int64_t rest = ticks % ticks_per_second;
  if (rest < 0)
  {
    rest += ticks_per_second;
    --seconds;
  }
  return {seconds, rest * 100};
}

inline void fs_fill_stat(const BY_HANDLE_FILE_INFORMATION &info, file_stat_t &out) noexcept
{
  out = {};
  out.st_dev = info.dwVolumeSerialNumber;
  out.st_ino = (static_cast<std::uint64_t>(info.nFileIndexHigh) << 32) | info.nFileIndexLow;
  out.st_nlink = info.nNumberOfLinks;
  const bool is_directory = (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
  out.st_size = is_directory ? 0 : (static_cast<std::uint64_t>(info.nFileSizeHigh) << 32) | info.nFileSizeLow;
  std::uint64_t mode = is_directory ? _S_IFDIR : _S_IFREG;
  if (info.dwFileAttributes & FILE_ATTRIBUTE_READONLY)
    mode |= _S_IREAD | (_S_IREAD >> 3) | (_S_IREAD >> 6);
  else
    mode |= (_S_IREAD | _S_IWRITE) | ((_S_IREAD | _S_IWRITE) >> 3) | ((_S_IREAD | _S_IWRITE) >> 6);
  out.st_mode = mode;
  out.st_blksize = 4096;
  out.st_blocks = (out.st_size + 511) / 512;
  out.st_atim = fs_from_filetime(info.ftLastAccessTime);
  out.st_mtim = fs_from_filetime(info.ftLastWriteTime);
  out.st_ctim = out.st_mtim;
  out.st_birthtim = fs_from_filetime(info.ftCreationTime);
}

[[nodiscard]] inline int fs_stat_handle(HANDLE handle, file_stat_t &out) noexcept
{
  switch (::GetFileType(handle))
  {
  case FILE_TYPE_CHAR:
    out = {};
    out.st_mode = _S_IFCHR;
    return 0;
  case FILE_TYPE_PIPE:
    out = {};
    out.st_mode = _S_IFIFO;
    return 0;
  default:
    break;
  }
  BY_HANDLE_FILE_INFORMATION info{};
  if (!::GetFileInformationByHandle(handle, &info))
    return errc_from_win32(::GetLastError());
  fs_fill_stat(info, out);
  return 0;
}

[[nodiscard]] inline int fs_randomize(std::string &path) noexcept
{
  static constexpr char alphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  try
  {
    std::random_device device;
    for (std::size_t i = path.size() - 6; i < path.size(); ++i)
      path[i] = alphabet[device() % (sizeof(alphabet) - 1)];
  }
  catch (...)
  {
    return errc::io_error;
  }
  return 0;
}
#else
inline void fs_fill_stat(const struct stat &status, file_stat_t &out) noexcept
{
  out = {};
  out.st_dev = static_cast<std::uint64_t>(status.st_dev);
  out.st_mode = static_cast<std::uint64_t>(status.st_mode);
  out.st_nlink = static_cast<std::uint64_t>(status.st_nlink);
  out.st_uid = static_cast<std::uint64_t>(status.st_uid);
  out.st_gid = static_cast<std::uint64_t>(status.st_gid);
  out.st_rdev = static_cast<std::uint64_t>(status.st_rdev);
  out.st_ino = static_cast<std::uint64_t>(status.st_ino);
  out.st_size = static_cast<std::uint64_t>(status.st_size);
  out.st_blksize = static_cast<std::uint64_t>(status.st_blksize);
  out.st_blocks = static_cast<std::uint64_t>(status.st_blocks);
#if defined(__APPLE__)
  out.st_flags = status.st_flags;
  out.st_gen = status.st_gen;
  out.st_atim = {status.st_atimespec.tv_sec, status.st_atimespec.tv_nsec};
  out.st_mtim = {status.st_mtimespec.tv_sec, status.st_mtimespec.tv_nsec};
  out.st_ctim = {status.st_ctimespec.tv_sec, status.st_ctimespec.tv_nsec};
  out.st_birthtim = {status.st_birthtimespec.tv_sec, status.st_birthtimespec.tv_nsec};
#elif defined(__FreeBSD__)
  out.st_flags = status.st_flags;
  out.st_gen = status.st_gen;
  out.st_atim = {status.st_atim.tv_sec, status.st_atim.tv_nsec};
  out.st_mtim = {status.st_mtim.tv_sec, status.st_mtim.tv_nsec};
  out.st_ctim = {status.st_ctim.tv_sec, status.st_ctim.tv_nsec};
  out.st_birthtim = {status.st_birthtim.tv_sec, status.st_birthtim.tv_nsec};
#else
  out.st_atim = {status.st_atim.tv_sec, status.st_atim.tv_nsec};
  out.st_mtim = {status.st_mtim.tv_sec, status.st_mtim.tv_nsec};
  out.st_ctim = {status.st_ctim.tv_sec, status.st_ctim.tv_nsec};
  out.st_birthtim = out.st_ctim;
#endif
}

#if defined(__linux__) && defined(STATX_BTIME)
inline std::atomic<bool> &fs_statx_unavailable() noexcept
{
  static std::atomic<bool> unavailable{false};
  return unavailable;
}

[[nodiscard]] inline int fs_statx(int directory, const char *path, int flags, file_stat_t &out) noexcept
{
  constexpr int use_stat = 1;
  if (fs_statx_unavailable().load(std::memory_order_relaxed))
    return use_stat;
  struct statx status{};
  const int result = ::statx(directory, path, flags, STATX_BASIC_STATS | STATX_BTIME, &status);
  if (result != 0)
  {
    const int error = errno;
    if (result == -1 && error != EINVAL && error != EPERM && error != ENOSYS && error != EOPNOTSUPP)
      return errc_from_errno(error);
    fs_statx_unavailable().store(true, std::memory_order_relaxed);
    return use_stat;
  }
  out = {};
  out.st_dev = static_cast<std::uint64_t>(makedev(status.stx_dev_major, status.stx_dev_minor));
  out.st_mode = status.stx_mode;
  out.st_nlink = status.stx_nlink;
  out.st_uid = status.stx_uid;
  out.st_gid = status.stx_gid;
  out.st_rdev = static_cast<std::uint64_t>(makedev(status.stx_rdev_major, status.stx_rdev_minor));
  out.st_ino = status.stx_ino;
  out.st_size = status.stx_size;
  out.st_blksize = status.stx_blksize;
  out.st_blocks = status.stx_blocks;
  out.st_atim = {status.stx_atime.tv_sec, status.stx_atime.tv_nsec};
  out.st_mtim = {status.stx_mtime.tv_sec, status.stx_mtime.tv_nsec};
  out.st_ctim = {status.stx_ctime.tv_sec, status.stx_ctime.tv_nsec};
  if (status.stx_mask & STATX_BTIME)
    out.st_birthtim = {status.stx_btime.tv_sec, status.stx_btime.tv_nsec};
  else
    out.st_birthtim = out.st_ctim;
  return 0;
}
#endif

[[nodiscard]] inline int fs_set_cloexec(int fd) noexcept
{
  int flags = ::fcntl(fd, F_GETFD, 0);
  if (flags < 0 || ::fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0)
    return errc_from_errno(errno);
  return 0;
}
#endif

[[nodiscard]] inline int fs_open(const std::string &path, int flags, int mode, native_file_t &out) noexcept
{
  out = invalid_native_file;
#if defined(_WIN32)
  std::wstring wide;
  if (int result = fs_wide(path, wide); result < 0)
    return result;
  DWORD access = 0;
  switch (flags & (open_flag::wronly | open_flag::rdwr))
  {
  case open_flag::rdonly:
    access = FILE_GENERIC_READ;
    break;
  case open_flag::wronly:
    access = FILE_GENERIC_WRITE;
    break;
  case open_flag::rdwr:
    access = FILE_GENERIC_READ | FILE_GENERIC_WRITE;
    break;
  default:
    return errc::invalid_argument;
  }
  if (flags & open_flag::append)
  {
    access &= ~static_cast<DWORD>(FILE_WRITE_DATA);
    access |= FILE_APPEND_DATA;
  }
  const DWORD sharing = (flags & open_flag::exlock) ? 0 : (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
  DWORD disposition = OPEN_EXISTING;
  switch (flags & (open_flag::creat | open_flag::excl | open_flag::trunc))
  {
  case open_flag::creat:
    disposition = OPEN_ALWAYS;
    break;
  case open_flag::creat | open_flag::excl:
  case open_flag::creat | open_flag::excl | open_flag::trunc:
    disposition = CREATE_NEW;
    break;
  case open_flag::creat | open_flag::trunc:
    disposition = CREATE_ALWAYS;
    break;
  case open_flag::trunc:
  case open_flag::trunc | open_flag::excl:
    disposition = TRUNCATE_EXISTING;
    break;
  default:
    disposition = OPEN_EXISTING;
    break;
  }
  DWORD attributes = FILE_ATTRIBUTE_NORMAL;
  if ((flags & open_flag::creat) && !(mode & _S_IWRITE))
    attributes |= FILE_ATTRIBUTE_READONLY;
  if (flags & open_flag::temporary)
  {
    attributes |= FILE_FLAG_DELETE_ON_CLOSE | FILE_ATTRIBUTE_TEMPORARY;
    access |= DELETE;
  }
  if (flags & open_flag::short_lived)
    attributes |= FILE_ATTRIBUTE_TEMPORARY;
  switch (flags & (open_flag::sequential | open_flag::random))
  {
  case 0:
    break;
  case open_flag::sequential:
    attributes |= FILE_FLAG_SEQUENTIAL_SCAN;
    break;
  case open_flag::random:
    attributes |= FILE_FLAG_RANDOM_ACCESS;
    break;
  default:
    return errc::invalid_argument;
  }
  if (flags & open_flag::direct)
  {
    if (access & FILE_APPEND_DATA)
    {
      if ((access & FILE_WRITE_DATA) != FILE_WRITE_DATA)
        return errc::invalid_argument;
      access &= ~static_cast<DWORD>(FILE_APPEND_DATA);
    }
    attributes |= FILE_FLAG_NO_BUFFERING;
  }
  if (flags & (open_flag::dsync | open_flag::sync))
    attributes |= FILE_FLAG_WRITE_THROUGH;
  attributes |= FILE_FLAG_BACKUP_SEMANTICS;
  HANDLE handle = ::CreateFileW(wide.c_str(), access, sharing, nullptr, disposition, attributes, nullptr);
  if (handle == INVALID_HANDLE_VALUE)
  {
    const DWORD error = ::GetLastError();
    if (error == ERROR_FILE_EXISTS && (flags & open_flag::creat) && !(flags & open_flag::excl))
      return errc::is_a_directory;
    return errc_from_win32(error);
  }
  int crt_flags = 0;
  if ((flags & (open_flag::wronly | open_flag::rdwr)) == 0)
    crt_flags |= _O_RDONLY;
  if (flags & open_flag::append)
    crt_flags |= _O_APPEND;
  const int fd = ::_open_osfhandle(reinterpret_cast<intptr_t>(handle), crt_flags);
  if (fd < 0)
  {
    ::CloseHandle(handle);
    return errc::too_many_open_files;
  }
  out = fd;
  return 0;
#else
  if (!fs_path_ok(path))
    return errc::invalid_argument;
  int system_flags = O_CLOEXEC;
  switch (flags & (open_flag::wronly | open_flag::rdwr))
  {
  case open_flag::rdonly:
    system_flags |= O_RDONLY;
    break;
  case open_flag::wronly:
    system_flags |= O_WRONLY;
    break;
  case open_flag::rdwr:
    system_flags |= O_RDWR;
    break;
  default:
    return errc::invalid_argument;
  }
  if (flags & open_flag::append)
    system_flags |= O_APPEND;
  if (flags & open_flag::creat)
    system_flags |= O_CREAT;
  if (flags & open_flag::excl)
    system_flags |= O_EXCL;
  if (flags & open_flag::trunc)
    system_flags |= O_TRUNC;
  if (flags & open_flag::noctty)
    system_flags |= O_NOCTTY;
  if (flags & open_flag::nofollow)
    system_flags |= O_NOFOLLOW;
  if (flags & open_flag::nonblock)
    system_flags |= O_NONBLOCK;
  if (flags & open_flag::sync)
    system_flags |= O_SYNC;
#if defined(O_DIRECTORY)
  if (flags & open_flag::directory)
    system_flags |= O_DIRECTORY;
#endif
#if defined(O_DIRECT)
  if (flags & open_flag::direct)
    system_flags |= O_DIRECT;
#endif
#if defined(O_DSYNC)
  if (flags & open_flag::dsync)
    system_flags |= O_DSYNC;
#endif
#if defined(O_EXLOCK)
  if (flags & open_flag::exlock)
    system_flags |= O_EXLOCK;
#endif
#if defined(O_NOATIME)
  if (flags & open_flag::noatime)
    system_flags |= O_NOATIME;
#endif
#if defined(O_SYMLINK)
  if (flags & open_flag::symlink)
    system_flags |= O_SYMLINK;
#endif
  for (;;)
  {
    const int fd = ::open(path.c_str(), system_flags, static_cast<mode_t>(mode));
    if (fd >= 0)
    {
      out = fd;
      return 0;
    }
    if (errno != EINTR)
      return errc_from_errno(errno);
  }
#endif
}

inline int fs_close(native_file_t file) noexcept
{
  if (file < 0)
    return errc::bad_descriptor;
#if defined(_WIN32)
  if (::_close(file) != 0)
    return errc_from_errno(errno);
#else
  if (::close(file) != 0 && errno != EINTR)
    return errc_from_errno(errno);
#endif
  return 0;
}

[[nodiscard]] inline std::int64_t fs_read(native_file_t file, std::span<std::byte> buffer, std::int64_t offset) noexcept
{
  const std::size_t length = std::min(buffer.size(), max_file_io);
#if defined(_WIN32)
  HANDLE handle = fs_handle(file);
  if (handle == INVALID_HANDLE_VALUE)
    return errc::bad_descriptor;
  OVERLAPPED overlapped{};
  OVERLAPPED *position = nullptr;
  if (offset >= 0)
  {
    overlapped.Offset = static_cast<DWORD>(static_cast<std::uint64_t>(offset));
    overlapped.OffsetHigh = static_cast<DWORD>(static_cast<std::uint64_t>(offset) >> 32);
    position = &overlapped;
  }
  DWORD transferred = 0;
  if (::ReadFile(handle, buffer.data(), static_cast<DWORD>(length), &transferred, position))
    return transferred;
  const DWORD error = ::GetLastError();
  if (error == ERROR_HANDLE_EOF || error == ERROR_BROKEN_PIPE)
    return 0;
  if (error == ERROR_ACCESS_DENIED)
    return errc::bad_descriptor;
  return errc_from_win32(error);
#else
  for (;;)
  {
    const auto count = offset < 0 ? ::read(file, buffer.data(), length) : ::pread(file, buffer.data(), length, static_cast<off_t>(offset));
    if (count >= 0)
      return count;
    if (errno != EINTR)
      return errc_from_errno(errno);
  }
#endif
}

[[nodiscard]] inline std::int64_t fs_write(native_file_t file, std::span<const std::byte> buffer, std::int64_t offset) noexcept
{
  const std::size_t length = std::min(buffer.size(), max_file_io);
#if defined(_WIN32)
  HANDLE handle = fs_handle(file);
  if (handle == INVALID_HANDLE_VALUE)
    return errc::bad_descriptor;
  OVERLAPPED overlapped{};
  OVERLAPPED *position = nullptr;
  if (offset >= 0)
  {
    overlapped.Offset = static_cast<DWORD>(static_cast<std::uint64_t>(offset));
    overlapped.OffsetHigh = static_cast<DWORD>(static_cast<std::uint64_t>(offset) >> 32);
    position = &overlapped;
  }
  DWORD transferred = 0;
  if (::WriteFile(handle, buffer.data(), static_cast<DWORD>(length), &transferred, position))
    return transferred;
  const DWORD error = ::GetLastError();
  if (error == ERROR_ACCESS_DENIED)
    return errc::bad_descriptor;
  return errc_from_win32(error);
#else
  for (;;)
  {
    const auto count = offset < 0 ? ::write(file, buffer.data(), length) : ::pwrite(file, buffer.data(), length, static_cast<off_t>(offset));
    if (count >= 0)
      return count;
    if (errno != EINTR)
      return errc_from_errno(errno);
  }
#endif
}

[[nodiscard]] inline int fs_fsync(native_file_t file) noexcept
{
#if defined(_WIN32)
  HANDLE handle = fs_handle(file);
  if (handle == INVALID_HANDLE_VALUE)
    return errc::bad_descriptor;
  if (!::FlushFileBuffers(handle))
    return errc_from_win32(::GetLastError());
  return 0;
#else
#if defined(__APPLE__)
  if (::fcntl(file, F_FULLFSYNC) == 0)
    return 0;
#endif
  for (;;)
  {
    if (::fsync(file) == 0)
      return 0;
    if (errno != EINTR)
      return errc_from_errno(errno);
  }
#endif
}

[[nodiscard]] inline int fs_fdatasync(native_file_t file) noexcept
{
#if defined(__linux__) || defined(__FreeBSD__) || defined(__NetBSD__)
  for (;;)
  {
    if (::fdatasync(file) == 0)
      return 0;
    if (errno != EINTR)
      return errc_from_errno(errno);
  }
#else
  return fs_fsync(file);
#endif
}

[[nodiscard]] inline int fs_ftruncate(native_file_t file, std::int64_t size) noexcept
{
  if (size < 0)
    return errc::invalid_argument;
#if defined(_WIN32)
  HANDLE handle = fs_handle(file);
  if (handle == INVALID_HANDLE_VALUE)
    return errc::bad_descriptor;
  FILE_END_OF_FILE_INFO info{};
  info.EndOfFile.QuadPart = size;
  if (!::SetFileInformationByHandle(handle, FileEndOfFileInfo, &info, sizeof(info)))
    return errc_from_win32(::GetLastError());
  return 0;
#else
  for (;;)
  {
    if (::ftruncate(file, static_cast<off_t>(size)) == 0)
      return 0;
    if (errno != EINTR)
      return errc_from_errno(errno);
  }
#endif
}

[[nodiscard]] inline int fs_fstat(native_file_t file, file_stat_t &out) noexcept
{
#if defined(_WIN32)
  HANDLE handle = fs_handle(file);
  if (handle == INVALID_HANDLE_VALUE)
    return errc::bad_descriptor;
  return fs_stat_handle(handle, out);
#else
#if defined(__linux__) && defined(STATX_BTIME)
  if (int result = fs_statx(file, "", AT_EMPTY_PATH, out); result <= 0)
    return result;
#endif
  struct stat status{};
  if (::fstat(file, &status) != 0)
    return errc_from_errno(errno);
  fs_fill_stat(status, out);
  return 0;
#endif
}

[[nodiscard]] inline int fs_stat(const std::string &path, file_stat_t &out) noexcept
{
#if defined(_WIN32)
  std::wstring wide;
  if (int result = fs_wide(path, wide); result < 0)
    return result;
  HANDLE handle = ::CreateFileW(wide.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
  if (handle == INVALID_HANDLE_VALUE)
    return errc_from_win32(::GetLastError());
  const int result = fs_stat_handle(handle, out);
  ::CloseHandle(handle);
  return result;
#else
  if (!fs_path_ok(path))
    return errc::invalid_argument;
#if defined(__linux__) && defined(STATX_BTIME)
  if (int result = fs_statx(AT_FDCWD, path.c_str(), 0, out); result <= 0)
    return result;
#endif
  struct stat status{};
  if (::stat(path.c_str(), &status) != 0)
    return errc_from_errno(errno);
  fs_fill_stat(status, out);
  return 0;
#endif
}

[[nodiscard]] inline int fs_rename(const std::string &from, const std::string &to) noexcept
{
#if defined(_WIN32)
  std::wstring wide_from;
  std::wstring wide_to;
  if (int result = fs_wide(from, wide_from); result < 0)
    return result;
  if (int result = fs_wide(to, wide_to); result < 0)
    return result;
  if (!::MoveFileExW(wide_from.c_str(), wide_to.c_str(), MOVEFILE_REPLACE_EXISTING))
    return errc_from_win32(::GetLastError());
  return 0;
#else
  if (!fs_path_ok(from) || !fs_path_ok(to))
    return errc::invalid_argument;
  if (::rename(from.c_str(), to.c_str()) != 0)
    return errc_from_errno(errno);
  return 0;
#endif
}

[[nodiscard]] inline int fs_unlink(const std::string &path) noexcept
{
#if defined(_WIN32)
  std::wstring wide;
  if (int result = fs_wide(path, wide); result < 0)
    return result;
  if (::DeleteFileW(wide.c_str()))
    return 0;
  DWORD error = ::GetLastError();
  if (error == ERROR_ACCESS_DENIED)
  {
    const DWORD attributes = ::GetFileAttributesW(wide.c_str());
    if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_READONLY) && !(attributes & FILE_ATTRIBUTE_DIRECTORY))
    {
      if (::SetFileAttributesW(wide.c_str(), attributes & ~static_cast<DWORD>(FILE_ATTRIBUTE_READONLY)))
      {
        if (::DeleteFileW(wide.c_str()))
          return 0;
        error = ::GetLastError();
        ::SetFileAttributesW(wide.c_str(), attributes);
      }
    }
  }
  return errc_from_win32(error);
#else
  if (!fs_path_ok(path))
    return errc::invalid_argument;
  if (::unlink(path.c_str()) != 0)
    return errc_from_errno(errno);
  return 0;
#endif
}

[[nodiscard]] inline int fs_mkdir(const std::string &path, int mode) noexcept
{
#if defined(_WIN32)
  (void)mode;
  std::wstring wide;
  if (int result = fs_wide(path, wide); result < 0)
    return result;
  if (!::CreateDirectoryW(wide.c_str(), nullptr))
    return errc_from_win32(::GetLastError());
  return 0;
#else
  if (!fs_path_ok(path))
    return errc::invalid_argument;
  if (::mkdir(path.c_str(), static_cast<mode_t>(mode)) != 0)
    return errc_from_errno(errno);
  return 0;
#endif
}

[[nodiscard]] inline int fs_rmdir(const std::string &path) noexcept
{
#if defined(_WIN32)
  std::wstring wide;
  if (int result = fs_wide(path, wide); result < 0)
    return result;
  if (!::RemoveDirectoryW(wide.c_str()))
    return errc_from_win32(::GetLastError());
  return 0;
#else
  if (!fs_path_ok(path))
    return errc::invalid_argument;
  if (::rmdir(path.c_str()) != 0)
    return errc_from_errno(errno);
  return 0;
#endif
}

[[nodiscard]] inline int fs_mkstemp(std::string &path, native_file_t &out) noexcept
{
  out = invalid_native_file;
  if (!fs_template_ok(path))
    return errc::invalid_argument;
#if defined(_WIN32)
  for (int attempt = 0; attempt < max_temp_attempts; ++attempt)
  {
    if (int result = fs_randomize(path); result < 0)
      return result;
    const int result = fs_open(path, open_flag::rdwr | open_flag::creat | open_flag::excl, _S_IREAD | _S_IWRITE, out);
    if (result != errc::file_exists)
      return result;
  }
  return errc::file_exists;
#else
#if defined(__linux__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
  const int fd = ::mkostemp(path.data(), O_CLOEXEC);
  if (fd < 0)
    return errc_from_errno(errno);
#else
  const int fd = ::mkstemp(path.data());
  if (fd < 0)
    return errc_from_errno(errno);
  if (int result = fs_set_cloexec(fd); result < 0)
  {
    ::close(fd);
    ::unlink(path.c_str());
    return result;
  }
#endif
  out = fd;
  return 0;
#endif
}

[[nodiscard]] inline int fs_mkdtemp(std::string &path) noexcept
{
  if (!fs_template_ok(path))
    return errc::invalid_argument;
#if defined(_WIN32)
  for (int attempt = 0; attempt < max_temp_attempts; ++attempt)
  {
    if (int result = fs_randomize(path); result < 0)
      return result;
    std::wstring wide;
    if (int result = fs_wide(path, wide); result < 0)
      return result;
    if (::CreateDirectoryW(wide.c_str(), nullptr))
      return 0;
    const DWORD error = ::GetLastError();
    if (error != ERROR_ALREADY_EXISTS && error != ERROR_FILE_EXISTS)
      return errc_from_win32(error);
  }
  return errc::file_exists;
#else
  if (::mkdtemp(path.data()) == nullptr)
    return errc_from_errno(errno);
  return 0;
#endif
}

[[nodiscard]] inline std::int64_t fs_copy_range(native_file_t out, native_file_t in, std::int64_t in_offset, std::size_t length) noexcept
{
  constexpr std::size_t chunk = 64 * 1024;
  std::byte buffer[chunk];
  std::size_t sent = 0;
  while (sent < length)
  {
    const std::size_t want = std::min(length - sent, chunk);
    const std::int64_t position = in_offset < 0 ? -1 : in_offset + static_cast<std::int64_t>(sent);
    const std::int64_t got = fs_read(in, std::span<std::byte>(buffer, want), position);
    if (got < 0)
      return sent > 0 ? static_cast<std::int64_t>(sent) : got;
    if (got == 0)
      break;
    std::size_t written = 0;
    while (written < static_cast<std::size_t>(got))
    {
      const std::int64_t put = fs_write(out, std::span<const std::byte>(buffer + written, static_cast<std::size_t>(got) - written), -1);
      if (put <= 0)
      {
        const std::size_t total = sent + written;
        if (total > 0)
          return static_cast<std::int64_t>(total);
        return put < 0 ? put : errc::io_error;
      }
      written += static_cast<std::size_t>(put);
    }
    sent += written;
  }
  return static_cast<std::int64_t>(sent);
}

[[nodiscard]] inline std::int64_t fs_sendfile(native_file_t out, native_file_t in, std::int64_t in_offset, std::size_t length) noexcept
{
  length = std::min(length, max_file_io);
  if (length == 0)
    return 0;
#if defined(__linux__)
  off_t position = static_cast<off_t>(in_offset);
  for (;;)
  {
    const auto count = ::sendfile(out, in, in_offset < 0 ? nullptr : &position, length);
    if (count >= 0)
      return count;
    switch (errno)
    {
    case EINTR:
      continue;
    case EINVAL:
    case EIO:
    case ENOTSOCK:
    case EXDEV:
    case ENOSYS:
    case EOPNOTSUPP:
      return fs_copy_range(out, in, in_offset, length);
    default:
      return errc_from_errno(errno);
    }
  }
#else
  return fs_copy_range(out, in, in_offset, length);
#endif
}
} // namespace vio::detail
