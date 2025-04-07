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

#include <uv.h>

#include "vio/bit_mask.h"
#include "vio/ref_ptr.h"
#include "vio/uv_coro.h"

#include <expected>

namespace vio
{

template <typename T>
class auto_close_t
{
public:
  explicit auto_close_t(T &&value) noexcept
    : m_value(std::move(value))
  {
  }

  auto_close_t(const auto_close_t &) = delete;
  auto_close_t &operator=(const auto_close_t &) = delete;

  auto_close_t(auto_close_t &&other) noexcept
    : m_value(std::move(other.m_value))
  {
    other.m_value.file_handle = -1;
  }

  auto_close_t &operator=(auto_close_t &&other) noexcept
  {
    if (this != &other)
    {
      close_file(&m_value);
      m_value = std::move(other.m_value);
      other.m_value.file_handle = -1;
    }
    return *this;
  }

  ~auto_close_t()
  {
    close_file(&m_value);
  }

  T *operator->()
  {
    return &m_value;
  }
  const T *operator->() const
  {
    return &m_value;
  }

  T &operator*()
  {
    return m_value;
  }
  const T &operator*() const
  {
    return m_value;
  }

private:
  T m_value;
};

template <typename T>
auto_close_t<T> make_auto_close(T &&t)
{
  return auto_close_t<T>(std::forward<T>(t));
}

enum class file_open_flag_t
{
  append = UV_FS_O_APPEND,
  creat = UV_FS_O_CREAT,
  excl = UV_FS_O_EXCL,
  filemap = UV_FS_O_FILEMAP,
  random = UV_FS_O_RANDOM,
  rdonly = UV_FS_O_RDONLY,
  rdwr = UV_FS_O_RDWR,
  sequential = UV_FS_O_SEQUENTIAL,
  short_lived = UV_FS_O_SHORT_LIVED,
  temporary = UV_FS_O_TEMPORARY,
  trunc = UV_FS_O_TRUNC,
  wronly = UV_FS_O_WRONLY,
  direct = UV_FS_O_DIRECT,
  directory = UV_FS_O_DIRECTORY,
  dsync = UV_FS_O_DSYNC,
  exlock = UV_FS_O_EXLOCK,
  noatime = UV_FS_O_NOATIME,
  noctty = UV_FS_O_NOCTTY,
  nofollow = UV_FS_O_NOFOLLOW,
  nonblock = UV_FS_O_NONBLOCK,
  symlink = UV_FS_O_SYMLINK,
  sync = UV_FS_O_SYNC,
};

using file_open_flags_t = bit_mask_t<file_open_flag_t>;

struct file_t
{
  event_loop_t *event_loop;
  uv_file file_handle;
};

inline void close_file(file_t *file)
{
  if (file->file_handle > 0)
  {
    uv_fs_t request = {};
    uv_fs_close(file->event_loop->loop(), &request, file->file_handle, nullptr);
  }
}

inline std::expected<auto_close_t<file_t>, error_t> open_file(event_loop_t &event_loop, const std::string &path, file_open_flags_t flags, int mode)
{
  uv_fs_t request = {};
  auto result = uv_fs_open(event_loop.loop(), &request, path.c_str(), flags.value(), mode, nullptr);

  if (result < 0)
  {
    // Construct an error_t with code and a UV error message.
    error_t err{
      result,
      uv_strerror(result) // or custom message
    };
    return std::unexpected(err);
  }

  file_t file{&event_loop, static_cast<uv_file>(result)};
  return make_auto_close(std::move(file));
}

inline std::expected<std::pair<auto_close_t<file_t>, std::string>, error_t> mkstemp_file(event_loop_t &event_loop, const std::string &tpl)
{
  uv_fs_t request = {};

  std::string localTpl = tpl;
  int result = uv_fs_mkstemp(event_loop.loop(), &request, localTpl.data(), nullptr);

  if (result < 0)
  {
    error_t err{result, uv_strerror(result)};
    uv_fs_req_cleanup(&request);
    return std::unexpected(err);
  }

  std::string generatedPath;
  if (request.path)
  {
    generatedPath = request.path;
  }

  file_t file{&event_loop, static_cast<uv_file>(request.result)};
  uv_fs_req_cleanup(&request);

  return std::make_pair(make_auto_close(std::move(file)), generatedPath);
}



inline uv_coro_awaitable<uv_fs_t, std::size_t> write_file(event_loop_t &event_loop, file_t &file, const uint8_t *data, std::size_t length, std::int64_t offset)
{
  uv_coro_awaitable<uv_fs_t, std::size_t> ret;
  uv_buf_t buf = uv_buf_init(std::bit_cast<char *>(const_cast<uint8_t *>(data)), static_cast<unsigned int>(length));

  auto callback = [](uv_fs_t *reqPtr)
  {
    auto stateRef = ref_ptr_t<uv_coro_state<uv_fs_t, std::size_t>>::from_raw(reqPtr->data);

    auto result = reqPtr->result;
    if (result < 0)
    {
      stateRef->result = std::unexpected(error_t{static_cast<int>(result), uv_strerror(result)});
    }
    else
    {
      stateRef->result = static_cast<std::size_t>(result);
    }

    // Mark as done and resume the coroutine if there is one.
    stateRef->done = true;
    uv_fs_req_cleanup(reqPtr);
    if (stateRef->continuation)
      stateRef->continuation.resume();
  };

  auto copy = ret.state;
  ret.state->req.data = copy.release_to_raw();

  int r = uv_fs_write(event_loop.loop(), &ret.state->req, file.file_handle, &buf, 1, offset, callback);

  if (r < 0)
  {
    ret.state->done = true;
    ret.state->result = std::unexpected(error_t{r, uv_strerror(r)});
  }

  return ret;
}

inline uv_coro_awaitable<uv_fs_t, std::size_t> read_file(event_loop_t &event_loop, file_t &file, uint8_t *buffer, std::size_t length, std::int64_t offset)
{
  uv_coro_awaitable<uv_fs_t, std::size_t> ret;

  uv_buf_t buf = uv_buf_init(reinterpret_cast<char *>(buffer), static_cast<unsigned int>(length));

  auto callback = [](uv_fs_t *reqPtr)
  {
    auto stateRef = ref_ptr_t<uv_coro_state<uv_fs_t, std::size_t>>::from_raw(reqPtr->data);

    auto result = reqPtr->result;
    if (result < 0)
    {
      stateRef->result = std::unexpected(error_t{static_cast<int>(result), uv_strerror(result)});
    }
    else
    {
      stateRef->result = static_cast<std::size_t>(result);
    }

    stateRef->done = true;
    uv_fs_req_cleanup(reqPtr);
    if (stateRef->continuation)
      stateRef->continuation.resume();
  };

  auto copy = ret.state; // Copy the ref_ptr to keep a strong reference
  ret.state->req.data = copy.release_to_raw();

  int r = uv_fs_read(event_loop.loop(), &ret.state->req, file.file_handle, &buf, 1, offset, callback);

  if (r < 0)
  {
    ret.state->done = true;
    ret.state->result = std::unexpected(error_t{r, uv_strerror(r)});
  }

  return ret;
}

inline std::expected<void, error_t> rename_file(event_loop_t &loop, const std::string &oldPath, const std::string &newPath)
{
  uv_fs_t req = {};
  const int result = uv_fs_rename(loop.loop(), &req, oldPath.c_str(), newPath.c_str(), nullptr);
  uv_fs_req_cleanup(&req);

  if (result < 0)
    return std::unexpected(error_t{result, uv_strerror(result)});

  return {};
}

inline std::expected<void, error_t> unlink_file(event_loop_t &loop, const std::string &path)
{
  uv_fs_t req = {};
  const int result = uv_fs_unlink(loop.loop(), &req, path.c_str(), nullptr);
  uv_fs_req_cleanup(&req);

  if (result < 0)
    return std::unexpected(error_t{result, uv_strerror(result)});

  return {};
}

inline std::expected<void, error_t> mkdir_path(event_loop_t &loop, const std::string &path, int mode)
{
  uv_fs_t req = {};
  const int result = uv_fs_mkdir(loop.loop(), &req, path.c_str(), mode, nullptr);
  uv_fs_req_cleanup(&req);

  if (result < 0)
    return std::unexpected(error_t{result, uv_strerror(result)});

  return {};
}

inline std::expected<void, error_t> rmdir_path(event_loop_t &loop, const std::string &path)
{
  uv_fs_t req = {};
  const int result = uv_fs_rmdir(loop.loop(), &req, path.c_str(), nullptr);
  uv_fs_req_cleanup(&req);

  if (result < 0)
    return std::unexpected(error_t{result, uv_strerror(result)});

  return {};
}

inline std::expected<uv_stat_t, error_t> stat_file(event_loop_t &loop, const std::string &path)
{
  uv_fs_t req = {};
  const int result = uv_fs_stat(loop.loop(), &req, path.c_str(), nullptr);
  if (result < 0)
  {
    uv_fs_req_cleanup(&req);
    return std::unexpected(error_t{result, uv_strerror(result)});
  }

  uv_stat_t statResult = req.statbuf;
  uv_fs_req_cleanup(&req);
  return statResult;
}

inline std::expected<std::string, error_t> mkdtemp_path(event_loop_t &loop, const std::string &tpl)
{
  uv_fs_t req = {};
  std::string localTpl = tpl;
  const int result = uv_fs_mkdtemp(loop.loop(), &req, localTpl.data(), nullptr);

  if (result < 0)
  {
    uv_fs_req_cleanup(&req);
    return std::unexpected(error_t{result, uv_strerror(result)});
  }

  std::string path = req.path;
  uv_fs_req_cleanup(&req);
  return path;
}

inline uv_coro_awaitable<uv_fs_t, std::size_t> send_file(event_loop_t &loop, file_t &outFile, file_t &inFile, std::int64_t inOffset, std::size_t length)
{
  uv_coro_awaitable<uv_fs_t, std::size_t> ret;

  auto callback = [](uv_fs_t *reqPtr)
  {
    auto stateRef = ref_ptr_t<uv_coro_state<uv_fs_t, std::size_t>>::from_raw(reqPtr->data);
    auto result = reqPtr->result;

    if (result < 0)
      stateRef->result = std::unexpected(error_t{static_cast<int>(result), uv_strerror(result)});
    else
      stateRef->result = static_cast<std::size_t>(result);

    stateRef->done = true;
    uv_fs_req_cleanup(reqPtr);
    if (stateRef->continuation)
      stateRef->continuation.resume();
  };

  auto copy = ret.state;
  ret.state->req.data = copy.release_to_raw();
  const int callResult = uv_fs_sendfile(loop.loop(), &ret.state->req, outFile.file_handle, inFile.file_handle, inOffset, length, callback);

  if (callResult < 0)
  {
    ret.state->done = true;
    ret.state->result = std::unexpected(error_t{callResult, uv_strerror(callResult)});
  }

  return ret;
}

} // namespace vio