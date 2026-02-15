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

#include "vio/auto_closer.h"
#include "vio/cancellation.h"
#include "vio/error.h"
#include "vio/ref_counted_wrapper.h"
#include "vio/uv_coro.h"

#include <coroutine>
#include <expected>

namespace vio
{

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
  uv_file handle;
};

inline void close_file(file_t *file)
{
  if (file->handle > 0)
  {
    uv_fs_t request = {};
    uv_fs_close(file->event_loop->loop(), &request, file->handle, nullptr);
  }
}

using auto_close_file_t = auto_close_t<file_t, decltype(&close_file)>;

inline auto_close_file_t make_auto_close_file(file_t &&file)
{
  return auto_close_file_t(std::forward<file_t>(file), &close_file);
}

inline std::expected<auto_close_file_t, error_t> open_file(event_loop_t &event_loop, const std::string &path, file_open_flags_t flags, int mode)
{
  uv_fs_t request = {};
  auto result = uv_fs_open(event_loop.loop(), &request, path.c_str(), flags.value(), mode, nullptr);

  if (result < 0)
  {
    // Construct an error_t with code and a UV error message.
    const error_t err{.code = result, .msg = uv_strerror(result)};
    return std::unexpected(err);
  }

  return make_auto_close_file({&event_loop, static_cast<uv_file>(result)});
}

inline std::expected<std::pair<auto_close_file_t, std::string>, error_t> mkstemp_file(event_loop_t &event_loop, const std::string &tpl)
{
  uv_fs_t request = {};

  std::string local_tpl = tpl; // NOLINT(performance-unnecessary-copy-initialization) - uv_fs_mkstemp mutates the buffer
  int result = uv_fs_mkstemp(event_loop.loop(), &request, local_tpl.data(), nullptr);

  if (result < 0)
  {
    const error_t err{.code = result, .msg = uv_strerror(result)};
    uv_fs_req_cleanup(&request);
    return std::unexpected(err);
  }

  std::string generated_path;
  if (request.path)
  {
    generated_path = request.path;
  }

  file_t file{&event_loop, static_cast<uv_file>(request.result)};
  uv_fs_req_cleanup(&request);

  return std::make_pair(make_auto_close_file(std::move(file)), generated_path);
}

struct file_io_state_t
{
  uv_fs_t req;
  std::expected<std::size_t, error_t> result;
  std::coroutine_handle<> continuation = {};
  registration_t cancel_registration;
  bool done = false;

  [[nodiscard]] bool await_ready() const noexcept
  {
    return done;
  }

  bool await_suspend(std::coroutine_handle<> continuation) noexcept
  {
    if (done)
    {
      return false;
    }
    this->continuation = continuation;
    return true;
  }

  auto await_resume() noexcept
  {
    return std::move(result);
  }
};

inline future_t<file_io_state_t> write_file(event_loop_t &event_loop, file_t &file, const uint8_t *data, std::size_t length, std::int64_t offset, cancellation_t *cancel = nullptr)
{
  using ret_t = future_t<file_io_state_t>;
  using future_ref_ptr_t = ret_t::future_ref_ptr_t;
  ret_t ret;

  if (cancel && cancel->is_cancelled())
  {
    ret.state_ptr->done = true;
    ret.state_ptr->result = std::unexpected(error_t{.code = vio_cancelled, .msg = "cancelled"});
    return ret;
  }

  uv_buf_t buf = uv_buf_init(std::bit_cast<char *>(const_cast<uint8_t *>(data)), static_cast<unsigned int>(length));

  auto callback = [](uv_fs_t *req_ptr)
  {
    auto state_ref = future_ref_ptr_t::from_raw(req_ptr->data);

    auto result = req_ptr->result;
    if (result < 0)
    {
      state_ref->result = std::unexpected(error_t{.code = static_cast<int>(result), .msg = uv_strerror(result)});
    }
    else
    {
      state_ref->result = static_cast<std::size_t>(result);
    }

    state_ref->done = true;
    state_ref->cancel_registration.reset();
    uv_fs_req_cleanup(req_ptr);
    if (state_ref->continuation)
    {
      state_ref->continuation.resume();
    }
  };

  auto copy = ret.state_ptr;
  ret.state_ptr->req.data = copy.release_to_raw();

  if (int r = uv_fs_write(event_loop.loop(), &ret.state_ptr->req, file.handle, &buf, 1, offset, callback); r < 0)
  {
    future_ref_ptr_t::from_raw(ret.state_ptr->req.data);
    ret.state_ptr->done = true;
    ret.state_ptr->result = std::unexpected(error_t{.code = r, .msg = uv_strerror(r)});
    return ret;
  }

  if (cancel)
  {
    auto *state_raw = &ret.state_ptr.data();
    ret.state_ptr->cancel_registration = cancel->register_callback([state_raw]()
    {
      if (state_raw->done)
        return;
      uv_cancel((uv_req_t *)&state_raw->req);
    });
  }

  return ret;
}

inline future_t<file_io_state_t> read_file(event_loop_t &event_loop, file_t &file, uint8_t *buffer, std::size_t length, std::int64_t offset, cancellation_t *cancel = nullptr)
{
  using ret_t = future_t<file_io_state_t>;
  using future_ref_ptr_t = ret_t::future_ref_ptr_t;
  ret_t ret;

  if (cancel && cancel->is_cancelled())
  {
    ret.state_ptr->done = true;
    ret.state_ptr->result = std::unexpected(error_t{.code = vio_cancelled, .msg = "cancelled"});
    return ret;
  }

  uv_buf_t buf = uv_buf_init(reinterpret_cast<char *>(buffer), static_cast<unsigned int>(length));

  auto callback = [](uv_fs_t *req_ptr)
  {
    auto state_ref = future_ref_ptr_t::from_raw(req_ptr->data);

    auto result = req_ptr->result;
    if (result < 0)
    {
      state_ref->result = std::unexpected(error_t{.code = static_cast<int>(result), .msg = uv_strerror(result)});
    }
    else
    {
      state_ref->result = static_cast<std::size_t>(result);
    }

    state_ref->done = true;
    state_ref->cancel_registration.reset();
    uv_fs_req_cleanup(req_ptr);
    if (state_ref->continuation)
    {
      state_ref->continuation.resume();
    }
  };

  auto copy = ret.state_ptr;
  ret.state_ptr->req.data = copy.release_to_raw();

  int r = uv_fs_read(event_loop.loop(), &ret.state_ptr->req, file.handle, &buf, 1, offset, callback);

  if (r < 0)
  {
    auto state_ref = future_ref_ptr_t::from_raw(ret.state_ptr->req.data);
    ret.state_ptr->done = true;
    ret.state_ptr->result = std::unexpected(error_t{.code = r, .msg = uv_strerror(r)});
    return ret;
  }

  if (cancel)
  {
    auto *state_raw = &ret.state_ptr.data();
    ret.state_ptr->cancel_registration = cancel->register_callback([state_raw]()
    {
      if (state_raw->done)
        return;
      uv_cancel((uv_req_t *)&state_raw->req);
    });
  }

  return ret;
}

inline std::expected<void, error_t> rename_file(event_loop_t &loop, const std::string &old_path, const std::string &new_path)
{
  uv_fs_t req = {};
  const int result = uv_fs_rename(loop.loop(), &req, old_path.c_str(), new_path.c_str(), nullptr);
  uv_fs_req_cleanup(&req);

  if (result < 0)
  {
    return std::unexpected(error_t{.code = result, .msg = uv_strerror(result)});
  }

  return {};
}

inline std::expected<void, error_t> unlink_file(event_loop_t &loop, const std::string &path)
{
  uv_fs_t req = {};
  const int result = uv_fs_unlink(loop.loop(), &req, path.c_str(), nullptr);
  uv_fs_req_cleanup(&req);

  if (result < 0)
  {
    return std::unexpected(error_t{.code = result, .msg = uv_strerror(result)});
  }

  return {};
}

inline std::expected<void, error_t> mkdir_path(event_loop_t &loop, const std::string &path, int mode)
{
  uv_fs_t req = {};
  const int result = uv_fs_mkdir(loop.loop(), &req, path.c_str(), mode, nullptr);
  uv_fs_req_cleanup(&req);

  if (result < 0)
  {
    return std::unexpected(error_t{.code = result, .msg = uv_strerror(result)});
  }

  return {};
}

inline std::expected<void, error_t> rmdir_path(event_loop_t &loop, const std::string &path)
{
  uv_fs_t req = {};
  const int result = uv_fs_rmdir(loop.loop(), &req, path.c_str(), nullptr);
  uv_fs_req_cleanup(&req);

  if (result < 0)
  {
    return std::unexpected(error_t{.code = result, .msg = uv_strerror(result)});
  }

  return {};
}

inline std::expected<uv_stat_t, error_t> stat_file(event_loop_t &loop, const std::string &path)
{
  uv_fs_t req = {};
  const int result = uv_fs_stat(loop.loop(), &req, path.c_str(), nullptr);
  if (result < 0)
  {
    uv_fs_req_cleanup(&req);
    return std::unexpected(error_t{.code = result, .msg = uv_strerror(result)});
  }

  const uv_stat_t stat_result = req.statbuf;
  uv_fs_req_cleanup(&req);
  return stat_result;
}

inline std::expected<std::string, error_t> mkdtemp_path(event_loop_t &loop, const std::string &tpl)
{
  uv_fs_t req = {};
  std::string local_tpl = tpl; // NOLINT(performance-unnecessary-copy-initialization) - uv_fs_mkdtemp mutates the buffer
  const int result = uv_fs_mkdtemp(loop.loop(), &req, local_tpl.data(), nullptr);

  if (result < 0)
  {
    uv_fs_req_cleanup(&req);
    return std::unexpected(error_t{.code = result, .msg = uv_strerror(result)});
  }

  std::string path = req.path;
  uv_fs_req_cleanup(&req);
  return path;
}

inline future_t<file_io_state_t> send_file(event_loop_t &loop, file_t &out_file, file_t &in_file, std::int64_t in_offset, std::size_t length, cancellation_t *cancel = nullptr)
{
  using ret_t = future_t<file_io_state_t>;
  using future_ref_ptr_t = ret_t::future_ref_ptr_t;
  ret_t ret;

  if (cancel && cancel->is_cancelled())
  {
    ret.state_ptr->done = true;
    ret.state_ptr->result = std::unexpected(error_t{.code = vio_cancelled, .msg = "cancelled"});
    return ret;
  }

  auto callback = [](uv_fs_t *req_ptr)
  {
    auto state_ref = future_ref_ptr_t::from_raw(req_ptr->data);
    auto result = req_ptr->result;

    if (result < 0)
    {
      state_ref->result = std::unexpected(error_t{.code = static_cast<int>(result), .msg = uv_strerror(result)});
    }
    else
    {
      state_ref->result = static_cast<std::size_t>(result);
    }

    state_ref->done = true;
    state_ref->cancel_registration.reset();
    uv_fs_req_cleanup(req_ptr);
    if (state_ref->continuation)
    {
      state_ref->continuation.resume();
    }
  };

  auto copy = ret.state_ptr;
  ret.state_ptr->req.data = copy.release_to_raw();
  const int call_result = uv_fs_sendfile(loop.loop(), &ret.state_ptr->req, out_file.handle, in_file.handle, in_offset, length, callback);

  if (call_result < 0)
  {
    auto state_ref = future_ref_ptr_t::from_raw(ret.state_ptr->req.data);
    ret.state_ptr->done = true;
    ret.state_ptr->result = std::unexpected(error_t{.code = call_result, .msg = uv_strerror(call_result)});
    return ret;
  }

  if (cancel)
  {
    auto *state_raw = &ret.state_ptr.data();
    ret.state_ptr->cancel_registration = cancel->register_callback([state_raw]()
    {
      if (state_raw->done)
        return;
      uv_cancel((uv_req_t *)&state_raw->req);
    });
  }

  return ret;
}

} // namespace vio