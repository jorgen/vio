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
#include <coroutine>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <utility>

#include "vio/auto_closer.h"
#include "vio/bit_mask.h"
#include "vio/cancellation.h"
#include "vio/detail/sys_file.h"
#include "vio/error.h"
#include "vio/event_loop.h"
#include "vio/future.h"
#include "vio/loop/backend.h"
#include "vio/loop/blocking_pool.h"
#include "vio/ref_counted_wrapper.h"

namespace vio
{
struct file_t
{
  event_loop_t *event_loop;
  native_file_t handle;
};

inline void close_file(file_t *file)
{
  if (file->handle >= 0)
  {
    detail::fs_close(file->handle);
    file->handle = invalid_native_file;
  }
}

using auto_close_file_t = auto_close_t<file_t, decltype(&close_file)>;

inline auto_close_file_t make_auto_close_file(file_t &&file)
{
  return auto_close_file_t(std::move(file), &close_file);
}

inline std::expected<auto_close_file_t, error_t> open_file(event_loop_t &event_loop, const std::string &path, file_open_flags_t flags, int mode)
{
  native_file_t handle = invalid_native_file;
  if (int result = detail::fs_open(path, flags.value(), mode, handle); result < 0)
    return std::unexpected(make_error(result));
  return make_auto_close_file({&event_loop, handle});
}

inline std::expected<std::pair<auto_close_file_t, std::string>, error_t> mkstemp_file(event_loop_t &event_loop, const std::string &tpl)
{
  std::string path = tpl;
  native_file_t handle = invalid_native_file;
  if (int result = detail::fs_mkstemp(path, handle); result < 0)
    return std::unexpected(make_error(result));
  return std::make_pair(make_auto_close_file({&event_loop, handle}), std::move(path));
}

struct file_io_state_t
{
  detail::pool_job_t job;
  detail::file_op_t op;
  detail::loop_core_t *loop = nullptr;
  void *parked = nullptr;
  native_file_t source = invalid_native_file;
  std::int64_t outcome = errc::canceled;
  bool copy = false;
  bool on_backend = false;
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
      return false;
    this->continuation = continuation;
    return true;
  }

  auto await_resume() noexcept
  {
    return std::move(result);
  }
};

namespace detail
{
inline std::int64_t file_io_perform(file_io_state_t &state) noexcept
{
  auto &op = state.op;
  if (state.copy)
    return fs_sendfile(op.file, state.source, op.offset, op.size);
  switch (op.kind)
  {
  case file_op_kind::read:
    return fs_read(op.file, std::span<std::byte>(op.data, op.size), op.offset);
  case file_op_kind::write:
    return fs_write(op.file, std::span<const std::byte>(op.data, op.size), op.offset);
  case file_op_kind::fsync:
    return fs_fsync(op.file);
  case file_op_kind::fdatasync:
    return fs_fdatasync(op.file);
  }
  return errc::invalid_argument;
}

inline void file_io_finish(file_io_state_t &state)
{
  auto owned = ref_ptr_t<file_io_state_t>::from_raw(std::exchange(state.parked, nullptr));
  state.on_backend = false;
  if (state.outcome < 0)
    state.result = std::unexpected(make_error(static_cast<int>(state.outcome)));
  else
    state.result = static_cast<std::size_t>(state.outcome);
  state.done = true;
  state.cancel_registration.reset();
  if (state.continuation)
    state.continuation.resume();
}

inline void file_io_work(pool_job_t *job)
{
  auto *state = static_cast<file_io_state_t *>(job->owner);
  state->outcome = file_io_perform(*state);
}

inline void file_io_pool_done(pool_job_t *job, bool)
{
  file_io_finish(*static_cast<file_io_state_t *>(job->owner));
}

inline void file_io_backend_done(file_op_t *op)
{
  auto *state = static_cast<file_io_state_t *>(op->owner);
  state->outcome = op->result;
  file_io_finish(*state);
}

inline void file_io_cancel(file_io_state_t &state) noexcept
{
  if (state.done || state.parked == nullptr)
    return;
  state.cancel_registration.reset();
  if (state.on_backend)
    state.loop->backend().cancel_file(state.op);
  else
    pool_cancel(state.job);
}

inline future_t<file_io_state_t> file_io_start(event_loop_t &event_loop, file_op_kind kind, native_file_t file, std::byte *data, std::size_t size, std::int64_t offset, native_file_t source, bool copy,
                                               cancellation_t *cancel)
{
  future_t<file_io_state_t> ret;
  auto &state = ret.state_ptr.data();
  if (cancel && cancel->is_cancelled())
  {
    state.done = true;
    state.result = std::unexpected(error_t{.code = vio_cancelled, .msg = "cancelled"});
    return ret;
  }

  auto &core = detail::core(event_loop);
  state.loop = &core;
  state.source = source;
  state.copy = copy;
  auto &op = state.op;
  op.owner = &state;
  op.kind = kind;
  op.file = file;
  op.offset = offset;
  op.data = data;
  op.size = std::min(size, max_file_io);
  op.result = 0;

  auto parked = ret.state_ptr;
  state.parked = parked.release_to_raw();
  if (!copy && core.backend().supports_async_files())
  {
    state.on_backend = true;
    op.complete = &file_io_backend_done;
    op.in_flight = true;
    core.backend().submit_file(op);
  }
  else
  {
    state.job.owner = &state;
    state.job.work = &file_io_work;
    state.job.done = &file_io_pool_done;
    pool_submit(core, state.job, pool_queue::file);
  }

  if (cancel && !state.done)
  {
    auto *raw = &state;
    state.cancel_registration = cancel->register_callback([raw]() { file_io_cancel(*raw); });
  }
  return ret;
}

inline std::expected<void, error_t> file_status(int result)
{
  if (result < 0)
    return std::unexpected(make_error(result));
  return {};
}

inline std::expected<std::size_t, error_t> file_count(std::int64_t result)
{
  if (result < 0)
    return std::unexpected(make_error(static_cast<int>(result)));
  return static_cast<std::size_t>(result);
}
} // namespace detail

inline future_t<file_io_state_t> write_file(event_loop_t &event_loop, file_t &file, const std::uint8_t *data, std::size_t length, std::int64_t offset, cancellation_t *cancel = nullptr)
{
  auto *bytes = const_cast<std::byte *>(reinterpret_cast<const std::byte *>(data));
  return detail::file_io_start(event_loop, detail::file_op_kind::write, file.handle, bytes, length, offset, invalid_native_file, false, cancel);
}

inline future_t<file_io_state_t> read_file(event_loop_t &event_loop, file_t &file, std::uint8_t *buffer, std::size_t length, std::int64_t offset, cancellation_t *cancel = nullptr)
{
  return detail::file_io_start(event_loop, detail::file_op_kind::read, file.handle, reinterpret_cast<std::byte *>(buffer), length, offset, invalid_native_file, false, cancel);
}

inline future_t<file_io_state_t> fsync_file(event_loop_t &event_loop, file_t &file, cancellation_t *cancel = nullptr)
{
  return detail::file_io_start(event_loop, detail::file_op_kind::fsync, file.handle, nullptr, 0, -1, invalid_native_file, false, cancel);
}

inline future_t<file_io_state_t> fdatasync_file(event_loop_t &event_loop, file_t &file, cancellation_t *cancel = nullptr)
{
  return detail::file_io_start(event_loop, detail::file_op_kind::fdatasync, file.handle, nullptr, 0, -1, invalid_native_file, false, cancel);
}

inline future_t<file_io_state_t> send_file(event_loop_t &loop, file_t &out_file, file_t &in_file, std::int64_t in_offset, std::size_t length, cancellation_t *cancel = nullptr)
{
  return detail::file_io_start(loop, detail::file_op_kind::write, out_file.handle, nullptr, length, in_offset, in_file.handle, true, cancel);
}

inline std::expected<std::size_t, error_t> read_file_sync(file_t &file, std::uint8_t *buffer, std::size_t length, std::int64_t offset)
{
  return detail::file_count(detail::fs_read(file.handle, std::span<std::byte>(reinterpret_cast<std::byte *>(buffer), length), offset));
}

inline std::expected<std::size_t, error_t> write_file_sync(file_t &file, const std::uint8_t *data, std::size_t length, std::int64_t offset)
{
  return detail::file_count(detail::fs_write(file.handle, std::span<const std::byte>(reinterpret_cast<const std::byte *>(data), length), offset));
}

inline std::expected<void, error_t> fsync_file_sync(file_t &file)
{
  return detail::file_status(detail::fs_fsync(file.handle));
}

inline std::expected<void, error_t> fdatasync_file_sync(file_t &file)
{
  return detail::file_status(detail::fs_fdatasync(file.handle));
}

inline std::expected<void, error_t> truncate_file(file_t &file, std::int64_t size)
{
  return detail::file_status(detail::fs_ftruncate(file.handle, size));
}

inline std::expected<file_stat_t, error_t> fstat_file(file_t &file)
{
  file_stat_t status;
  if (int result = detail::fs_fstat(file.handle, status); result < 0)
    return std::unexpected(make_error(result));
  return status;
}

inline std::expected<void, error_t> rename_file(event_loop_t &loop, const std::string &old_path, const std::string &new_path)
{
  (void)loop;
  return detail::file_status(detail::fs_rename(old_path, new_path));
}

inline std::expected<void, error_t> unlink_file(event_loop_t &loop, const std::string &path)
{
  (void)loop;
  return detail::file_status(detail::fs_unlink(path));
}

inline std::expected<void, error_t> mkdir_path(event_loop_t &loop, const std::string &path, int mode)
{
  (void)loop;
  return detail::file_status(detail::fs_mkdir(path, mode));
}

inline std::expected<void, error_t> rmdir_path(event_loop_t &loop, const std::string &path)
{
  (void)loop;
  return detail::file_status(detail::fs_rmdir(path));
}

inline std::expected<file_stat_t, error_t> stat_file(event_loop_t &loop, const std::string &path)
{
  (void)loop;
  file_stat_t status;
  if (int result = detail::fs_stat(path, status); result < 0)
    return std::unexpected(make_error(result));
  return status;
}

inline std::expected<std::string, error_t> mkdtemp_path(event_loop_t &loop, const std::string &tpl)
{
  (void)loop;
  std::string path = tpl;
  if (int result = detail::fs_mkdtemp(path); result < 0)
    return std::unexpected(make_error(result));
  return path;
}
} // namespace vio
