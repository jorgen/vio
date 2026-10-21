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
#include <memory>

#include "vio/detail/native.h"
#include "vio/loop/intrusive.h"
#include "vio/vio_export.h"

namespace vio::detail
{
class loop_core_t;

enum class backend_kind
{
  automatic,
  epoll,
  io_uring,
  kqueue,
  iocp
};

inline constexpr std::uint8_t interest_read = 1;
inline constexpr std::uint8_t interest_write = 2;

struct io_watch_t
{
  native_socket_t socket = invalid_native_socket;
  op_list_t readers;
  op_list_t writers;
  std::uint32_t epoch = 0;
  bool closed = true;
  std::uint8_t armed = 0;
  std::uint8_t retry = 0;
  io_watch_t *retry_next = nullptr;
  void *backend_state = nullptr;
};

enum class file_op_kind : std::uint8_t
{
  read,
  write,
  fsync,
  fdatasync
};

struct file_op_t
{
  using complete_fn_t = void (*)(file_op_t *op);

  ~file_op_t()
  {
    if (in_flight)
      abort_destroyed_in_flight("file operation");
  }

  complete_fn_t complete = nullptr;
  void *owner = nullptr;
  file_op_kind kind = file_op_kind::read;
  native_file_t file = invalid_native_file;
  std::int64_t offset = -1;
  std::byte *data = nullptr;
  std::size_t size = 0;
  std::int64_t result = 0;
  bool in_flight = false;
  file_op_t *prev = nullptr;
  file_op_t *next = nullptr;
  alignas(16) unsigned char backend_storage[64] = {};
};

class VIO_EXPORT backend_t
{
public:
  explicit backend_t(loop_core_t &loop) noexcept
    : _loop(loop)
  {
    _retry.owner = this;
    _retry.run = &backend_t::on_retry;
  }
  backend_t(const backend_t &) = delete;
  backend_t &operator=(const backend_t &) = delete;
  virtual ~backend_t() = default;

  [[nodiscard]] virtual const char *name() const noexcept = 0;
  [[nodiscard]] virtual std::intptr_t native_handle() const noexcept
  {
    return -1;
  }
  [[nodiscard]] virtual int add_watch(io_watch_t &watch) = 0;
  virtual void remove_watch(io_watch_t &watch, posted_t &done) = 0;
  virtual void wake() noexcept = 0;
  virtual void poll(std::int64_t timeout_ns) = 0;
  virtual void abandon_after_fork() noexcept;

  [[nodiscard]] virtual bool supports_async_files() const noexcept
  {
    return false;
  }
  virtual void submit_file(file_op_t &op);
  virtual void cancel_file(file_op_t &op) noexcept;

  [[nodiscard]] int open_watch(io_watch_t &watch);
  void close_watch(io_watch_t &watch, posted_t &done);
  void wait(io_watch_t &watch, std::uint8_t interest, io_op_t &op);
  void cancel_wait(io_watch_t &watch, io_op_t &op) noexcept;

protected:
  virtual void arm(io_watch_t &watch, std::uint8_t interest);
  void dispatch(io_watch_t &watch, bool readable, bool writable);
  void retry_later(io_watch_t &watch, bool readable, bool writable) noexcept;

  loop_core_t &_loop;

private:
  static void on_retry(posted_t *node);
  void forget_retry(io_watch_t &watch) noexcept;

  posted_t _retry;
  io_watch_t *_retry_head = nullptr;
  io_watch_t *_retry_tail = nullptr;
};

VIO_EXPORT std::unique_ptr<backend_t> make_backend(loop_core_t &loop, backend_kind kind, int &error);
} // namespace vio::detail
