/*
  Copyright (c) 2026 Jørgen Lind

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

#ifdef __EMSCRIPTEN__
#error "vio/operation/process.h needs the native event loop"
#endif

#include <coroutine>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include "vio/cancellation.h"
#include "vio/errc.h"
#include "vio/error.h"
#include "vio/event_loop.h"
#include "vio/loop/loop_core.h"
#include "vio/owned_payload.h"
#include "vio/ref_counted_wrapper.h"
#include "vio/unique_buf.h"
#include "vio/vio_export.h"

namespace vio
{
struct pty_size_t
{
  std::uint16_t columns = 80;
  std::uint16_t rows = 24;
  std::uint16_t pixel_width = 0;
  std::uint16_t pixel_height = 0;
};

struct environment_variable_t
{
  std::string name;
  std::string value;
};

struct process_options_t
{
  std::string program;
  std::vector<std::string> arguments;
  bool inherit_environment = true;
  std::vector<environment_variable_t> environment;
  std::string working_directory;
  pty_size_t size;
};

struct exit_status_t
{
  int exit_code = 0;
  int signal = 0;
};

inline constexpr int process_signal_hangup = 1;
inline constexpr int process_signal_interrupt = 2;
inline constexpr int process_signal_kill = 9;
inline constexpr int process_signal_terminate = 15;

namespace detail
{
class process_core_t;

enum class process_op_kind : std::uint8_t
{
  read,
  write,
  wait
};

struct process_op_t
{
  using complete_fn_t = void (*)(process_op_t *op);

  complete_fn_t complete = nullptr;
  void *owner = nullptr;
  process_op_t *next = nullptr;
  process_op_t *prev = nullptr;
  std::uint64_t target = 0;
  unique_buf_t buffer;
  exit_status_t status;
  int error = 0;
  process_op_kind kind = process_op_kind::read;
  bool parked = false;
};

struct VIO_EXPORT process_core_deleter_t
{
  void operator()(process_core_t *core) const noexcept;
};

VIO_EXPORT process_core_t *process_core_spawn(loop_core_t &loop, const process_options_t &options, int &error);
VIO_EXPORT resource_t &process_core_resource(process_core_t &core) noexcept;
VIO_EXPORT std::int64_t process_core_pid(const process_core_t &core) noexcept;
VIO_EXPORT int process_core_resize(process_core_t &core, const pty_size_t &size) noexcept;
VIO_EXPORT int process_core_kill(process_core_t &core, int signal) noexcept;
VIO_EXPORT bool process_core_exit_status(const process_core_t &core, exit_status_t &status) noexcept;
VIO_EXPORT int process_core_claim_reader(process_core_t &core, bool claim) noexcept;
VIO_EXPORT process_op_t *process_core_parked_reader(process_core_t &core) noexcept;
VIO_EXPORT int process_core_write(process_core_t &core, std::span<const std::byte> data, std::unique_ptr<owned_payload_t> owned, std::uint64_t &target);
VIO_EXPORT bool process_core_submit(process_core_t &core, process_op_t &op);
VIO_EXPORT bool process_core_cancel(process_core_t &core, process_op_t &op) noexcept;

inline error_t process_cancelled_error()
{
  return error_t{.code = vio_cancelled, .msg = "cancelled"};
}

inline error_t process_error(int code)
{
  return code == vio_cancelled ? process_cancelled_error() : make_error(code);
}
} // namespace detail

struct process_state_t
{
  explicit process_state_t(event_loop_t &loop)
    : event_loop(loop)
  {
  }

  event_loop_t &event_loop;
  std::unique_ptr<detail::process_core_t, detail::process_core_deleter_t> core;
};

struct process_t
{
  ref_ptr_t<process_state_t> handle;
};

inline std::expected<process_t, error_t> process_spawn(event_loop_t &loop, const process_options_t &options)
{
  int code = 0;
  auto *core = detail::process_core_spawn(detail::core(loop), options, code);
  if (!core)
    return std::unexpected(make_error(code));
  process_t process{ref_ptr_t<process_state_t>(loop)};
  process.handle->core.reset(core);
  process.handle.register_resource(detail::process_core_resource(*core));
  return process;
}

[[nodiscard]] inline std::int64_t process_pid(const process_t &process) noexcept
{
  if (!process.handle)
    return -1;
  return detail::process_core_pid(*process.handle->core);
}

inline std::expected<void, error_t> process_resize(process_t &process, pty_size_t size)
{
  if (!process.handle)
    return std::unexpected(make_error(errc::bad_descriptor));
  if (int result = detail::process_core_resize(*process.handle->core, size); result < 0)
    return std::unexpected(make_error(result));
  return {};
}

inline std::expected<void, error_t> process_kill(process_t &process, int signal = process_signal_kill)
{
  if (!process.handle)
    return std::unexpected(make_error(errc::bad_descriptor));
  if (int result = detail::process_core_kill(*process.handle->core, signal); result < 0)
    return std::unexpected(make_error(result));
  return {};
}

[[nodiscard]] inline std::optional<exit_status_t> process_exit_status(const process_t &process)
{
  exit_status_t status;
  if (!process.handle || !detail::process_core_exit_status(*process.handle->core, status))
    return std::nullopt;
  return status;
}

class process_reader_t
{
public:
  process_reader_t(const process_reader_t &) = delete;
  process_reader_t &operator=(const process_reader_t &) = delete;

  process_reader_t(process_reader_t &&other) noexcept
    : _handle(std::move(other._handle))
  {
  }

  process_reader_t &operator=(process_reader_t &&other) noexcept
  {
    if (this != &other)
    {
      release();
      _handle = std::move(other._handle);
    }
    return *this;
  }

  ~process_reader_t()
  {
    release();
  }

  struct awaiter_t
  {
    explicit awaiter_t(process_state_t *state) noexcept
      : state(state)
    {
    }

    awaiter_t(const awaiter_t &) = delete;
    awaiter_t &operator=(const awaiter_t &) = delete;

    ~awaiter_t()
    {
      if (op.parked)
        detail::process_core_cancel(*state->core, op);
    }

    [[nodiscard]] bool await_ready() noexcept
    {
      if (state)
        return false;
      op.error = errc::bad_descriptor;
      return true;
    }

    bool await_suspend(std::coroutine_handle<> handle)
    {
      continuation = handle;
      op.kind = detail::process_op_kind::read;
      op.owner = this;
      op.complete = &awaiter_t::on_complete;
      return !detail::process_core_submit(*state->core, op);
    }

    std::expected<unique_buf_t, error_t> await_resume()
    {
      if (op.error != 0)
        return std::unexpected(detail::process_error(op.error));
      return std::move(op.buffer);
    }

    static void on_complete(detail::process_op_t *op)
    {
      static_cast<awaiter_t *>(op->owner)->continuation.resume();
    }

    process_state_t *state;
    detail::process_op_t op;
    std::coroutine_handle<> continuation = {};
  };

  awaiter_t operator co_await() noexcept
  {
    return awaiter_t{_handle ? &_handle.data() : nullptr};
  }

  void cancel()
  {
    if (!_handle)
      return;
    auto &core = *_handle->core;
    auto *op = detail::process_core_parked_reader(core);
    if (!op)
      return;
    detail::process_core_cancel(core, *op);
    op->error = errc::canceled;
    op->complete(op);
  }

private:
  friend std::expected<process_reader_t, error_t> process_create_reader(process_t &process);

  explicit process_reader_t(ref_ptr_t<process_state_t> handle) noexcept
    : _handle(std::move(handle))
  {
  }

  void release() noexcept
  {
    if (!_handle)
      return;
    cancel();
    detail::process_core_claim_reader(*_handle->core, false);
    _handle = ref_ptr_t<process_state_t>::null();
  }

  ref_ptr_t<process_state_t> _handle = ref_ptr_t<process_state_t>::null();
};

inline std::expected<process_reader_t, error_t> process_create_reader(process_t &process)
{
  if (!process.handle)
    return std::unexpected(make_error(errc::bad_descriptor));
  if (int result = detail::process_core_claim_reader(*process.handle->core, true); result < 0)
    return std::unexpected(make_error(result));
  return process_reader_t{process.handle};
}

namespace detail
{
template <typename Result>
struct process_future_t
{
  process_future_t(ref_ptr_t<process_state_t> state, cancellation_t *cancel, process_op_kind kind) noexcept
    : state(std::move(state))
    , cancel(cancel)
  {
    op.kind = kind;
  }

  process_future_t(process_future_t &&other) noexcept = default;
  process_future_t(const process_future_t &) = delete;
  process_future_t &operator=(const process_future_t &) = delete;
  process_future_t &operator=(process_future_t &&) = delete;

  ~process_future_t()
  {
    if (op.parked)
      process_core_cancel(*state->core, op);
  }

  [[nodiscard]] bool await_ready() noexcept
  {
    if (op.error != 0)
      return true;
    if (cancel && cancel->is_cancelled())
    {
      op.error = vio_cancelled;
      return true;
    }
    return false;
  }

  bool await_suspend(std::coroutine_handle<> handle)
  {
    continuation = handle;
    op.owner = this;
    op.complete = &process_future_t::on_complete;
    if (process_core_submit(*state->core, op))
      return false;
    if (cancel)
    {
      registration = cancel->register_callback([this] {
        if (!process_core_cancel(*state->core, op))
          return;
        op.error = vio_cancelled;
        continuation.resume();
      });
    }
    return true;
  }

  std::expected<Result, error_t> await_resume()
  {
    registration.reset();
    if (op.error != 0)
      return std::unexpected(process_error(op.error));
    if constexpr (std::is_same_v<Result, exit_status_t>)
      return op.status;
    else
      return {};
  }

  static void on_complete(process_op_t *op)
  {
    static_cast<process_future_t *>(op->owner)->continuation.resume();
  }

  ref_ptr_t<process_state_t> state;
  cancellation_t *cancel = nullptr;
  process_op_t op;
  std::coroutine_handle<> continuation = {};
  registration_t registration;
};

inline process_future_t<void> process_write_owned(process_t &process, std::span<const std::byte> data, std::unique_ptr<owned_payload_t> owned, cancellation_t *cancel)
{
  process_future_t<void> ret(process.handle, cancel, process_op_kind::write);
  if (!process.handle)
  {
    ret.op.error = errc::bad_descriptor;
    return ret;
  }
  if (int result = process_core_write(*process.handle->core, data, std::move(owned), ret.op.target); result < 0)
    ret.op.error = result;
  return ret;
}
} // namespace detail

using process_write_future_t = detail::process_future_t<void>;
using process_wait_future_t = detail::process_future_t<exit_status_t>;

inline process_write_future_t process_write(process_t &process, std::span<const std::byte> data, cancellation_t *cancel = nullptr)
{
  return detail::process_write_owned(process, data, nullptr, cancel);
}

inline process_write_future_t process_write(process_t &process, std::string_view text, cancellation_t *cancel = nullptr)
{
  return detail::process_write_owned(process, std::as_bytes(std::span(text.data(), text.size())), nullptr, cancel);
}

template <typename Bytes>
  requires owned_byte_range<std::remove_cvref_t<Bytes>> && (!std::is_lvalue_reference_v<Bytes>) && (!std::is_const_v<std::remove_reference_t<Bytes>>)
process_write_future_t process_write(process_t &process, Bytes &&data, cancellation_t *cancel = nullptr)
{
  auto holder = std::make_unique<owned_payload_impl_t<std::remove_cvref_t<Bytes>>>(std::forward<Bytes>(data));
  auto view = std::as_bytes(std::span(std::ranges::data(holder->value), std::ranges::size(holder->value)));
  return detail::process_write_owned(process, view, std::move(holder), cancel);
}

inline process_wait_future_t process_wait(process_t &process, cancellation_t *cancel = nullptr)
{
  process_wait_future_t ret(process.handle, cancel, detail::process_op_kind::wait);
  if (!process.handle)
    ret.op.error = errc::bad_descriptor;
  return ret;
}
} // namespace vio
