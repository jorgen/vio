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
#error "vio/host_loop.h needs the native event loop"
#endif

#include <chrono>
#include <cstdint>
#include <expected>
#include <optional>

#include "vio/errc.h"
#include "vio/error.h"
#include "vio/event_loop.h"

namespace vio
{
class host_wait_t
{
public:
  virtual ~host_wait_t() = default;
  virtual void wait(std::optional<std::chrono::nanoseconds> timeout) = 0;
};

inline std::expected<void, error_t> loop_set_host_wait(event_loop_t &loop, host_wait_t *host)
{
  auto &core = detail::core(loop);
  if (host && !core.backend().supports_host_wait())
    return std::unexpected(make_error(errc::not_supported));
  core.set_host_wait(host);
  return {};
}

[[nodiscard]] inline std::intptr_t loop_native_handle(event_loop_t &loop) noexcept
{
  return detail::core(loop).backend().native_handle();
}

[[nodiscard]] inline std::optional<std::chrono::nanoseconds> loop_next_timeout(event_loop_t &loop) noexcept
{
  const std::int64_t next = detail::core(loop).next_timeout();
  if (next < 0)
    return std::nullopt;
  return std::chrono::nanoseconds(next);
}

inline void loop_run_nested(event_loop_t &loop)
{
  detail::core(loop).run_nested();
}
} // namespace vio
