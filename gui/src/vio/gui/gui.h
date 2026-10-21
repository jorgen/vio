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

#include <expected>
#include <memory>
#include <string>
#include <string_view>

#include <vio/event_loop.h>

#include "vio/gui/detail/core.h"
#include "vio/gui/events.h"

namespace vio::gui
{
class window_t;

class clipboard_awaitable_t : detail::value_waiter_t<std::string>
{
public:
  explicit clipboard_awaitable_t(detail::display_impl_t *display) noexcept
    : _display(display)
  {
  }
  clipboard_awaitable_t(const clipboard_awaitable_t &) = delete;
  clipboard_awaitable_t &operator=(const clipboard_awaitable_t &) = delete;
  ~clipboard_awaitable_t()
  {
    if (list)
      list->remove(*this);
  }

  [[nodiscard]] bool await_ready() const noexcept
  {
    return false;
  }
  void await_suspend(std::coroutine_handle<> continuation)
  {
    handle = continuation;
    _display->add_clipboard_waiter(*this);
  }
  std::expected<std::string, error_t> await_resume()
  {
    if (error)
      return std::unexpected(make_error(error));
    return std::move(*value);
  }

private:
  detail::display_impl_t *_display;
};

class display_t
{
public:
  display_t() = default;
  display_t(display_t &&) noexcept = default;
  display_t &operator=(display_t &&) noexcept = default;
  ~display_t() = default;

  static std::expected<display_t, error_t> open(event_loop_t &loop, const display_config_t &config = {});

  [[nodiscard]] explicit operator bool() const noexcept
  {
    return static_cast<bool>(_impl);
  }
  [[nodiscard]] const char *backend_name() const noexcept
  {
    return _impl->backend->name();
  }
  [[nodiscard]] platform_t platform() const noexcept
  {
    return _impl->backend->platform();
  }
  [[nodiscard]] void *native_display() const noexcept
  {
    return _impl->backend->native_display();
  }

  void set_clipboard_text(std::string text)
  {
    _impl->backend->set_clipboard_text(std::move(text));
  }
  [[nodiscard]] clipboard_awaitable_t clipboard_text() noexcept
  {
    return clipboard_awaitable_t(_impl.get());
  }

  [[nodiscard]] detail::display_impl_t *impl() const noexcept
  {
    return _impl.get();
  }

private:
  struct release_t
  {
    void operator()(detail::display_impl_t *impl) const noexcept
    {
      impl->release();
    }
  };
  std::unique_ptr<detail::display_impl_t, release_t> _impl;
};

class window_t
{
public:
  using input_awaitable_t = detail::channel_awaitable_t<input_event_t, &detail::window_impl_t::input_waiters>;
  using resize_awaitable_t = detail::channel_awaitable_t<resize_event_t, &detail::window_impl_t::resize_waiters>;
  using close_awaitable_t = detail::channel_awaitable_t<detail::closed_t, &detail::window_impl_t::close_waiters>;
  using frame_awaitable_t = detail::channel_awaitable_t<frame_t, &detail::window_impl_t::frame_waiters>;

  window_t() = default;
  window_t(window_t &&) noexcept = default;
  window_t &operator=(window_t &&) noexcept = default;
  ~window_t() = default;

  static std::expected<window_t, error_t> create(display_t &display, const window_config_t &config = {});

  [[nodiscard]] explicit operator bool() const noexcept
  {
    return _impl && _impl->open();
  }

  [[nodiscard]] frame_awaitable_t frame() noexcept
  {
    return frame_awaitable_t(_impl.get());
  }
  [[nodiscard]] input_awaitable_t input() noexcept
  {
    return input_awaitable_t(_impl.get());
  }
  [[nodiscard]] resize_awaitable_t resized() noexcept
  {
    return resize_awaitable_t(_impl.get());
  }
  [[nodiscard]] close_awaitable_t close_requested() noexcept
  {
    return close_awaitable_t(_impl.get());
  }

  void close() noexcept
  {
    _impl.reset();
  }

  void set_title(std::string_view title);
  std::expected<void, error_t> set_size(extent_t size);
  std::expected<void, error_t> set_position(point_t position);
  [[nodiscard]] std::expected<point_t, error_t> position() const;
  void set_size_limits(extent_t min_size, extent_t max_size);
  void show();
  void hide();
  void set_fullscreen(bool fullscreen);
  void minimize();
  void maximize();
  void restore();
  void focus();
  void set_cursor(cursor_t cursor);
  void request_frame();

  [[nodiscard]] extent_t size() const noexcept
  {
    return _impl ? _impl->size : extent_t{};
  }
  [[nodiscard]] extent_t framebuffer_size() const noexcept
  {
    return _impl ? _impl->framebuffer : extent_t{};
  }
  [[nodiscard]] float scale() const noexcept
  {
    return _impl ? _impl->scale : 1.0f;
  }
  [[nodiscard]] bool visible() const noexcept
  {
    return _impl && _impl->visible;
  }
  [[nodiscard]] std::size_t input_dropped() const noexcept
  {
    return _impl ? _impl->input_dropped : 0;
  }
  [[nodiscard]] native_window_t native() const
  {
    return _impl && _impl->backend ? _impl->backend->native() : native_window_t{};
  }

  [[nodiscard]] detail::window_impl_t *impl() const noexcept
  {
    return _impl.get();
  }

private:
  std::unique_ptr<detail::window_impl_t> _impl;
};
} // namespace vio::gui
