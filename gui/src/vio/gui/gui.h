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

// A window's events -- input, resizes and close requests -- filtered to Ts... and buffered for this
// subscriber alone. This is the only way to read them: every subscription sees every matching event
// that arrives after it was made, independently of the others, and an event of a type nobody
// subscribed to is not kept. An await yields std::nullopt once the window has closed or the
// subscription was dropped, so `while (auto event = co_await keys)` ends exactly when the stream
// does.
//
//   subscribe<key_event_t>()                 -> std::optional<key_event_t>
//   subscribe<key_event_t, text_event_t>()   -> std::optional<std::variant<key_event_t, text_event_t>>
//   subscribe<>()                            -> std::optional<window_event_t>
//
// Order is kept within a subscription and not across two: subscribe to keys and text together
// when their interleaving matters, or to keys and close_request_t when a dialog must see both in
// the order they happened. A pointer move, resize or close request that arrives straight after
// another of its kind replaces it, since only the latest is worth anything. A subscription made
// after the window's first size does not see it; size() answers that. One coroutine at a time
// should await a given subscription; several are served in the order they started waiting.
template <typename... Ts>
class subscription_t
{
public:
  using event_t = typename detail::subscribed_event<Ts...>::type;
  using awaitable_t = detail::subscription_awaitable_t<Ts...>;

  subscription_t() = default;
  explicit subscription_t(std::unique_ptr<detail::subscription_impl_t> impl) noexcept
    : _impl(std::move(impl))
  {
  }
  subscription_t(subscription_t &&) noexcept = default;
  subscription_t &operator=(subscription_t &&) noexcept = default;
  ~subscription_t() = default;

  [[nodiscard]] awaitable_t next() noexcept
  {
    return awaitable_t(_impl.get());
  }
  [[nodiscard]] awaitable_t operator co_await() noexcept
  {
    return next();
  }

  // False once the window has closed: every later await yields std::nullopt at once.
  [[nodiscard]] explicit operator bool() const noexcept
  {
    return _impl && _impl->window;
  }
  // Events this subscription lost because nobody took them before its queue reached
  // display_config_t::input_queue_limit. Merged events are not counted.
  [[nodiscard]] std::size_t dropped() const noexcept
  {
    return _impl ? _impl->dropped : 0;
  }

private:
  std::unique_ptr<detail::subscription_impl_t> _impl;
};

class window_t
{
public:
  using frame_awaitable_t = detail::frame_awaitable_t;

  window_t() = default;
  window_t(window_t &&) noexcept = default;
  window_t &operator=(window_t &&) noexcept = default;
  ~window_t() = default;

  static std::expected<window_t, error_t> create(display_t &display, const window_config_t &config = {});

  [[nodiscard]] explicit operator bool() const noexcept
  {
    return _impl && _impl->open();
  }

  // std::optional<frame_t>; std::nullopt once the window has closed.
  [[nodiscard]] frame_awaitable_t frame() noexcept
  {
    return frame_awaitable_t(_impl.get());
  }
  template <typename... Ts>
  [[nodiscard]] subscription_t<Ts...> subscribe()
  {
    return subscription_t<Ts...>(std::make_unique<detail::subscription_impl_t>(_impl.get(), detail::event_mask<Ts...>()));
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
