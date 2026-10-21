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

#include <coroutine>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <expected>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include <vio/error.h>
#include <vio/errc.h>
#include <vio/loop/loop_core.h>
#include <vio/loop/timer_heap.h>

#include "vio/gui/events.h"

namespace vio::gui
{
enum class platform_t : std::uint8_t
{
  x11,
  wayland,
  win32,
  cocoa
};

struct native_window_t
{
  platform_t platform = platform_t::x11;
  void *display = nullptr;
  void *handle = nullptr;
  std::uintptr_t id = 0;
  void *view = nullptr;
};

struct window_config_t
{
  std::string title = "vio";
  extent_t size = {640, 480};
  extent_t min_size;
  extent_t max_size;
  bool resizable = true;
  bool visible = true;
  bool decorated = true;
  bool transparent = false;
  bool fullscreen = false;
};

struct display_config_t
{
  std::string backend;
  std::int64_t frame_interval_ns = 0;
  std::size_t input_queue_limit = 4096;
};

namespace detail
{
using vio::detail::hook_t;
using vio::detail::loop_core_t;
using vio::detail::posted_t;
using vio::detail::timer_node_t;

class waiter_list_t;

struct waiter_t
{
  std::coroutine_handle<> handle;
  waiter_t *prev = nullptr;
  waiter_t *next = nullptr;
  waiter_list_t *list = nullptr;
  int error = 0;
};

class waiter_list_t
{
public:
  [[nodiscard]] bool empty() const noexcept
  {
    return _head == nullptr;
  }

  void push_back(waiter_t &waiter) noexcept
  {
    waiter.list = this;
    waiter.next = nullptr;
    waiter.prev = _tail;
    if (_tail)
      _tail->next = &waiter;
    else
      _head = &waiter;
    _tail = &waiter;
  }

  void remove(waiter_t &waiter) noexcept
  {
    if (waiter.prev)
      waiter.prev->next = waiter.next;
    else
      _head = waiter.next;
    if (waiter.next)
      waiter.next->prev = waiter.prev;
    else
      _tail = waiter.prev;
    waiter.prev = nullptr;
    waiter.next = nullptr;
    waiter.list = nullptr;
  }

  waiter_t *pop_front() noexcept
  {
    auto *waiter = _head;
    if (waiter)
      remove(*waiter);
    return waiter;
  }

  [[nodiscard]] waiter_t *front() const noexcept
  {
    return _head;
  }

private:
  waiter_t *_head = nullptr;
  waiter_t *_tail = nullptr;
};

struct closed_t
{
};

template <typename T>
struct value_waiter_t : waiter_t
{
  std::optional<T> value;
};

class display_impl_t;
class window_impl_t;

class window_backend_t
{
public:
  virtual ~window_backend_t() = default;

  virtual void set_title(std::string_view title) = 0;
  virtual int set_size(extent_t size) = 0;
  virtual int set_position(point_t position) = 0;
  [[nodiscard]] virtual std::expected<point_t, int> position() const = 0;
  virtual void set_size_limits(extent_t min_size, extent_t max_size) = 0;
  virtual void set_visible(bool visible) = 0;
  virtual void set_fullscreen(bool fullscreen) = 0;
  virtual void minimize() = 0;
  virtual void maximize() = 0;
  virtual void restore() = 0;
  virtual void focus() = 0;
  virtual void set_cursor(cursor_t cursor) = 0;
  virtual void frame_wanted() = 0;
  virtual void frame_delivered()
  {
  }
  [[nodiscard]] virtual native_window_t native() const = 0;
};

class display_backend_t
{
public:
  virtual ~display_backend_t() = default;

  [[nodiscard]] virtual const char *name() const noexcept = 0;
  [[nodiscard]] virtual platform_t platform() const noexcept = 0;
  [[nodiscard]] virtual std::expected<std::unique_ptr<window_backend_t>, int> create_window(window_impl_t &window, const window_config_t &config) = 0;
  virtual void dispatch() = 0;
  virtual bool dispatch_queued()
  {
    return false;
  }
  virtual void flush()
  {
  }
  virtual void set_clipboard_text(std::string text) = 0;
  virtual void request_clipboard_text() = 0;
  [[nodiscard]] virtual void *native_display() const noexcept = 0;
  virtual void close(loop_core_t &core, posted_t &done) = 0;
};

using backend_factory_t = std::expected<std::unique_ptr<display_backend_t>, int> (*)(display_impl_t &display);

class frame_clock_t
{
public:
  frame_clock_t(loop_core_t &core, std::int64_t interval_ns, void (*fire)(void *), void *context) noexcept;
  frame_clock_t(const frame_clock_t &) = delete;
  frame_clock_t &operator=(const frame_clock_t &) = delete;
  ~frame_clock_t();

  void request() noexcept;
  void set_interval(std::int64_t interval_ns) noexcept
  {
    _interval = interval_ns;
  }

private:
  static void on_fire(timer_node_t *node);

  loop_core_t &_core;
  timer_node_t _timer;
  std::int64_t _interval;
  void (*_fire)(void *);
  void *_context;
};

class window_impl_t
{
public:
  window_impl_t(display_impl_t &display) noexcept;
  window_impl_t(const window_impl_t &) = delete;
  window_impl_t &operator=(const window_impl_t &) = delete;
  ~window_impl_t();

  void close() noexcept;
  [[nodiscard]] bool open() const noexcept
  {
    return static_cast<bool>(backend);
  }

  void on_resize(extent_t size, extent_t framebuffer, float scale);
  void on_input(input_event_t event);
  void on_close_request() noexcept;
  void on_damage() noexcept;
  void on_frame(std::int64_t time_ns) noexcept;
  void on_visible(bool visible) noexcept;

  void add_frame_waiter(value_waiter_t<frame_t> &waiter);
  [[nodiscard]] bool frame_ready_now() const noexcept;
  [[nodiscard]] frame_t take_frame() noexcept;

  void mark_dirty() noexcept;
  void deliver() noexcept;

  display_impl_t &display;
  std::unique_ptr<window_backend_t> backend;
  extent_t size;
  extent_t framebuffer;
  float scale = 1.0f;
  bool visible = false;
  bool damaged = true;
  bool frame_tick = false;
  bool dirty = false;
  bool closing = false;
  std::uint64_t frames = 0;
  std::int64_t frame_time = 0;
  std::size_t input_dropped = 0;

  std::deque<input_event_t> input;
  std::optional<resize_event_t> resized;
  std::size_t close_requests = 0;

  waiter_list_t input_waiters;
  waiter_list_t resize_waiters;
  waiter_list_t close_waiters;
  waiter_list_t frame_waiters;
};

class display_impl_t
{
public:
  display_impl_t(loop_core_t &core, const display_config_t &config) noexcept;
  display_impl_t(const display_impl_t &) = delete;
  display_impl_t &operator=(const display_impl_t &) = delete;
  ~display_impl_t();

  int start(backend_factory_t factory);
  void release() noexcept;

  void ready(waiter_t &waiter) noexcept
  {
    _ready.push_back(waiter);
  }
  void mark_dirty(window_impl_t &window);
  void forget(window_impl_t &window) noexcept;

  void clipboard_arrived(std::expected<std::string, int> text) noexcept;
  void add_clipboard_waiter(value_waiter_t<std::string> &waiter);

  loop_core_t &core;
  display_config_t config;
  std::unique_ptr<display_backend_t> backend;
  std::size_t windows = 0;

private:
  static void on_dispatch(hook_t *hook);
  static void on_pump(hook_t *hook);
  static void on_closed(posted_t *node);
  static void on_finish(posted_t *node);
  void pump();

  hook_t _dispatch_hook;
  hook_t _pump_hook;
  posted_t _finish;
  posted_t _closed;
  waiter_list_t _ready;
  waiter_list_t _clipboard_waiters;
  std::vector<std::expected<std::string, int>> _clipboard_results;
  std::vector<window_impl_t *> _dirty;
  bool _clipboard_requested = false;
  bool _started = false;
};

template <typename T, waiter_list_t window_impl_t::*List>
class channel_awaitable_t : value_waiter_t<T>
{
public:
  explicit channel_awaitable_t(window_impl_t *window) noexcept
    : _window(window)
  {
  }
  channel_awaitable_t(const channel_awaitable_t &) = delete;
  channel_awaitable_t &operator=(const channel_awaitable_t &) = delete;
  ~channel_awaitable_t()
  {
    if (this->list)
      this->list->remove(*this);
  }

  [[nodiscard]] bool await_ready() noexcept
  {
    if (!_window || !_window->open())
    {
      this->error = errc::canceled;
      return true;
    }
    if ((_window->*List).empty() && take())
      return true;
    return false;
  }

  void await_suspend(std::coroutine_handle<> handle)
  {
    this->handle = handle;
    if constexpr (std::is_same_v<T, frame_t>)
      _window->add_frame_waiter(*this);
    else
      (_window->*List).push_back(*this);
  }

  auto await_resume()
  {
    using result_t = std::conditional_t<std::is_same_v<T, closed_t>, std::expected<void, error_t>, std::expected<T, error_t>>;
    if (this->error)
      return result_t(std::unexpected(make_error(this->error)));
    if constexpr (std::is_same_v<T, closed_t>)
      return result_t();
    else
      return result_t(std::move(*this->value));
  }

private:
  bool take()
  {
    if constexpr (std::is_same_v<T, input_event_t>)
    {
      if (_window->input.empty())
        return false;
      this->value.emplace(std::move(_window->input.front()));
      _window->input.pop_front();
      return true;
    }
    else if constexpr (std::is_same_v<T, resize_event_t>)
    {
      if (!_window->resized)
        return false;
      this->value = std::exchange(_window->resized, std::nullopt);
      return true;
    }
    else if constexpr (std::is_same_v<T, frame_t>)
    {
      if (!_window->frame_ready_now())
        return false;
      this->value.emplace(_window->take_frame());
      return true;
    }
    else
    {
      if (_window->close_requests == 0)
        return false;
      --_window->close_requests;
      this->value.emplace();
      return true;
    }
  }

  window_impl_t *_window;
};

} // namespace detail
} // namespace vio::gui
