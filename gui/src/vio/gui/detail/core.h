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
#include <variant>
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
  std::uint32_t visual = 0;
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

template <typename T>
struct value_waiter_t : waiter_t
{
  std::optional<T> value;
};

class display_impl_t;
class window_impl_t;

template <typename T, typename... Ts>
constexpr std::size_t event_index(std::variant<Ts...> *) noexcept
{
  constexpr bool matches[] = {std::is_same_v<T, Ts>...};
  for (std::size_t i = 0; i < sizeof...(Ts); ++i)
  {
    if (matches[i])
      return i;
  }
  return sizeof...(Ts);
}

template <typename T>
inline constexpr std::size_t event_index_v = event_index<T>(static_cast<window_event_t *>(nullptr));

template <typename... Ts>
constexpr std::uint32_t event_mask() noexcept
{
  static_assert(std::variant_size_v<window_event_t> <= 32);
  if constexpr (sizeof...(Ts) == 0)
    return (std::uint32_t(1) << std::variant_size_v<window_event_t>) - 1;
  else
  {
    static_assert(((event_index_v<Ts> < std::variant_size_v<window_event_t>) && ...), "subscribe<> takes window event types only");
    return ((std::uint32_t(1) << event_index_v<Ts>) | ...);
  }
}

// One subscriber's view of a window's events, and the only place they are queued. The window copies
// each event into every subscription whose mask names its type, so subscriptions never take events
// from one another, and an event nobody subscribed to is never stored at all.
class subscription_impl_t
{
public:
  subscription_impl_t(window_impl_t *window, std::uint32_t mask);
  subscription_impl_t(const subscription_impl_t &) = delete;
  subscription_impl_t &operator=(const subscription_impl_t &) = delete;
  ~subscription_impl_t();

  [[nodiscard]] bool wants(const window_event_t &event) const noexcept
  {
    return (mask & (std::uint32_t(1) << event.index())) != 0;
  }
  void push(const window_event_t &event, std::size_t limit);
  void end() noexcept;

  window_impl_t *window = nullptr;
  std::uint32_t mask = 0;
  std::size_t dropped = 0;
  std::deque<window_event_t> queue;
  waiter_list_t waiters;
};

class window_attachment_t
{
public:
  window_attachment_t() = default;
  window_attachment_t(const window_attachment_t &) = delete;
  window_attachment_t &operator=(const window_attachment_t &) = delete;
  virtual ~window_attachment_t();

  virtual void window_closing() noexcept = 0;

  window_impl_t *window = nullptr;
};

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
  void on_input(const window_event_t &event);
  void on_close_request();
  void on_damage() noexcept;
  void on_frame(std::int64_t time_ns) noexcept;
  void on_visible(bool visible) noexcept;

  void add_frame_waiter(value_waiter_t<frame_t> &waiter);
  [[nodiscard]] bool frame_ready_now() const noexcept;
  [[nodiscard]] frame_t take_frame() noexcept;

  void mark_dirty() noexcept;
  void deliver() noexcept;
  void attach(window_attachment_t &attachment);
  void detach(window_attachment_t &attachment) noexcept;

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

  waiter_list_t frame_waiters;
  std::vector<window_attachment_t *> attachments;
  std::vector<subscription_impl_t *> subscriptions;
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
  std::shared_ptr<void> gl_state;
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

// Awaiting a frame is what asks for one, which is why frames are not a subscription: a subscription
// would want frames for as long as it lived, and a queued frame is a stale one. Every coroutine
// waiting in the same turn gets the same frame. Yields std::nullopt once the window has closed.
class frame_awaitable_t : value_waiter_t<frame_t>
{
public:
  explicit frame_awaitable_t(window_impl_t *window) noexcept
    : _window(window)
  {
  }
  frame_awaitable_t(const frame_awaitable_t &) = delete;
  frame_awaitable_t &operator=(const frame_awaitable_t &) = delete;
  ~frame_awaitable_t()
  {
    if (list)
      list->remove(*this);
  }

  [[nodiscard]] bool await_ready() noexcept
  {
    if (!_window || !_window->open())
      return true;
    if (_window->frame_waiters.empty() && _window->frame_ready_now())
    {
      value.emplace(_window->take_frame());
      return true;
    }
    return false;
  }

  void await_suspend(std::coroutine_handle<> continuation)
  {
    handle = continuation;
    _window->add_frame_waiter(*this);
  }

  std::optional<frame_t> await_resume() noexcept
  {
    return std::move(value);
  }

private:
  window_impl_t *_window;
};

// What one await on a subscription yields: every window event for subscribe<>(), the event itself
// for one type, a variant of exactly the subscribed types for several.
template <typename... Ts>
struct subscribed_event
{
  using type = std::variant<Ts...>;
};
template <>
struct subscribed_event<>
{
  using type = window_event_t;
};
template <typename T>
struct subscribed_event<T>
{
  using type = T;
};

template <typename... Ts>
class subscription_awaitable_t : value_waiter_t<window_event_t>
{
public:
  using event_t = typename subscribed_event<Ts...>::type;

  explicit subscription_awaitable_t(subscription_impl_t *subscription) noexcept
    : _subscription(subscription)
  {
  }
  subscription_awaitable_t(const subscription_awaitable_t &) = delete;
  subscription_awaitable_t &operator=(const subscription_awaitable_t &) = delete;
  ~subscription_awaitable_t()
  {
    if (list)
      list->remove(*this);
  }

  [[nodiscard]] bool await_ready() noexcept
  {
    if (!_subscription || !_subscription->window)
      return true;
    if (_subscription->waiters.empty() && !_subscription->queue.empty())
    {
      value.emplace(std::move(_subscription->queue.front()));
      _subscription->queue.pop_front();
      return true;
    }
    return false;
  }

  void await_suspend(std::coroutine_handle<> continuation) noexcept
  {
    handle = continuation;
    _subscription->waiters.push_back(*this);
  }

  std::optional<event_t> await_resume()
  {
    if (!value)
      return std::nullopt;
    if constexpr (sizeof...(Ts) == 0)
      return std::move(*value);
    else
      return std::visit(
        [](auto &&event) -> std::optional<event_t> {
          using type_t = std::remove_cvref_t<decltype(event)>;
          if constexpr ((std::is_same_v<type_t, Ts> || ...))
            return event_t(std::move(event));
          else
            return std::nullopt;
        },
        std::move(*value));
  }

private:
  subscription_impl_t *_subscription;
};

} // namespace detail
} // namespace vio::gui
