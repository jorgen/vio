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

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string_view>

#include "vio/gui/backends.h"
#include "vio/gui/gui.h"

namespace vio::gui
{
namespace detail
{
namespace
{
constexpr std::int64_t default_frame_interval = 16'666'667;

void cancel_all(waiter_list_t &list, display_impl_t &display) noexcept
{
  while (auto *waiter = list.pop_front())
  {
    waiter->error = errc::canceled;
    display.ready(*waiter);
  }
}

template <typename T>
value_waiter_t<T> &as(waiter_t &waiter) noexcept
{
  return static_cast<value_waiter_t<T> &>(waiter);
}
} // namespace

frame_clock_t::frame_clock_t(loop_core_t &core, std::int64_t interval_ns, void (*fire)(void *), void *context) noexcept
  : _core(core)
  , _interval(interval_ns > 0 ? interval_ns : default_frame_interval)
  , _fire(fire)
  , _context(context)
{
  _timer.owner = this;
  _timer.fire = &frame_clock_t::on_fire;
  _timer.keeps_alive = false;
}

frame_clock_t::~frame_clock_t()
{
  _core.remove_timer(_timer);
}

void frame_clock_t::request() noexcept
{
  if (_timer.armed())
    return;
  const auto now = loop_core_t::now();
  _core.add_timer(_timer, now - now % _interval + _interval);
}

void frame_clock_t::on_fire(timer_node_t *node)
{
  auto *self = static_cast<frame_clock_t *>(node->owner);
  self->_fire(self->_context);
}

window_impl_t::window_impl_t(display_impl_t &display) noexcept
  : display(display)
{
  ++display.windows;
}

window_impl_t::~window_impl_t()
{
  close();
  --display.windows;
}

window_attachment_t::~window_attachment_t()
{
  if (window)
    window->detach(*this);
}

void window_impl_t::attach(window_attachment_t &attachment)
{
  attachment.window = this;
  attachments.push_back(&attachment);
}

void window_impl_t::detach(window_attachment_t &attachment) noexcept
{
  attachment.window = nullptr;
  std::erase(attachments, &attachment);
}

void window_impl_t::close() noexcept
{
  if (!backend)
    return;
  closing = true;
  for (auto *attachment : std::exchange(attachments, {}))
  {
    attachment->window = nullptr;
    attachment->window_closing();
  }
  backend.reset();
  cancel_all(input_waiters, display);
  cancel_all(resize_waiters, display);
  cancel_all(close_waiters, display);
  cancel_all(frame_waiters, display);
  display.forget(*this);
  input.clear();
  visible = false;
}

void window_impl_t::on_resize(extent_t new_size, extent_t new_framebuffer, float new_scale)
{
  if (new_size == size && new_framebuffer == framebuffer && new_scale == scale)
    return;
  size = new_size;
  framebuffer = new_framebuffer;
  scale = new_scale;
  resized = resize_event_t{size, framebuffer, scale};
  damaged = true;
  mark_dirty();
}

void window_impl_t::on_input(input_event_t event)
{
  if (std::holds_alternative<pointer_move_event_t>(event) && !input.empty() && std::holds_alternative<pointer_move_event_t>(input.back()))
  {
    input.back() = std::move(event);
    mark_dirty();
    return;
  }
  if (input.size() >= display.config.input_queue_limit)
  {
    input.pop_front();
    ++input_dropped;
  }
  input.push_back(std::move(event));
  mark_dirty();
}

void window_impl_t::on_close_request() noexcept
{
  ++close_requests;
  mark_dirty();
}

void window_impl_t::on_damage() noexcept
{
  damaged = true;
  mark_dirty();
}

void window_impl_t::on_frame(std::int64_t time_ns) noexcept
{
  frame_tick = true;
  frame_time = time_ns;
  mark_dirty();
}

void window_impl_t::on_visible(bool now_visible) noexcept
{
  if (visible == now_visible)
    return;
  visible = now_visible;
  if (visible)
    damaged = true;
  mark_dirty();
}

bool window_impl_t::frame_ready_now() const noexcept
{
  return backend && visible && (damaged || frame_tick);
}

frame_t window_impl_t::take_frame() noexcept
{
  frame_t frame{size, framebuffer, scale, ++frames, frame_tick ? frame_time : loop_core_t::now(), damaged};
  damaged = false;
  frame_tick = false;
  backend->frame_delivered();
  return frame;
}

void window_impl_t::add_frame_waiter(value_waiter_t<frame_t> &waiter)
{
  frame_waiters.push_back(waiter);
  if (frame_ready_now())
    mark_dirty();
  else
    backend->frame_wanted();
}

void window_impl_t::mark_dirty() noexcept
{
  if (!dirty && backend)
    display.mark_dirty(*this);
}

void window_impl_t::deliver() noexcept
{
  dirty = false;
  if (!backend)
    return;
  while (!input_waiters.empty() && !input.empty())
  {
    auto &waiter = as<input_event_t>(*input_waiters.pop_front());
    waiter.value.emplace(std::move(input.front()));
    input.pop_front();
    display.ready(waiter);
  }
  if (!resize_waiters.empty() && resized)
  {
    auto &waiter = as<resize_event_t>(*resize_waiters.pop_front());
    waiter.value = std::exchange(resized, std::nullopt);
    display.ready(waiter);
  }
  while (!close_waiters.empty() && close_requests > 0)
  {
    --close_requests;
    auto &waiter = as<closed_t>(*close_waiters.pop_front());
    waiter.value.emplace();
    display.ready(waiter);
  }
  if (!frame_waiters.empty() && frame_ready_now())
  {
    const auto frame = take_frame();
    while (auto *raw = frame_waiters.pop_front())
    {
      auto &waiter = as<frame_t>(*raw);
      waiter.value = frame;
      display.ready(waiter);
    }
  }
}

display_impl_t::display_impl_t(loop_core_t &core, const display_config_t &config) noexcept
  : core(core)
  , config(config)
{
  _dispatch_hook.owner = this;
  _dispatch_hook.run = &display_impl_t::on_dispatch;
  _pump_hook.owner = this;
  _pump_hook.run = &display_impl_t::on_pump;
  _finish.owner = this;
  _finish.run = &display_impl_t::on_finish;
  _closed.owner = this;
  _closed.run = &display_impl_t::on_closed;
}

display_impl_t::~display_impl_t() = default;

int display_impl_t::start(backend_factory_t factory)
{
  auto made = factory(*this);
  if (!made)
    return made.error();
  backend = std::move(*made);
  core.add_hook(_dispatch_hook);
  core.add_hook(_pump_hook);
  _started = true;
  return 0;
}

void display_impl_t::release() noexcept
{
  if (windows > 0)
  {
    std::fprintf(stderr, "vio gui: a display was released while %zu window(s) were open; close them first\n", windows);
    std::abort();
  }
  if (!_started)
  {
    delete this;
    return;
  }
  core.remove_hook(_dispatch_hook);
  core.remove_hook(_pump_hook);
  core.defer(_finish);
}

void display_impl_t::on_finish(posted_t *node)
{
  auto *self = static_cast<display_impl_t *>(node->owner);
  cancel_all(self->_clipboard_waiters, *self);
  while (auto *waiter = self->_ready.pop_front())
    waiter->handle.resume();
  self->backend->close(self->core, self->_closed);
}

void display_impl_t::on_closed(posted_t *node)
{
  delete static_cast<display_impl_t *>(node->owner);
}

void display_impl_t::mark_dirty(window_impl_t &window)
{
  window.dirty = true;
  _dirty.push_back(&window);
}

void display_impl_t::forget(window_impl_t &window) noexcept
{
  window.dirty = false;
  std::erase(_dirty, &window);
}

void display_impl_t::add_clipboard_waiter(value_waiter_t<std::string> &waiter)
{
  _clipboard_waiters.push_back(waiter);
  if (_clipboard_requested)
    return;
  _clipboard_requested = true;
  backend->request_clipboard_text();
}

void display_impl_t::clipboard_arrived(std::expected<std::string, int> text) noexcept
{
  _clipboard_requested = false;
  while (auto *raw = _clipboard_waiters.pop_front())
  {
    auto &waiter = as<std::string>(*raw);
    if (text)
      waiter.value = *text;
    else
      waiter.error = text.error();
    ready(waiter);
  }
}

void display_impl_t::on_dispatch(hook_t *hook)
{
  auto *self = static_cast<display_impl_t *>(hook->owner);
  self->backend->dispatch();
}

void display_impl_t::on_pump(hook_t *hook)
{
  static_cast<display_impl_t *>(hook->owner)->pump();
}

void display_impl_t::pump()
{
  for (;;)
  {
    auto dirty = std::exchange(_dirty, {});
    for (auto *window : dirty)
    {
      if (window->dirty)
        window->deliver();
    }
    if (!_ready.empty())
    {
      while (auto *waiter = _ready.pop_front())
        waiter->handle.resume();
      continue;
    }
    backend->flush();
    if (!backend->dispatch_queued())
      break;
  }
}

namespace
{
class null_window_t final : public window_backend_t
{
public:
  null_window_t(window_impl_t &window, const window_config_t &config)
    : _window(window)
    , _clock(window.display.core, window.display.config.frame_interval_ns, &null_window_t::tick, this)
    , _title(config.title)
  {
  }

  void start(const window_config_t &config)
  {
    _window.on_resize(config.size, config.size, 1.0f);
    _window.on_visible(config.visible);
  }

  void set_title(std::string_view title) override
  {
    _title = title;
  }
  int set_size(extent_t size) override
  {
    _window.on_resize(size, size, 1.0f);
    return 0;
  }
  int set_position(point_t position) override
  {
    _position = position;
    return 0;
  }
  [[nodiscard]] std::expected<point_t, int> position() const override
  {
    return _position;
  }
  void set_size_limits(extent_t, extent_t) override
  {
  }
  void set_visible(bool visible) override
  {
    _window.on_visible(visible);
  }
  void set_fullscreen(bool) override
  {
  }
  void minimize() override
  {
    _window.on_visible(false);
  }
  void maximize() override
  {
  }
  void restore() override
  {
    _window.on_visible(true);
  }
  void focus() override
  {
  }
  void set_cursor(cursor_t) override
  {
  }
  void frame_wanted() override
  {
    _clock.request();
  }
  [[nodiscard]] native_window_t native() const override
  {
    return {};
  }

private:
  static void tick(void *context)
  {
    static_cast<null_window_t *>(context)->_window.on_frame(loop_core_t::now());
  }

  window_impl_t &_window;
  frame_clock_t _clock;
  std::string _title;
  point_t _position;
};

class null_display_t final : public display_backend_t
{
public:
  explicit null_display_t(display_impl_t &display)
    : _display(display)
  {
  }

  [[nodiscard]] const char *name() const noexcept override
  {
    return "null";
  }
  [[nodiscard]] platform_t platform() const noexcept override
  {
    return platform_t::x11;
  }
  std::expected<std::unique_ptr<window_backend_t>, int> create_window(window_impl_t &window, const window_config_t &config) override
  {
    auto made = std::make_unique<null_window_t>(window, config);
    made->start(config);
    return made;
  }
  void dispatch() override
  {
  }
  void set_clipboard_text(std::string text) override
  {
    _clipboard = std::move(text);
  }
  void request_clipboard_text() override
  {
    _display.clipboard_arrived(_clipboard);
  }
  [[nodiscard]] void *native_display() const noexcept override
  {
    return nullptr;
  }
  void close(loop_core_t &core, posted_t &done) override
  {
    core.defer(done);
  }

private:
  display_impl_t &_display;
  std::string _clipboard;
};
} // namespace

std::expected<std::unique_ptr<display_backend_t>, int> make_null_backend(display_impl_t &display)
{
  return std::make_unique<null_display_t>(display);
}

namespace
{
backend_factory_t choose_backend(std::string_view name, int &error)
{
  if (name.empty())
  {
    const char *forced = std::getenv("VIO_GUI_BACKEND");
    name = forced ? forced : "";
  }
  if (name == "null")
    return &make_null_backend;
#if defined(VIO_GUI_HAVE_WAYLAND)
  if (name == "wayland")
    return &make_wayland_backend;
#endif
#if defined(VIO_GUI_HAVE_X11)
  if (name == "x11")
    return &make_x11_backend;
#endif
  if (!name.empty())
  {
    error = errc::not_supported;
    return nullptr;
  }
#if defined(_WIN32)
  return &make_win32_backend;
#elif defined(__APPLE__)
  return &make_cocoa_backend;
#else
#if defined(VIO_GUI_HAVE_WAYLAND)
  if (const char *wayland = std::getenv("WAYLAND_DISPLAY"); wayland && *wayland)
    return &make_wayland_backend;
#endif
#if defined(VIO_GUI_HAVE_X11)
  return &make_x11_backend;
#else
  error = errc::not_supported;
  return nullptr;
#endif
#endif
}
} // namespace
} // namespace detail

std::expected<display_t, error_t> display_t::open(event_loop_t &loop, const display_config_t &config)
{
  int error = 0;
  auto factory = detail::choose_backend(config.backend, error);
  if (!factory)
    return std::unexpected(make_error(error));
  auto &core = vio::detail::core(loop);
  display_t display;
  display._impl.reset(new detail::display_impl_t(core, config));
  if (int result = display._impl->start(factory); result < 0)
  {
#if defined(VIO_GUI_HAVE_WAYLAND) && defined(VIO_GUI_HAVE_X11)
    if (factory == &detail::make_wayland_backend && config.backend.empty() && !std::getenv("VIO_GUI_BACKEND"))
    {
      display._impl.reset(new detail::display_impl_t(core, config));
      if (display._impl->start(&detail::make_x11_backend) == 0)
        return display;
    }
#endif
    return std::unexpected(make_error(result));
  }
  return display;
}

std::expected<window_t, error_t> window_t::create(display_t &display, const window_config_t &config)
{
  if (!display)
    return std::unexpected(make_error(errc::invalid_argument));
  window_t window;
  window._impl = std::make_unique<detail::window_impl_t>(*display.impl());
  auto backend = display.impl()->backend->create_window(*window._impl, config);
  if (!backend)
    return std::unexpected(make_error(backend.error()));
  window._impl->backend = std::move(*backend);
  return window;
}

void window_t::set_title(std::string_view title)
{
  if (*this)
    _impl->backend->set_title(title);
}

std::expected<void, error_t> window_t::set_size(extent_t size)
{
  if (!*this)
    return std::unexpected(make_error(errc::canceled));
  if (size.width <= 0 || size.height <= 0)
    return std::unexpected(make_error(errc::invalid_argument));
  if (int result = _impl->backend->set_size(size); result < 0)
    return std::unexpected(make_error(result));
  return {};
}

std::expected<void, error_t> window_t::set_position(point_t position)
{
  if (!*this)
    return std::unexpected(make_error(errc::canceled));
  if (int result = _impl->backend->set_position(position); result < 0)
    return std::unexpected(make_error(result));
  return {};
}

std::expected<point_t, error_t> window_t::position() const
{
  if (!*this)
    return std::unexpected(make_error(errc::canceled));
  auto position = _impl->backend->position();
  if (!position)
    return std::unexpected(make_error(position.error()));
  return *position;
}

void window_t::set_size_limits(extent_t min_size, extent_t max_size)
{
  if (*this)
    _impl->backend->set_size_limits(min_size, max_size);
}

void window_t::show()
{
  if (*this)
    _impl->backend->set_visible(true);
}

void window_t::hide()
{
  if (*this)
    _impl->backend->set_visible(false);
}

void window_t::set_fullscreen(bool fullscreen)
{
  if (*this)
    _impl->backend->set_fullscreen(fullscreen);
}

void window_t::minimize()
{
  if (*this)
    _impl->backend->minimize();
}

void window_t::maximize()
{
  if (*this)
    _impl->backend->maximize();
}

void window_t::restore()
{
  if (*this)
    _impl->backend->restore();
}

void window_t::focus()
{
  if (*this)
    _impl->backend->focus();
}

void window_t::set_cursor(cursor_t cursor)
{
  if (*this)
    _impl->backend->set_cursor(cursor);
}

void window_t::request_frame()
{
  if (*this)
    _impl->on_damage();
}
} // namespace vio::gui
