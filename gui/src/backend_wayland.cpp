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
#include <cerrno>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include <fcntl.h>
#include <poll.h>
#include <sys/mman.h>
#include <unistd.h>

#include "fd_watch.h"
#include "vio/gui/backends.h"
#include "vio/gui/gui.h"

#include <linux/input-event-codes.h>
#include <wayland-client.h>
#include <wayland-cursor.h>
#include <xkbcommon/xkbcommon.h>

#include "xdg-decoration-unstable-v1.h"
#include "xdg-shell.h"

namespace vio::gui::detail
{
namespace
{
constexpr const char *text_mime = "text/plain;charset=utf-8";

key_t translate_key(std::uint32_t code)
{
  switch (code)
  {
  case KEY_A: return key_t::a;
  case KEY_B: return key_t::b;
  case KEY_C: return key_t::c;
  case KEY_D: return key_t::d;
  case KEY_E: return key_t::e;
  case KEY_F: return key_t::f;
  case KEY_G: return key_t::g;
  case KEY_H: return key_t::h;
  case KEY_I: return key_t::i;
  case KEY_J: return key_t::j;
  case KEY_K: return key_t::k;
  case KEY_L: return key_t::l;
  case KEY_M: return key_t::m;
  case KEY_N: return key_t::n;
  case KEY_O: return key_t::o;
  case KEY_P: return key_t::p;
  case KEY_Q: return key_t::q;
  case KEY_R: return key_t::r;
  case KEY_S: return key_t::s;
  case KEY_T: return key_t::t;
  case KEY_U: return key_t::u;
  case KEY_V: return key_t::v;
  case KEY_W: return key_t::w;
  case KEY_X: return key_t::x;
  case KEY_Y: return key_t::y;
  case KEY_Z: return key_t::z;
  case KEY_1: return key_t::digit_1;
  case KEY_2: return key_t::digit_2;
  case KEY_3: return key_t::digit_3;
  case KEY_4: return key_t::digit_4;
  case KEY_5: return key_t::digit_5;
  case KEY_6: return key_t::digit_6;
  case KEY_7: return key_t::digit_7;
  case KEY_8: return key_t::digit_8;
  case KEY_9: return key_t::digit_9;
  case KEY_0: return key_t::digit_0;
  case KEY_SPACE: return key_t::space;
  case KEY_APOSTROPHE: return key_t::apostrophe;
  case KEY_COMMA: return key_t::comma;
  case KEY_MINUS: return key_t::minus;
  case KEY_DOT: return key_t::period;
  case KEY_SLASH: return key_t::slash;
  case KEY_SEMICOLON: return key_t::semicolon;
  case KEY_EQUAL: return key_t::equal;
  case KEY_LEFTBRACE: return key_t::left_bracket;
  case KEY_BACKSLASH: return key_t::backslash;
  case KEY_RIGHTBRACE: return key_t::right_bracket;
  case KEY_GRAVE: return key_t::grave_accent;
  case KEY_ESC: return key_t::escape;
  case KEY_ENTER: return key_t::enter;
  case KEY_TAB: return key_t::tab;
  case KEY_BACKSPACE: return key_t::backspace;
  case KEY_INSERT: return key_t::insert;
  case KEY_DELETE: return key_t::delete_key;
  case KEY_RIGHT: return key_t::right;
  case KEY_LEFT: return key_t::left;
  case KEY_DOWN: return key_t::down;
  case KEY_UP: return key_t::up;
  case KEY_PAGEUP: return key_t::page_up;
  case KEY_PAGEDOWN: return key_t::page_down;
  case KEY_HOME: return key_t::home;
  case KEY_END: return key_t::end;
  case KEY_CAPSLOCK: return key_t::caps_lock;
  case KEY_SCROLLLOCK: return key_t::scroll_lock;
  case KEY_NUMLOCK: return key_t::num_lock;
  case KEY_SYSRQ: return key_t::print_screen;
  case KEY_PAUSE: return key_t::pause;
  case KEY_F1: return key_t::f1;
  case KEY_F2: return key_t::f2;
  case KEY_F3: return key_t::f3;
  case KEY_F4: return key_t::f4;
  case KEY_F5: return key_t::f5;
  case KEY_F6: return key_t::f6;
  case KEY_F7: return key_t::f7;
  case KEY_F8: return key_t::f8;
  case KEY_F9: return key_t::f9;
  case KEY_F10: return key_t::f10;
  case KEY_F11: return key_t::f11;
  case KEY_F12: return key_t::f12;
  case KEY_KP0: return key_t::keypad_0;
  case KEY_KP1: return key_t::keypad_1;
  case KEY_KP2: return key_t::keypad_2;
  case KEY_KP3: return key_t::keypad_3;
  case KEY_KP4: return key_t::keypad_4;
  case KEY_KP5: return key_t::keypad_5;
  case KEY_KP6: return key_t::keypad_6;
  case KEY_KP7: return key_t::keypad_7;
  case KEY_KP8: return key_t::keypad_8;
  case KEY_KP9: return key_t::keypad_9;
  case KEY_KPDOT: return key_t::keypad_decimal;
  case KEY_KPSLASH: return key_t::keypad_divide;
  case KEY_KPASTERISK: return key_t::keypad_multiply;
  case KEY_KPMINUS: return key_t::keypad_subtract;
  case KEY_KPPLUS: return key_t::keypad_add;
  case KEY_KPENTER: return key_t::keypad_enter;
  case KEY_KPEQUAL: return key_t::keypad_equal;
  case KEY_LEFTSHIFT: return key_t::left_shift;
  case KEY_LEFTCTRL: return key_t::left_control;
  case KEY_LEFTALT: return key_t::left_alt;
  case KEY_LEFTMETA: return key_t::left_super;
  case KEY_RIGHTSHIFT: return key_t::right_shift;
  case KEY_RIGHTCTRL: return key_t::right_control;
  case KEY_RIGHTALT: return key_t::right_alt;
  case KEY_RIGHTMETA: return key_t::right_super;
  case KEY_COMPOSE: return key_t::menu;
  default: return key_t::unknown;
  }
}

const char *cursor_name(cursor_t cursor)
{
  switch (cursor)
  {
  case cursor_t::text: return "xterm";
  case cursor_t::hand: return "hand2";
  case cursor_t::crosshair: return "crosshair";
  case cursor_t::resize_horizontal: return "sb_h_double_arrow";
  case cursor_t::resize_vertical: return "sb_v_double_arrow";
  case cursor_t::resize_all: return "fleur";
  case cursor_t::not_allowed: return "crossed_circle";
  case cursor_t::wait: return "watch";
  default: return "left_ptr";
  }
}

const char *cursor_fallback(cursor_t cursor)
{
  switch (cursor)
  {
  case cursor_t::text: return "text";
  case cursor_t::hand: return "pointer";
  case cursor_t::resize_horizontal: return "ew-resize";
  case cursor_t::resize_vertical: return "ns-resize";
  case cursor_t::resize_all: return "move";
  case cursor_t::not_allowed: return "not-allowed";
  case cursor_t::wait: return "wait";
  default: return "default";
  }
}

struct output_t
{
  wl_output *output = nullptr;
  std::uint32_t name = 0;
  int scale = 1;
};

class wayland_display_t;

class wayland_window_t final : public window_backend_t
{
public:
  wayland_window_t(wayland_display_t &display, window_impl_t &window);
  ~wayland_window_t() override;

  int create(const window_config_t &config);

  void set_title(std::string_view title) override;
  int set_size(extent_t size) override;
  int set_position(point_t position) override;
  [[nodiscard]] std::expected<point_t, int> position() const override;
  void set_size_limits(extent_t min_size, extent_t max_size) override;
  void set_visible(bool visible) override;
  void set_fullscreen(bool fullscreen) override;
  void minimize() override;
  void maximize() override;
  void restore() override;
  void focus() override;
  void set_cursor(cursor_t cursor) override;
  void frame_wanted() override;
  void frame_delivered() override;
  [[nodiscard]] native_window_t native() const override;

  void output_scale_changed();

  window_impl_t &window;
  wl_surface *surface = nullptr;
  cursor_t cursor = cursor_t::arrow;

private:
  void create_role();
  void destroy_role();
  void apply_size();
  int scale() const;

  static void on_surface_enter(void *data, wl_surface *, wl_output *output);
  static void on_surface_leave(void *data, wl_surface *, wl_output *output);
  static void on_preferred_scale(void *data, wl_surface *, std::int32_t factor);
  static void on_preferred_transform(void *, wl_surface *, std::uint32_t);
  static void on_xdg_configure(void *data, xdg_surface *, std::uint32_t serial);
  static void on_toplevel_configure(void *data, xdg_toplevel *, std::int32_t width, std::int32_t height, wl_array *states);
  static void on_toplevel_close(void *data, xdg_toplevel *);
  static void on_toplevel_bounds(void *, xdg_toplevel *, std::int32_t, std::int32_t);
  static void on_toplevel_capabilities(void *, xdg_toplevel *, wl_array *);
  static void on_frame_done(void *data, wl_callback *callback, std::uint32_t time);
  static void tick(void *context);

  static constexpr wl_surface_listener surface_listener{&on_surface_enter, &on_surface_leave, &on_preferred_scale, &on_preferred_transform};
  static constexpr xdg_surface_listener xdg_listener{&on_xdg_configure};
  static constexpr xdg_toplevel_listener toplevel_listener{&on_toplevel_configure, &on_toplevel_close, &on_toplevel_bounds, &on_toplevel_capabilities};
  static constexpr wl_callback_listener frame_listener{&on_frame_done};

  wayland_display_t &_display;
  xdg_surface *_xdg_surface = nullptr;
  xdg_toplevel *_toplevel = nullptr;
  zxdg_toplevel_decoration_v1 *_decoration = nullptr;
  wl_callback *_frame_callback = nullptr;
  frame_clock_t _clock;
  std::vector<wl_output *> _outputs;
  std::string _title;
  extent_t _size;
  extent_t _pending_size;
  extent_t _min_size;
  extent_t _max_size;
  int _preferred_scale = 0;
  int _applied_scale = 1;
  bool _configured = false;
  bool _fullscreen = false;
  bool _maximized = false;
  bool _decorated = true;
  bool _resizable = true;
  bool _shown = false;
};

class clipboard_read_t
{
public:
  clipboard_read_t(wayland_display_t &display, int fd);
  ~clipboard_read_t();

  static void on_readable(void *context);
  void finish(std::expected<std::string, int> result);

  wayland_display_t &display;
  std::unique_ptr<fd_watch_t> watch;
  std::string text;
  int fd;
  bool done = false;
};

class wayland_display_t final : public display_backend_t
{
public:
  explicit wayland_display_t(display_impl_t &display)
    : impl(display)
    , _watch(std::make_unique<fd_watch_t>(display.core, "wayland display"))
  {
    _repeat.owner = this;
    _repeat.fire = &wayland_display_t::on_repeat;
    _repeat.keeps_alive = false;
  }

  ~wayland_display_t() override
  {
    impl.core.remove_timer(_repeat);
    reads.clear();
    if (_source)
      wl_data_source_destroy(_source);
    if (_offer)
      wl_data_offer_destroy(_offer);
    if (_data_device)
      wl_data_device_destroy(_data_device);
    if (_data_manager)
      wl_data_device_manager_destroy(_data_manager);
    if (_cursor_surface)
      wl_surface_destroy(_cursor_surface);
    if (_cursor_theme)
      wl_cursor_theme_destroy(_cursor_theme);
    if (_xkb_state)
      xkb_state_unref(_xkb_state);
    if (_xkb_keymap)
      xkb_keymap_unref(_xkb_keymap);
    if (_xkb)
      xkb_context_unref(_xkb);
    if (_pointer)
      wl_pointer_destroy(_pointer);
    if (_keyboard)
      wl_keyboard_destroy(_keyboard);
    if (_seat)
      wl_seat_destroy(_seat);
    for (auto &output : outputs)
      wl_output_destroy(output.output);
    if (decoration_manager)
      zxdg_decoration_manager_v1_destroy(decoration_manager);
    if (wm_base)
      xdg_wm_base_destroy(wm_base);
    if (_shm)
      wl_shm_destroy(_shm);
    if (compositor)
      wl_compositor_destroy(compositor);
    if (_registry)
      wl_registry_destroy(_registry);
    if (display)
      wl_display_disconnect(display);
  }

  int open()
  {
    display = wl_display_connect(nullptr);
    if (!display)
      return errc::no_such_device;
    _registry = wl_display_get_registry(display);
    wl_registry_add_listener(_registry, &registry_listener, this);
    if (wl_display_roundtrip(display) < 0 || wl_display_roundtrip(display) < 0)
      return errc::io_error;
    if (!compositor || !wm_base)
      return errc::not_supported;
    _xkb = xkb_context_new(XKB_CONTEXT_NO_FLAGS);
    if (int result = _watch->open(wl_display_get_fd(display)); result < 0)
      return result;
    return 0;
  }

  [[nodiscard]] const char *name() const noexcept override
  {
    return "wayland";
  }
  [[nodiscard]] platform_t platform() const noexcept override
  {
    return platform_t::wayland;
  }

  std::expected<std::unique_ptr<window_backend_t>, int> create_window(window_impl_t &window, const window_config_t &config) override
  {
    auto made = std::make_unique<wayland_window_t>(*this, window);
    if (int result = made->create(config); result < 0)
      return std::unexpected(result);
    windows.push_back(made.get());
    return made;
  }

  void dispatch() override
  {
    _watch->take_readable();
    wl_display_dispatch_pending(display);
    for (;;)
    {
      while (wl_display_prepare_read(display) != 0)
        wl_display_dispatch_pending(display);
      wl_display_flush(display);
      pollfd descriptor{wl_display_get_fd(display), POLLIN, 0};
      if (::poll(&descriptor, 1, 0) <= 0)
      {
        wl_display_cancel_read(display);
        break;
      }
      if (wl_display_read_events(display) < 0)
        break;
      wl_display_dispatch_pending(display);
    }
    _watch->park();
  }

  bool dispatch_queued() override
  {
    return wl_display_dispatch_pending(display) > 0;
  }

  void flush() override
  {
    wl_display_flush(display);
  }

  void set_clipboard_text(std::string text) override
  {
    _clipboard_text = std::move(text);
    if (!_data_manager || !_data_device)
      return;
    if (_source)
      wl_data_source_destroy(_source);
    _source = wl_data_device_manager_create_data_source(_data_manager);
    wl_data_source_add_listener(_source, &source_listener, this);
    wl_data_source_offer(_source, text_mime);
    wl_data_source_offer(_source, "text/plain");
    wl_data_source_offer(_source, "UTF8_STRING");
    wl_data_device_set_selection(_data_device, _source, _serial);
  }

  void request_clipboard_text() override
  {
    if (_source)
    {
      impl.clipboard_arrived(_clipboard_text);
      return;
    }
    if (!_offer || !_offer_has_text)
    {
      impl.clipboard_arrived(std::string());
      return;
    }
    int fds[2];
    if (::pipe2(fds, O_CLOEXEC | O_NONBLOCK) < 0)
    {
      impl.clipboard_arrived(std::unexpected(errc::too_many_open_files));
      return;
    }
    wl_data_offer_receive(_offer, text_mime, fds[1]);
    ::close(fds[1]);
    wl_display_flush(display);
    reads.push_back(std::make_unique<clipboard_read_t>(*this, fds[0]));
  }

  [[nodiscard]] void *native_display() const noexcept override
  {
    return display;
  }

  void close(loop_core_t &core, posted_t &done) override
  {
    _done = &done;
    _core = &core;
    _pending_closes = 1;
    for (auto &read : reads)
    {
      ++_pending_closes;
      if (read->watch->closing())
        continue;
      read->done = true;
      read->watch->close(&wayland_display_t::on_watch_closed, this);
    }
    _watch->close(&wayland_display_t::on_watch_closed, this);
  }

  void remove(wayland_window_t *window)
  {
    std::erase(windows, window);
    if (_pointer_window == window)
      _pointer_window = nullptr;
    if (_keyboard_window == window)
    {
      _keyboard_window = nullptr;
      impl.core.remove_timer(_repeat);
    }
  }

  wayland_window_t *find(wl_surface *surface)
  {
    for (auto *window : windows)
    {
      if (window->surface == surface)
        return window;
    }
    return nullptr;
  }

  output_t *find(wl_output *output)
  {
    for (auto &entry : outputs)
    {
      if (entry.output == output)
        return &entry;
    }
    return nullptr;
  }

  void apply_cursor(wayland_window_t &window)
  {
    if (!_pointer || _pointer_window != &window)
      return;
    if (window.cursor == cursor_t::hidden)
    {
      wl_pointer_set_cursor(_pointer, _pointer_serial, nullptr, 0, 0);
      return;
    }
    if (!_cursor_theme && _shm)
      _cursor_theme = wl_cursor_theme_load(nullptr, 24, _shm);
    if (!_cursor_theme)
      return;
    wl_cursor *shape = wl_cursor_theme_get_cursor(_cursor_theme, cursor_name(window.cursor));
    if (!shape)
      shape = wl_cursor_theme_get_cursor(_cursor_theme, cursor_fallback(window.cursor));
    if (!shape || shape->image_count == 0)
      return;
    wl_cursor_image *image = shape->images[0];
    wl_buffer *buffer = wl_cursor_image_get_buffer(image);
    if (!buffer)
      return;
    if (!_cursor_surface)
      _cursor_surface = wl_compositor_create_surface(compositor);
    wl_pointer_set_cursor(_pointer, _pointer_serial, _cursor_surface, static_cast<std::int32_t>(image->hotspot_x), static_cast<std::int32_t>(image->hotspot_y));
    wl_surface_attach(_cursor_surface, buffer, 0, 0);
    wl_surface_damage(_cursor_surface, 0, 0, static_cast<std::int32_t>(image->width), static_cast<std::int32_t>(image->height));
    wl_surface_commit(_cursor_surface);
  }

  void read_finished(clipboard_read_t *read)
  {
    if (_done)
    {
      on_watch_closed(this);
      return;
    }
    std::erase_if(reads, [read](const auto &entry) { return entry.get() == read; });
  }

  display_impl_t &impl;
  wl_display *display = nullptr;
  wl_compositor *compositor = nullptr;
  xdg_wm_base *wm_base = nullptr;
  zxdg_decoration_manager_v1 *decoration_manager = nullptr;
  std::vector<output_t> outputs;
  std::vector<wayland_window_t *> windows;
  std::vector<std::unique_ptr<clipboard_read_t>> reads;
  std::uint32_t compositor_version = 0;

private:
  static void on_global(void *data, wl_registry *registry, std::uint32_t name, const char *interface, std::uint32_t version)
  {
    auto *self = static_cast<wayland_display_t *>(data);
    const std::string_view kind(interface);
    if (kind == wl_compositor_interface.name)
    {
      self->compositor_version = std::min(version, 6u);
      self->compositor = static_cast<wl_compositor *>(wl_registry_bind(registry, name, &wl_compositor_interface, self->compositor_version));
    }
    else if (kind == xdg_wm_base_interface.name)
    {
      self->wm_base = static_cast<xdg_wm_base *>(wl_registry_bind(registry, name, &xdg_wm_base_interface, std::min(version, 4u)));
      xdg_wm_base_add_listener(self->wm_base, &wm_base_listener, self);
    }
    else if (kind == wl_shm_interface.name)
    {
      self->_shm = static_cast<wl_shm *>(wl_registry_bind(registry, name, &wl_shm_interface, 1));
    }
    else if (kind == wl_seat_interface.name && !self->_seat)
    {
      self->_seat = static_cast<wl_seat *>(wl_registry_bind(registry, name, &wl_seat_interface, std::min(version, 5u)));
      wl_seat_add_listener(self->_seat, &seat_listener, self);
      self->create_data_device();
    }
    else if (kind == wl_output_interface.name)
    {
      auto *output = static_cast<wl_output *>(wl_registry_bind(registry, name, &wl_output_interface, std::min(version, 2u)));
      self->outputs.push_back({output, name, 1});
      wl_output_add_listener(output, &output_listener, self);
    }
    else if (kind == zxdg_decoration_manager_v1_interface.name)
    {
      self->decoration_manager = static_cast<zxdg_decoration_manager_v1 *>(wl_registry_bind(registry, name, &zxdg_decoration_manager_v1_interface, 1));
    }
    else if (kind == wl_data_device_manager_interface.name)
    {
      self->_data_manager = static_cast<wl_data_device_manager *>(wl_registry_bind(registry, name, &wl_data_device_manager_interface, std::min(version, 3u)));
      self->create_data_device();
    }
  }

  static void on_global_remove(void *data, wl_registry *, std::uint32_t name)
  {
    auto *self = static_cast<wayland_display_t *>(data);
    auto found = std::find_if(self->outputs.begin(), self->outputs.end(), [name](const output_t &output) { return output.name == name; });
    if (found == self->outputs.end())
      return;
    wl_output_destroy(found->output);
    self->outputs.erase(found);
    for (auto *window : self->windows)
      window->output_scale_changed();
  }

  static void on_ping(void *, xdg_wm_base *base, std::uint32_t serial)
  {
    xdg_wm_base_pong(base, serial);
  }

  static void on_output_geometry(void *, wl_output *, std::int32_t, std::int32_t, std::int32_t, std::int32_t, std::int32_t, const char *, const char *, std::int32_t)
  {
  }
  static void on_output_mode(void *, wl_output *, std::uint32_t, std::int32_t, std::int32_t, std::int32_t)
  {
  }
  static void on_output_done(void *data, wl_output *)
  {
    auto *self = static_cast<wayland_display_t *>(data);
    for (auto *window : self->windows)
      window->output_scale_changed();
  }
  static void on_output_scale(void *data, wl_output *output, std::int32_t factor)
  {
    if (auto *entry = static_cast<wayland_display_t *>(data)->find(output))
      entry->scale = std::max(1, factor);
  }

  void create_data_device()
  {
    if (_data_device || !_data_manager || !_seat)
      return;
    _data_device = wl_data_device_manager_get_data_device(_data_manager, _seat);
    wl_data_device_add_listener(_data_device, &data_device_listener, this);
  }

  static void on_capabilities(void *data, wl_seat *seat, std::uint32_t capabilities)
  {
    auto *self = static_cast<wayland_display_t *>(data);
    const bool pointer = capabilities & WL_SEAT_CAPABILITY_POINTER;
    const bool keyboard = capabilities & WL_SEAT_CAPABILITY_KEYBOARD;
    if (pointer && !self->_pointer)
    {
      self->_pointer = wl_seat_get_pointer(seat);
      wl_pointer_add_listener(self->_pointer, &pointer_listener, self);
    }
    else if (!pointer && self->_pointer)
    {
      wl_pointer_destroy(self->_pointer);
      self->_pointer = nullptr;
      self->_pointer_window = nullptr;
    }
    if (keyboard && !self->_keyboard)
    {
      self->_keyboard = wl_seat_get_keyboard(seat);
      wl_keyboard_add_listener(self->_keyboard, &keyboard_listener, self);
    }
    else if (!keyboard && self->_keyboard)
    {
      wl_keyboard_destroy(self->_keyboard);
      self->_keyboard = nullptr;
      self->_keyboard_window = nullptr;
    }
  }
  static void on_seat_name(void *, wl_seat *, const char *)
  {
  }

  static void on_pointer_enter(void *data, wl_pointer *, std::uint32_t serial, wl_surface *surface, wl_fixed_t x, wl_fixed_t y)
  {
    auto *self = static_cast<wayland_display_t *>(data);
    self->_pointer_serial = serial;
    self->_pointer_window = self->find(surface);
    self->_pointer_position = {wl_fixed_to_double(x), wl_fixed_to_double(y)};
    if (!self->_pointer_window)
      return;
    self->apply_cursor(*self->_pointer_window);
    self->_pointer_window->window.on_input(pointer_enter_event_t{true, self->_pointer_position});
  }
  static void on_pointer_leave(void *data, wl_pointer *, std::uint32_t, wl_surface *)
  {
    auto *self = static_cast<wayland_display_t *>(data);
    if (self->_pointer_window)
      self->_pointer_window->window.on_input(pointer_enter_event_t{false, self->_pointer_position});
    self->_pointer_window = nullptr;
  }
  static void on_pointer_motion(void *data, wl_pointer *, std::uint32_t, wl_fixed_t x, wl_fixed_t y)
  {
    auto *self = static_cast<wayland_display_t *>(data);
    self->_pointer_position = {wl_fixed_to_double(x), wl_fixed_to_double(y)};
    if (self->_pointer_window)
      self->_pointer_window->window.on_input(pointer_move_event_t{self->_pointer_position, self->_modifiers});
  }
  static void on_pointer_button(void *data, wl_pointer *, std::uint32_t serial, std::uint32_t, std::uint32_t code, std::uint32_t state)
  {
    auto *self = static_cast<wayland_display_t *>(data);
    self->_serial = serial;
    if (!self->_pointer_window)
      return;
    button_t button = button_t::other;
    if (code == BTN_LEFT)
      button = button_t::left;
    else if (code == BTN_RIGHT)
      button = button_t::right;
    else if (code == BTN_MIDDLE)
      button = button_t::middle;
    else if (code == BTN_SIDE)
      button = button_t::back;
    else if (code == BTN_EXTRA)
      button = button_t::forward;
    self->_pointer_window->window.on_input(pointer_button_event_t{button, state == WL_POINTER_BUTTON_STATE_PRESSED, self->_pointer_position, self->_modifiers});
  }
  static void on_pointer_axis(void *data, wl_pointer *, std::uint32_t, std::uint32_t axis, wl_fixed_t value)
  {
    auto *self = static_cast<wayland_display_t *>(data);
    if (!self->_pointer_window)
      return;
    const double amount = -wl_fixed_to_double(value) / 10.0;
    scroll_event_t event{0, 0, self->_pointer_position, self->_modifiers};
    if (axis == WL_POINTER_AXIS_VERTICAL_SCROLL)
      event.dy = amount;
    else
      event.dx = -amount;
    self->_pointer_window->window.on_input(event);
  }
  static void on_pointer_frame(void *, wl_pointer *)
  {
  }
  static void on_pointer_axis_source(void *, wl_pointer *, std::uint32_t)
  {
  }
  static void on_pointer_axis_stop(void *, wl_pointer *, std::uint32_t, std::uint32_t)
  {
  }
  static void on_pointer_axis_discrete(void *, wl_pointer *, std::uint32_t, std::int32_t)
  {
  }
  static void on_pointer_axis_value120(void *, wl_pointer *, std::uint32_t, std::int32_t)
  {
  }
  static void on_pointer_axis_direction(void *, wl_pointer *, std::uint32_t, std::uint32_t)
  {
  }

  static void on_keymap(void *data, wl_keyboard *, std::uint32_t format, std::int32_t fd, std::uint32_t size)
  {
    auto *self = static_cast<wayland_display_t *>(data);
    if (format != WL_KEYBOARD_KEYMAP_FORMAT_XKB_V1 || !self->_xkb)
    {
      ::close(fd);
      return;
    }
    void *mapped = ::mmap(nullptr, size, PROT_READ, MAP_PRIVATE, fd, 0);
    ::close(fd);
    if (mapped == MAP_FAILED)
      return;
    xkb_keymap *keymap = xkb_keymap_new_from_buffer(self->_xkb, static_cast<const char *>(mapped), strnlen(static_cast<const char *>(mapped), size), XKB_KEYMAP_FORMAT_TEXT_V1, XKB_KEYMAP_COMPILE_NO_FLAGS);
    ::munmap(mapped, size);
    if (!keymap)
      return;
    if (self->_xkb_state)
      xkb_state_unref(self->_xkb_state);
    if (self->_xkb_keymap)
      xkb_keymap_unref(self->_xkb_keymap);
    self->_xkb_keymap = keymap;
    self->_xkb_state = xkb_state_new(keymap);
  }
  static void on_keyboard_enter(void *data, wl_keyboard *, std::uint32_t serial, wl_surface *surface, wl_array *)
  {
    auto *self = static_cast<wayland_display_t *>(data);
    self->_serial = serial;
    self->_keyboard_window = self->find(surface);
    if (self->_keyboard_window)
      self->_keyboard_window->window.on_input(focus_event_t{true});
  }
  static void on_keyboard_leave(void *data, wl_keyboard *, std::uint32_t, wl_surface *)
  {
    auto *self = static_cast<wayland_display_t *>(data);
    self->impl.core.remove_timer(self->_repeat);
    if (self->_keyboard_window)
      self->_keyboard_window->window.on_input(focus_event_t{false});
    self->_keyboard_window = nullptr;
  }
  static void on_key(void *data, wl_keyboard *, std::uint32_t serial, std::uint32_t, std::uint32_t code, std::uint32_t state)
  {
    auto *self = static_cast<wayland_display_t *>(data);
    self->_serial = serial;
    if (!self->_keyboard_window)
      return;
    const bool pressed = state == WL_KEYBOARD_KEY_STATE_PRESSED;
    self->emit_key(code, pressed, false);
    if (pressed && self->_repeat_rate > 0 && self->_xkb_keymap && xkb_keymap_key_repeats(self->_xkb_keymap, code + 8))
    {
      self->_repeat_code = code;
      self->impl.core.add_timer(self->_repeat, loop_core_t::deadline_after(std::int64_t(self->_repeat_delay) * 1'000'000));
    }
    else if (!pressed && code == self->_repeat_code)
    {
      self->impl.core.remove_timer(self->_repeat);
    }
  }
  static void on_modifiers(void *data, wl_keyboard *, std::uint32_t, std::uint32_t depressed, std::uint32_t latched, std::uint32_t locked, std::uint32_t group)
  {
    auto *self = static_cast<wayland_display_t *>(data);
    if (!self->_xkb_state)
      return;
    xkb_state_update_mask(self->_xkb_state, depressed, latched, locked, 0, 0, group);
    auto active = [self](const char *name) { return xkb_state_mod_name_is_active(self->_xkb_state, name, XKB_STATE_MODS_EFFECTIVE) > 0; };
    auto modifiers = modifier_t::none;
    if (active(XKB_MOD_NAME_SHIFT))
      modifiers = modifiers | modifier_t::shift;
    if (active(XKB_MOD_NAME_CTRL))
      modifiers = modifiers | modifier_t::control;
    if (active(XKB_MOD_NAME_ALT))
      modifiers = modifiers | modifier_t::alt;
    if (active(XKB_MOD_NAME_LOGO))
      modifiers = modifiers | modifier_t::super;
    if (active(XKB_MOD_NAME_CAPS))
      modifiers = modifiers | modifier_t::caps_lock;
    if (active(XKB_MOD_NAME_NUM))
      modifiers = modifiers | modifier_t::num_lock;
    self->_modifiers = modifiers;
  }
  static void on_repeat_info(void *data, wl_keyboard *, std::int32_t rate, std::int32_t delay)
  {
    auto *self = static_cast<wayland_display_t *>(data);
    self->_repeat_rate = rate;
    self->_repeat_delay = delay;
  }

  static void on_repeat(timer_node_t *node)
  {
    auto *self = static_cast<wayland_display_t *>(node->owner);
    if (!self->_keyboard_window || self->_repeat_rate <= 0)
      return;
    self->emit_key(self->_repeat_code, true, true);
    self->impl.core.add_timer(self->_repeat, loop_core_t::deadline_after(1'000'000'000 / self->_repeat_rate));
  }

  void emit_key(std::uint32_t code, bool pressed, bool repeat)
  {
    key_event_t event{translate_key(code), code, _modifiers, pressed, repeat};
    _keyboard_window->window.on_input(event);
    if (!pressed || !_xkb_state)
      return;
    char buffer[64];
    const int length = xkb_state_key_get_utf8(_xkb_state, code + 8, buffer, sizeof(buffer));
    if (length <= 0 || length >= static_cast<int>(sizeof(buffer)))
      return;
    std::string text(buffer, static_cast<std::size_t>(length));
    if (static_cast<unsigned char>(text[0]) < 0x20 || text[0] == 0x7f)
      return;
    _keyboard_window->window.on_input(text_event_t{std::move(text)});
  }

  static void on_data_offer(void *data, wl_data_device *, wl_data_offer *offer)
  {
    auto *self = static_cast<wayland_display_t *>(data);
    wl_data_offer_add_listener(offer, &offer_listener, self);
  }
  static void on_drag_enter(void *, wl_data_device *, std::uint32_t, wl_surface *, wl_fixed_t, wl_fixed_t, wl_data_offer *offer)
  {
    if (offer)
      wl_data_offer_destroy(offer);
  }
  static void on_drag_leave(void *, wl_data_device *)
  {
  }
  static void on_drag_motion(void *, wl_data_device *, std::uint32_t, wl_fixed_t, wl_fixed_t)
  {
  }
  static void on_drop(void *, wl_data_device *)
  {
  }
  static void on_selection(void *data, wl_data_device *, wl_data_offer *offer)
  {
    auto *self = static_cast<wayland_display_t *>(data);
    if (self->_offer && self->_offer != offer)
      wl_data_offer_destroy(self->_offer);
    self->_offer = offer;
    self->_offer_has_text = offer && wl_data_offer_get_user_data(offer) == self->text_marker();
  }
  static void on_offer_mime(void *data, wl_data_offer *offer, const char *mime)
  {
    auto *self = static_cast<wayland_display_t *>(data);
    if (std::strcmp(mime, text_mime) == 0)
      wl_data_offer_set_user_data(offer, self->text_marker());
  }
  static void on_offer_actions(void *, wl_data_offer *, std::uint32_t)
  {
  }
  static void on_offer_action(void *, wl_data_offer *, std::uint32_t)
  {
  }
  void *text_marker() noexcept
  {
    return &_offer_has_text;
  }

  static void on_source_target(void *, wl_data_source *, const char *)
  {
  }
  static void on_source_send(void *data, wl_data_source *, const char *, std::int32_t fd)
  {
    auto *self = static_cast<wayland_display_t *>(data);
    const int flags = ::fcntl(fd, F_GETFL);
    ::fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
    std::size_t sent = 0;
    while (sent < self->_clipboard_text.size())
    {
      const auto written = ::write(fd, self->_clipboard_text.data() + sent, self->_clipboard_text.size() - sent);
      if (written < 0 && errno == EINTR)
        continue;
      if (written <= 0)
        break;
      sent += static_cast<std::size_t>(written);
    }
    ::close(fd);
  }
  static void on_source_cancelled(void *data, wl_data_source *source)
  {
    auto *self = static_cast<wayland_display_t *>(data);
    if (self->_source == source)
      self->_source = nullptr;
    wl_data_source_destroy(source);
  }
  static void on_source_dnd_drop(void *, wl_data_source *)
  {
  }
  static void on_source_dnd_finished(void *, wl_data_source *)
  {
  }
  static void on_source_action(void *, wl_data_source *, std::uint32_t)
  {
  }

  static void on_watch_closed(void *context)
  {
    auto *self = static_cast<wayland_display_t *>(context);
    if (--self->_pending_closes == 0)
      self->_core->defer(*self->_done);
  }

  static constexpr wl_registry_listener registry_listener{&on_global, &on_global_remove};
  static constexpr xdg_wm_base_listener wm_base_listener{&on_ping};
  static constexpr wl_output_listener output_listener{&on_output_geometry, &on_output_mode, &on_output_done, &on_output_scale};
  static constexpr wl_seat_listener seat_listener{&on_capabilities, &on_seat_name};
  static constexpr wl_pointer_listener pointer_listener{&on_pointer_enter, &on_pointer_leave, &on_pointer_motion, &on_pointer_button, &on_pointer_axis, &on_pointer_frame, &on_pointer_axis_source, &on_pointer_axis_stop, &on_pointer_axis_discrete, &on_pointer_axis_value120, &on_pointer_axis_direction};
  static constexpr wl_keyboard_listener keyboard_listener{&on_keymap, &on_keyboard_enter, &on_keyboard_leave, &on_key, &on_modifiers, &on_repeat_info};
  static constexpr wl_data_device_listener data_device_listener{&on_data_offer, &on_drag_enter, &on_drag_leave, &on_drag_motion, &on_drop, &on_selection};
  static constexpr wl_data_offer_listener offer_listener{&on_offer_mime, &on_offer_actions, &on_offer_action};
  static constexpr wl_data_source_listener source_listener{&on_source_target, &on_source_send, &on_source_cancelled, &on_source_dnd_drop, &on_source_dnd_finished, &on_source_action};

  std::unique_ptr<fd_watch_t> _watch;
  wl_registry *_registry = nullptr;
  wl_shm *_shm = nullptr;
  wl_seat *_seat = nullptr;
  wl_pointer *_pointer = nullptr;
  wl_keyboard *_keyboard = nullptr;
  wl_data_device_manager *_data_manager = nullptr;
  wl_data_device *_data_device = nullptr;
  wl_data_offer *_offer = nullptr;
  wl_data_source *_source = nullptr;
  wl_cursor_theme *_cursor_theme = nullptr;
  wl_surface *_cursor_surface = nullptr;
  xkb_context *_xkb = nullptr;
  xkb_keymap *_xkb_keymap = nullptr;
  xkb_state *_xkb_state = nullptr;
  wayland_window_t *_pointer_window = nullptr;
  wayland_window_t *_keyboard_window = nullptr;
  point_t _pointer_position;
  modifier_t _modifiers = modifier_t::none;
  timer_node_t _repeat;
  std::string _clipboard_text;
  posted_t *_done = nullptr;
  loop_core_t *_core = nullptr;
  std::size_t _pending_closes = 0;
  std::uint32_t _serial = 0;
  std::uint32_t _pointer_serial = 0;
  std::uint32_t _repeat_code = 0;
  std::int32_t _repeat_rate = 0;
  std::int32_t _repeat_delay = 0;
  bool _offer_has_text = false;
};

clipboard_read_t::clipboard_read_t(wayland_display_t &display, int fd)
  : display(display)
  , watch(std::make_unique<fd_watch_t>(display.impl.core, "wayland clipboard", &clipboard_read_t::on_readable, this))
  , fd(fd)
{
  if (int result = watch->open(fd); result < 0)
    finish(std::unexpected(result));
  else
    on_readable(this);
}

clipboard_read_t::~clipboard_read_t()
{
  ::close(fd);
}

void clipboard_read_t::on_readable(void *context)
{
  auto *self = static_cast<clipboard_read_t *>(context);
  if (self->done)
    return;
  char buffer[4096];
  for (;;)
  {
    const auto count = ::read(self->fd, buffer, sizeof(buffer));
    if (count > 0)
    {
      self->text.append(buffer, static_cast<std::size_t>(count));
      continue;
    }
    if (count == 0)
    {
      self->finish(std::move(self->text));
      return;
    }
    if (errno == EINTR)
      continue;
    if (errno == EAGAIN)
    {
      self->watch->park();
      return;
    }
    self->finish(std::unexpected(errc::io_error));
    return;
  }
}

void clipboard_read_t::finish(std::expected<std::string, int> result)
{
  done = true;
  display.impl.clipboard_arrived(std::move(result));
  watch->close([](void *context) {
    auto *self = static_cast<clipboard_read_t *>(context);
    self->display.read_finished(self);
  }, this);
}

wayland_window_t::wayland_window_t(wayland_display_t &display, window_impl_t &window)
  : window(window)
  , _display(display)
  , _clock(window.display.core, window.display.config.frame_interval_ns, &wayland_window_t::tick, this)
{
}

wayland_window_t::~wayland_window_t()
{
  _display.remove(this);
  if (_frame_callback)
    wl_callback_destroy(_frame_callback);
  destroy_role();
  if (surface)
    wl_surface_destroy(surface);
  wl_display_flush(_display.display);
}

int wayland_window_t::create(const window_config_t &config)
{
  surface = wl_compositor_create_surface(_display.compositor);
  if (!surface)
    return errc::out_of_memory;
  wl_surface_add_listener(surface, &surface_listener, this);
  _title = config.title;
  _size = config.size;
  _min_size = config.min_size;
  _max_size = config.max_size;
  _decorated = config.decorated;
  _resizable = config.resizable;
  _fullscreen = config.fullscreen;
  window.on_resize(_size, _size, 1.0f);
  if (config.visible)
    create_role();
  return 0;
}

void wayland_window_t::create_role()
{
  if (_toplevel)
    return;
  _xdg_surface = xdg_wm_base_get_xdg_surface(_display.wm_base, surface);
  xdg_surface_add_listener(_xdg_surface, &xdg_listener, this);
  _toplevel = xdg_surface_get_toplevel(_xdg_surface);
  xdg_toplevel_add_listener(_toplevel, &toplevel_listener, this);
  xdg_toplevel_set_title(_toplevel, _title.c_str());
  xdg_toplevel_set_app_id(_toplevel, "vio");
  if (!_resizable)
  {
    xdg_toplevel_set_min_size(_toplevel, _size.width, _size.height);
    xdg_toplevel_set_max_size(_toplevel, _size.width, _size.height);
  }
  else
  {
    xdg_toplevel_set_min_size(_toplevel, _min_size.width, _min_size.height);
    xdg_toplevel_set_max_size(_toplevel, _max_size.width, _max_size.height);
  }
  if (_display.decoration_manager)
  {
    _decoration = zxdg_decoration_manager_v1_get_toplevel_decoration(_display.decoration_manager, _toplevel);
    zxdg_toplevel_decoration_v1_set_mode(_decoration, _decorated ? ZXDG_TOPLEVEL_DECORATION_V1_MODE_SERVER_SIDE : ZXDG_TOPLEVEL_DECORATION_V1_MODE_CLIENT_SIDE);
  }
  if (_fullscreen)
    xdg_toplevel_set_fullscreen(_toplevel, nullptr);
  _configured = false;
  _shown = true;
  wl_surface_commit(surface);
}

void wayland_window_t::destroy_role()
{
  if (_decoration)
    zxdg_toplevel_decoration_v1_destroy(_decoration);
  if (_toplevel)
    xdg_toplevel_destroy(_toplevel);
  if (_xdg_surface)
    xdg_surface_destroy(_xdg_surface);
  _decoration = nullptr;
  _toplevel = nullptr;
  _xdg_surface = nullptr;
  _configured = false;
}

int wayland_window_t::scale() const
{
  if (_preferred_scale > 0)
    return _preferred_scale;
  int result = 1;
  for (auto *output : _outputs)
  {
    if (auto *entry = _display.find(output))
      result = std::max(result, entry->scale);
  }
  return result;
}

void wayland_window_t::apply_size()
{
  const int factor = scale();
  window.on_resize(_size, {_size.width * factor, _size.height * factor}, static_cast<float>(factor));
}

void wayland_window_t::output_scale_changed()
{
  std::erase_if(_outputs, [this](wl_output *output) { return _display.find(output) == nullptr; });
  if (_configured)
    apply_size();
}

void wayland_window_t::on_surface_enter(void *data, wl_surface *, wl_output *output)
{
  auto *self = static_cast<wayland_window_t *>(data);
  self->_outputs.push_back(output);
  self->output_scale_changed();
}

void wayland_window_t::on_surface_leave(void *data, wl_surface *, wl_output *output)
{
  auto *self = static_cast<wayland_window_t *>(data);
  std::erase(self->_outputs, output);
  self->output_scale_changed();
}

void wayland_window_t::on_preferred_scale(void *data, wl_surface *, std::int32_t factor)
{
  auto *self = static_cast<wayland_window_t *>(data);
  self->_preferred_scale = std::max(1, factor);
  self->output_scale_changed();
}

void wayland_window_t::on_preferred_transform(void *, wl_surface *, std::uint32_t)
{
}

void wayland_window_t::on_toplevel_configure(void *data, xdg_toplevel *, std::int32_t width, std::int32_t height, wl_array *states)
{
  auto *self = static_cast<wayland_window_t *>(data);
  self->_pending_size = {width, height};
  bool fullscreen = false;
  bool maximized = false;
  auto *begin = static_cast<std::uint32_t *>(states->data);
  auto *end = begin + states->size / sizeof(std::uint32_t);
  for (auto *state = begin; state != end; ++state)
  {
    if (*state == XDG_TOPLEVEL_STATE_FULLSCREEN)
      fullscreen = true;
    else if (*state == XDG_TOPLEVEL_STATE_MAXIMIZED)
      maximized = true;
  }
  self->_fullscreen = fullscreen;
  self->_maximized = maximized;
}

void wayland_window_t::on_xdg_configure(void *data, xdg_surface *surface, std::uint32_t serial)
{
  auto *self = static_cast<wayland_window_t *>(data);
  xdg_surface_ack_configure(surface, serial);
  if (self->_pending_size.width > 0 && self->_pending_size.height > 0)
    self->_size = self->_pending_size;
  self->_configured = true;
  self->apply_size();
  self->window.on_damage();
  self->window.on_visible(true);
}

void wayland_window_t::on_toplevel_close(void *data, xdg_toplevel *)
{
  static_cast<wayland_window_t *>(data)->window.on_close_request();
}

void wayland_window_t::on_toplevel_bounds(void *, xdg_toplevel *, std::int32_t, std::int32_t)
{
}

void wayland_window_t::on_toplevel_capabilities(void *, xdg_toplevel *, wl_array *)
{
}

void wayland_window_t::on_frame_done(void *data, wl_callback *callback, std::uint32_t)
{
  auto *self = static_cast<wayland_window_t *>(data);
  wl_callback_destroy(callback);
  self->_frame_callback = nullptr;
  self->window.on_frame(loop_core_t::now());
}

void wayland_window_t::tick(void *context)
{
  auto *self = static_cast<wayland_window_t *>(context);
  if (!self->_frame_callback)
    self->window.on_frame(loop_core_t::now());
}

void wayland_window_t::frame_wanted()
{
  if (!_frame_callback)
    _clock.request();
}

void wayland_window_t::frame_delivered()
{
  const int factor = scale();
  if (factor != _applied_scale)
  {
    wl_surface_set_buffer_scale(surface, factor);
    _applied_scale = factor;
  }
  if (_frame_callback || !_configured)
    return;
  _frame_callback = wl_surface_frame(surface);
  wl_callback_add_listener(_frame_callback, &frame_listener, this);
}

void wayland_window_t::set_title(std::string_view title)
{
  _title = title;
  if (_toplevel)
    xdg_toplevel_set_title(_toplevel, _title.c_str());
}

int wayland_window_t::set_size(extent_t size)
{
  if (_fullscreen || _maximized)
    return errc::busy;
  _size = size;
  if (!_resizable && _toplevel)
  {
    xdg_toplevel_set_min_size(_toplevel, size.width, size.height);
    xdg_toplevel_set_max_size(_toplevel, size.width, size.height);
  }
  apply_size();
  return 0;
}

int wayland_window_t::set_position(point_t)
{
  return errc::not_supported;
}

std::expected<point_t, int> wayland_window_t::position() const
{
  return std::unexpected(errc::not_supported);
}

void wayland_window_t::set_size_limits(extent_t min_size, extent_t max_size)
{
  _min_size = min_size;
  _max_size = max_size;
  if (_toplevel && _resizable)
  {
    xdg_toplevel_set_min_size(_toplevel, min_size.width, min_size.height);
    xdg_toplevel_set_max_size(_toplevel, max_size.width, max_size.height);
  }
}

void wayland_window_t::set_visible(bool visible)
{
  if (visible == _shown)
    return;
  if (visible)
  {
    create_role();
    return;
  }
  _shown = false;
  if (_frame_callback)
  {
    wl_callback_destroy(_frame_callback);
    _frame_callback = nullptr;
  }
  destroy_role();
  wl_surface_attach(surface, nullptr, 0, 0);
  wl_surface_commit(surface);
  window.on_visible(false);
}

void wayland_window_t::set_fullscreen(bool fullscreen)
{
  if (!_toplevel)
  {
    _fullscreen = fullscreen;
    return;
  }
  if (fullscreen)
    xdg_toplevel_set_fullscreen(_toplevel, nullptr);
  else
    xdg_toplevel_unset_fullscreen(_toplevel);
}

void wayland_window_t::minimize()
{
  if (_toplevel)
    xdg_toplevel_set_minimized(_toplevel);
}

void wayland_window_t::maximize()
{
  if (_toplevel)
    xdg_toplevel_set_maximized(_toplevel);
}

void wayland_window_t::restore()
{
  if (!_shown)
    create_role();
  else if (_toplevel)
    xdg_toplevel_unset_maximized(_toplevel);
}

void wayland_window_t::focus()
{
}

void wayland_window_t::set_cursor(cursor_t shape)
{
  cursor = shape;
  _display.apply_cursor(*this);
}

native_window_t wayland_window_t::native() const
{
  return {platform_t::wayland, _display.display, surface, 0, nullptr};
}
} // namespace

std::expected<std::unique_ptr<display_backend_t>, int> make_wayland_backend(display_impl_t &display)
{
  auto made = std::make_unique<wayland_display_t>(display);
  if (int result = made->open(); result < 0)
    return std::unexpected(result);
  return made;
}
} // namespace vio::gui::detail
