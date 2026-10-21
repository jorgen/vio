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

#include <array>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "fd_watch.h"
#include "vio/gui/backends.h"
#include "vio/gui/gui.h"

#include <X11/XKBlib.h>
#include <X11/Xatom.h>
#include <X11/Xlib.h>
#include <X11/Xresource.h>
#include <X11/Xutil.h>
#include <X11/cursorfont.h>
#include <X11/keysym.h>

namespace vio::gui::detail
{
namespace
{
int ignore_x_error(Display *, XErrorEvent *)
{
  return 0;
}

key_t translate_keysym(KeySym sym)
{
  if (sym >= XK_a && sym <= XK_z)
    return static_cast<key_t>(static_cast<int>(key_t::a) + static_cast<int>(sym - XK_a));
  if (sym >= XK_A && sym <= XK_Z)
    return static_cast<key_t>(static_cast<int>(key_t::a) + static_cast<int>(sym - XK_A));
  if (sym >= XK_0 && sym <= XK_9)
    return static_cast<key_t>(static_cast<int>(key_t::digit_0) + static_cast<int>(sym - XK_0));
  if (sym >= XK_F1 && sym <= XK_F12)
    return static_cast<key_t>(static_cast<int>(key_t::f1) + static_cast<int>(sym - XK_F1));
  if (sym >= XK_KP_0 && sym <= XK_KP_9)
    return static_cast<key_t>(static_cast<int>(key_t::keypad_0) + static_cast<int>(sym - XK_KP_0));
  switch (sym)
  {
  case XK_space: return key_t::space;
  case XK_apostrophe: return key_t::apostrophe;
  case XK_comma: return key_t::comma;
  case XK_minus: return key_t::minus;
  case XK_period: return key_t::period;
  case XK_slash: return key_t::slash;
  case XK_semicolon: return key_t::semicolon;
  case XK_equal: return key_t::equal;
  case XK_bracketleft: return key_t::left_bracket;
  case XK_backslash: return key_t::backslash;
  case XK_bracketright: return key_t::right_bracket;
  case XK_grave: return key_t::grave_accent;
  case XK_Escape: return key_t::escape;
  case XK_Return: return key_t::enter;
  case XK_Tab: return key_t::tab;
  case XK_BackSpace: return key_t::backspace;
  case XK_Insert: return key_t::insert;
  case XK_Delete: return key_t::delete_key;
  case XK_Right: return key_t::right;
  case XK_Left: return key_t::left;
  case XK_Down: return key_t::down;
  case XK_Up: return key_t::up;
  case XK_Page_Up: return key_t::page_up;
  case XK_Page_Down: return key_t::page_down;
  case XK_Home: return key_t::home;
  case XK_End: return key_t::end;
  case XK_Caps_Lock: return key_t::caps_lock;
  case XK_Scroll_Lock: return key_t::scroll_lock;
  case XK_Num_Lock: return key_t::num_lock;
  case XK_Print: return key_t::print_screen;
  case XK_Pause: return key_t::pause;
  case XK_KP_Decimal: return key_t::keypad_decimal;
  case XK_KP_Divide: return key_t::keypad_divide;
  case XK_KP_Multiply: return key_t::keypad_multiply;
  case XK_KP_Subtract: return key_t::keypad_subtract;
  case XK_KP_Add: return key_t::keypad_add;
  case XK_KP_Enter: return key_t::keypad_enter;
  case XK_KP_Equal: return key_t::keypad_equal;
  case XK_Shift_L: return key_t::left_shift;
  case XK_Control_L: return key_t::left_control;
  case XK_Alt_L: return key_t::left_alt;
  case XK_Super_L: return key_t::left_super;
  case XK_Shift_R: return key_t::right_shift;
  case XK_Control_R: return key_t::right_control;
  case XK_Alt_R: return key_t::right_alt;
  case XK_Super_R: return key_t::right_super;
  case XK_Menu: return key_t::menu;
  default: return key_t::unknown;
  }
}

modifier_t translate_state(unsigned state)
{
  auto modifiers = modifier_t::none;
  if (state & ShiftMask)
    modifiers = modifiers | modifier_t::shift;
  if (state & ControlMask)
    modifiers = modifiers | modifier_t::control;
  if (state & Mod1Mask)
    modifiers = modifiers | modifier_t::alt;
  if (state & Mod4Mask)
    modifiers = modifiers | modifier_t::super;
  if (state & LockMask)
    modifiers = modifiers | modifier_t::caps_lock;
  if (state & Mod2Mask)
    modifiers = modifiers | modifier_t::num_lock;
  return modifiers;
}

void append_utf8(std::string &out, unsigned code)
{
  if (code < 0x80)
  {
    out.push_back(static_cast<char>(code));
  }
  else if (code < 0x800)
  {
    out.push_back(static_cast<char>(0xc0 | (code >> 6)));
    out.push_back(static_cast<char>(0x80 | (code & 0x3f)));
  }
  else
  {
    out.push_back(static_cast<char>(0xe0 | (code >> 12)));
    out.push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3f)));
    out.push_back(static_cast<char>(0x80 | (code & 0x3f)));
  }
}

bool printable(const std::string &text)
{
  if (text.empty())
    return false;
  for (unsigned char c : text)
  {
    if (c < 0x20 || c == 0x7f)
      return false;
  }
  return true;
}

class x11_display_t;

class x11_window_t final : public window_backend_t
{
public:
  x11_window_t(x11_display_t &display, window_impl_t &window);
  ~x11_window_t() override;

  int create(const window_config_t &config);
  void handle(XEvent &event);

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
  [[nodiscard]] native_window_t native() const override;

private:
  static void tick(void *context);
  void send_state(long action, Atom first, Atom second);
  void apply_size_hints();
  void key(XKeyEvent &event, bool pressed);

  x11_display_t &_display;
  window_impl_t &_window;
  Window _handle = 0;
  VisualID _visual = 0;
  XIC _ic = nullptr;
  frame_clock_t _clock;
  extent_t _min_size;
  extent_t _max_size;
  extent_t _size;
  bool _resizable = true;
  bool _fullscreen = false;
  bool _mapped = false;
  std::unordered_set<unsigned> _keys_down;
};

class x11_display_t final : public display_backend_t
{
public:
  explicit x11_display_t(display_impl_t &display)
    : impl(display)
    , _watch(std::make_unique<fd_watch_t>(display.core, "x11 display"))
  {
  }

  ~x11_display_t() override
  {
    for (auto cursor : _cursors)
    {
      if (cursor)
        XFreeCursor(display, cursor);
    }
    if (_helper)
      XDestroyWindow(display, _helper);
    if (im)
      XCloseIM(im);
    if (display)
      XCloseDisplay(display);
  }

  int open()
  {
    XInitThreads();
    XSetErrorHandler(&ignore_x_error);
    display = XOpenDisplay(nullptr);
    if (!display)
      return errc::no_such_device;
    screen = DefaultScreen(display);
    root = RootWindow(display, screen);
    const char *names[] = {"WM_PROTOCOLS", "WM_DELETE_WINDOW", "_NET_WM_NAME", "UTF8_STRING", "_NET_WM_STATE", "_NET_WM_STATE_FULLSCREEN", "_NET_WM_STATE_MAXIMIZED_VERT", "_NET_WM_STATE_MAXIMIZED_HORZ", "CLIPBOARD", "TARGETS", "VIO_SELECTION", "_MOTIF_WM_HINTS", "_NET_ACTIVE_WINDOW", "INCR"};
    std::array<Atom, std::size(names)> atoms{};
    XInternAtoms(display, const_cast<char **>(names), static_cast<int>(atoms.size()), False, atoms.data());
    wm_protocols = atoms[0];
    wm_delete = atoms[1];
    net_wm_name = atoms[2];
    utf8_string = atoms[3];
    net_wm_state = atoms[4];
    net_wm_fullscreen = atoms[5];
    net_wm_max_vert = atoms[6];
    net_wm_max_horz = atoms[7];
    clipboard = atoms[8];
    targets = atoms[9];
    selection_property = atoms[10];
    motif_hints = atoms[11];
    net_active_window = atoms[12];
    incr = atoms[13];

    Bool detectable = False;
    XkbSetDetectableAutoRepeat(display, True, &detectable);
    XSetLocaleModifiers("");
    im = XOpenIM(display, nullptr, nullptr, nullptr);
    scale = read_scale();

    XSetWindowAttributes attributes{};
    attributes.event_mask = PropertyChangeMask;
    _helper = XCreateWindow(display, root, -1, -1, 1, 1, 0, 0, InputOnly, CopyFromParent, CWEventMask, &attributes);

    if (int result = _watch->open(ConnectionNumber(display)); result < 0)
      return result;
    XFlush(display);
    return 0;
  }

  [[nodiscard]] const char *name() const noexcept override
  {
    return "x11";
  }
  [[nodiscard]] platform_t platform() const noexcept override
  {
    return platform_t::x11;
  }

  std::expected<std::unique_ptr<window_backend_t>, int> create_window(window_impl_t &window, const window_config_t &config) override
  {
    auto made = std::make_unique<x11_window_t>(*this, window);
    if (int result = made->create(config); result < 0)
      return std::unexpected(result);
    return made;
  }

  void dispatch() override
  {
    if (!_watch->take_readable() && XEventsQueued(display, QueuedAlready) == 0)
    {
      _watch->park();
      return;
    }
    while (XPending(display) > 0)
      next_event();
    _watch->park();
  }

  bool dispatch_queued() override
  {
    if (XEventsQueued(display, QueuedAfterReading) == 0)
      return false;
    while (XEventsQueued(display, QueuedAlready) > 0)
      next_event();
    return true;
  }

  void flush() override
  {
    XFlush(display);
  }

  void set_clipboard_text(std::string text) override
  {
    _clipboard_text = std::move(text);
    XSetSelectionOwner(display, clipboard, _helper, CurrentTime);
  }

  void request_clipboard_text() override
  {
    const Window owner = XGetSelectionOwner(display, clipboard);
    if (owner == _helper)
    {
      impl.clipboard_arrived(_clipboard_text);
      return;
    }
    if (owner == None)
    {
      impl.clipboard_arrived(std::string());
      return;
    }
    XConvertSelection(display, clipboard, utf8_string, selection_property, _helper, CurrentTime);
  }

  [[nodiscard]] void *native_display() const noexcept override
  {
    return display;
  }

  void close(loop_core_t &core, posted_t &done) override
  {
    _done = &done;
    _core = &core;
    _watch->close(&x11_display_t::on_watch_closed, this);
  }

  Cursor cursor(cursor_t shape)
  {
    auto &slot = _cursors[static_cast<std::size_t>(shape)];
    if (slot)
      return slot;
    if (shape == cursor_t::hidden)
    {
      char empty = 0;
      Pixmap pixmap = XCreateBitmapFromData(display, root, &empty, 1, 1);
      XColor black{};
      slot = XCreatePixmapCursor(display, pixmap, pixmap, &black, &black, 0, 0);
      XFreePixmap(display, pixmap);
      return slot;
    }
    unsigned glyph = XC_left_ptr;
    switch (shape)
    {
    case cursor_t::text: glyph = XC_xterm; break;
    case cursor_t::hand: glyph = XC_hand2; break;
    case cursor_t::crosshair: glyph = XC_crosshair; break;
    case cursor_t::resize_horizontal: glyph = XC_sb_h_double_arrow; break;
    case cursor_t::resize_vertical: glyph = XC_sb_v_double_arrow; break;
    case cursor_t::resize_all: glyph = XC_fleur; break;
    case cursor_t::not_allowed: glyph = XC_X_cursor; break;
    case cursor_t::wait: glyph = XC_watch; break;
    default: break;
    }
    slot = XCreateFontCursor(display, glyph);
    return slot;
  }

  void add(Window handle, x11_window_t *window)
  {
    _windows[handle] = window;
  }
  void remove(Window handle)
  {
    _windows.erase(handle);
  }

  display_impl_t &impl;
  Display *display = nullptr;
  XIM im = nullptr;
  int screen = 0;
  Window root = 0;
  float scale = 1.0f;
  Atom wm_protocols = 0;
  Atom wm_delete = 0;
  Atom net_wm_name = 0;
  Atom utf8_string = 0;
  Atom net_wm_state = 0;
  Atom net_wm_fullscreen = 0;
  Atom net_wm_max_vert = 0;
  Atom net_wm_max_horz = 0;
  Atom clipboard = 0;
  Atom targets = 0;
  Atom selection_property = 0;
  Atom motif_hints = 0;
  Atom net_active_window = 0;
  Atom incr = 0;

private:
  static void on_watch_closed(void *context)
  {
    auto *self = static_cast<x11_display_t *>(context);
    self->_core->defer(*self->_done);
  }

  float read_scale()
  {
    const char *resources = XResourceManagerString(display);
    if (!resources)
      return 1.0f;
    XrmInitialize();
    XrmDatabase database = XrmGetStringDatabase(resources);
    if (!database)
      return 1.0f;
    float result = 1.0f;
    char *type = nullptr;
    XrmValue value{};
    if (XrmGetResource(database, "Xft.dpi", "Xft.Dpi", &type, &value) && type && std::strcmp(type, "String") == 0)
    {
      const float dpi = std::strtof(value.addr, nullptr);
      if (dpi > 0)
        result = dpi / 96.0f;
    }
    XrmDestroyDatabase(database);
    return result;
  }

  void next_event()
  {
    XEvent event;
    XNextEvent(display, &event);
    if (XFilterEvent(&event, None))
      return;
    if (event.xany.window == _helper)
    {
      selection(event);
      return;
    }
    if (event.type == SelectionRequest)
    {
      selection(event);
      return;
    }
    auto found = _windows.find(event.xany.window);
    if (found != _windows.end())
      found->second->handle(event);
  }

  void selection(XEvent &event)
  {
    if (event.type == SelectionClear)
    {
      _clipboard_text.clear();
    }
    else if (event.type == SelectionRequest)
    {
      auto &request = event.xselectionrequest;
      XSelectionEvent reply{};
      reply.type = SelectionNotify;
      reply.requestor = request.requestor;
      reply.selection = request.selection;
      reply.target = request.target;
      reply.time = request.time;
      reply.property = None;
      const Atom property = request.property == None ? request.target : request.property;
      if (request.target == targets)
      {
        Atom offered[] = {targets, utf8_string, XA_STRING};
        XChangeProperty(display, request.requestor, property, XA_ATOM, 32, PropModeReplace, reinterpret_cast<unsigned char *>(offered), 3);
        reply.property = property;
      }
      else if (request.target == utf8_string || request.target == XA_STRING)
      {
        XChangeProperty(display, request.requestor, property, request.target, 8, PropModeReplace, reinterpret_cast<const unsigned char *>(_clipboard_text.data()), static_cast<int>(_clipboard_text.size()));
        reply.property = property;
      }
      XSendEvent(display, request.requestor, False, 0, reinterpret_cast<XEvent *>(&reply));
    }
    else if (event.type == SelectionNotify)
    {
      if (event.xselection.property == None)
      {
        impl.clipboard_arrived(std::string());
        return;
      }
      Atom type = None;
      int format = 0;
      unsigned long count = 0;
      unsigned long remaining = 0;
      unsigned char *data = nullptr;
      XGetWindowProperty(display, _helper, selection_property, 0, 0x1fffffff, True, AnyPropertyType, &type, &format, &count, &remaining, &data);
      if (type == incr)
      {
        if (data)
          XFree(data);
        impl.clipboard_arrived(std::unexpected(errc::not_supported));
        return;
      }
      std::string text;
      if (data && format == 8)
        text.assign(reinterpret_cast<char *>(data), count);
      if (data)
        XFree(data);
      impl.clipboard_arrived(std::move(text));
    }
  }

  std::unique_ptr<fd_watch_t> _watch;
  std::unordered_map<Window, x11_window_t *> _windows;
  std::array<Cursor, static_cast<std::size_t>(cursor_t::hidden) + 1> _cursors{};
  std::string _clipboard_text;
  Window _helper = 0;
  posted_t *_done = nullptr;
  loop_core_t *_core = nullptr;
};

x11_window_t::x11_window_t(x11_display_t &display, window_impl_t &window)
  : _display(display)
  , _window(window)
  , _clock(window.display.core, window.display.config.frame_interval_ns, &x11_window_t::tick, this)
{
}

x11_window_t::~x11_window_t()
{
  if (_ic)
    XDestroyIC(_ic);
  if (_handle)
  {
    _display.remove(_handle);
    XDestroyWindow(_display.display, _handle);
    XFlush(_display.display);
  }
}

int x11_window_t::create(const window_config_t &config)
{
  auto *dpy = _display.display;
  Visual *visual = DefaultVisual(dpy, _display.screen);
  int depth = DefaultDepth(dpy, _display.screen);
  XSetWindowAttributes attributes{};
  unsigned long mask = CWEventMask | CWBorderPixel;
  if (config.transparent)
  {
    XVisualInfo info{};
    if (XMatchVisualInfo(dpy, _display.screen, 32, TrueColor, &info))
    {
      visual = info.visual;
      depth = info.depth;
      attributes.colormap = XCreateColormap(dpy, _display.root, visual, AllocNone);
      attributes.background_pixel = 0;
      mask |= CWColormap | CWBackPixel;
    }
  }
  attributes.event_mask = KeyPressMask | KeyReleaseMask | ButtonPressMask | ButtonReleaseMask | PointerMotionMask | EnterWindowMask | LeaveWindowMask | StructureNotifyMask | ExposureMask | FocusChangeMask | VisibilityChangeMask | PropertyChangeMask;
  _size = config.size;
  _visual = XVisualIDFromVisual(visual);
  _handle = XCreateWindow(dpy, _display.root, 0, 0, static_cast<unsigned>(std::max(1, config.size.width)), static_cast<unsigned>(std::max(1, config.size.height)), 0, depth, InputOutput, visual, mask, &attributes);
  if (!_handle)
    return errc::out_of_memory;
  _display.add(_handle, this);

  Atom protocols[] = {_display.wm_delete};
  XSetWMProtocols(dpy, _handle, protocols, 1);
  XClassHint *hint = XAllocClassHint();
  if (hint)
  {
    hint->res_name = const_cast<char *>("vio");
    hint->res_class = const_cast<char *>("vio");
    XSetClassHint(dpy, _handle, hint);
    XFree(hint);
  }
  set_title(config.title);
  _resizable = config.resizable;
  _min_size = config.min_size;
  _max_size = config.max_size;
  apply_size_hints();

  if (!config.decorated)
  {
    long hints[5] = {2, 0, 0, 0, 0};
    XChangeProperty(dpy, _handle, _display.motif_hints, _display.motif_hints, 32, PropModeReplace, reinterpret_cast<unsigned char *>(hints), 5);
  }
  if (config.fullscreen)
  {
    _fullscreen = true;
    Atom state[] = {_display.net_wm_fullscreen};
    XChangeProperty(dpy, _handle, _display.net_wm_state, XA_ATOM, 32, PropModeReplace, reinterpret_cast<unsigned char *>(state), 1);
  }
  if (_display.im)
  {
    _ic = XCreateIC(_display.im, XNInputStyle, XIMPreeditNothing | XIMStatusNothing, XNClientWindow, _handle, XNFocusWindow, _handle, nullptr);
    if (_ic)
    {
      unsigned long filter = 0;
      if (!XGetICValues(_ic, XNFilterEvents, &filter, nullptr))
        XSelectInput(dpy, _handle, attributes.event_mask | static_cast<long>(filter));
    }
  }
  const extent_t pixels = config.size;
  _window.on_resize(pixels, pixels, _display.scale);
  if (config.visible)
    XMapWindow(dpy, _handle);
  XFlush(dpy);
  return 0;
}

void x11_window_t::apply_size_hints()
{
  XSizeHints *hints = XAllocSizeHints();
  if (!hints)
    return;
  if (!_resizable)
  {
    hints->flags |= PMinSize | PMaxSize;
    hints->min_width = hints->max_width = _size.width;
    hints->min_height = hints->max_height = _size.height;
  }
  else
  {
    if (_min_size.width > 0 && _min_size.height > 0)
    {
      hints->flags |= PMinSize;
      hints->min_width = _min_size.width;
      hints->min_height = _min_size.height;
    }
    if (_max_size.width > 0 && _max_size.height > 0)
    {
      hints->flags |= PMaxSize;
      hints->max_width = _max_size.width;
      hints->max_height = _max_size.height;
    }
  }
  XSetWMNormalHints(_display.display, _handle, hints);
  XFree(hints);
}

void x11_window_t::handle(XEvent &event)
{
  switch (event.type)
  {
  case ConfigureNotify:
  {
    const extent_t size{event.xconfigure.width, event.xconfigure.height};
    _size = size;
    _window.on_resize(size, size, _display.scale);
    break;
  }
  case Expose:
    if (event.xexpose.count == 0)
      _window.on_damage();
    break;
  case MapNotify:
    _mapped = true;
    _window.on_visible(true);
    break;
  case UnmapNotify:
    _mapped = false;
    _window.on_visible(false);
    break;
  case ClientMessage:
    if (event.xclient.message_type == _display.wm_protocols && static_cast<Atom>(event.xclient.data.l[0]) == _display.wm_delete)
      _window.on_close_request();
    break;
  case KeyPress:
    key(event.xkey, true);
    break;
  case KeyRelease:
    key(event.xkey, false);
    break;
  case ButtonPress:
  case ButtonRelease:
  {
    const bool pressed = event.type == ButtonPress;
    const point_t at{static_cast<double>(event.xbutton.x), static_cast<double>(event.xbutton.y)};
    const auto modifiers = translate_state(event.xbutton.state);
    const unsigned number = event.xbutton.button;
    if (number >= 4 && number <= 7)
    {
      if (pressed)
      {
        const double dx = number == 6 ? -1.0 : number == 7 ? 1.0 : 0.0;
        const double dy = number == 4 ? 1.0 : number == 5 ? -1.0 : 0.0;
        _window.on_input(scroll_event_t{dx, dy, at, modifiers});
      }
      break;
    }
    button_t button = button_t::other;
    if (number == 1)
      button = button_t::left;
    else if (number == 2)
      button = button_t::middle;
    else if (number == 3)
      button = button_t::right;
    else if (number == 8)
      button = button_t::back;
    else if (number == 9)
      button = button_t::forward;
    _window.on_input(pointer_button_event_t{button, pressed, at, modifiers});
    break;
  }
  case MotionNotify:
    _window.on_input(pointer_move_event_t{{static_cast<double>(event.xmotion.x), static_cast<double>(event.xmotion.y)}, translate_state(event.xmotion.state)});
    break;
  case EnterNotify:
  case LeaveNotify:
    _window.on_input(pointer_enter_event_t{event.type == EnterNotify, {static_cast<double>(event.xcrossing.x), static_cast<double>(event.xcrossing.y)}});
    break;
  case FocusIn:
  case FocusOut:
    if (event.xfocus.mode == NotifyGrab || event.xfocus.mode == NotifyUngrab)
      break;
    if (_ic)
    {
      if (event.type == FocusIn)
        XSetICFocus(_ic);
      else
        XUnsetICFocus(_ic);
    }
    if (event.type == FocusOut)
      _keys_down.clear();
    _window.on_input(focus_event_t{event.type == FocusIn});
    break;
  default:
    break;
  }
}

void x11_window_t::key(XKeyEvent &event, bool pressed)
{
  const KeySym sym = XLookupKeysym(&event, 0);
  key_event_t out;
  out.key = translate_keysym(sym);
  out.scancode = event.keycode;
  out.modifiers = translate_state(event.state);
  out.pressed = pressed;
  if (pressed)
    out.repeat = !_keys_down.insert(event.keycode).second;
  else
    _keys_down.erase(event.keycode);
  _window.on_input(out);
  if (!pressed)
    return;
  std::string text;
  if (_ic)
  {
    char buffer[64];
    KeySym ignored = 0;
    Status status = 0;
    int count = Xutf8LookupString(_ic, &event, buffer, sizeof(buffer), &ignored, &status);
    if (status == XBufferOverflow)
    {
      std::vector<char> large(static_cast<std::size_t>(count) + 1);
      count = Xutf8LookupString(_ic, &event, large.data(), count, &ignored, &status);
      text.assign(large.data(), static_cast<std::size_t>(std::max(0, count)));
    }
    else if (status == XLookupChars || status == XLookupBoth)
    {
      text.assign(buffer, static_cast<std::size_t>(std::max(0, count)));
    }
  }
  else
  {
    char buffer[16];
    const int count = XLookupString(&event, buffer, sizeof(buffer), nullptr, nullptr);
    for (int i = 0; i < count; ++i)
      append_utf8(text, static_cast<unsigned char>(buffer[i]));
  }
  if (printable(text))
    _window.on_input(text_event_t{std::move(text)});
}

void x11_window_t::set_title(std::string_view title)
{
  const std::string copy(title);
  XStoreName(_display.display, _handle, copy.c_str());
  XChangeProperty(_display.display, _handle, _display.net_wm_name, _display.utf8_string, 8, PropModeReplace, reinterpret_cast<const unsigned char *>(copy.data()), static_cast<int>(copy.size()));
}

int x11_window_t::set_size(extent_t size)
{
  _size = size;
  if (!_resizable)
    apply_size_hints();
  XResizeWindow(_display.display, _handle, static_cast<unsigned>(size.width), static_cast<unsigned>(size.height));
  return 0;
}

int x11_window_t::set_position(point_t position)
{
  XMoveWindow(_display.display, _handle, static_cast<int>(position.x), static_cast<int>(position.y));
  return 0;
}

std::expected<point_t, int> x11_window_t::position() const
{
  int x = 0;
  int y = 0;
  Window child = 0;
  if (!XTranslateCoordinates(_display.display, _handle, _display.root, 0, 0, &x, &y, &child))
    return std::unexpected(errc::io_error);
  return point_t{static_cast<double>(x), static_cast<double>(y)};
}

void x11_window_t::set_size_limits(extent_t min_size, extent_t max_size)
{
  _min_size = min_size;
  _max_size = max_size;
  apply_size_hints();
}

void x11_window_t::set_visible(bool visible)
{
  if (visible)
    XMapWindow(_display.display, _handle);
  else
    XUnmapWindow(_display.display, _handle);
}

void x11_window_t::send_state(long action, Atom first, Atom second)
{
  XEvent event{};
  event.xclient.type = ClientMessage;
  event.xclient.window = _handle;
  event.xclient.message_type = _display.net_wm_state;
  event.xclient.format = 32;
  event.xclient.data.l[0] = action;
  event.xclient.data.l[1] = static_cast<long>(first);
  event.xclient.data.l[2] = static_cast<long>(second);
  event.xclient.data.l[3] = 1;
  XSendEvent(_display.display, _display.root, False, SubstructureNotifyMask | SubstructureRedirectMask, &event);
}

void x11_window_t::set_fullscreen(bool fullscreen)
{
  _fullscreen = fullscreen;
  send_state(fullscreen ? 1 : 0, _display.net_wm_fullscreen, 0);
}

void x11_window_t::minimize()
{
  XIconifyWindow(_display.display, _handle, _display.screen);
}

void x11_window_t::maximize()
{
  send_state(1, _display.net_wm_max_vert, _display.net_wm_max_horz);
}

void x11_window_t::restore()
{
  if (!_mapped)
    XMapWindow(_display.display, _handle);
  send_state(0, _display.net_wm_max_vert, _display.net_wm_max_horz);
}

void x11_window_t::focus()
{
  XEvent event{};
  event.xclient.type = ClientMessage;
  event.xclient.window = _handle;
  event.xclient.message_type = _display.net_active_window;
  event.xclient.format = 32;
  event.xclient.data.l[0] = 1;
  event.xclient.data.l[1] = CurrentTime;
  XSendEvent(_display.display, _display.root, False, SubstructureNotifyMask | SubstructureRedirectMask, &event);
  XRaiseWindow(_display.display, _handle);
}

void x11_window_t::set_cursor(cursor_t cursor)
{
  XDefineCursor(_display.display, _handle, _display.cursor(cursor));
}

void x11_window_t::frame_wanted()
{
  _clock.request();
}

void x11_window_t::tick(void *context)
{
  static_cast<x11_window_t *>(context)->_window.on_frame(loop_core_t::now());
}

native_window_t x11_window_t::native() const
{
  return {platform_t::x11, _display.display, nullptr, static_cast<std::uintptr_t>(_handle), nullptr, static_cast<std::uint32_t>(_visual)};
}
} // namespace

std::expected<std::unique_ptr<display_backend_t>, int> make_x11_backend(display_impl_t &display)
{
  auto made = std::make_unique<x11_display_t>(display);
  if (int result = made->open(); result < 0)
    return std::unexpected(result);
  return made;
}
} // namespace vio::gui::detail
