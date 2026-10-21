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

#if !defined(NOMINMAX)
#define NOMINMAX
#endif
#if !defined(WIN32_LEAN_AND_MEAN)
#define WIN32_LEAN_AND_MEAN
#endif

#include <algorithm>
#include <array>
#include <atomic>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "vio/gui/backends.h"
#include "vio/gui/gui.h"
#include "win32_common.h"

#include <windows.h>
#include <windowsx.h>

namespace vio::gui::detail
{
namespace
{
constexpr UINT wake_message = WM_APP + 1;
constexpr UINT_PTR modal_timer = 1;
constexpr ULONG_PTR forwarder_exit_key = 0x7669'6f65'7869'74ull;
constexpr wchar_t window_class[] = L"vio_window";
constexpr wchar_t helper_class[] = L"vio_helper";

std::wstring widen(std::string_view text)
{
  if (text.empty())
    return {};
  const int length = MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
  std::wstring out(static_cast<std::size_t>(length), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), length);
  return out;
}

std::string narrow(const wchar_t *text, int length)
{
  if (length == 0)
    return {};
  const int bytes = WideCharToMultiByte(CP_UTF8, 0, text, length, nullptr, 0, nullptr, nullptr);
  std::string out(static_cast<std::size_t>(bytes), '\0');
  WideCharToMultiByte(CP_UTF8, 0, text, length, out.data(), bytes, nullptr, nullptr);
  return out;
}

key_t translate_key(WPARAM vk, LPARAM lparam)
{
  const bool extended = (lparam >> 24) & 1;
  if (vk >= 'A' && vk <= 'Z')
    return static_cast<key_t>(static_cast<int>(key_t::a) + static_cast<int>(vk - 'A'));
  if (vk >= '0' && vk <= '9')
    return static_cast<key_t>(static_cast<int>(key_t::digit_0) + static_cast<int>(vk - '0'));
  if (vk >= VK_F1 && vk <= VK_F12)
    return static_cast<key_t>(static_cast<int>(key_t::f1) + static_cast<int>(vk - VK_F1));
  if (vk >= VK_NUMPAD0 && vk <= VK_NUMPAD9)
    return static_cast<key_t>(static_cast<int>(key_t::keypad_0) + static_cast<int>(vk - VK_NUMPAD0));
  switch (vk)
  {
  case VK_SPACE: return key_t::space;
  case VK_OEM_7: return key_t::apostrophe;
  case VK_OEM_COMMA: return key_t::comma;
  case VK_OEM_MINUS: return key_t::minus;
  case VK_OEM_PERIOD: return key_t::period;
  case VK_OEM_2: return key_t::slash;
  case VK_OEM_1: return key_t::semicolon;
  case VK_OEM_PLUS: return key_t::equal;
  case VK_OEM_4: return key_t::left_bracket;
  case VK_OEM_5: return key_t::backslash;
  case VK_OEM_6: return key_t::right_bracket;
  case VK_OEM_3: return key_t::grave_accent;
  case VK_ESCAPE: return key_t::escape;
  case VK_RETURN: return extended ? key_t::keypad_enter : key_t::enter;
  case VK_TAB: return key_t::tab;
  case VK_BACK: return key_t::backspace;
  case VK_INSERT: return key_t::insert;
  case VK_DELETE: return key_t::delete_key;
  case VK_RIGHT: return key_t::right;
  case VK_LEFT: return key_t::left;
  case VK_DOWN: return key_t::down;
  case VK_UP: return key_t::up;
  case VK_PRIOR: return key_t::page_up;
  case VK_NEXT: return key_t::page_down;
  case VK_HOME: return key_t::home;
  case VK_END: return key_t::end;
  case VK_CAPITAL: return key_t::caps_lock;
  case VK_SCROLL: return key_t::scroll_lock;
  case VK_NUMLOCK: return key_t::num_lock;
  case VK_SNAPSHOT: return key_t::print_screen;
  case VK_PAUSE: return key_t::pause;
  case VK_DECIMAL: return key_t::keypad_decimal;
  case VK_DIVIDE: return key_t::keypad_divide;
  case VK_MULTIPLY: return key_t::keypad_multiply;
  case VK_SUBTRACT: return key_t::keypad_subtract;
  case VK_ADD: return key_t::keypad_add;
  case VK_SHIFT: return ((lparam >> 16) & 0xff) == 0x36 ? key_t::right_shift : key_t::left_shift;
  case VK_CONTROL: return extended ? key_t::right_control : key_t::left_control;
  case VK_MENU: return extended ? key_t::right_alt : key_t::left_alt;
  case VK_LWIN: return key_t::left_super;
  case VK_RWIN: return key_t::right_super;
  case VK_APPS: return key_t::menu;
  default: return key_t::unknown;
  }
}

modifier_t current_modifiers()
{
  auto modifiers = modifier_t::none;
  if (GetKeyState(VK_SHIFT) & 0x8000)
    modifiers = modifiers | modifier_t::shift;
  if (GetKeyState(VK_CONTROL) & 0x8000)
    modifiers = modifiers | modifier_t::control;
  if (GetKeyState(VK_MENU) & 0x8000)
    modifiers = modifiers | modifier_t::alt;
  if ((GetKeyState(VK_LWIN) | GetKeyState(VK_RWIN)) & 0x8000)
    modifiers = modifiers | modifier_t::super;
  if (GetKeyState(VK_CAPITAL) & 1)
    modifiers = modifiers | modifier_t::caps_lock;
  if (GetKeyState(VK_NUMLOCK) & 1)
    modifiers = modifiers | modifier_t::num_lock;
  return modifiers;
}

LPCWSTR cursor_resource(cursor_t cursor)
{
  switch (cursor)
  {
  case cursor_t::text: return MAKEINTRESOURCEW(32513);
  case cursor_t::hand: return MAKEINTRESOURCEW(32649);
  case cursor_t::crosshair: return MAKEINTRESOURCEW(32515);
  case cursor_t::resize_horizontal: return MAKEINTRESOURCEW(32644);
  case cursor_t::resize_vertical: return MAKEINTRESOURCEW(32645);
  case cursor_t::resize_all: return MAKEINTRESOURCEW(32646);
  case cursor_t::not_allowed: return MAKEINTRESOURCEW(32648);
  case cursor_t::wait: return MAKEINTRESOURCEW(32514);
  default: return MAKEINTRESOURCEW(32512);
  }
}

std::int64_t refresh_interval(std::int64_t configured)
{
  if (configured > 0)
    return configured;
  DEVMODEW mode{};
  mode.dmSize = sizeof(mode);
  if (EnumDisplaySettingsW(nullptr, ENUM_CURRENT_SETTINGS, &mode) && mode.dmDisplayFrequency > 1)
    return 1'000'000'000 / static_cast<std::int64_t>(mode.dmDisplayFrequency);
  return 16'666'667;
}

class win32_display_t;

class win32_thread_t final : public vio::detail::host_wait_t
{
public:
  explicit win32_thread_t(loop_core_t &core)
    : core(core)
  {
  }

  ~win32_thread_t() override
  {
    stop_forwarder();
    if (_arm)
      CloseHandle(_arm);
    if (_finished)
      CloseHandle(_finished);
    if (helper)
      DestroyWindow(helper);
  }

  int start()
  {
    _port = reinterpret_cast<HANDLE>(core.backend().native_handle());
    if (!_port || _port == INVALID_HANDLE_VALUE)
      return errc::not_supported;
    helper = CreateWindowExW(0, helper_class, L"", 0, 0, 0, 0, 0, HWND_MESSAGE, nullptr, GetModuleHandleW(nullptr), this);
    if (!helper)
      return errc::out_of_memory;
    _arm = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    _finished = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!_arm || !_finished)
      return errc::out_of_memory;
    _forwarder = std::thread([this] {
      forward();
      SetEvent(_finished);
    });
    core.set_host_wait(this);
    return 0;
  }

  void wait(std::int64_t timeout_ns) override
  {
    if (timeout_ns == 0)
      return;
    DWORD milliseconds = INFINITE;
    if (timeout_ns > 0)
    {
      const std::int64_t rounded = timeout_ns / 1'000'000 + (timeout_ns % 1'000'000 != 0 ? 1 : 0);
      milliseconds = static_cast<DWORD>(std::min<std::int64_t>(rounded, INFINITE - 1));
    }
    SetEvent(_arm);
    MsgWaitForMultipleObjectsEx(0, nullptr, milliseconds, QS_ALLINPUT, MWMO_INPUTAVAILABLE);
  }

  void dispatch()
  {
    MSG message;
    while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE))
    {
      if (message.message == WM_QUIT)
        continue;
      TranslateMessage(&message);
      DispatchMessageW(&message);
    }
  }

  void enter_modal()
  {
    if (modal++ == 0)
      arm_modal_timer();
  }

  void leave_modal()
  {
    if (modal > 0 && --modal == 0)
      KillTimer(helper, modal_timer);
  }

  void nested_turn()
  {
    core.run_nested();
    if (modal > 0)
      arm_modal_timer();
  }

  loop_core_t &core;
  HWND helper = nullptr;
  int modal = 0;
  std::size_t displays = 0;

private:
  void arm_modal_timer()
  {
    const std::int64_t next = core.next_timeout();
    UINT milliseconds = USER_TIMER_MINIMUM;
    if (next > 0)
      milliseconds = static_cast<UINT>(std::clamp<std::int64_t>(next / 1'000'000, USER_TIMER_MINIMUM, 1000));
    SetTimer(helper, modal_timer, milliseconds, nullptr);
  }

  void forward()
  {
    std::array<OVERLAPPED_ENTRY, 64> entries{};
    for (;;)
    {
      WaitForSingleObject(_arm, INFINITE);
      if (_exiting.load(std::memory_order_acquire))
        return;
      ULONG count = 0;
      if (!GetQueuedCompletionStatusEx(_port, entries.data(), static_cast<ULONG>(entries.size()), &count, INFINITE, FALSE))
        continue;
      bool exit = false;
      for (ULONG i = 0; i < count; ++i)
      {
        if (entries[i].lpCompletionKey == forwarder_exit_key)
        {
          exit = true;
          continue;
        }
        PostQueuedCompletionStatus(_port, entries[i].dwNumberOfBytesTransferred, entries[i].lpCompletionKey, entries[i].lpOverlapped);
      }
      PostMessageW(helper, wake_message, 0, 0);
      if (exit || _exiting.load(std::memory_order_acquire))
        return;
    }
  }

  void stop_forwarder()
  {
    if (!_forwarder.joinable())
      return;
    core.set_host_wait(nullptr);
    _exiting.store(true, std::memory_order_release);
    for (;;)
    {
      SetEvent(_arm);
      PostQueuedCompletionStatus(_port, 0, forwarder_exit_key, nullptr);
      if (WaitForSingleObject(_finished, 10) == WAIT_OBJECT_0)
        break;
    }
    _forwarder.join();
  }

  HANDLE _port = nullptr;
  HANDLE _arm = nullptr;
  HANDLE _finished = nullptr;
  std::thread _forwarder;
  std::atomic<bool> _exiting{false};
};

thread_local std::weak_ptr<win32_thread_t> current_thread;

LRESULT CALLBACK helper_procedure(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam)
{
  if (message == WM_NCCREATE)
  {
    auto *create = reinterpret_cast<CREATESTRUCTW *>(lparam);
    SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(create->lpCreateParams));
  }
  auto *thread = reinterpret_cast<win32_thread_t *>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
  if (thread && (message == wake_message || (message == WM_TIMER && wparam == modal_timer)))
  {
    if (thread->modal > 0)
      thread->nested_turn();
    return 0;
  }
  return DefWindowProcW(hwnd, message, wparam, lparam);
}

class win32_window_t final : public window_backend_t
{
public:
  win32_window_t(win32_display_t &display, window_impl_t &window);
  ~win32_window_t() override;

  int create(const window_config_t &config);
  LRESULT procedure(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam);

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

  HWND handle = nullptr;

private:
  static void tick(void *context);
  [[nodiscard]] float scale() const;
  [[nodiscard]] RECT outer_rect(extent_t client) const;
  void report_size();
  void button(button_t which, bool pressed, LPARAM lparam);

  win32_display_t &_display;
  window_impl_t &_window;
  frame_clock_t _clock;
  extent_t _min_size;
  extent_t _max_size;
  DWORD _style = 0;
  DWORD _ex_style = 0;
  RECT _windowed{};
  DWORD _windowed_style = 0;
  cursor_t _cursor = cursor_t::arrow;
  WCHAR _high_surrogate = 0;
  int _buttons = 0;
  bool _tracking = false;
  bool _fullscreen = false;
  bool _resizable = true;
};

class win32_display_t final : public display_backend_t
{
public:
  explicit win32_display_t(display_impl_t &display)
    : impl(display)
  {
  }

  ~win32_display_t() override
  {
    if (thread && --thread->displays == 0)
      current_thread.reset();
  }

  int open()
  {
    win32_enable_dpi_awareness();
    const HINSTANCE instance = GetModuleHandleW(nullptr);
    WNDCLASSEXW helper_info{};
    helper_info.cbSize = sizeof(helper_info);
    helper_info.lpfnWndProc = &helper_procedure;
    helper_info.hInstance = instance;
    helper_info.lpszClassName = helper_class;
    RegisterClassExW(&helper_info);
    WNDCLASSEXW info{};
    info.cbSize = sizeof(info);
    info.style = CS_HREDRAW | CS_VREDRAW | CS_OWNDC;
    info.lpfnWndProc = &win32_display_t::procedure;
    info.hInstance = instance;
    info.hCursor = LoadCursorW(nullptr, MAKEINTRESOURCEW(32512));
    info.lpszClassName = window_class;
    RegisterClassExW(&info);

    thread = current_thread.lock();
    if (!thread)
    {
      thread = std::make_shared<win32_thread_t>(impl.core);
      if (int result = thread->start(); result < 0)
        return result;
      current_thread = thread;
    }
    else if (&thread->core != &impl.core)
    {
      return errc::busy;
    }
    ++thread->displays;
    return 0;
  }

  [[nodiscard]] const char *name() const noexcept override
  {
    return "win32";
  }
  [[nodiscard]] platform_t platform() const noexcept override
  {
    return platform_t::win32;
  }

  std::expected<std::unique_ptr<window_backend_t>, int> create_window(window_impl_t &window, const window_config_t &config) override
  {
    auto made = std::make_unique<win32_window_t>(*this, window);
    if (int result = made->create(config); result < 0)
      return std::unexpected(result);
    return made;
  }

  void dispatch() override
  {
    thread->dispatch();
  }

  void set_clipboard_text(std::string text) override
  {
    if (!OpenClipboard(thread->helper))
      return;
    EmptyClipboard();
    const std::wstring wide = widen(text);
    HGLOBAL memory = GlobalAlloc(GMEM_MOVEABLE, (wide.size() + 1) * sizeof(wchar_t));
    if (memory)
    {
      auto *target = static_cast<wchar_t *>(GlobalLock(memory));
      std::copy(wide.begin(), wide.end(), target);
      target[wide.size()] = 0;
      GlobalUnlock(memory);
      if (!SetClipboardData(CF_UNICODETEXT, memory))
        GlobalFree(memory);
    }
    CloseClipboard();
  }

  void request_clipboard_text() override
  {
    if (!OpenClipboard(thread->helper))
    {
      impl.clipboard_arrived(std::unexpected(errc::busy));
      return;
    }
    std::string text;
    if (HANDLE data = GetClipboardData(CF_UNICODETEXT))
    {
      if (const auto *wide = static_cast<const wchar_t *>(GlobalLock(data)))
      {
        text = narrow(wide, static_cast<int>(wcslen(wide)));
        GlobalUnlock(data);
      }
    }
    CloseClipboard();
    impl.clipboard_arrived(std::move(text));
  }

  [[nodiscard]] void *native_display() const noexcept override
  {
    return GetModuleHandleW(nullptr);
  }

  void close(loop_core_t &core, posted_t &done) override
  {
    core.defer(done);
  }

  static LRESULT CALLBACK procedure(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam)
  {
    if (message == WM_NCCREATE)
    {
      auto *create = reinterpret_cast<CREATESTRUCTW *>(lparam);
      auto *window = static_cast<win32_window_t *>(create->lpCreateParams);
      window->handle = hwnd;
      SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(window));
    }
    auto *window = reinterpret_cast<win32_window_t *>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (!window)
      return DefWindowProcW(hwnd, message, wparam, lparam);
    return window->procedure(hwnd, message, wparam, lparam);
  }

  display_impl_t &impl;
  std::shared_ptr<win32_thread_t> thread;
};

win32_window_t::win32_window_t(win32_display_t &display, window_impl_t &window)
  : _display(display)
  , _window(window)
  , _clock(window.display.core, refresh_interval(window.display.config.frame_interval_ns), &win32_window_t::tick, this)
{
}

win32_window_t::~win32_window_t()
{
  if (!handle)
    return;
  SetWindowLongPtrW(handle, GWLP_USERDATA, 0);
  if (GetCapture() == handle)
    ReleaseCapture();
  DestroyWindow(handle);
}

float win32_window_t::scale() const
{
  return static_cast<float>(win32_window_dpi(handle)) / 96.0f;
}

RECT win32_window_t::outer_rect(extent_t client) const
{
  RECT rect{0, 0, client.width, client.height};
  win32_adjust_rect(rect, _style, _ex_style, win32_window_dpi(handle));
  return rect;
}

int win32_window_t::create(const window_config_t &config)
{
  _resizable = config.resizable;
  _min_size = config.min_size;
  _max_size = config.max_size;
  _style = WS_CLIPSIBLINGS | WS_CLIPCHILDREN;
  if (config.decorated)
  {
    _style |= WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;
    if (config.resizable)
      _style |= WS_MAXIMIZEBOX | WS_THICKFRAME;
  }
  else
  {
    _style |= WS_POPUP;
  }
  _ex_style = WS_EX_APPWINDOW;
  if (config.transparent)
    _ex_style |= WS_EX_NOREDIRECTIONBITMAP;
  RECT rect{0, 0, config.size.width, config.size.height};
  win32_adjust_rect(rect, _style, _ex_style, win32_system_dpi());
  const std::wstring title = widen(config.title);
  CreateWindowExW(_ex_style, window_class, title.c_str(), _style, CW_USEDEFAULT, CW_USEDEFAULT, rect.right - rect.left, rect.bottom - rect.top, nullptr, nullptr, GetModuleHandleW(nullptr), this);
  if (!handle)
    return errc::out_of_memory;
  const float factor = scale();
  if (factor != 1.0f)
  {
    const RECT scaled = outer_rect(config.size);
    SetWindowPos(handle, nullptr, 0, 0, scaled.right - scaled.left, scaled.bottom - scaled.top, SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
  }
  report_size();
  if (config.fullscreen)
    set_fullscreen(true);
  if (config.visible)
  {
    ShowWindow(handle, SW_SHOWNORMAL);
    _window.on_visible(true);
  }
  return 0;
}

void win32_window_t::report_size()
{
  RECT client{};
  GetClientRect(handle, &client);
  const extent_t size{client.right - client.left, client.bottom - client.top};
  _window.on_resize(size, size, scale());
}

void win32_window_t::button(button_t which, bool pressed, LPARAM lparam)
{
  if (pressed)
  {
    if (_buttons++ == 0)
      SetCapture(handle);
  }
  else if (_buttons > 0 && --_buttons == 0)
  {
    ReleaseCapture();
  }
  _window.on_input(pointer_button_event_t{which, pressed, {static_cast<double>(GET_X_LPARAM(lparam)), static_cast<double>(GET_Y_LPARAM(lparam))}, current_modifiers()});
}

LRESULT win32_window_t::procedure(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam)
{
  auto &thread = *_display.thread;
  switch (message)
  {
  case WM_CLOSE:
    _window.on_close_request();
    return 0;
  case WM_SIZE:
    if (wparam == SIZE_MINIMIZED)
    {
      _window.on_visible(false);
    }
    else
    {
      if (IsWindowVisible(hwnd))
        _window.on_visible(true);
      report_size();
    }
    if (thread.modal > 0)
      thread.nested_turn();
    return 0;
  case WM_SHOWWINDOW:
    _window.on_visible(wparam != 0);
    break;
  case WM_PAINT:
  {
    PAINTSTRUCT paint;
    BeginPaint(hwnd, &paint);
    EndPaint(hwnd, &paint);
    _window.on_damage();
    if (thread.modal > 0)
      thread.nested_turn();
    return 0;
  }
  case WM_ERASEBKGND:
    return 1;
  case WM_ENTERSIZEMOVE:
  case WM_ENTERMENULOOP:
    thread.enter_modal();
    break;
  case WM_EXITSIZEMOVE:
  case WM_EXITMENULOOP:
    thread.leave_modal();
    break;
  case WM_DPICHANGED:
  {
    const auto *suggested = reinterpret_cast<const RECT *>(lparam);
    SetWindowPos(hwnd, nullptr, suggested->left, suggested->top, suggested->right - suggested->left, suggested->bottom - suggested->top, SWP_NOZORDER | SWP_NOACTIVATE);
    report_size();
    return 0;
  }
  case WM_GETMINMAXINFO:
  {
    if (!handle)
      break;
    auto *info = reinterpret_cast<MINMAXINFO *>(lparam);
    if (_min_size.width > 0 && _min_size.height > 0)
    {
      const RECT rect = outer_rect(_min_size);
      info->ptMinTrackSize = {rect.right - rect.left, rect.bottom - rect.top};
    }
    if (_max_size.width > 0 && _max_size.height > 0)
    {
      const RECT rect = outer_rect(_max_size);
      info->ptMaxTrackSize = {rect.right - rect.left, rect.bottom - rect.top};
    }
    return 0;
  }
  case WM_SETFOCUS:
    _window.on_input(focus_event_t{true});
    return 0;
  case WM_KILLFOCUS:
    _window.on_input(focus_event_t{false});
    return 0;
  case WM_KEYDOWN:
  case WM_SYSKEYDOWN:
  case WM_KEYUP:
  case WM_SYSKEYUP:
  {
    const bool pressed = message == WM_KEYDOWN || message == WM_SYSKEYDOWN;
    key_event_t event;
    event.key = translate_key(wparam, lparam);
    event.scancode = static_cast<std::uint32_t>((lparam >> 16) & 0x1ff);
    event.modifiers = current_modifiers();
    event.pressed = pressed;
    event.repeat = pressed && ((lparam >> 30) & 1);
    _window.on_input(event);
    if (message == WM_SYSKEYDOWN && wparam == VK_F4)
      break;
    return 0;
  }
  case WM_CHAR:
  case WM_SYSCHAR:
  {
    const auto unit = static_cast<WCHAR>(wparam);
    if (unit >= 0xd800 && unit <= 0xdbff)
    {
      _high_surrogate = unit;
      return 0;
    }
    std::string text;
    if (unit >= 0xdc00 && unit <= 0xdfff && _high_surrogate)
    {
      const WCHAR pair[2] = {_high_surrogate, unit};
      text = narrow(pair, 2);
    }
    else if (unit >= 0x20 && unit != 0x7f)
    {
      text = narrow(&unit, 1);
    }
    _high_surrogate = 0;
    if (!text.empty())
      _window.on_input(text_event_t{std::move(text)});
    return message == WM_SYSCHAR ? DefWindowProcW(hwnd, message, wparam, lparam) : 0;
  }
  case WM_MOUSEMOVE:
  {
    const point_t at{static_cast<double>(GET_X_LPARAM(lparam)), static_cast<double>(GET_Y_LPARAM(lparam))};
    if (!_tracking)
    {
      TRACKMOUSEEVENT track{sizeof(track), TME_LEAVE, hwnd, 0};
      TrackMouseEvent(&track);
      _tracking = true;
      _window.on_input(pointer_enter_event_t{true, at});
    }
    _window.on_input(pointer_move_event_t{at, current_modifiers()});
    return 0;
  }
  case WM_MOUSELEAVE:
    _tracking = false;
    _window.on_input(pointer_enter_event_t{false, {}});
    return 0;
  case WM_LBUTTONDOWN:
  case WM_LBUTTONUP:
    button(button_t::left, message == WM_LBUTTONDOWN, lparam);
    return 0;
  case WM_RBUTTONDOWN:
  case WM_RBUTTONUP:
    button(button_t::right, message == WM_RBUTTONDOWN, lparam);
    return 0;
  case WM_MBUTTONDOWN:
  case WM_MBUTTONUP:
    button(button_t::middle, message == WM_MBUTTONDOWN, lparam);
    return 0;
  case WM_XBUTTONDOWN:
  case WM_XBUTTONUP:
    button(GET_XBUTTON_WPARAM(wparam) == XBUTTON1 ? button_t::back : button_t::forward, message == WM_XBUTTONDOWN, lparam);
    return TRUE;
  case WM_MOUSEWHEEL:
  case WM_MOUSEHWHEEL:
  {
    POINT at{GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam)};
    ScreenToClient(hwnd, &at);
    const double amount = static_cast<double>(GET_WHEEL_DELTA_WPARAM(wparam)) / WHEEL_DELTA;
    scroll_event_t event{0, 0, {static_cast<double>(at.x), static_cast<double>(at.y)}, current_modifiers()};
    if (message == WM_MOUSEWHEEL)
      event.dy = amount;
    else
      event.dx = amount;
    _window.on_input(event);
    return 0;
  }
  case WM_SETCURSOR:
    if (LOWORD(lparam) == HTCLIENT)
    {
      SetCursor(_cursor == cursor_t::hidden ? nullptr : LoadCursorW(nullptr, cursor_resource(_cursor)));
      return TRUE;
    }
    break;
  default:
    break;
  }
  return DefWindowProcW(hwnd, message, wparam, lparam);
}

void win32_window_t::set_title(std::string_view title)
{
  SetWindowTextW(handle, widen(title).c_str());
}

int win32_window_t::set_size(extent_t size)
{
  if (_fullscreen)
    return errc::busy;
  const RECT rect = outer_rect(size);
  SetWindowPos(handle, nullptr, 0, 0, rect.right - rect.left, rect.bottom - rect.top, SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
  return 0;
}

int win32_window_t::set_position(point_t position)
{
  SetWindowPos(handle, nullptr, static_cast<int>(position.x), static_cast<int>(position.y), 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
  return 0;
}

std::expected<point_t, int> win32_window_t::position() const
{
  RECT rect{};
  if (!GetWindowRect(handle, &rect))
    return std::unexpected(errc::io_error);
  return point_t{static_cast<double>(rect.left), static_cast<double>(rect.top)};
}

void win32_window_t::set_size_limits(extent_t min_size, extent_t max_size)
{
  _min_size = min_size;
  _max_size = max_size;
}

void win32_window_t::set_visible(bool visible)
{
  ShowWindow(handle, visible ? SW_SHOWNA : SW_HIDE);
  _window.on_visible(visible && !IsIconic(handle));
}

void win32_window_t::set_fullscreen(bool fullscreen)
{
  if (fullscreen == _fullscreen)
    return;
  _fullscreen = fullscreen;
  if (fullscreen)
  {
    GetWindowRect(handle, &_windowed);
    _windowed_style = static_cast<DWORD>(GetWindowLongPtrW(handle, GWL_STYLE));
    MONITORINFO monitor{};
    monitor.cbSize = sizeof(monitor);
    GetMonitorInfoW(MonitorFromWindow(handle, MONITOR_DEFAULTTONEAREST), &monitor);
    SetWindowLongPtrW(handle, GWL_STYLE, static_cast<LONG_PTR>((_windowed_style & ~WS_OVERLAPPEDWINDOW) | WS_POPUP));
    const RECT &area = monitor.rcMonitor;
    SetWindowPos(handle, HWND_TOP, area.left, area.top, area.right - area.left, area.bottom - area.top, SWP_FRAMECHANGED | SWP_NOOWNERZORDER);
  }
  else
  {
    SetWindowLongPtrW(handle, GWL_STYLE, static_cast<LONG_PTR>(_windowed_style));
    SetWindowPos(handle, nullptr, _windowed.left, _windowed.top, _windowed.right - _windowed.left, _windowed.bottom - _windowed.top, SWP_FRAMECHANGED | SWP_NOZORDER | SWP_NOOWNERZORDER);
  }
}

void win32_window_t::minimize()
{
  ShowWindow(handle, SW_MINIMIZE);
}

void win32_window_t::maximize()
{
  ShowWindow(handle, SW_MAXIMIZE);
}

void win32_window_t::restore()
{
  ShowWindow(handle, SW_RESTORE);
}

void win32_window_t::focus()
{
  BringWindowToTop(handle);
  SetForegroundWindow(handle);
  SetFocus(handle);
}

void win32_window_t::set_cursor(cursor_t cursor)
{
  _cursor = cursor;
  POINT at{};
  GetCursorPos(&at);
  if (WindowFromPoint(at) == handle)
    SetCursor(cursor == cursor_t::hidden ? nullptr : LoadCursorW(nullptr, cursor_resource(cursor)));
}

void win32_window_t::frame_wanted()
{
  _clock.request();
}

void win32_window_t::tick(void *context)
{
  static_cast<win32_window_t *>(context)->_window.on_frame(loop_core_t::now());
}

native_window_t win32_window_t::native() const
{
  return {platform_t::win32, GetModuleHandleW(nullptr), handle, reinterpret_cast<std::uintptr_t>(handle), nullptr, 0};
}
} // namespace

HWND win32_handle(window_impl_t &window)
{
  return static_cast<HWND>(window.backend->native().handle);
}

std::expected<std::unique_ptr<display_backend_t>, int> make_win32_backend(display_impl_t &display)
{
  auto made = std::make_unique<win32_display_t>(display);
  if (int result = made->open(); result < 0)
    return std::unexpected(result);
  return made;
}
} // namespace vio::gui::detail
