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

#if !defined(NOMINMAX)
#define NOMINMAX
#endif
#if !defined(WIN32_LEAN_AND_MEAN)
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>

#include "vio/gui/detail/core.h"

namespace vio::gui::detail
{
HWND win32_handle(window_impl_t &window);

inline FARPROC win32_user32(const char *name)
{
  static HMODULE user32 = GetModuleHandleW(L"user32.dll");
  return user32 ? GetProcAddress(user32, name) : nullptr;
}

inline void win32_enable_dpi_awareness()
{
  using set_context_t = BOOL(WINAPI *)(HANDLE);
  static bool done = false;
  if (done)
    return;
  done = true;
  if (auto set = reinterpret_cast<set_context_t>(reinterpret_cast<void *>(win32_user32("SetProcessDpiAwarenessContext"))))
    set(reinterpret_cast<HANDLE>(static_cast<LONG_PTR>(-4)));
}

inline UINT win32_window_dpi(HWND window)
{
  using get_t = UINT(WINAPI *)(HWND);
  static auto get = reinterpret_cast<get_t>(reinterpret_cast<void *>(win32_user32("GetDpiForWindow")));
  return get && window ? get(window) : 96;
}

inline UINT win32_system_dpi()
{
  using get_t = UINT(WINAPI *)();
  static auto get = reinterpret_cast<get_t>(reinterpret_cast<void *>(win32_user32("GetDpiForSystem")));
  return get ? get() : 96;
}

inline void win32_adjust_rect(RECT &rect, DWORD style, DWORD ex_style, UINT dpi)
{
  using adjust_t = BOOL(WINAPI *)(LPRECT, DWORD, BOOL, DWORD, UINT);
  static auto adjust = reinterpret_cast<adjust_t>(reinterpret_cast<void *>(win32_user32("AdjustWindowRectExForDpi")));
  if (adjust)
    adjust(&rect, style, FALSE, ex_style, dpi);
  else
    AdjustWindowRectEx(&rect, style, FALSE, ex_style);
}
} // namespace vio::gui::detail
