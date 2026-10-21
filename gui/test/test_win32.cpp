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

#if defined(_WIN32)

#if !defined(NOMINMAX)
#define NOMINMAX
#endif
#if !defined(WIN32_LEAN_AND_MEAN)
#define WIN32_LEAN_AND_MEAN
#endif

#include <doctest/doctest.h>

#include <chrono>
#include <string>
#include <variant>
#include <vector>

#include <vio/event_loop.h>
#include <vio/gui/context.h>
#include <vio/gui/gui.h>
#include <vio/operation/sleep.h>
#include <vio/task.h>

#include "gui_test_helpers.h"

#include <windows.h>

#include <d3d12.h>
#include <dxgi1_6.h>

using namespace std::chrono_literals;
namespace gui = vio::gui;

namespace
{
gui::display_t open_win32(vio::event_loop_t &loop)
{
  auto display = gui::display_t::open(loop);
  REQUIRE(display.has_value());
  CHECK(std::string(display->backend_name()) == "win32");
  return std::move(*display);
}

HWND hwnd_of(gui::window_t &window)
{
  return static_cast<HWND>(window.native().handle);
}
} // namespace

TEST_CASE("win32: a shown window delivers its first frame at the size asked for")
{
  vio::event_loop_t loop;
  run_gui_test(loop, [](vio::event_loop_t &loop) -> vio::task_t<void> {
    auto display = open_win32(loop);
    {
      auto window = gui::window_t::create(display, {.title = "first frame", .size = {320, 200}});
      REQUIRE(window.has_value());
      auto frame = co_await window->frame();
      REQUIRE(frame.has_value());
      CHECK(frame->framebuffer.width > 0);
      CHECK(window->native().platform == gui::platform_t::win32);
    }
    loop.stop();
  }(loop));
}

TEST_CASE("win32: a size change comes back as a resize")
{
  vio::event_loop_t loop;
  run_gui_test(loop, [](vio::event_loop_t &loop) -> vio::task_t<void> {
    auto display = open_win32(loop);
    {
      auto window = gui::window_t::create(display, {.size = {200, 200}});
      co_await window->frame();
      const auto scale = window->scale();
      REQUIRE(window->set_size({410, 270}).has_value());
      auto resized = co_await window->resized();
      REQUIRE(resized.has_value());
      CHECK(resized->size == gui::extent_t{410, 270});
      CHECK(resized->scale == scale);
    }
    loop.stop();
  }(loop));
}

TEST_CASE("win32: WM_CLOSE is a close request and the window stays open")
{
  vio::event_loop_t loop;
  run_gui_test(loop, [](vio::event_loop_t &loop) -> vio::task_t<void> {
    auto display = open_win32(loop);
    {
      auto window = gui::window_t::create(display);
      co_await window->frame();
      PostMessageW(hwnd_of(*window), WM_CLOSE, 0, 0);
      auto request = co_await window->close_requested();
      CHECK(request.has_value());
      CHECK(IsWindow(hwnd_of(*window)));
    }
    loop.stop();
  }(loop));
}

TEST_CASE("win32: key and character messages become key and text events")
{
  vio::event_loop_t loop;
  std::vector<gui::input_event_t> events;
  run_gui_test(loop, [](vio::event_loop_t &loop, std::vector<gui::input_event_t> &events) -> vio::task_t<void> {
    auto display = open_win32(loop);
    {
      auto window = gui::window_t::create(display);
      co_await window->frame();
      const HWND hwnd = hwnd_of(*window);
      PostMessageW(hwnd, WM_KEYDOWN, 'Q', 0x00100001);
      PostMessageW(hwnd, WM_CHAR, 0xd83d, 0);
      PostMessageW(hwnd, WM_CHAR, 0xde00, 0);
      PostMessageW(hwnd, WM_KEYUP, 'Q', static_cast<LPARAM>(0xc0100001u));
      while (events.size() < 3)
      {
        auto event = co_await window->input();
        REQUIRE(event.has_value());
        if (std::holds_alternative<gui::key_event_t>(*event) || std::holds_alternative<gui::text_event_t>(*event))
          events.push_back(*event);
      }
    }
    loop.stop();
  }(loop, events));
  REQUIRE(events.size() == 3);
  CHECK(std::get<gui::key_event_t>(events[0]).key == gui::key_t::q);
  CHECK(std::get<gui::text_event_t>(events[1]).text == "\xf0\x9f\x98\x80");
  CHECK(!std::get<gui::key_event_t>(events[2]).pressed);
}

TEST_CASE("win32: the loop keeps turning inside a modal size loop")
{
  vio::event_loop_t loop;
  int ticks_inside = 0;
  run_gui_test(loop, [](vio::event_loop_t &loop, int &ticks_inside) -> vio::task_t<void> {
    auto display = open_win32(loop);
    {
      auto window = gui::window_t::create(display);
      co_await window->frame();
      int ticks = 0;
      bool stop_ticking = false;
      auto ticker = [](vio::event_loop_t &loop, int &ticks, bool &stop) -> vio::task_t<void> {
        while (!stop)
        {
          co_await vio::sleep(loop, 5ms);
          ++ticks;
        }
      }(loop, ticks, stop_ticking);
      const HWND hwnd = hwnd_of(*window);
      SendMessageW(hwnd, WM_ENTERSIZEMOVE, 0, 0);
      co_await vio::sleep(loop, 30ms);
      const int before = ticks;
      const auto until = std::chrono::steady_clock::now() + 200ms;
      while (std::chrono::steady_clock::now() < until)
      {
        MSG message;
        while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE))
        {
          TranslateMessage(&message);
          DispatchMessageW(&message);
        }
        MsgWaitForMultipleObjectsEx(0, nullptr, 10, QS_ALLINPUT, MWMO_INPUTAVAILABLE);
      }
      ticks_inside = ticks - before;
      SendMessageW(hwnd, WM_EXITSIZEMOVE, 0, 0);
      stop_ticking = true;
      co_await std::move(ticker);
    }
    loop.stop();
  }(loop, ticks_inside));
  CHECK(ticks_inside >= 5);
}

TEST_CASE("win32: clipboard text round-trips through the system clipboard")
{
  vio::event_loop_t loop;
  std::string text;
  run_gui_test(loop, [](vio::event_loop_t &loop, std::string &text) -> vio::task_t<void> {
    auto display = open_win32(loop);
    display.set_clipboard_text("vio \xc3\xa6\xc3\xb8\xc3\xa5");
    auto got = co_await display.clipboard_text();
    REQUIRE(got.has_value());
    text = *got;
    loop.stop();
  }(loop, text));
  CHECK(text == "vio \xc3\xa6\xc3\xb8\xc3\xa5");
}

TEST_CASE("win32: a WARP device presents through a swap chain made for the window")
{
  HMODULE d3d12 = LoadLibraryW(L"d3d12.dll");
  if (!d3d12)
    return;
  using create_device_t = HRESULT(WINAPI *)(IUnknown *, D3D_FEATURE_LEVEL, REFIID, void **);
  auto create_device = reinterpret_cast<create_device_t>(reinterpret_cast<void *>(GetProcAddress(d3d12, "D3D12CreateDevice")));
  HMODULE dxgi = LoadLibraryW(L"dxgi.dll");
  using create_factory_t = HRESULT(WINAPI *)(REFIID, void **);
  auto create_factory = reinterpret_cast<create_factory_t>(reinterpret_cast<void *>(GetProcAddress(dxgi, "CreateDXGIFactory1")));
  REQUIRE(create_device);
  REQUIRE(create_factory);
  IDXGIFactory4 *factory = nullptr;
  REQUIRE(SUCCEEDED(create_factory(__uuidof(IDXGIFactory4), reinterpret_cast<void **>(&factory))));
  IDXGIAdapter *warp = nullptr;
  REQUIRE(SUCCEEDED(factory->EnumWarpAdapter(__uuidof(IDXGIAdapter), reinterpret_cast<void **>(&warp))));
  ID3D12Device *device = nullptr;
  if (FAILED(create_device(warp, D3D_FEATURE_LEVEL_11_0, __uuidof(ID3D12Device), reinterpret_cast<void **>(&device))))
  {
    warp->Release();
    factory->Release();
    return;
  }
  D3D12_COMMAND_QUEUE_DESC queue_description{};
  queue_description.Type = D3D12_COMMAND_LIST_TYPE_DIRECT;
  ID3D12CommandQueue *queue = nullptr;
  REQUIRE(SUCCEEDED(device->CreateCommandQueue(&queue_description, __uuidof(ID3D12CommandQueue), reinterpret_cast<void **>(&queue))));

  vio::event_loop_t loop;
  run_gui_test(loop, [](vio::event_loop_t &loop, ID3D12CommandQueue *queue) -> vio::task_t<void> {
    auto display = open_win32(loop);
    {
      auto window = gui::window_t::create(display, {.size = {128, 96}});
      auto frame = co_await window->frame();
      REQUIRE(frame.has_value());
      auto chain = gui::d3d12::create_swap_chain(*window, queue);
      if (!chain)
        FAIL("swap chain: " << chain.error().msg);
      auto *swap_chain = static_cast<IDXGISwapChain3 *>(*chain);
      for (int i = 0; i < 3; ++i)
      {
        CHECK(SUCCEEDED(swap_chain->Present(1, 0)));
        co_await window->frame();
      }
      REQUIRE(window->set_size({200, 150}).has_value());
      auto resized = co_await window->resized();
      CHECK(gui::d3d12::resize_swap_chain(swap_chain, resized->framebuffer).has_value());
      CHECK(SUCCEEDED(swap_chain->Present(1, 0)));
      swap_chain->Release();
      auto luid = gui::adapter_luid(*window);
      CHECK(luid.has_value());
    }
    loop.stop();
  }(loop, queue));

  queue->Release();
  device->Release();
  warp->Release();
  factory->Release();
}

TEST_CASE("win32: a GL context draws or reports that GL is not available")
{
  vio::event_loop_t loop;
  run_gui_test(loop, [](vio::event_loop_t &loop) -> vio::task_t<void> {
    auto display = open_win32(loop);
    {
      auto window = gui::window_t::create(display, {.size = {64, 48}});
      co_await window->frame();
      auto context = gui::gl_context_t::create(*window, {.major = 2, .minor = 1, .core_profile = false});
      if (!context)
      {
        CHECK(context.error().code == vio::errc::not_supported);
      }
      else
      {
        auto clear_color = context->proc<void (*)(float, float, float, float)>("glClearColor");
        auto clear = context->proc<void (*)(unsigned)>("glClear");
        REQUIRE(clear_color);
        clear_color(0, 1, 0, 1);
        clear(0x4000);
        CHECK(context->swap_buffers().has_value());
        auto properties = context->opencl_properties();
        CHECK(properties.size() == 5);
      }
    }
    loop.stop();
  }(loop));
}

#endif
