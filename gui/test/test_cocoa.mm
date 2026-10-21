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

#include <doctest/doctest.h>

#include <array>
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

#import <Cocoa/Cocoa.h>
#import <QuartzCore/CAMetalLayer.h>

using namespace std::chrono_literals;
namespace gui = vio::gui;

namespace
{
gui::display_t open_cocoa(vio::event_loop_t &loop)
{
  auto display = gui::display_t::open(loop);
  if (!display)
    FAIL("display: " << display.error().msg);
  CHECK(std::string(display->backend_name()) == "cocoa");
  return std::move(*display);
}

NSWindow *ns_window_of(gui::window_t &window)
{
  return (__bridge NSWindow *)window.native().handle;
}

NSView *ns_view_of(gui::window_t &window)
{
  return (__bridge NSView *)window.native().view;
}
} // namespace

TEST_CASE("cocoa: a shown window delivers its first frame at the size asked for")
{
  vio::event_loop_t loop;
  run_gui_test(loop, [](vio::event_loop_t &loop) -> vio::task_t<void> {
    auto display = open_cocoa(loop);
    {
      auto window = gui::window_t::create(display, {.title = "first frame", .size = {320, 200}});
      REQUIRE(window.has_value());
      auto frame = co_await window->frame();
      REQUIRE(frame.has_value());
      CHECK(frame->size == gui::extent_t{320, 200});
      CHECK(frame->framebuffer.width == static_cast<int>(320 * frame->scale));
    }
    loop.stop();
  }(loop));
}

TEST_CASE("cocoa: a size change comes back as a resize")
{
  vio::event_loop_t loop;
  run_gui_test(loop, [](vio::event_loop_t &loop) -> vio::task_t<void> {
    auto display = open_cocoa(loop);
    {
      auto window = gui::window_t::create(display, {.size = {200, 200}});
      co_await window->frame();
      REQUIRE(window->set_size({410, 270}).has_value());
      for (;;)
      {
        auto resized = co_await window->resized();
        REQUIRE(resized.has_value());
        if (resized->size == gui::extent_t{410, 270})
          break;
      }
    }
    loop.stop();
  }(loop));
}

TEST_CASE("cocoa: the close button is a close request and the window stays open")
{
  vio::event_loop_t loop;
  run_gui_test(loop, [](vio::event_loop_t &loop) -> vio::task_t<void> {
    auto display = open_cocoa(loop);
    {
      auto window = gui::window_t::create(display);
      co_await window->frame();
      [ns_window_of(*window) performClose:nil];
      auto request = co_await window->close_requested();
      CHECK(request.has_value());
      CHECK([ns_window_of(*window) isVisible]);
    }
    loop.stop();
  }(loop));
}

TEST_CASE("cocoa: a key down becomes a key event and its text")
{
  vio::event_loop_t loop;
  std::vector<gui::input_event_t> events;
  run_gui_test(loop, [](vio::event_loop_t &loop, std::vector<gui::input_event_t> &events) -> vio::task_t<void> {
    auto display = open_cocoa(loop);
    {
      auto window = gui::window_t::create(display);
      co_await window->frame();
      NSEvent *down = [NSEvent keyEventWithType:NSEventTypeKeyDown location:NSZeroPoint modifierFlags:0 timestamp:0 windowNumber:[ns_window_of(*window) windowNumber] context:nil characters:@"q" charactersIgnoringModifiers:@"q" isARepeat:NO keyCode:0x0C];
      [ns_view_of(*window) keyDown:down];
      while (events.size() < 2)
      {
        auto event = co_await window->input();
        REQUIRE(event.has_value());
        if (std::holds_alternative<gui::key_event_t>(*event) || std::holds_alternative<gui::text_event_t>(*event))
          events.push_back(*event);
      }
    }
    loop.stop();
  }(loop, events));
  REQUIRE(events.size() == 2);
  CHECK(std::get<gui::key_event_t>(events[0]).key == gui::key_t::q);
  CHECK(std::get<gui::text_event_t>(events[1]).text == "q");
}

TEST_CASE("cocoa: the loop keeps turning while the run loop tracks")
{
  vio::event_loop_t loop;
  int ticks_inside = 0;
  run_gui_test(loop, [](vio::event_loop_t &loop, int &ticks_inside) -> vio::task_t<void> {
    auto display = open_cocoa(loop);
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
      const int before = ticks;
      NSDate *until = [NSDate dateWithTimeIntervalSinceNow:0.2];
      while ([until timeIntervalSinceNow] > 0)
        [[NSRunLoop currentRunLoop] runMode:NSEventTrackingRunLoopMode beforeDate:until];
      ticks_inside = ticks - before;
      stop_ticking = true;
      co_await std::move(ticker);
    }
    loop.stop();
  }(loop, ticks_inside));
  CHECK(ticks_inside >= 10);
}

TEST_CASE("cocoa: clipboard text round-trips through the pasteboard")
{
  vio::event_loop_t loop;
  std::string text;
  run_gui_test(loop, [](vio::event_loop_t &loop, std::string &text) -> vio::task_t<void> {
    auto display = open_cocoa(loop);
    display.set_clipboard_text("vio \xc3\xa6\xc3\xb8\xc3\xa5");
    auto got = co_await display.clipboard_text();
    REQUIRE(got.has_value());
    text = *got;
    loop.stop();
  }(loop, text));
  CHECK(text == "vio \xc3\xa6\xc3\xb8\xc3\xa5");
}

TEST_CASE("cocoa: a Metal layer backs the view and follows its size")
{
  vio::event_loop_t loop;
  run_gui_test(loop, [](vio::event_loop_t &loop) -> vio::task_t<void> {
    auto display = open_cocoa(loop);
    {
      auto window = gui::window_t::create(display, {.size = {300, 200}});
      auto layer = gui::metal::create_layer(*window);
      REQUIRE(layer.has_value());
      auto *metal = (__bridge CAMetalLayer *)*layer;
      const bool backed = [ns_view_of(*window) layer] == metal;
      CHECK(backed);
      auto frame = co_await window->frame();
      CHECK(metal.drawableSize.width == frame->framebuffer.width);
      REQUIRE(window->set_size({400, 250}).has_value());
      for (;;)
      {
        auto resized = co_await window->resized();
        if (resized->size == gui::extent_t{400, 250})
        {
          CHECK(metal.drawableSize.width == resized->framebuffer.width);
          break;
        }
      }
    }
    loop.stop();
  }(loop));
}

TEST_CASE("cocoa: a GL context draws into the window")
{
  vio::event_loop_t loop;
  std::array<std::uint8_t, 4> pixel{};
  run_gui_test(loop, [](vio::event_loop_t &loop, std::array<std::uint8_t, 4> &pixel) -> vio::task_t<void> {
    auto display = open_cocoa(loop);
    {
      auto window = gui::window_t::create(display, {.size = {64, 48}});
      auto context = gui::gl_context_t::create(*window, {.major = 3, .minor = 2});
      if (!context)
        FAIL("gl: " << context.error().msg);
      auto clear_color = context->proc<void (*)(float, float, float, float)>("glClearColor");
      auto clear = context->proc<void (*)(unsigned)>("glClear");
      auto read_pixels = context->proc<void (*)(int, int, int, int, unsigned, unsigned, void *)>("glReadPixels");
      auto finish = context->proc<void (*)()>("glFinish");
      REQUIRE(clear_color);
      auto frame = co_await window->frame();
      REQUIRE(context->make_current().has_value());
      clear_color(0, 1, 0, 1);
      clear(0x4000);
      finish();
      read_pixels(frame->framebuffer.width / 2, frame->framebuffer.height / 2, 1, 1, 0x1908, 0x1401, pixel.data());
      CHECK(context->swap_buffers().has_value());
      auto properties = context->opencl_properties();
      CHECK(properties.size() == 3);
      CHECK(properties[0] == 0x10000000);
    }
    loop.stop();
  }(loop, pixel));
  CHECK(pixel == std::array<std::uint8_t, 4>{0, 255, 0, 255});
}
