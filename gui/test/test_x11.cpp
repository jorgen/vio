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

#if defined(VIO_GUI_HAVE_X11)

#include <doctest/doctest.h>

#include <chrono>
#include <string>
#include <variant>
#include <vector>

#include <vio/event_loop.h>
#include <vio/gui/gui.h>
#include <vio/operation/sleep.h>
#include <vio/task.h>

#include "gui_test_helpers.h"

#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/keysym.h>

using namespace std::chrono_literals;
namespace gui = vio::gui;

namespace
{
bool x11_available()
{
  Display *probe = XOpenDisplay(nullptr);
  if (!probe)
    return false;
  XCloseDisplay(probe);
  return true;
}

gui::display_t open_x11(vio::event_loop_t &loop)
{
  auto display = gui::display_t::open(loop, {.backend = "x11"});
  REQUIRE(display.has_value());
  CHECK(std::string(display->backend_name()) == "x11");
  return std::move(*display);
}

struct other_client_t
{
  Display *display = XOpenDisplay(nullptr);
  ~other_client_t()
  {
    XCloseDisplay(display);
  }

  void send_close(Window window)
  {
    XEvent event{};
    event.xclient.type = ClientMessage;
    event.xclient.window = window;
    event.xclient.message_type = XInternAtom(display, "WM_PROTOCOLS", False);
    event.xclient.format = 32;
    event.xclient.data.l[0] = static_cast<long>(XInternAtom(display, "WM_DELETE_WINDOW", False));
    event.xclient.data.l[1] = CurrentTime;
    XSendEvent(display, window, False, NoEventMask, &event);
    XFlush(display);
  }

  void send_key(Window window, KeySym sym, bool pressed)
  {
    XEvent event{};
    event.xkey.type = pressed ? KeyPress : KeyRelease;
    event.xkey.display = display;
    event.xkey.window = window;
    event.xkey.root = DefaultRootWindow(display);
    event.xkey.keycode = XKeysymToKeycode(display, sym);
    event.xkey.same_screen = True;
    XSendEvent(display, window, True, pressed ? KeyPressMask : KeyReleaseMask, &event);
    XFlush(display);
  }
};
} // namespace

TEST_CASE("x11: a mapped window delivers its first frame at the size asked for")
{
  if (!x11_available())
    return;
  vio::event_loop_t loop;
  run_gui_test(loop, [](vio::event_loop_t &loop) -> vio::task_t<void> {
    auto display = open_x11(loop);
    {
      auto window = gui::window_t::create(display, {.title = "first frame", .size = {320, 200}});
      REQUIRE(window.has_value());
      auto frame = co_await window->frame();
      REQUIRE(frame.has_value());
      CHECK(frame->framebuffer == gui::extent_t{320, 200});
      CHECK(window->visible());
      auto native = window->native();
      CHECK(native.platform == gui::platform_t::x11);
      CHECK(native.id != 0);
    }
    loop.stop();
  }(loop));
}

TEST_CASE("x11: a size change comes back as a resize")
{
  if (!x11_available())
    return;
  vio::event_loop_t loop;
  run_gui_test(loop, [](vio::event_loop_t &loop) -> vio::task_t<void> {
    auto display = open_x11(loop);
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
      CHECK(window->framebuffer_size() == gui::extent_t{410, 270});
      auto frame = co_await window->frame();
      CHECK(frame->damaged);
    }
    loop.stop();
  }(loop));
}

TEST_CASE("x11: WM_DELETE_WINDOW from another client is a close request")
{
  if (!x11_available())
    return;
  vio::event_loop_t loop;
  run_gui_test(loop, [](vio::event_loop_t &loop) -> vio::task_t<void> {
    auto display = open_x11(loop);
    {
      auto window = gui::window_t::create(display);
      co_await window->frame();
      other_client_t other;
      other.send_close(static_cast<Window>(window->native().id));
      auto request = co_await window->close_requested();
      CHECK(request.has_value());
    }
    loop.stop();
  }(loop));
}

TEST_CASE("x11: a key press yields a key event and its text")
{
  if (!x11_available())
    return;
  vio::event_loop_t loop;
  std::vector<gui::input_event_t> events;
  run_gui_test(loop, [](vio::event_loop_t &loop, std::vector<gui::input_event_t> &events) -> vio::task_t<void> {
    auto display = open_x11(loop);
    {
      auto window = gui::window_t::create(display);
      co_await window->frame();
      other_client_t other;
      const auto handle = static_cast<Window>(window->native().id);
      other.send_key(handle, XK_q, true);
      other.send_key(handle, XK_q, false);
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
  CHECK(std::get<gui::key_event_t>(events[0]).pressed);
  CHECK(std::get<gui::text_event_t>(events[1]).text == "q");
  CHECK(!std::get<gui::key_event_t>(events[2]).pressed);
}

TEST_CASE("x11: clipboard text moves between two displays")
{
  if (!x11_available())
    return;
  vio::event_loop_t loop;
  std::string received;
  run_gui_test(loop, [](vio::event_loop_t &loop, std::string &received) -> vio::task_t<void> {
    auto owner = open_x11(loop);
    auto reader = open_x11(loop);
    owner.set_clipboard_text("from vio \xc3\xa6\xc3\xb8\xc3\xa5");
    co_await vio::sleep(loop, 20ms);
    auto text = co_await reader.clipboard_text();
    REQUIRE(text.has_value());
    received = *text;
    loop.stop();
  }(loop, received));
  CHECK(received == "from vio \xc3\xa6\xc3\xb8\xc3\xa5");
}

TEST_CASE("x11: frames follow the clock while shown and stop while hidden")
{
  if (!x11_available())
    return;
  vio::event_loop_t loop;
  run_gui_test(loop, [](vio::event_loop_t &loop) -> vio::task_t<void> {
    auto display = gui::display_t::open(loop, {.backend = "x11", .frame_interval_ns = std::chrono::nanoseconds(10ms).count()});
    REQUIRE(display.has_value());
    {
      auto window = gui::window_t::create(*display);
      for (int i = 0; i < 5; ++i)
        REQUIRE((co_await window->frame()).has_value());
      window->hide();
      while (window->visible())
        co_await vio::sleep(loop, 5ms);
      bool hidden_frame = false;
      auto watcher = [](gui::window_t &window, bool &hidden_frame) -> vio::task_t<void> {
        auto frame = co_await window.frame();
        hidden_frame = frame.has_value() && !window.visible();
      }(*window, hidden_frame);
      co_await vio::sleep(loop, 80ms);
      CHECK(!watcher.done());
      window->show();
      co_await std::move(watcher);
      CHECK(!hidden_frame);
    }
    loop.stop();
  }(loop));
}

TEST_CASE("x11: timers keep running beside an open window")
{
  if (!x11_available())
    return;
  vio::event_loop_t loop;
  int ticks = 0;
  run_gui_test(loop, [](vio::event_loop_t &loop, int &ticks) -> vio::task_t<void> {
    auto display = open_x11(loop);
    {
      auto window = gui::window_t::create(display);
      co_await window->frame();
      for (int i = 0; i < 10; ++i)
      {
        co_await vio::sleep(loop, 5ms);
        ++ticks;
      }
    }
    loop.stop();
  }(loop, ticks));
  CHECK(ticks == 10);
}

#endif
