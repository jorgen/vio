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

#include <chrono>
#include <optional>
#include <string>
#include <vector>

#include <vio/event_loop.h>
#include <vio/gui/gui.h>
#include <vio/operation/sleep.h>
#include <vio/task.h>

#include "gui_test_helpers.h"

using namespace std::chrono_literals;
namespace gui = vio::gui;

namespace
{
gui::display_t open_null(vio::event_loop_t &loop, gui::display_config_t config = {})
{
  config.backend = "null";
  auto display = gui::display_t::open(loop, config);
  REQUIRE(display.has_value());
  return std::move(*display);
}
} // namespace

TEST_CASE("input recorded before an await is delivered in order")
{
  vio::event_loop_t loop;
  std::vector<gui::input_event_t> seen;
  run_gui_test(loop, [](vio::event_loop_t &loop, std::vector<gui::input_event_t> &seen) -> vio::task_t<void> {
    auto display = open_null(loop);
    {
      auto window = gui::window_t::create(display);
      REQUIRE(window.has_value());
      window->impl()->on_input(gui::key_event_t{.key = gui::key_t::a, .pressed = true});
      window->impl()->on_input(gui::text_event_t{"a"});
      window->impl()->on_input(gui::key_event_t{.key = gui::key_t::a, .pressed = false});
      for (int i = 0; i < 3; ++i)
      {
        auto event = co_await window->input();
        REQUIRE(event.has_value());
        seen.push_back(*event);
      }
    }
    loop.stop();
  }(loop, seen));
  REQUIRE(seen.size() == 3);
  CHECK(std::get<gui::key_event_t>(seen[0]).pressed);
  CHECK(std::get<gui::text_event_t>(seen[1]).text == "a");
  CHECK(!std::get<gui::key_event_t>(seen[2]).pressed);
}

TEST_CASE("input arriving while a coroutine waits resumes it in the same turn")
{
  vio::event_loop_t loop;
  int resumed = 0;
  run_gui_test(loop, [](vio::event_loop_t &loop, int &resumed) -> vio::task_t<void> {
    auto display = open_null(loop);
    {
      auto window = gui::window_t::create(display);
      REQUIRE(window.has_value());
      auto *impl = window->impl();
      loop.run_in_loop([impl] { impl->on_input(gui::focus_event_t{true}); });
      auto event = co_await window->input();
      REQUIRE(event.has_value());
      CHECK(std::get<gui::focus_event_t>(*event).focused);
      ++resumed;
    }
    loop.stop();
  }(loop, resumed));
  CHECK(resumed == 1);
}

TEST_CASE("pointer moves that nobody has taken yet are merged")
{
  vio::event_loop_t loop;
  run_gui_test(loop, [](vio::event_loop_t &loop) -> vio::task_t<void> {
    auto display = open_null(loop);
    {
      auto window = gui::window_t::create(display);
      auto *impl = window->impl();
      impl->on_input(gui::pointer_move_event_t{{1, 1}});
      impl->on_input(gui::pointer_move_event_t{{2, 2}});
      impl->on_input(gui::pointer_button_event_t{gui::button_t::left, true, {2, 2}});
      impl->on_input(gui::pointer_move_event_t{{3, 3}});
      CHECK(impl->input.size() == 3);
      auto first = co_await window->input();
      CHECK(std::get<gui::pointer_move_event_t>(*first).position == gui::point_t{2, 2});
    }
    loop.stop();
  }(loop));
}

TEST_CASE("an input queue nobody reads is bounded and counts what it dropped")
{
  vio::event_loop_t loop;
  run_gui_test(loop, [](vio::event_loop_t &loop) -> vio::task_t<void> {
    auto display = open_null(loop, {.input_queue_limit = 8});
    {
      auto window = gui::window_t::create(display);
      for (int i = 0; i < 20; ++i)
        window->impl()->on_input(gui::key_event_t{.scancode = static_cast<std::uint32_t>(i), .pressed = true});
      CHECK(window->impl()->input.size() == 8);
      CHECK(window->input_dropped() == 12);
      auto oldest = co_await window->input();
      CHECK(std::get<gui::key_event_t>(*oldest).scancode == 12);
    }
    loop.stop();
    co_return;
  }(loop));
}

TEST_CASE("sizes that arrive while nobody waits merge into the latest")
{
  vio::event_loop_t loop;
  run_gui_test(loop, [](vio::event_loop_t &loop) -> vio::task_t<void> {
    auto display = open_null(loop);
    {
      auto window = gui::window_t::create(display, {.size = {100, 100}});
      auto first = co_await window->resized();
      CHECK(first->size == gui::extent_t{100, 100});
      REQUIRE(window->set_size({200, 150}).has_value());
      REQUIRE(window->set_size({300, 250}).has_value());
      auto latest = co_await window->resized();
      CHECK(latest->size == gui::extent_t{300, 250});
      CHECK(window->size() == gui::extent_t{300, 250});
    }
    loop.stop();
  }(loop));
}

TEST_CASE("the first frame is immediate and the next waits for the clock")
{
  vio::event_loop_t loop;
  run_gui_test(loop, [](vio::event_loop_t &loop) -> vio::task_t<void> {
    auto display = open_null(loop, {.frame_interval_ns = std::chrono::nanoseconds(20ms).count()});
    {
      auto window = gui::window_t::create(display);
      auto start = std::chrono::steady_clock::now();
      auto first = co_await window->frame();
      REQUIRE(first.has_value());
      CHECK(first->damaged);
      CHECK(first->number == 1);
      CHECK(std::chrono::steady_clock::now() - start < 15ms);
      std::vector<std::int64_t> times;
      for (int i = 0; i < 5; ++i)
      {
        auto frame = co_await window->frame();
        REQUIRE(frame.has_value());
        CHECK(!frame->damaged);
        CHECK(frame->number == static_cast<std::uint64_t>(i + 2));
        times.push_back(frame->time_ns);
      }
      for (std::size_t i = 1; i < times.size(); ++i)
        CHECK(times[i] > times[i - 1]);
      CHECK(times.back() - times.front() >= std::chrono::nanoseconds(70ms).count());
    }
    loop.stop();
  }(loop));
}

TEST_CASE("a hidden window gets no frames until it is shown")
{
  vio::event_loop_t loop;
  bool got_frame_while_hidden = false;
  run_gui_test(loop, [](vio::event_loop_t &loop, bool &early) -> vio::task_t<void> {
    auto display = open_null(loop);
    {
      auto window = gui::window_t::create(display, {.visible = false});
      bool shown = false;
      auto *impl = window->impl();
      auto show = [](vio::event_loop_t &loop, gui::window_t &window, bool &shown) -> vio::task_t<void> {
        co_await vio::sleep(loop, 60ms);
        shown = true;
        window.show();
      }(loop, *window, shown);
      auto frame = co_await window->frame();
      REQUIRE(frame.has_value());
      early = !shown;
      CHECK(impl->visible);
      co_await std::move(show);
    }
    loop.stop();
  }(loop, got_frame_while_hidden));
  CHECK(!got_frame_while_hidden);
}

TEST_CASE("closing a window cancels its waiters and later awaits")
{
  vio::event_loop_t loop;
  std::vector<int> errors;
  run_gui_test(loop, [](vio::event_loop_t &loop, std::vector<int> &errors) -> vio::task_t<void> {
    auto display = open_null(loop);
    {
      auto window = gui::window_t::create(display);
      auto reader = [](gui::window_t &window, std::vector<int> &errors) -> vio::task_t<void> {
        auto event = co_await window.input();
        errors.push_back(event ? 0 : event.error().code);
      }(*window, errors);
      auto closer = [](gui::window_t &window, std::vector<int> &errors) -> vio::task_t<void> {
        auto request = co_await window.close_requested();
        errors.push_back(request ? 0 : request.error().code);
        window.close();
      }(*window, errors);
      window->impl()->on_close_request();
      co_await std::move(closer);
      co_await std::move(reader);
      auto after = co_await window->frame();
      errors.push_back(after ? 0 : after.error().code);
    }
    loop.stop();
  }(loop, errors));
  CHECK(errors == std::vector<int>{0, vio::errc::canceled, vio::errc::canceled});
}

TEST_CASE("a waiting coroutine does not keep the loop alive after stop")
{
  vio::event_loop_t loop;
  std::optional<gui::display_t> display;
  std::optional<gui::window_t> window;
  std::optional<vio::task_t<void>> waiter;
  loop.run_in_loop([&] {
    display.emplace(open_null(loop));
    window.emplace(std::move(*gui::window_t::create(*display)));
    waiter.emplace([](gui::window_t &window) -> vio::task_t<void> { co_await window.input(); }(*window));
    loop.stop();
  });
  auto start = std::chrono::steady_clock::now();
  loop.run();
  CHECK(std::chrono::steady_clock::now() - start < 1s);
  CHECK(!waiter->done());
  window->close();
  window.reset();
  display.reset();
  loop.stop();
  loop.run();
  CHECK(waiter->done());
}

TEST_CASE("the clipboard round-trips through the display")
{
  vio::event_loop_t loop;
  std::string text;
  run_gui_test(loop, [](vio::event_loop_t &loop, std::string &text) -> vio::task_t<void> {
    auto display = open_null(loop);
    display.set_clipboard_text("hello");
    auto got = co_await display.clipboard_text();
    REQUIRE(got.has_value());
    text = *got;
    loop.stop();
  }(loop, text));
  CHECK(text == "hello");
}

TEST_CASE("a coroutine can drop its window from inside a resumed await")
{
  vio::event_loop_t loop;
  bool finished = false;
  run_gui_test(loop, [](vio::event_loop_t &loop, bool &finished) -> vio::task_t<void> {
    auto display = open_null(loop);
    {
      std::optional<gui::window_t> window(std::move(*gui::window_t::create(display)));
      auto *impl = window->impl();
      impl->on_input(gui::focus_event_t{true});
      impl->on_input(gui::focus_event_t{false});
      auto event = co_await window->input();
      CHECK(event.has_value());
      window.reset();
    }
    finished = true;
    loop.stop();
  }(loop, finished));
  CHECK(finished);
}
