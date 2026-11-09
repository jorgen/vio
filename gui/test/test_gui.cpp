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
#include <type_traits>
#include <variant>
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

TEST_CASE("input recorded before an await is delivered to a subscription in order")
{
  vio::event_loop_t loop;
  std::vector<gui::window_event_t> seen;
  run_gui_test(loop, [](vio::event_loop_t &loop, std::vector<gui::window_event_t> &seen) -> vio::task_t<void> {
    auto display = open_null(loop);
    {
      auto window = gui::window_t::create(display);
      REQUIRE(window.has_value());
      auto all = window->subscribe<>();
      window->impl()->on_input(gui::key_event_t{.key = gui::key_t::a, .pressed = true});
      window->impl()->on_input(gui::text_event_t{"a"});
      window->impl()->on_input(gui::key_event_t{.key = gui::key_t::a, .pressed = false});
      for (int i = 0; i < 3; ++i)
      {
        auto event = co_await all;
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
      auto focus = window->subscribe<gui::focus_event_t>();
      auto *impl = window->impl();
      loop.run_in_loop([impl] { impl->on_input(gui::focus_event_t{true}); });
      auto event = co_await focus;
      REQUIRE(event.has_value());
      CHECK(event->focused);
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
      auto pointer = window->subscribe<gui::pointer_move_event_t, gui::pointer_button_event_t>();
      auto *impl = window->impl();
      impl->on_input(gui::pointer_move_event_t{{1, 1}});
      impl->on_input(gui::pointer_move_event_t{{2, 2}});
      impl->on_input(gui::pointer_button_event_t{gui::button_t::left, true, {2, 2}});
      impl->on_input(gui::pointer_move_event_t{{3, 3}});
      auto first = co_await pointer;
      auto second = co_await pointer;
      auto third = co_await pointer;
      REQUIRE((first && second && third));
      CHECK(std::get<gui::pointer_move_event_t>(*first).position == gui::point_t{2, 2});
      CHECK(std::get<gui::pointer_button_event_t>(*second).pressed);
      CHECK(std::get<gui::pointer_move_event_t>(*third).position == gui::point_t{3, 3});
      CHECK(pointer.dropped() == 0);
    }
    loop.stop();
  }(loop));
}

TEST_CASE("a subscription nobody reads is bounded and counts what it dropped")
{
  vio::event_loop_t loop;
  run_gui_test(loop, [](vio::event_loop_t &loop) -> vio::task_t<void> {
    auto display = open_null(loop, {.input_queue_limit = 8});
    {
      auto window = gui::window_t::create(display);
      auto keys = window->subscribe<gui::key_event_t>();
      for (int i = 0; i < 20; ++i)
        window->impl()->on_input(gui::key_event_t{.scancode = static_cast<std::uint32_t>(i), .pressed = true});
      CHECK(keys.dropped() == 12);
      auto oldest = co_await keys;
      REQUIRE(oldest.has_value());
      CHECK(oldest->scancode == 12);
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
      CHECK(window->size() == gui::extent_t{100, 100});
      auto sizes = window->subscribe<gui::resize_event_t>();
      REQUIRE(window->set_size({200, 150}).has_value());
      REQUIRE(window->set_size({300, 250}).has_value());
      auto latest = co_await sizes;
      REQUIRE(latest.has_value());
      CHECK(latest->size == gui::extent_t{300, 250});
      CHECK(window->size() == gui::extent_t{300, 250});
      CHECK(sizes.dropped() == 0);
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
      CHECK(times.back() - times.front() >= std::chrono::nanoseconds(60ms).count());
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

TEST_CASE("a close request closes the window, which ends every await")
{
  vio::event_loop_t loop;
  bool requested = false;
  bool keys_ended = false;
  bool frame_ended = false;
  run_gui_test(loop, [](vio::event_loop_t &loop, bool &requested, bool &keys_ended, bool &frame_ended) -> vio::task_t<void> {
    auto display = open_null(loop);
    {
      auto window = gui::window_t::create(display);
      auto reader = [](gui::window_t &window, bool &keys_ended) -> vio::task_t<void> {
        auto keys = window.subscribe<gui::key_event_t>();
        keys_ended = !(co_await keys).has_value();
      }(*window, keys_ended);
      auto closer = [](gui::window_t &window, bool &requested) -> vio::task_t<void> {
        auto requests = window.subscribe<gui::close_request_t>();
        requested = (co_await requests).has_value();
        window.close();
      }(*window, requested);
      window->impl()->on_close_request();
      co_await std::move(closer);
      co_await std::move(reader);
      frame_ended = !(co_await window->frame()).has_value();
    }
    loop.stop();
  }(loop, requested, keys_ended, frame_ended));
  CHECK(requested);
  CHECK(keys_ended);
  CHECK(frame_ended);
}

TEST_CASE("every subscriber sees a close request and a resize, in order with input")
{
  vio::event_loop_t loop;
  run_gui_test(loop, [](vio::event_loop_t &loop) -> vio::task_t<void> {
    auto display = open_null(loop);
    {
      auto window = gui::window_t::create(display, {.size = {100, 100}});
      auto dialog = window->subscribe<gui::key_event_t, gui::close_request_t>();
      auto layout = window->subscribe<gui::resize_event_t>();
      auto renderer = window->subscribe<gui::resize_event_t>();
      auto *impl = window->impl();
      impl->on_input(gui::key_event_t{.key = gui::key_t::escape, .pressed = true});
      impl->on_close_request();
      impl->on_close_request();
      REQUIRE(window->set_size({300, 200}).has_value());

      auto first = co_await dialog;
      auto second = co_await dialog;
      REQUIRE((first && second));
      CHECK(std::get<gui::key_event_t>(*first).key == gui::key_t::escape);
      CHECK(std::holds_alternative<gui::close_request_t>(*second));
      for (auto *sizes : {&layout, &renderer})
      {
        auto resized = co_await *sizes;
        REQUIRE(resized.has_value());
        CHECK(resized->size == gui::extent_t{300, 200});
      }
      window->close();
      CHECK(!(co_await dialog).has_value());
    }
    loop.stop();
  }(loop));
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
    waiter.emplace([](gui::window_t &window) -> vio::task_t<void> {
      auto all = window.subscribe<>();
      co_await all;
    }(*window));
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
      auto focus = window->subscribe<gui::focus_event_t>();
      auto *impl = window->impl();
      impl->on_input(gui::focus_event_t{true});
      impl->on_input(gui::focus_event_t{false});
      auto event = co_await focus;
      CHECK(event.has_value());
      window.reset();
      CHECK(!focus);
    }
    finished = true;
    loop.stop();
  }(loop, finished));
  CHECK(finished);
}

TEST_CASE("subscriptions each see every event of their types")
{
  vio::event_loop_t loop;
  run_gui_test(loop, [](vio::event_loop_t &loop) -> vio::task_t<void> {
    auto display = open_null(loop);
    {
      auto window = gui::window_t::create(display);
      REQUIRE(window.has_value());
      auto keys_a = window->subscribe<gui::key_event_t>();
      auto keys_b = window->subscribe<gui::key_event_t>();
      auto focus = window->subscribe<gui::focus_event_t>();
      auto *impl = window->impl();
      impl->on_input(gui::key_event_t{.key = gui::key_t::a, .pressed = true});
      impl->on_input(gui::focus_event_t{true});
      impl->on_input(gui::key_event_t{.key = gui::key_t::b, .pressed = true});

      for (auto *keys : {&keys_a, &keys_b})
      {
        auto first = co_await *keys;
        auto second = co_await *keys;
        REQUIRE(first.has_value());
        REQUIRE(second.has_value());
        CHECK(first->key == gui::key_t::a);
        CHECK(second->key == gui::key_t::b);
      }
      auto focused = co_await focus;
      REQUIRE(focused.has_value());
      CHECK(focused->focused);
    }
    loop.stop();
  }(loop));
}

TEST_CASE("a subscription to several types keeps their order and yields only those types")
{
  vio::event_loop_t loop;
  run_gui_test(loop, [](vio::event_loop_t &loop) -> vio::task_t<void> {
    auto display = open_null(loop);
    {
      auto window = gui::window_t::create(display);
      REQUIRE(window.has_value());
      auto edit = window->subscribe<gui::key_event_t, gui::text_event_t>();
      static_assert(std::is_same_v<decltype(edit)::event_t, std::variant<gui::key_event_t, gui::text_event_t>>);
      auto *impl = window->impl();
      impl->on_input(gui::key_event_t{.key = gui::key_t::a, .pressed = true});
      impl->on_input(gui::pointer_move_event_t{{1, 1}});
      impl->on_input(gui::text_event_t{"a"});
      impl->on_input(gui::key_event_t{.key = gui::key_t::a, .pressed = false});
      auto first = co_await edit;
      auto second = co_await edit;
      auto third = co_await edit;
      REQUIRE((first && second && third));
      CHECK(std::get<gui::key_event_t>(*first).pressed);
      CHECK(std::get<gui::text_event_t>(*second).text == "a");
      CHECK(!std::get<gui::key_event_t>(*third).pressed);
    }
    loop.stop();
  }(loop));
}

TEST_CASE("a subscription sees only what arrives after it, and counts its own drops")
{
  vio::event_loop_t loop;
  run_gui_test(loop, [](vio::event_loop_t &loop) -> vio::task_t<void> {
    auto display = open_null(loop, {.input_queue_limit = 4});
    {
      auto window = gui::window_t::create(display);
      REQUIRE(window.has_value());
      auto *impl = window->impl();
      impl->on_input(gui::key_event_t{.scancode = 100, .pressed = true});
      auto keys = window->subscribe<gui::key_event_t>();
      auto all = window->subscribe<>();
      for (int i = 0; i < 6; ++i)
        impl->on_input(gui::key_event_t{.scancode = static_cast<std::uint32_t>(i), .pressed = true});
      CHECK(keys.dropped() == 2);
      CHECK(all.dropped() == 2);
      auto oldest = co_await keys;
      REQUIRE(oldest.has_value());
      CHECK(oldest->scancode == 2);
      auto any = co_await all;
      REQUIRE(any.has_value());
      CHECK(std::get<gui::key_event_t>(*any).scancode == 2);
    }
    loop.stop();
  }(loop));
}

TEST_CASE("closing the window ends a subscription loop, and later awaits end at once")
{
  vio::event_loop_t loop;
  std::vector<gui::key_t> seen;
  run_gui_test(loop, [](vio::event_loop_t &loop, std::vector<gui::key_t> &seen) -> vio::task_t<void> {
    auto display = open_null(loop);
    {
      auto window = gui::window_t::create(display);
      REQUIRE(window.has_value());
      auto keys = window->subscribe<gui::key_event_t>();
      auto reader = [](gui::subscription_t<gui::key_event_t> &keys, std::vector<gui::key_t> &seen) -> vio::task_t<void> {
        while (auto key = co_await keys)
          seen.push_back(key->key);
      }(keys, seen);
      auto *impl = window->impl();
      loop.run_in_loop([impl] { impl->on_input(gui::key_event_t{.key = gui::key_t::x, .pressed = true}); });
      co_await vio::sleep(loop, 10ms);
      window->close();
      co_await std::move(reader);
      CHECK(!keys);
      CHECK(!(co_await keys).has_value());
      auto late = window->subscribe<gui::text_event_t>();
      CHECK(!late);
      CHECK(!(co_await late).has_value());
    }
    loop.stop();
  }(loop, seen));
  CHECK(seen == std::vector<gui::key_t>{gui::key_t::x});
}

TEST_CASE("dropping a subscription while a coroutine awaits it ends that await")
{
  vio::event_loop_t loop;
  bool ended = false;
  run_gui_test(loop, [](vio::event_loop_t &loop, bool &ended) -> vio::task_t<void> {
    auto display = open_null(loop);
    {
      auto window = gui::window_t::create(display);
      REQUIRE(window.has_value());
      std::optional<gui::subscription_t<gui::scroll_event_t>> scrolls(window->subscribe<gui::scroll_event_t>());
      auto reader = [](gui::subscription_t<gui::scroll_event_t> &scrolls, bool &ended) -> vio::task_t<void> {
        ended = !(co_await scrolls).has_value();
      }(*scrolls, ended);
      scrolls.reset();
      CHECK(window->impl()->subscriptions.empty());
      co_await std::move(reader);
    }
    loop.stop();
  }(loop, ended));
  CHECK(ended);
}
