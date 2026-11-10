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
#include <string>
#include <vector>

#include <vio/event_loop.h>
#include <vio/gui/gui.h>
#include <vio/gui/ui/ui.h>
#include <vio/operation/sleep.h>
#include <vio/task.h>

#include "gui_test_helpers.h"

using namespace std::chrono_literals;
namespace gui = vio::gui;
namespace ui = vio::gui::ui;

namespace
{
constexpr ui::color_t red{1, 0, 0, 1};
constexpr ui::color_t green{0, 1, 0, 1};
constexpr ui::color_t grey{0.5f, 0.5f, 0.5f, 1};

gui::display_t open_null(vio::event_loop_t &loop)
{
  gui::display_config_t config;
  config.backend = "null";
  config.frame_interval_ns = std::chrono::nanoseconds(2ms).count();
  auto display = gui::display_t::open(loop, config);
  REQUIRE(display.has_value());
  return std::move(*display);
}

void click(gui::window_t &window, gui::point_t at)
{
  window.impl()->on_input(gui::pointer_move_event_t{at});
  window.impl()->on_input(gui::pointer_button_event_t{gui::button_t::left, true, at});
  window.impl()->on_input(gui::pointer_button_event_t{gui::button_t::left, false, at});
}

// Long enough for the pointer events to be delivered, the behaviours to run and a frame to follow.
vio::task_t<void> settle(vio::event_loop_t &loop)
{
  (void)co_await vio::sleep(loop, 40ms);
}

struct counter_t
{
  int count = 0;
  ui::pressable_t inc;
  ui::pressable_t dec;
  mutable int views = 0;

  ui::node_t view() const
  {
    ++views;
    return ui::row_t{.gap = 8,
                     .children = {
                       ui::box_t{.size = {60, 60}, .color = red, .events = dec},
                       ui::box_t{.size = {60, 60}, .color = green, .events = inc},
                       ui::box_t{.size = {20 * count + 1, 60}, .color = grey},
                     }};
  }

  ui::behaviour_t behave(ui::scope_t &)
  {
    auto presses = ui::subscribe<ui::press_event_t>(inc, dec);
    while (auto press = co_await presses)
      count += press->source == &inc ? 1 : -1;
  }
};
} // namespace

TEST_CASE("ui: a press reaches the behaviour, and the view is rebuilt from the new state")
{
  vio::event_loop_t loop;
  struct seen_t
  {
    std::vector<ui::rect_t> first;
    std::vector<ui::rect_t> last;
    int count_after_two = 0;
    int count_after_three = 0;
    bool hovered = false;
  } seen;
  run_gui_test(loop, [](vio::event_loop_t &loop, seen_t &seen) -> vio::task_t<void> {
    auto display = open_null(loop);
    {
      auto window = gui::window_t::create(display, {.size = {640, 480}});
      REQUIRE(window.has_value());
      counter_t counter;
      auto on_layout = [&seen](std::span<const ui::draw_item_t> items) {
        seen.last.clear();
        for (const auto &item : items)
          seen.last.push_back(item.rect);
        if (seen.first.empty())
          seen.first = seen.last;
      };
      auto running = ui::run(*window, counter, {.on_layout = on_layout});
      co_await settle(loop);
      click(*window, {90, 30});
      click(*window, {90, 30});
      co_await settle(loop);
      seen.count_after_two = counter.count;
      seen.hovered = counter.inc.hovered();
      click(*window, {30, 30});
      co_await settle(loop);
      seen.count_after_three = counter.count;
      window->close();
      co_await std::move(running);
    }
    loop.stop();
  }(loop, seen));
  REQUIRE(seen.first.size() == 3);
  CHECK(seen.first[0] == ui::rect_t{0, 0, 60, 60});
  CHECK(seen.first[1] == ui::rect_t{68, 0, 60, 60});
  CHECK(seen.first[2] == ui::rect_t{136, 0, 1, 60});
  CHECK(seen.count_after_two == 2);
  CHECK(seen.hovered);
  CHECK(seen.count_after_three == 1);
  REQUIRE(seen.last.size() == 3);
  CHECK(seen.last[2].width == 21);
}

TEST_CASE("ui: a press released off the box it started on is abandoned")
{
  vio::event_loop_t loop;
  int count = -1;
  bool held_while_down = false;
  run_gui_test(loop, [](vio::event_loop_t &loop, int &count, bool &held_while_down) -> vio::task_t<void> {
    auto display = open_null(loop);
    {
      auto window = gui::window_t::create(display, {.size = {640, 480}});
      counter_t counter;
      auto running = ui::run(*window, counter);
      co_await settle(loop);
      window->impl()->on_input(gui::pointer_button_event_t{gui::button_t::left, true, {90, 30}});
      co_await settle(loop);
      held_while_down = counter.inc.held();
      window->impl()->on_input(gui::pointer_button_event_t{gui::button_t::left, false, {400, 300}});
      co_await settle(loop);
      count = counter.count;
      window->close();
      co_await std::move(running);
    }
    loop.stop();
  }(loop, count, held_while_down));
  CHECK(held_while_down);
  CHECK(count == 0);
}

namespace
{
struct handler_t
{
  int presses = 0;
  mutable int views = 0;

  ui::node_t view() const
  {
    ++views;
    return ui::box_t{.size = {50, 50}, .color = red, .on_press = [this] { ++const_cast<handler_t *>(this)->presses; }};
  }
};
} // namespace

TEST_CASE("ui: an on_press handler in the literal runs, and its component is rebuilt")
{
  vio::event_loop_t loop;
  int presses = 0;
  int views = 0;
  run_gui_test(loop, [](vio::event_loop_t &loop, int &presses, int &views) -> vio::task_t<void> {
    auto display = open_null(loop);
    {
      auto window = gui::window_t::create(display, {.size = {640, 480}});
      handler_t handler;
      auto running = ui::run(*window, handler);
      co_await settle(loop);
      const int before = handler.views;
      click(*window, {10, 10});
      co_await settle(loop);
      presses = handler.presses;
      views = handler.views - before;
      window->close();
      co_await std::move(running);
    }
    loop.stop();
  }(loop, presses, views));
  CHECK(presses == 1);
  CHECK(views >= 1);
}

namespace
{
struct pair_t
{
  counter_t left;
  counter_t right;
  mutable int views = 0;

  ui::node_t view() const
  {
    ++views;
    return ui::column_t{.gap = 10, .children = {ui::mount(left), ui::mount(right)}};
  }
};
} // namespace

TEST_CASE("ui: only the component that changed re-runs its view")
{
  vio::event_loop_t loop;
  struct seen_t
  {
    int left = 0;
    int right = 0;
    int parent = 0;
    int left_count = 0;
    int right_count = 0;
    ui::rect_t right_inc;
  } seen;
  run_gui_test(loop, [](vio::event_loop_t &loop, seen_t &seen) -> vio::task_t<void> {
    auto display = open_null(loop);
    {
      auto window = gui::window_t::create(display, {.size = {640, 480}});
      pair_t pair;
      auto on_layout = [&seen](std::span<const ui::draw_item_t> items) {
        if (items.size() == 6)
          seen.right_inc = items[4].rect;
      };
      auto running = ui::run(*window, pair, {.on_layout = on_layout});
      co_await settle(loop);
      // Move the pointer away first, so hovering does not count as a change of its own.
      window->impl()->on_input(gui::pointer_move_event_t{{600, 400}});
      co_await settle(loop);
      const int left = pair.left.views;
      const int right = pair.right.views;
      const int parent = pair.views;
      window->impl()->on_input(gui::pointer_button_event_t{gui::button_t::left, true, {90, 30}});
      window->impl()->on_input(gui::pointer_button_event_t{gui::button_t::left, false, {90, 30}});
      co_await settle(loop);
      seen.left = pair.left.views - left;
      seen.right = pair.right.views - right;
      seen.parent = pair.views - parent;
      seen.left_count = pair.left.count;
      seen.right_count = pair.right.count;
      window->close();
      co_await std::move(running);
    }
    loop.stop();
  }(loop, seen));
  CHECK(seen.left_count == 1);
  CHECK(seen.right_count == 0);
  CHECK(seen.left >= 1);
  CHECK(seen.right == 0);
  CHECK(seen.parent == 0);
  CHECK(seen.right_inc == ui::rect_t{68, 70, 60, 60});
}

namespace
{
struct witness_t
{
  bool *destroyed;
  ~witness_t()
  {
    *destroyed = true;
  }
};

struct child_t
{
  ui::pressable_t button;
  bool *ticker_gone = nullptr;
  bool *listener_ended = nullptr;
  int *ticks = nullptr;

  ui::node_t view() const
  {
    return ui::box_t{.size = {40, 40}, .color = grey, .events = button};
  }

  // Sleeps with no token: it is not woken by the unmount, it is refused at its next await.
  ui::behaviour_t tick(ui::scope_t &scope)
  {
    witness_t witness{ticker_gone};
    while (true)
    {
      (void)co_await vio::sleep(scope.loop(), 1ms);
      ++*ticks;
    }
  }

  ui::behaviour_t behave(ui::scope_t &scope)
  {
    scope.spawn(tick(scope));
    auto presses = ui::subscribe<ui::press_event_t>(button);
    while (co_await presses)
    {
    }
    *listener_ended = true;
  }
};

struct parent_t
{
  bool show = true;
  child_t child;

  ui::node_t view() const
  {
    ui::row_t row{.gap = 4};
    row.children.push_back(ui::box_t{.size = {40, 40}, .color = red, .on_press = [this] { const_cast<parent_t *>(this)->show = !show; }});
    if (show)
      row.children.push_back(ui::mount(child));
    return row;
  }
};
} // namespace

TEST_CASE("ui: unmounting a component ends every behaviour in its scope")
{
  vio::event_loop_t loop;
  struct seen_t
  {
    bool ticker_gone = false;
    bool listener_ended = false;
    int ticks = 0;
    int ticks_at_unmount = 0;
    int ticks_later = 0;
    bool ticker_gone_before = true;
  } seen;
  run_gui_test(loop, [](vio::event_loop_t &loop, seen_t &seen) -> vio::task_t<void> {
    auto display = open_null(loop);
    {
      auto window = gui::window_t::create(display, {.size = {640, 480}});
      parent_t parent;
      parent.child.ticker_gone = &seen.ticker_gone;
      parent.child.listener_ended = &seen.listener_ended;
      parent.child.ticks = &seen.ticks;
      auto running = ui::run(*window, parent);
      co_await settle(loop);
      seen.ticker_gone_before = seen.ticker_gone;
      click(*window, {10, 10});
      co_await settle(loop);
      seen.ticks_at_unmount = seen.ticks;
      co_await settle(loop);
      seen.ticks_later = seen.ticks;
      window->close();
      co_await std::move(running);
    }
    loop.stop();
  }(loop, seen));
  CHECK(!seen.ticker_gone_before);
  CHECK(seen.ticker_gone);
  CHECK(seen.listener_ended);
  CHECK(seen.ticks_at_unmount > 0);
  CHECK(seen.ticks_later == seen.ticks_at_unmount);
}

namespace
{
struct sleeper_t
{
  bool *cancelled = nullptr;

  ui::node_t view() const
  {
    return ui::box_t{.size = {10, 10}};
  }

  ui::behaviour_t behave(ui::scope_t &scope)
  {
    auto slept = co_await vio::sleep(scope.loop(), 1h, scope.token());
    *cancelled = !slept && vio::is_cancelled(slept.error());
  }
};
} // namespace

TEST_CASE("ui: closing the window resolves an operation started with the scope's token")
{
  vio::event_loop_t loop;
  bool cancelled = false;
  run_gui_test(
    loop,
    [](vio::event_loop_t &loop, bool &cancelled) -> vio::task_t<void> {
      auto display = open_null(loop);
      {
        auto window = gui::window_t::create(display, {.size = {640, 480}});
        auto running = ui::run(*window, sleeper_t{&cancelled});
        co_await settle(loop);
        window->close();
        co_await std::move(running);
      }
      loop.stop();
    }(loop, cancelled),
    5s);
  CHECK(cancelled);
}

namespace
{
struct ordered_t
{
  std::vector<std::string> *order = nullptr;

  ui::node_t view() const
  {
    return ui::box_t{.size = {10, 10}};
  }

  ui::behaviour_t child(ui::scope_t &scope)
  {
    order->push_back("child starts");
    (void)co_await vio::sleep(scope.loop(), 1ms, scope.token());
    order->push_back("child resumes");
  }

  ui::behaviour_t behave(ui::scope_t &scope)
  {
    order->push_back("behave starts");
    scope.spawn(child(scope));
    order->push_back("spawn returned");
    co_return;
  }
};

struct ticker_t
{
  int ticks = 0;
  mutable std::vector<int> shown;

  ui::node_t view() const
  {
    shown.push_back(ticks);
    return ui::box_t{.size = {10 + ticks, 10}};
  }

  ui::behaviour_t behave(ui::scope_t &scope)
  {
    for (int i = 0; i < 3; ++i)
    {
      (void)co_await vio::sleep(scope.loop(), 5ms, scope.token());
      ++ticks;
    }
  }
};
} // namespace

TEST_CASE("ui: spawn runs the new behaviour to its first suspension before returning")
{
  vio::event_loop_t loop;
  std::vector<std::string> order;
  run_gui_test(loop, [](vio::event_loop_t &loop, std::vector<std::string> &order) -> vio::task_t<void> {
    auto display = open_null(loop);
    {
      auto window = gui::window_t::create(display, {.size = {640, 480}});
      auto running = ui::run(*window, ordered_t{&order});
      co_await settle(loop);
      window->close();
      co_await std::move(running);
    }
    loop.stop();
  }(loop, order));
  CHECK(order == std::vector<std::string>{"behave starts", "child starts", "spawn returned", "child resumes"});
}

TEST_CASE("ui: a behaviour woken by something other than the ui rebuilds its view")
{
  vio::event_loop_t loop;
  std::vector<int> shown;
  run_gui_test(loop, [](vio::event_loop_t &loop, std::vector<int> &shown) -> vio::task_t<void> {
    auto display = open_null(loop);
    {
      auto window = gui::window_t::create(display, {.size = {640, 480}});
      ticker_t clock;
      auto running = ui::run(*window, clock);
      (void)co_await vio::sleep(loop, 100ms);
      shown = clock.shown;
      window->close();
      co_await std::move(running);
    }
    loop.stop();
  }(loop, shown));
  REQUIRE(!shown.empty());
  CHECK(shown.back() == 3);
  CHECK(std::is_sorted(shown.begin(), shown.end()));
}
