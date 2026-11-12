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

// G46: keyboard focus, popups, and the widgets built on them.

#include <doctest/doctest.h>

#include <chrono>
#include <functional>
#include <string>
#include <vector>

#include <vio/event_loop.h>
#include <vio/gui/gui.h>
#include <vio/gui/ui/ui.h>
#include <vio/gui/ui/widgets.h>
#include <vio/operation/sleep.h>
#include <vio/task.h>

#include "gui_test_helpers.h"

using namespace std::chrono_literals;
namespace gui = vio::gui;
namespace ui = vio::gui::ui;

namespace
{
// What the last layout put where, and what each place reports to.
struct seen_t
{
  ui::rect_t rect;
  const ui::pressable_t *source = nullptr;
};

using act_t = std::function<vio::task_t<void>(vio::event_loop_t &, gui::window_t &)>;

template <typename C>
void drive(C &root, std::vector<seen_t> &seen, act_t act)
{
  vio::event_loop_t loop;
  run_gui_test(loop,
               [](vio::event_loop_t &loop, C &root, std::vector<seen_t> &seen, act_t act) -> vio::task_t<void>
               {
                 gui::display_config_t display_config;
                 display_config.backend = "null";
                 display_config.frame_interval_ns = std::chrono::nanoseconds(2ms).count();
                 auto display = gui::display_t::open(loop, display_config);
                 REQUIRE(display.has_value());
                 {
                   auto window = gui::window_t::create(*display, {.size = {400, 300}});
                   ui::run_config_t config;
                   config.on_layout = [&seen](std::span<const ui::draw_item_t> items)
                   {
                     seen.clear();
                     for (const auto &item : items)
                       seen.push_back({item.rect, item.box->events.source});
                   };
                   auto running = ui::run(*window, root, std::move(config));
                   (void)co_await vio::sleep(loop, 40ms);
                   co_await act(loop, *window);
                   window->close();
                   co_await std::move(running);
                 }
                 loop.stop();
               }(loop, root, seen, std::move(act)));
}

vio::task_t<void> settle(vio::event_loop_t &loop)
{
  (void)co_await vio::sleep(loop, 40ms);
}

gui::point_t centre(const ui::rect_t &r)
{
  return {r.x + r.width / 2.0, r.y + r.height / 2.0};
}

void click(gui::window_t &window, gui::point_t at)
{
  window.impl()->on_input(gui::pointer_move_event_t{at});
  window.impl()->on_input(gui::pointer_button_event_t{gui::button_t::left, true, at});
  window.impl()->on_input(gui::pointer_button_event_t{gui::button_t::left, false, at});
}

void key(gui::window_t &window, gui::key_t k, gui::modifier_t modifiers = gui::modifier_t::none)
{
  window.impl()->on_input(gui::key_event_t{k, 0, modifiers, true});
  window.impl()->on_input(gui::key_event_t{k, 0, modifiers, false});
}

// The rect of the first box reporting to `source`.
ui::rect_t rect_of(const std::vector<seen_t> &seen, const ui::pressable_t *source)
{
  for (const auto &s : seen)
  {
    if (s.source == source)
      return s.rect;
  }
  return {};
}

std::size_t count_of(const std::vector<seen_t> &seen, const ui::pressable_t *source)
{
  std::size_t n = 0;
  for (const auto &s : seen)
    n += s.source == source ? 1 : 0;
  return n;
}
} // namespace

TEST_CASE("ui focus: Tab walks the focusable boxes in drawing order, and Space presses the focused one")
{
  struct root_t
  {
    ui::pressable_t a{ui::focusable}, b, c{ui::focusable};
    int presses_a = 0, presses_c = 0;

    ui::node_t view() const
    {
      return ui::row_t{.children = {ui::box_t{.size = {40, 40}, .events = a}, ui::box_t{.size = {40, 40}, .events = b}, ui::box_t{.size = {40, 40}, .events = c}}};
    }
    ui::behaviour_t behave(ui::scope_t &)
    {
      auto presses = ui::subscribe<ui::press_event_t>(a, c);
      while (auto press = co_await presses)
        ++(press->source == &a ? presses_a : presses_c);
    }
  } root;
  std::vector<seen_t> seen;
  drive(root, seen,
        [&root](vio::event_loop_t &loop, gui::window_t &window) -> vio::task_t<void>
        {
          CHECK_FALSE(root.a.focused());
          key(window, gui::key_t::tab);
          co_await settle(loop);
          CHECK(root.a.focused());
          CHECK(root.a.focus_visible());
          // b is not focusable, so it is skipped.
          key(window, gui::key_t::tab);
          co_await settle(loop);
          CHECK_FALSE(root.a.focused());
          CHECK(root.c.focused());
          key(window, gui::key_t::space);
          co_await settle(loop);
          CHECK(root.presses_c == 1);
          // Back round to a, and a click on c focuses it without a ring.
          key(window, gui::key_t::tab, gui::modifier_t::shift);
          co_await settle(loop);
          CHECK(root.a.focused());
          click(window, {100, 20});
          co_await settle(loop);
          CHECK(root.c.focused());
          CHECK_FALSE(root.c.focus_visible());
          CHECK(root.presses_c == 2);
          CHECK(root.presses_a == 0);
        });
}

TEST_CASE("ui popup: takes no room, is drawn last and kept in the window, and a press outside it dismisses")
{
  struct menu_t
  {
    ui::pressable_t item;
    ui::node_t view() const
    {
      return ui::box_t{.size = {150, 100}, .color = {1, 0, 0, 1}, .events = item};
    }
  };
  struct root_t
  {
    std::shared_ptr<menu_t> menu = std::make_shared<menu_t>();
    ui::pressable_t under, close;
    bool open = true;
    int under_presses = 0, closes = 0;

    ui::node_t view() const
    {
      ui::column_t column{.children = {ui::box_t{.size = {50, 20}}}};
      if (open)
        column.children.push_back(ui::mount(menu).on_top(close));
      column.children.push_back(ui::box_t{.size = {50, 20}, .events = under});
      // Placed at x 300, which leaves the 150-wide popup 100 short of the 400-wide window.
      return ui::at_t{.x = 300, .y = 0, .children = {std::move(column)}};
    }
    ui::behaviour_t behave(ui::scope_t &)
    {
      auto presses = ui::subscribe<ui::press_event_t>(under, close);
      while (auto press = co_await presses)
      {
        if (press->source == &under)
          ++under_presses;
        else
        {
          ++closes;
          open = false;
        }
      }
    }
  } root;
  std::vector<seen_t> seen;
  drive(root, seen,
        [&](vio::event_loop_t &loop, gui::window_t &window) -> vio::task_t<void>
        {
          // The box after the popup sits right under the first: the popup took no room.
          CHECK(rect_of(seen, &root.under) == ui::rect_t{300, 20, 50, 20});
          // Moved left to fit, and drawn after `under`, which comes later in the view.
          CHECK(rect_of(seen, &root.menu->item) == ui::rect_t{250, 20, 150, 100});
          CHECK(rect_of(seen, &root.close) == ui::rect_t{0, 0, 400, 300});
          std::size_t under_at = 0, item_at = 0;
          for (std::size_t i = 0; i < seen.size(); ++i)
          {
            under_at = seen[i].source == &root.under ? i : under_at;
            item_at = seen[i].source == &root.menu->item ? i : item_at;
          }
          CHECK(item_at > under_at);
          // `under` is covered by the popup, so this lands on the popup and nothing happens.
          click(window, {320, 30});
          co_await settle(loop);
          CHECK(root.under_presses == 0);
          CHECK(root.closes == 0);
          // Outside the popup: the backdrop takes it, not what is under it.
          click(window, {20, 250});
          co_await settle(loop);
          CHECK(root.closes == 1);
          CHECK(count_of(seen, &root.close) == 0);
          click(window, {320, 30});
          co_await settle(loop);
          CHECK(root.under_presses == 1);
        });
}

TEST_CASE("ui widgets: a checkbox asks to change and the parent decides; disabled, it asks nothing")
{
  struct root_t
  {
    bool on = false;
    bool enabled = true;
    int changes = 0;
    ui::checkbox_t box;
    ui::node_t view() const
    {
      return ui::mount(box, {.label = "Remember", .checked = on, .enabled = enabled});
    }
    ui::behaviour_t behave(ui::scope_t &)
    {
      auto changes_ = ui::subscribe<ui::toggle_event_t>(box.changed);
      while (auto change = co_await changes_)
      {
        CHECK(change->source == &box);
        on = change->checked;
        // Disabled after the second, from here, so that the parent is rebuilt with it.
        if (++changes == 2)
          enabled = false;
      }
    }
  } root;
  std::vector<seen_t> seen;
  drive(root, seen,
        [&](vio::event_loop_t &loop, gui::window_t &window) -> vio::task_t<void>
        {
          REQUIRE(!seen.empty());
          // The first hit-testable box is the whole checkbox, label and all.
          ui::rect_t whole;
          for (const auto &s : seen)
          {
            if (s.source)
            {
              whole = s.rect;
              break;
            }
          }
          CHECK(whole.width > 60);
          click(window, centre(whole));
          co_await settle(loop);
          CHECK(root.on);
          CHECK(root.box.props.checked);
          key(window, gui::key_t::space);
          co_await settle(loop);
          CHECK_FALSE(root.on);
          CHECK(root.changes == 2);
          CHECK_FALSE(root.enabled);
          click(window, centre(whole));
          key(window, gui::key_t::space);
          co_await settle(loop);
          CHECK(root.changes == 2);
        });
}

TEST_CASE("ui widgets: a combobox opens over what follows, picks by pointer and by keyboard, and closes")
{
  struct root_t
  {
    int selected = -1;
    std::vector<std::size_t> picks;
    ui::combobox_t combo;
    ui::button_t after;
    int after_presses = 0;
    ui::node_t view() const
    {
      return ui::column_t{.gap = 8, .children = {ui::mount(combo, {.options = {"one", "two", "three"}, .selected = selected, .placeholder = "choose"}), ui::mount(after, {.label = "after"})}};
    }
    ui::behaviour_t behave(ui::scope_t &scope)
    {
      auto selections = ui::subscribe<ui::select_event_t>(combo.changed);
      auto presses = ui::subscribe<ui::press_event_t>(after.press);
      auto events = ui::merge(scope, selections, presses);
      while (auto event = co_await events)
      {
        if (event->index() == 0)
        {
          selected = int(std::get<0>(*event).index);
          picks.push_back(std::get<0>(*event).index);
        }
        else
          ++after_presses;
      }
    }
  } root;
  std::vector<seen_t> seen;
  drive(root, seen,
        [&](vio::event_loop_t &loop, gui::window_t &window) -> vio::task_t<void>
        {
          const auto after_rect = rect_of(seen, &root.after.press);
          REQUIRE(after_rect.width > 0);
          // The field is the box that is neither the button nor anything else pressable yet.
          ui::rect_t field;
          for (const auto &s : seen)
          {
            if (s.source && s.source != &root.after.press)
            {
              field = s.rect;
              break;
            }
          }
          REQUIRE(field.width > 0);
          click(window, centre(field));
          co_await settle(loop);
          REQUIRE(root.combo.open());
          // Opening moved nothing.
          CHECK(rect_of(seen, &root.after.press) == after_rect);
          // Three rows under the field, as wide as it, the second over the button.
          std::vector<ui::rect_t> rows;
          bool past_backdrop = false;
          for (const auto &s : seen)
          {
            if (s.rect == ui::rect_t{0, 0, 400, 300} && s.source)
              past_backdrop = true;
            else if (past_backdrop && s.source)
              rows.push_back(s.rect);
          }
          REQUIRE(rows.size() == 3);
          CHECK(rows[0].y >= field.y + field.height);
          // Inside the menu's 1-unit border; the menu itself is as wide as the field, which the
          // placeholder, wider than any option, decides.
          CHECK(rows[0].width == field.width - 2);
          click(window, centre(rows[1]));
          co_await settle(loop);
          CHECK_FALSE(root.combo.open());
          CHECK(root.selected == 1);
          CHECK(root.after_presses == 0);

          // The keyboard: it has focus from the click. Down changes it closed; Enter opens, Down
          // moves, Enter picks; Escape closes without picking.
          key(window, gui::key_t::down);
          co_await settle(loop);
          CHECK(root.selected == 2);
          key(window, gui::key_t::up);
          key(window, gui::key_t::up);
          co_await settle(loop);
          CHECK(root.selected == 0);
          key(window, gui::key_t::enter);
          co_await settle(loop);
          CHECK(root.combo.open());
          key(window, gui::key_t::down);
          key(window, gui::key_t::down);
          key(window, gui::key_t::enter);
          co_await settle(loop);
          CHECK_FALSE(root.combo.open());
          CHECK(root.selected == 2);
          key(window, gui::key_t::enter);
          key(window, gui::key_t::up);
          key(window, gui::key_t::escape);
          co_await settle(loop);
          CHECK_FALSE(root.combo.open());
          CHECK(root.selected == 2);

          // A press outside the open menu closes it and reaches nothing else.
          click(window, centre(field));
          co_await settle(loop);
          REQUIRE(root.combo.open());
          click(window, {390, 290});
          co_await settle(loop);
          CHECK_FALSE(root.combo.open());
          CHECK(root.picks == std::vector<std::size_t>{1, 2, 1, 0, 2});
        });
}
