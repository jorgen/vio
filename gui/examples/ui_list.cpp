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

// A list of live rows (gui/PLAN.md, phase 7). "add" puts a row at the top; each row counts its own
// presses, "work" runs a job in a child scope that the row's "x" cancels along with everything else
// the row is doing. Pressing a row's label selects it, and the selection reaches the row as props.
// Rows stretch to the window's width and a spacer pushes their buttons to the right edge.

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>

#include <vio/event_loop.h>
#include <vio/gui/gui.h>
#include <vio/gui/ui/ui.h>
#include <vio/operation/sleep.h>
#include <vio/run.h>

namespace gui = vio::gui;
namespace ui = vio::gui::ui;
using namespace std::chrono_literals;

namespace
{
constexpr ui::color_t ink{0.92f, 0.92f, 0.95f, 1};
constexpr ui::color_t grey{0.6f, 0.6f, 0.65f, 1};
constexpr ui::color_t row_colour{0.18f, 0.18f, 0.21f, 1};
constexpr ui::color_t selected_colour{0.22f, 0.3f, 0.45f, 1};
constexpr ui::color_t button_colour{0.3f, 0.3f, 0.36f, 1};
constexpr ui::color_t hover_colour{0.4f, 0.4f, 0.48f, 1};
constexpr ui::color_t remove_colour{0.6f, 0.22f, 0.22f, 1};
constexpr ui::color_t accent{0.3f, 0.5f, 0.9f, 1};

ui::node_t button(const ui::pressable_t &p, std::string label, ui::color_t colour = button_colour, int width = 32)
{
  return ui::box_t{.size = {width, 28}, .color = p.hovered() ? hover_colour : colour, .radius = 6, .events = p, .children = {ui::text_t{.text = std::move(label), .size = 15, .color = ink, .tight = true}}};
}

struct row_t
{
  struct props_t
  {
    bool selected = false;
    friend bool operator==(const props_t &, const props_t &) = default;
  };
  props_t props;

  int number = 0;
  int count = 0;
  std::string status;
  ui::pressable_t select, inc, dec, work, remove;

  ui::node_t view() const
  {
    return ui::box_t{.color = props.selected ? selected_colour : row_colour,
                     .radius = 8,
                     .padding = {12, 8},
                     .align_x = ui::align_t::stretch,
                     .children = {ui::row_t{
                       .gap = 8,
                       .align = ui::align_t::center,
                       .children = {
                         ui::box_t{.size = {90, 28}, .color = {0, 0, 0, 0}, .events = select, .align_x = ui::align_t::start, .children = {ui::text_t{.text = "row " + std::to_string(number), .size = 16, .color = ink}}},
                         ui::text_t{.text = "count " + std::to_string(count), .size = 14, .color = grey},
                         ui::text_t{.text = status, .size = 14, .color = accent},
                         ui::spacer_t{},
                         button(dec, "\xE2\x88\x92"),
                         button(inc, "+"),
                         button(work, "work", button_colour, 56),
                         button(remove, "\xC3\x97", remove_colour),
                       }}}};
  }

  // A job: three steps of made-up work, reporting as it goes. Cancelled, it stops at its next
  // step; its scope's cancellation reaches the sleep, which resolves at once.
  static ui::job_t<int> crunch(ui::scope_t &scope, row_t &row)
  {
    int total = 0;
    for (int step = 1; step <= 3; ++step)
    {
      row.status = "working " + std::to_string(step) + "/3";
      if (!co_await vio::sleep(scope.loop(), 400ms, scope.token()))
        co_return total;
      total += step * row.number;
    }
    co_return total;
  }

  ui::behaviour_t behave(ui::scope_t &scope)
  {
    auto presses = ui::subscribe<ui::press_event_t>(inc, dec, work);
    while (auto press = co_await presses)
    {
      if (press->source == &inc)
        ++count;
      else if (press->source == &dec)
        --count;
      else
      {
        // Work runs in a child scope, so the row stays responsive and the job ends with the row.
        ui::scope_t sub(scope);
        auto result = sub.spawn(crunch(sub, *this));
        auto value = co_await result;
        co_await sub.join();
        status = value ? "done: " + std::to_string(*value) : "cancelled";
      }
    }
  }
};

struct app_t
{
  ui::list_t<row_t> rows;
  ui::pressable_t add;
  int next = 1;
  const row_t *selected = nullptr;

  ui::node_t view() const
  {
    std::vector<ui::node_t> children;
    for (std::size_t i = 0; i < rows.size(); ++i)
      children.push_back(rows.mount(i, row_t::props_t{.selected = &rows[i] == selected}));
    return ui::column_t{.gap = 12,
                        .align = ui::align_t::stretch,
                        .padding = 16,
                        .children = {
                          ui::row_t{.gap = 12,
                                    .align = ui::align_t::center,
                                    .children = {ui::text_t{.text = "vio ui: a list", .size = 20, .color = ink}, ui::spacer_t{}, ui::text_t{.text = std::to_string(rows.size()) + " rows", .size = 14, .color = grey},
                                                 button(add, "add", accent, 56)}},
                          ui::column_t{.gap = 6, .align = ui::align_t::stretch, .children = std::move(children)},
                        }};
  }

  // The list's own events: add, and from every row, select and remove. A row's sources are
  // subscribed when it is added; erasing the row ends that subscription with the row's sources.
  ui::behaviour_t behave(ui::scope_t &scope)
  {
    for (int i = 0; i < 3; ++i)
      watch(scope, rows.emplace_back(row_t{.number = next++}));
    auto adds = ui::subscribe<ui::press_event_t>(add);
    while (co_await adds)
      watch(scope, rows.emplace(0, row_t{.number = next++}));
  }

  void watch(ui::scope_t &scope, row_t &row)
  {
    scope.spawn(watch_row(scope, row));
  }

  ui::behaviour_t watch_row(ui::scope_t &, row_t &row)
  {
    auto presses = ui::subscribe<ui::press_event_t>(row.select, row.remove);
    while (auto press = co_await presses)
    {
      if (press->source == &row.select)
      {
        selected = &row;
        continue;
      }
      if (selected == &row)
        selected = nullptr;
      // The subscription is over the row's own sources; leaving the loop before erasing keeps this
      // frame from reading a row that is gone.
      break;
    }
    rows.erase(row);
  }
};
} // namespace

int main(int argc, char **argv)
{
  const auto limit = std::chrono::milliseconds(argc > 1 ? std::atoi(argv[1]) : 0);
  return vio::run(
    [limit](vio::event_loop_t &loop) -> vio::task_t<int>
    {
      auto display = gui::display_t::open(loop);
      if (!display)
      {
        std::fprintf(stderr, "no display: %s\n", display.error().msg.c_str());
        co_return 1;
      }
      {
        auto window = gui::window_t::create(*display, {.title = "vio ui: a list", .size = {900, 640}});
        if (!window)
          co_return 1;
        auto closing = [](gui::window_t &window, std::chrono::milliseconds limit) -> vio::task_t<void>
        {
          auto requests = window.subscribe<gui::close_request_t>();
          if (limit.count() > 0)
            (void)co_await vio::sleep(*window.impl()->display.loop, limit);
          else
            co_await requests;
          window.close();
        }(*window, limit);
        co_await ui::run(*window, app_t{});
        co_await std::move(closing);
      }
      co_return 0;
    });
}
