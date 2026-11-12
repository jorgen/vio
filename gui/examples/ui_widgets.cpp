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

// The widgets (G46): a settings form of buttons, checkboxes and comboboxes. Every value lives here
// in the form and goes down to its widget as props; every change comes up as an event, which one
// behaviour applies. Tab moves between them, Space presses, the arrows work a combobox.

#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include <vio/event_loop.h>
#include <vio/gui/gui.h>
#include <vio/gui/ui/ui.h>
#include <vio/gui/ui/widgets.h>
#include <vio/operation/sleep.h>
#include <vio/run.h>

namespace gui = vio::gui;
namespace ui = vio::gui::ui;
using namespace std::chrono_literals;

namespace
{
constexpr ui::color_t ink{0.92f, 0.92f, 0.95f, 1};
constexpr ui::color_t grey{0.6f, 0.6f, 0.65f, 1};
constexpr ui::color_t panel{0.16f, 0.16f, 0.19f, 1};

const std::vector<std::string> qualities{"Low", "Medium", "High", "Ultra"};
const std::vector<std::string> fruits{"Apple", "Banana", "Cherry", "Dragon fruit", "Elderberry", "Fig", "Grape"};
const std::vector<std::string> themes{"Follow the system", "Light", "Dark"};

struct form_t
{
  // The values.
  bool notify = true;
  bool autosave = false;
  bool advanced = false;
  bool beta = false;
  int quality = 2;
  int fruit = -1;
  int theme = 0;
  std::string status = "Nothing changed yet.";

  // The widgets that show them.
  ui::checkbox_t notify_box, autosave_box, advanced_box, beta_box;
  ui::combobox_t quality_box, fruit_box, theme_box;
  ui::button_t save, reset, remove;

  static ui::node_t label(const char *text)
  {
    return ui::box_t{.size = {120, 0}, .color = {0, 0, 0, 0}, .align_x = ui::align_t::start, .children = {ui::text_t{.text = text, .size = 14, .color = grey}}};
  }
  static ui::node_t line(const char *text, ui::node_t control)
  {
    return ui::row_t{.gap = 12, .align = ui::align_t::center, .children = {label(text), std::move(control)}};
  }

  ui::node_t view() const
  {
    return ui::column_t{.gap = 16,
                        .padding = 24,
                        .children =
                          {
                            ui::text_t{.text = "vio ui: widgets", .size = 22, .color = ink},
                            ui::box_t{.color = panel,
                                      .radius = 10,
                                      .padding = 20,
                                      .align_x = ui::align_t::start,
                                      .children = {ui::column_t{.gap = 14,
                                                                .children =
                                                                  {
                                                                    ui::mount(notify_box, {.label = "Notify me when a render finishes", .checked = notify}),
                                                                    ui::mount(autosave_box, {.label = "Save automatically", .checked = autosave}),
                                                                    ui::mount(advanced_box, {.label = "Show advanced settings", .checked = advanced}),
                                                                    ui::mount(beta_box, {.label = "Beta features (needs advanced)", .checked = beta, .enabled = advanced}),
                                                                    line("Quality", ui::mount(quality_box, {.options = qualities, .selected = quality})),
                                                                    line("Favourite fruit", ui::mount(fruit_box, {.options = fruits, .selected = fruit, .placeholder = "Pick one"})),
                                                                    line("Theme", ui::mount(theme_box, {.options = themes, .selected = theme, .enabled = advanced})),
                                                                  }}}},
                            ui::row_t{.gap = 10, .children = {ui::mount(save, {.label = "Save", .primary = true}), ui::mount(reset, {.label = "Reset"}), ui::mount(remove, {.label = "Delete", .enabled = advanced})}},
                            ui::text_t{.text = status, .size = 14, .color = grey},
                          }};
  }

  ui::behaviour_t behave(ui::scope_t &scope)
  {
    auto toggles = ui::subscribe<ui::toggle_event_t>(notify_box.changed, autosave_box.changed, advanced_box.changed, beta_box.changed);
    auto selections = ui::subscribe<ui::select_event_t>(quality_box.changed, fruit_box.changed, theme_box.changed);
    auto presses = ui::subscribe<ui::press_event_t>(save.press, reset.press, remove.press);
    auto events = ui::merge(scope, toggles, selections, presses);
    while (auto event = co_await events)
    {
      if (event->index() == 0)
      {
        const auto &toggle = std::get<0>(*event);
        if (toggle.source == &notify_box)
          notify = toggle.checked;
        else if (toggle.source == &autosave_box)
          autosave = toggle.checked;
        else if (toggle.source == &advanced_box)
          advanced = toggle.checked;
        else
          beta = toggle.checked;
        status = std::string(toggle.checked ? "Ticked " : "Unticked ") + toggle.source->props.label + ".";
      }
      else if (event->index() == 1)
      {
        const auto &selection = std::get<1>(*event);
        if (selection.source == &quality_box)
          quality = int(selection.index);
        else if (selection.source == &fruit_box)
          fruit = int(selection.index);
        else
          theme = int(selection.index);
        status = "Chose " + selection.source->props.options[selection.index] + ".";
      }
      else
      {
        const auto *source = std::get<2>(*event).source;
        if (source == &save.press)
          status = "Saved: quality " + qualities[std::size_t(quality)] + (notify ? ", notifying" : "") + (autosave ? ", autosaving" : "") + ".";
        else if (source == &reset.press)
        {
          notify = true;
          autosave = false;
          advanced = false;
          beta = false;
          quality = 2;
          fruit = -1;
          theme = 0;
          status = "Reset to the defaults.";
        }
        else
          status = "Deleted nothing; this is a demo.";
      }
    }
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
      auto window = gui::window_t::create(*display, {.title = "vio ui: widgets", .size = {720, 820}});
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
      co_await ui::run(*window, form_t{});
      co_await std::move(closing);
      co_return 0;
    });
}
