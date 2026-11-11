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

// Two counters and a clock. Press the green square to count up and the red one to count down; the
// grey bar and the label show the count. The clock's bar grows once a second, driven by vio::sleep
// rather than by the ui, which is enough to rebuild its view. Each component is one struct: state,
// view, behaviour. Text is drawn in the system font; the title's star is an icon from a path.

#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <memory>
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
constexpr ui::color_t red{0.85f, 0.25f, 0.25f, 1};
constexpr ui::color_t dark_red{0.55f, 0.12f, 0.12f, 1};
constexpr ui::color_t green{0.25f, 0.75f, 0.35f, 1};
constexpr ui::color_t dark_green{0.12f, 0.45f, 0.2f, 1};
constexpr ui::color_t light_green{0.4f, 0.9f, 0.5f, 1};
constexpr ui::color_t light_red{1.0f, 0.45f, 0.45f, 1};
constexpr ui::color_t grey{0.6f, 0.6f, 0.65f, 1};
constexpr ui::color_t blue{0.3f, 0.5f, 0.9f, 1};

constexpr ui::color_t outline{0.85f, 0.85f, 0.9f, 1};
constexpr ui::color_t ink{0.92f, 0.92f, 0.95f, 1};
constexpr ui::color_t gold{1.0f, 0.8f, 0.25f, 1};

// A five-pointed star in the unit square.
std::shared_ptr<const ui::path_t> star()
{
  auto path = std::make_shared<ui::path_t>();
  for (int i = 0; i < 10; ++i)
  {
    const float angle = -1.5707963f + float(i) * 0.6283185f;
    const float radius = i % 2 ? 0.2f : 0.5f;
    const float x = 0.5f + radius * std::cos(angle);
    const float y = 0.53f + radius * std::sin(angle);
    if (i == 0)
      path->move_to(x, y);
    else
      path->line_to(x, y);
  }
  path->close();
  return path;
}

ui::color_t shade(const ui::pressable_t &p, ui::color_t normal, ui::color_t hover, ui::color_t held)
{
  return p.held() ? held : p.hovered() ? hover : normal;
}

// A button sits on a shadow that tightens as it is pressed.
ui::shadow_t lift(const ui::pressable_t &p)
{
  const float height = p.held() ? 1.0f : p.hovered() ? 5.0f : 3.0f;
  return {.x = 0, .y = height, .blur = height * 1.5f, .color = {0, 0, 0, 0.6f}};
}

struct counter_t
{
  int count = 0;
  ui::pressable_t inc;
  ui::pressable_t dec;

  ui::node_t view() const
  {
    return ui::row_t{.gap = 8,
                     .children = {
                       ui::box_t{.size = {60, 60}, .color = shade(dec, red, light_red, dark_red), .radius = 12, .shadow = lift(dec), .events = dec},
                       ui::box_t{.size = {60, 60}, .color = shade(inc, green, light_green, dark_green), .radius = 12, .shadow = lift(inc), .events = inc},
                       ui::box_t{.size = {4 + 16 * std::max(count, 0), 60}, .color = grey, .radius = 6, .border_width = 2, .border_color = outline},
                       ui::text_t{.text = "count: " + std::to_string(count), .size = 16, .color = ink},
                     }};
  }

  ui::behaviour_t behave(ui::scope_t &)
  {
    auto presses = ui::subscribe<ui::press_event_t>(inc, dec);
    while (auto press = co_await presses)
      count += press->source == &inc ? 1 : -1;
  }
};

struct clock_bar_t
{
  int seconds = 0;

  ui::node_t view() const
  {
    return ui::row_t{.gap = 8,
                     .children = {
                       ui::box_t{.size = {4 + 8 * (seconds % 60), 20}, .color = blue, .radius = 10},
                       ui::text_t{.text = std::to_string(seconds) + " s", .size = 14, .color = ink},
                     }};
  }

  ui::behaviour_t behave(ui::scope_t &scope)
  {
    while (co_await vio::sleep(scope.loop(), 1s, scope.token()))
      ++seconds;
  }
};

struct app_t
{
  counter_t top;
  counter_t bottom;
  clock_bar_t clock;
  std::shared_ptr<const ui::path_t> icon = star();

  ui::node_t view() const
  {
    return ui::column_t{.gap = 16,
                        .children = {
                          ui::row_t{.gap = 8, .children = {ui::icon_t{.path = icon, .size = 24, .color = gold}, ui::text_t{.text = "vio ui: counters", .size = 20, .color = ink}}},
                          ui::mount(top),
                          ui::mount(bottom),
                          ui::mount(clock),
                          // Shaped by HarfBuzz: joined Arabic letters, right to left. One direction per text node (G40).
                          ui::row_t{.gap = 8,
                                    .children = {ui::text_t{.text = "Arabic:", .size = 16, .color = grey},
                                                 ui::text_t{.text = "\xD9\x85\xD8\xB1\xD8\xAD\xD8\xA8\xD8\xA7\x20\xD8\xA8\xD8\xA7\xD9\x84\xD8\xB9\xD8\xA7\xD9\x84\xD9\x85", .size = 18, .color = ink}}},
                        }};
  }
};
} // namespace

int main(int argc, char **argv)
{
  const auto limit = std::chrono::milliseconds(argc > 1 ? std::atoi(argv[1]) : 0);
  return vio::run([limit](vio::event_loop_t &loop) -> vio::task_t<int> {
    auto display = gui::display_t::open(loop);
    if (!display)
    {
      std::fprintf(stderr, "no display: %s\n", display.error().msg.c_str());
      co_return 1;
    }
    {
      auto window = gui::window_t::create(*display, {.title = "vio ui: counters", .size = {640, 440}});
      if (!window)
        co_return 1;
      auto closing = [](gui::window_t &window, std::chrono::milliseconds limit) -> vio::task_t<void> {
        auto requests = window.subscribe<gui::close_request_t>();
        if (limit.count() > 0)
        {
          // For CI: close after the given time, whatever happens.
          auto &loop = *window.impl()->display.loop;
          (void)co_await vio::sleep(loop, limit);
        }
        else
        {
          co_await requests;
        }
        window.close();
      }(*window, limit);
      ui::run_config_t config;
      config.on_renderer = [](std::string_view what) { std::fprintf(stderr, "renderer: %.*s\n", int(what.size()), what.data()); };
      co_await ui::run(*window, app_t{}, std::move(config));
      co_await std::move(closing);
    }
    co_return 0;
  });
}
