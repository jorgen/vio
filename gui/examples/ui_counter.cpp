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

// Two counters, a clock and three live plots. Press + to count up and - to count down; the grey bar
// and the label show the count. The clock's bar grows once a second, driven by vio::sleep rather than
// by the ui, which is enough to rebuild its view. Each plot is a component sampling a made-up
// measurement on a timer and showing only the last few seconds of it, scrolling as time passes: a
// filled line, a bar chart of counts per second, and a scatter of readings under their moving
// average. Each component is one struct: state, view, behaviour. Text is drawn in the system font;
// the title's star is an icon from a path.

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <memory>
#include <random>
#include <string>
#include <string_view>
#include <vector>

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
constexpr ui::color_t cyan{0.3f, 0.8f, 0.95f, 1};
constexpr ui::color_t orange{1.0f, 0.6f, 0.2f, 1};

constexpr ui::color_t outline{0.85f, 0.85f, 0.9f, 1};
constexpr ui::color_t ink{0.92f, 0.92f, 0.95f, 1};
constexpr ui::color_t gold{1.0f, 0.8f, 0.25f, 1};
constexpr ui::color_t panel{0.16f, 0.16f, 0.19f, 1};
constexpr ui::color_t rule{0.3f, 0.3f, 0.35f, 1};
constexpr ui::color_t clear{0, 0, 0, 0};

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

// A square button with its label centred on it.
ui::node_t button(const ui::pressable_t &p, std::string label, ui::color_t normal, ui::color_t hover, ui::color_t held)
{
  return ui::box_t{.size = {60, 60}, .color = shade(p, normal, hover, held), .radius = 12, .shadow = lift(p), .events = p, .children = {ui::text_t{.text = std::move(label), .size = 28, .color = ink}}};
}

struct counter_t
{
  int count = 0;
  ui::pressable_t inc;
  ui::pressable_t dec;

  ui::node_t view() const
  {
    return ui::row_t{.gap = 8,
                     .align = ui::align_t::center,
                     .children = {
                       // U+2212 MINUS SIGN: as wide as the plus, where a hyphen is not.
                       button(dec, "\xE2\x88\x92", red, light_red, dark_red),
                       button(inc, "+", green, light_green, dark_green),
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
                     .align = ui::align_t::center,
                     .children = {
                       ui::box_t{.size = {4 + 4 * (seconds % 60), 20}, .color = blue, .radius = 10},
                       ui::text_t{.text = std::to_string(seconds) + " s", .size = 14, .color = ink},
                     }};
  }

  ui::behaviour_t behave(ui::scope_t &scope)
  {
    while (co_await vio::sleep(scope.loop(), 1s, scope.token()))
      ++seconds;
  }
};

// ---------------------------------------------------------------------------------------------
// Plots. Each samples on its own timer and keeps what is still inside its window of time; the view
// maps time to x so that now is the right edge, which is what makes it scroll.

constexpr int plot_width = 380;
constexpr int plot_height = 90;

// Seconds since the program started, which is the time axis of every plot.
double seconds_since(std::chrono::steady_clock::time_point start)
{
  return std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
}

std::string fixed(double value, int decimals)
{
  char text[32];
  std::snprintf(text, sizeof text, "%.*f", decimals, value);
  return text;
}

struct sample_t
{
  double t = 0;
  float value = 0;
};

// The x of time `t` when the right edge is `now` and the plot spans `span` seconds.
float x_of(double t, double now, double span)
{
  return float(plot_width * (1.0 - (now - t) / span));
}

float y_of(double value, double low, double high)
{
  return float(plot_height * (1.0 - (value - low) / (high - low)));
}

// The samples as points, cut at the left edge: the first point inside is joined to the edge by
// interpolating with the one before it, so the line reaches the edge rather than stopping short.
std::vector<ui::vec2_t> points_of(const std::deque<sample_t> &samples, double now, double span, double low, double high)
{
  std::vector<ui::vec2_t> points;
  const double left = now - span;
  for (std::size_t i = 0; i < samples.size(); ++i)
  {
    const auto &s = samples[i];
    if (s.t < left)
      continue;
    if (points.empty() && i > 0)
    {
      const auto &before = samples[i - 1];
      const double f = (left - before.t) / (s.t - before.t);
      points.push_back({0, y_of(before.value + f * (s.value - before.value), low, high)});
    }
    points.push_back({x_of(s.t, now, span), y_of(s.value, low, high)});
  }
  return points;
}

// Horizontal rules at the given values, under everything else in the plot.
std::vector<ui::node_t> rules(std::initializer_list<double> values, double low, double high)
{
  std::vector<ui::node_t> nodes;
  for (double value : values)
  {
    const float y = y_of(value, low, high);
    nodes.push_back(ui::polyline_t{.size = {plot_width, plot_height}, .points = {{0, y}, {float(plot_width), y}}, .width = 1, .color = rule});
  }
  return nodes;
}

// A titled panel around a plot: the title and the current value on one baseline, the plot, and the
// time axis under it, labelled at its ends and its middle.
ui::node_t plot_panel(std::string title, std::string value, ui::color_t accent, std::vector<ui::node_t> layers, int span)
{
  const auto axis_label = [](std::string text, ui::align_t align)
  { return ui::box_t{.size = {plot_width / 3, 14}, .color = clear, .align_x = align, .children = {ui::text_t{.text = std::move(text), .size = 11, .color = grey}}}; };
  return ui::box_t{
    .color = panel,
    .radius = 8,
    .border_width = 1,
    .border_color = rule,
    .padding = {12, 10},
    .align_x = ui::align_t::start,
    .align_y = ui::align_t::start,
    .children = {ui::column_t{
      .gap = 6,
      .children = {
        ui::row_t{.gap = 8, .align = ui::align_t::baseline, .children = {ui::text_t{.text = std::move(title), .size = 13, .color = grey}, ui::text_t{.text = std::move(value), .size = 20, .color = accent}}},
        // The layers overlap at the plot's top left.
        ui::box_t{.size = {plot_width, plot_height}, .color = clear, .align_x = ui::align_t::start, .align_y = ui::align_t::start, .children = std::move(layers)},
        ui::row_t{.children = {axis_label("-" + std::to_string(span) + " s", ui::align_t::start), axis_label("-" + std::to_string(span / 2) + " s", ui::align_t::center), axis_label("now", ui::align_t::end)}},
      }}}};
}

// An intensity read fifty times a second: two slow waves and some noise, drawn as a line over the
// area under it.
struct intensity_plot_t
{
  static constexpr double span = 10;
  std::deque<sample_t> samples;
  double now = 0;

  ui::node_t view() const
  {
    auto layers = rules({0.0, 0.5, 1.0}, 0, 1);
    layers.push_back(ui::polyline_t{.size = {plot_width, plot_height}, .points = points_of(samples, now, span, 0, 1), .width = 1.5f, .color = cyan, .fill = {0.3f, 0.8f, 0.95f, 0.25f}});
    const double last = samples.empty() ? 0 : samples.back().value;
    return plot_panel("intensity", fixed(last, 2), cyan, std::move(layers), int(span));
  }

  ui::behaviour_t behave(ui::scope_t &scope)
  {
    const auto start = std::chrono::steady_clock::now();
    std::mt19937 random(1);
    std::normal_distribution<double> noise(0, 0.03);
    while (co_await vio::sleep(scope.loop(), 20ms, scope.token()))
    {
      now = seconds_since(start);
      const double value = 0.5 + 0.28 * std::sin(now * 1.9) + 0.12 * std::sin(now * 7.3) + noise(random);
      samples.push_back({now, float(std::clamp(value, 0.0, 1.0))});
      // Keep one sample left of the window, for the line to reach the edge.
      while (samples.size() > 2 && samples[1].t < now - span)
        samples.pop_front();
    }
  }
};

// Events counted per second, a bar a second; the bar for the current second grows as it fills.
struct events_plot_t
{
  static constexpr double span = 20;
  static constexpr double high = 12;
  struct bucket_t
  {
    long second = 0;
    int count = 0;
  };
  std::deque<bucket_t> buckets;
  double now = 0;

  ui::node_t view() const
  {
    auto layers = rules({0.0, high / 2, high}, 0, high);
    constexpr int bar_width = plot_width / int(span) - 4;
    for (const auto &bucket : buckets)
    {
      // A bar is drawn over the second before the one it counts, so the bar still filling ends at
      // the right edge rather than past it. The one leaving on the left is cut at the edge.
      const float x = x_of(double(bucket.second - 1), now, span) + 2;
      const float left = std::max(x, 0.0f);
      const int width = int(std::lround(float(bar_width) - (left - x)));
      const float y = y_of(std::min(double(bucket.count), high), 0, high);
      if (width <= 0 || bucket.count == 0)
        continue;
      layers.push_back(ui::at_t{.x = left, .y = y, .children = {ui::box_t{.size = {width, plot_height - int(std::lround(y))}, .color = orange, .radius = 2}}});
    }
    const int last = buckets.empty() ? 0 : buckets.back().count;
    return plot_panel("events / s", std::to_string(last), orange, std::move(layers), int(span));
  }

  ui::behaviour_t behave(ui::scope_t &scope)
  {
    const auto start = std::chrono::steady_clock::now();
    std::mt19937 random(2);
    std::uniform_real_distribution<double> uniform(0, 1);
    while (co_await vio::sleep(scope.loop(), 20ms, scope.token()))
    {
      now = seconds_since(start);
      const auto second = long(std::floor(now));
      if (buckets.empty() || buckets.back().second != second)
        buckets.push_back({second, 0});
      // A rate that wanders between about 1 and 9 events a second.
      const double rate = 5 + 4 * std::sin(now * 0.4);
      if (uniform(random) < rate * 0.02)
        ++buckets.back().count;
      while (!buckets.empty() && double(buckets.front().second) < now - span)
        buckets.pop_front();
    }
  }
};

// A temperature read five times a second, noisily: the readings as a scatter, their two-second
// moving average as a line through them.
struct temperature_plot_t
{
  static constexpr double span = 30;
  static constexpr double low = 18;
  static constexpr double high = 24;
  std::deque<sample_t> readings;
  std::deque<sample_t> average;
  double now = 0;

  ui::node_t view() const
  {
    auto layers = rules({low, (low + high) / 2, high}, low, high);
    std::vector<ui::vec2_t> dots;
    for (const auto &reading : readings)
    {
      if (reading.t >= now - span)
        dots.push_back({x_of(reading.t, now, span), y_of(reading.value, low, high)});
    }
    layers.push_back(ui::polyline_t{.size = {plot_width, plot_height}, .points = std::move(dots), .width = 0, .color = {1.0f, 0.6f, 0.2f, 0.8f}, .marker = 4});
    layers.push_back(ui::polyline_t{.size = {plot_width, plot_height}, .points = points_of(average, now, span, low, high), .width = 2, .color = ink});
    const double last = average.empty() ? 0 : average.back().value;
    return plot_panel("temperature \xC2\xB0"
                      "C",
                      fixed(last, 1), orange, std::move(layers), int(span));
  }

  ui::behaviour_t behave(ui::scope_t &scope)
  {
    const auto start = std::chrono::steady_clock::now();
    std::mt19937 random(3);
    std::normal_distribution<double> noise(0, 0.45);
    while (co_await vio::sleep(scope.loop(), 200ms, scope.token()))
    {
      now = seconds_since(start);
      const double value = 21 + 1.6 * std::sin(now * 0.15) + noise(random);
      readings.push_back({now, float(value)});
      double sum = 0;
      int count = 0;
      for (auto it = readings.rbegin(); it != readings.rend() && it->t >= now - 2; ++it, ++count)
        sum += it->value;
      average.push_back({now, float(sum / count)});
      while (readings.size() > 2 && readings[1].t < now - span)
        readings.pop_front();
      while (average.size() > 2 && average[1].t < now - span)
        average.pop_front();
    }
  }
};

struct app_t
{
  counter_t top;
  counter_t bottom;
  clock_bar_t clock;
  intensity_plot_t intensity;
  events_plot_t events;
  temperature_plot_t temperature;
  std::shared_ptr<const ui::path_t> icon = star();

  ui::node_t view() const
  {
    return ui::column_t{
      .gap = 16,
      .padding = 16,
      .children =
        {
          ui::row_t{.gap = 8, .align = ui::align_t::center, .children = {ui::icon_t{.path = icon, .size = 24, .color = gold}, ui::text_t{.text = "vio ui: counters and plots", .size = 20, .color = ink}}},
          ui::row_t{.gap = 32,
                    .children =
                      {
                        ui::column_t{.gap = 16,
                                     .children =
                                       {
                                         ui::mount(top),
                                         ui::mount(bottom),
                                         ui::mount(clock),
                                         // Shaped by HarfBuzz: joined Arabic letters, right to left. One direction per text node
                                         // (G40). The two sizes share a baseline.
                                         ui::row_t{.gap = 8,
                                                   .align = ui::align_t::baseline,
                                                   .children = {ui::text_t{.text = "Arabic:", .size = 13, .color = grey},
                                                                ui::text_t{.text = "\xD9\x85\xD8\xB1\xD8\xAD\xD8\xA8\xD8\xA7\x20\xD8\xA8\xD8\xA7\xD9\x84\xD8\xB9\xD8\xA7\xD9\x84\xD9\x85", .size = 20, .color = ink}}},
                                       }},
                        ui::column_t{.gap = 12, .children = {ui::mount(intensity), ui::mount(events), ui::mount(temperature)}},
                      }},
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
      auto window = gui::window_t::create(*display, {.title = "vio ui: counters and plots", .size = {1100, 920}});
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
