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

// The display list, its chunks, and the Vulkan pipeline that draws it (gui/PLAN.md, "Rendering").

#include <doctest/doctest.h>

#include <array>
#include <chrono>
#include <cmath>
#include <cstdlib>
#include <string>
#include <vector>

#include <vio/event_loop.h>
#include <vio/gui/gui.h>
#include <vio/gui/ui/ui.h>
#include <vio/operation/sleep.h>
#include <vio/task.h>

#include "gui_test_helpers.h"
#include "ui_renderer.h"

using namespace std::chrono_literals;
namespace gui = vio::gui;
namespace ui = vio::gui::ui;

namespace
{
constexpr ui::color_t red{1, 0, 0, 1};
constexpr ui::color_t green{0, 1, 0, 1};
constexpr ui::color_t blue{0, 0, 1, 1};
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
  // Off every box again, so hovering is not a change of its own.
  window.impl()->on_input(gui::pointer_move_event_t{{900, 900}});
}

vio::task_t<void> settle(vio::event_loop_t &loop)
{
  (void)co_await vio::sleep(loop, 40ms);
}

// A copy of what one frame's display list held, since the spans die with the frame.
struct snapshot_t
{
  std::vector<ui::prim_t> prims;
  std::vector<ui::run_t> runs;
  int frames = 0;

  void take(const ui::display_list_t &list)
  {
    prims.assign(list.prims.begin(), list.prims.end());
    runs.assign(list.runs.begin(), list.runs.end());
    ++frames;
  }

  // The prims of one run, in window coordinates.
  [[nodiscard]] std::vector<ui::prim_t> placed(std::size_t run) const
  {
    std::vector<ui::prim_t> out;
    const auto &r = runs[run];
    for (std::uint32_t i = r.first; i < r.first + r.count; ++i)
    {
      auto prim = prims[i];
      prim.x += r.x;
      prim.y += r.y;
      out.push_back(prim);
    }
    return out;
  }
};

// Three boxes, the last one as wide as the count, and one that grows the count.
struct grower_t
{
  int count = 0;
  ui::pressable_t inc;
  mutable int views = 0;

  ui::node_t view() const
  {
    ++views;
    return ui::row_t{.gap = 4,
                     .children = {
                       ui::box_t{.size = {20, 20}, .color = green, .events = inc},
                       ui::box_t{.size = {10 + 10 * count, 20}, .color = grey},
                     }};
  }

  ui::behaviour_t behave(ui::scope_t &)
  {
    auto presses = ui::subscribe<ui::press_event_t>(inc);
    while (co_await presses)
      ++count;
  }
};

// Six boxes: past a threshold of four, so it holds a chunk of its own.
struct grid_t
{
  mutable int views = 0;

  ui::node_t view() const
  {
    ++views;
    std::vector<ui::node_t> boxes;
    for (int i = 0; i < 6; ++i)
      boxes.push_back(ui::box_t{.size = {8, 8}, .color = blue});
    return ui::row_t{.gap = 2, .children = std::move(boxes)};
  }
};

struct page_t
{
  grower_t grower;
  grid_t grid;

  ui::node_t view() const
  {
    return ui::row_t{.gap = 10, .children = {ui::mount(grower), ui::mount(grid)}};
  }
};
} // namespace

TEST_CASE("ui render: boxes become prims in painter's order, with a box's shadow first")
{
  struct shadowed_t
  {
    ui::node_t view() const
    {
      return ui::column_t{.gap = 5,
                          .children = {
                            ui::box_t{.size = {30, 20}, .color = red, .radius = 4, .border_width = 2, .border_color = grey},
                            ui::box_t{.size = {40, 10}, .color = green, .shadow = {.x = 1, .y = 2, .blur = 3, .color = {0, 0, 0, 0.5f}}},
                          }};
    }
  };
  vio::event_loop_t loop;
  snapshot_t seen;
  std::string renderer;
  run_gui_test(loop,
               [](vio::event_loop_t &loop, snapshot_t &seen, std::string &renderer) -> vio::task_t<void>
               {
                 auto display = open_null(loop);
                 {
                   auto window = gui::window_t::create(display, {.size = {200, 100}});
                   shadowed_t root;
                   ui::run_config_t config;
                   config.on_display_list = [&seen](const ui::display_list_t &list) { seen.take(list); };
                   config.on_renderer = [&renderer](std::string_view what) { renderer = what; };
                   auto running = ui::run(*window, root, std::move(config));
                   co_await settle(loop);
                   window->close();
                   co_await std::move(running);
                 }
                 loop.stop();
               }(loop, seen, renderer));
  // The null backend has no surface, so nothing tries to load a driver for it.
  CHECK(renderer == "none: the window has no native surface");
  REQUIRE(seen.runs.size() == 1);
  auto prims = seen.placed(0);
  REQUIRE(prims.size() == 3);
  CHECK(prims[0].width == 30);
  CHECK(prims[0].radii[2] == 4);
  CHECK(prims[0].border_width == 2);
  CHECK(prims[0].fill == red);
  // The shadow: the second box's shape, moved and blurred, drawn before it.
  CHECK(prims[1].blur == 3);
  CHECK(prims[1].x == 1);
  CHECK(prims[1].y == 25 + 2);
  CHECK(prims[2].fill == green);
  CHECK(prims[2].y == 25);
}

TEST_CASE("ui render: a large subtree holds its own chunk, and moving it changes only its origin")
{
  struct seen_t
  {
    snapshot_t before;
    snapshot_t after;
    int grid_views = 0;
    int grower_views = 0;
  } seen;
  vio::event_loop_t loop;
  run_gui_test(loop,
               [](vio::event_loop_t &loop, seen_t &seen) -> vio::task_t<void>
               {
                 auto display = open_null(loop);
                 {
                   auto window = gui::window_t::create(display, {.size = {400, 100}});
                   page_t page;
                   snapshot_t latest;
                   ui::run_config_t config;
                   config.chunk_threshold = 4;
                   config.on_display_list = [&latest](const ui::display_list_t &list) { latest.take(list); };
                   auto running = ui::run(*window, page, std::move(config));
                   co_await settle(loop);
                   seen.before = latest;
                   const int grid = page.grid.views;
                   const int grower = page.grower.views;
                   click(*window, {10, 10});
                   co_await settle(loop);
                   seen.after = latest;
                   seen.grid_views = page.grid.views - grid;
                   seen.grower_views = page.grower.views - grower;
                   window->close();
                   co_await std::move(running);
                 }
                 loop.stop();
               }(loop, seen));
  // The grower's two boxes are inlined into the root's chunk; the grid's six are a run of their own.
  REQUIRE(seen.before.runs.size() == 2);
  CHECK(seen.before.runs[0].count == 2);
  CHECK(seen.before.runs[1].count == 6);
  CHECK(seen.before.runs[1].x == 20 + 4 + 10 + 10);
  REQUIRE(seen.after.runs.size() == 2);
  CHECK(seen.grower_views >= 1);
  CHECK(seen.grid_views == 0);
  // The grower's second box grew by 10, so the grid moved by 10 -- and only its origin says so.
  CHECK(seen.after.runs[1].x == seen.before.runs[1].x + 10);
  for (std::uint32_t i = 0; i < 6; ++i)
  {
    const auto &a = seen.before.prims[seen.before.runs[1].first + i];
    const auto &b = seen.after.prims[seen.after.runs[1].first + i];
    CHECK(a.x == b.x);
    CHECK(a.y == b.y);
  }
}

namespace
{
// A strip of `n` boxes after two buttons, behind a background box of its parent's.
struct strip_t
{
  int n = 4;
  ui::pressable_t less;
  ui::pressable_t more;

  ui::node_t view() const
  {
    std::vector<ui::node_t> boxes{ui::box_t{.size = {10, 10}, .color = red, .events = less}, ui::box_t{.size = {10, 10}, .color = green, .events = more}};
    for (int i = 0; i < n; ++i)
      boxes.push_back(ui::box_t{.size = {4, 10}, .color = grey});
    return ui::row_t{.gap = 2, .children = std::move(boxes)};
  }

  ui::behaviour_t behave(ui::scope_t &)
  {
    auto presses = ui::subscribe<ui::press_event_t>(less, more);
    while (auto press = co_await presses)
      n += press->source == &more ? 1 : -1;
  }
};

struct backed_t
{
  strip_t strip;

  ui::node_t view() const
  {
    return ui::column_t{.children = {ui::box_t{.size = {100, 4}, .color = blue}, ui::mount(strip)}};
  }
};
} // namespace

TEST_CASE("ui render: a chunk is given up only below half the threshold")
{
  // Threshold 6: the strip holds a chunk from 6 prims and keeps it down to 3.
  std::vector<std::size_t> runs;
  vio::event_loop_t loop;
  run_gui_test(loop,
               [](vio::event_loop_t &loop, std::vector<std::size_t> &runs) -> vio::task_t<void>
               {
                 auto display = open_null(loop);
                 {
                   auto window = gui::window_t::create(display, {.size = {400, 100}});
                   backed_t root;
                   std::size_t latest = 0;
                   ui::run_config_t config;
                   config.chunk_threshold = 6;
                   config.on_display_list = [&latest](const ui::display_list_t &list) { latest = list.runs.size(); };
                   auto running = ui::run(*window, root, std::move(config));
                   co_await settle(loop);
                   runs.push_back(latest); // n = 4: 6 prims, its own chunk
                   const gui::point_t less{5, 9};
                   const gui::point_t more{17, 9};
                   click(*window, less);
                   click(*window, less);
                   co_await settle(loop);
                   runs.push_back(latest); // n = 2: 4 prims, kept
                   click(*window, less);
                   click(*window, less);
                   co_await settle(loop);
                   runs.push_back(latest); // n = 0: 2 prims, given up
                   click(*window, more);
                   click(*window, more);
                   click(*window, more);
                   co_await settle(loop);
                   runs.push_back(latest); // n = 3: 5 prims, not yet taken back
                   window->close();
                   co_await std::move(running);
                 }
                 loop.stop();
               }(loop, runs));
  CHECK(runs == std::vector<std::size_t>{2, 2, 1, 1});
}

TEST_CASE("ui render: an expose repaints without running a view")
{
  struct seen_t
  {
    int frames = 0;
    int views = 0;
  } seen;
  vio::event_loop_t loop;
  run_gui_test(loop,
               [](vio::event_loop_t &loop, seen_t &seen) -> vio::task_t<void>
               {
                 auto display = open_null(loop);
                 {
                   auto window = gui::window_t::create(display, {.size = {400, 100}});
                   grid_t grid;
                   int frames = 0;
                   auto running = ui::run(*window, grid, {.on_display_list = [&frames](const ui::display_list_t &) { ++frames; }});
                   co_await settle(loop);
                   const int frames_before = frames;
                   const int views_before = grid.views;
                   window->minimize();
                   window->restore();
                   co_await settle(loop);
                   seen.frames = frames - frames_before;
                   seen.views = grid.views - views_before;
                   window->close();
                   co_await std::move(running);
                 }
                 loop.stop();
               }(loop, seen));
  CHECK(seen.frames >= 1);
  CHECK(seen.views == 0);
}

// ---- the pipeline itself, offscreen. Skipped, with the reason printed, where no Vulkan device is.

namespace
{
std::array<int, 4> pixel(const ui::detail::offscreen_image_t &image, int x, int y)
{
  const auto *p = &image.rgba[(std::size_t(y) * image.extent.width + x) * 4];
  return {p[0], p[1], p[2], p[3]};
}

bool matches(std::array<int, 4> a, std::array<int, 4> b, int tolerance = 2)
{
  for (int i = 0; i < 4; ++i)
  {
    if (std::abs(a[i] - b[i]) > tolerance)
      return false;
  }
  return true;
}
} // namespace

// Named vulkan: so the Linux script runs it in the pass without leak detection (G18).
TEST_CASE("vulkan: the UI pipeline draws rounded corners, borders and shadows")
{
  // A 100x100 target at scale 2: 50x50 logical units.
  std::vector<ui::prim_t> prims(3);
  // A red box with a 10-unit radius at (5, 5), 30x30.
  prims[0].x = 5;
  prims[0].y = 5;
  prims[0].width = 30;
  prims[0].height = 30;
  for (auto &r : prims[0].radii)
    r = 10;
  prims[0].fill = red;
  // A shadow, then the green box it belongs to, in the second run at origin (38, 0).
  prims[1].x = 0;
  prims[1].y = 20;
  prims[1].width = 10;
  prims[1].height = 10;
  prims[1].fill = {0, 0, 0, 1};
  prims[1].blur = 2;
  prims[2].x = 0;
  prims[2].y = 5;
  prims[2].width = 10;
  prims[2].height = 10;
  prims[2].fill = green;
  prims[2].border_width = 2;
  prims[2].border_color = blue;
  const std::vector<ui::run_t> runs{{0, 1, 0, 0}, {1, 2, 38, 0}};
  ui::display_list_t list;
  list.prims = prims;
  list.runs = runs;
  list.background = {1, 1, 1, 1};
  list.logical = {50, 50};
  list.framebuffer = {100, 100};
  list.scale = 2;

  std::string why;
  auto image = ui::detail::render_offscreen_vulkan(list, why);
  if (!image)
  {
    MESSAGE("no Vulkan here, skipped: " << why);
    return;
  }
  MESSAGE("rendered on " << image->device);
  const std::array<int, 4> white{255, 255, 255, 255};
  // The red box's centre, and a point inside its square bounds but outside the rounded corner.
  CHECK(matches(pixel(*image, 40, 40), {255, 0, 0, 255}));
  CHECK(matches(pixel(*image, 11, 11), white));
  // Just inside the straight top edge, away from the corners.
  CHECK(matches(pixel(*image, 40, 11), {255, 0, 0, 255}));
  // The green box: its border (blue) at the edge, green in the middle.
  CHECK(matches(pixel(*image, 77, 11), {0, 0, 255, 255}));
  CHECK(matches(pixel(*image, 86, 20), {0, 255, 0, 255}));
  // The shadow is grey: darker than the background, lighter than black, and soft at its edge.
  const auto shadow = pixel(*image, 86, 50);
  CHECK(shadow[0] < 200);
  CHECK(shadow[0] > 0);
  const auto edge = pixel(*image, 86, 62);
  CHECK(edge[0] > shadow[0]);
  CHECK(edge[0] < 255);
  // Far from everything: background.
  CHECK(matches(pixel(*image, 50, 95), white));
}
