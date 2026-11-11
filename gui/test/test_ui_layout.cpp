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

#include <array>
#include <chrono>
#include <cmath>
#include <cstdlib>
#include <optional>
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

// What the last frame laid out: the hit-test rects and the prims in window coordinates.
struct capture_t
{
  std::vector<ui::rect_t> rects;
  std::vector<ui::prim_t> prims;

  [[nodiscard]] std::vector<ui::prim_t> of(ui::prim_kind_t kind) const
  {
    std::vector<ui::prim_t> out;
    for (const auto &prim : prims)
    {
      if (prim.kind == kind)
        out.push_back(prim);
    }
    return out;
  }
};

// Show `root` in a null window for a few frames, pressing at `press` if given, and keep the last
// frame's layout.
template <typename C>
void capture(C &root, capture_t &out, std::optional<gui::point_t> press = std::nullopt)
{
  vio::event_loop_t loop;
  run_gui_test(loop,
               [](vio::event_loop_t &loop, C &root, capture_t &out, std::optional<gui::point_t> press) -> vio::task_t<void>
               {
                 gui::display_config_t display_config;
                 display_config.backend = "null";
                 display_config.frame_interval_ns = std::chrono::nanoseconds(2ms).count();
                 auto display = gui::display_t::open(loop, display_config);
                 REQUIRE(display.has_value());
                 {
                   auto window = gui::window_t::create(*display, {.size = {300, 200}});
                   ui::run_config_t config;
                   config.on_layout = [&out](std::span<const ui::draw_item_t> items)
                   {
                     out.rects.clear();
                     for (const auto &item : items)
                       out.rects.push_back(item.rect);
                   };
                   config.on_display_list = [&out](const ui::display_list_t &list)
                   {
                     out.prims.clear();
                     for (const auto &run : list.runs)
                     {
                       for (std::uint32_t i = run.first; i < run.first + run.count; ++i)
                         out.prims.push_back(list.prims[i]);
                     }
                   };
                   auto running = ui::run(*window, root, std::move(config));
                   (void)co_await vio::sleep(loop, 40ms);
                   if (press)
                   {
                     window->impl()->on_input(gui::pointer_move_event_t{*press});
                     window->impl()->on_input(gui::pointer_button_event_t{gui::button_t::left, true, *press});
                     window->impl()->on_input(gui::pointer_button_event_t{gui::button_t::left, false, *press});
                     (void)co_await vio::sleep(loop, 40ms);
                   }
                   window->close();
                   co_await std::move(running);
                 }
                 loop.stop();
               }(loop, root, out, press));
}

std::array<int, 4> pixel(const ui::detail::offscreen_image_t &image, int x, int y)
{
  const auto *p = &image.rgba[(std::size_t(y) * image.extent.width + x) * 4];
  return {p[0], p[1], p[2], p[3]};
}

bool close_to(std::array<int, 4> a, std::array<int, 4> b, int tolerance)
{
  for (int i = 0; i < 4; ++i)
  {
    if (std::abs(a[i] - b[i]) > tolerance)
      return false;
  }
  return true;
}
} // namespace

TEST_CASE("ui layout: a box holds its children inside its padding, aligned, and grows to fit them")
{
  struct boxes_t
  {
    ui::node_t view() const
    {
      return ui::column_t{.children = {
                            // Smaller than its child and its padding: it grows, and the child sits at the padding.
                            ui::box_t{.size = {10, 10}, .color = red, .padding = {8, 4}, .children = {ui::box_t{.size = {30, 12}, .color = green}}},
                            // Larger: the child is centred, which is the default.
                            ui::box_t{.size = {100, 40}, .color = red, .children = {ui::box_t{.size = {30, 12}, .color = green}}},
                            // Start across, end down, inside the padding.
                            ui::box_t{.size = {100, 40}, .color = red, .padding = {2, 3, 4, 5}, .align_x = ui::align_t::start, .align_y = ui::align_t::end, .children = {ui::box_t{.size = {30, 12}, .color = green}}},
                          }};
    }
  } root;
  capture_t seen;
  capture(root, seen);
  REQUIRE(seen.rects.size() == 6);
  // The box first, its child after it: painter's order, and the child is what a press finds.
  CHECK(seen.rects[0] == ui::rect_t{0, 0, 46, 20});
  CHECK(seen.rects[1] == ui::rect_t{8, 4, 30, 12});
  CHECK(seen.rects[2] == ui::rect_t{0, 20, 100, 40});
  CHECK(seen.rects[3] == ui::rect_t{35, 20 + 14, 30, 12});
  CHECK(seen.rects[4] == ui::rect_t{0, 60, 100, 40});
  CHECK(seen.rects[5] == ui::rect_t{2, 60 + 40 - 5 - 12, 30, 12});
  // The prim is drawn at the size the box grew to.
  REQUIRE(seen.prims.size() == 6);
  CHECK(seen.prims[0].width == 46);
  CHECK(seen.prims[0].height == 20);
}

TEST_CASE("ui layout: rows and columns place their children across, inside their padding")
{
  struct lines_t
  {
    ui::align_t align;

    ui::node_t view() const
    {
      return ui::column_t{
        .gap = 10,
        .children = {
          ui::row_t{.gap = 2, .align = align, .padding = {1, 2, 3, 4}, .children = {ui::box_t{.size = {10, 10}, .color = red}, ui::box_t{.size = {10, 30}, .color = green}, ui::box_t{.size = {10, 20}, .color = blue}}},
          ui::column_t{.align = align, .children = {ui::box_t{.size = {10, 5}, .color = red}, ui::box_t{.size = {30, 5}, .color = green}}},
        }};
    }
  };

  // The row is 1 + 10 + 2 + 10 + 2 + 10 + 3 wide and 2 + 30 + 4 tall; the column starts 10 below.
  lines_t centred{ui::align_t::center};
  capture_t seen;
  capture(centred, seen);
  REQUIRE(seen.rects.size() == 5);
  CHECK(seen.rects[0] == ui::rect_t{1, 2 + 10, 10, 10});
  CHECK(seen.rects[1] == ui::rect_t{13, 2, 10, 30});
  CHECK(seen.rects[2] == ui::rect_t{25, 2 + 5, 10, 20});
  CHECK(seen.rects[3] == ui::rect_t{10, 46, 10, 5});
  CHECK(seen.rects[4] == ui::rect_t{0, 51, 30, 5});

  lines_t ended{ui::align_t::end};
  capture(ended, seen);
  REQUIRE(seen.rects.size() == 5);
  CHECK(seen.rects[0].y == 2 + 20);
  CHECK(seen.rects[1].y == 2);
  CHECK(seen.rects[2].y == 2 + 10);
  CHECK(seen.rects[3].x == 20);
  CHECK(seen.rects[4].x == 0);
}

TEST_CASE("ui layout: pressing what is drawn on a button presses the button")
{
  struct button_t
  {
    int count = 0;
    ui::pressable_t press;

    ui::node_t view() const
    {
      // The label has no events of its own, so a press on it is the button's.
      return ui::box_t{.size = {80, 40}, .color = red, .events = press, .children = {ui::box_t{.size = {40, 10}, .color = green}}};
    }

    ui::behaviour_t behave(ui::scope_t &)
    {
      auto presses = ui::subscribe<ui::press_event_t>(press);
      while (co_await presses)
        ++count;
    }
  } root;
  capture_t seen;
  capture(root, seen, gui::point_t{40, 20});
  CHECK(root.count == 1);
}

TEST_CASE("ui layout: at_t keeps a fractional offset for drawing and rounds it for hit testing")
{
  struct placed_t
  {
    ui::node_t view() const
    {
      return ui::row_t{.children = {
                         ui::at_t{.x = 10.25f, .y = 5.5f, .children = {ui::box_t{.size = {10, 10}, .color = red}}},
                         ui::box_t{.size = {4, 4}, .color = green},
                       }};
    }
  } root;
  capture_t seen;
  capture(root, seen);
  REQUIRE(seen.prims.size() == 2);
  CHECK(seen.prims[0].x == 10.25f);
  CHECK(seen.prims[0].y == 5.5f);
  REQUIRE(seen.rects.size() == 2);
  CHECK(seen.rects[0] == ui::rect_t{10, 6, 10, 10});
  // Its size reaches to the far edge of the child: ceil(10.25 + 10).
  CHECK(seen.rects[1].x == 21);
}

TEST_CASE("ui plot: a polyline is its areas, then its segments, then its markers, where it was placed")
{
  struct plot_t
  {
    ui::node_t view() const
    {
      return ui::polyline_t{.size = {20, 10}, .points = {{0, 10}, {10, 0}, {5, 5}, {20, 8}}, .width = 2, .color = red, .fill = {0, 0, 1, 0.5f}, .marker = 3};
    }
  };
  struct page_t
  {
    plot_t plot;
    ui::node_t view() const
    {
      return ui::row_t{.gap = 5, .padding = {0, 7, 0, 0}, .children = {ui::box_t{.size = {20, 20}, .color = green}, ui::mount(plot)}};
    }
  } root;
  capture_t seen;
  capture(root, seen);
  const auto areas = seen.of(ui::prim_kind_t::area);
  const auto segments = seen.of(ui::prim_kind_t::segment);
  // Three segments; the one that runs back from x = 10 to x = 5 has no area.
  REQUIRE(areas.size() == 2);
  REQUIRE(segments.size() == 3);
  REQUIRE(seen.prims.size() == 1 + 2 + 3 + 4);
  // Painter's order: the box, the areas, the segments, the markers.
  CHECK(seen.prims[1].kind == ui::prim_kind_t::area);
  CHECK(seen.prims[3].kind == ui::prim_kind_t::segment);
  CHECK(seen.prims[6].kind == ui::prim_kind_t::shape);

  // Placed 25 across and 7 down, both ends moved: a mounted child's prims are moved into the chunk
  // that holds them.
  CHECK(areas[0].x == 25);
  CHECK(areas[0].y == 7 + 10);
  CHECK(areas[0].radii[0] == 35);
  CHECK(areas[0].radii[1] == 7);
  CHECK(areas[0].radii[2] == 7 + 10);
  CHECK(areas[1].x == 30);
  CHECK(areas[1].radii[0] == 45);
  CHECK(segments[1].x == 35);
  CHECK(segments[1].radii[0] == 30);
  CHECK(segments[1].border_width == 2);
  // A marker is a disc on its point.
  CHECK(seen.prims[6].x == 25 - 1.5f);
  CHECK(seen.prims[6].width == 3);
  CHECK(seen.prims[6].radii[0] == 1.5f);
}

// Named vulkan: so the Linux script runs it in the pass without leak detection (G18).
TEST_CASE("vulkan: a polyline's line and fill reach the screen, and neighbouring areas meet without a seam")
{
  // A 100x100 target at scale 2: a V from (5, 10) down to (25.25, 40) and up to (45, 10), filled
  // to y = 45 in translucent blue, with a red line 2 units wide.
  std::vector<ui::prim_t> prims;
  const std::array<ui::vec2_t, 3> points{{{5, 10}, {25.25f, 40}, {45, 10}}};
  for (std::size_t i = 1; i < points.size(); ++i)
  {
    ui::prim_t area;
    area.kind = ui::prim_kind_t::area;
    area.x = points[i - 1].x;
    area.y = points[i - 1].y;
    area.radii[0] = points[i].x;
    area.radii[1] = points[i].y;
    area.radii[2] = 45;
    area.fill = {0, 0, 1, 0.5f};
    prims.push_back(area);
  }
  for (std::size_t i = 1; i < points.size(); ++i)
  {
    ui::prim_t segment;
    segment.kind = ui::prim_kind_t::segment;
    segment.x = points[i - 1].x;
    segment.y = points[i - 1].y;
    segment.radii[0] = points[i].x;
    segment.radii[1] = points[i].y;
    segment.border_width = 2;
    segment.fill = red;
    prims.push_back(segment);
  }
  const std::vector<ui::run_t> runs{{0, std::uint32_t(prims.size()), 0, 0}};
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
  // Half blue over white, blended in linear space and encoded back to sRGB.
  const auto fill = pixel(*image, 50, 88);
  CHECK(fill[2] == 255);
  CHECK(fill[0] > 100);
  CHECK(fill[0] < 230);
  CHECK(fill[0] == fill[1]);

  // On the line: x = 15 is half way down the first segment, at y = 25. In pixels (30, 50).
  CHECK(close_to(pixel(*image, 30, 50), {255, 0, 0, 255}, 2));
  // Above the V: background. Below the line, above the bottom: the fill.
  CHECK(close_to(pixel(*image, 50, 20), white, 0));
  CHECK(close_to(pixel(*image, 20, 70), fill, 2));
  // Below the bottom: background.
  CHECK(close_to(pixel(*image, 50, 95), white, 0));

  // The two areas meet at x = 25.25, which is 50.5 in pixels: the centres of column 50 lie exactly
  // on the shared edge. Drawn twice, it would be darker than its neighbours; drawn by neither, white.
  for (int y = 84; y < 90; ++y)
  {
    CHECK(close_to(pixel(*image, 49, y), fill, 1));
    CHECK(close_to(pixel(*image, 50, y), fill, 1));
    CHECK(close_to(pixel(*image, 51, y), fill, 1));
  }
}

TEST_CASE("vulkan: many thin areas at a fractional scale and origin cover every pixel once")
{
  // What a scrolling plot produces: a few hundred areas a little over a pixel wide each, in a run
  // whose origin is not on a pixel, at 1.5x.
  std::vector<ui::prim_t> prims;
  float x = 0.37f;
  for (int i = 0; i < 300; ++i)
  {
    const float next = x + 0.761f + 0.013f * float(i % 7);
    ui::prim_t area;
    area.kind = ui::prim_kind_t::area;
    area.x = x;
    area.y = 10 + float(i % 5);
    area.radii[0] = next;
    area.radii[1] = 10 + float((i + 1) % 5);
    area.radii[2] = 60;
    area.fill = {0, 0, 1, 0.5f};
    prims.push_back(area);
    x = next;
  }
  const std::vector<ui::run_t> runs{{0, std::uint32_t(prims.size()), 13.3f, 7.7f}};
  ui::display_list_t list;
  list.prims = prims;
  list.runs = runs;
  list.background = {1, 1, 1, 1};
  list.logical = {400, 100};
  list.framebuffer = {600, 150};
  list.scale = 1.5f;
  std::string why;
  auto image = ui::detail::render_offscreen_vulkan(list, why);
  if (!image)
  {
    MESSAGE("no Vulkan here, skipped: " << why);
    return;
  }
  // A row well below the line and above the bottom, across the whole run.
  const int y = int((7.7f + 40) * 1.5f);
  const auto first = pixel(*image, 30, y);
  int odd = 0;
  for (int px = 30; px < int((13.3f + x) * 1.5f) - 2; ++px)
  {
    if (!close_to(pixel(*image, px, y), first, 1))
      ++odd;
  }
  CHECK(odd == 0);
}
