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

// Text and icons: shaping, the atlas, labels at two scales, and the pixels they become
// (gui/PLAN.md, "Rendering"; G27, G39, G40). The fonts are HarfBuzz's test fonts, so these run only
// where HarfBuzz was fetched rather than found on the system.

#include <doctest/doctest.h>

#include <chrono>
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
#include "ui_text.h"

#if defined(VIO_GUI_TEST_FONTS)

using namespace std::chrono_literals;
namespace gui = vio::gui;
namespace ui = vio::gui::ui;

namespace
{
ui::font_t load(const char *relative)
{
  auto font = ui::font_t::from_file(std::string(VIO_GUI_TEST_FONTS) + "/" + relative);
  REQUIRE_MESSAGE(font.has_value(), font.error());
  return *font;
}

ui::font_t roboto()
{
  return load("perf/fonts/Roboto-Regular.ttf");
}

// A right triangle filling the lower left half of its square.
std::shared_ptr<const ui::path_t> triangle()
{
  auto path = std::make_shared<ui::path_t>();
  path->move_to(0, 0).line_to(1, 1).line_to(0, 1).close();
  return path;
}

// What one frame's display list held, atlas included, since the spans die with the frame.
struct snapshot_t
{
  std::vector<ui::prim_t> prims;
  std::vector<ui::run_t> runs;
  std::vector<std::uint8_t> atlas;
  ui::atlas_view_t view;
  gui::extent_t logical;
  gui::extent_t framebuffer;
  float scale = 1;

  void take(const ui::display_list_t &list)
  {
    prims.assign(list.prims.begin(), list.prims.end());
    runs.assign(list.runs.begin(), list.runs.end());
    atlas.assign(list.atlas.pixels.begin(), list.atlas.pixels.end());
    view = list.atlas;
    logical = list.logical;
    framebuffer = list.framebuffer;
    scale = list.scale;
  }

  [[nodiscard]] ui::display_list_t list(ui::color_t background) const
  {
    ui::display_list_t out;
    out.prims = prims;
    out.runs = runs;
    out.background = background;
    out.logical = logical;
    out.framebuffer = framebuffer;
    out.scale = scale;
    out.atlas = view;
    out.atlas.pixels = atlas;
    return out;
  }

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

  // Summed coverage under a prim's atlas rectangle.
  [[nodiscard]] long coverage(const ui::prim_t &prim) const
  {
    long sum = 0;
    for (int y = 0; y < int(prim.height); ++y)
    {
      for (int x = 0; x < int(prim.width); ++x)
        sum += atlas[std::size_t(int(prim.radii[1]) + y) * view.extent.width + int(prim.radii[0]) + x];
    }
    return sum;
  }
};

struct label_t
{
  ui::font_t font;
  std::shared_ptr<const ui::path_t> icon = triangle();

  ui::node_t view() const
  {
    return ui::column_t{.children = {
                          ui::text_t{.text = "Hello", .size = 20, .color = {0, 0, 0, 1}, .font = font},
                          ui::row_t{.children = {ui::icon_t{.path = icon, .size = 16, .color = {0, 0, 0, 1}}, ui::box_t{.size = {10, 10}, .color = {1, 0, 0, 1}}}},
                        }};
  }
};

// Run `label` in a 200x100 window, at scale 1 and then 2, and keep a display list from each.
void run_label(snapshot_t &one, snapshot_t &two)
{
  vio::event_loop_t loop;
  run_gui_test(loop,
               [](vio::event_loop_t &loop, snapshot_t &one, snapshot_t &two) -> vio::task_t<void>
               {
                 gui::display_config_t display_config;
                 display_config.backend = "null";
                 display_config.frame_interval_ns = std::chrono::nanoseconds(2ms).count();
                 auto display = gui::display_t::open(loop, display_config);
                 REQUIRE(display.has_value());
                 {
                   auto window = gui::window_t::create(*display, {.size = {200, 100}});
                   label_t label{roboto()};
                   snapshot_t latest;
                   ui::run_config_t config;
                   config.on_display_list = [&latest](const ui::display_list_t &list) { latest.take(list); };
                   auto running = ui::run(*window, label, std::move(config));
                   (void)co_await vio::sleep(loop, 40ms);
                   one = latest;
                   window->impl()->on_resize({200, 100}, {400, 200}, 2.0f);
                   (void)co_await vio::sleep(loop, 40ms);
                   two = latest;
                   window->close();
                   co_await std::move(running);
                 }
                 loop.stop();
               }(loop, one, two));
}
} // namespace

TEST_CASE("ui text: HarfBuzz shapes Devanagari and Arabic, not just Latin")
{
  ui::detail::text_engine_t engine;
  // KA followed by the vowel sign I, which is written before the consonant it follows: shaped, the
  // sign comes first and KA second, the reverse of the code points.
  const auto devanagari = load("test/subset/data/fonts/NotoSansDevanagari-Regular.ttf");
  const auto ka = ui::detail::text_engine_t::nominal_glyph(devanagari, U'क');
  REQUIRE(ka != 0);
  const auto glyphs = engine.shape(devanagari, 32, "\xE0\xA4\x95\xE0\xA4\xBF");
  REQUIRE(glyphs.size() == 2);
  CHECK(glyphs[0].glyph != ka);
  CHECK(glyphs[1].glyph == ka);
  CHECK(glyphs[0].x < glyphs[1].x);

  // Two BEHs join: the first takes its initial form and the second its final form, neither the
  // isolated glyph the cmap names, and in visual order the final one comes first.
  const auto amiri = load("perf/fonts/Amiri-Regular.ttf");
  const auto beh = ui::detail::text_engine_t::nominal_glyph(amiri, U'ب');
  REQUIRE(beh != 0);
  const auto joined = engine.shape(amiri, 32, "\xD8\xA8\xD8\xA8");
  REQUIRE(joined.size() == 2);
  CHECK(joined[0].glyph != beh);
  CHECK(joined[1].glyph != beh);
  CHECK(joined[0].glyph != joined[1].glyph);
}

TEST_CASE("ui text: a label lays out the same at 1x and 2x and is rasterized at each")
{
  snapshot_t one;
  snapshot_t two;
  run_label(one, two);
  REQUIRE(one.scale == 1);
  REQUIRE(two.scale == 2);

  const auto glyphs_one = one.of(ui::prim_kind_t::coverage);
  const auto glyphs_two = two.of(ui::prim_kind_t::coverage);
  // H, e, l, l, o and the icon.
  REQUIRE(glyphs_one.size() == 6);
  REQUIRE(glyphs_two.size() == 6);

  // Layout is in logical units, so the box after the icon sits where it did; the text above it is
  // within a unit of the same height at both scales.
  const auto boxes_one = one.of(ui::prim_kind_t::shape);
  const auto boxes_two = two.of(ui::prim_kind_t::shape);
  REQUIRE(boxes_one.size() == 1);
  REQUIRE(boxes_two.size() == 1);
  CHECK(boxes_one[0].x == 16);
  CHECK(boxes_two[0].x == 16);
  CHECK(std::abs(boxes_one[0].y - boxes_two[0].y) <= 1);
  CHECK(boxes_one[0].y >= 20);

  // Rasterized at the size in pixels: the H is about twice as tall at 2x, the icon exactly so.
  CHECK(glyphs_two[0].height >= 2 * glyphs_one[0].height - 2);
  CHECK(glyphs_two[0].height <= 2 * glyphs_one[0].height + 2);
  CHECK(glyphs_one[5].width == 16);
  CHECK(glyphs_two[5].width == 32);
  // Every glyph shares its text's anchor; its own place is the pixel offset.
  for (int i = 1; i < 5; ++i)
  {
    CHECK(glyphs_one[i].x == glyphs_one[0].x);
    CHECK(glyphs_one[i].radii[2] > glyphs_one[i - 1].radii[2]);
  }

  // The atlas holds what they name, and a new scale is a new atlas.
  for (const auto &glyph : glyphs_one)
    CHECK(one.coverage(glyph) > 0);
  for (const auto &glyph : glyphs_two)
    CHECK(two.coverage(glyph) > 0);
  CHECK(one.view.generation != two.view.generation);
}

TEST_CASE("ui text: a full atlas is emptied and says so once")
{
  ui::detail::text_engine_t engine;
  const auto font = roboto();
  std::vector<ui::prim_t> prims;
  bool reset = false;
  std::uint64_t generation = 0;
  for (int size = 200; size < 2000 && !reset; size += 40)
  {
    prims.clear();
    generation = engine.atlas().generation;
    engine.add_text({.text = "ABCDEFGHIJKLMNOPQRSTUVWXYZ", .size = float(size), .font = font}, {}, 0, 0, prims);
    reset = engine.take_reset();
  }
  REQUIRE(reset);
  CHECK_FALSE(engine.take_reset());
  CHECK(engine.atlas().extent.width == 4096);
  CHECK(engine.atlas().generation != generation);
}

TEST_CASE("vulkan: text and an icon reach the screen")
{
  snapshot_t one;
  snapshot_t two;
  run_label(one, two);
  std::string why;
  auto image = ui::detail::render_offscreen_vulkan(two.list({1, 1, 1, 1}), why);
  if (!image)
  {
    MESSAGE("no Vulkan here, skipped: " << why);
    return;
  }
  MESSAGE("rendered on " << image->device);
  auto red_at = [&](int x, int y) { return int(image->rgba[(std::size_t(y) * image->extent.width + x) * 4]); };

  // The text: dark pixels inside its line, none to the right of it.
  const auto glyphs = two.of(ui::prim_kind_t::coverage);
  REQUIRE(glyphs.size() == 6);
  const int top = int(glyphs[5].y * 2);
  int dark = 0;
  int stray = 0;
  for (int y = 0; y < top; ++y)
  {
    for (int x = 0; x < 400; ++x)
    {
      if (red_at(x, y) < 128)
        (x < 140 ? dark : stray) += 1;
    }
  }
  CHECK(dark > 100);
  CHECK(stray == 0);

  // The icon at 2x is 32 pixels square, below the text: dark in its lower left half, white in its
  // upper right.
  CHECK(red_at(6, top + 26) < 64);
  CHECK(red_at(26, top + 6) > 240);
}

namespace
{
// "Hi", and a box that adds a W to it.
struct growing_t
{
  ui::font_t font;
  std::string text = "Hi";
  ui::pressable_t more;

  ui::node_t view() const
  {
    return ui::column_t{.children = {
                          ui::text_t{.text = text, .size = 20, .color = {0, 0, 0, 1}, .font = font},
                          ui::box_t{.size = {20, 20}, .color = {1, 0, 0, 1}, .events = more},
                        }};
  }

  ui::behaviour_t behave(ui::scope_t &)
  {
    auto presses = ui::subscribe<ui::press_event_t>(more);
    while (co_await presses)
      text += "W";
  }
};
} // namespace

TEST_CASE("vulkan: a glyph added later reaches the screen through the atlas's dirty rectangle")
{
  std::vector<snapshot_t> frames;
  vio::event_loop_t loop;
  run_gui_test(loop,
               [](vio::event_loop_t &loop, std::vector<snapshot_t> &frames) -> vio::task_t<void>
               {
                 gui::display_config_t display_config;
                 display_config.backend = "null";
                 display_config.frame_interval_ns = std::chrono::nanoseconds(2ms).count();
                 auto display = gui::display_t::open(loop, display_config);
                 REQUIRE(display.has_value());
                 {
                   auto window = gui::window_t::create(*display, {.size = {200, 100}});
                   growing_t growing{roboto()};
                   ui::run_config_t config;
                   config.on_display_list = [&frames](const ui::display_list_t &list) { frames.emplace_back().take(list); };
                   auto running = ui::run(*window, growing, std::move(config));
                   (void)co_await vio::sleep(loop, 40ms);
                   const gui::point_t box{10, 35};
                   window->impl()->on_input(gui::pointer_move_event_t{box});
                   window->impl()->on_input(gui::pointer_button_event_t{gui::button_t::left, true, box});
                   window->impl()->on_input(gui::pointer_button_event_t{gui::button_t::left, false, box});
                   (void)co_await vio::sleep(loop, 40ms);
                   window->close();
                   co_await std::move(running);
                 }
                 loop.stop();
               }(loop, frames));
  REQUIRE(frames.size() >= 2);
  const auto &last = frames.back();
  const auto glyphs = last.of(ui::prim_kind_t::coverage);
  REQUIRE(glyphs.size() == 3);
  // The W was added to the atlas it shares with the frames before, not to a new one: only the
  // dirty rectangle carries it to the GPU.
  CHECK(last.view.generation == frames.front().view.generation);
  // And its rectangle is not on 4-texel boundaries, the case the renderer widens (G39): copied as
  // it is, it did not arrive on an RX 5700 XT.
  bool unaligned = false;
  for (const auto &frame : frames)
  {
    const auto &dirty = frame.view.dirty;
    if (dirty.width > 0 && ((dirty.x | dirty.width) & 3) != 0)
      unaligned = true;
  }
  CHECK(unaligned);

  std::vector<ui::display_list_t> lists;
  for (const auto &frame : frames)
    lists.push_back(frame.list({1, 1, 1, 1}));
  std::string why;
  auto image = ui::detail::render_offscreen_vulkan(lists, why);
  if (!image)
  {
    MESSAGE("no Vulkan here, skipped: " << why);
    return;
  }
  // Dark pixels where the W is drawn.
  const auto &w = glyphs[2];
  const int left = int(w.x) + int(w.radii[2]);
  const int top = int(w.y) + int(w.radii[3]);
  int dark = 0;
  for (int y = top; y < top + int(w.height); ++y)
  {
    for (int x = left; x < left + int(w.width); ++x)
    {
      if (image->rgba[(std::size_t(y) * image->extent.width + x) * 4] < 128)
        ++dark;
    }
  }
  CHECK(dark > 20);
}

#endif
