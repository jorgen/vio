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

// A stress test after Qt's 40,000-chip graphics view demo, five times over: 200,000 chips, each one
// movable and editable. Scroll to zoom about the pointer, drag the background to pan, drag a chip to
// move it, click one to select it and type to change its label (Backspace deletes, Escape lets go).
// Zoomed in, chips show a die and pins, then a label.
//
// The chips are plain data in 400 tiles of 500. Each tile is a component whose props are a zoom
// step, whether it is in view and a version its chips bump when they change. It is mounted scaled
// from its step to the actual zoom, which the GPU applies, so panning rebuilds nothing, zooming
// rebuilds the tiles in view only when it crosses a step, and moving or editing a chip rebuilds its
// tile alone. A tile out
// of view draws nothing; one in view holds its own chunk, which panning only moves.
//
// `vio_gui_ui_chips --bench` drives it through five workloads and prints what each frame cost.

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <memory>
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
constexpr int columns = 500;
constexpr int rows = 400;
constexpr int tile_columns = 25;
constexpr int tile_rows = 20;
constexpr int tiles_across = columns / tile_columns;
constexpr int tiles_down = rows / tile_rows;
// Scene units: a chip is 10 by 7 at zoom 1, on a 12 by 9 pitch.
constexpr float chip_w = 10;
constexpr float chip_h = 7;
constexpr float pitch_x = 12;
constexpr float pitch_y = 9;
constexpr float tile_w = tile_columns * pitch_x;
constexpr float tile_h = tile_rows * pitch_y;

constexpr ui::color_t background{0.1f, 0.1f, 0.12f, 1};
constexpr ui::color_t ink{0.92f, 0.92f, 0.95f, 1};
constexpr ui::color_t grey{0.6f, 0.6f, 0.65f, 1};
constexpr ui::color_t selected_border{1, 0.85f, 0.2f, 1};

struct chip_t
{
  float x = 0;
  float y = 0;
  std::uint32_t id = 0;
  ui::color_t color;
  std::string label; // empty: "#id"
};

ui::color_t hue(float h, float v)
{
  const float r = std::clamp(std::abs(h * 6 - 3) - 1, 0.0f, 1.0f);
  const float g = std::clamp(2 - std::abs(h * 6 - 2), 0.0f, 1.0f);
  const float b = std::clamp(2 - std::abs(h * 6 - 4), 0.0f, 1.0f);
  return {0.15f + r * v, 0.15f + g * v, 0.15f + b * v, 1};
}

// Darker, for a chip's outline and die.
ui::color_t shade(ui::color_t c, float f)
{
  return {c.r * f, c.g * f, c.b * f, 1};
}

// ---------------------------------------------------------------------------------------------
// Frame statistics, gathered from run_config_t::on_stats.

struct sample_t
{
  double interval_ms = 0;
  double views_ms = 0;
  double layout_ms = 0;
  double list_ms = 0;
  double render_ms = 0;
  std::size_t prims = 0;
  std::size_t views_run = 0;
};

struct stats_t
{
  std::deque<sample_t> recent;
  std::vector<sample_t> *recording = nullptr;

  void add(const ui::frame_stats_t &s)
  {
    const auto ms = [](std::chrono::nanoseconds d) { return double(d.count()) / 1e6; };
    sample_t sample{ms(s.interval), ms(s.views), ms(s.layout), ms(s.display_list), ms(s.render), s.prims, s.views_run};
    recent.push_back(sample);
    if (recent.size() > 120)
      recent.pop_front();
    if (recording)
      recording->push_back(sample);
  }
};

stats_t stats;

double percentile(std::vector<double> values, double p)
{
  if (values.empty())
    return 0;
  std::sort(values.begin(), values.end());
  return values[std::min(values.size() - 1, std::size_t(p * double(values.size())))];
}

std::string fixed(double value, int decimals)
{
  char text[32];
  std::snprintf(text, sizeof text, "%.*f", decimals, value);
  return text;
}

// ---------------------------------------------------------------------------------------------
// Tiles

// A chip keeps its size, and a box grows to fit what is in it, so a long label shows its tail --
// the end being typed -- cut at a character boundary.
std::string shown(const chip_t &chip)
{
  std::string text = chip.label.empty() ? "#" + std::to_string(chip.id) : chip.label;
  constexpr std::size_t most = 8;
  std::size_t cut = text.size() > most ? text.size() - most : 0;
  while (cut > 0 && cut < text.size() && (static_cast<unsigned char>(text[cut]) & 0xC0) == 0x80)
    ++cut;
  return text.substr(cut);
}

constexpr ui::color_t silver{0.78f, 0.78f, 0.82f, 1};
constexpr ui::color_t clear{0, 0, 0, 0};

// One chip at a zoom step, as a DIP package: silver pins along its top and bottom edges, a body in
// the chip's colour with a notch at its left end, a darker die with the label, and -- close up -- a
// model number in one corner and a serial number in the other. Less of it the further out: a plain
// box, then the body's border, then pins and die, then the label, notch and shadow, then the small
// print. Pins are drawn first so the body covers their inner ends.
std::vector<ui::node_t> chip_parts(const chip_t &chip, float z, int w, int h, bool selected)
{
  const float fw = float(w);
  const float fh = float(h);
  const ui::color_t edge = selected ? selected_border : shade(chip.color, 0.5f);
  if (z < 1.6f)
  {
    ui::box_t body{.size = {w, h}, .color = chip.color, .radius = z >= 1 ? 0.06f * fw : 0, .border_width = z >= 1 || selected ? std::max(selected ? 1.0f : 0.5f, 0.05f * fw) : 0, .border_color = edge};
    return {std::move(body)};
  }

  std::vector<ui::node_t> parts;
  // Pins: eight a side, reaching under a third of the gap to the next row, tucked under the body.
  constexpr int pins = 8;
  const int pin_w = std::max(1, int(std::lround(0.045f * fw)));
  const float reach = 0.6f * z;
  const int pin_h = std::max(1, int(std::lround(reach + 0.15f * fh)));
  const float first = 0.1f * fw;
  const float step = (0.8f * fw - float(pin_w)) / float(pins - 1);
  for (int i = 0; i < pins; ++i)
  {
    const float x = first + step * float(i);
    parts.push_back(ui::at_t{.x = x, .y = -reach, .children = {ui::box_t{.size = {pin_w, pin_h}, .color = silver, .radius = 0.3f * float(pin_w)}}});
    parts.push_back(ui::at_t{.x = x, .y = fh - 0.15f * fh, .children = {ui::box_t{.size = {pin_w, pin_h}, .color = silver, .radius = 0.3f * float(pin_w)}}});
  }

  ui::box_t body{.size = {w, h},
                 .color = chip.color,
                 .radius = 0.06f * fw,
                 .border_width = std::max(selected ? 1.5f : 0.5f, (selected ? 0.07f : 0.035f) * fw),
                 .border_color = edge,
                 .align_x = ui::align_t::start,
                 .align_y = ui::align_t::start};
  if (z >= 2.5f)
    body.shadow = {.x = 0, .y = 0.25f * z, .blur = 0.35f * z, .color = {0, 0, 0, 0.55f}};

  // The die, and on it the label.
  ui::box_t die{.size = {int(0.6f * fw), int(0.56f * fh)}, .color = shade(chip.color, 0.45f), .radius = 0.03f * fw, .border_width = std::max(0.5f, 0.015f * fw), .border_color = shade(chip.color, 0.3f)};
  if (z >= 2.5f)
    die.children.push_back(ui::text_t{.text = shown(chip), .size = 1.35f * z, .color = ink});
  body.children.push_back(ui::at_t{.x = 0.2f * fw, .y = 0.22f * fh, .children = {std::move(die)}});

  if (z >= 2.5f)
  {
    // The notch that marks pin 1's end: a half circle let into the body's left edge.
    const float notch = 0.18f * fh;
    body.children.push_back(ui::at_t{.x = -notch / 2, .y = (fh - notch) / 2, .children = {ui::box_t{.size = {int(notch), int(notch)}, .color = shade(chip.color, 0.35f), .radius = notch / 2}}});
  }

  // The small print, close up: in the bands above and below the die.
  if (z >= 5.5f)
  {
    char serial[24];
    std::snprintf(serial, sizeof serial, "S/N %08X", unsigned(chip.id * 2654435761u));
    const ui::color_t print{0.95f, 0.95f, 0.97f, 0.8f};
    const struct
    {
      int x, y;
    } pad{int(0.05f * fw), int(0.03f * fh)};
    body.children.push_back(ui::box_t{.size = {w, h},
                                      .color = clear,
                                      .padding = {pad.x, pad.y},
                                      .align_x = ui::align_t::start,
                                      .align_y = ui::align_t::start,
                                      .children = {ui::text_t{.text = "VC-" + std::to_string(1000 + chip.id % 9000) + "  rev " + std::to_string(1 + chip.id % 7), .size = 0.6f * z, .color = print}}});
    body.children.push_back(
      ui::box_t{.size = {w, h}, .color = clear, .padding = {pad.x, pad.y}, .align_x = ui::align_t::end, .align_y = ui::align_t::end, .children = {ui::text_t{.text = serial, .size = 0.5f * z, .color = print}}});
  }
  parts.push_back(std::move(body));
  return parts;
}

struct tile_t
{
  struct props_t
  {
    float zoom = 1;
    bool visible = false;
    std::uint64_t version = 0;
    std::uint32_t selected = 0; // a chip id, 0 for none (ids start at 1)
    friend bool operator==(const props_t &, const props_t &) = default;
  };
  props_t props;
  std::vector<chip_t> chips;
  float origin_x = 0;
  float origin_y = 0;

  ui::node_t view() const
  {
    const float z = props.zoom;
    if (!props.visible)
      return ui::spacer_t{.grow = 0, .size = {int(std::ceil(tile_w * z)), int(std::ceil(tile_h * z))}};
    const int w = std::max(1, int(std::lround(chip_w * z)));
    const int h = std::max(1, int(std::lround(chip_h * z)));
    std::vector<ui::node_t> nodes;
    nodes.reserve(chips.size());
    for (const auto &chip : chips)
    {
      const bool selected = chip.id == props.selected;
      nodes.push_back(ui::at_t{.x = (chip.x - origin_x) * z, .y = (chip.y - origin_y) * z, .children = chip_parts(chip, z, w, h, selected)});
    }
    return ui::at_t{.children = std::move(nodes)};
  }
};

// ---------------------------------------------------------------------------------------------
// The stats bar: refreshed four times a second, not every frame, or it would keep the frames coming.

struct stats_bar_t
{
  std::string text = "...";
  std::string mode;

  ui::node_t view() const
  {
    return ui::box_t{.color = {0.05f, 0.05f, 0.07f, 0.92f},
                     .padding = {12, 6},
                     .align_x = ui::align_t::stretch,
                     .children = {ui::row_t{.gap = 16,
                                            .align = ui::align_t::baseline,
                                            .children = {ui::text_t{.text = "200,000 chips", .size = 15, .color = ink}, ui::text_t{.text = text, .size = 13, .color = grey}, ui::spacer_t{},
                                                         ui::text_t{.text = mode, .size = 13, .color = grey}}}}};
  }

  ui::behaviour_t behave(ui::scope_t &scope)
  {
    auto ticks = ui::every(scope, 250ms);
    while (co_await ticks)
    {
      std::vector<double> intervals;
      double cpu = 0;
      std::size_t prims = 0;
      for (const auto &s : stats.recent)
      {
        intervals.push_back(s.interval_ms);
        cpu += s.views_ms + s.layout_ms + s.list_ms + s.render_ms;
        prims = s.prims;
      }
      const double median = percentile(intervals, 0.5);
      text = fixed(median > 0 ? 1000.0 / median : 0, 0) + " fps   cpu " + fixed(stats.recent.empty() ? 0 : cpu / double(stats.recent.size()), 2) + " ms/frame   " + std::to_string(prims) + " prims";
    }
  }
};

// ---------------------------------------------------------------------------------------------
// The scene

struct scene_t
{
  std::vector<tile_t> tiles = std::vector<tile_t>(tiles_across * tiles_down);
  std::vector<std::uint64_t> versions = std::vector<std::uint64_t>(tiles_across * tiles_down, 0);
  stats_bar_t bar;
  float zoom = 1;
  float pan_x = 20;
  float pan_y = 40;
  std::uint32_t selected = 0;
  int selected_tile = -1;
  gui::extent_t viewport{1, 1};
  bool bench = false;

  scene_t()
  {
    std::uint32_t id = 1;
    for (int ty = 0; ty < tiles_down; ++ty)
    {
      for (int tx = 0; tx < tiles_across; ++tx)
      {
        auto &tile = tiles[std::size_t(ty * tiles_across + tx)];
        tile.origin_x = float(tx) * tile_w;
        tile.origin_y = float(ty) * tile_h;
        tile.chips.reserve(tile_columns * tile_rows);
      }
    }
    for (int row = 0; row < rows; ++row)
    {
      for (int column = 0; column < columns; ++column)
      {
        chip_t chip;
        chip.x = float(column) * pitch_x;
        chip.y = float(row) * pitch_y;
        chip.id = id++;
        const float u = float(column) / columns;
        const float v = float(row) / rows;
        chip.color = hue(std::fmod(u * 0.8f + v * 0.3f + 0.1f * std::sin(u * 40) * std::cos(v * 30), 1.0f), 0.55f + 0.25f * std::sin(u * 9 + v * 7));
        tiles[std::size_t((row / tile_rows) * tiles_across + column / tile_columns)].chips.push_back(std::move(chip));
      }
    }
  }

  [[nodiscard]] bool tile_visible(int index) const
  {
    const auto &tile = tiles[std::size_t(index)];
    const float x = pan_x + tile.origin_x * zoom;
    const float y = pan_y + tile.origin_y * zoom;
    // A chip moved to the edge of its tile hangs over by one chip.
    return x + (tile_w + chip_w) * zoom > 0 && y + (tile_h + chip_h) * zoom > 0 && x < float(viewport.width) && y < float(viewport.height);
  }

  // Tiles are laid out at zoom steps a factor of the square root of two apart, and drawn scaled
  // the rest of the way: zooming rebuilds a tile only when it crosses a step.
  static float layout_zoom(float z)
  {
    return std::exp2(std::round(std::log2(z) * 2) / 2);
  }

  ui::node_t view() const
  {
    const float level = layout_zoom(zoom);
    std::vector<ui::node_t> placed;
    placed.reserve(tiles.size());
    for (std::size_t i = 0; i < tiles.size(); ++i)
    {
      const auto &tile = tiles[i];
      const tile_t::props_t props{level, tile_visible(int(i)), versions[i], int(i) == selected_tile ? selected : 0};
      placed.push_back(ui::at_t{.x = tile.origin_x * zoom, .y = tile.origin_y * zoom, .children = {ui::mount(tile, props).scaled(zoom / level)}});
    }
    return ui::box_t{.color = background, .align_x = ui::align_t::stretch, .align_y = ui::align_t::start, .children = {ui::at_t{.x = pan_x, .y = pan_y, .children = std::move(placed)}, ui::mount(bar)}};
  }

  // Which tile a scene point falls in, clamped to the grid.
  static int tile_at(float sx, float sy)
  {
    const int tx = std::clamp(int(std::floor(sx / tile_w)), 0, tiles_across - 1);
    const int ty = std::clamp(int(std::floor(sy / tile_h)), 0, tiles_down - 1);
    return ty * tiles_across + tx;
  }

  // The topmost chip under a window point: in the tile it falls in and the ones around it, since a
  // chip near a tile's edge can hang over into its neighbour.
  bool hit(gui::point_t p, int &tile_index, std::size_t &chip_index) const
  {
    const float sx = (float(p.x) - pan_x) / zoom;
    const float sy = (float(p.y) - pan_y) / zoom;
    const int tx = std::clamp(int(std::floor(sx / tile_w)), 0, tiles_across - 1);
    const int ty = std::clamp(int(std::floor(sy / tile_h)), 0, tiles_down - 1);
    for (int dy = 1; dy >= -1; --dy)
    {
      for (int dx = 1; dx >= -1; --dx)
      {
        const int x = tx + dx;
        const int y = ty + dy;
        if (x < 0 || y < 0 || x >= tiles_across || y >= tiles_down)
          continue;
        const auto &chips = tiles[std::size_t(y * tiles_across + x)].chips;
        for (std::size_t i = chips.size(); i-- > 0;)
        {
          const auto &c = chips[i];
          if (sx >= c.x && sy >= c.y && sx < c.x + chip_w && sy < c.y + chip_h)
          {
            tile_index = y * tiles_across + x;
            chip_index = i;
            return true;
          }
        }
      }
    }
    return false;
  }

  chip_t *selected_chip()
  {
    if (selected_tile < 0)
      return nullptr;
    for (auto &chip : tiles[std::size_t(selected_tile)].chips)
    {
      if (chip.id == selected)
        return &chip;
    }
    return nullptr;
  }

  // Move the selected chip to a scene position, and into the tile it now lies in.
  void move_selected(float sx, float sy)
  {
    auto *chip = selected_chip();
    if (!chip)
      return;
    chip->x = sx;
    chip->y = sy;
    ++versions[std::size_t(selected_tile)];
    const int home = tile_at(sx + chip_w / 2, sy + chip_h / 2);
    if (home == selected_tile)
      return;
    auto &from = tiles[std::size_t(selected_tile)].chips;
    auto moved = std::move(*chip);
    from.erase(from.begin() + (chip - from.data()));
    tiles[std::size_t(home)].chips.push_back(std::move(moved));
    selected_tile = home;
    ++versions[std::size_t(home)];
  }

  void edit(std::string_view text, bool backspace)
  {
    auto *chip = selected_chip();
    if (!chip)
      return;
    if (chip->label.empty())
      chip->label = "#" + std::to_string(chip->id);
    if (backspace)
    {
      // Back over one UTF-8 character.
      while (!chip->label.empty() && (static_cast<unsigned char>(chip->label.back()) & 0xC0) == 0x80)
        chip->label.pop_back();
      if (!chip->label.empty())
        chip->label.pop_back();
    }
    else
      chip->label += text;
    ++versions[std::size_t(selected_tile)];
  }

  void zoom_about(gui::point_t p, float to)
  {
    to = std::clamp(to, 0.1f, 24.0f);
    pan_x = float(p.x) - (float(p.x) - pan_x) * to / zoom;
    pan_y = float(p.y) - (float(p.y) - pan_y) * to / zoom;
    zoom = to;
  }

  ui::behaviour_t behave(ui::scope_t &scope)
  {
    // The viewport is known once a frame has been laid out.
    (void)co_await vio::sleep(scope.loop(), 30ms, scope.token());
    viewport = scope.viewport();
    if (bench)
    {
      (void)co_await scope.spawn(run_bench(scope));
      co_return;
    }
    auto events = scope.window().subscribe<gui::pointer_move_event_t, gui::pointer_button_event_t, gui::scroll_event_t, gui::key_event_t, gui::text_event_t, gui::resize_event_t>();
    enum class drag_t
    {
      none,
      pan,
      chip
    } drag = drag_t::none;
    gui::point_t last;
    float grab_x = 0;
    float grab_y = 0;
    while (auto event = co_await events)
    {
      if (std::holds_alternative<gui::resize_event_t>(*event))
      {
        // The new size is laid out at the next frame; read it after.
        (void)co_await vio::sleep(scope.loop(), 30ms, scope.token());
        viewport = scope.viewport();
        continue;
      }
      viewport = scope.viewport();
      if (auto *move = std::get_if<gui::pointer_move_event_t>(&*event))
      {
        const auto p = scope.to_logical(move->position);
        if (drag == drag_t::pan)
        {
          pan_x += float(p.x - last.x);
          pan_y += float(p.y - last.y);
        }
        else if (drag == drag_t::chip)
          move_selected((float(p.x) - pan_x) / zoom - grab_x, (float(p.y) - pan_y) / zoom - grab_y);
        last = p;
      }
      else if (auto *button = std::get_if<gui::pointer_button_event_t>(&*event))
      {
        if (button->button != gui::button_t::left)
          continue;
        const auto p = scope.to_logical(button->position);
        last = p;
        if (!button->pressed)
        {
          drag = drag_t::none;
          continue;
        }
        int tile = -1;
        std::size_t index = 0;
        if (hit(p, tile, index))
        {
          const auto &chip = tiles[std::size_t(tile)].chips[index];
          if (selected_tile >= 0)
            ++versions[std::size_t(selected_tile)];
          selected = chip.id;
          selected_tile = tile;
          ++versions[std::size_t(tile)];
          grab_x = (float(p.x) - pan_x) / zoom - chip.x;
          grab_y = (float(p.y) - pan_y) / zoom - chip.y;
          drag = drag_t::chip;
        }
        else
          drag = drag_t::pan;
      }
      else if (auto *scroll = std::get_if<gui::scroll_event_t>(&*event))
        zoom_about(scope.to_logical(scroll->position), zoom * std::pow(1.15f, float(scroll->dy)));
      else if (auto *key = std::get_if<gui::key_event_t>(&*event))
      {
        if (!key->pressed)
          continue;
        if (key->key == gui::key_t::backspace)
          edit({}, true);
        else if (key->key == gui::key_t::escape && selected_tile >= 0)
        {
          ++versions[std::size_t(selected_tile)];
          selected = 0;
          selected_tile = -1;
        }
      }
      else if (auto *text = std::get_if<gui::text_event_t>(&*event))
      {
        if (!text->text.empty() && static_cast<unsigned char>(text->text[0]) >= 0x20)
          edit(text->text, false);
      }
    }
  }

  // ---- the benchmark: five workloads, each for a few seconds, each frame forced by a change.
  struct phase_t
  {
    const char *name;
    std::vector<sample_t> samples;
  };
  std::vector<phase_t> phases;

  ui::job_t<int> run_bench(ui::scope_t &scope)
  {
    auto &loop = scope.loop();
    const auto run_phase = [&](const char *name) -> phase_t &
    {
      phases.push_back({name, {}});
      bar.mode = name;
      return phases.back();
    };
    const auto for_a_while = [&](ui::scope_t &, phase_t &phase, auto step) -> ui::job_t<int>
    {
      // Let the phase's first frame -- which may rebuild everything -- go unrecorded.
      step(0);
      (void)co_await vio::sleep(loop, 100ms, scope.token());
      stats.recording = &phase.samples;
      const auto start = std::chrono::steady_clock::now();
      for (int i = 1; std::chrono::steady_clock::now() - start < 3s; ++i)
      {
        step(i);
        if (!co_await vio::sleep(loop, 1ms, scope.token()))
          break;
      }
      stats.recording = nullptr;
      co_return 0;
    };
    (void)co_await vio::sleep(loop, 300ms, scope.token());
    viewport = scope.viewport();
    const float fit = std::min(float(viewport.width) / (columns * pitch_x), float(viewport.height - 40) / (rows * pitch_y));

    // 1. Everything in view, panning: no view runs, every chunk moves.
    zoom = fit;
    {
      auto &phase = run_phase("all 200,000 in view, panning");
      co_await scope.spawn(for_a_while(scope, phase, [&](int i) { pan_x = 4 + 4 * std::sin(float(i) * 0.1f); }));
    }
    // 2. Zoomed in to labels, panning: tiles enter and leave the view and are built as they do.
    {
      auto &phase = run_phase("zoomed in (labels), panning");
      zoom = 3.5f;
      co_await scope.spawn(for_a_while(scope, phase,
                                       [&](int i)
                                       {
                                         pan_x = -200 - float(i) * 4;
                                         pan_y = -150 - float(i) * 1.5f;
                                       }));
    }
    // 3. Zooming every frame, all of it in view: every tile rebuilt, every frame.
    {
      auto &phase = run_phase("zooming, all in view");
      co_await scope.spawn(for_a_while(scope, phase,
                                       [&](int i)
                                       {
                                         zoom_about({double(viewport.width) / 2, double(viewport.height) / 2}, fit * (1.0f + 0.15f * std::sin(float(i) * 0.05f)));
                                         pan_x = 4;
                                         pan_y = 40;
                                       }));
    }
    // 4. Dragging one chip, zoomed out: one tile rebuilt a frame.
    {
      zoom = fit;
      pan_x = 4;
      pan_y = 40;
      selected = tiles[210].chips[250].id;
      selected_tile = 210;
      auto &phase = run_phase("dragging a chip, all in view");
      co_await scope.spawn(for_a_while(scope, phase, [&](int i) { move_selected(2400 + 600 * std::sin(float(i) * 0.02f), 1800 + 400 * std::cos(float(i) * 0.02f)); }));
    }
    // 5. Typing into a chip's label, zoomed in.
    {
      zoom = 4;
      auto *chip = selected_chip();
      pan_x = float(viewport.width) / 2 - chip->x * zoom;
      pan_y = float(viewport.height) / 2 - chip->y * zoom;
      auto &phase = run_phase("typing into a label, zoomed in");
      co_await scope.spawn(for_a_while(scope, phase, [&](int i) { edit(i % 12 == 11 ? std::string_view{} : std::string_view{"x"}, i % 12 == 11); }));
    }

    std::printf("\n%-34s %7s %8s %8s %8s %8s %8s %8s %8s %9s\n", "workload", "frames", "fps", "p95 ms", "views", "layout", "list", "render", "cpu", "prims");
    for (const auto &phase : phases)
    {
      std::vector<double> intervals;
      double views = 0, layout = 0, list = 0, render = 0;
      std::size_t prims = 0;
      for (const auto &s : phase.samples)
      {
        intervals.push_back(s.interval_ms);
        views += s.views_ms;
        layout += s.layout_ms;
        list += s.list_ms;
        render += s.render_ms;
        prims = std::max(prims, s.prims);
      }
      const double n = std::max<double>(1, double(phase.samples.size()));
      const double median = percentile(intervals, 0.5);
      std::printf("%-34s %7zu %8.1f %8.2f %8.2f %8.2f %8.2f %8.2f %8.2f %9zu\n", phase.name, phase.samples.size(), median > 0 ? 1000.0 / median : 0.0, percentile(intervals, 0.95), views / n, layout / n, list / n,
                  render / n, (views + layout + list + render) / n, prims);
    }
    std::printf("(ms are CPU time per frame on the loop thread, averaged; fps from the median interval)\n");
    std::fflush(stdout);
    scope.window().close();
    co_return 0;
  }
};
} // namespace

int main(int argc, char **argv)
{
  const bool bench = argc > 1 && std::strcmp(argv[1], "--bench") == 0;
  // `--zoom 12` starts that far in, at the middle of the grid.
  const float start_zoom = argc > 2 && std::strcmp(argv[1], "--zoom") == 0 ? float(std::atof(argv[2])) : 0;
  const auto limit = std::chrono::milliseconds(!bench && start_zoom == 0 && argc > 1 ? std::atoi(argv[1]) : 0);
  return vio::run(
    [bench, limit, start_zoom](vio::event_loop_t &loop) -> vio::task_t<int>
    {
      auto display = gui::display_t::open(loop);
      if (!display)
      {
        std::fprintf(stderr, "no display: %s\n", display.error().msg.c_str());
        co_return 1;
      }
      {
        auto window = gui::window_t::create(*display, {.title = "vio ui: 200,000 chips", .size = {1400, 900}});
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
        auto scene = std::make_unique<scene_t>();
        scene->bench = bench;
        if (start_zoom > 0)
        {
          scene->zoom = std::clamp(start_zoom, 0.1f, 24.0f);
          scene->pan_x = 900 - columns * pitch_x / 2 * scene->zoom;
          scene->pan_y = 500 - rows * pitch_y / 2 * scene->zoom;
        }
        ui::run_config_t config;
        config.on_renderer = [](std::string_view what) { std::fprintf(stderr, "renderer: %.*s\n", int(what.size()), what.data()); };
        config.on_stats = [](const ui::frame_stats_t &s) { stats.add(s); };
        co_await ui::run(*window, *scene, std::move(config));
        if (!bench)
          co_await std::move(closing);
      }
      co_return 0;
    });
}
