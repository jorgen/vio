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

#include "ui_text.h"

#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <unordered_map>

#include <ft2build.h>
#include FT_FREETYPE_H
#include FT_OUTLINE_H

#include <hb.h>

namespace vio::gui::ui
{
namespace detail
{
// What a font_t shares: the file's bytes and HarfBuzz's face over them. Both are immutable once
// made, and an hb_face_t is safe to use from any thread, which is what lets font_t be shared.
struct font_data_t
{
  std::vector<std::byte> bytes;
  hb_face_t *face = nullptr;

  font_data_t() = default;
  font_data_t(const font_data_t &) = delete;
  font_data_t &operator=(const font_data_t &) = delete;
  ~font_data_t()
  {
    if (face)
      hb_face_destroy(face);
  }
};
} // namespace detail

// ---- font_t

std::expected<font_t, std::string> font_t::from_memory(std::vector<std::byte> bytes)
{
  auto data = std::make_shared<detail::font_data_t>();
  data->bytes = std::move(bytes);
  if (data->bytes.empty())
    return std::unexpected(std::string("empty font data"));
  auto *blob = hb_blob_create(reinterpret_cast<const char *>(data->bytes.data()), unsigned(data->bytes.size()), HB_MEMORY_MODE_READONLY, nullptr, nullptr);
  data->face = hb_face_create(blob, 0);
  hb_blob_destroy(blob);
  if (hb_face_get_glyph_count(data->face) == 0)
    return std::unexpected(std::string("not a TrueType or OpenType font"));
  return font_t(std::move(data));
}

std::expected<font_t, std::string> font_t::from_file(const std::string &path)
{
  std::ifstream file(path, std::ios::binary);
  if (!file)
    return std::unexpected("cannot open " + path);
  std::vector<char> raw((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
  std::vector<std::byte> bytes(raw.size());
  std::memcpy(bytes.data(), raw.data(), raw.size());
  auto font = from_memory(std::move(bytes));
  if (!font)
    return std::unexpected(path + ": " + font.error());
  return font;
}

std::expected<font_t, std::string> font_t::system_default()
{
  std::vector<std::string> candidates;
#if defined(_WIN32)
  const char *windir = std::getenv("WINDIR");
  const std::string fonts = std::string(windir ? windir : "C:\\Windows") + "\\Fonts\\";
  candidates = {fonts + "segoeui.ttf", fonts + "arial.ttf"};
#elif defined(__APPLE__)
  candidates = {"/System/Library/Fonts/SFNS.ttf", "/System/Library/Fonts/Helvetica.ttc", "/System/Library/Fonts/Geneva.ttf"};
#else
  for (const char *dir : {"/usr/share/fonts/truetype/", "/usr/share/fonts/TTF/", "/usr/share/fonts/", "/usr/local/share/fonts/"})
  {
    for (const char *name : {"dejavu/DejaVuSans.ttf", "DejaVuSans.ttf", "noto/NotoSans-Regular.ttf", "NotoSans-Regular.ttf", "google-noto/NotoSans-Regular.ttf", "liberation/LiberationSans-Regular.ttf",
                             "LiberationSans-Regular.ttf", "liberation-sans/LiberationSans-Regular.ttf"})
      candidates.push_back(std::string(dir) + name);
  }
#endif
  for (const auto &path : candidates)
  {
    if (auto font = from_file(path))
      return font;
  }
  return std::unexpected(std::string("no system UI font at any known path"));
}

// ---- path_t

path_t &path_t::move_to(float x, float y)
{
  close();
  _points.push_back({x, y, tag_t::on});
  return *this;
}

path_t &path_t::line_to(float x, float y)
{
  _points.push_back({x, y, tag_t::on});
  return *this;
}

path_t &path_t::quad_to(float cx, float cy, float x, float y)
{
  _points.push_back({cx, cy, tag_t::quad_control});
  _points.push_back({x, y, tag_t::on});
  return *this;
}

path_t &path_t::cubic_to(float c1x, float c1y, float c2x, float c2y, float x, float y)
{
  _points.push_back({c1x, c1y, tag_t::cubic_control});
  _points.push_back({c2x, c2y, tag_t::cubic_control});
  _points.push_back({x, y, tag_t::on});
  return *this;
}

path_t &path_t::close()
{
  const std::size_t start = _ends.empty() ? 0 : _ends.back();
  if (_points.size() > start)
    _ends.push_back(_points.size());
  return *this;
}

namespace detail
{
namespace
{
// The atlas grows from 512 square by doubling to this, and past it is emptied (G39).
constexpr int atlas_initial = 512;
constexpr int atlas_largest = 4096;
// Four horizontal subpixel positions per glyph (G27).
constexpr int subpixel_bins = 4;

struct glyph_key_t
{
  const font_data_t *font = nullptr;
  std::int32_t px64 = 0;
  std::uint32_t glyph = 0;
  std::uint32_t bin = 0;
  friend bool operator==(const glyph_key_t &, const glyph_key_t &) = default;
};

struct icon_key_t
{
  const path_t *path = nullptr;
  std::int32_t px64 = 0;
  friend bool operator==(const icon_key_t &, const icon_key_t &) = default;
};

struct key_hash_t
{
  static std::size_t mix(std::size_t seed, std::size_t value) noexcept
  {
    return seed ^ (value + 0x9e3779b97f4a7c15ull + (seed << 6) + (seed >> 2));
  }
  std::size_t operator()(const glyph_key_t &k) const noexcept
  {
    std::size_t h = std::hash<const void *>()(k.font);
    h = mix(h, std::size_t(k.px64));
    h = mix(h, k.glyph);
    return mix(h, k.bin);
  }
  std::size_t operator()(const icon_key_t &k) const noexcept
  {
    return mix(std::hash<const void *>()(k.path), std::size_t(k.px64));
  }
};

// Where a rasterized glyph sits in the atlas, and where its top left is from the pen on the
// baseline, in pixels with y down.
struct cached_t
{
  int x = 0;
  int y = 0;
  int width = 0;
  int height = 0;
  int left = 0;
  int top = 0;
};

struct sized_key_t
{
  const font_data_t *font = nullptr;
  std::int32_t px64 = 0;
  friend bool operator==(const sized_key_t &, const sized_key_t &) = default;
};

struct sized_hash_t
{
  std::size_t operator()(const sized_key_t &k) const noexcept
  {
    return key_hash_t::mix(std::hash<const void *>()(k.font), std::size_t(k.px64));
  }
};

int ceil_div(int value, int by) noexcept
{
  return (value + by - 1) / by;
}
} // namespace

struct text_engine_t::impl_t
{
  FT_Library library = nullptr;
  hb_buffer_t *buffer = nullptr;
  float scale = 1;

  struct face_t
  {
    font_t font; // keeps the bytes FreeType reads alive
    FT_Face face = nullptr;
    std::int32_t px64 = 0;
  };
  std::unordered_map<const font_data_t *, face_t> faces;
  std::unordered_map<sized_key_t, hb_font_t *, sized_hash_t> sized;

  // The atlas: shelves of rows, each as tall as the first glyph put on it.
  struct shelf_t
  {
    int y = 0;
    int height = 0;
    int x = 0;
  };
  std::vector<std::uint8_t> pixels;
  int width = 0;
  int height = 0;
  std::vector<shelf_t> shelves;
  int next_y = 0;
  rect_t dirty;
  std::uint64_t generation = 0;
  bool reset = false;

  std::unordered_map<glyph_key_t, cached_t, key_hash_t> glyphs;
  std::unordered_map<icon_key_t, cached_t, key_hash_t> icons;
  std::vector<std::shared_ptr<const path_t>> icon_paths; // keep the keys' addresses from being reused

  impl_t()
  {
    FT_Init_FreeType(&library);
    buffer = hb_buffer_create();
  }

  ~impl_t()
  {
    for (auto &[key, font] : sized)
      hb_font_destroy(font);
    for (auto &[key, face] : faces)
      FT_Done_Face(face.face);
    hb_buffer_destroy(buffer);
    if (library)
      FT_Done_FreeType(library);
  }

  face_t *face_for(const font_t &font)
  {
    auto it = faces.find(font.data());
    if (it != faces.end())
      return &it->second;
    if (!library)
      return nullptr;
    face_t entry;
    entry.font = font;
    const auto &bytes = font.data()->bytes;
    if (FT_New_Memory_Face(library, reinterpret_cast<const FT_Byte *>(bytes.data()), FT_Long(bytes.size()), 0, &entry.face) != 0)
      return nullptr;
    return &faces.emplace(font.data(), std::move(entry)).first->second;
  }

  hb_font_t *sized_font(const font_t &font, std::int32_t px64)
  {
    const sized_key_t key{font.data(), px64};
    auto it = sized.find(key);
    if (it != sized.end())
      return it->second;
    // HarfBuzz's own OpenType font functions, scaled so positions come back in 26.6 pixels.
    auto *hb = hb_font_create(font.data()->face);
    hb_font_set_scale(hb, px64, px64);
    sized.emplace(key, hb);
    return hb;
  }

  // ---- the atlas
  void empty_atlas()
  {
    std::fill(pixels.begin(), pixels.end(), std::uint8_t(0));
    shelves.clear();
    next_y = 0;
    glyphs.clear();
    icons.clear();
    icon_paths.clear();
    dirty = {};
    ++generation;
  }

  void grow(int side)
  {
    std::vector<std::uint8_t> grown(std::size_t(side) * side, 0);
    for (int row = 0; row < height; ++row)
      std::memcpy(&grown[std::size_t(row) * side], &pixels[std::size_t(row) * width], std::size_t(width));
    pixels = std::move(grown);
    width = height = side;
    dirty = {};
    ++generation;
  }

  bool place(int w, int h, int &x, int &y)
  {
    // One texel of space around each rectangle; the shader reads texels exactly, but a neighbour
    // touching it would show at any scale where rounding nudges a quad.
    const int pw = w + 1;
    const int ph = h + 1;
    for (auto &shelf : shelves)
    {
      if (ph <= shelf.height && ph * 4 >= shelf.height * 3 && shelf.x + pw <= width)
      {
        x = shelf.x;
        y = shelf.y;
        shelf.x += pw;
        return true;
      }
    }
    if (next_y + ph <= height && pw <= width)
    {
      shelves.push_back({next_y, ph, pw});
      x = 0;
      y = next_y;
      next_y += ph;
      return true;
    }
    return false;
  }

  bool allocate(int w, int h, int &x, int &y)
  {
    if (width == 0)
      grow(atlas_initial);
    while (!place(w, h, x, y))
    {
      if (width >= atlas_largest)
      {
        if (reset || w + 1 > width || h + 1 > height)
          return false; // a second fill in one layout, or a glyph larger than the atlas: drop it
        empty_atlas();
        reset = true;
        continue;
      }
      grow(width * 2);
    }
    return true;
  }

  void store(const std::uint8_t *source, int pitch, int w, int h, cached_t &into)
  {
    if (!allocate(w, h, into.x, into.y))
    {
      into.width = into.height = 0;
      return;
    }
    for (int row = 0; row < h; ++row)
      std::memcpy(&pixels[std::size_t(into.y + row) * width + into.x], source + std::ptrdiff_t(row) * pitch, std::size_t(w));
    into.width = w;
    into.height = h;
    const rect_t added{into.x, into.y, w, h};
    if (dirty.width == 0 || dirty.height == 0)
      dirty = added;
    else
    {
      const int x0 = std::min(dirty.x, added.x);
      const int y0 = std::min(dirty.y, added.y);
      const int x1 = std::max(dirty.x + dirty.width, added.x + added.width);
      const int y1 = std::max(dirty.y + dirty.height, added.y + added.height);
      dirty = {x0, y0, x1 - x0, y1 - y0};
    }
  }

  // ---- rasterizing
  const cached_t &glyph(const font_t &font, std::int32_t px64, std::uint32_t id, std::uint32_t bin)
  {
    const glyph_key_t key{font.data(), px64, id, bin};
    if (auto it = glyphs.find(key); it != glyphs.end())
      return it->second;
    cached_t cached;
    if (auto *face = face_for(font))
    {
      if (face->px64 != px64)
      {
        FT_Set_Char_Size(face->face, 0, px64, 72, 72);
        face->px64 = px64;
      }
      // Light hinting moves outlines vertically only, so HarfBuzz's unhinted advances still fit
      // them; the subpixel offset is applied to the outline before it is rendered.
      if (FT_Load_Glyph(face->face, id, FT_LOAD_TARGET_LIGHT | FT_LOAD_NO_BITMAP) == 0 && face->face->glyph->format == FT_GLYPH_FORMAT_OUTLINE)
      {
        auto *slot = face->face->glyph;
        FT_Outline_Translate(&slot->outline, FT_Pos(bin * 64 / subpixel_bins), 0);
        if (FT_Render_Glyph(slot, FT_RENDER_MODE_NORMAL) == 0 && slot->bitmap.width > 0 && slot->bitmap.rows > 0)
        {
          const auto &bitmap = slot->bitmap;
          store(bitmap.buffer, bitmap.pitch, int(bitmap.width), int(bitmap.rows), cached);
          cached.left = slot->bitmap_left;
          cached.top = -slot->bitmap_top;
        }
      }
    }
    return glyphs.emplace(key, cached).first->second;
  }

  const cached_t &icon(const std::shared_ptr<const path_t> &path, std::int32_t px64, int side)
  {
    const icon_key_t key{path.get(), px64};
    if (auto it = icons.find(key); it != icons.end())
      return it->second;
    cached_t cached;
    const auto points = path->points();
    std::vector<std::size_t> ends(path->ends().begin(), path->ends().end());
    if (ends.empty() ? !points.empty() : ends.back() < points.size())
      ends.push_back(points.size());
    FT_Outline outline{};
    if (library && !points.empty() && side > 0 && FT_Outline_New(library, FT_UInt(points.size()), FT_Int(ends.size()), &outline) == 0)
    {
      const float px = float(px64) / 64.0f;
      for (std::size_t i = 0; i < points.size(); ++i)
      {
        // Unit square, y down, to 26.6 pixels with y up and the bitmap's bottom at zero.
        outline.points[i].x = FT_Pos(std::lround(points[i].x * px * 64.0f));
        outline.points[i].y = FT_Pos(std::lround((float(side) - points[i].y * px) * 64.0f));
        const auto tag = points[i].tag;
        using tag_type = std::remove_reference_t<decltype(*outline.tags)>;
        outline.tags[i] = tag_type(tag == path_t::tag_t::on ? FT_CURVE_TAG_ON : tag == path_t::tag_t::quad_control ? FT_CURVE_TAG_CONIC : FT_CURVE_TAG_CUBIC);
      }
      using contour_type = std::remove_reference_t<decltype(*outline.contours)>;
      for (std::size_t i = 0; i < ends.size(); ++i)
        outline.contours[i] = contour_type(ends[i] - 1);
      outline.flags = path->even_odd ? FT_OUTLINE_EVEN_ODD_FILL : FT_OUTLINE_NONE;
      std::vector<std::uint8_t> raster(std::size_t(side) * side, 0);
      FT_Bitmap bitmap{};
      bitmap.rows = unsigned(side);
      bitmap.width = unsigned(side);
      bitmap.pitch = side;
      bitmap.buffer = raster.data();
      bitmap.num_grays = 256;
      bitmap.pixel_mode = FT_PIXEL_MODE_GRAY;
      if (FT_Outline_Get_Bitmap(library, &outline, &bitmap) == 0)
        store(raster.data(), side, side, side, cached);
      FT_Outline_Done(library, &outline);
    }
    icon_paths.push_back(path);
    return icons.emplace(key, cached).first->second;
  }
};

text_engine_t::text_engine_t()
  : _impl(std::make_unique<impl_t>())
{
}

text_engine_t::~text_engine_t() = default;

void text_engine_t::set_scale(float scale)
{
  if (scale == _impl->scale)
    return;
  _impl->scale = scale;
  if (_impl->width > 0)
    _impl->empty_atlas();
}

text_engine_t::laid_out_t text_engine_t::add_text(const text_t &text, const font_t &fallback, float x, float y, std::vector<prim_t> &out)
{
  auto &impl = *_impl;
  const font_t &font = text.font ? text.font : fallback;
  if (!font || text.size <= 0)
    return {};
  const float scale = impl.scale;
  const auto px64 = std::int32_t(std::lround(text.size * scale * 64.0f));
  auto *hb = impl.sized_font(font, px64);
  hb_font_extents_t extents{};
  hb_font_get_h_extents(hb, &extents);
  // The baseline sits on a whole pixel, the ascender above it rounded up.
  const int baseline = ceil_div(std::max(extents.ascender, 0), 64);
  const int below = ceil_div(std::max(-extents.descender, 0), 64);

  hb_buffer_reset(impl.buffer);
  hb_buffer_add_utf8(impl.buffer, text.text.data(), int(text.text.size()), 0, int(text.text.size()));
  hb_buffer_guess_segment_properties(impl.buffer);
  hb_shape(hb, impl.buffer, nullptr, 0);
  unsigned count = 0;
  const auto *infos = hb_buffer_get_glyph_infos(impl.buffer, &count);
  const auto *positions = hb_buffer_get_glyph_positions(impl.buffer, &count);

  // Glyphs come back in visual order, left to right, whatever the direction.
  std::int64_t pen = 0;
  for (unsigned i = 0; i < count; ++i)
  {
    const std::int64_t at = pen + positions[i].x_offset;
    const std::int64_t whole = at >= 0 ? at / 64 : -((-at + 63) / 64);
    const auto bin = std::uint32_t(((at - whole * 64) * subpixel_bins) / 64);
    const auto &cached = impl.glyph(font, px64, infos[i].codepoint, bin);
    pen += positions[i].x_advance;
    if (cached.width == 0)
      continue;
    prim_t prim;
    prim.kind = prim_kind_t::coverage;
    prim.x = x;
    prim.y = y;
    prim.width = float(cached.width);
    prim.height = float(cached.height);
    prim.radii[0] = float(cached.x);
    prim.radii[1] = float(cached.y);
    prim.radii[2] = float(whole + cached.left);
    prim.radii[3] = float(baseline + cached.top - int(std::lround(positions[i].y_offset / 64.0)));
    prim.fill = text.color;
    out.push_back(prim);
  }
  const int width_px = int(ceil_div(int(std::max<std::int64_t>(pen, 0)), 64));
  const int height_px = baseline + below;
  return {{int(std::ceil(width_px / scale - 1e-3f)), int(std::ceil(height_px / scale - 1e-3f))}, float(baseline) / scale};
}

extent_t text_engine_t::add_icon(const icon_t &icon, float x, float y, std::vector<prim_t> &out)
{
  auto &impl = *_impl;
  const int logical = int(std::ceil(icon.size - 1e-3f));
  if (!icon.path || icon.size <= 0)
    return {logical, logical};
  const float px = icon.size * impl.scale;
  const auto px64 = std::int32_t(std::lround(px * 64.0f));
  const int side = int(std::ceil(px - 1e-3f));
  const auto &cached = impl.icon(icon.path, px64, side);
  if (cached.width > 0)
  {
    prim_t prim;
    prim.kind = prim_kind_t::coverage;
    prim.x = x;
    prim.y = y;
    prim.width = float(cached.width);
    prim.height = float(cached.height);
    prim.radii[0] = float(cached.x);
    prim.radii[1] = float(cached.y);
    prim.fill = icon.color;
    out.push_back(prim);
  }
  return {logical, logical};
}

bool text_engine_t::take_reset() noexcept
{
  return std::exchange(_impl->reset, false);
}

atlas_view_t text_engine_t::atlas() const noexcept
{
  const auto &impl = *_impl;
  return {impl.pixels, {impl.width, impl.height}, impl.dirty, impl.generation};
}

void text_engine_t::clear_dirty() noexcept
{
  _impl->dirty = {};
}

std::vector<shaped_glyph_t> text_engine_t::shape(const font_t &font, float pixels, std::string_view text)
{
  std::vector<shaped_glyph_t> out;
  if (!font)
    return out;
  auto *hb = _impl->sized_font(font, std::int32_t(std::lround(pixels * 64.0f)));
  auto *buffer = _impl->buffer;
  hb_buffer_reset(buffer);
  hb_buffer_add_utf8(buffer, text.data(), int(text.size()), 0, int(text.size()));
  hb_buffer_guess_segment_properties(buffer);
  hb_shape(hb, buffer, nullptr, 0);
  unsigned count = 0;
  const auto *infos = hb_buffer_get_glyph_infos(buffer, &count);
  const auto *positions = hb_buffer_get_glyph_positions(buffer, &count);
  std::int64_t pen = 0;
  for (unsigned i = 0; i < count; ++i)
  {
    out.push_back({infos[i].codepoint, float(pen + positions[i].x_offset) / 64.0f, -float(positions[i].y_offset) / 64.0f});
    pen += positions[i].x_advance;
  }
  return out;
}

std::uint32_t text_engine_t::nominal_glyph(const font_t &font, char32_t codepoint)
{
  if (!font)
    return 0;
  auto *hb = hb_font_create(font.data()->face);
  hb_codepoint_t glyph = 0;
  hb_font_get_nominal_glyph(hb, codepoint, &glyph);
  hb_font_destroy(hb);
  return glyph;
}
} // namespace detail
} // namespace vio::gui::ui
