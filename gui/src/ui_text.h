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

#pragma once

// Text and icons for the toolkit (gui/PLAN.md, "Rendering"; G27, G39, G40): HarfBuzz shapes,
// FreeType rasterizes into a coverage atlas, and layout gets back coverage prims and a size.

#include <cstdint>
#include <memory>
#include <string_view>
#include <vector>

#include "vio/gui/ui/ui.h"

namespace vio::gui::ui::detail
{
// A shaped glyph: its id and pen position in pixels, y down. For tests.
struct shaped_glyph_t
{
  std::uint32_t glyph = 0;
  float x = 0;
  float y = 0;
};

// Everything about text that must not be shared between windows -- FreeType faces, HarfBuzz fonts
// at each size, the atlas and what is in it. One per runtime, used from its loop thread only.
class text_engine_t
{
public:
  text_engine_t();
  ~text_engine_t();
  text_engine_t(const text_engine_t &) = delete;
  text_engine_t &operator=(const text_engine_t &) = delete;

  // Glyphs are rasterized at size * scale pixels. A new scale empties the atlas.
  void set_scale(float scale);

  // Append the glyphs of `text` anchored at (x, y), in logical units, and return its size and its
  // baseline below the top: in logical units, and exactly a whole number of pixels, so moving the
  // anchor by the difference of two baselines lines them up to the pixel (G41).
  struct laid_out_t
  {
    extent_t size;
    float baseline = 0;
  };
  laid_out_t add_text(const text_t &text, const font_t &fallback, float x, float y, std::vector<prim_t> &out);
  extent_t add_icon(const icon_t &icon, float x, float y, std::vector<prim_t> &out);
  // A heatmap's values, quantized into the atlas -- again only when its data or range changed --
  // and the prim that draws them.
  void add_heatmap(const heatmap_t &map, float x, float y, std::vector<prim_t> &out);

  // True once after the atlas filled at its largest size and was emptied: prims made before that
  // name rectangles that are gone, so the caller lays everything out again.
  bool take_reset() noexcept;

  [[nodiscard]] atlas_view_t atlas() const noexcept;
  // The renderer has the atlas as it stands; start a new dirty rectangle.
  void clear_dirty() noexcept;

  std::vector<shaped_glyph_t> shape(const font_t &font, float pixels, std::string_view text);
  static std::uint32_t nominal_glyph(const font_t &font, char32_t codepoint);

private:
  struct impl_t;
  std::unique_ptr<impl_t> _impl;
};
} // namespace vio::gui::ui::detail
