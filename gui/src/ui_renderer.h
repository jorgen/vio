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

// The seam between the toolkit and a graphics API. A renderer is handed a whole display list each
// frame and draws all of it (PLAN.md, "Rendering"); it keeps nothing of the toolkit's.

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "vio/gui/ui/ui.h"

namespace vio::gui::ui::detail
{
class renderer_t
{
public:
  virtual ~renderer_t() = default;
  // Draw `list` and present it. Returns false once the renderer cannot draw any more (a lost
  // device, a surface that went away), so the caller can stop asking.
  virtual bool render(const display_list_t &list) = 0;
  // What draws, for run_config_t::on_renderer.
  [[nodiscard]] virtual std::string describe() const = 0;
};

// Each returns nullptr with `why` filled in when its API is unavailable here.
std::unique_ptr<renderer_t> make_vulkan_renderer(window_t &window, const std::optional<vulkan_device_t> &shared, std::string &why);
std::unique_ptr<renderer_t> make_gl_renderer(window_t &window, std::string &why);

// For tests: draw one display list into an image with no window and read it back, sRGB-encoded
// RGBA8, rows top to bottom. Runs wherever a Vulkan device does, lavapipe included.
struct offscreen_image_t
{
  std::vector<std::uint8_t> rgba;
  extent_t extent;
  std::string device;
};
std::optional<offscreen_image_t> render_offscreen_vulkan(const display_list_t &list, std::string &why);
} // namespace vio::gui::ui::detail
