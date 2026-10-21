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

#include <array>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <vector>

#include "vio/gui/gui.h"

namespace vio::gui
{
struct gl_config_t
{
  int major = 3;
  int minor = 3;
  bool core_profile = true;
  bool es = false;
  bool debug = false;
  int depth_bits = 24;
  int stencil_bits = 8;
  int samples = 0;
  bool srgb = false;
  bool vsync = true;
  bool transparent = false;
};

struct gl_native_t
{
  void *display = nullptr;
  void *context = nullptr;
  void *surface = nullptr;
  void *config = nullptr;
};

namespace detail
{
class gl_impl_t : public window_attachment_t
{
public:
  [[nodiscard]] virtual int make_current() = 0;
  [[nodiscard]] virtual int swap_buffers() = 0;
  virtual void release_current() = 0;
  [[nodiscard]] virtual void *proc_address(const char *name) const = 0;
  virtual int set_swap_interval(int interval) = 0;
  [[nodiscard]] virtual gl_native_t native() const = 0;
  [[nodiscard]] virtual std::vector<std::intptr_t> opencl_properties() const = 0;
};

std::expected<std::unique_ptr<gl_impl_t>, int> make_gl_context(window_impl_t &window, const gl_config_t &config);
} // namespace detail

class gl_context_t
{
public:
  gl_context_t() = default;
  gl_context_t(gl_context_t &&) noexcept = default;
  gl_context_t &operator=(gl_context_t &&) noexcept = default;
  ~gl_context_t() = default;

  static std::expected<gl_context_t, error_t> create(window_t &window, const gl_config_t &config = {});

  std::expected<void, error_t> make_current();
  void release_current();
  std::expected<void, error_t> swap_buffers();
  std::expected<void, error_t> set_swap_interval(int interval);
  [[nodiscard]] void *proc_address(const char *name) const;
  [[nodiscard]] gl_native_t native() const;

  template <typename Function>
  [[nodiscard]] Function proc(const char *name) const
  {
    return reinterpret_cast<Function>(proc_address(name));
  }

  [[nodiscard]] std::vector<std::intptr_t> opencl_properties(void *platform = nullptr) const;
  [[nodiscard]] std::expected<std::array<std::uint8_t, 16>, error_t> device_uuid() const;

  [[nodiscard]] explicit operator bool() const noexcept
  {
    return static_cast<bool>(_impl);
  }

private:
  std::unique_ptr<detail::gl_impl_t> _impl;
};

namespace vulkan
{
using get_instance_proc_addr_t = void (*(*)(void *instance, const char *name))();

[[nodiscard]] std::vector<const char *> required_instance_extensions(const display_t &display);
std::expected<std::uint64_t, error_t> create_surface(window_t &window, void *instance, get_instance_proc_addr_t get_instance_proc_addr, const void *allocator = nullptr);
std::expected<std::array<std::uint8_t, 16>, error_t> device_uuid(void *instance, void *physical_device, get_instance_proc_addr_t get_instance_proc_addr);
} // namespace vulkan

namespace metal
{
std::expected<void *, error_t> create_layer(window_t &window);
}

namespace d3d12
{
struct swap_chain_config_t
{
  unsigned buffer_count = 2;
  unsigned format = 28;
  bool allow_tearing = false;
};

std::expected<void *, error_t> create_swap_chain(window_t &window, void *command_queue, const swap_chain_config_t &config = {});
std::expected<void, error_t> resize_swap_chain(void *swap_chain, extent_t framebuffer);
} // namespace d3d12

std::expected<std::array<std::uint8_t, 8>, error_t> adapter_luid(window_t &window);
} // namespace vio::gui
