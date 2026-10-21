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

#include <cstring>
#include <string_view>

#include "vio/gui/backends.h"
#include "vio/gui/context.h"

namespace vio::gui
{
namespace detail
{
std::expected<std::unique_ptr<gl_impl_t>, int> make_egl_context(window_impl_t &window, const gl_config_t &config);
std::expected<std::unique_ptr<gl_impl_t>, int> make_wgl_context(window_impl_t &window, const gl_config_t &config);
std::expected<std::unique_ptr<gl_impl_t>, int> make_cgl_context(window_impl_t &window, const gl_config_t &config);

std::expected<std::unique_ptr<gl_impl_t>, int> make_gl_context(window_impl_t &window, const gl_config_t &config)
{
  switch (window.display.backend->platform())
  {
#if defined(VIO_GUI_HAVE_X11) || defined(VIO_GUI_HAVE_WAYLAND)
  case platform_t::x11:
  case platform_t::wayland:
    return make_egl_context(window, config);
#endif
#if defined(_WIN32)
  case platform_t::win32:
    return make_wgl_context(window, config);
#endif
#if defined(__APPLE__)
  case platform_t::cocoa:
    return make_cgl_context(window, config);
#endif
  default:
    return std::unexpected(errc::not_supported);
  }
}

namespace
{
constexpr std::intptr_t cl_context_platform = 0x1084;
constexpr unsigned gl_extensions = 0x1F03;
constexpr unsigned gl_num_extensions = 0x821D;
constexpr unsigned gl_device_uuid_ext = 0x9597;

using vk_result_t = std::int32_t;
using vk_create_surface_t = vk_result_t (*)(void *, const void *, const void *, std::uint64_t *);

struct vk_xlib_surface_info_t
{
  std::int32_t type = 1000004000;
  const void *next = nullptr;
  std::uint32_t flags = 0;
  void *display = nullptr;
  unsigned long window = 0;
};

struct vk_wayland_surface_info_t
{
  std::int32_t type = 1000006000;
  const void *next = nullptr;
  std::uint32_t flags = 0;
  void *display = nullptr;
  void *surface = nullptr;
};

struct vk_win32_surface_info_t
{
  std::int32_t type = 1000009000;
  const void *next = nullptr;
  std::uint32_t flags = 0;
  void *instance = nullptr;
  void *window = nullptr;
};

struct vk_metal_surface_info_t
{
  std::int32_t type = 1000217000;
  const void *next = nullptr;
  std::uint32_t flags = 0;
  const void *layer = nullptr;
};

struct vk_id_properties_t
{
  std::int32_t type = 1000071004;
  void *next = nullptr;
  std::uint8_t device_uuid[16] = {};
  std::uint8_t driver_uuid[16] = {};
  std::uint8_t device_luid[8] = {};
  std::uint32_t device_node_mask = 0;
  std::uint32_t device_luid_valid = 0;
};

struct vk_properties2_t
{
  std::int32_t type = 1000059001;
  void *next = nullptr;
  alignas(8) unsigned char properties[2048] = {};
};

template <typename Function>
Function vk_proc(vulkan::get_instance_proc_addr_t get, void *instance, const char *name)
{
  return reinterpret_cast<Function>(get(instance, name));
}
} // namespace
} // namespace detail

std::expected<gl_context_t, error_t> gl_context_t::create(window_t &window, const gl_config_t &config)
{
  if (!window)
    return std::unexpected(make_error(errc::canceled));
  auto made = detail::make_gl_context(*window.impl(), config);
  if (!made)
    return std::unexpected(make_error(made.error()));
  gl_context_t context;
  context._impl = std::move(*made);
  return context;
}

std::expected<void, error_t> gl_context_t::make_current()
{
  if (!_impl)
    return std::unexpected(make_error(errc::canceled));
  if (int result = _impl->make_current(); result < 0)
    return std::unexpected(make_error(result));
  return {};
}

void gl_context_t::release_current()
{
  if (_impl)
    _impl->release_current();
}

std::expected<void, error_t> gl_context_t::swap_buffers()
{
  if (!_impl)
    return std::unexpected(make_error(errc::canceled));
  if (int result = _impl->swap_buffers(); result < 0)
    return std::unexpected(make_error(result));
  return {};
}

std::expected<void, error_t> gl_context_t::set_swap_interval(int interval)
{
  if (!_impl)
    return std::unexpected(make_error(errc::canceled));
  if (int result = _impl->set_swap_interval(interval); result < 0)
    return std::unexpected(make_error(result));
  return {};
}

void *gl_context_t::proc_address(const char *name) const
{
  return _impl ? _impl->proc_address(name) : nullptr;
}

gl_native_t gl_context_t::native() const
{
  return _impl ? _impl->native() : gl_native_t{};
}

std::vector<std::intptr_t> gl_context_t::opencl_properties(void *platform) const
{
  std::vector<std::intptr_t> properties;
  if (!_impl)
    return properties;
  if (platform)
  {
    properties.push_back(detail::cl_context_platform);
    properties.push_back(reinterpret_cast<std::intptr_t>(platform));
  }
  auto shared = _impl->opencl_properties();
  properties.insert(properties.end(), shared.begin(), shared.end());
  properties.push_back(0);
  return properties;
}

std::expected<std::array<std::uint8_t, 16>, error_t> gl_context_t::device_uuid() const
{
  if (!_impl)
    return std::unexpected(make_error(errc::canceled));
  if (int result = _impl->make_current(); result < 0)
    return std::unexpected(make_error(result));
  using get_integer_t = void (*)(unsigned, int *);
  using get_string_i_t = const unsigned char *(*)(unsigned, unsigned);
  using get_string_t = const unsigned char *(*)(unsigned);
  using get_unsigned_bytes_t = void (*)(unsigned, unsigned, std::uint8_t *);
  auto get_integer = proc<get_integer_t>("glGetIntegerv");
  auto get_string_i = proc<get_string_i_t>("glGetStringi");
  auto get_string = proc<get_string_t>("glGetString");
  auto get_bytes = proc<get_unsigned_bytes_t>("glGetUnsignedBytei_vEXT");
  bool supported = false;
  if (get_integer && get_string_i)
  {
    int count = 0;
    get_integer(detail::gl_num_extensions, &count);
    for (int i = 0; i < count && !supported; ++i)
    {
      const auto *name = get_string_i(detail::gl_extensions, static_cast<unsigned>(i));
      supported = name && std::string_view(reinterpret_cast<const char *>(name)) == "GL_EXT_memory_object";
    }
  }
  else if (get_string)
  {
    const auto *all = get_string(detail::gl_extensions);
    supported = all && std::string_view(reinterpret_cast<const char *>(all)).find("GL_EXT_memory_object") != std::string_view::npos;
  }
  if (!supported || !get_bytes)
    return std::unexpected(make_error(errc::not_supported));
  std::array<std::uint8_t, 16> uuid{};
  get_bytes(detail::gl_device_uuid_ext, 0, uuid.data());
  return uuid;
}

namespace vulkan
{
std::vector<const char *> required_instance_extensions(const display_t &display)
{
  if (!display)
    return {};
  switch (display.platform())
  {
  case platform_t::x11:
    return {"VK_KHR_surface", "VK_KHR_xlib_surface"};
  case platform_t::wayland:
    return {"VK_KHR_surface", "VK_KHR_wayland_surface"};
  case platform_t::win32:
    return {"VK_KHR_surface", "VK_KHR_win32_surface"};
  case platform_t::cocoa:
    return {"VK_KHR_surface", "VK_EXT_metal_surface"};
  }
  return {};
}

std::expected<std::uint64_t, error_t> create_surface(window_t &window, void *instance, get_instance_proc_addr_t get_instance_proc_addr, const void *allocator)
{
  if (!window)
    return std::unexpected(make_error(errc::canceled));
  if (!instance || !get_instance_proc_addr)
    return std::unexpected(make_error(errc::invalid_argument));
  const auto native = window.native();
  std::uint64_t surface = 0;
  detail::vk_result_t result = -7;
  switch (native.platform)
  {
  case platform_t::x11:
  {
    auto create = detail::vk_proc<detail::vk_create_surface_t>(get_instance_proc_addr, instance, "vkCreateXlibSurfaceKHR");
    if (!create)
      return std::unexpected(make_error(errc::not_supported));
    detail::vk_xlib_surface_info_t info;
    info.display = native.display;
    info.window = static_cast<unsigned long>(native.id);
    result = create(instance, &info, allocator, &surface);
    break;
  }
  case platform_t::wayland:
  {
    auto create = detail::vk_proc<detail::vk_create_surface_t>(get_instance_proc_addr, instance, "vkCreateWaylandSurfaceKHR");
    if (!create)
      return std::unexpected(make_error(errc::not_supported));
    detail::vk_wayland_surface_info_t info;
    info.display = native.display;
    info.surface = native.handle;
    result = create(instance, &info, allocator, &surface);
    break;
  }
  case platform_t::win32:
  {
    auto create = detail::vk_proc<detail::vk_create_surface_t>(get_instance_proc_addr, instance, "vkCreateWin32SurfaceKHR");
    if (!create)
      return std::unexpected(make_error(errc::not_supported));
    detail::vk_win32_surface_info_t info;
    info.instance = native.display;
    info.window = native.handle;
    result = create(instance, &info, allocator, &surface);
    break;
  }
  case platform_t::cocoa:
  {
    auto create = detail::vk_proc<detail::vk_create_surface_t>(get_instance_proc_addr, instance, "vkCreateMetalSurfaceEXT");
    if (!create)
      return std::unexpected(make_error(errc::not_supported));
    auto layer = metal::create_layer(window);
    if (!layer)
      return std::unexpected(layer.error());
    detail::vk_metal_surface_info_t info;
    info.layer = *layer;
    result = create(instance, &info, allocator, &surface);
    break;
  }
  }
  if (result != 0)
    return std::unexpected(make_error(errc::not_supported));
  return surface;
}

std::expected<std::array<std::uint8_t, 16>, error_t> device_uuid(void *instance, void *physical_device, get_instance_proc_addr_t get_instance_proc_addr)
{
  if (!instance || !physical_device || !get_instance_proc_addr)
    return std::unexpected(make_error(errc::invalid_argument));
  using get_properties2_t = void (*)(void *, void *);
  auto get = detail::vk_proc<get_properties2_t>(get_instance_proc_addr, instance, "vkGetPhysicalDeviceProperties2");
  if (!get)
    get = detail::vk_proc<get_properties2_t>(get_instance_proc_addr, instance, "vkGetPhysicalDeviceProperties2KHR");
  if (!get)
    return std::unexpected(make_error(errc::not_supported));
  detail::vk_id_properties_t ids;
  detail::vk_properties2_t properties;
  properties.next = &ids;
  get(physical_device, &properties);
  std::array<std::uint8_t, 16> uuid{};
  std::memcpy(uuid.data(), ids.device_uuid, uuid.size());
  return uuid;
}
} // namespace vulkan

#if !defined(__APPLE__)
namespace metal
{
std::expected<void *, error_t> create_layer(window_t &)
{
  return std::unexpected(make_error(errc::not_supported));
}
} // namespace metal
#endif

#if !defined(_WIN32)
namespace d3d12
{
std::expected<void *, error_t> create_swap_chain(window_t &, void *, const swap_chain_config_t &)
{
  return std::unexpected(make_error(errc::not_supported));
}

std::expected<void, error_t> resize_swap_chain(void *, extent_t)
{
  return std::unexpected(make_error(errc::not_supported));
}
} // namespace d3d12

std::expected<std::array<std::uint8_t, 8>, error_t> adapter_luid(window_t &)
{
  return std::unexpected(make_error(errc::not_supported));
}
#endif
} // namespace vio::gui
