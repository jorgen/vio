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

#include <array>
#include <cstdint>
#include <memory>
#include <vector>

#include <dlfcn.h>

#include "vio/gui/context.h"

namespace vio::gui::detail
{
namespace
{
using EGLint = std::int32_t;
using EGLBoolean = unsigned;
using EGLenum = unsigned;
using EGLDisplay = void *;
using EGLConfig = void *;
using EGLContext = void *;
using EGLSurface = void *;

constexpr EGLint egl_none = 0x3038;
constexpr EGLint egl_surface_type = 0x3033;
constexpr EGLint egl_window_bit = 0x0004;
constexpr EGLint egl_renderable_type = 0x3040;
constexpr EGLint egl_opengl_bit = 0x0008;
constexpr EGLint egl_opengl_es2_bit = 0x0004;
constexpr EGLint egl_opengl_es3_bit = 0x0040;
constexpr EGLint egl_red_size = 0x3024;
constexpr EGLint egl_green_size = 0x3023;
constexpr EGLint egl_blue_size = 0x3022;
constexpr EGLint egl_alpha_size = 0x3021;
constexpr EGLint egl_depth_size = 0x3025;
constexpr EGLint egl_stencil_size = 0x3026;
constexpr EGLint egl_sample_buffers = 0x3032;
constexpr EGLint egl_samples = 0x3031;
constexpr EGLint egl_native_visual_id = 0x302E;
constexpr EGLenum egl_platform_x11 = 0x31D5;
constexpr EGLenum egl_platform_wayland = 0x31D8;
constexpr EGLint egl_context_major_version = 0x3098;
constexpr EGLint egl_context_minor_version = 0x30FB;
constexpr EGLint egl_context_opengl_profile_mask = 0x30FD;
constexpr EGLint egl_context_opengl_core_profile_bit = 0x0001;
constexpr EGLint egl_context_opengl_compatibility_profile_bit = 0x0002;
constexpr EGLint egl_context_opengl_debug = 0x31B0;
constexpr EGLenum egl_opengl_api = 0x30A2;
constexpr EGLenum egl_opengl_es_api = 0x30A0;
constexpr EGLint egl_gl_colorspace = 0x309D;
constexpr EGLint egl_gl_colorspace_srgb = 0x3089;

constexpr std::intptr_t cl_gl_context_khr = 0x2008;
constexpr std::intptr_t cl_egl_display_khr = 0x2009;

struct egl_t
{
  void *library = nullptr;
  void *wayland_egl = nullptr;
  EGLDisplay display = nullptr;

  EGLDisplay (*get_platform_display)(EGLenum, void *, const std::intptr_t *) = nullptr;
  EGLBoolean (*initialize)(EGLDisplay, EGLint *, EGLint *) = nullptr;
  EGLBoolean (*terminate)(EGLDisplay) = nullptr;
  EGLBoolean (*bind_api)(EGLenum) = nullptr;
  EGLBoolean (*choose_config)(EGLDisplay, const EGLint *, EGLConfig *, EGLint, EGLint *) = nullptr;
  EGLBoolean (*get_config_attrib)(EGLDisplay, EGLConfig, EGLint, EGLint *) = nullptr;
  EGLContext (*create_context)(EGLDisplay, EGLConfig, EGLContext, const EGLint *) = nullptr;
  EGLBoolean (*destroy_context)(EGLDisplay, EGLContext) = nullptr;
  EGLSurface (*create_platform_window_surface)(EGLDisplay, EGLConfig, void *, const std::intptr_t *) = nullptr;
  EGLBoolean (*destroy_surface)(EGLDisplay, EGLSurface) = nullptr;
  EGLBoolean (*make_current)(EGLDisplay, EGLSurface, EGLSurface, EGLContext) = nullptr;
  EGLContext (*get_current_context)() = nullptr;
  EGLBoolean (*swap_buffers)(EGLDisplay, EGLSurface) = nullptr;
  EGLBoolean (*swap_interval)(EGLDisplay, EGLint) = nullptr;
  void (*(*get_proc_address)(const char *))() = nullptr;
  EGLint (*get_error)() = nullptr;

  void *(*wl_egl_window_create)(void *, int, int) = nullptr;
  void (*wl_egl_window_resize)(void *, int, int, int, int) = nullptr;
  void (*wl_egl_window_destroy)(void *) = nullptr;

  egl_t() = default;
  egl_t(const egl_t &) = delete;
  egl_t &operator=(const egl_t &) = delete;
  ~egl_t()
  {
    if (display && terminate)
      terminate(display);
  }

  template <typename T>
  bool load(T &slot, const char *name)
  {
    slot = reinterpret_cast<T>(dlsym(library, name));
    return slot != nullptr;
  }

  int open(platform_t platform, void *native_display)
  {
    library = dlopen("libEGL.so.1", RTLD_NOW | RTLD_LOCAL);
    if (!library)
      return errc::not_supported;
    bool ok = load(initialize, "eglInitialize") && load(terminate, "eglTerminate") && load(bind_api, "eglBindAPI") && load(choose_config, "eglChooseConfig") && load(get_config_attrib, "eglGetConfigAttrib") && load(create_context, "eglCreateContext") && load(destroy_context, "eglDestroyContext") && load(destroy_surface, "eglDestroySurface") && load(make_current, "eglMakeCurrent") && load(get_current_context, "eglGetCurrentContext") && load(swap_buffers, "eglSwapBuffers") && load(swap_interval, "eglSwapInterval") && load(get_proc_address, "eglGetProcAddress") && load(get_error, "eglGetError");
    if (!ok)
      return errc::not_supported;
    if (!load(get_platform_display, "eglGetPlatformDisplay"))
      get_platform_display = reinterpret_cast<decltype(get_platform_display)>(get_proc_address("eglGetPlatformDisplayEXT"));
    if (!load(create_platform_window_surface, "eglCreatePlatformWindowSurface"))
      create_platform_window_surface = reinterpret_cast<decltype(create_platform_window_surface)>(get_proc_address("eglCreatePlatformWindowSurfaceEXT"));
    if (!get_platform_display || !create_platform_window_surface)
      return errc::not_supported;
    if (platform == platform_t::wayland)
    {
      wayland_egl = dlopen("libwayland-egl.so.1", RTLD_NOW | RTLD_LOCAL);
      if (!wayland_egl)
        return errc::not_supported;
      wl_egl_window_create = reinterpret_cast<decltype(wl_egl_window_create)>(dlsym(wayland_egl, "wl_egl_window_create"));
      wl_egl_window_resize = reinterpret_cast<decltype(wl_egl_window_resize)>(dlsym(wayland_egl, "wl_egl_window_resize"));
      wl_egl_window_destroy = reinterpret_cast<decltype(wl_egl_window_destroy)>(dlsym(wayland_egl, "wl_egl_window_destroy"));
      if (!wl_egl_window_create || !wl_egl_window_resize || !wl_egl_window_destroy)
        return errc::not_supported;
    }
    display = get_platform_display(platform == platform_t::wayland ? egl_platform_wayland : egl_platform_x11, native_display, nullptr);
    if (!display)
      return errc::not_supported;
    EGLint major = 0;
    EGLint minor = 0;
    if (!initialize(display, &major, &minor))
    {
      display = nullptr;
      return errc::not_supported;
    }
    return 0;
  }
};

class egl_context_t final : public gl_impl_t
{
public:
  egl_context_t(std::shared_ptr<egl_t> egl, platform_t platform)
    : _egl(std::move(egl))
    , _platform(platform)
  {
  }

  ~egl_context_t() override
  {
    release();
  }

  int create(window_impl_t &window, const gl_config_t &config)
  {
    auto &egl = *_egl;
    const auto native = window.backend->native();
    const EGLint renderable = !config.es ? egl_opengl_bit : config.major >= 3 ? egl_opengl_es3_bit : egl_opengl_es2_bit;
    const EGLint attributes[] = {
      egl_surface_type, egl_window_bit,
      egl_renderable_type, renderable,
      egl_red_size, 8,
      egl_green_size, 8,
      egl_blue_size, 8,
      egl_alpha_size, config.transparent ? 8 : 0,
      egl_depth_size, config.depth_bits,
      egl_stencil_size, config.stencil_bits,
      egl_sample_buffers, config.samples > 0 ? 1 : 0,
      egl_samples, config.samples,
      egl_none};
    std::array<EGLConfig, 64> configs{};
    EGLint count = 0;
    if (!egl.choose_config(egl.display, attributes, configs.data(), static_cast<EGLint>(configs.size()), &count) || count == 0)
      return errc::not_supported;
    _config = configs[0];
    if (_platform == platform_t::x11 && native.visual != 0)
    {
      bool matched = false;
      for (EGLint i = 0; i < count && !matched; ++i)
      {
        EGLint visual = 0;
        if (egl.get_config_attrib(egl.display, configs[static_cast<std::size_t>(i)], egl_native_visual_id, &visual) && static_cast<std::uint32_t>(visual) == native.visual)
        {
          _config = configs[static_cast<std::size_t>(i)];
          matched = true;
        }
      }
    }

    _api = config.es ? egl_opengl_es_api : egl_opengl_api;
    if (!egl.bind_api(_api))
      return errc::not_supported;
    std::vector<EGLint> context_attributes = {egl_context_major_version, config.major, egl_context_minor_version, config.minor};
    if (!config.es)
    {
      context_attributes.push_back(egl_context_opengl_profile_mask);
      context_attributes.push_back(config.core_profile ? egl_context_opengl_core_profile_bit : egl_context_opengl_compatibility_profile_bit);
    }
    if (config.debug)
    {
      context_attributes.push_back(egl_context_opengl_debug);
      context_attributes.push_back(1);
    }
    context_attributes.push_back(egl_none);
    _context = egl.create_context(egl.display, _config, nullptr, context_attributes.data());
    if (!_context)
      return errc::not_supported;

    _framebuffer = window.framebuffer;
    void *native_window = nullptr;
    if (_platform == platform_t::wayland)
    {
      _wayland_window = egl.wl_egl_window_create(native.handle, std::max(1, _framebuffer.width), std::max(1, _framebuffer.height));
      if (!_wayland_window)
        return errc::out_of_memory;
      native_window = _wayland_window;
    }
    else
    {
      _x11_window = static_cast<unsigned long>(native.id);
      native_window = &_x11_window;
    }
    std::vector<std::intptr_t> surface_attributes;
    if (config.srgb)
    {
      surface_attributes.push_back(egl_gl_colorspace);
      surface_attributes.push_back(egl_gl_colorspace_srgb);
    }
    surface_attributes.push_back(egl_none);
    _surface = egl.create_platform_window_surface(egl.display, _config, native_window, surface_attributes.data());
    if (!_surface)
      return errc::not_supported;
    _window = &window;
    window.attach(*this);
    if (int result = make_current(); result < 0)
      return result;
    egl.swap_interval(egl.display, config.vsync && _platform != platform_t::wayland ? 1 : 0);
    return 0;
  }

  int make_current() override
  {
    if (!_egl || !_context || !_surface)
      return errc::canceled;
    if (_wayland_window && _window && _window->framebuffer != _framebuffer && _window->framebuffer.width > 0 && _window->framebuffer.height > 0)
    {
      _framebuffer = _window->framebuffer;
      _egl->wl_egl_window_resize(_wayland_window, _framebuffer.width, _framebuffer.height, 0, 0);
    }
    _egl->bind_api(_api);
    if (!_egl->make_current(_egl->display, _surface, _surface, _context))
      return errc::io_error;
    return 0;
  }

  void release_current() override
  {
    if (_egl && _context && _egl->get_current_context() == _context)
      _egl->make_current(_egl->display, nullptr, nullptr, nullptr);
  }

  int swap_buffers() override
  {
    if (!_egl || !_surface)
      return errc::canceled;
    if (!_egl->swap_buffers(_egl->display, _surface))
      return errc::io_error;
    return 0;
  }

  void *proc_address(const char *name) const override
  {
    return _egl ? reinterpret_cast<void *>(_egl->get_proc_address(name)) : nullptr;
  }

  int set_swap_interval(int interval) override
  {
    if (!_egl || !_context)
      return errc::canceled;
    return _egl->swap_interval(_egl->display, interval) ? 0 : errc::not_supported;
  }

  gl_native_t native() const override
  {
    return {_egl ? _egl->display : nullptr, _context, _surface, _config};
  }

  std::vector<std::intptr_t> opencl_properties() const override
  {
    if (!_egl || !_context)
      return {};
    return {cl_gl_context_khr, reinterpret_cast<std::intptr_t>(_context), cl_egl_display_khr, reinterpret_cast<std::intptr_t>(_egl->display)};
  }

  void window_closing() noexcept override
  {
    release();
    _egl.reset();
  }

private:
  void release() noexcept
  {
    if (!_egl)
      return;
    if (_context && _egl->get_current_context() == _context)
      _egl->make_current(_egl->display, nullptr, nullptr, nullptr);
    if (_surface)
      _egl->destroy_surface(_egl->display, _surface);
    if (_wayland_window)
      _egl->wl_egl_window_destroy(_wayland_window);
    if (_context)
      _egl->destroy_context(_egl->display, _context);
    _surface = nullptr;
    _wayland_window = nullptr;
    _context = nullptr;
    _window = nullptr;
  }

  std::shared_ptr<egl_t> _egl;
  platform_t _platform;
  EGLConfig _config = nullptr;
  EGLContext _context = nullptr;
  EGLSurface _surface = nullptr;
  EGLenum _api = egl_opengl_api;
  void *_wayland_window = nullptr;
  unsigned long _x11_window = 0;
  window_impl_t *_window = nullptr;
  extent_t _framebuffer;
};
} // namespace

std::expected<std::unique_ptr<gl_impl_t>, int> make_egl_context(window_impl_t &window, const gl_config_t &config)
{
  auto &display = window.display;
  const auto platform = display.backend->platform();
  auto egl = std::static_pointer_cast<egl_t>(display.gl_state);
  if (!egl)
  {
    egl = std::make_shared<egl_t>();
    if (int result = egl->open(platform, display.backend->native_display()); result < 0)
      return std::unexpected(result);
    display.gl_state = egl;
  }
  auto context = std::make_unique<egl_context_t>(std::move(egl), platform);
  if (int result = context->create(window, config); result < 0)
    return std::unexpected(result);
  return context;
}
} // namespace vio::gui::detail
