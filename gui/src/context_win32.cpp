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

#include "win32_common.h"

#include <algorithm>
#include <cstring>
#include <memory>
#include <optional>
#include <vector>

#include <dxgi1_6.h>

#include "vio/gui/context.h"

namespace vio::gui
{
namespace detail
{
namespace
{
constexpr int wgl_draw_to_window = 0x2001;
constexpr int wgl_acceleration = 0x2003;
constexpr int wgl_support_opengl = 0x2010;
constexpr int wgl_double_buffer = 0x2011;
constexpr int wgl_pixel_type = 0x2013;
constexpr int wgl_red_bits = 0x2015;
constexpr int wgl_green_bits = 0x2017;
constexpr int wgl_blue_bits = 0x2019;
constexpr int wgl_alpha_bits = 0x201B;
constexpr int wgl_depth_bits = 0x2022;
constexpr int wgl_stencil_bits = 0x2023;
constexpr int wgl_full_acceleration = 0x2027;
constexpr int wgl_type_rgba = 0x202B;
constexpr int wgl_sample_buffers = 0x2041;
constexpr int wgl_samples = 0x2042;
constexpr int wgl_framebuffer_srgb_capable = 0x20A9;
constexpr int wgl_context_major_version = 0x2091;
constexpr int wgl_context_minor_version = 0x2092;
constexpr int wgl_context_flags = 0x2094;
constexpr int wgl_context_debug_bit = 0x0001;
constexpr int wgl_context_profile_mask = 0x9126;
constexpr int wgl_context_core_profile_bit = 0x0001;
constexpr int wgl_context_compatibility_profile_bit = 0x0002;
constexpr int wgl_context_es2_profile_bit = 0x0004;

constexpr std::intptr_t cl_gl_context_khr = 0x2008;
constexpr std::intptr_t cl_wgl_hdc_khr = 0x200B;

struct wgl_t
{
  HMODULE library = nullptr;
  HGLRC(WINAPI *create_context)(HDC) = nullptr;
  BOOL(WINAPI *delete_context)(HGLRC) = nullptr;
  BOOL(WINAPI *make_current)(HDC, HGLRC) = nullptr;
  HGLRC(WINAPI *get_current_context)() = nullptr;
  PROC(WINAPI *get_proc_address)(LPCSTR) = nullptr;
  HGLRC(WINAPI *create_context_attribs)(HDC, HGLRC, const int *) = nullptr;
  BOOL(WINAPI *choose_pixel_format)(HDC, const int *, const FLOAT *, UINT, int *, UINT *) = nullptr;
  BOOL(WINAPI *swap_interval)(int) = nullptr;

  template <typename T>
  bool load(T &slot, const char *name)
  {
    slot = reinterpret_cast<T>(reinterpret_cast<void *>(GetProcAddress(library, name)));
    return slot != nullptr;
  }

  template <typename T>
  void extension(T &slot, const char *name)
  {
    slot = reinterpret_cast<T>(reinterpret_cast<void *>(get_proc_address(name)));
  }

  int open()
  {
    library = LoadLibraryW(L"opengl32.dll");
    if (!library)
      return errc::not_supported;
    if (!(load(create_context, "wglCreateContext") && load(delete_context, "wglDeleteContext") && load(make_current, "wglMakeCurrent") && load(get_current_context, "wglGetCurrentContext") && load(get_proc_address, "wglGetProcAddress")))
      return errc::not_supported;
    HWND dummy = CreateWindowExW(0, L"STATIC", L"", WS_POPUP, 0, 0, 1, 1, nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);
    if (!dummy)
      return errc::out_of_memory;
    HDC dc = GetDC(dummy);
    PIXELFORMATDESCRIPTOR format{};
    format.nSize = sizeof(format);
    format.nVersion = 1;
    format.dwFlags = PFD_DRAW_TO_WINDOW | PFD_SUPPORT_OPENGL | PFD_DOUBLEBUFFER;
    format.iPixelType = PFD_TYPE_RGBA;
    format.cColorBits = 24;
    int result = errc::not_supported;
    if (SetPixelFormat(dc, ChoosePixelFormat(dc, &format), &format))
    {
      if (HGLRC context = create_context(dc))
      {
        make_current(dc, context);
        extension(create_context_attribs, "wglCreateContextAttribsARB");
        extension(choose_pixel_format, "wglChoosePixelFormatARB");
        extension(swap_interval, "wglSwapIntervalEXT");
        make_current(nullptr, nullptr);
        delete_context(context);
        if (create_context_attribs && choose_pixel_format)
          result = 0;
      }
    }
    ReleaseDC(dummy, dc);
    DestroyWindow(dummy);
    return result;
  }
};

wgl_t *wgl()
{
  static wgl_t instance;
  static int status = instance.open();
  return status == 0 ? &instance : nullptr;
}

class wgl_context_t final : public gl_impl_t
{
public:
  ~wgl_context_t() override
  {
    release();
  }

  int create(window_impl_t &window, const gl_config_t &config)
  {
    _wgl = wgl();
    if (!_wgl)
      return errc::not_supported;
    _hwnd = win32_handle(window);
    _dc = GetDC(_hwnd);
    if (!_dc)
      return errc::not_supported;
    if (GetPixelFormat(_dc) == 0)
    {
      const int attributes[] = {
        wgl_draw_to_window, 1,
        wgl_support_opengl, 1,
        wgl_double_buffer, 1,
        wgl_pixel_type, wgl_type_rgba,
        wgl_acceleration, wgl_full_acceleration,
        wgl_red_bits, 8,
        wgl_green_bits, 8,
        wgl_blue_bits, 8,
        wgl_alpha_bits, config.transparent ? 8 : 0,
        wgl_depth_bits, config.depth_bits,
        wgl_stencil_bits, config.stencil_bits,
        wgl_sample_buffers, config.samples > 0 ? 1 : 0,
        wgl_samples, config.samples,
        wgl_framebuffer_srgb_capable, config.srgb ? 1 : 0,
        0};
      int format = 0;
      UINT count = 0;
      if (!_wgl->choose_pixel_format(_dc, attributes, nullptr, 1, &format, &count) || count == 0)
        return errc::not_supported;
      PIXELFORMATDESCRIPTOR descriptor{};
      DescribePixelFormat(_dc, format, sizeof(descriptor), &descriptor);
      if (!SetPixelFormat(_dc, format, &descriptor))
        return errc::not_supported;
    }
    std::vector<int> attributes = {wgl_context_major_version, config.major, wgl_context_minor_version, config.minor};
    attributes.push_back(wgl_context_profile_mask);
    attributes.push_back(config.es ? wgl_context_es2_profile_bit : config.core_profile ? wgl_context_core_profile_bit : wgl_context_compatibility_profile_bit);
    if (config.debug)
    {
      attributes.push_back(wgl_context_flags);
      attributes.push_back(wgl_context_debug_bit);
    }
    attributes.push_back(0);
    _context = _wgl->create_context_attribs(_dc, nullptr, attributes.data());
    if (!_context)
      return errc::not_supported;
    window.attach(*this);
    if (int result = make_current(); result < 0)
      return result;
    if (_wgl->swap_interval)
      _wgl->swap_interval(config.vsync ? 1 : 0);
    return 0;
  }

  int make_current() override
  {
    if (!_context)
      return errc::canceled;
    return _wgl->make_current(_dc, _context) ? 0 : errc::io_error;
  }

  void release_current() override
  {
    if (_context && _wgl->get_current_context() == _context)
      _wgl->make_current(nullptr, nullptr);
  }

  int swap_buffers() override
  {
    if (!_context)
      return errc::canceled;
    return SwapBuffers(_dc) ? 0 : errc::io_error;
  }

  void *proc_address(const char *name) const override
  {
    if (!_wgl)
      return nullptr;
    auto address = reinterpret_cast<std::intptr_t>(_wgl->get_proc_address(name));
    if (address == 0 || address == 1 || address == 2 || address == 3 || address == -1)
      return reinterpret_cast<void *>(GetProcAddress(_wgl->library, name));
    return reinterpret_cast<void *>(address);
  }

  int set_swap_interval(int interval) override
  {
    if (!_context)
      return errc::canceled;
    if (!_wgl->swap_interval)
      return errc::not_supported;
    return _wgl->swap_interval(interval) ? 0 : errc::not_supported;
  }

  gl_native_t native() const override
  {
    return {_dc, _context, _hwnd, nullptr};
  }

  std::vector<std::intptr_t> opencl_properties() const override
  {
    if (!_context)
      return {};
    return {cl_gl_context_khr, reinterpret_cast<std::intptr_t>(_context), cl_wgl_hdc_khr, reinterpret_cast<std::intptr_t>(_dc)};
  }

  void window_closing() noexcept override
  {
    release();
  }

private:
  void release() noexcept
  {
    if (_context)
    {
      if (_wgl->get_current_context() == _context)
        _wgl->make_current(nullptr, nullptr);
      _wgl->delete_context(_context);
    }
    _context = nullptr;
    _dc = nullptr;
    _hwnd = nullptr;
  }

  wgl_t *_wgl = nullptr;
  HWND _hwnd = nullptr;
  HDC _dc = nullptr;
  HGLRC _context = nullptr;
};

template <typename Interface>
struct com_t
{
  Interface *pointer = nullptr;
  com_t() = default;
  com_t(const com_t &) = delete;
  com_t &operator=(const com_t &) = delete;
  ~com_t()
  {
    if (pointer)
      pointer->Release();
  }
  Interface **put() noexcept
  {
    return &pointer;
  }
  Interface *operator->() const noexcept
  {
    return pointer;
  }
  explicit operator bool() const noexcept
  {
    return pointer != nullptr;
  }
};

HRESULT create_factory(REFIID id, void **factory)
{
  static HMODULE dxgi = LoadLibraryW(L"dxgi.dll");
  if (!dxgi)
    return E_NOINTERFACE;
  using create2_t = HRESULT(WINAPI *)(UINT, REFIID, void **);
  using create1_t = HRESULT(WINAPI *)(REFIID, void **);
  if (auto create = reinterpret_cast<create2_t>(reinterpret_cast<void *>(GetProcAddress(dxgi, "CreateDXGIFactory2"))))
    return create(0, id, factory);
  if (auto create = reinterpret_cast<create1_t>(reinterpret_cast<void *>(GetProcAddress(dxgi, "CreateDXGIFactory1"))))
    return create(id, factory);
  return E_NOINTERFACE;
}
} // namespace

std::expected<std::unique_ptr<gl_impl_t>, int> make_wgl_context(window_impl_t &window, const gl_config_t &config)
{
  auto context = std::make_unique<wgl_context_t>();
  if (int result = context->create(window, config); result < 0)
    return std::unexpected(result);
  return context;
}
} // namespace detail

namespace d3d12
{
std::expected<void *, error_t> create_swap_chain(window_t &window, void *command_queue, const swap_chain_config_t &config)
{
  if (!window)
    return std::unexpected(make_error(errc::canceled));
  if (!command_queue || config.buffer_count < 2)
    return std::unexpected(make_error(errc::invalid_argument));
  detail::com_t<IDXGIFactory2> factory;
  if (FAILED(detail::create_factory(__uuidof(IDXGIFactory2), reinterpret_cast<void **>(factory.put()))))
    return std::unexpected(make_error(errc::not_supported));
  UINT flags = 0;
  if (config.allow_tearing)
  {
    detail::com_t<IDXGIFactory5> factory5;
    BOOL allowed = FALSE;
    if (SUCCEEDED(factory->QueryInterface(__uuidof(IDXGIFactory5), reinterpret_cast<void **>(factory5.put()))) && SUCCEEDED(factory5->CheckFeatureSupport(DXGI_FEATURE_PRESENT_ALLOW_TEARING, &allowed, sizeof(allowed))) && allowed)
      flags |= DXGI_SWAP_CHAIN_FLAG_ALLOW_TEARING;
  }
  const HWND hwnd = detail::win32_handle(*window.impl());
  const auto framebuffer = window.framebuffer_size();
  DXGI_SWAP_CHAIN_DESC1 description{};
  description.Width = static_cast<UINT>(std::max(1, framebuffer.width));
  description.Height = static_cast<UINT>(std::max(1, framebuffer.height));
  description.Format = static_cast<DXGI_FORMAT>(config.format);
  description.SampleDesc.Count = 1;
  description.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
  description.BufferCount = config.buffer_count;
  description.Scaling = DXGI_SCALING_STRETCH;
  description.SwapEffect = DXGI_SWAP_EFFECT_FLIP_DISCARD;
  description.AlphaMode = DXGI_ALPHA_MODE_UNSPECIFIED;
  description.Flags = flags;
  detail::com_t<IDXGISwapChain1> chain;
  if (FAILED(factory->CreateSwapChainForHwnd(static_cast<IUnknown *>(command_queue), hwnd, &description, nullptr, nullptr, chain.put())))
    return std::unexpected(make_error(errc::not_supported));
  factory->MakeWindowAssociation(hwnd, DXGI_MWA_NO_ALT_ENTER);
  IDXGISwapChain3 *result = nullptr;
  if (FAILED(chain->QueryInterface(__uuidof(IDXGISwapChain3), reinterpret_cast<void **>(&result))))
    return std::unexpected(make_error(errc::not_supported));
  return static_cast<void *>(result);
}

std::expected<void, error_t> resize_swap_chain(void *swap_chain, extent_t framebuffer)
{
  if (!swap_chain || framebuffer.width <= 0 || framebuffer.height <= 0)
    return std::unexpected(make_error(errc::invalid_argument));
  auto *chain = static_cast<IDXGISwapChain1 *>(swap_chain);
  DXGI_SWAP_CHAIN_DESC1 description{};
  chain->GetDesc1(&description);
  if (FAILED(chain->ResizeBuffers(0, static_cast<UINT>(framebuffer.width), static_cast<UINT>(framebuffer.height), DXGI_FORMAT_UNKNOWN, description.Flags)))
    return std::unexpected(make_error(errc::io_error));
  return {};
}
} // namespace d3d12

std::expected<std::array<std::uint8_t, 8>, error_t> adapter_luid(window_t &window)
{
  if (!window)
    return std::unexpected(make_error(errc::canceled));
  detail::com_t<IDXGIFactory1> factory;
  if (FAILED(detail::create_factory(__uuidof(IDXGIFactory1), reinterpret_cast<void **>(factory.put()))))
    return std::unexpected(make_error(errc::not_supported));
  const HMONITOR monitor = MonitorFromWindow(detail::win32_handle(*window.impl()), MONITOR_DEFAULTTONEAREST);
  std::optional<LUID> found;
  std::optional<LUID> first;
  for (UINT index = 0; !found; ++index)
  {
    detail::com_t<IDXGIAdapter1> adapter;
    if (factory->EnumAdapters1(index, adapter.put()) == DXGI_ERROR_NOT_FOUND)
      break;
    DXGI_ADAPTER_DESC1 description{};
    adapter->GetDesc1(&description);
    if (!first)
      first = description.AdapterLuid;
    for (UINT output_index = 0;; ++output_index)
    {
      detail::com_t<IDXGIOutput> output;
      if (adapter->EnumOutputs(output_index, output.put()) == DXGI_ERROR_NOT_FOUND)
        break;
      DXGI_OUTPUT_DESC output_description{};
      output->GetDesc(&output_description);
      if (output_description.Monitor == monitor)
      {
        found = description.AdapterLuid;
        break;
      }
    }
  }
  if (!found)
    found = first;
  if (!found)
    return std::unexpected(make_error(errc::no_such_device));
  std::array<std::uint8_t, 8> luid{};
  std::memcpy(luid.data(), &found->LowPart, 4);
  std::memcpy(luid.data() + 4, &found->HighPart, 4);
  return luid;
}
} // namespace vio::gui
