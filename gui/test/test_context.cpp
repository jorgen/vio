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

#if defined(VIO_GUI_HAVE_X11) || defined(VIO_GUI_HAVE_WAYLAND)

#include <doctest/doctest.h>

#include <array>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

#include <dlfcn.h>

#include <vio/event_loop.h>
#include <vio/gui/context.h>
#include <vio/gui/gui.h>
#include <vio/task.h>

#include "gui_test_helpers.h"

namespace gui = vio::gui;

namespace
{
std::vector<std::string> linux_backends()
{
  std::vector<std::string> found;
  vio::event_loop_t loop;
  for (const char *name : {"x11", "wayland"})
  {
    auto display = gui::display_t::open(loop, {.backend = name});
    if (display)
      found.emplace_back(name);
  }
  loop.stop();
  loop.run();
  return found;
}

struct gl_functions_t
{
  void (*clear_color)(float, float, float, float);
  void (*clear)(unsigned);
  void (*read_pixels)(int, int, int, int, unsigned, unsigned, void *);
  void (*finish)();
  void (*viewport)(int, int, int, int);

  explicit gl_functions_t(const gui::gl_context_t &context)
    : clear_color(context.proc<decltype(clear_color)>("glClearColor"))
    , clear(context.proc<decltype(clear)>("glClear"))
    , read_pixels(context.proc<decltype(read_pixels)>("glReadPixels"))
    , finish(context.proc<decltype(finish)>("glFinish"))
    , viewport(context.proc<decltype(viewport)>("glViewport"))
  {
  }
};

constexpr unsigned gl_color_buffer_bit = 0x4000;
constexpr unsigned gl_rgba = 0x1908;
constexpr unsigned gl_unsigned_byte = 0x1401;
} // namespace

TEST_CASE("gl: a context draws into the window on every Linux backend")
{
  for (const auto &backend : linux_backends())
  {
    CAPTURE(backend);
    vio::event_loop_t loop;
    std::vector<std::array<std::uint8_t, 4>> pixels;
    run_gui_test(loop, [](vio::event_loop_t &loop, std::string backend, std::vector<std::array<std::uint8_t, 4>> &pixels) -> vio::task_t<void> {
      auto display = gui::display_t::open(loop, {.backend = backend});
      REQUIRE(display.has_value());
      {
        auto window = gui::window_t::create(*display, {.title = "gl", .size = {64, 48}});
        REQUIRE(window.has_value());
        auto context = gui::gl_context_t::create(*window, {.major = 3, .minor = 3});
        if (!context)
          FAIL("gl context: " << context.error().msg);
        gl_functions_t gl(*context);
        REQUIRE(gl.clear_color);
        const float colours[3][3] = {{1, 0, 0}, {0, 1, 0}, {0, 0, 1}};
        for (const auto &colour : colours)
        {
          auto frame = co_await window->frame();
          REQUIRE(frame.has_value());
          REQUIRE(context->make_current().has_value());
          gl.viewport(0, 0, frame->framebuffer.width, frame->framebuffer.height);
          gl.clear_color(colour[0], colour[1], colour[2], 1);
          gl.clear(gl_color_buffer_bit);
          gl.finish();
          std::array<std::uint8_t, 4> pixel{};
          gl.read_pixels(frame->framebuffer.width / 2, frame->framebuffer.height / 2, 1, 1, gl_rgba, gl_unsigned_byte, pixel.data());
          pixels.push_back(pixel);
          REQUIRE(context->swap_buffers().has_value());
        }
      }
      loop.stop();
    }(loop, backend, pixels));
    REQUIRE(pixels.size() == 3);
    CHECK(pixels[0] == std::array<std::uint8_t, 4>{255, 0, 0, 255});
    CHECK(pixels[1] == std::array<std::uint8_t, 4>{0, 255, 0, 255});
    CHECK(pixels[2] == std::array<std::uint8_t, 4>{0, 0, 255, 255});
  }
}

TEST_CASE("gl: closing the window releases the context and later calls are refused")
{
  for (const auto &backend : linux_backends())
  {
    CAPTURE(backend);
    vio::event_loop_t loop;
    run_gui_test(loop, [](vio::event_loop_t &loop, std::string backend) -> vio::task_t<void> {
      auto display = gui::display_t::open(loop, {.backend = backend});
      if (!display)
        FAIL("display: " << display.error().msg);
      {
        auto window = gui::window_t::create(*display);
        auto context = gui::gl_context_t::create(*window);
        REQUIRE(context.has_value());
        co_await window->frame();
        REQUIRE(context->make_current().has_value());
        window->close();
        auto again = context->make_current();
        REQUIRE(!again.has_value());
        CHECK(again.error().code == vio::errc::canceled);
        CHECK(!context->swap_buffers().has_value());
        CHECK(context->native().context == nullptr);
      }
      loop.stop();
    }(loop, backend));
  }
}

TEST_CASE("gl: OpenCL sharing properties name the context and its EGL display")
{
  for (const auto &backend : linux_backends())
  {
    CAPTURE(backend);
    vio::event_loop_t loop;
    run_gui_test(loop, [](vio::event_loop_t &loop, std::string backend) -> vio::task_t<void> {
      auto display = gui::display_t::open(loop, {.backend = backend});
      if (!display)
        FAIL("display: " << display.error().msg);
      {
        auto window = gui::window_t::create(*display);
        auto context = gui::gl_context_t::create(*window);
        REQUIRE(context.has_value());
        int platform = 0;
        auto properties = context->opencl_properties(&platform);
        const auto native = context->native();
        REQUIRE(properties.size() == 7);
        CHECK(properties[0] == 0x1084);
        CHECK(properties[1] == reinterpret_cast<std::intptr_t>(&platform));
        CHECK(properties[2] == 0x2008);
        CHECK(properties[3] == reinterpret_cast<std::intptr_t>(native.context));
        CHECK(properties[4] == 0x2009);
        CHECK(properties[5] == reinterpret_cast<std::intptr_t>(native.display));
        CHECK(properties[6] == 0);
        auto uuid = context->device_uuid();
        if (uuid)
          CHECK(*uuid != std::array<std::uint8_t, 16>{});
        else
          CHECK(uuid.error().code == vio::errc::not_supported);
        co_await window->frame();
      }
      loop.stop();
    }(loop, backend));
  }
}

#if __has_include(<vulkan/vulkan.h>)
#include <vulkan/vulkan.h>

TEST_CASE("vulkan: a surface made for the window can present from the device")
{
  void *library = dlopen("libvulkan.so.1", RTLD_NOW | RTLD_LOCAL);
  if (!library)
    return;
  auto get_instance_proc_addr = reinterpret_cast<PFN_vkGetInstanceProcAddr>(dlsym(library, "vkGetInstanceProcAddr"));
  REQUIRE(get_instance_proc_addr);
  auto create_instance = reinterpret_cast<PFN_vkCreateInstance>(get_instance_proc_addr(nullptr, "vkCreateInstance"));
  for (const auto &backend : linux_backends())
  {
    CAPTURE(backend);
    vio::event_loop_t loop;
    run_gui_test(loop, [](vio::event_loop_t &loop, std::string backend, PFN_vkGetInstanceProcAddr gipa, PFN_vkCreateInstance create_instance) -> vio::task_t<void> {
      auto display = gui::display_t::open(loop, {.backend = backend});
      if (!display)
        FAIL("display: " << display.error().msg);
      {
        auto window = gui::window_t::create(*display, {.size = {96, 64}});
        auto extensions = gui::vulkan::required_instance_extensions(*display);
        REQUIRE(extensions.size() == 2);
        VkApplicationInfo application{VK_STRUCTURE_TYPE_APPLICATION_INFO};
        application.apiVersion = VK_API_VERSION_1_1;
        VkInstanceCreateInfo info{VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO};
        info.pApplicationInfo = &application;
        info.enabledExtensionCount = static_cast<std::uint32_t>(extensions.size());
        info.ppEnabledExtensionNames = extensions.data();
        VkInstance instance = VK_NULL_HANDLE;
        REQUIRE(create_instance(&info, nullptr, &instance) == VK_SUCCESS);
        auto proc = [gipa, instance](const char *name) { return gipa(instance, name); };
        auto destroy_instance = reinterpret_cast<PFN_vkDestroyInstance>(proc("vkDestroyInstance"));
        auto destroy_surface = reinterpret_cast<PFN_vkDestroySurfaceKHR>(proc("vkDestroySurfaceKHR"));
        auto enumerate = reinterpret_cast<PFN_vkEnumeratePhysicalDevices>(proc("vkEnumeratePhysicalDevices"));
        auto supported = reinterpret_cast<PFN_vkGetPhysicalDeviceSurfaceSupportKHR>(proc("vkGetPhysicalDeviceSurfaceSupportKHR"));
        auto capabilities = reinterpret_cast<PFN_vkGetPhysicalDeviceSurfaceCapabilitiesKHR>(proc("vkGetPhysicalDeviceSurfaceCapabilitiesKHR"));

        auto surface = gui::vulkan::create_surface(*window, instance, reinterpret_cast<gui::vulkan::get_instance_proc_addr_t>(gipa));
        if (!surface)
          FAIL("surface: " << surface.error().msg);
        auto handle = reinterpret_cast<VkSurfaceKHR>(*surface);
        std::uint32_t count = 0;
        enumerate(instance, &count, nullptr);
        REQUIRE(count > 0);
        std::vector<VkPhysicalDevice> devices(count);
        enumerate(instance, &count, devices.data());
        VkBool32 present = VK_FALSE;
        REQUIRE(supported(devices[0], 0, handle, &present) == VK_SUCCESS);
        CHECK(present == VK_TRUE);
        VkSurfaceCapabilitiesKHR caps{};
        REQUIRE(capabilities(devices[0], handle, &caps) == VK_SUCCESS);
        CHECK(caps.maxImageExtent.width >= 96);
        auto uuid = gui::vulkan::device_uuid(instance, devices[0], reinterpret_cast<gui::vulkan::get_instance_proc_addr_t>(gipa));
        REQUIRE(uuid.has_value());
        CHECK(*uuid != std::array<std::uint8_t, 16>{});
        destroy_surface(instance, handle, nullptr);
        destroy_instance(instance, nullptr);
        co_await window->frame();
      }
      loop.stop();
    }(loop, backend, get_instance_proc_addr, create_instance));
  }
  dlclose(library);
}
#endif

#endif
