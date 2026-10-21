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

#if defined(VIO_GUI_HAVE_WAYLAND)

#include <doctest/doctest.h>

#include <chrono>
#include <cstring>
#include <string>

#include <sys/mman.h>
#include <unistd.h>

#include <vio/event_loop.h>
#include <vio/gui/gui.h>
#include <vio/operation/sleep.h>
#include <vio/task.h>

#include "gui_test_helpers.h"

#include <wayland-client.h>

using namespace std::chrono_literals;
namespace gui = vio::gui;

namespace
{
bool wayland_available()
{
  wl_display *probe = wl_display_connect(nullptr);
  if (!probe)
    return false;
  wl_display_disconnect(probe);
  return true;
}

gui::display_t open_wayland(vio::event_loop_t &loop, gui::display_config_t config = {})
{
  config.backend = "wayland";
  auto display = gui::display_t::open(loop, config);
  REQUIRE(display.has_value());
  CHECK(std::string(display->backend_name()) == "wayland");
  return std::move(*display);
}

class shm_painter_t
{
public:
  explicit shm_painter_t(wl_display *display)
  {
    _registry = wl_display_get_registry(display);
    wl_registry_add_listener(_registry, &listener, this);
    wl_display_roundtrip(display);
  }
  ~shm_painter_t()
  {
    if (_shm)
      wl_shm_destroy(_shm);
    wl_registry_destroy(_registry);
  }

  void paint(wl_surface *surface, gui::extent_t size, std::uint32_t colour)
  {
    const int stride = size.width * 4;
    const int bytes = stride * size.height;
    const int fd = memfd_create("vio-test", MFD_CLOEXEC);
    REQUIRE(fd >= 0);
    REQUIRE(ftruncate(fd, bytes) == 0);
    void *pixels = mmap(nullptr, static_cast<std::size_t>(bytes), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    REQUIRE(pixels != MAP_FAILED);
    auto *words = static_cast<std::uint32_t *>(pixels);
    for (int i = 0; i < size.width * size.height; ++i)
      words[i] = colour;
    munmap(pixels, static_cast<std::size_t>(bytes));
    wl_shm_pool *pool = wl_shm_create_pool(_shm, fd, bytes);
    wl_buffer *buffer = wl_shm_pool_create_buffer(pool, 0, size.width, size.height, stride, WL_SHM_FORMAT_XRGB8888);
    wl_shm_pool_destroy(pool);
    close(fd);
    wl_surface_attach(surface, buffer, 0, 0);
    wl_surface_damage_buffer(surface, 0, 0, size.width, size.height);
    wl_surface_commit(surface);
    wl_buffer_destroy(buffer);
  }

private:
  static void on_global(void *data, wl_registry *registry, std::uint32_t name, const char *interface, std::uint32_t)
  {
    if (std::strcmp(interface, wl_shm_interface.name) == 0)
      static_cast<shm_painter_t *>(data)->_shm = static_cast<wl_shm *>(wl_registry_bind(registry, name, &wl_shm_interface, 1));
  }
  static void on_global_remove(void *, wl_registry *, std::uint32_t)
  {
  }
  static constexpr wl_registry_listener listener{&on_global, &on_global_remove};

  wl_registry *_registry = nullptr;
  wl_shm *_shm = nullptr;
};
} // namespace

TEST_CASE("wayland: a configured window delivers frames paced by the compositor")
{
  if (!wayland_available())
    return;
  vio::event_loop_t loop;
  run_gui_test(loop, [](vio::event_loop_t &loop) -> vio::task_t<void> {
    auto display = open_wayland(loop);
    {
      auto window = gui::window_t::create(display, {.title = "frames", .size = {240, 160}});
      REQUIRE(window.has_value());
      shm_painter_t painter(static_cast<wl_display *>(display.native_display()));
      auto *surface = static_cast<wl_surface *>(window->native().handle);
      std::uint64_t last = 0;
      for (int i = 0; i < 4; ++i)
      {
        auto frame = co_await window->frame();
        REQUIRE(frame.has_value());
        CHECK(frame->number > last);
        last = frame->number;
        CHECK(frame->size == gui::extent_t{240, 160});
        CHECK(frame->framebuffer.width == 240 * static_cast<int>(frame->scale));
        painter.paint(surface, frame->framebuffer, 0xff2040u + static_cast<std::uint32_t>(i));
      }
      CHECK(window->visible());
    }
    loop.stop();
  }(loop));
}

TEST_CASE("wayland: a size the client chooses comes back as a resize")
{
  if (!wayland_available())
    return;
  vio::event_loop_t loop;
  run_gui_test(loop, [](vio::event_loop_t &loop) -> vio::task_t<void> {
    auto display = open_wayland(loop);
    {
      auto window = gui::window_t::create(display, {.size = {200, 120}});
      co_await window->frame();
      REQUIRE(window->set_size({330, 210}).has_value());
      for (;;)
      {
        auto resized = co_await window->resized();
        REQUIRE(resized.has_value());
        if (resized->size == gui::extent_t{330, 210})
          break;
      }
      CHECK(!window->set_position({10, 10}).has_value());
    }
    loop.stop();
  }(loop));
}

TEST_CASE("wayland: hiding unmaps the window and showing configures it again")
{
  if (!wayland_available())
    return;
  vio::event_loop_t loop;
  run_gui_test(loop, [](vio::event_loop_t &loop) -> vio::task_t<void> {
    auto display = open_wayland(loop);
    {
      auto window = gui::window_t::create(display, {.size = {100, 100}});
      co_await window->frame();
      window->hide();
      CHECK(!window->visible());
      window->show();
      auto frame = co_await window->frame();
      REQUIRE(frame.has_value());
      CHECK(frame->damaged);
      CHECK(window->visible());
    }
    loop.stop();
  }(loop));
}

TEST_CASE("wayland: a selection set before any input focus is refused and reads back empty")
{
  if (!wayland_available())
    return;
  vio::event_loop_t loop;
  std::string text;
  run_gui_test(loop, [](vio::event_loop_t &loop, std::string &text) -> vio::task_t<void> {
    auto display = open_wayland(loop);
    display.set_clipboard_text("wayland text");
    co_await vio::sleep(loop, 50ms);
    auto got = co_await display.clipboard_text();
    REQUIRE(got.has_value());
    text = *got;
    loop.stop();
  }(loop, text));
  CHECK(text.empty());
}

#endif
