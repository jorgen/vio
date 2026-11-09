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

#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <optional>
#include <variant>

#include <vio/event_loop.h>
#include <vio/gui/context.h>
#include <vio/gui/gui.h>
#include <vio/operation/sleep.h>
#include <vio/task.h>

namespace gui = vio::gui;
using namespace std::chrono_literals;

struct state_t
{
  bool done = false;
  float hue = 0;
};

vio::task_t<void> draw(gui::window_t &window, state_t &state, int frame_limit)
{
  auto context = gui::gl_context_t::create(window, {.major = 3, .minor = 2});
  if (!context)
  {
    std::fprintf(stderr, "no OpenGL: %s\n", context.error().msg.c_str());
    state.done = true;
    co_return;
  }
  auto viewport = context->proc<void (*)(int, int, int, int)>("glViewport");
  auto clear_color = context->proc<void (*)(float, float, float, float)>("glClearColor");
  auto clear = context->proc<void (*)(unsigned)>("glClear");
  while (auto frame = co_await window.frame())
  {
    context->make_current();
    viewport(0, 0, frame->framebuffer.width, frame->framebuffer.height);
    const float t = static_cast<float>(frame->time_ns % 6'000'000'000) / 6e9f;
    clear_color(0.5f + 0.5f * std::sin(6.283f * (t + state.hue)), 0.3f, 0.6f, 1);
    clear(0x4000);
    context->swap_buffers();
    if (frame_limit > 0 && frame->number >= static_cast<std::uint64_t>(frame_limit))
    {
      state.done = true;
      break;
    }
  }
}

// Each subscription ends when the window closes, so these loops need no flag of their own.
vio::task_t<void> read_keys(gui::window_t &window, state_t &state)
{
  auto keys = window.subscribe<gui::key_event_t, gui::text_event_t>();
  while (auto event = co_await keys)
  {
    if (auto *key = std::get_if<gui::key_event_t>(&*event); key && key->pressed && key->key == gui::key_t::escape)
      state.done = true;
    else if (auto *text = std::get_if<gui::text_event_t>(&*event))
      std::printf("typed %s\n", text->text.c_str());
  }
}

vio::task_t<void> read_clicks(gui::window_t &window, state_t &state)
{
  auto buttons = window.subscribe<gui::pointer_button_event_t>();
  while (auto button = co_await buttons)
  {
    if (button->pressed)
      state.hue += 0.25f;
  }
}

vio::task_t<void> follow_size(gui::window_t &window)
{
  auto sizes = window.subscribe<gui::resize_event_t>();
  while (auto resized = co_await sizes)
    std::printf("size %dx%d, %dx%d pixels\n", resized->size.width, resized->size.height, resized->framebuffer.width, resized->framebuffer.height);
}

vio::task_t<void> run(vio::event_loop_t &loop, int frame_limit)
{
  auto display = gui::display_t::open(loop);
  if (!display)
  {
    std::fprintf(stderr, "no display: %s\n", display.error().msg.c_str());
    loop.stop();
    co_return;
  }
  std::printf("window system: %s\n", display->backend_name());
  {
    auto window = gui::window_t::create(*display, {.title = "hello vio", .size = {640, 400}});
    if (!window)
    {
      loop.stop();
      co_return;
    }
    state_t state;
    auto drawing = draw(*window, state, frame_limit);
    auto keys = read_keys(*window, state);
    auto clicks = read_clicks(*window, state);
    auto sizes = follow_size(*window);
    auto closing = [](gui::window_t &window, state_t &state) -> vio::task_t<void> {
      auto requests = window.subscribe<gui::close_request_t>();
      if (co_await requests)
        state.done = true;
    }(*window, state);
    while (!state.done)
      co_await vio::sleep(loop, 50ms);
    window->close();
    co_await std::move(drawing);
    co_await std::move(keys);
    co_await std::move(clicks);
    co_await std::move(sizes);
    co_await std::move(closing);
  }
  loop.stop();
}

int main(int argc, char **argv)
{
  const int frame_limit = argc > 1 ? std::atoi(argv[1]) : 0;
  vio::event_loop_t loop;
  std::optional<vio::task_t<void>> task;
  loop.run_in_loop([&] { task.emplace(run(loop, frame_limit)); });
  loop.run();
  return 0;
}
