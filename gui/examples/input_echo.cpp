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
#include <cstdlib>
#include <print>
#include <string>
#include <variant>
#include <vector>

#include <vio/gui/context.h>
#include <vio/gui/gui.h>
#include <vio/operation/sleep.h>
#include <vio/run.h>

namespace gui = vio::gui;
using namespace std::chrono_literals;

namespace
{
const char *button_name(gui::button_t button)
{
  switch (button)
  {
  case gui::button_t::left: return "left";
  case gui::button_t::right: return "right";
  case gui::button_t::middle: return "middle";
  case gui::button_t::back: return "back";
  case gui::button_t::forward: return "forward";
  default: return "other";
  }
}

template <typename... Fs>
struct overloaded : Fs...
{
  using Fs::operator()...;
};

struct shared_t
{
  bool done = false;
  int pastes = 0;
};

vio::task_t<void> paste(gui::display_t &display, shared_t &shared)
{
  auto text = co_await display.clipboard_text();
  if (text)
    std::println("clipboard holds \"{}\"", *text);
  else
    std::println("clipboard could not be read: {}", text.error().msg);
  ++shared.pastes;
}

// One coroutine per concern, each subscribed to just the events it handles. Every subscription
// sees its events independently of the others, and each loop ends when the window closes.

// Keys and text share a subscription, because their interleaving matters to anything that edits.
vio::task_t<void> keyboard(gui::display_t &display, gui::window_t &window, shared_t &shared)
{
  std::vector<vio::task_t<void>> pastes;
  auto keys = window.subscribe<gui::key_event_t, gui::text_event_t>();
  while (auto event = co_await keys)
  {
    if (auto *text = std::get_if<gui::text_event_t>(&*event))
    {
      std::println("text \"{}\"", text->text);
      continue;
    }
    const auto &key = std::get<gui::key_event_t>(*event);
    std::println("key {} scancode {} {}{}", static_cast<int>(key.key), key.scancode, key.pressed ? "down" : "up", key.repeat ? " (repeat)" : "");
    if (!key.pressed)
      continue;
    const bool control = gui::has(key.modifiers, gui::modifier_t::control) || gui::has(key.modifiers, gui::modifier_t::super);
    if (key.key == gui::key_t::escape)
      shared.done = true;
    else if (control && key.key == gui::key_t::c)
      display.set_clipboard_text("copied from vio");
    else if (control && key.key == gui::key_t::v)
      pastes.push_back(paste(display, shared));
    else if (key.key >= gui::key_t::digit_0 && key.key <= gui::key_t::digit_9)
      window.set_cursor(static_cast<gui::cursor_t>(static_cast<int>(key.key) - static_cast<int>(gui::key_t::digit_0)));
  }
  for (auto &pending : pastes)
    co_await std::move(pending);
}

// The variant holds exactly the four subscribed types, so this overload set has to cover them all
// and nothing else: leaving one out, or handling a type not subscribed to, does not compile.
vio::task_t<void> pointer(gui::window_t &window)
{
  auto events = window.subscribe<gui::pointer_move_event_t, gui::pointer_button_event_t, gui::scroll_event_t, gui::pointer_enter_event_t>();
  while (auto event = co_await events)
  {
    std::visit(overloaded{
                 [](const gui::pointer_move_event_t &e) { std::println("pointer at {:.1f}, {:.1f}", e.position.x, e.position.y); },
                 [](const gui::pointer_button_event_t &e) { std::println("{} button {} at {:.1f}, {:.1f}", button_name(e.button), e.pressed ? "down" : "up", e.position.x, e.position.y); },
                 [](const gui::scroll_event_t &e) { std::println("scroll {:.2f}, {:.2f}", e.dx, e.dy); },
                 [](const gui::pointer_enter_event_t &e) { std::println("pointer {}", e.entered ? "entered" : "left"); },
               },
               *event);
  }
}

vio::task_t<void> focus(gui::window_t &window)
{
  auto changes = window.subscribe<gui::focus_event_t>();
  while (auto change = co_await changes)
    std::println("focus {}", change->focused ? "gained" : "lost");
}

vio::task_t<void> draw(gui::window_t &window, shared_t &shared)
{
  auto context = gui::gl_context_t::create(window);
  if (!context)
  {
    std::println(stderr, "no OpenGL: {}", context.error().msg);
    co_return;
  }
  auto clear_color = context->proc<void (*)(float, float, float, float)>("glClearColor");
  auto clear = context->proc<void (*)(unsigned)>("glClear");
  while (auto frame = co_await window.frame())
  {
    context->make_current();
    clear_color(0.15f, 0.15f, 0.2f, 1);
    clear(0x4000);
    context->swap_buffers();
  }
}
} // namespace

int main(int argc, char **argv)
{
  const auto limit = std::chrono::milliseconds(argc > 1 ? std::atoi(argv[1]) : 0);
  return vio::run([limit](vio::event_loop_t &loop) -> vio::task_t<int> {
    auto display = gui::display_t::open(loop);
    if (!display)
    {
      std::println(stderr, "no display: {}", display.error().msg);
      co_return 1;
    }
    std::println("Type, click and scroll. Ctrl+C copies, Ctrl+V pastes, 0-9 change the cursor, Escape quits.");
    {
      auto window = gui::window_t::create(*display, {.title = "input echo", .size = {480, 320}});
      if (!window)
        co_return 1;
      shared_t shared;
      auto drawing = draw(*window, shared);
      auto typing = keyboard(*display, *window, shared);
      auto pointing = pointer(*window);
      auto focusing = focus(*window);
      auto closing = [](gui::window_t &window, shared_t &shared) -> vio::task_t<void> {
        auto requests = window.subscribe<gui::close_request_t>();
        if (co_await requests)
          shared.done = true;
      }(*window, shared);
      const auto start = std::chrono::steady_clock::now();
      while (!shared.done && (limit.count() == 0 || std::chrono::steady_clock::now() - start < limit))
        co_await vio::sleep(loop, 20ms);
      shared.done = true;
      window->close();
      co_await std::move(drawing);
      co_await std::move(typing);
      co_await std::move(pointing);
      co_await std::move(focusing);
      co_await std::move(closing);
    }
    co_return 0;
  });
}
