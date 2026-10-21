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
#include <chrono>
#include <cstdlib>
#include <format>
#include <optional>
#include <print>
#include <string>
#include <vector>

#include <vio/gui/context.h>
#include <vio/gui/gui.h>
#include <vio/operation/sleep.h>
#include <vio/operation/tcp.h>
#include <vio/operation/tcp_server.h>
#include <vio/run.h>

namespace gui = vio::gui;
using namespace std::chrono_literals;

namespace
{
struct state_t
{
  std::array<std::optional<gui::window_t>, 2> windows;
  int messages = 0;
  bool done = false;

  [[nodiscard]] bool any_open() const
  {
    return windows[0] || windows[1];
  }
};

vio::task_t<void> draw(gui::window_t &window, state_t &state, float hue)
{
  auto context = gui::gl_context_t::create(window);
  if (!context)
  {
    std::println(stderr, "no OpenGL: {}", context.error().msg);
    co_return;
  }
  auto viewport = context->proc<void (*)(int, int, int, int)>("glViewport");
  auto clear_color = context->proc<void (*)(float, float, float, float)>("glClearColor");
  auto clear = context->proc<void (*)(unsigned)>("glClear");
  while (auto frame = co_await window.frame())
  {
    const float pulse = static_cast<float>(state.messages % 10) / 10.0f;
    context->make_current();
    viewport(0, 0, frame->framebuffer.width, frame->framebuffer.height);
    clear_color(hue, pulse, 1.0f - hue, 1);
    clear(0x4000);
    context->swap_buffers();
  }
}

vio::task_t<void> close_on_request(std::optional<gui::window_t> &window)
{
  if (co_await window->close_requested())
    window.reset();
}

vio::task_t<void> serve(vio::tcp_server_t server, state_t &state)
{
  if (!co_await vio::tcp_listen(server, 4))
    co_return;
  auto connection = vio::tcp_accept(server);
  if (!connection)
    co_return;
  auto reader = vio::tcp_create_reader(*connection);
  if (!reader)
    co_return;
  while (auto data = co_await *reader)
  {
    const std::string text(data->chars(), data->size());
    ++state.messages;
    for (auto &window : state.windows)
    {
      if (window)
        window->set_title(text);
    }
  }
}

vio::task_t<void> send_ticks(vio::event_loop_t &loop, int port, state_t &state)
{
  auto client = vio::tcp_create(loop);
  auto address = vio::ip4_addr("127.0.0.1", port);
  if (!client || !address || !co_await vio::tcp_connect(*client, reinterpret_cast<const sockaddr *>(&*address)))
    co_return;
  for (int tick = 1; !state.done; ++tick)
  {
    const auto text = std::format("message {} over TCP", tick);
    if (!co_await vio::write_tcp(*client, reinterpret_cast<const std::uint8_t *>(text.data()), text.size()))
      break;
    co_await vio::sleep(loop, 250ms);
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
    auto server = vio::tcp_create_server(loop);
    auto any = vio::ip4_addr("127.0.0.1", 0);
    if (!server || !any || !vio::tcp_bind(*server, reinterpret_cast<const sockaddr *>(&*any)))
      co_return 1;
    auto bound = vio::sockname(server->tcp);
    const int port = ntohs(reinterpret_cast<const sockaddr_in *>(&*bound)->sin_port);
    std::println("Two windows; their titles follow messages arriving on 127.0.0.1:{}. Close both to quit.", port);

    state_t state;
    std::vector<vio::task_t<void>> drawing;
    std::vector<vio::task_t<void>> closing;
    for (int i = 0; i < 2; ++i)
    {
      auto window = gui::window_t::create(*display, {.title = "waiting for the network", .size = {360, 240}});
      if (!window)
        co_return 1;
      auto &slot = state.windows[static_cast<std::size_t>(i)];
      slot.emplace(std::move(*window));
      drawing.push_back(draw(*slot, state, static_cast<float>(i)));
      closing.push_back(close_on_request(slot));
    }

    auto serving = serve(std::move(*server), state);
    auto sending = send_ticks(loop, port, state);

    const auto start = std::chrono::steady_clock::now();
    while (state.any_open() && (limit.count() == 0 || std::chrono::steady_clock::now() - start < limit))
      co_await vio::sleep(loop, 20ms);
    std::println("{} messages arrived", state.messages);

    state.done = true;
    for (auto &window : state.windows)
      window.reset();
    co_await std::move(sending);
    co_await std::move(serving);
    for (auto &task : drawing)
      co_await std::move(task);
    for (auto &task : closing)
      co_await std::move(task);
    co_return 0;
  });
}
