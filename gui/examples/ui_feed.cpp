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

// Presses, a timer and a socket in one behaviour (gui/PLAN.md, phase 8). A server in the same
// process writes a line every few hundred milliseconds over a real TCP connection; the window's
// one behaviour merges those lines with a once-a-second clock and the "clear" button, in one loop
// with no callbacks and no locks.

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <optional>
#include <string>

#include <vio/event_loop.h>
#include <vio/gui/gui.h>
#include <vio/gui/ui/ui.h>
#include <vio/operation/sleep.h>
#include <vio/operation/tcp.h>
#include <vio/operation/tcp_server.h>
#include <vio/run.h>

namespace gui = vio::gui;
namespace ui = vio::gui::ui;
using namespace std::chrono_literals;

namespace
{
constexpr ui::color_t ink{0.92f, 0.92f, 0.95f, 1};
constexpr ui::color_t grey{0.6f, 0.6f, 0.65f, 1};
constexpr ui::color_t panel{0.16f, 0.16f, 0.19f, 1};
constexpr ui::color_t accent{0.3f, 0.5f, 0.9f, 1};

struct feed_t
{
  vio::tcp_reader_t *reader = nullptr;
  ui::pressable_t clear;
  std::deque<std::string> log;
  std::uint64_t seconds = 0;
  int received = 0;
  bool closed = false;

  ui::node_t view() const
  {
    std::vector<ui::node_t> entries;
    for (const auto &line : log)
      entries.push_back(ui::text_t{.text = line, .size = 14, .color = ink});
    return ui::column_t{
      .gap = 12,
      .align = ui::align_t::stretch,
      .padding = 16,
      .children = {
        ui::row_t{
          .gap = 12,
          .align = ui::align_t::center,
          .children = {ui::text_t{.text = "vio ui: a socket feed", .size = 20, .color = ink}, ui::spacer_t{},
                       ui::text_t{.text = std::to_string(received) + " lines, " + std::to_string(seconds) + " s" + (closed ? ", closed" : ""), .size = 14, .color = grey},
                       ui::box_t{.size = {64, 28}, .color = clear.hovered() ? ui::color_t{0.4f, 0.6f, 1, 1} : accent, .radius = 6, .events = clear, .children = {ui::text_t{.text = "clear", .size = 14, .color = ink}}}}},
        ui::box_t{.color = panel, .radius = 8, .grow = 1, .padding = 12, .align_x = ui::align_t::start, .align_y = ui::align_t::start, .children = {ui::column_t{.gap = 4, .children = std::move(entries)}}},
      }};
  }

  ui::behaviour_t behave(ui::scope_t &scope)
  {
    auto presses = ui::subscribe<ui::press_event_t>(clear);
    auto clock = ui::every(scope, 1s);
    auto lines = ui::lines(scope, *reader);
    auto events = ui::merge(scope, presses, clock, lines);
    while (auto event = co_await events)
    {
      if (event->index() == 0)
        log.clear();
      else if (event->index() == 1)
        seconds = std::get<1>(*event).count;
      else
      {
        auto &line = std::get<2>(*event);
        closed = line.closed;
        if (line.text.empty())
          continue;
        ++received;
        log.push_back(std::move(line.text));
        while (log.size() > 20)
          log.pop_front();
      }
    }
  }
};

// The other end: writes a line now and then until the window closes.
vio::task_t<void> serve(vio::event_loop_t &loop, vio::tcp_t &peer, const bool &stop)
{
  const char *words[] = {"temperature nominal", "pressure rising", "valve 3 open", "pump 2 at 80%", "flow steady", "alarm cleared"};
  for (int n = 1; !stop; ++n)
  {
    const std::string line = "#" + std::to_string(n) + "  " + words[n % 6] + "\n";
    if (!co_await vio::write_tcp(peer, reinterpret_cast<const uint8_t *>(line.data()), line.size()))
      break;
    (void)co_await vio::sleep(loop, std::chrono::milliseconds(150 + (n * 97) % 400));
  }
}
} // namespace

int main(int argc, char **argv)
{
  const auto limit = std::chrono::milliseconds(argc > 1 ? std::atoi(argv[1]) : 0);
  return vio::run(
    [limit](vio::event_loop_t &loop) -> vio::task_t<int>
    {
      auto display = gui::display_t::open(loop);
      if (!display)
      {
        std::fprintf(stderr, "no display: %s\n", display.error().msg.c_str());
        co_return 1;
      }
      // A loopback connection: the feed reads one end, serve() writes the other.
      auto address = vio::ip4_addr("127.0.0.1", 0);
      auto server = vio::tcp_create_server(loop);
      if (!address || !server || !vio::tcp_bind(server.value(), reinterpret_cast<const sockaddr *>(&address.value())))
        co_return 1;
      auto name = vio::sockname(server->tcp);
      if (!name)
        co_return 1;
      sockaddr_storage storage = name.value();
      auto target = vio::ip4_addr("127.0.0.1", int(ntohs(reinterpret_cast<sockaddr_in *>(&storage)->sin_port)));
      auto listening = vio::tcp_listen(server.value(), 1);
      auto client = vio::tcp_create(loop);
      if (!client || !target || !co_await vio::tcp_connect(client.value(), reinterpret_cast<const sockaddr *>(&target.value())) || !co_await std::move(listening))
        co_return 1;
      auto accepted = vio::tcp_accept(server.value());
      if (!accepted)
        co_return 1;
      auto reader = vio::tcp_create_reader(client.value());
      if (!reader)
        co_return 1;
      {
        bool stop = false;
        auto writer = serve(loop, accepted.value(), stop);
        auto window = gui::window_t::create(*display, {.title = "vio ui: a socket feed", .size = {900, 700}});
        if (!window)
          co_return 1;
        auto closing = [](gui::window_t &window, std::chrono::milliseconds limit) -> vio::task_t<void>
        {
          auto requests = window.subscribe<gui::close_request_t>();
          if (limit.count() > 0)
            (void)co_await vio::sleep(*window.impl()->display.loop, limit);
          else
            co_await requests;
          window.close();
        }(*window, limit);
        co_await ui::run(*window, feed_t{.reader = &reader.value()});
        co_await std::move(closing);
        stop = true;
        co_await std::move(writer);
      }
      co_return 0;
    });
}
