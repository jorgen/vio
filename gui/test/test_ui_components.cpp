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

// Phase 7: flex, dynamic children, props and child scopes.

#include <doctest/doctest.h>

#include <chrono>
#include <expected>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include <vio/event_loop.h>
#include <vio/gui/gui.h>
#include <vio/gui/ui/ui.h>
#include <vio/operation/sleep.h>
#include <vio/operation/tcp.h>
#include <vio/operation/tcp_server.h>
#include <vio/task.h>

#include "gui_test_helpers.h"

using namespace std::chrono_literals;
namespace gui = vio::gui;
namespace ui = vio::gui::ui;

namespace
{
constexpr ui::color_t red{1, 0, 0, 1};
constexpr ui::color_t green{0, 1, 0, 1};

// Run `root` in a 300x200 null window: settle, then `act` (which may press, change state and settle
// again), then close. `rects` is the last layout's hit-test list.
template <typename C>
void drive(C &root, std::vector<ui::rect_t> &rects, std::function<vio::task_t<void>(vio::event_loop_t &, gui::window_t &)> act = {})
{
  vio::event_loop_t loop;
  run_gui_test(loop,
               [](vio::event_loop_t &loop, C &root, std::vector<ui::rect_t> &rects, std::function<vio::task_t<void>(vio::event_loop_t &, gui::window_t &)> act) -> vio::task_t<void>
               {
                 gui::display_config_t display_config;
                 display_config.backend = "null";
                 display_config.frame_interval_ns = std::chrono::nanoseconds(2ms).count();
                 auto display = gui::display_t::open(loop, display_config);
                 REQUIRE(display.has_value());
                 {
                   auto window = gui::window_t::create(*display, {.size = {300, 200}});
                   ui::run_config_t config;
                   config.on_layout = [&rects](std::span<const ui::draw_item_t> items)
                   {
                     rects.clear();
                     for (const auto &item : items)
                       rects.push_back(item.rect);
                   };
                   auto running = ui::run(*window, root, std::move(config));
                   (void)co_await vio::sleep(loop, 40ms);
                   if (act)
                     co_await act(loop, *window);
                   window->close();
                   co_await std::move(running);
                 }
                 loop.stop();
               }(loop, root, rects, std::move(act)));
}

vio::task_t<void> settle(vio::event_loop_t &loop)
{
  (void)co_await vio::sleep(loop, 40ms);
}

void click(gui::window_t &window, gui::point_t at)
{
  window.impl()->on_input(gui::pointer_move_event_t{at});
  window.impl()->on_input(gui::pointer_button_event_t{gui::button_t::left, true, at});
  window.impl()->on_input(gui::pointer_button_event_t{gui::button_t::left, false, at});
  window.impl()->on_input(gui::pointer_move_event_t{{900, 900}});
}
} // namespace

TEST_CASE("ui flex: what is left along a row is shared by what grows, and a spacer pushes to the end")
{
  struct rows_t
  {
    ui::node_t view() const
    {
      // A 200-wide box stretches its row; inside, a spacer takes what the boxes leave.
      return ui::column_t{.children = {
                            ui::box_t{.size = {200, 20},
                                      .color = {0, 0, 0, 0},
                                      .align_x = ui::align_t::stretch,
                                      .children = {ui::row_t{.children = {ui::box_t{.size = {20, 20}, .color = red}, ui::spacer_t{}, ui::box_t{.size = {30, 20}, .color = green}}}}},
                            // 100 wide, two growing boxes 1:3 after 10 and 10 of their own and a gap of 4.
                            ui::box_t{.size = {100, 10},
                                      .color = {0, 0, 0, 0},
                                      .align_x = ui::align_t::stretch,
                                      .children = {ui::row_t{.gap = 4, .children = {ui::box_t{.size = {10, 10}, .color = red, .grow = 1}, ui::box_t{.size = {10, 10}, .color = green, .grow = 3}}}}},
                          }};
    }
  } root;
  std::vector<ui::rect_t> rects;
  drive(root, rects);
  REQUIRE(rects.size() == 6);
  CHECK(rects[1] == ui::rect_t{0, 0, 20, 20});
  CHECK(rects[2] == ui::rect_t{170, 0, 30, 20});
  // 100 - 10 - 10 - 4 = 76 left: 19 and 57.
  CHECK(rects[4] == ui::rect_t{0, 20, 10 + 19, 10});
  CHECK(rects[5] == ui::rect_t{10 + 19 + 4, 20, 10 + 57, 10});
}

TEST_CASE("ui flex: the window is the root's size, so a column can fill it and stretch across it")
{
  struct page_t
  {
    ui::node_t view() const
    {
      return ui::column_t{.align = ui::align_t::stretch,
                          .children = {
                            ui::box_t{.size = {10, 30}, .color = red},
                            ui::box_t{.size = {10, 10}, .color = green, .grow = 1},
                          }};
    }
  } root;
  std::vector<ui::rect_t> rects;
  drive(root, rects);
  REQUIRE(rects.size() == 2);
  CHECK(rects[0] == ui::rect_t{0, 0, 300, 30});
  CHECK(rects[1] == ui::rect_t{0, 30, 300, 170});
}

namespace
{
struct item_t
{
  int id = 0;
  int count = 0;
  bool *ended = nullptr;
  ui::pressable_t press;

  ui::node_t view() const
  {
    return ui::box_t{.size = {20 + count, 10}, .color = red, .events = press};
  }

  ui::behaviour_t behave(ui::scope_t &scope)
  {
    auto presses = ui::subscribe<ui::press_event_t>(press);
    while (co_await presses)
      ++count;
    if (ended)
      *ended = true;
    (void)scope;
  }
};

// The list changes from outside any behaviour, so a press on `poke` is what wakes the page.
struct list_page_t
{
  ui::list_t<item_t> items;
  ui::pressable_t poke;

  ui::node_t view() const
  {
    return ui::row_t{.children = {ui::box_t{.size = {10, 10}, .color = green, .events = poke}, ui::column_t{.gap = 2, .children = items.mount_all()}}};
  }

  ui::behaviour_t behave(ui::scope_t &)
  {
    auto presses = ui::subscribe<ui::press_event_t>(poke);
    while (co_await presses)
    {
    }
  }
};
} // namespace

TEST_CASE("ui list: items keep their state through inserts, and erasing one ends its behaviours")
{
  list_page_t page;
  bool first_ended = false;
  bool second_ended = false;
  page.items.emplace_back(item_t{.id = 1, .ended = &first_ended});
  page.items.emplace_back(item_t{.id = 2, .ended = &second_ended});
  struct seen_t
  {
    std::vector<ui::rect_t> after_insert;
    bool first_ended_at_erase = true;
  } seen;
  std::vector<ui::rect_t> rects;
  drive(page, rects,
        [&page, &rects, &seen, &first_ended](vio::event_loop_t &loop, gui::window_t &window) -> vio::task_t<void>
        {
          // Press the second item three times: it grows to 23 wide.
          for (int i = 0; i < 3; ++i)
            click(window, {15, 12 + 5});
          co_await settle(loop);
          // A new item in front: the second item moves down, keeping its count.
          page.items.emplace(0, item_t{.id = 0});
          click(window, {5, 5});
          co_await settle(loop);
          seen.after_insert = rects;
          // Erase the item with id 1.
          seen.first_ended_at_erase = first_ended;
          page.items.erase(page.items[1]);
          click(window, {5, 5});
          co_await settle(loop);
        });
  REQUIRE(seen.after_insert.size() == 4);
  CHECK(seen.after_insert[3] == ui::rect_t{10, 24, 23, 10});
  CHECK(!seen.first_ended_at_erase);
  CHECK(first_ended);
  CHECK(page.items.size() == 2);
  CHECK(page.items[1].id == 2);
  CHECK(page.items[1].count == 3);
  REQUIRE(rects.size() == 3);
  CHECK(rects[2] == ui::rect_t{10, 12, 23, 10});
}

namespace
{
struct badge_t
{
  struct props_t
  {
    bool highlight = false;
    friend bool operator==(const props_t &, const props_t &) = default;
  };
  props_t props;
  mutable int views = 0;

  ui::node_t view() const
  {
    ++views;
    return ui::box_t{.size = {props.highlight ? 40 : 20, 10}, .color = green};
  }
};

struct holder_t
{
  badge_t badge;
  int selected = 0;
  int other = 0;
  ui::pressable_t select;
  ui::pressable_t touch;

  ui::node_t view() const
  {
    return ui::row_t{.children = {ui::box_t{.size = {10, 10}, .color = red, .events = select}, ui::box_t{.size = {10, 10}, .color = red, .events = touch}, ui::mount(badge, {.highlight = selected == 1})}};
  }

  ui::behaviour_t behave(ui::scope_t &)
  {
    auto presses = ui::subscribe<ui::press_event_t>(select, touch);
    while (auto press = co_await presses)
    {
      if (press->source == &select)
        selected = 1;
      else
        ++other;
    }
  }
};
} // namespace

TEST_CASE("ui props: a child is rebuilt when its props change, and not when its parent merely rebuilds")
{
  holder_t holder;
  struct seen_t
  {
    int views_first = 0;
    int views_after_touch = 0;
    bool highlight = false;
  } seen;
  std::vector<ui::rect_t> rects;
  drive(holder, rects,
        [&holder, &seen](vio::event_loop_t &loop, gui::window_t &window) -> vio::task_t<void>
        {
          seen.views_first = holder.badge.views;
          // The parent rebuilds with the same props: the badge does not.
          click(window, {15, 5});
          co_await settle(loop);
          seen.views_after_touch = holder.badge.views;
          click(window, {5, 5});
          co_await settle(loop);
          seen.highlight = holder.badge.props.highlight;
        });
  CHECK(holder.other == 1);
  CHECK(seen.views_first == 1);
  CHECK(seen.views_after_touch == 1);
  CHECK(seen.highlight);
  CHECK(holder.badge.views == 2);
  REQUIRE(rects.size() == 3);
  CHECK(rects[2].width == 40);
}

namespace
{
struct worker_t
{
  std::optional<int> answer;
  std::optional<int> cancelled_answer = 7;
  bool joined = false;
  bool after = false;

  ui::node_t view() const
  {
    return ui::box_t{.size = {10, 10}};
  }

  static ui::job_t<int> compute(ui::scope_t &scope, std::chrono::milliseconds delay, int value)
  {
    if (!co_await vio::sleep(scope.loop(), delay, scope.token()))
      co_return -1;
    co_return value;
  }

  ui::behaviour_t behave(ui::scope_t &scope)
  {
    // A job in the component's own scope, awaited for its result.
    auto spawned = scope.spawn(compute(scope, 5ms, 42));
    answer = co_await spawned;

    // A child scope: a long job cancelled with it, and joined before the scope ends.
    {
      ui::scope_t sub(scope);
      auto slow = sub.spawn(compute(sub, 1h, 9));
      (void)co_await vio::sleep(scope.loop(), 5ms, scope.token());
      sub.cancel();
      cancelled_answer = co_await slow;
      co_await sub.join();
      joined = true;
    }
    // The component's own scope is untouched by the child's cancellation.
    after = bool(co_await vio::sleep(scope.loop(), 1ms, scope.token()));
  }
};
} // namespace

TEST_CASE("ui scope: a spawned job gives back its result, and a cancelled child scope gives back none")
{
  worker_t worker;
  std::vector<ui::rect_t> rects;
  drive(worker, rects);
  CHECK(worker.answer == 42);
  // The cancelled sleep resolved, the job returned -1 at once... or its frame was refused first;
  // either way the parent learns it, and nothing waits forever.
  CHECK((!worker.cancelled_answer.has_value() || *worker.cancelled_answer == -1));
  CHECK(worker.joined);
  CHECK(worker.after);
}

namespace
{
// Presses, a timer and a socket in one loop (phase 8).
struct mixer_t
{
  vio::tcp_reader_t *reader = nullptr;
  ui::pressable_t press;
  int presses = 0;
  int ticks = 0;
  std::vector<std::string> lines;
  bool closed = false;
  bool finished = false;

  ui::node_t view() const
  {
    return ui::box_t{.size = {10, 10}, .color = red, .events = press};
  }

  ui::behaviour_t behave(ui::scope_t &scope)
  {
    auto pressed = ui::subscribe<ui::press_event_t>(press);
    auto ticked = ui::every(scope, 5ms);
    auto read = ui::lines(scope, *reader);
    auto events = ui::merge(scope, pressed, ticked, read);
    while (auto event = co_await events)
    {
      switch (event->index())
      {
      case 0:
        ++presses;
        break;
      case 1:
        ++ticks;
        break;
      default:
        auto &line = std::get<2>(*event);
        if (!line.text.empty())
          lines.push_back(line.text);
        closed = closed || line.closed;
        break;
      }
      if (closed && presses > 0 && ticks >= 3)
        break;
    }
    finished = true;
  }
};

std::expected<std::pair<vio::tcp_server_t, int>, vio::error_t> listener(vio::event_loop_t &loop)
{
  auto address = vio::ip4_addr("127.0.0.1", 0);
  if (!address)
    return std::unexpected(address.error());
  auto server = vio::tcp_create_server(loop);
  if (!server)
    return std::unexpected(server.error());
  if (auto bound = vio::tcp_bind(server.value(), reinterpret_cast<const sockaddr *>(&address.value())); !bound)
    return std::unexpected(bound.error());
  auto name = vio::sockname(server->tcp);
  if (!name)
    return std::unexpected(name.error());
  sockaddr_storage storage = name.value();
  return std::make_pair(std::move(server.value()), int(ntohs(reinterpret_cast<sockaddr_in *>(&storage)->sin_port)));
}
} // namespace

TEST_CASE("ui merge: presses, a timer and a socket's lines arrive in one loop, and none is lost")
{
  vio::event_loop_t loop;
  mixer_t mixer;
  run_gui_test(loop,
               [](vio::event_loop_t &loop, mixer_t &mixer) -> vio::task_t<void>
               {
                 gui::display_config_t display_config;
                 display_config.backend = "null";
                 display_config.frame_interval_ns = std::chrono::nanoseconds(2ms).count();
                 auto display = gui::display_t::open(loop, display_config);
                 REQUIRE(display.has_value());
                 {
                   auto server = listener(loop);
                   REQUIRE(server.has_value());
                   auto address = vio::ip4_addr("127.0.0.1", server->second);
                   REQUIRE(address.has_value());
                   auto listening = vio::tcp_listen(server->first, 4);
                   std::optional<vio::tcp_t> client;
                   {
                     auto created = vio::tcp_create(loop);
                     REQUIRE(created.has_value());
                     client.emplace(std::move(created.value()));
                   }
                   auto connected = co_await vio::tcp_connect(*client, reinterpret_cast<const sockaddr *>(&address.value()));
                   REQUIRE(connected.has_value());
                   REQUIRE((co_await std::move(listening)).has_value());
                   auto accepted = vio::tcp_accept(server->first);
                   REQUIRE(accepted.has_value());
                   auto reader = vio::tcp_create_reader(accepted.value());
                   REQUIRE(reader.has_value());
                   mixer.reader = &reader.value();
                   {
                     auto window = gui::window_t::create(*display, {.size = {100, 100}});
                     auto running = ui::run(*window, mixer);
                     // A line split across writes, a CRLF, and an unterminated tail the close ends.
                     const std::string first = "alpha\nbeta\r\ngam";
                     (void)co_await vio::write_tcp(*client, reinterpret_cast<const uint8_t *>(first.data()), first.size());
                     (void)co_await vio::sleep(loop, 20ms);
                     const std::string second = "ma\nlast";
                     (void)co_await vio::write_tcp(*client, reinterpret_cast<const uint8_t *>(second.data()), second.size());
                     window->impl()->on_input(gui::pointer_move_event_t{{5, 5}});
                     window->impl()->on_input(gui::pointer_button_event_t{gui::button_t::left, true, {5, 5}});
                     window->impl()->on_input(gui::pointer_button_event_t{gui::button_t::left, false, {5, 5}});
                     (void)co_await vio::sleep(loop, 20ms);
                     client.reset();
                     for (int i = 0; i < 50 && !mixer.finished; ++i)
                       (void)co_await vio::sleep(loop, 10ms);
                     window->close();
                     co_await std::move(running);
                   }
                 }
                 loop.stop();
               }(loop, mixer));
  CHECK(mixer.finished);
  CHECK(mixer.presses == 1);
  CHECK(mixer.ticks >= 3);
  CHECK(mixer.lines == std::vector<std::string>{"alpha", "beta", "gamma", "last"});
  CHECK(mixer.closed);
}
