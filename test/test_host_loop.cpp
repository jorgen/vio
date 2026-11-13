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

#include <doctest/doctest.h>

#include <algorithm>
#include <chrono>
#include <functional>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <vio/event_loop.h>
#include <vio/host_loop.h>
#include <vio/operation/timer.h>

using namespace std::chrono_literals;

namespace
{
bool host_wait_supported(vio::event_loop_t &loop)
{
  return std::string(loop.backend_name()) != "io_uring";
}

struct sleeping_host_t final : vio::host_wait_t
{
  void wait(std::optional<std::chrono::nanoseconds> timeout) override
  {
    timeouts.push_back(timeout);
    if (during_wait)
      std::exchange(during_wait, nullptr)();
    if (timeout)
      std::this_thread::sleep_for(std::min<std::chrono::nanoseconds>(*timeout, 50ms));
    else
      std::this_thread::sleep_for(1ms);
  }

  std::vector<std::optional<std::chrono::nanoseconds>> timeouts;
  std::function<void()> during_wait;
};

vio::timer_t make_timer(vio::event_loop_t &loop)
{
  auto created = vio::timer_create(loop);
  REQUIRE(created.has_value());
  return std::move(created.value());
}
} // namespace

TEST_CASE("host_loop: every native backend has a handle a host can wait on")
{
  vio::event_loop_t loop;
  CHECK(vio::loop_native_handle(loop) != -1);
}

TEST_CASE("host_loop: the next timeout is empty with nothing scheduled and bounded by the next timer")
{
  vio::event_loop_t loop;
  CHECK_FALSE(vio::loop_next_timeout(loop).has_value());
  {
    auto timer = make_timer(loop);
    REQUIRE(vio::timer_rearm(timer, 1s));
    auto next = vio::loop_next_timeout(loop);
    REQUIRE(next.has_value());
    CHECK(*next > 0ns);
    CHECK(*next <= 1s);
  }
  loop.stop();
  loop.run();
}

TEST_CASE("host_loop: io_uring refuses a host wait")
{
  vio::event_loop_t loop;
  sleeping_host_t host;
  auto installed = vio::loop_set_host_wait(loop, &host);
  if (host_wait_supported(loop))
  {
    CHECK(installed.has_value());
  }
  else
  {
    REQUIRE_FALSE(installed.has_value());
    CHECK(installed.error().code == vio::errc::not_supported);
  }
  CHECK(vio::loop_set_host_wait(loop, nullptr).has_value());
}

TEST_CASE("host_loop: the loop blocks in the host, which is told when the next timer is due")
{
  vio::event_loop_t loop;
  if (!host_wait_supported(loop))
    return;
  sleeping_host_t host;
  REQUIRE(vio::loop_set_host_wait(loop, &host));
  bool fired = false;
  std::optional<vio::timer_t> timer;
  loop.run_in_loop([&] {
    timer = make_timer(loop);
    vio::timer_on_fire(*timer, [&] {
      fired = true;
      timer.reset();
      loop.stop();
    });
    REQUIRE(vio::timer_rearm(*timer, 20ms));
  });
  loop.run();
  REQUIRE(vio::loop_set_host_wait(loop, nullptr));
  CHECK(fired);
  REQUIRE_FALSE(host.timeouts.empty());
  const bool told_about_timer =
    std::any_of(host.timeouts.begin(), host.timeouts.end(), [](const auto &timeout) { return timeout && *timeout > 0ns && *timeout <= 20ms; });
  CHECK(told_about_timer);
}

TEST_CASE("host_loop: a nested turn run from inside the host wait runs the work the loop has queued")
{
  vio::event_loop_t loop;
  if (!host_wait_supported(loop))
    return;
  sleeping_host_t host;
  REQUIRE(vio::loop_set_host_wait(loop, &host));
  bool ran_inside = false;
  bool inside_wait = false;
  host.during_wait = [&] {
    inside_wait = true;
    loop.run_in_loop([&] { ran_inside = inside_wait; });
    vio::loop_run_nested(loop);
    inside_wait = false;
    loop.stop();
  };
  loop.run();
  REQUIRE(vio::loop_set_host_wait(loop, nullptr));
  CHECK(ran_inside);
}

TEST_CASE("host_loop: a nested turn outside run() does nothing")
{
  vio::event_loop_t loop;
  bool ran = false;
  loop.run_in_loop([&] { ran = true; });
  vio::loop_run_nested(loop);
  CHECK_FALSE(ran);
  loop.stop();
  loop.run();
  CHECK(ran);
}
