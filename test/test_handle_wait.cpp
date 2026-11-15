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

#include <array>
#include <chrono>
#include <functional>
#include <optional>
#include <thread>
#include <utility>

#include <vio/cancellation.h>
#include <vio/event_loop.h>
#include <vio/host_loop.h>
#include <vio/operation/handle_wait.h>
#include <vio/operation/timer.h>
#include <vio/task.h>

using namespace std::chrono_literals;

namespace
{
struct event_t
{
  explicit event_t(bool manual_reset = false)
    : handle(::CreateEventW(nullptr, manual_reset ? TRUE : FALSE, FALSE, nullptr))
  {
    REQUIRE(handle != nullptr);
  }
  event_t(const event_t &) = delete;
  event_t &operator=(const event_t &) = delete;
  ~event_t()
  {
    ::CloseHandle(handle);
  }
  HANDLE handle;
};

vio::handle_wait_t make_wait(vio::event_loop_t &loop, HANDLE object)
{
  auto created = vio::handle_wait_create(loop, object);
  REQUIRE(created.has_value());
  return std::move(created.value());
}

void after_turns(vio::event_loop_t &loop, int turns, std::function<void()> work)
{
  if (turns == 0)
  {
    work();
    return;
  }
  loop.run_in_loop([&loop, turns, work = std::move(work)]() mutable { after_turns(loop, turns - 1, std::move(work)); });
}
} // namespace

TEST_CASE("handle_wait: an armed wait reports an event set while it waits")
{
  vio::event_loop_t loop;
  event_t event;
  std::optional<vio::handle_wait_t> wait;
  int calls = 0;
  loop.run_in_loop([&] {
    wait = make_wait(loop, event.handle);
    vio::handle_wait_on_signalled(*wait, [&] {
      ++calls;
      CHECK_FALSE(vio::handle_wait_is_armed(*wait));
      wait.reset();
      loop.stop();
    });
    REQUIRE(vio::handle_wait_arm(*wait));
    CHECK(vio::handle_wait_is_armed(*wait));
    ::SetEvent(event.handle);
  });
  loop.run();
  CHECK(calls == 1);
  CHECK(::WaitForSingleObject(event.handle, 0) == WAIT_TIMEOUT);
  CHECK(vio::detail::core(loop).open_resources() == 0);
}

TEST_CASE("handle_wait: an event already set when the wait is armed is reported")
{
  vio::event_loop_t loop;
  event_t event;
  ::SetEvent(event.handle);
  std::optional<vio::handle_wait_t> wait;
  int calls = 0;
  loop.run_in_loop([&] {
    wait = make_wait(loop, event.handle);
    vio::handle_wait_on_signalled(*wait, [&] {
      ++calls;
      wait.reset();
      loop.stop();
    });
    REQUIRE(vio::handle_wait_arm(*wait));
  });
  loop.run();
  CHECK(calls == 1);
}

TEST_CASE("handle_wait: a signal set from another thread wakes a blocked loop")
{
  vio::event_loop_t loop;
  event_t event;
  std::optional<vio::handle_wait_t> wait;
  std::thread setter;
  int calls = 0;
  loop.run_in_loop([&] {
    wait = make_wait(loop, event.handle);
    vio::handle_wait_on_signalled(*wait, [&] {
      ++calls;
      wait.reset();
      loop.stop();
    });
    REQUIRE(vio::handle_wait_arm(*wait));
    setter = std::thread([&] {
      std::this_thread::sleep_for(30ms);
      ::SetEvent(event.handle);
    });
  });
  loop.run();
  setter.join();
  CHECK(calls == 1);
}

TEST_CASE("handle_wait: a signal is reported once per arm")
{
  vio::event_loop_t loop;
  event_t event(true);
  ::SetEvent(event.handle);
  std::optional<vio::handle_wait_t> wait;
  int calls = 0;
  loop.run_in_loop([&] {
    wait = make_wait(loop, event.handle);
    vio::handle_wait_on_signalled(*wait, [&] {
      ++calls;
      if (calls == 1)
      {
        after_turns(loop, 3, [&] {
          CHECK(calls == 1);
          REQUIRE(vio::handle_wait_arm(*wait));
        });
        return;
      }
      wait.reset();
      loop.stop();
    });
    REQUIRE(vio::handle_wait_arm(*wait));
  });
  loop.run();
  CHECK(calls == 2);
}

TEST_CASE("handle_wait: a disarmed wait is not called and leaves the event set")
{
  vio::event_loop_t loop;
  event_t event;
  std::optional<vio::handle_wait_t> wait;
  int calls = 0;
  loop.run_in_loop([&] {
    wait = make_wait(loop, event.handle);
    vio::handle_wait_on_signalled(*wait, [&] { ++calls; });
    REQUIRE(vio::handle_wait_arm(*wait));
    vio::handle_wait_disarm(*wait);
    CHECK_FALSE(vio::handle_wait_is_armed(*wait));
    ::SetEvent(event.handle);
    after_turns(loop, 3, [&] {
      wait.reset();
      loop.stop();
    });
  });
  loop.run();
  CHECK(calls == 0);
  CHECK(::WaitForSingleObject(event.handle, 0) == WAIT_OBJECT_0);
}

TEST_CASE("handle_wait: an armed wait that does not keep the loop alive lets run() return")
{
  vio::event_loop_t loop;
  event_t event;
  std::optional<vio::handle_wait_t> wait;
  loop.run_in_loop([&] {
    wait = make_wait(loop, event.handle);
    REQUIRE(vio::handle_wait_set_keeps_loop_alive(*wait, false));
    REQUIRE(vio::handle_wait_arm(*wait));
    loop.stop();
  });
  loop.run();
  REQUIRE(wait.has_value());
  CHECK(vio::handle_wait_is_armed(*wait));
  CHECK(vio::detail::core(loop).in_flight() == 0);

  REQUIRE(vio::handle_wait_set_keeps_loop_alive(*wait, true));
  CHECK(vio::handle_wait_is_armed(*wait));
  CHECK(vio::detail::core(loop).in_flight() == 1);

  wait.reset();
  loop.stop();
  loop.run();
  CHECK(vio::detail::core(loop).in_flight() == 0);
  CHECK(vio::detail::core(loop).open_resources() == 0);
}

TEST_CASE("handle_wait: a wait destroyed while armed closes without being called")
{
  vio::event_loop_t loop;
  event_t event;
  int calls = 0;
  loop.run_in_loop([&] {
    auto wait = make_wait(loop, event.handle);
    vio::handle_wait_on_signalled(wait, [&] { ++calls; });
    REQUIRE(vio::handle_wait_arm(wait));
    ::SetEvent(event.handle);
  });
  loop.stop();
  loop.run();
  CHECK(calls == 0);
  CHECK(vio::detail::core(loop).open_resources() == 0);
}

TEST_CASE("handle_wait: a null or invalid handle is refused")
{
  vio::event_loop_t loop;
  auto null_wait = vio::handle_wait_create(loop, nullptr);
  REQUIRE_FALSE(null_wait.has_value());
  CHECK(null_wait.error().code == vio::errc::invalid_argument);
  auto invalid_wait = vio::handle_wait_create(loop, INVALID_HANDLE_VALUE);
  REQUIRE_FALSE(invalid_wait.has_value());
  CHECK(invalid_wait.error().code == vio::errc::invalid_argument);
  loop.stop();
  loop.run();
}

namespace
{
struct stealing_host_t final : vio::host_wait_t
{
  explicit stealing_host_t(vio::event_loop_t &loop)
    : port(reinterpret_cast<HANDLE>(vio::loop_native_handle(loop)))
  {
  }

  void wait(std::optional<std::chrono::nanoseconds> timeout) override
  {
    const DWORD milliseconds = timeout ? static_cast<DWORD>(std::chrono::ceil<std::chrono::milliseconds>(*timeout).count()) : 100;
    std::array<OVERLAPPED_ENTRY, 16> entries{};
    ULONG count = 0;
    if (!::GetQueuedCompletionStatusEx(port, entries.data(), static_cast<ULONG>(entries.size()), &count, milliseconds, FALSE))
      return;
    if (while_held)
      std::exchange(while_held, nullptr)();
    for (ULONG i = 0; i < count; ++i)
      ::PostQueuedCompletionStatus(port, entries[i].dwNumberOfBytesTransferred, entries[i].lpCompletionKey, entries[i].lpOverlapped);
  }

  HANDLE port;
  std::function<void()> while_held;
};
} // namespace

TEST_CASE("handle_wait: a wait disarmed while another thread holds its packet is not called")
{
  vio::event_loop_t loop;
  event_t event;
  stealing_host_t host(loop);
  REQUIRE(vio::loop_set_host_wait(loop, &host));
  std::optional<vio::handle_wait_t> wait;
  int calls = 0;
  loop.run_in_loop([&] {
    wait = make_wait(loop, event.handle);
    vio::handle_wait_on_signalled(*wait, [&] { ++calls; });
    REQUIRE(vio::handle_wait_arm(*wait));
    host.while_held = [&] {
      vio::handle_wait_disarm(*wait);
      after_turns(loop, 3, [&] {
        wait.reset();
        loop.stop();
      });
    };
    ::SetEvent(event.handle);
  });
  loop.run();
  REQUIRE(vio::loop_set_host_wait(loop, nullptr));
  CHECK(calls == 0);
  CHECK(vio::detail::core(loop).open_resources() == 0);
}

TEST_CASE("handle_wait: a wait rearmed while another thread holds its packet gets that signal")
{
  vio::event_loop_t loop;
  event_t event;
  stealing_host_t host(loop);
  REQUIRE(vio::loop_set_host_wait(loop, &host));
  std::optional<vio::handle_wait_t> wait;
  int calls = 0;
  loop.run_in_loop([&] {
    wait = make_wait(loop, event.handle);
    vio::handle_wait_on_signalled(*wait, [&] {
      ++calls;
      wait.reset();
      loop.stop();
    });
    REQUIRE(vio::handle_wait_arm(*wait));
    host.while_held = [&] {
      vio::handle_wait_disarm(*wait);
      REQUIRE(vio::handle_wait_arm(*wait));
    };
    ::SetEvent(event.handle);
  });
  loop.run();
  REQUIRE(vio::loop_set_host_wait(loop, nullptr));
  CHECK(calls == 1);
}

TEST_CASE("handle_wait: a wait closed while another thread holds its packet finishes closing")
{
  vio::event_loop_t loop;
  event_t event;
  stealing_host_t host(loop);
  REQUIRE(vio::loop_set_host_wait(loop, &host));
  std::optional<vio::handle_wait_t> wait;
  int calls = 0;
  loop.run_in_loop([&] {
    wait = make_wait(loop, event.handle);
    vio::handle_wait_on_signalled(*wait, [&] { ++calls; });
    REQUIRE(vio::handle_wait_arm(*wait));
    host.while_held = [&] {
      wait.reset();
      loop.stop();
    };
    ::SetEvent(event.handle);
  });
  loop.run();
  REQUIRE(vio::loop_set_host_wait(loop, nullptr));
  CHECK(calls == 0);
  CHECK(vio::detail::core(loop).open_resources() == 0);
}

TEST_CASE("handle_wait: wait_for_handle resolves when the handle is signalled")
{
  vio::event_loop_t loop;
  event_t event;
  bool resolved = false;
  std::optional<vio::task_t<void>> task;
  loop.run_in_loop([&] {
    task.emplace([](vio::event_loop_t &loop, HANDLE handle, bool &resolved) -> vio::task_t<void> {
      auto setter = vio::timer_create(loop);
      REQUIRE(setter.has_value());
      vio::timer_on_fire(*setter, [handle] { ::SetEvent(handle); });
      REQUIRE(vio::timer_rearm(*setter, 10ms));
      auto result = co_await vio::wait_for_handle(loop, handle);
      resolved = result.has_value();
      loop.stop();
    }(loop, event.handle, resolved));
  });
  loop.run();
  CHECK(resolved);
  CHECK(vio::detail::core(loop).open_resources() == 0);
}

TEST_CASE("handle_wait: wait_for_handle resolves with vio_cancelled when cancelled, and with an error for a bad handle")
{
  vio::event_loop_t loop;
  event_t event;
  std::optional<vio::error_t> cancelled;
  std::optional<vio::error_t> refused;
  std::optional<vio::task_t<void>> task;
  loop.run_in_loop([&] {
    task.emplace([](vio::event_loop_t &loop, HANDLE handle, std::optional<vio::error_t> &cancelled, std::optional<vio::error_t> &refused) -> vio::task_t<void> {
      vio::cancellation_t cancel;
      loop.run_in_loop([&cancel] { cancel.cancel(); });
      auto result = co_await vio::wait_for_handle(loop, handle, &cancel);
      if (!result)
        cancelled = result.error();
      auto bad = co_await vio::wait_for_handle(loop, nullptr);
      if (!bad)
        refused = bad.error();
      loop.stop();
    }(loop, event.handle, cancelled, refused));
  });
  loop.run();
  REQUIRE(cancelled.has_value());
  CHECK(cancelled->code == vio::vio_cancelled);
  REQUIRE(refused.has_value());
  CHECK(refused->code == vio::errc::invalid_argument);
  CHECK(::WaitForSingleObject(event.handle, 0) == WAIT_TIMEOUT);
  CHECK(vio::detail::core(loop).open_resources() == 0);
}
