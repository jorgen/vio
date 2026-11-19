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

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <vio/cancellation.h>
#include <vio/errc.h>
#include <vio/event_loop.h>
#include <vio/operation/process.h>
#include <vio/operation/sleep.h>
#include <vio/task.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <cerrno>
#include <csignal>
#include <unistd.h>
#endif

using namespace std::chrono_literals;

namespace
{
vio::process_options_t shell(const std::string &command)
{
  vio::process_options_t options;
#if defined(_WIN32)
  options.program = "cmd.exe";
  options.arguments = {"/d", "/c", command};
#else
  options.program = "/bin/sh";
  options.arguments = {"-c", command};
#endif
  return options;
}

vio::process_options_t sleeper()
{
#if defined(_WIN32)
  return shell("ping -n 30 127.0.0.1 >nul");
#else
  return shell("sleep 30");
#endif
}

struct output_t
{
  std::string text;
  int end = 0;
};

vio::task_t<output_t> read_until(vio::process_reader_t &reader, std::string needle)
{
  output_t output;
  for (;;)
  {
    auto chunk = co_await reader;
    if (!chunk)
    {
      output.end = chunk.error().code;
      co_return output;
    }
    output.text.append(reinterpret_cast<const char *>(chunk->data()), chunk->size());
    if (!needle.empty() && output.text.find(needle) != std::string::npos)
      co_return output;
  }
}

vio::process_t spawn_or_fail(vio::event_loop_t &loop, const vio::process_options_t &options)
{
  auto spawned = vio::process_spawn(loop, options);
  REQUIRE_MESSAGE(spawned.has_value(), (spawned ? std::string() : spawned.error().msg));
  return std::move(*spawned);
}

vio::process_reader_t reader_or_fail(vio::process_t &process)
{
  auto reader = vio::process_create_reader(process);
  REQUIRE(reader.has_value());
  return std::move(*reader);
}

struct run_t
{
  vio::event_loop_t loop;
  std::optional<vio::task_t<void>> task;

  template <typename Body>
  void operator()(Body body)
  {
    loop.run_in_loop([&] { task.emplace(body(loop)); });
    loop.run();
    CHECK(vio::detail::core(loop).open_resources() == 0);
  }
};

bool process_is_gone(std::int64_t pid)
{
#if defined(_WIN32)
  HANDLE process = ::OpenProcess(SYNCHRONIZE, FALSE, static_cast<DWORD>(pid));
  if (!process)
    return true;
  const bool gone = ::WaitForSingleObject(process, 10000) == WAIT_OBJECT_0;
  ::CloseHandle(process);
  return gone;
#else
  return ::kill(static_cast<pid_t>(pid), 0) != 0 && errno == ESRCH;
#endif
}
} // namespace

TEST_CASE("process: a child's output arrives through the pty and ends in eof")
{
  output_t output;
  std::optional<vio::exit_status_t> status;
  run_t run;
  run([&](vio::event_loop_t &loop) {
    return [](vio::event_loop_t &loop, output_t &output, std::optional<vio::exit_status_t> &status) -> vio::task_t<void> {
      {
        auto process = spawn_or_fail(loop, shell("echo vio-pty-output"));
        CHECK(vio::process_pid(process) > 0);
        auto reader = reader_or_fail(process);
        output = co_await read_until(reader, {});
        auto waited = co_await vio::process_wait(process);
        REQUIRE(waited.has_value());
        status = *waited;
        CHECK(vio::process_exit_status(process).has_value());
      }
      loop.stop();
    }(loop, output, status);
  });
  CHECK(output.text.find("vio-pty-output") != std::string::npos);
  CHECK(output.end == vio::errc::eof);
  REQUIRE(status.has_value());
  CHECK(status->exit_code == 0);
  CHECK(status->signal == 0);
}

TEST_CASE("process: bytes written to the pty reach the child")
{
  output_t output;
  run_t run;
  run([&](vio::event_loop_t &loop) {
    return [](vio::event_loop_t &loop, output_t &output) -> vio::task_t<void> {
      {
#if defined(_WIN32)
        auto options = shell("set /p line=&& echo got-!line!-end");
        options.arguments.insert(options.arguments.begin() + 1, "/v:on");
        auto process = spawn_or_fail(loop, options);
        const std::string line = "ping\r";
#else
        auto process = spawn_or_fail(loop, shell("read line; echo \"got-$line-end\""));
        const std::string line = "ping\n";
#endif
        auto reader = reader_or_fail(process);
        auto written = co_await vio::process_write(process, std::string(line));
        CHECK(written.has_value());
        output = co_await read_until(reader, "got-ping-end");
        auto waited = co_await vio::process_wait(process);
        CHECK(waited.has_value());
      }
      loop.stop();
    }(loop, output);
  });
  CHECK(output.text.find("got-ping-end") != std::string::npos);
}

TEST_CASE("process: a resize reaches the child")
{
  output_t output;
  bool resized = false;
  run_t run;
  run([&](vio::event_loop_t &loop) {
    return [](vio::event_loop_t &loop, output_t &output, bool &resized) -> vio::task_t<void> {
      {
#if defined(_WIN32)
        auto process = spawn_or_fail(loop, shell("set /p line=&& mode con"));
        const std::string line = "go\r";
        const std::string needle = "Columns:";
#else
        auto process = spawn_or_fail(loop, shell("read line; stty size"));
        const std::string line = "go\n";
        const std::string needle = "37 101";
#endif
        auto reader = reader_or_fail(process);
        resized = vio::process_resize(process, {.columns = 101, .rows = 37, .pixel_width = 808, .pixel_height = 740}).has_value();
        (void)co_await vio::process_write(process, line);
        output = co_await read_until(reader, {});
        (void)co_await vio::process_wait(process);
      }
      loop.stop();
    }(loop, output, resized);
  });
  CHECK(resized);
#if defined(_WIN32)
  CHECK(output.text.find("101") != std::string::npos);
  CHECK(output.text.find("37") != std::string::npos);
#else
  CHECK(output.text.find("37 101") != std::string::npos);
#endif
}

TEST_CASE("process: the exit code reaches process_wait")
{
  std::optional<vio::exit_status_t> status;
  run_t run;
  run([&](vio::event_loop_t &loop) {
    return [](vio::event_loop_t &loop, std::optional<vio::exit_status_t> &status) -> vio::task_t<void> {
      {
        auto process = spawn_or_fail(loop, shell("exit 7"));
        auto waited = co_await vio::process_wait(process);
        if (waited)
          status = *waited;
        auto again = co_await vio::process_wait(process);
        REQUIRE(again.has_value());
        CHECK(again->exit_code == 7);
      }
      loop.stop();
    }(loop, status);
  });
  REQUIRE(status.has_value());
  CHECK(status->exit_code == 7);
}

TEST_CASE("process: kill ends a running child")
{
  std::optional<vio::exit_status_t> status;
  run_t run;
  run([&](vio::event_loop_t &loop) {
    return [](vio::event_loop_t &loop, std::optional<vio::exit_status_t> &status) -> vio::task_t<void> {
      {
        auto process = spawn_or_fail(loop, sleeper());
        (void)co_await vio::sleep(loop, 50ms);
        CHECK_FALSE(vio::process_exit_status(process).has_value());
        CHECK(vio::process_kill(process, vio::process_signal_kill).has_value());
        auto waited = co_await vio::process_wait(process);
        if (waited)
          status = *waited;
        auto again = vio::process_kill(process);
        REQUIRE_FALSE(again.has_value());
        CHECK(again.error().code == vio::errc::no_such_process);
      }
      loop.stop();
    }(loop, status);
  });
  REQUIRE(status.has_value());
  CHECK(status->exit_code == 128 + vio::process_signal_kill);
#if !defined(_WIN32)
  CHECK(status->signal == SIGKILL);
#endif
}

TEST_CASE("process: spawning a program that does not exist fails")
{
  vio::event_loop_t loop;
  vio::process_options_t options;
  options.program = "vio-no-such-program-anywhere";
  auto spawned = vio::process_spawn(loop, options);
  REQUIRE_FALSE(spawned.has_value());
  CHECK(spawned.error().code == vio::errc::no_such_file);

  options.program.clear();
  auto empty = vio::process_spawn(loop, options);
  REQUIRE_FALSE(empty.has_value());
  CHECK(empty.error().code == vio::errc::invalid_argument);

#if !defined(_WIN32)
  options.program = "/bin/sh";
  options.working_directory = "/vio-no-such-directory";
  auto bad_directory = vio::process_spawn(loop, options);
  REQUIRE_FALSE(bad_directory.has_value());
  CHECK(bad_directory.error().code == vio::errc::no_such_file);
#endif
  loop.stop();
  loop.run();
  CHECK(vio::detail::core(loop).open_resources() == 0);
}

TEST_CASE("process: the environment and working directory reach the child")
{
  output_t output;
  output_t replaced;
  run_t run;
  run([&](vio::event_loop_t &loop) {
    return [](vio::event_loop_t &loop, output_t &output, output_t &replaced) -> vio::task_t<void> {
      {
#if defined(_WIN32)
        auto options = shell("echo [%VIO_PTY_TEST%] & cd");
        options.working_directory = "C:\\Windows";
#else
        auto options = shell("echo \"[$VIO_PTY_TEST]\"; pwd");
        options.working_directory = "/";
#endif
        options.environment.push_back({"VIO_PTY_TEST", "spaced value"});
        auto process = spawn_or_fail(loop, options);
        auto reader = reader_or_fail(process);
        output = co_await read_until(reader, {});
        (void)co_await vio::process_wait(process);
      }
      {
#if defined(_WIN32)
        auto options = shell("echo [%USERNAME%][%VIO_ONLY%]");
        options.program = "C:\\Windows\\System32\\cmd.exe";
        options.environment.push_back({"SystemRoot", "C:\\Windows"});
#else
        auto options = shell("echo \"[$HOME][$VIO_ONLY]\"");
#endif
        options.inherit_environment = false;
        options.environment.push_back({"VIO_ONLY", "alone"});
        auto process = spawn_or_fail(loop, options);
        auto reader = reader_or_fail(process);
        replaced = co_await read_until(reader, {});
        (void)co_await vio::process_wait(process);
      }
      loop.stop();
    }(loop, output, replaced);
  });
  CHECK(output.text.find("[spaced value]") != std::string::npos);
#if defined(_WIN32)
  CHECK(output.text.find("C:\\Windows") != std::string::npos);
  CHECK(replaced.text.find("[%USERNAME%][alone]") != std::string::npos);
#else
  CHECK(output.text.find("\n/\r") != std::string::npos);
  CHECK(replaced.text.find("[][alone]") != std::string::npos);
#endif
}

TEST_CASE("process: a pending read can be cancelled")
{
  output_t output;
  run_t run;
  run([&](vio::event_loop_t &loop) {
    return [](vio::event_loop_t &loop, output_t &output) -> vio::task_t<void> {
      {
        auto process = spawn_or_fail(loop, sleeper());
        auto reader = reader_or_fail(process);
        auto reading = read_until(reader, {});
        (void)co_await vio::sleep(loop, 500ms);
        reader.cancel();
        output = co_await std::move(reading);
        CHECK(vio::process_kill(process).has_value());
        (void)co_await vio::process_wait(process);
      }
      loop.stop();
    }(loop, output);
  });
  CHECK(output.end == vio::errc::canceled);
}

TEST_CASE("process: a pending wait can be cancelled")
{
  int code = 0;
  run_t run;
  run([&](vio::event_loop_t &loop) {
    return [](vio::event_loop_t &loop, int &code) -> vio::task_t<void> {
      {
        auto process = spawn_or_fail(loop, sleeper());
        vio::cancellation_t token;
        auto canceller = [](vio::event_loop_t &loop, vio::cancellation_t &token) -> vio::task_t<void> {
          (void)co_await vio::sleep(loop, 50ms);
          token.cancel();
        }(loop, token);
        auto waited = co_await vio::process_wait(process, &token);
        REQUIRE_FALSE(waited.has_value());
        code = waited.error().code;
        co_await std::move(canceller);
        CHECK_FALSE(vio::process_exit_status(process).has_value());
        auto already = co_await vio::process_wait(process, &token);
        CHECK_FALSE(already.has_value());
        CHECK(vio::process_kill(process).has_value());
        auto finished = co_await vio::process_wait(process);
        CHECK(finished.has_value());
      }
      loop.stop();
    }(loop, code);
  });
  CHECK(code == vio::vio_cancelled);
}

TEST_CASE("process: only one reader at a time")
{
  run_t run;
  run([&](vio::event_loop_t &loop) {
    return [](vio::event_loop_t &loop) -> vio::task_t<void> {
      {
        auto process = spawn_or_fail(loop, shell("exit 0"));
        {
          auto first = reader_or_fail(process);
          auto second = vio::process_create_reader(process);
          REQUIRE_FALSE(second.has_value());
          CHECK(second.error().code == vio::errc::busy);
        }
        auto third = vio::process_create_reader(process);
        CHECK(third.has_value());
        (void)co_await vio::process_wait(process);
      }
      loop.stop();
    }(loop);
  });
}

TEST_CASE("process: dropping the handle while the child runs ends the child")
{
  std::int64_t pid = -1;
  run_t run;
  run([&](vio::event_loop_t &loop) {
    return [](vio::event_loop_t &loop, std::int64_t &pid) -> vio::task_t<void> {
      {
        auto process = spawn_or_fail(loop, sleeper());
        pid = vio::process_pid(process);
        (void)co_await vio::sleep(loop, 100ms);
        CHECK(vio::process_write(process, std::string_view("pending")).op.error == 0);
      }
      loop.stop();
    }(loop, pid);
  });
  REQUIRE(pid > 0);
  CHECK(process_is_gone(pid));
}

#if !defined(_WIN32)
TEST_CASE("process: a child that ignores the hangup is killed after the grace period")
{
  std::int64_t pid = -1;
  auto started = std::chrono::steady_clock::now();
  run_t run;
  run([&](vio::event_loop_t &loop) {
    return [](vio::event_loop_t &loop, std::int64_t &pid) -> vio::task_t<void> {
      {
        auto process = spawn_or_fail(loop, shell("trap '' HUP; echo ready; while :; do sleep 1; done"));
        pid = vio::process_pid(process);
        auto reader = reader_or_fail(process);
        co_await read_until(reader, "ready");
      }
      loop.stop();
    }(loop, pid);
  });
  REQUIRE(pid > 0);
  CHECK(process_is_gone(pid));
  CHECK(std::chrono::steady_clock::now() - started >= 1900ms);
}
#endif
