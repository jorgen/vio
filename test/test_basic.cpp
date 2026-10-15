#include <chrono>
#include <doctest/doctest.h>
#include <vio/event_loop.h>
#include <vio/event_pipe.h>
#include <vio/operation/sleep.h>
#include <vio/run.h>

TEST_SUITE("Event Loop")
{
TEST_CASE("Simple event_pipe")
{
  vio::event_loop_t event_loop;

  int counter = 2;
  bool void_called = false;
  bool int_called = false; // NOLINT(misc-const-correctness) modified via lambda capture
  vio::event_pipe_t<void> event_pipe_void(event_loop,
                                     [&void_called, &event_loop, &counter]()
                                     {
                                       void_called = true;
                                       counter--;
                                       if (counter == 0)
                                       {
                                         event_loop.stop();
                                       }
                                     });

  vio::event_pipe_t<int> event_pipe_int(event_loop,
                                    [&int_called, &event_loop, &counter](int i)
                                    {
                                      CHECK(i == 567);
                                      int_called = true;
                                      counter--;
                                      if (counter == 0)
                                      {
                                        event_loop.stop();
                                      }
                                    });

  event_pipe_void.post_event();
  event_pipe_int.post_event(567);

  event_loop.run();

  CHECK(void_called);
  CHECK(int_called);
}

TEST_CASE("Run function in event_loop")
{
  vio::event_loop_t event_loop;
  bool has_been_called = false;
  event_loop.run_in_loop([&has_been_called, &event_loop]() { has_been_called = true; event_loop.stop(); });
  event_loop.run();
  CHECK(has_been_called);
}

TEST_CASE("run returns the value of the coroutine it drives")
{
  const int result = vio::run([](vio::event_loop_t &loop) -> vio::task_t<int> {
    auto slept = co_await vio::sleep(loop, std::chrono::milliseconds(1));
    co_return slept.has_value() ? 42 : -1;
  });
  CHECK(result == 42);
}

TEST_CASE("run with a void coroutine returns once it finishes")
{
  int steps = 0;
  vio::run([&steps](vio::event_loop_t &loop) -> vio::task_t<void> {
    ++steps;
    auto slept = co_await vio::sleep(loop, std::chrono::milliseconds(1));
    CHECK(slept.has_value());
    ++steps;
  });
  CHECK(steps == 2);
}

} // TEST_SUITE
