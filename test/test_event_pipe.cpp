#include <doctest/doctest.h>
#include <vio/event_loop.h>
#include <vio/operation/dns.h>
#include <vio/task.h>

#include "require_expected.h"

namespace
{
TEST_CASE("Test basic event pipe")
{
  vio::event_loop_t primary_event_loop;

  bool has_event_from_secondary_been_called = false;
  vio::event_pipe_t<int> event_from_secondary(primary_event_loop,
                                              [&primary_event_loop, &has_event_from_secondary_been_called](int a)
                                              {
                                                REQUIRE(a == 55);
                                                has_event_from_secondary_been_called = true;
                                                primary_event_loop.stop();
                                              });

  vio::thread_with_event_loop_t secondary_event_loop;
  bool has_event_from_main_thread_been_called = false;
  vio::event_pipe_t<int> event_from_main_thread_been_called(secondary_event_loop.event_loop(),
                                                            [&has_event_from_main_thread_been_called, &event_from_secondary](int a)
                                                            {
                                                              REQUIRE(a == 44);
                                                              has_event_from_main_thread_been_called = true;
                                                              event_from_secondary(55);
                                                            });
  std::function<void()> run_in_main = [&event_from_main_thread_been_called]() { event_from_main_thread_been_called(44); };
  primary_event_loop.run_in_loop(std::move(run_in_main));
  primary_event_loop.run();

  REQUIRE(has_event_from_secondary_been_called);
  REQUIRE(has_event_from_main_thread_been_called);
}

{
}

TEST_CASE("Test awaitable event pipe")
{
}
} // namespace
