#include <doctest/doctest.h>

#include <vio/event_loop.h>
#include <vio/event_pipe.h>

#include <algorithm>
#include <memory>
#include <vector>

TEST_SUITE("event_pipe drain")
{
  // The drain reuses a scratch buffer across wakeups (instead of reallocating
  // the event vector each time). This exercises delivery across several drains,
  // in order, and posts the next batch from inside the callback to confirm the
  // mutex is not held during processing (re-entrant post must not deadlock).
  TEST_CASE("delivers all events across repeated drains, in order, re-entrantly")
  {
    vio::event_loop_t loop;

    std::vector<int> received;
    constexpr int per_batch = 500;
    constexpr int batches = 5;

    vio::event_pipe_t<int> *pipe_ptr = nullptr;
    vio::event_pipe_t<int> pipe(loop,
                                [&](int value)
                                {
                                  received.push_back(value);
                                  if (received.size() % per_batch == 0)
                                  {
                                    const int next_batch = static_cast<int>(received.size()) / per_batch;
                                    if (next_batch < batches)
                                    {
                                      // Re-enter post_event from within the drain callback.
                                      for (int i = 0; i < per_batch; ++i)
                                      {
                                        pipe_ptr->post_event((next_batch * per_batch) + i);
                                      }
                                    }
                                    else
                                    {
                                      loop.stop();
                                    }
                                  }
                                });
    pipe_ptr = &pipe;

    loop.run_in_loop(
      [&]
      {
        for (int i = 0; i < per_batch; ++i)
        {
          pipe.post_event(int{i});
        }
      });
    loop.run();

    REQUIRE_EQ(received.size(), static_cast<std::size_t>(per_batch * batches));
    bool in_order = true;
    for (std::size_t i = 0; i < received.size(); ++i)
    {
      if (received[i] != static_cast<int>(i))
      {
        in_order = false;
        break;
      }
    }
    CHECK(in_order);
  }

  TEST_CASE("a callback that drains its own pipe again neither nests nor loses events")
  {
    vio::event_loop_t loop;
    constexpr int total = 300;
    constexpr int per_batch = 100;
    std::vector<int> received;
    int depth = 0;
    int max_depth = 0;
    vio::event_pipe_t<int> *pipe_ptr = nullptr;
    vio::event_pipe_t<int> pipe(loop, [&](int value) {
      ++depth;
      max_depth = std::max(max_depth, depth);
      received.push_back(value);
      if (value + per_batch < total)
        pipe_ptr->post_event(value + per_batch);
      pipe_ptr->drain_events();
      if (received.size() == total)
        loop.stop();
      --depth;
    });
    pipe_ptr = &pipe;

    loop.run_in_loop([&] {
      for (int i = 0; i < per_batch; ++i)
        pipe.post_event(int{i});
    });
    loop.run();

    CHECK(max_depth == 1);
    REQUIRE(received.size() == static_cast<std::size_t>(total));
    for (int i = 0; i < total; ++i)
      CHECK(received[static_cast<std::size_t>(i)] == i);
  }

  TEST_CASE("draining a pipe directly while its wakeup is queued delivers each event once")
  {
    vio::event_loop_t loop;
    std::vector<int> received;
    vio::event_pipe_t<int> pipe(loop, [&](int value) { received.push_back(value); });

    std::size_t after_direct_drain = 0;
    loop.run_in_loop([&] {
      pipe.post_event(1);
      pipe.post_event(2);
      pipe.post_event(3);
      pipe.drain_events();
      after_direct_drain = received.size();
      pipe.drain_events();
      loop.run_in_loop([&] {
        pipe.post_event(4);
        loop.stop();
      });
    });
    loop.run();

    CHECK(after_direct_drain == 3);
    CHECK(received == std::vector<int>{1, 2, 3, 4});
  }

  TEST_CASE("a pipe destroyed while its wakeup is queued is never run")
  {
    vio::event_loop_t loop;
    int calls = 0;
    auto pipe = std::make_unique<vio::event_pipe_t<int>>(loop, [&calls](int) { ++calls; });
    pipe->post_event(7);
    pipe.reset();
    loop.run_in_loop([&] { loop.stop(); });
    loop.run();
    CHECK(calls == 0);
  }

  TEST_CASE("a pipe destroyed by work that runs before its wakeup in the same turn is never run")
  {
    vio::event_loop_t loop;
    int calls = 0;
    auto pipe = std::make_unique<vio::event_pipe_t<int>>(loop, [&calls](int) { ++calls; });
    loop.run_in_loop([&pipe] { pipe.reset(); });
    pipe->post_event(7);
    loop.run_in_loop([&loop] { loop.stop(); });
    loop.run();
    CHECK(calls == 0);
  }
}
