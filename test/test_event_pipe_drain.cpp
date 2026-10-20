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

  TEST_CASE("a callback that throws leaves the pipe working and the events it did not reach queued in order")
  {
    struct failure_t
    {
    };
    struct state_t
    {
      vio::event_loop_t loop;
      std::unique_ptr<vio::event_pipe_t<int>> pipe;
      std::vector<int> received;
      std::size_t stop_at = 0;
      vio::detail::timer_node_t watchdog;
      bool timed_out = false;
    } state;
    state.pipe = std::make_unique<vio::event_pipe_t<int>>(state.loop, [&state](int value) {
      if (value == 7)
        state.pipe->post_event(9);
      if (value == 2 || value == 7)
        throw failure_t{};
      state.received.push_back(value);
      if (state.received.size() == state.stop_at)
        state.loop.stop();
    });
    state.watchdog.owner = &state;
    state.watchdog.keeps_alive = false;
    state.watchdog.fire = [](vio::detail::timer_node_t *raw) {
      auto &self = *static_cast<state_t *>(raw->owner);
      self.timed_out = true;
      self.pipe.reset();
      self.loop.stop();
    };
    auto &core = vio::detail::core(state.loop);
    auto run_watched = [&](std::size_t stop_at) {
      state.stop_at = stop_at;
      core.add_timer(state.watchdog, vio::detail::loop_core_t::deadline_after(std::int64_t{5000} * 1000000));
      state.loop.run();
      core.remove_timer(state.watchdog);
    };

    for (int value : {1, 2, 3, 4})
      state.pipe->post_event(int{value});
    CHECK_THROWS_AS(state.loop.run(), failure_t);
    CHECK(state.received == std::vector<int>{1});
    run_watched(3);
    CHECK_FALSE(state.timed_out);
    CHECK(state.received == std::vector<int>{1, 3, 4});
    REQUIRE(state.pipe);

    state.pipe->post_event(7);
    state.pipe->post_event(8);
    CHECK_THROWS_AS(state.loop.run(), failure_t);
    CHECK(state.received == std::vector<int>{1, 3, 4});
    state.pipe->post_event(10);
    run_watched(6);
    CHECK_FALSE(state.timed_out);
    CHECK(state.received == std::vector<int>{1, 3, 4, 8, 9, 10});
  }
}
