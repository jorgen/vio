#include <doctest/doctest.h>

#include <vio/event_loop.h>
#include <vio/event_pipe.h>

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
}
