#include <doctest/doctest.h>
#include <vio/event_loop.h>
#include <vio/event_pipe.h>

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

TEST_CASE("Test workers and thread pools")
{
  struct my_worker_t : public vio::worker_t
  {
    my_worker_t(vio::event_loop_t &loop, int &counter)
      : loop(loop)
      , counter(counter)
    {

    }
    void work() override
    {
      thread_id = std::this_thread::get_id();
    }
    void after_work(completion_t /*completion*/) override
    {
      counter--;
      if (counter == 0)
      {
        loop.stop();
      }
    }
    vio::event_loop_t &loop;
    int &counter;
    std::thread::id thread_id;
  };

  vio::thread_pool_t pool(4); // NOLINT(misc-const-correctness) passed as non-const ref
  vio::event_loop_t event_loop;

  std::vector<my_worker_t> workers;
  workers.reserve(10);

  int counter = 10;
  for (int i = 0; i < 10; ++i)
  {
    workers.emplace_back(event_loop, counter);
  }
  for (auto &worker : workers)
  {
    worker.enqueue(event_loop, pool);
  }

  event_loop.run();

  CHECK(counter == 0);
  for (auto &worker : workers)
  {
    CHECK(worker.thread_id != std::this_thread::get_id());
    CHECK(worker.thread_id != std::thread::id());
  }
}
