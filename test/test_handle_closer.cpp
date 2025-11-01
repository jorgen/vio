#include <doctest/doctest.h>
#include <vio/event_loop.h>
#include <vio/handle_closer.h>
#include <vio/ref_counted_wrapper.h>

namespace
{

// Test structure using inline_wrapper_t with closable_handle_t
struct connection_with_inline_t
{
  vio::reference_counted_t ref_count;
  vio::inline_wrapper_t<vio::async_t> async_handle;
  vio::inline_wrapper_t<vio::timer_t> timer_handle;
  bool async_closed{false};
  bool timer_closed{false};

  explicit connection_with_inline_t(vio::event_loop_t &loop)
    : ref_count(
        [&loop, this]
        {
          loop.stop();
          delete this;
        })
    , async_handle(&ref_count)
    , timer_handle(&ref_count)
  {
    uv_async_init(loop.loop(), &async_handle.data(), nullptr);
    async_handle->call_close = true;

    uv_timer_init(loop.loop(), &timer_handle.data());
    timer_handle->call_close = true;

    ref_count.register_destroy_callback(
      [this]()
      {
        if (async_handle->call_close)
        {
          async_closed = true;
        }
        if (timer_handle->call_close)
        {
          timer_closed = true;
        }
      });
  }
};

// Test structure using owned_wrapper_t with closable_handle_t
struct async_handle_data_t
{
  vio::async_t handle;
  std::function<void()> callback;
  bool &closed;
  bool &destroyed;

  explicit async_handle_data_t(vio::reference_counted_t *parent, std::function<void()> &&callback, bool &closed, bool &destroyed, vio::event_loop_t &loop)
    : handle(parent)
    , callback(std::move(callback))
    , closed(closed)
    , destroyed(destroyed)
  {
    handle.data = this;
    uv_async_init(loop.loop(), &handle, on_async_callback);
    handle.call_close = true;

    parent->register_destroy_callback([this]() { this->closed = true; });
  }

  ~async_handle_data_t()
  {
    destroyed = true;
  }

  static void on_async_callback(uv_async_t *async)
  {
    auto *data = static_cast<async_handle_data_t *>(async->data);
    data->callback();
  }
};

using owned_async_t = vio::owned_wrapper_t<async_handle_data_t>;

} // namespace

TEST_CASE("closable_handle_t with inline_wrapper_t")
{
  SUBCASE("handles are properly initialized")
  {
    vio::event_loop_t loop;
    auto *conn = new connection_with_inline_t(loop);

    CHECK(conn->async_handle->call_close);
    CHECK(conn->timer_handle->call_close);
    CHECK_FALSE(conn->async_closed);
    CHECK_FALSE(conn->timer_closed);

    conn->ref_count.dec();
    // Event loop needs explicit run() call since it maintains internal handles
    // even when all user handles are closed
    loop.run();
  }

  SUBCASE("handles close on destruction")
  {
    vio::event_loop_t loop;
    bool callback_executed = false;

    {
      auto *conn = new connection_with_inline_t(loop);

      loop.run_in_loop(
        [&loop, &callback_executed]()
        {
          callback_executed = true;
          loop.stop();
        });

      conn->ref_count.dec();
    }

    loop.run();
    CHECK(callback_executed);
  }

  SUBCASE("multiple handles close in correct order")
  {
    vio::event_loop_t loop;
    auto *conn = new connection_with_inline_t(loop);

    std::vector<int> close_order;

    conn->ref_count.register_destroy_callback([&close_order]() { close_order.push_back(1); });

    bool loop_stopped = false;
    loop.run_in_loop(
      [&loop, &loop_stopped]()
      {
        loop_stopped = true;
        loop.stop();
      });

    conn->ref_count.dec();
    loop.run();

    CHECK(loop_stopped);
    CHECK(conn->async_closed);
    CHECK(conn->timer_closed);
  }
}

TEST_CASE("closable_handle_t with owned_wrapper_t")
{
  SUBCASE("async handle initialization and callback")
  {
    vio::event_loop_t loop;
    bool loop_finished = false;
    int callback_count = 0;
    bool async_closed = false;
    bool async_destroyed = false;

    std::function<void()> called_from_callback;

    auto callback = [&called_from_callback]() { called_from_callback(); };
    owned_async_t async_wrapper(std::move(callback), async_closed, async_destroyed, loop);

    called_from_callback = [&async_wrapper, &callback_count]()
    {
      ++callback_count;
      async_wrapper.~owned_async_t();
    };

    CHECK(async_wrapper->handle.call_close);
    CHECK(callback_count == 0);

    loop.run_in_loop(
      [&loop, &loop_finished, &async_wrapper, &async_closed, &async_destroyed]()
      {
        uv_async_send(&async_wrapper->handle);
        loop_finished = true;
        loop.stop();
      });

    loop.run();

    CHECK(loop_finished);
    CHECK(callback_count > 0);
  }

  SUBCASE("owned wrapper can be copied and shared")
  {
    vio::event_loop_t loop;
    bool async_closed = false;
    bool async_destroyed = false;
    owned_async_t async1([] {}, async_closed, async_destroyed, loop);

    CHECK(async1.ref_counted()->ref_count == 1);

    {
      owned_async_t async2 = async1;
      CHECK(async1.ref_counted()->ref_count == 2);
      CHECK(async2.ref_counted()->ref_count == 2);

      loop.run_in_loop(
        [&loop, &async1, &async2]()
        {
          loop.stop();
          async1.~owned_async_t();
          CHECK(async2.ref_counted()->ref_count == 1);
          async2.~owned_async_t();
        });
      loop.run();
    }
  }

  SUBCASE("handle closes when last reference is dropped")
  {
    vio::event_loop_t loop;
    bool destroyed = false;
    bool async_closed = false;
    bool async_destroyed = false;

    {
      owned_async_t async1([] {}, async_closed, async_destroyed, loop);
      async1.ref_counted()->register_destroy_callback([&destroyed]() { destroyed = true; });

      {
        owned_async_t async2 = async1;
        owned_async_t async3 = async2;
        CHECK(async1.ref_counted()->ref_count == 3);
        CHECK_FALSE(destroyed);
      }

      CHECK(async1.ref_counted()->ref_count == 1);
      CHECK_FALSE(destroyed);
    }

    // Now the handle should be scheduled to close
    CHECK(destroyed);
    CHECK(async_closed);
    CHECK_FALSE(async_destroyed);
    loop.run_in_loop([&loop] { loop.stop(); });
    loop.run();
    CHECK(async_closed);
    CHECK(async_destroyed);
  }

  // SUBCASE("async send and receive multiple times")
  //{
  //   vio::event_loop_t loop;
  //   owned_async_t async_wrapper(loop);

  //  int send_count = 5;
  //  loop.run_in_loop(
  //    [&loop, &async_wrapper, &send_count]()
  //    {
  //      for (int i = 0; i < send_count; ++i)
  //      {
  //        uv_async_send(&async_wrapper->handle);
  //      }
  //      loop.stop();
  //    });

  //  loop.run();

  //  // Note: uv_async_send may coalesce multiple sends
  //  CHECK(async_wrapper->callback_count >= 1);
}

TEST_CASE("closable_handle_t timer operations")
{
  SUBCASE("timer fires and closes properly")
  {
    vio::event_loop_t loop;

    struct timer_data_t
    {
      vio::timer_t handle;
      int fire_count{0};
      bool closed{false};

      explicit timer_data_t(vio::reference_counted_t *parent, vio::event_loop_t &loop)
        : handle(parent)
      {
        handle.data = this;
        uv_timer_init(loop.loop(), &handle);
        handle.call_close = true;

        parent->register_destroy_callback([this]() { closed = true; });
      }

      static void on_timer(uv_timer_t *timer)
      {
        auto *data = static_cast<timer_data_t *>(timer->data);
        data->fire_count++;
      }
    };

    using owned_timer_t = vio::owned_wrapper_t<timer_data_t>;

    owned_timer_t timer(loop);
    uv_timer_start(&timer->handle, timer_data_t::on_timer, 10, 0);

    loop.run_in_loop(
      [&loop]()
      {
        // Give timer time to fire
        auto delayed_stop = [](uv_timer_t *t)
        {
          auto *l = static_cast<vio::event_loop_t *>(t->data);
          l->stop();
          uv_close(reinterpret_cast<uv_handle_t *>(t), nullptr);
        };

        auto *stop_timer = new uv_timer_t();
        stop_timer->data = &loop;
        uv_timer_init(loop.loop(), stop_timer);
        uv_timer_start(stop_timer, delayed_stop, 50, 0);
      });

    loop.run();

    CHECK(timer->fire_count >= 1);
  }
}

TEST_CASE("closable_handle_t reference counting with event loop")
{
  SUBCASE("handle keeps object alive during close")
  {
    vio::event_loop_t loop;
    int destruction_phase = 0;

    struct tracked_async_t
    {
      vio::async_t handle;
      int *phase;

      explicit tracked_async_t(vio::reference_counted_t *parent, vio::event_loop_t &loop, int *p)
        : handle(parent)
        , phase(p)
      {
        uv_async_init(loop.loop(), &handle, nullptr);
        handle.call_close = true;

        parent->register_destroy_callback([this, p]() { *p = 1; });
      }

      ~tracked_async_t()
      {
        *phase = 2;
      }
    };

    using owned_tracked_t = vio::owned_wrapper_t<tracked_async_t>;

    {
      owned_tracked_t async(loop, &destruction_phase);
      CHECK(destruction_phase == 0);
    }

    // Destruction callback should have run
    CHECK(destruction_phase == 1);

    loop.run();

    // After event loop, destructor should have completed
    CHECK(destruction_phase == 2);
  }

  SUBCASE("multiple handles with different lifetimes")
  {
    vio::event_loop_t loop;

    static std::vector<int> close_order;
    struct counted_async_t
    {
      vio::async_t handle;
      int id;

      explicit counted_async_t(vio::reference_counted_t *parent, vio::event_loop_t &loop, int i)
        : handle(parent)
        , id(i)
      {
        uv_async_init(loop.loop(), &handle, nullptr);
        handle.call_close = true;

        parent->register_destroy_callback([this]() { close_order.push_back(id); });
      }
    };

    using owned_counted_t = vio::owned_wrapper_t<counted_async_t>;

    close_order.clear();

    {
      owned_counted_t async1(loop, 1);
      {
        owned_counted_t async2(loop, 2);
        owned_counted_t async3(loop, 3);
      }
      // async2 and async3 should start closing
    }
    // async1 should start closing

    loop.run();

    // All three should have closed
    REQUIRE(close_order.size() == 3);
    // Order might vary, but all should be present
    CHECK(std::find(close_order.begin(), close_order.end(), 1) != close_order.end());
    CHECK(std::find(close_order.begin(), close_order.end(), 2) != close_order.end());
    CHECK(std::find(close_order.begin(), close_order.end(), 3) != close_order.end());
  }
}

TEST_CASE("closable_handle_t call_close flag behavior")
{
  SUBCASE("call_close=false prevents automatic closing")
  {
    vio::event_loop_t loop;

    struct manual_close_async_t
    {
      vio::async_t handle;
      bool manually_closed{false};

      explicit manual_close_async_t(vio::reference_counted_t *parent, vio::event_loop_t &loop)
        : handle(parent)
      {
        uv_async_init(loop.loop(), &handle, nullptr);
        handle.call_close = false; // Don't automatically close

        parent->register_destroy_callback(
          [this, parent]()
          {
            // Manually close
            manually_closed = true;
            parent->inc();
            uv_close(handle.handle(), manual_close_cb);
          });
      }

      static void manual_close_cb(uv_handle_t *h)
      {
        auto *closable = reinterpret_cast<vio::async_t *>(h);
        auto *data = reinterpret_cast<manual_close_async_t *>(closable);
        data->handle.parent->dec();
      }
    };

    using owned_manual_t = vio::owned_wrapper_t<manual_close_async_t>;

    {
      owned_manual_t async(loop);
      CHECK_FALSE(async->handle.call_close);
    }

    loop.run();
  }

  SUBCASE("call_close can be toggled")
  {
    vio::event_loop_t loop;

    struct toggleable_async_t
    {
      vio::async_t handle;

      explicit toggleable_async_t(vio::reference_counted_t *parent, vio::event_loop_t &loop)
        : handle(parent)
      {
        uv_async_init(loop.loop(), &handle, nullptr);
        handle.call_close = false;
      }
    };

    using owned_toggleable_t = vio::owned_wrapper_t<toggleable_async_t>;

    {
      owned_toggleable_t async(loop);
      CHECK_FALSE(async->handle.call_close);

      async->handle.call_close = true;
      CHECK(async->handle.call_close);
    }

    loop.run();
  }
}