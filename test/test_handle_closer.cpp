#include <doctest/doctest.h>
#include <vio/event_loop.h>
#include <vio/ref_counted_wrapper.h>

namespace
{

struct simple_async_data_t
{
  std::function<void()> callback;
  uv_async_t async_handle = {};
  bool &closed;
  bool &destroyed;

  simple_async_data_t(std::function<void()> &&callback, bool &closed, bool &destroyed, vio::event_loop_t &loop)
    : callback(std::move(callback))
    , closed(closed)
    , destroyed(destroyed)
  {
    async_handle.data = this;
    uv_async_init(loop.loop(), &async_handle, on_async_callback);
  }

  ~simple_async_data_t()
  {
    destroyed = true;
  }

  static void on_async_callback(uv_async_t *async)
  {
    auto *data = static_cast<simple_async_data_t *>(async->data);
    data->callback();
  }
};

using owned_async_t = vio::ref_ptr_t<simple_async_data_t>;

TEST_CASE("register_handle with ref_ptr_t")
{
  SUBCASE("async handle initialization and callback")
  {
    vio::event_loop_t loop;
    int callback_count = 0;
    bool async_closed = false;
    bool async_destroyed = false;

    std::function<void()> called_from_callback;

    auto callback = [&called_from_callback]() { called_from_callback(); };
    owned_async_t async_wrapper(std::move(callback), async_closed, async_destroyed, loop);
    async_wrapper.register_handle(&async_wrapper->async_handle);
    async_wrapper.on_destroy([&async_closed]() { async_closed = true; });

    called_from_callback = [&async_wrapper, &callback_count]()
    {
      ++callback_count;
      async_wrapper.release();
    };

    CHECK(callback_count == 0);

    loop.run_in_loop(
      [&loop, &async_wrapper]()
      {
        uv_async_send(&async_wrapper->async_handle);
        loop.stop();
      });

    loop.run();

    CHECK(callback_count > 0);
  }

  SUBCASE("owned wrapper can be copied and shared")
  {
    vio::event_loop_t loop;
    bool async_closed = false;
    bool async_destroyed = false;
    owned_async_t async1([] {}, async_closed, async_destroyed, loop);
    async1.register_handle(&async1->async_handle);

    CHECK(async1.ref_counted()->ref_count == 1);

    {
      owned_async_t async2 = async1;
      CHECK(async1.ref_counted()->ref_count == 2);
      CHECK(async2.ref_counted()->ref_count == 2);

      loop.run_in_loop(
        [&loop, &async1, &async2]()
        {
          loop.stop();
          async1.release();
          CHECK(async2.ref_counted()->ref_count == 1);
          async2.release();
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
      async1.register_handle(&async1->async_handle);
      async1.on_destroy([&destroyed]() { destroyed = true; });
      async1.on_destroy([&async_closed]() { async_closed = true; });

      {
        owned_async_t async2 = async1;
        owned_async_t async3 = async2;
        CHECK(async1.ref_counted()->ref_count == 3);
        CHECK_FALSE(destroyed);
      }

      CHECK(async1.ref_counted()->ref_count == 1);
      CHECK_FALSE(destroyed);
    }

    CHECK(destroyed);
    CHECK(async_closed);
    CHECK_FALSE(async_destroyed);
    loop.run_in_loop([&loop] { loop.stop(); });
    loop.run();
    CHECK(async_destroyed);
  }

  SUBCASE("async send and receive multiple times")
  {
    vio::event_loop_t loop;
    bool async_closed = false;
    bool async_destroyed = false;

    int call_count = 0;
    owned_async_t async_wrapper([&call_count] { call_count++; }, async_closed, async_destroyed, loop);
    async_wrapper.register_handle(&async_wrapper->async_handle);

    int send_count = 5;
    loop.run_in_loop(
      [&loop, &async_wrapper, &send_count]()
      {
        for (int i = 0; i < send_count; ++i)
        {
          uv_async_send(&async_wrapper->async_handle);
        }
        loop.run_in_loop(
          [&async_wrapper, &loop]
          {
            async_wrapper.release();
            loop.stop();
          });
      });

    loop.run();

    CHECK(call_count >= 1);
  }
}

TEST_CASE("register_handle reference counting with event loop")
{
  SUBCASE("handle keeps object alive during close")
  {
    vio::event_loop_t loop;
    int destruction_phase = 0;

    struct tracked_async_t
    {
      uv_async_t handle = {};
      int *phase;

      explicit tracked_async_t(vio::event_loop_t &loop, int *p)
        : phase(p)
      {
        uv_async_init(loop.loop(), &handle, nullptr);
      }

      ~tracked_async_t()
      {
        *phase = 2;
      }
    };

    using owned_tracked_t = vio::ref_ptr_t<tracked_async_t>;

    {
      owned_tracked_t async(loop, &destruction_phase);
      async.register_handle(&async->handle);
      async.on_destroy([p = &destruction_phase]() { *p = 1; });
      CHECK(destruction_phase == 0);
    }

    CHECK(destruction_phase == 1);

    loop.run_in_loop([&loop] { loop.stop(); });
    loop.run();

    CHECK(destruction_phase == 2);
  }

  SUBCASE("multiple handles close in LIFO order")
  {
    vio::event_loop_t loop;

    struct multi_handle_t
    {
      uv_async_t async1 = {};
      uv_async_t async2 = {};
      uv_async_t async3 = {};

      explicit multi_handle_t(vio::event_loop_t &loop)
      {
        uv_async_init(loop.loop(), &async1, nullptr);
        uv_async_init(loop.loop(), &async2, nullptr);
        uv_async_init(loop.loop(), &async3, nullptr);
      }
    };

    using owned_multi_t = vio::ref_ptr_t<multi_handle_t>;

    std::vector<uv_handle_t *> close_order;

    {
      owned_multi_t wrapper(loop);
      wrapper.register_handle(&wrapper->async1);
      wrapper.register_handle(&wrapper->async2);
      wrapper.register_handle(&wrapper->async3);
    }

    loop.run_in_loop([&loop] { loop.stop(); });
    loop.run();
  }

  SUBCASE("multiple independent wrappers with different lifetimes")
  {
    vio::event_loop_t loop;

    struct counted_async_t
    {
      uv_async_t handle = {};
      int id;

      explicit counted_async_t(vio::event_loop_t &loop, int i)
        : id(i)
      {
        uv_async_init(loop.loop(), &handle, nullptr);
      }
    };

    using owned_counted_t = vio::ref_ptr_t<counted_async_t>;

    static std::vector<int> close_order;
    close_order.clear();

    {
      owned_counted_t async1(loop, 1);
      async1.register_handle(&async1->handle);
      async1.on_destroy([&]() { close_order.push_back(1); });
      {
        owned_counted_t async2(loop, 2);
        async2.register_handle(&async2->handle);
        async2.on_destroy([&]() { close_order.push_back(2); });
        owned_counted_t async3(loop, 3);
        async3.register_handle(&async3->handle);
        async3.on_destroy([&]() { close_order.push_back(3); });
      }
    }
    loop.run_in_loop([&loop] { loop.stop(); });
    loop.run();

    REQUIRE(close_order.size() == 3);
    CHECK(std::find(close_order.begin(), close_order.end(), 1) != close_order.end());
    CHECK(std::find(close_order.begin(), close_order.end(), 2) != close_order.end());
    CHECK(std::find(close_order.begin(), close_order.end(), 3) != close_order.end());
  }
}

TEST_CASE("on_destroy callback behavior")
{
  SUBCASE("destroy callbacks run before handle closing")
  {
    vio::event_loop_t loop;
    bool callback_called = false;

    struct simple_handle_t
    {
      uv_async_t handle = {};

      explicit simple_handle_t(vio::event_loop_t &loop)
      {
        uv_async_init(loop.loop(), &handle, nullptr);
      }
    };

    using owned_simple_t = vio::ref_ptr_t<simple_handle_t>;

    {
      owned_simple_t wrapper(loop);
      wrapper.register_handle(&wrapper->handle);
      wrapper.on_destroy([&callback_called]() { callback_called = true; });
      CHECK_FALSE(callback_called);
    }

    CHECK(callback_called);
    loop.run_in_loop([&loop] { loop.stop(); });
    loop.run();
  }

  SUBCASE("destroy callback can increment refcount to postpone destruction")
  {
    vio::event_loop_t loop;

    struct simple_handle_t
    {
      uv_async_t handle = {};

      explicit simple_handle_t(vio::event_loop_t &loop)
      {
        uv_async_init(loop.loop(), &handle, nullptr);
      }
    };

    using owned_simple_t = vio::ref_ptr_t<simple_handle_t>;

    bool destroyed = false;
    owned_simple_t *wrapper_ptr = nullptr;

    {
      owned_simple_t wrapper(loop);
      wrapper.register_handle(&wrapper->handle);
      wrapper_ptr = &wrapper;

      wrapper.ref_counted()->register_destroy_callback(
        [&]()
        {
          wrapper_ptr->ref_counted()->inc();
          auto close_callback = [wrapper_ptr]() { wrapper_ptr->ref_counted()->dec(); };
          close_callback();
        });

      wrapper.on_destroy([&destroyed]() { destroyed = true; });
    }

    CHECK(destroyed);
    loop.run_in_loop([&loop] { loop.stop(); });
    loop.run();
  }
}
} // namespace
