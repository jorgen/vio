#include <doctest/doctest.h>

#include "vio/event_loop.h"
#include "vio/ref_counted_wrapper.h"

namespace
{
struct destruction_tracker_t
{
  static inline int destruction_count = 0;
  static inline int construction_count = 0;

  static void reset()
  {
    destruction_count = 0;
    construction_count = 0;
  }
};

struct test_data_t
{
  int value{0};
  bool *destroyed{nullptr};

  test_data_t()
  {
    destruction_tracker_t::construction_count++;
  }

  explicit test_data_t(int v)
    : value(v)
  {
    destruction_tracker_t::construction_count++;
  }

  explicit test_data_t(int v, bool *d)
    : value(v)
    , destroyed(d)
  {
    destruction_tracker_t::construction_count++;
  }

  ~test_data_t()
  {
    destruction_tracker_t::destruction_count++;
    if (destroyed)
    {
      *destroyed = true;
    }
  }
};

using test_owned_t = vio::wrapper_t<test_data_t>;

TEST_CASE("reference_counted_t basic operations")
{
  SUBCASE("initial ref count is 1")
  {
    struct dummy_t
    {
    };
    auto *obj = new dummy_t();
    vio::reference_counted_t ref([obj]() { delete obj; });

    CHECK(ref.ref_count == 1);
  }

  SUBCASE("inc increases ref count")
  {
    struct dummy_t
    {
    };
    auto *obj = new dummy_t();
    vio::reference_counted_t ref([obj]() { delete obj; });

    ref.inc();
    CHECK(ref.ref_count == 2);

    ref.inc();
    CHECK(ref.ref_count == 3);

    ref.dec();
    ref.dec();
    ref.dec();
  }

  SUBCASE("dec decreases ref count")
  {
    struct dummy_t
    {
    };
    auto *obj = new dummy_t();
    vio::reference_counted_t ref([obj]() { delete obj; });

    ref.inc();
    ref.inc();

    bool result = ref.dec();
    CHECK_FALSE(result);
    CHECK(ref.ref_count == 2);

    result = ref.dec();
    CHECK_FALSE(result);
    CHECK(ref.ref_count == 1);
  }

  SUBCASE("dec to zero triggers deletion")
  {
    bool destroyed = false;
    struct test_t
    {
      bool *flag;
      test_t(bool *f)
        : flag(f)
      {
      }
      ~test_t()
      {
        *flag = true;
      }
    };

    auto *obj = new test_t(&destroyed);
    auto *ref = new vio::reference_counted_t([obj]() { delete obj; });

    CHECK_FALSE(destroyed);
    bool result = ref->dec();
    CHECK(result);
    CHECK(destroyed);
  }

  SUBCASE("destroy callbacks are called in reverse order")
  {
    struct dummy_t
    {
    };
    auto *obj = new dummy_t();
    auto *ref = new vio::reference_counted_t([obj]() { delete obj; });

    std::vector<int> order;
    ref->register_destroy_callback([&]() { order.push_back(1); });
    ref->register_destroy_callback([&]() { order.push_back(2); });
    ref->register_destroy_callback([&]() { order.push_back(3); });

    ref->dec();

    REQUIRE(order.size() == 3);
    CHECK(order[0] == 3);
    CHECK(order[1] == 2);
    CHECK(order[2] == 1);
  }

  SUBCASE("callback can increment ref count to postpone destruction")
  {
    struct dummy_t
    {
    };
    auto *obj = new dummy_t();
    auto *ref = new vio::reference_counted_t([obj]() { delete obj; });

    bool callback_called = false;
    ref->register_destroy_callback(
      [&]()
      {
        callback_called = true;
        ref->inc();
      });

    bool result = ref->dec();
    CHECK(callback_called);
    CHECK_FALSE(result);
    CHECK(ref->ref_count == 1);

    ref->dec();
  }
}

TEST_CASE("wrapper_t basic operations")
{
  destruction_tracker_t::reset();

  SUBCASE("default construction")
  {
    test_owned_t wrapper;

    CHECK(wrapper.ref_counted()->ref_count == 1);
    CHECK(wrapper->value == 0);
  }

  SUBCASE("construction with arguments")
  {
    test_owned_t wrapper(42);

    CHECK(wrapper.ref_counted()->ref_count == 1);
    CHECK(wrapper->value == 42);
  }

  SUBCASE("data access through operator->")
  {
    test_owned_t wrapper(100);

    wrapper->value = 200;
    CHECK(wrapper->value == 200);
  }

  SUBCASE("data access through data()")
  {
    test_owned_t wrapper(100);

    wrapper.data().value = 300;
    CHECK(wrapper.data().value == 300);
  }
}

TEST_CASE("wrapper_t reference counting")
{
  destruction_tracker_t::reset();

  SUBCASE("copy constructor increments ref count")
  {
    test_owned_t wrapper1(42);
    CHECK(wrapper1.ref_counted()->ref_count == 1);

    test_owned_t wrapper2 = wrapper1;
    CHECK(wrapper1.ref_counted()->ref_count == 2);
    CHECK(wrapper2.ref_counted()->ref_count == 2);
    CHECK(wrapper1->value == 42);
    CHECK(wrapper2->value == 42);
  }

  SUBCASE("copy assignment increments ref count")
  {
    test_owned_t wrapper1(42);
    test_owned_t wrapper2(99);

    CHECK(destruction_tracker_t::construction_count == 2);

    wrapper2 = wrapper1;

    CHECK(wrapper1.ref_counted()->ref_count == 2);
    CHECK(wrapper2.ref_counted()->ref_count == 2);
    CHECK(wrapper2->value == 42);

    CHECK(destruction_tracker_t::destruction_count == 1);
  }

  SUBCASE("move constructor transfers ownership")
  {
    test_owned_t wrapper1(42);
    CHECK(wrapper1.ref_counted()->ref_count == 1);

    test_owned_t wrapper2 = std::move(wrapper1);
    CHECK(wrapper2.ref_counted()->ref_count == 1);
    CHECK(wrapper2->value == 42);
  }

  SUBCASE("destructor decrements ref count")
  {
    destruction_tracker_t::reset();

    {
      test_owned_t wrapper1(42);
      {
        test_owned_t wrapper2 = wrapper1;
        CHECK(wrapper1.ref_counted()->ref_count == 2);
      }
      CHECK(wrapper1.ref_counted()->ref_count == 1);
      CHECK(destruction_tracker_t::destruction_count == 0);
    }
    CHECK(destruction_tracker_t::destruction_count == 1);
  }

  SUBCASE("storage deleted when last reference is destroyed")
  {
    destruction_tracker_t::reset();
    bool destroyed = false;

    {
      test_owned_t wrapper1(42, &destroyed);
      {
        test_owned_t wrapper2 = wrapper1;
        test_owned_t wrapper3 = wrapper2;
        CHECK(wrapper1.ref_counted()->ref_count == 3);
        CHECK_FALSE(destroyed);
      }
      CHECK(wrapper1.ref_counted()->ref_count == 1);
      CHECK_FALSE(destroyed);
    }
    CHECK(destroyed);
  }
}

TEST_CASE("wrapper_t with callbacks")
{
  SUBCASE("destroy callback is invoked on destruction")
  {
    bool callback_called = false;

    {
      test_owned_t wrapper(42);
      wrapper.ref_counted()->register_destroy_callback([&]() { callback_called = true; });
      CHECK_FALSE(callback_called);
    }

    CHECK(callback_called);
  }

  SUBCASE("callback can postpone destruction (libuv style)")
  {
    destruction_tracker_t::reset();
    test_owned_t *wrapper_ptr = nullptr;
    int callback_count = 0;

    {
      test_owned_t wrapper(42);
      wrapper_ptr = &wrapper;

      wrapper.ref_counted()->register_destroy_callback(
        [&]()
        {
          callback_count++;
          wrapper_ptr->ref_counted()->inc();

          auto close_callback = [wrapper_ptr]() { wrapper_ptr->ref_counted()->dec(); };

          close_callback();
        });
    }

    CHECK(callback_count == 1);
    CHECK(destruction_tracker_t::destruction_count == 1);
  }

  SUBCASE("multiple callbacks executed in reverse order")
  {
    std::vector<int> order;

    {
      test_owned_t wrapper(42);
      wrapper.ref_counted()->register_destroy_callback([&]() { order.push_back(1); });
      wrapper.ref_counted()->register_destroy_callback([&]() { order.push_back(2); });
      wrapper.ref_counted()->register_destroy_callback([&]() { order.push_back(3); });
    }

    REQUIRE(order.size() == 3);
    CHECK(order[0] == 3);
    CHECK(order[1] == 2);
    CHECK(order[2] == 1);
  }
}

TEST_CASE("wrapper_t register_handle and on_destroy")
{
  SUBCASE("register_handle stores handle for closing")
  {
    vio::event_loop_t loop;

    struct handle_data_t
    {
      uv_async_t async = {};

      explicit handle_data_t(vio::event_loop_t &loop)
      {
        uv_async_init(loop.loop(), &async, nullptr);
      }
    };

    using owned_handle_t = vio::wrapper_t<handle_data_t>;

    bool destroyed = false;
    {
      owned_handle_t wrapper(loop);
      wrapper.register_handle(&wrapper->async);
      wrapper.on_destroy([&destroyed]() { destroyed = true; });
    }

    CHECK(destroyed);
    loop.run_in_loop([&loop] { loop.stop(); });
    loop.run();
  }

  SUBCASE("on_destroy is alias for register_destroy_callback")
  {
    std::vector<int> order;

    {
      test_owned_t wrapper(42);
      wrapper.on_destroy([&]() { order.push_back(1); });
      wrapper.on_destroy([&]() { order.push_back(2); });
    }

    REQUIRE(order.size() == 2);
    CHECK(order[0] == 2);
    CHECK(order[1] == 1);
  }
}

TEST_CASE("mixed usage scenario")
{
  destruction_tracker_t::reset();

  SUBCASE("owned wrapper can be part of larger structure")
  {
    struct request_t
    {
      test_owned_t owned_tcp;
      int request_id;

      request_t(int id)
        : owned_tcp(id)
        , request_id(id)
      {
      }
    };

    request_t req(42);
    CHECK(req.owned_tcp->value == 42);
    CHECK(req.owned_tcp.ref_counted()->ref_count == 1);

    test_owned_t copy = req.owned_tcp;
    CHECK(req.owned_tcp.ref_counted()->ref_count == 2);
  }
}
} // namespace
