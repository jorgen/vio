#include <doctest/doctest.h>

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

  // Constructors for owned_wrapper_t (no parent ref_counted)
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

  // Constructors for inline_wrapper_t (with parent ref_counted)
  test_data_t(vio::reference_counted_t *ref_counted)
  {
    (void)ref_counted;
    destruction_tracker_t::construction_count++;
  }

  explicit test_data_t(vio::reference_counted_t *ref_counted, int v)
    : value(v)
  {
    (void)ref_counted;
    destruction_tracker_t::construction_count++;
  }

  explicit test_data_t(vio::reference_counted_t *ref_counted, int v, bool *d)
    : value(v)
    , destroyed(d)
  {
    (void)ref_counted;
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

using test_owned_t = vio::owned_wrapper_t<test_data_t>;
using test_inline_t = vio::inline_wrapper_t<test_data_t>;

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

TEST_CASE("owned_wrapper_t basic operations")
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

TEST_CASE("owned_wrapper_t reference counting")
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

TEST_CASE("owned_wrapper_t with callbacks")
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

TEST_CASE("inline_wrapper_t basic operations")
{
  destruction_tracker_t::reset();

  SUBCASE("construction with parent ref count")
  {
    struct container_t
    {
      vio::reference_counted_t ref_count;
      test_inline_t wrapper;

      container_t()
        : ref_count([this] { delete this; })
        , wrapper(&ref_count)
      {
      }
    };

    container_t container;
    CHECK(container.ref_count.ref_count == 1);
    CHECK(container.wrapper->value == 0);
  }

  SUBCASE("construction with parent and data arguments")
  {
    struct container_t
    {
      vio::reference_counted_t ref_count;
      test_inline_t wrapper;

      container_t()
        : ref_count([this] { delete this; })
        , wrapper(&ref_count, 42)
      {
      }
    };

    container_t container;
    CHECK(container.wrapper->value == 42);
  }

  SUBCASE("data access")
  {
    struct container_t
    {
      vio::reference_counted_t ref_count;
      test_inline_t wrapper;

      container_t()
        : ref_count([this] { delete this; })
        , wrapper(&ref_count, 100)
      {
      }
    };

    container_t container;
    container.wrapper->value = 200;
    CHECK(container.wrapper->value == 200);
    CHECK(container.wrapper.data().value == 200);
  }

  SUBCASE("access to parent ref count")
  {
    struct container_t
    {
      vio::reference_counted_t ref_count;
      test_inline_t wrapper;

      container_t()
        : ref_count([this] { delete this; })
        , wrapper(&ref_count)
      {
      }
    };

    container_t container;
    CHECK((void *)container.wrapper.ref_counted() == &container.ref_count);
  }
}

TEST_CASE("inline_wrapper_t does not manage ref count")
{
  destruction_tracker_t::reset();

  SUBCASE("wrapper destruction does not affect parent ref count")
  {
    struct container_t
    {
      vio::reference_counted_t ref_count;
      test_inline_t wrapper;

      container_t()
        : ref_count([this] { delete this; })
        , wrapper(&ref_count)
      {
      }
    };

    auto *container = new container_t();
    CHECK(container->ref_count.ref_count == 1);

    container->ref_count.inc();
    CHECK(container->ref_count.ref_count == 2);

    container->ref_count.dec();
    CHECK(container->ref_count.ref_count == 1);

    container->ref_count.dec();
  }

  SUBCASE("parent manages lifetime")
  {
    destruction_tracker_t::reset();

    struct container_t
    {
      vio::reference_counted_t ref_count;
      test_inline_t wrapper;

      container_t()
        : ref_count([this] { delete this; })
        , wrapper(&ref_count, 42)
      {
      }
    };

    auto *container = new container_t();

    container->ref_count.inc();
    container->ref_count.inc();
    CHECK(container->ref_count.ref_count == 3);

    container->ref_count.dec();
    container->ref_count.dec();
    CHECK(container->ref_count.ref_count == 1);
    CHECK(destruction_tracker_t::destruction_count == 0);

    container->ref_count.dec();
    CHECK(destruction_tracker_t::destruction_count == 1);
  }
}

TEST_CASE("inline_wrapper_t with multiple wrappers")
{
  destruction_tracker_t::reset();

  struct multi_container_t
  {
    vio::reference_counted_t ref_count;
    test_inline_t wrapper1;
    test_inline_t wrapper2;
    test_inline_t wrapper3;

    multi_container_t()
      : ref_count([this] { delete this; })
      , wrapper1(&ref_count, 1)
      , wrapper2(&ref_count, 2)
      , wrapper3(&ref_count, 3)
    {
    }
  };

  SUBCASE("multiple wrappers share parent ref count")
  {
    auto *container = new multi_container_t();

    CHECK(container->wrapper1->value == 1);
    CHECK(container->wrapper2->value == 2);
    CHECK(container->wrapper3->value == 3);

    CHECK(((void *)container->wrapper1.ref_counted()) == &container->ref_count);
    CHECK(((void *)container->wrapper2.ref_counted()) == &container->ref_count);
    CHECK(((void *)container->wrapper3.ref_counted()) == &container->ref_count);

    CHECK(container->ref_count.ref_count == 1);

    container->ref_count.dec();
  }

  SUBCASE("all wrappers destroyed with container")
  {
    CHECK(destruction_tracker_t::construction_count == 0);

    auto *container = new multi_container_t();
    CHECK(destruction_tracker_t::construction_count == 3);

    container->ref_count.dec();
    CHECK(destruction_tracker_t::destruction_count == 3);
  }
}

TEST_CASE("inline_wrapper_t with callbacks")
{
  SUBCASE("callbacks registered through wrapper")
  {
    struct container_t
    {
      vio::reference_counted_t ref_count;
      test_inline_t wrapper;

      container_t()
        : ref_count([this] { delete this; })
        , wrapper(&ref_count, 42)
      {
      }
    };

    bool callback_called = false;
    auto *container = new container_t();

    container->wrapper.ref_counted()->register_destroy_callback([&]() { callback_called = true; });

    container->ref_count.dec();
    CHECK(callback_called);
  }

  SUBCASE("simulate libuv close with inline wrappers")
  {
    struct container_t
    {
      vio::reference_counted_t ref_count;
      test_inline_t tcp;
      test_inline_t async_handle;
      bool tcp_closed{false};
      bool async_closed{false};

      container_t()
        : ref_count([this] { delete this; })
        , tcp(&ref_count, 1)
        , async_handle(&ref_count, 2)
      {

        ref_count.register_destroy_callback(
          [this]()
          {
            ref_count.inc();
            ref_count.inc();

            auto tcp_close = [this]()
            {
              tcp_closed = true;
              ref_count.dec();
            };

            auto async_close = [this]()
            {
              async_closed = true;
              ref_count.dec();
            };

            tcp_close();
            async_close();
          });
      }
    };

    auto *container = new container_t();
    CHECK_FALSE(container->tcp_closed);
    CHECK_FALSE(container->async_closed);

    container->ref_count.dec();

    CHECK(container->tcp_closed);
    CHECK(container->async_closed);
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

  SUBCASE("inline wrappers in heap-allocated container")
  {
    struct connection_t
    {
      vio::reference_counted_t ref_count;
      test_inline_t tcp;
      test_inline_t file;

      connection_t()
        : ref_count([this] { delete this; })
        , tcp(&ref_count, 1)
        , file(&ref_count, 2)
      {
      }
    };

    auto *conn1 = new connection_t();
    auto *conn2 = new connection_t();

    conn1->ref_count.inc();
    conn2->ref_count.inc();

    CHECK(conn1->tcp->value == 1);
    CHECK(conn2->tcp->value == 1);

    conn1->ref_count.dec();
    conn1->ref_count.dec();

    conn2->ref_count.dec();
    conn2->ref_count.dec();
  }
}
} // namespace