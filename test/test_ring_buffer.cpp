#include <doctest/doctest.h>

#include <vio/ring_buffer.h>

#include <cassert>
#include <utility>

namespace
{
// Copy/move-accounting type to verify emplace() forwards instead of copying.
struct counted_t
{
  static inline int copies = 0; // NOLINT
  static inline int moves = 0;  // NOLINT
  int value = 0;

  counted_t() = default;
  explicit counted_t(int v)
    : value(v)
  {
  }
  counted_t(const counted_t &o)
    : value(o.value)
  {
    ++copies;
  }
  counted_t(counted_t &&o) noexcept
    : value(o.value)
  {
    ++moves;
  }
  counted_t &operator=(const counted_t &o)
  {
    value = o.value;
    ++copies;
    return *this;
  }
  counted_t &operator=(counted_t &&o) noexcept
  {
    value = o.value;
    ++moves;
    return *this;
  }
  ~counted_t() = default;

  static void reset()
  {
    copies = 0;
    moves = 0;
  }
};
} // namespace

TEST_SUITE("ring_buffer_t")
{
  TEST_CASE("emplace returns a reference to the inserted element")
  {
    vio::ring_buffer_t<int, 4> rb;
    int &ref = rb.emplace(42);

    // The returned reference must alias the element that was just inserted
    // (i.e. the current back()), not the next, still-empty slot.
    CHECK_EQ(&ref, &rb.back());
    CHECK_EQ(ref, 42);
  }

  TEST_CASE("emplace preserves FIFO ordering")
  {
    vio::ring_buffer_t<int, 4> rb;
    rb.emplace(1);
    rb.emplace(2);
    rb.emplace(3);

    CHECK_EQ(rb.pop_front(), 1);
    CHECK_EQ(rb.pop_front(), 2);
    CHECK_EQ(rb.pop_front(), 3);
    CHECK(rb.empty());
  }

  TEST_CASE("emplace forwards its arguments rather than copying")
  {
    counted_t::reset();
    vio::ring_buffer_t<counted_t, 4> rb;
    rb.emplace(counted_t{7});

    CHECK_EQ(rb.back().value, 7);
    // A forwarding emplace must not make any copies of the argument.
    CHECK_EQ(counted_t::copies, 0);
  }

  TEST_CASE("a popped or discarded slot is released once and stays usable")
  {
    struct probe_t
    {
      int *destroyed_twice = nullptr;
      int *live = nullptr;
      bool alive = true;

      probe_t() = default;
      probe_t(int *twice, int *count)
        : destroyed_twice(twice)
        , live(count)
      {
        ++*live;
      }
      probe_t(probe_t &&other) noexcept
        : destroyed_twice(other.destroyed_twice)
        , live(std::exchange(other.live, nullptr))
      {
      }
      probe_t &operator=(probe_t &&other) noexcept
      {
        if (live)
          --*live;
        destroyed_twice = other.destroyed_twice;
        live = std::exchange(other.live, nullptr);
        alive = true;
        return *this;
      }
      ~probe_t()
      {
        if (!alive && destroyed_twice)
          ++*destroyed_twice;
        if (alive && live)
          --*live;
        alive = false;
      }
    };

    int destroyed_twice = 0;
    int live = 0;
    {
      vio::ring_buffer_t<probe_t, 4> rb;
      rb.push(probe_t(&destroyed_twice, &live));
      rb.push(probe_t(&destroyed_twice, &live));
      CHECK_EQ(live, 2);
      {
        auto taken = rb.pop_front();
      }
      CHECK_EQ(live, 1);
      rb.discard_front();
      CHECK_EQ(live, 0);
      rb.push(probe_t(&destroyed_twice, &live));
      CHECK_EQ(live, 1);
    }
    CHECK_EQ(live, 0);
    CHECK_EQ(destroyed_twice, 0);
  }
}
