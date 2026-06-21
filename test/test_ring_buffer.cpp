#include <doctest/doctest.h>

#include <vio/ring_buffer.h>

#include <cassert>

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
}
