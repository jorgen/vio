#include <chrono>
#include <optional>
#include <utility>
#include <doctest/doctest.h>
#include <vio/event_loop.h>
#include <vio/operation/timer.h>
#include <vio/tick.h>

// A uv handle is closed when the last reference to it goes away, and the close
// callback only runs while the loop does. Every test here therefore releases
// its timer before the loop is torn down, which is the same discipline the udp
// and tcp tests get for free by owning their handles inside a coroutine.

TEST_CASE("tick_t arithmetic and ordering")
{
  const auto origin = vio::tick_t::from_nanoseconds(std::chrono::nanoseconds(1000));
  const auto later = origin + std::chrono::microseconds(5);

  CHECK(later > origin);
  CHECK(origin < later);
  CHECK(origin == vio::tick_t::from_nanoseconds(std::chrono::nanoseconds(1000)));
  CHECK(later - origin == std::chrono::microseconds(5));
  CHECK((later - std::chrono::microseconds(5)) == origin);

  auto mutated = origin;
  mutated += std::chrono::microseconds(5);
  CHECK(mutated == later);
  mutated -= std::chrono::microseconds(5);
  CHECK(mutated == origin);
}

TEST_CASE("loop_now is monotonic")
{
  vio::event_loop_t event_loop;
  auto previous = vio::loop_now(event_loop);
  for (int i = 0; i < 10000; ++i)
  {
    auto current = vio::loop_now(event_loop);
    REQUIRE(current >= previous);
    previous = current;
  }
  event_loop.stop();
  event_loop.run();
}

TEST_CASE("timer fires repeatedly on one rearmed handle")
{
  vio::event_loop_t event_loop;
  int fired = 0;
  std::optional<vio::timer_t> timer;

  auto created = vio::timer_create(event_loop);
  REQUIRE(created.has_value());
  timer = std::move(created.value());
  const uv_timer_t *first_handle = timer->get_timer();
  CHECK_FALSE(vio::timer_is_armed(*timer));

  vio::timer_on_fire(*timer, [&]()
                     {
                       ++fired;
                       if (fired < 5)
                       {
                         REQUIRE(vio::timer_rearm(*timer, std::chrono::milliseconds(1)).has_value());
                         return;
                       }
                       CHECK(timer->get_timer() == first_handle);
                       timer.reset();
                       event_loop.stop();
                     });

  REQUIRE(vio::timer_rearm(*timer, std::chrono::milliseconds(1)).has_value());
  CHECK(vio::timer_is_armed(*timer));
  event_loop.run();

  CHECK(fired == 5);
  CHECK_FALSE(timer.has_value());
}

TEST_CASE("rearming does not allocate a new handle")
{
  vio::event_loop_t event_loop;
  std::optional<vio::timer_t> timer;

  auto created = vio::timer_create(event_loop);
  REQUIRE(created.has_value());
  timer = std::move(created.value());
  const uv_timer_t *handle = timer->get_timer();

  for (int i = 0; i < 100000; ++i)
  {
    REQUIRE(vio::timer_rearm(*timer, std::chrono::milliseconds(1000)).has_value());
  }
  CHECK(timer->get_timer() == handle);
  CHECK(vio::timer_is_armed(*timer));

  vio::timer_disarm(*timer);
  CHECK_FALSE(vio::timer_is_armed(*timer));

  timer.reset();
  event_loop.stop();
  event_loop.run();
}

TEST_CASE("a deadline already in the past fires on the next iteration")
{
  vio::event_loop_t event_loop;
  bool fired = false;
  std::optional<vio::timer_t> timer;

  auto created = vio::timer_create(event_loop);
  REQUIRE(created.has_value());
  timer = std::move(created.value());

  vio::timer_on_fire(*timer, [&]()
                     {
                       fired = true;
                       timer.reset();
                       event_loop.stop();
                     });
  REQUIRE(vio::timer_rearm(*timer, std::chrono::milliseconds(-50)).has_value());
  event_loop.run();

  CHECK(fired);
}

TEST_CASE("a disarmed timer does not fire")
{
  vio::event_loop_t event_loop;
  bool fired = false;
  std::optional<vio::timer_t> timer;
  std::optional<vio::timer_t> stopper;

  auto created = vio::timer_create(event_loop);
  REQUIRE(created.has_value());
  timer = std::move(created.value());
  vio::timer_on_fire(*timer, [&]() { fired = true; });
  REQUIRE(vio::timer_rearm(*timer, std::chrono::milliseconds(1)).has_value());
  vio::timer_disarm(*timer);

  auto created_stopper = vio::timer_create(event_loop);
  REQUIRE(created_stopper.has_value());
  stopper = std::move(created_stopper.value());
  vio::timer_on_fire(*stopper, [&]()
                     {
                       timer.reset();
                       stopper.reset();
                       event_loop.stop();
                     });
  REQUIRE(vio::timer_rearm(*stopper, std::chrono::milliseconds(40)).has_value());
  event_loop.run();

  CHECK_FALSE(fired);
}

TEST_CASE("dropping the timer inside its own callback is safe")
{
  vio::event_loop_t event_loop;
  bool fired = false;
  std::optional<vio::timer_t> timer;

  auto created = vio::timer_create(event_loop);
  REQUIRE(created.has_value());
  timer = std::move(created.value());

  vio::timer_on_fire(*timer, [&]()
                     {
                       fired = true;
                       timer.reset();
                       event_loop.stop();
                     });
  REQUIRE(vio::timer_rearm(*timer, std::chrono::milliseconds(1)).has_value());
  event_loop.run();

  CHECK(fired);
  CHECK_FALSE(timer.has_value());
}
