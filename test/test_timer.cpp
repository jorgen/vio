#include <chrono>
#include <optional>
#include <utility>
#include <vector>
#include <doctest/doctest.h>
#include <vio/event_loop.h>
#include <vio/operation/timer.h>
#include <vio/tick.h>

namespace
{
struct turn_counter_t
{
  vio::detail::loop_core_t &core;
  vio::detail::hook_t hook;
  int turns = 0;

  explicit turn_counter_t(vio::event_loop_t &loop)
    : core(vio::detail::core(loop))
  {
    hook.owner = this;
    hook.run = [](vio::detail::hook_t *raw) { ++static_cast<turn_counter_t *>(raw->owner)->turns; };
    core.add_hook(hook);
  }
  turn_counter_t(const turn_counter_t &) = delete;
  turn_counter_t &operator=(const turn_counter_t &) = delete;
  turn_counter_t(turn_counter_t &&) = delete;
  turn_counter_t &operator=(turn_counter_t &&) = delete;
  ~turn_counter_t()
  {
    core.remove_hook(hook);
  }
};

void spin_for(std::chrono::nanoseconds duration)
{
  const auto until = std::chrono::steady_clock::now() + duration;
  while (std::chrono::steady_clock::now() < until)
  {
  }
}

vio::timer_t make_timer(vio::event_loop_t &loop)
{
  auto created = vio::timer_create(loop);
  REQUIRE(created.has_value());
  return std::move(created.value());
}
} // namespace

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
  const vio::reference_counted_t *first_handle = timer->handle.ref_counted();
  CHECK_FALSE(vio::timer_is_armed(*timer));

  vio::timer_on_fire(*timer, [&]()
                     {
                       ++fired;
                       if (fired < 5)
                       {
                         REQUIRE(vio::timer_rearm(*timer, std::chrono::milliseconds(1)).has_value());
                         return;
                       }
                       CHECK(timer->handle.ref_counted() == first_handle);
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
  const vio::reference_counted_t *handle = timer->handle.ref_counted();
  const auto *state = &timer->handle.data();

  for (int i = 0; i < 100000; ++i)
  {
    REQUIRE(vio::timer_rearm(*timer, std::chrono::milliseconds(1000)).has_value());
  }
  CHECK(timer->handle.ref_counted() == handle);
  CHECK(&timer->handle.data() == state);
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

TEST_CASE("a timer stopped after it expired but before it fired does not fire")
{
  vio::event_loop_t event_loop;
  std::optional<vio::timer_t> first;
  std::optional<vio::timer_t> second;
  int first_fired = 0;
  int second_fired = 0;
  first.emplace(make_timer(event_loop));
  second.emplace(make_timer(event_loop));
  vio::timer_on_fire(*second, [&] { ++second_fired; });
  auto finish = [&] {
    event_loop.run_in_loop([&] {
      first.reset();
      second.reset();
      event_loop.stop();
    });
  };

  SUBCASE("disarmed by a timer that fires before it in the same pass")
  {
    bool armed_after_disarm = true;
    vio::timer_on_fire(*first, [&] {
      ++first_fired;
      vio::timer_disarm(*second);
      armed_after_disarm = vio::timer_is_armed(*second);
      finish();
    });
    event_loop.run_in_loop([&] {
      REQUIRE(vio::timer_rearm(*first, std::chrono::milliseconds(1)).has_value());
      REQUIRE(vio::timer_rearm(*second, std::chrono::milliseconds(1)).has_value());
      spin_for(std::chrono::milliseconds(3));
    });
    event_loop.run();
    CHECK(first_fired == 1);
    CHECK_FALSE(armed_after_disarm);
  }

  SUBCASE("dropped by a timer that fires before it in the same pass")
  {
    vio::timer_on_fire(*first, [&] {
      ++first_fired;
      second.reset();
      finish();
    });
    event_loop.run_in_loop([&] {
      REQUIRE(vio::timer_rearm(*first, std::chrono::milliseconds(1)).has_value());
      REQUIRE(vio::timer_rearm(*second, std::chrono::milliseconds(1)).has_value());
      spin_for(std::chrono::milliseconds(3));
    });
    event_loop.run();
    CHECK(first_fired == 1);
  }

  SUBCASE("disarmed by work that ran after it expired")
  {
    event_loop.run_in_loop([&] {
      REQUIRE(vio::timer_rearm(*second, std::chrono::milliseconds(1)).has_value());
      spin_for(std::chrono::milliseconds(3));
      vio::timer_disarm(*second);
      finish();
    });
    event_loop.run();
  }

  SUBCASE("rearmed for later by work that ran after it expired")
  {
    event_loop.run_in_loop([&] {
      REQUIRE(vio::timer_rearm(*second, std::chrono::milliseconds(1)).has_value());
      spin_for(std::chrono::milliseconds(3));
      REQUIRE(vio::timer_rearm(*second, std::chrono::seconds(10)).has_value());
      finish();
    });
    event_loop.run();
  }

  CHECK(second_fired == 0);
  CHECK_FALSE(first.has_value());
  CHECK_FALSE(second.has_value());
}

TEST_CASE("a timer rearmed during dispatch with a past deadline fires on a later turn")
{
  vio::event_loop_t event_loop;
  turn_counter_t counter(event_loop);

  SUBCASE("rearmed from its own callback")
  {
    std::optional<vio::timer_t> timer;
    std::vector<int> fire_turns;
    timer.emplace(make_timer(event_loop));
    vio::timer_on_fire(*timer, [&] {
      fire_turns.push_back(counter.turns);
      if (fire_turns.size() < 5)
      {
        REQUIRE(vio::timer_rearm(*timer, std::chrono::milliseconds(-10)).has_value());
        return;
      }
      timer.reset();
      event_loop.stop();
    });
    REQUIRE(vio::timer_rearm(*timer, std::chrono::milliseconds(-10)).has_value());
    event_loop.run();

    REQUIRE(fire_turns.size() == 5);
    for (std::size_t i = 1; i < fire_turns.size(); ++i)
      CHECK(fire_turns[i] > fire_turns[i - 1]);
  }

  SUBCASE("rearmed from another timer's callback")
  {
    std::optional<vio::timer_t> first;
    std::optional<vio::timer_t> second;
    int first_turn = -1;
    int second_turn = -1;
    first.emplace(make_timer(event_loop));
    second.emplace(make_timer(event_loop));
    vio::timer_on_fire(*first, [&] {
      first_turn = counter.turns;
      REQUIRE(vio::timer_rearm(*second, std::chrono::milliseconds(-10)).has_value());
    });
    vio::timer_on_fire(*second, [&] {
      second_turn = counter.turns;
      first.reset();
      second.reset();
      event_loop.stop();
    });
    REQUIRE(vio::timer_rearm(*second, std::chrono::seconds(10)).has_value());
    REQUIRE(vio::timer_rearm(*first, std::chrono::milliseconds(-10)).has_value());
    event_loop.run();

    CHECK(first_turn >= 0);
    CHECK(second_turn > first_turn);
  }
}

TEST_CASE("a timer that does not keep the loop alive does not hold run open after stop")
{
  vio::event_loop_t event_loop;
  std::optional<vio::timer_t> timer;
  bool fired = false;
  timer.emplace(make_timer(event_loop));
  vio::timer_on_fire(*timer, [&] { fired = true; });
  vio::timer_set_keeps_loop_alive(*timer, false);
  REQUIRE(vio::timer_rearm(*timer, std::chrono::seconds(10)).has_value());

  const auto start = std::chrono::steady_clock::now();
  event_loop.run_in_loop([&] { event_loop.stop(); });
  event_loop.run();

  CHECK(std::chrono::steady_clock::now() - start < std::chrono::seconds(5));
  CHECK_FALSE(fired);
  CHECK(vio::timer_is_armed(*timer));

  timer.reset();
  event_loop.run();
  CHECK(vio::detail::core(event_loop).open_resources() == 0);
}
