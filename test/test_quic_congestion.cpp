#include <chrono>
#include <cstdint>
#include <optional>
#include <ostream>
#include <vector>
#include <doctest/doctest.h>
#include <vio/quic/congestion_control.h>

// RFC 9002 section 7, NewReno. The window is the only number here, so the
// tests are about what moves it and, just as importantly, what must not.

namespace
{
using namespace vio::quic;
using namespace std::chrono_literals;

constexpr std::size_t datagram = 1200;

vio::tick_t at(std::chrono::nanoseconds offset)
{
  return vio::tick_t::from_nanoseconds(offset);
}

sent_packet_t packet(std::uint64_t number, vio::tick_t sent, std::size_t size = datagram, bool ack_eliciting = true)
{
  sent_packet_t out;
  out.packet_number = number;
  out.time_sent = sent;
  out.ack_eliciting = ack_eliciting;
  out.in_flight = true;
  out.size = size;
  return out;
}

rtt_estimator_t settled_rtt(std::chrono::nanoseconds sample = std::chrono::nanoseconds(100ms))
{
  rtt_estimator_t rtt;
  rtt.on_rtt_sample(sample, 0ns, false, 25ms);
  return rtt;
}
} // namespace

TEST_SUITE("quic congestion control")
{
TEST_CASE("the initial window follows section 7.2")
{
  // Ten datagrams, bounded by the larger of 14720 and two datagrams.
  CHECK(initial_congestion_window(1200) == 12000);
  CHECK(initial_congestion_window(1500) == 14720);
  CHECK(initial_congestion_window(65527) == 131054);
  CHECK(minimum_congestion_window(1200) == 2400);

  congestion_control_t congestion(datagram);
  CHECK(congestion.window() == 12000);
  CHECK(congestion.in_slow_start());
}

TEST_CASE("slow start grows the window by every byte acknowledged")
{
  congestion_control_t congestion(datagram);
  const auto start = congestion.window();

  congestion.on_packet_acked(packet(0, at(0ns)));
  CHECK(congestion.window() == start + datagram);

  congestion.on_packet_acked(packet(1, at(0ns)));
  CHECK(congestion.window() == start + 2 * datagram);

  SUBCASE("a packet that was not in flight does not count")
  {
    auto not_in_flight = packet(2, at(0ns));
    not_in_flight.in_flight = false;
    const auto before = congestion.window();
    congestion.on_packet_acked(not_in_flight);
    CHECK(congestion.window() == before);
  }
}

TEST_CASE("a loss halves the window and starts a recovery period")
{
  congestion_control_t congestion(datagram);
  const auto start = congestion.window();

  std::vector<sent_packet_t> lost = {packet(0, at(100ms))};
  congestion.on_packets_lost(lost, at(200ms), settled_rtt(), 25ms, std::nullopt);

  CHECK(congestion.window() == start / 2);
  CHECK(congestion.slow_start_threshold() == start / 2);
  CHECK_FALSE(congestion.in_slow_start());

  SUBCASE("a second loss from the same round trip does not halve it again")
  {
    // The defining property of a recovery period: one lost round trip is one
    // congestion event, not one per packet.
    std::vector<sent_packet_t> also_lost = {packet(1, at(150ms))};
    congestion.on_packets_lost(also_lost, at(210ms), settled_rtt(), 25ms, std::nullopt);
    CHECK(congestion.window() == start / 2);
  }

  SUBCASE("a loss of something sent after recovery began does halve it again")
  {
    std::vector<sent_packet_t> later = {packet(2, at(300ms))};
    congestion.on_packets_lost(later, at(400ms), settled_rtt(), 25ms, std::nullopt);
    CHECK(congestion.window() == start / 4);
  }

  SUBCASE("acknowledging a packet sent before recovery does not grow it")
  {
    const auto during = congestion.window();
    congestion.on_packet_acked(packet(3, at(50ms)));
    CHECK(congestion.window() == during);
  }

  SUBCASE("acknowledging one sent after recovery began does")
  {
    const auto during = congestion.window();
    congestion.on_packet_acked(packet(4, at(300ms)));
    CHECK(congestion.window() > during);
  }

  SUBCASE("it never falls below the minimum")
  {
    congestion_control_t small(datagram);
    for (int i = 0; i < 20; ++i)
    {
      std::vector<sent_packet_t> each = {packet(static_cast<std::uint64_t>(i), at(std::chrono::milliseconds(1000 * (i + 1))))};
      small.on_packets_lost(each, at(std::chrono::milliseconds(1000 * (i + 1) + 1)), settled_rtt(), 25ms, std::nullopt);
    }
    CHECK(small.window() == minimum_congestion_window(datagram));
  }
}

TEST_CASE("congestion avoidance grows by about one datagram per round trip")
{
  congestion_control_t congestion(datagram);
  // Drop out of slow start.
  std::vector<sent_packet_t> lost = {packet(0, at(0ns))};
  congestion.on_packets_lost(lost, at(1ms), settled_rtt(), 25ms, std::nullopt);
  const auto window = congestion.window();
  REQUIRE_FALSE(congestion.in_slow_start());

  // Acknowledge a full window's worth, all sent after recovery started.
  std::size_t acknowledged = 0;
  std::uint64_t number = 100;
  while (acknowledged < window)
  {
    congestion.on_packet_acked(packet(number++, at(1s), datagram));
    acknowledged += datagram;
  }

  const auto growth = congestion.window() - window;
  // One datagram per round trip, give or take the integer arithmetic.
  CHECK(growth >= datagram / 2);
  CHECK(growth <= 2 * datagram);

  SUBCASE("and the remainder is carried rather than discarded")
  {
    // With a window far larger than a datagram, each acknowledgement on its
    // own contributes less than a byte. Dropping the remainder would stall
    // growth completely.
    congestion_control_t wide(datagram);
    std::vector<sent_packet_t> drop = {packet(0, at(0ns))};
    wide.on_packets_lost(drop, at(1ms), settled_rtt(), 25ms, std::nullopt);
    const auto before = wide.window();
    for (int i = 0; i < 40; ++i)
    {
      wide.on_packet_acked(packet(static_cast<std::uint64_t>(200 + i), at(1s), 40));
    }
    CHECK(wide.window() > before);
  }
}

TEST_CASE("persistent congestion drops the window to the floor")
{
  const auto rtt = settled_rtt();
  const auto duration = congestion_control_t::persistent_congestion_duration(rtt, 25ms);
  CHECK(duration == (rtt.pto_base() + std::chrono::nanoseconds(25ms)) * 3);

  congestion_control_t congestion(datagram);
  const auto first_sample = at(0ns);

  // Two ack-eliciting packets, sent further apart than the duration, both lost.
  std::vector<sent_packet_t> lost = {packet(1, at(10ms)), packet(2, at(10ms) + duration + std::chrono::nanoseconds(1ms))};
  congestion.on_packets_lost(lost, at(5s), rtt, 25ms, first_sample);
  CHECK(congestion.window() == minimum_congestion_window(datagram));

  SUBCASE("but not when the two are close together")
  {
    congestion_control_t other(datagram);
    std::vector<sent_packet_t> near = {packet(1, at(10ms)), packet(2, at(20ms))};
    other.on_packets_lost(near, at(5s), rtt, 25ms, first_sample);
    // A plain congestion event: halved, not floored.
    CHECK(other.window() == initial_congestion_window(datagram) / 2);
  }

  SUBCASE("nor with only one ack-eliciting packet")
  {
    congestion_control_t other(datagram);
    std::vector<sent_packet_t> single = {packet(1, at(10ms)), packet(2, at(10ms) + duration + std::chrono::nanoseconds(1ms), datagram, false)};
    other.on_packets_lost(single, at(5s), rtt, 25ms, first_sample);
    CHECK(other.window() == initial_congestion_window(datagram) / 2);
  }

  SUBCASE("nor before there is an RTT sample at all")
  {
    // Section 7.6.2: until then the PTO came from a guess, and declaring
    // persistent congestion off it would punish a path that is merely slow.
    congestion_control_t other(datagram);
    other.on_packets_lost(lost, at(5s), rtt, 25ms, std::nullopt);
    CHECK(other.window() == initial_congestion_window(datagram) / 2);
  }

  SUBCASE("nor for packets sent before the first sample")
  {
    congestion_control_t other(datagram);
    other.on_packets_lost(lost, at(5s), rtt, 25ms, at(10s));
    CHECK(other.window() == initial_congestion_window(datagram) / 2);
  }

  SUBCASE("and afterwards the connection is back in slow start")
  {
    // The window equals the threshold, so the next acknowledgement grows it by
    // the avoidance rule rather than the slow start one; what matters is that
    // recovery is over and growth resumes.
    const auto before = congestion.window();
    congestion.on_packet_acked(packet(9, at(6s)));
    CHECK(congestion.window() > before);
  }
}

TEST_CASE("losing nothing that was in flight is not a congestion event")
{
  congestion_control_t congestion(datagram);
  const auto start = congestion.window();

  auto not_in_flight = packet(0, at(0ns));
  not_in_flight.in_flight = false;
  std::vector<sent_packet_t> lost = {not_in_flight};
  congestion.on_packets_lost(lost, at(100ms), settled_rtt(), 25ms, std::nullopt);
  CHECK(congestion.window() == start);

  SUBCASE("and neither is an empty loss set")
  {
    congestion.on_packets_lost({}, at(100ms), settled_rtt(), 25ms, std::nullopt);
    CHECK(congestion.window() == start);
  }
}
TEST_CASE("the pacer lets a burst out and then meters the rest")
{
  // RFC 9002 section 7.7. The window says how much may be outstanding; the
  // pacer says how fast. Handing a whole window over at once is the burst that
  // overflows the queue at the narrowest hop even when the path could have
  // carried the average.
  pacer_t pacer(datagram);
  const auto window = initial_congestion_window(datagram);
  constexpr auto rtt = 100ms;

  std::size_t burst = 0;
  while (pacer.ready(at(0ns), window, rtt, datagram))
  {
    pacer.on_sent(at(0ns), datagram, window, rtt);
    burst += datagram;
    REQUIRE(burst <= window * 2);
  }
  // Section 7.2: the burst is bounded by the initial window.
  CHECK(burst >= window - datagram);
  CHECK(burst <= window);
}

TEST_CASE("the pacer says when to come back")
{
  pacer_t pacer(datagram);
  const auto window = initial_congestion_window(datagram);
  constexpr auto rtt = 100ms;

  while (pacer.ready(at(0ns), window, rtt, datagram))
  {
    pacer.on_sent(at(0ns), datagram, window, rtt);
  }
  auto departure = pacer.next_departure(at(0ns), window, rtt, datagram);
  REQUIRE(departure.has_value());
  CHECK(*departure > at(0ns));

  // At a rate of 1.25 * window per round trip, a further datagram is due well
  // inside one -- otherwise the window would go unused.
  CHECK(*departure - at(0ns) < rtt);
  CHECK(pacer.ready(*departure, window, rtt, datagram));
}

TEST_CASE("an idle connection does not bank an unlimited burst")
{
  // The whole point is to bound what leaves at once, so time spent quiet must
  // not turn into credit that is spent in one go.
  pacer_t pacer(datagram);
  const auto window = initial_congestion_window(datagram);
  constexpr auto rtt = 10ms;

  while (pacer.ready(at(0ns), window, rtt, datagram))
  {
    pacer.on_sent(at(0ns), datagram, window, rtt);
  }

  std::size_t after_idle = 0;
  const auto later = at(60s);
  while (pacer.ready(later, window, rtt, datagram))
  {
    pacer.on_sent(later, datagram, window, rtt);
    after_idle += datagram;
    REQUIRE(after_idle <= window * 2);
  }
  CHECK(after_idle <= window);
}

TEST_CASE("a faster path is paced faster")
{
  const auto window = initial_congestion_window(datagram);
  pacer_t slow(datagram);
  pacer_t quick(datagram);

  while (slow.ready(at(0ns), window, 200ms, datagram))
  {
    slow.on_sent(at(0ns), datagram, window, 200ms);
  }
  while (quick.ready(at(0ns), window, 20ms, datagram))
  {
    quick.on_sent(at(0ns), datagram, window, 20ms);
  }

  auto slow_wait = slow.next_departure(at(0ns), window, 200ms, datagram);
  auto quick_wait = quick.next_departure(at(0ns), window, 20ms, datagram);
  REQUIRE(slow_wait.has_value());
  REQUIRE(quick_wait.has_value());
  CHECK(*quick_wait < *slow_wait);
}
}

TEST_SUITE("quic hystart")
{
// RFC 9406. Slow start otherwise ends only at a loss, which on a path that
// does not drop means it ends long after the window passed what the path can
// carry -- and everything past that point is queue the connection then pays
// for. Watching the round trip time ends it at the right place instead.

// A round is one round trip, and what makes it one is that the next flight is
// already on the wire while the last one is being acknowledged. Sending a
// flight and then draining it before sending the next would put a single
// packet in each round, which is not what a sender does and not what the
// algorithm is measuring.
struct pipeline_t
{
  static constexpr int flight = 12;
  congestion_control_t &control;
  std::uint64_t sent = 0;
  std::uint64_t acked = 0;

  void send()
  {
    for (int i = 0; i < flight; ++i)
    {
      control.on_packet_sent(sent++);
    }
  }

  void round(std::chrono::nanoseconds rtt)
  {
    send();
    for (int i = 0; i < flight; ++i)
    {
      control.on_rtt_sample(rtt);
      control.on_packet_acked(packet(acked, at(0ns)));
      control.on_ack_round_progress(acked);
      ++acked;
    }
  }
};

TEST_CASE("a round trip time that climbs ends slow start without a loss")
{
  congestion_control_t control(datagram);
  CHECK(control.hystart_phase() == hystart_phase_t::slow_start);

  pipeline_t pipe{control};
  pipe.send();
  // A steady path. Nothing here should be mistaken for a queue.
  for (int i = 0; i < 3; ++i)
  {
    pipe.round(20ms);
  }
  CHECK(control.hystart_phase() == hystart_phase_t::slow_start);
  CHECK(control.in_slow_start());

  // The minimum of this round rises well past an eighth of the last one, which
  // is a queue filling rather than jitter.
  pipe.round(40ms);
  CHECK(control.hystart_phase() == hystart_phase_t::conservative);

  // Confirmed over the following rounds, so slow start ends at the window that
  // found the queue rather than at the one that overflowed it.
  const auto window_at_detection = control.window();
  for (int i = 0; i < 6; ++i)
  {
    pipe.round(40ms);
  }
  CHECK(control.hystart_phase() == hystart_phase_t::finished);
  CHECK_FALSE(control.in_slow_start());
  CHECK(control.slow_start_threshold() < (std::numeric_limits<std::size_t>::max)());
  CHECK(control.window() >= window_at_detection);
}

TEST_CASE("a rise that does not hold puts slow start back")
{
  congestion_control_t control(datagram);
  pipeline_t pipe{control};
  pipe.send();
  for (int i = 0; i < 3; ++i)
  {
    pipe.round(20ms);
  }
  pipe.round(40ms);
  REQUIRE(control.hystart_phase() == hystart_phase_t::conservative);

  // One slow round is not a queue. Dropping back below the baseline says so,
  // and full growth resumes rather than the connection giving up its slow
  // start over a transient.
  pipe.round(18ms);
  CHECK(control.hystart_phase() == hystart_phase_t::slow_start);
  CHECK(control.in_slow_start());
}

TEST_CASE("a rise that keeps climbing does not wait out the confirmation")
{
  congestion_control_t control(datagram);
  pipeline_t pipe{control};
  pipe.send();
  for (int i = 0; i < 3; ++i)
  {
    pipe.round(20ms);
  }
  pipe.round(40ms);
  REQUIRE(control.hystart_phase() == hystart_phase_t::conservative);

  // The queue did not stop at the depth that was noticed -- another round
  // trip's worth of it arrived. That is what the confirmation phase is there
  // to establish, so serving out its remaining rounds would only add to the
  // queue being complained about. Slow start ends here rather than three
  // rounds later.
  pipe.round(60ms);
  CHECK(control.hystart_phase() == hystart_phase_t::finished);
  CHECK_FALSE(control.in_slow_start());
}

TEST_CASE("growth is a quarter of slow start while a rise is being confirmed")
{
  congestion_control_t control(datagram);
  pipeline_t pipe{control};
  pipe.send();
  for (int i = 0; i < 3; ++i)
  {
    pipe.round(20ms);
  }
  pipe.round(40ms);
  REQUIRE(control.hystart_phase() == hystart_phase_t::conservative);

  const auto before = control.window();
  pipe.round(40ms);
  const auto growth = control.window() - before;
  // A dozen datagrams acknowledged, where slow start would have added all
  // twelve.
  CHECK(growth > 0);
  CHECK(growth < pipeline_t::flight * datagram);
}

TEST_CASE("a loss ends the question")
{
  congestion_control_t control(datagram);
  pipeline_t pipe{control};
  pipe.send();
  for (int i = 0; i < 3; ++i)
  {
    pipe.round(20ms);
  }
  pipe.round(40ms);
  REQUIRE(control.hystart_phase() == hystart_phase_t::conservative);

  // Slow start is over for the ordinary reason, so there is nothing left to
  // decide and the round trip time stops being consulted.
  rtt_estimator_t rtt;
  control.on_packets_lost({packet(pipe.sent, at(0ns))}, at(1s), rtt, 25ms, std::optional<vio::tick_t>(at(0ns)));
  CHECK(control.hystart_phase() == hystart_phase_t::finished);
}
}

TEST_SUITE("quic delivery rate")
{
using vio::quic::delivery_rate_estimator_t;

// The estimator driven by hand, against a path whose rate is known because the
// test chose it: packets sent back to back and acknowledged as the path
// delivers them, one round trip later.
TEST_CASE("a steady path reports the rate it is delivering at")
{
  delivery_rate_estimator_t estimator;
  constexpr std::size_t packet = 1200;
  constexpr auto delay = 20ms;
  // 1200 bytes every 40 microseconds is 30 MB/s.
  constexpr auto spacing = 40us;

  std::vector<delivery_rate_estimator_t::stamp_t> stamps;
  std::vector<vio::tick_t> sent_at;
  auto now = at(0ns);
  for (int i = 0; i < 500; ++i)
  {
    stamps.push_back(estimator.on_packet_sent(now, i == 0, static_cast<std::uint64_t>(i)));
    sent_at.push_back(now);
    now = now + std::chrono::nanoseconds(spacing);
  }

  auto ack_time = at(0ns) + std::chrono::nanoseconds(delay);
  for (std::size_t i = 0; i < stamps.size(); ++i)
  {
    estimator.on_packet_acked(stamps[i], sent_at[i], packet, ack_time, i);
    ack_time = ack_time + std::chrono::nanoseconds(spacing);
  }

  auto sample = estimator.take(delay);
  REQUIRE(sample.has_value());
  CHECK_FALSE(sample->app_limited);
  CAPTURE(sample->rate);
  CHECK(sample->rate > 28000000);
  CHECK(sample->rate < 32000000);
  CHECK(estimator.peak() == sample->rate);
}

TEST_CASE("a sample shorter than a round trip is refused")
{
  delivery_rate_estimator_t estimator;
  auto now = at(0ns);
  const auto stamp = estimator.on_packet_sent(now, true, 0);
  // This measures one burst arriving, not what the path carries; reporting it
  // would be an enormous invented rate.
  estimator.on_packet_acked(stamp, now, 1200, now + std::chrono::nanoseconds(1us), 0);
  CHECK_FALSE(estimator.take(20ms).has_value());
  CHECK(estimator.peak() == 0);
}

TEST_CASE("a rate the sender limited does not become the path's peak")
{
  delivery_rate_estimator_t estimator;
  constexpr auto delay = 20ms;
  auto now = at(0ns);

  estimator.set_app_limited();
  std::vector<delivery_rate_estimator_t::stamp_t> stamps;
  std::vector<vio::tick_t> sent_at;
  for (int i = 0; i < 20; ++i)
  {
    stamps.push_back(estimator.on_packet_sent(now, i == 0, static_cast<std::uint64_t>(i)));
    sent_at.push_back(now);
    now = now + std::chrono::nanoseconds(2ms);
  }
  auto ack_time = at(0ns) + std::chrono::nanoseconds(delay);
  for (std::size_t i = 0; i < stamps.size(); ++i)
  {
    estimator.on_packet_acked(stamps[i], sent_at[i], 1200, ack_time, i);
    ack_time = ack_time + std::chrono::nanoseconds(2ms);
  }

  auto sample = estimator.take(delay);
  REQUIRE(sample.has_value());
  CHECK(sample->app_limited);
  CHECK(sample->rate > 0);
  // Reported, but never believed as a statement about the path.
  CHECK(estimator.peak() == 0);
}

// The point of a windowed maximum rather than an all-time one: a path that
// slows down has to be believed. An estimate that only ever grows would hold
// the connection to a rate the path stopped carrying.
TEST_CASE("a path that slows down is eventually believed")
{
  delivery_rate_estimator_t estimator;
  constexpr auto delay = 20ms;
  std::uint64_t packet_number = 0;

  // Drive one round of traffic at a chosen spacing and read the filter back.
  const auto run_round = [&](std::chrono::nanoseconds spacing, vio::tick_t start)
  {
    std::vector<delivery_rate_estimator_t::stamp_t> stamps;
    std::vector<vio::tick_t> sent_at;
    auto now = start;
    const auto first = packet_number;
    for (int i = 0; i < 60; ++i)
    {
      stamps.push_back(estimator.on_packet_sent(now, false, packet_number++));
      sent_at.push_back(now);
      now = now + spacing;
    }
    auto ack_time = start + std::chrono::nanoseconds(delay);
    for (std::size_t i = 0; i < stamps.size(); ++i)
    {
      estimator.on_packet_acked(stamps[i], sent_at[i], 1200, ack_time, first + i);
      ack_time = ack_time + spacing;
    }
    (void)estimator.take(delay);
    return now;
  };

  // Fast to begin with. The rate a single round can show is bounded by the
  // propagation delay it is measured across, so this is well under the 30 MB/s
  // the spacing alone would suggest -- what matters here is that it is the
  // larger of the two rates, and that the filter lets go of it.
  auto now = at(0ns);
  now = run_round(std::chrono::nanoseconds(40us), now);
  const auto fast = estimator.peak();
  CHECK(fast > 3000000);

  // Then the path drops to a fifth of that and stays there. The filter holds
  // the old maximum for its window and then lets it go.
  for (int round = 0; round < 14; ++round)
  {
    now = run_round(std::chrono::nanoseconds(200us), now + std::chrono::nanoseconds(delay));
  }

  CAPTURE(fast);
  CAPTURE(estimator.peak());
  CHECK(estimator.peak() < fast);
  CHECK(estimator.peak() > 1500000);
  CHECK(estimator.peak() < 3000000);
}

// The interval is the larger of how long the acknowledgements took to come back
// and how long the packets took to go out. Without that, a path that holds
// acknowledgements and releases them together reads back as infinitely fast.
TEST_CASE("acknowledgements bunched by the path do not inflate the rate")
{
  delivery_rate_estimator_t estimator;
  constexpr auto delay = 20ms;
  auto now = at(0ns);

  std::vector<delivery_rate_estimator_t::stamp_t> stamps;
  std::vector<vio::tick_t> sent_at;
  // One packet a millisecond left this sender: about 1.2 MB/s.
  for (int i = 0; i < 40; ++i)
  {
    stamps.push_back(estimator.on_packet_sent(now, i == 0, static_cast<std::uint64_t>(i)));
    sent_at.push_back(now);
    now = now + std::chrono::nanoseconds(1ms);
  }
  const auto ack_time = at(0ns) + std::chrono::nanoseconds(delay + 40ms);
  for (std::size_t i = 0; i < stamps.size(); ++i)
  {
    estimator.on_packet_acked(stamps[i], sent_at[i], 1200, ack_time, i);
  }

  auto sample = estimator.take(delay);
  REQUIRE(sample.has_value());
  CAPTURE(sample->rate);
  CHECK(sample->rate < 2000000);
}
}

TEST_SUITE("quic cubic")
{
using vio::quic::congestion_algorithm_t;
using vio::quic::cubic_constants_t;

// A controller that has grown a real window and then lost it -- which is the
// situation the two algorithms actually differ in. Losing the *initial* window
// tells you nothing: with nothing above it to climb back to, CUBIC's curve has
// no work to do and the flow runs on its Reno-friendly floor, which is
// deliberately slower than Reno.
congestion_control_t after_losing_a_large_window(congestion_algorithm_t algorithm, vio::tick_t now, std::size_t target)
{
  congestion_control_t control(datagram, algorithm);
  rtt_estimator_t rtt;
  std::uint64_t number = 0;

  // Slow start doubles per round trip until the window is worth losing.
  while (control.window() < target)
  {
    const auto in_window = (std::max<std::size_t>)(1, control.window() / datagram);
    for (std::size_t i = 0; i < in_window; ++i)
    {
      control.on_packet_sent(number);
      control.on_packet_acked(packet(number, now), now, 20ms);
      ++number;
    }
    now = now + std::chrono::nanoseconds(20ms);
  }

  control.on_packet_sent(number);
  control.on_packets_lost({packet(number, now)}, now, rtt, 25ms, std::optional<vio::tick_t>(now));
  return control;
}

TEST_CASE("a congestion event leaves CUBIC more window than NewReno")
{
  const auto now = at(0ns);
  // Section 4.6: CUBIC keeps 0.7 of the window where NewReno keeps half.
  congestion_control_t reno(datagram, congestion_algorithm_t::new_reno);
  congestion_control_t cubic(datagram, congestion_algorithm_t::cubic);
  rtt_estimator_t rtt;

  const auto before = reno.window();
  REQUIRE(cubic.window() == before);

  reno.on_packet_sent(0);
  cubic.on_packet_sent(0);
  reno.on_packets_lost({packet(0, now)}, now, rtt, 25ms, std::optional<vio::tick_t>(now));
  cubic.on_packets_lost({packet(0, now)}, now, rtt, 25ms, std::optional<vio::tick_t>(now));

  CAPTURE(reno.window());
  CAPTURE(cubic.window());
  CHECK(cubic.window() > reno.window());
  // And it is the fraction the RFC names, within the rounding to whole bytes.
  const auto expected = static_cast<std::size_t>(static_cast<double>(before) * cubic_constants_t::beta);
  CHECK(cubic.window() >= expected - datagram);
  CHECK(cubic.window() <= expected + datagram);
}

TEST_CASE("CUBIC climbs back toward the window the path refused")
{
  auto now = at(0ns);
  auto control = after_losing_a_large_window(congestion_algorithm_t::cubic, now, 150000);
  const auto after_loss = control.window();

  // A round trip of acknowledgements, repeated. The curve is anchored at the
  // window the loss happened at, so growth accelerates as it returns there.
  std::uint64_t number = 1;
  for (int round = 0; round < 12; ++round)
  {
    for (int i = 0; i < 20; ++i)
    {
      control.on_packet_sent(number);
      control.on_packet_acked(packet(number, now), now, 20ms);
      ++number;
    }
    now = now + std::chrono::nanoseconds(20ms);
  }

  CAPTURE(after_loss);
  CAPTURE(control.window());
  CHECK(control.window() > after_loss);
}

// The point of choosing CUBIC, and the reason it exists: its growth is a
// function of *time*, where Reno's is a function of round trips. On a short
// path Reno's one datagram per round trip is already brisk and CUBIC is the
// more cautious of the two -- deliberately, since it also gives up less on a
// loss. It is on long paths, where a round trip is expensive and Reno crawls,
// that the curve pulls away. That is the case worth testing, because it is the
// case the algorithm was written for.
//
// A round here is a real round trip: the connection acknowledges a window's
// worth and the clock moves on by one RTT. Acknowledging a fixed number of
// packets per round instead would hand whichever algorithm grows per
// acknowledgement an advantage that has nothing to do with either algorithm.
std::size_t run_rounds(congestion_control_t &control, int rounds, std::chrono::nanoseconds rtt, vio::tick_t now)
{
  std::uint64_t number = 1;
  for (int round = 0; round < rounds; ++round)
  {
    const auto in_window = (std::max<std::size_t>)(1, control.window() / datagram);
    for (std::size_t i = 0; i < in_window; ++i)
    {
      control.on_packet_sent(number);
      control.on_packet_acked(packet(number, now), now, rtt);
      ++number;
    }
    now = now + rtt;
  }
  return control.window();
}

TEST_CASE("on a long path CUBIC takes back a lost window far faster than NewReno")
{
  const auto now = at(0ns);
  auto reno = after_losing_a_large_window(congestion_algorithm_t::new_reno, now, 150000);
  auto cubic = after_losing_a_large_window(congestion_algorithm_t::cubic, now, 150000);

  // Fifteen seconds of a 200ms path: seventy-five round trips, which is not
  // many, and exactly the point.
  const auto reno_window = run_rounds(reno, 75, 200ms, now);
  const auto cubic_window = run_rounds(cubic, 75, 200ms, now);

  CAPTURE(reno_window);
  CAPTURE(cubic_window);
  CHECK(cubic_window > reno_window);
}

TEST_CASE("on a short path CUBIC is the more cautious of the two")
{
  const auto now = at(0ns);
  auto reno = after_losing_a_large_window(congestion_algorithm_t::new_reno, now, 150000);
  auto cubic = after_losing_a_large_window(congestion_algorithm_t::cubic, now, 150000);

  // The same fifteen seconds over a 20ms path is 750 round trips, and Reno
  // spends every one of them adding a datagram.
  const auto reno_window = run_rounds(reno, 750, 20ms, now);
  const auto cubic_window = run_rounds(cubic, 750, 20ms, now);

  CAPTURE(reno_window);
  CAPTURE(cubic_window);
  CHECK(cubic_window < reno_window);
}

TEST_CASE("a flow that never reached its old maximum aims lower next time")
{
  // Section 4.7, fast convergence. Two congestion events, the second at a
  // smaller window than the first: the target comes down rather than staying
  // where a flow with the path to itself would have left it.
  auto now = at(0ns);
  congestion_control_t control(datagram, congestion_algorithm_t::cubic);
  rtt_estimator_t rtt;

  control.on_packet_sent(0);
  control.on_packets_lost({packet(0, now)}, now, rtt, 25ms, std::optional<vio::tick_t>(now));
  const auto first = control.window();

  now = now + std::chrono::nanoseconds(1s);
  control.on_packet_sent(1);
  control.on_packets_lost({packet(1, now)}, now, rtt, 25ms, std::optional<vio::tick_t>(now));
  const auto second = control.window();

  CAPTURE(first);
  CAPTURE(second);
  CHECK(second < first);
}

TEST_CASE("NewReno is what a connection gets unless it asks otherwise")
{
  congestion_control_t control(datagram);
  CHECK(control.algorithm() == congestion_algorithm_t::new_reno);
}
}
