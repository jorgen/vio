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
