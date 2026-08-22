#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <ostream>
#include <vector>
#include <doctest/doctest.h>
#include <vio/quic/ack_tracker.h>
#include <vio/quic/loss_recovery.h>

// RFC 9002 sections 5 and 6. The arithmetic is transcribed from the appendix A
// pseudocode, so the tests compute the expected values by hand from the same
// formulas rather than from what the code happens to produce.

namespace
{
using namespace vio::quic;
using namespace std::chrono_literals;

vio::tick_t at(std::chrono::nanoseconds offset)
{
  return vio::tick_t::from_nanoseconds(offset);
}

sent_packet_t packet(std::uint64_t number, vio::tick_t sent, bool ack_eliciting = true, std::size_t size = 1200)
{
  sent_packet_t out;
  out.packet_number = number;
  out.time_sent = sent;
  out.ack_eliciting = ack_eliciting;
  out.in_flight = ack_eliciting;
  out.size = size;
  out.frames.push_back(sent_frame_t{.kind = frame_kind_t::crypto, .offset = number * 100, .length = 100});
  return out;
}

// An ACK frame as it would arrive off the wire, built through the same writer
// the sender uses so the test exercises the real encoding.
struct ack_builder_t
{
  std::array<std::uint8_t, 512> scratch = {};
  ack_range_writer_t writer{scratch};
  frame_t frame;

  ack_builder_t(std::uint64_t largest, std::uint64_t first_range, std::uint64_t delay = 0)
  {
    frame.kind = frame_kind_t::ack;
    frame.largest_acknowledged = largest;
    frame.first_ack_range = first_range;
    frame.ack_delay = delay;
  }

  void add(std::uint64_t gap, std::uint64_t length)
  {
    REQUIRE(writer.write(ack_range_t{.gap = gap, .length = length}));
  }

  const frame_t &build()
  {
    frame.ack_range_count = writer.count();
    frame.ack_ranges = writer.bytes();
    return frame;
  }
};

std::vector<std::uint64_t> numbers(const std::vector<sent_packet_t> &packets)
{
  std::vector<std::uint64_t> out;
  out.reserve(packets.size());
  for (const auto &entry : packets)
  {
    out.push_back(entry.packet_number);
  }
  std::sort(out.begin(), out.end());
  return out;
}
} // namespace

TEST_SUITE("quic rtt estimator")
{
TEST_CASE("the first sample seeds the estimate outright")
{
  rtt_estimator_t rtt;
  CHECK_FALSE(rtt.has_sample());
  // Before any sample, section 6.2.2 assumes 333ms.
  CHECK(rtt.smoothed() == initial_rtt);
  CHECK(rtt.variation() == initial_rtt / 2);

  rtt.on_rtt_sample(100ms, 0ns, false, 25ms);
  CHECK(rtt.has_sample());
  CHECK(rtt.latest() == std::chrono::nanoseconds(100ms));
  CHECK(rtt.minimum() == std::chrono::nanoseconds(100ms));
  CHECK(rtt.smoothed() == std::chrono::nanoseconds(100ms));
  CHECK(rtt.variation() == std::chrono::nanoseconds(50ms));
}

TEST_CASE("subsequent samples follow the appendix A.7 arithmetic")
{
  rtt_estimator_t rtt;
  rtt.on_rtt_sample(100ms, 0ns, false, 25ms);
  rtt.on_rtt_sample(200ms, 0ns, false, 25ms);

  // rttvar uses the previous smoothed_rtt, then smoothed_rtt moves:
  //   rttvar   = 3/4 * 50 + 1/4 * |100 - 200| = 62.5ms
  //   smoothed = 7/8 * 100 + 1/8 * 200        = 112.5ms
  CHECK(rtt.variation() == std::chrono::nanoseconds(62500us));
  CHECK(rtt.smoothed() == std::chrono::nanoseconds(112500us));
  CHECK(rtt.minimum() == std::chrono::nanoseconds(100ms));

  SUBCASE("a faster sample lowers the minimum but not below itself")
  {
    rtt.on_rtt_sample(80ms, 0ns, false, 25ms);
    CHECK(rtt.minimum() == std::chrono::nanoseconds(80ms));
    CHECK(rtt.latest() == std::chrono::nanoseconds(80ms));
  }
}

TEST_CASE("acknowledgment delay is removed only when it is plausible")
{
  SUBCASE("it is subtracted when the sample is at least min_rtt plus the delay")
  {
    rtt_estimator_t rtt;
    rtt.on_rtt_sample(100ms, 0ns, false, 25ms);
    rtt.on_rtt_sample(150ms, 20ms, false, 25ms);
    // 150 >= 100 + 20, so adjusted = 130.
    // rttvar   = 3/4 * 50 + 1/4 * |100 - 130| = 45ms
    // smoothed = 7/8 * 100 + 1/8 * 130        = 103.75ms
    CHECK(rtt.variation() == std::chrono::nanoseconds(45ms));
    CHECK(rtt.smoothed() == std::chrono::nanoseconds(103750us));
  }

  SUBCASE("it is ignored when subtracting it would go below min_rtt")
  {
    rtt_estimator_t rtt;
    rtt.on_rtt_sample(100ms, 0ns, false, 25ms);
    rtt.on_rtt_sample(105ms, 20ms, false, 25ms);
    // 105 < 100 + 20, so adjusted stays 105.
    // rttvar   = 3/4 * 50 + 1/4 * 5   = 38.75ms
    // smoothed = 7/8 * 100 + 1/8 * 105 = 100.625ms
    CHECK(rtt.variation() == std::chrono::nanoseconds(38750us));
    CHECK(rtt.smoothed() == std::chrono::nanoseconds(100625us));
  }

  SUBCASE("the peer's claimed delay is capped only once the handshake is confirmed")
  {
    rtt_estimator_t before;
    before.on_rtt_sample(100ms, 0ns, true, 25ms);
    before.on_rtt_sample(200ms, 90ms, false, 25ms);

    rtt_estimator_t after;
    after.on_rtt_sample(100ms, 0ns, true, 25ms);
    after.on_rtt_sample(200ms, 90ms, true, 25ms);

    // Unconfirmed the whole 90ms comes off; confirmed only 25ms does, so the
    // confirmed estimate is the larger of the two.
    CHECK(after.smoothed() > before.smoothed());
  }

  SUBCASE("min_rtt itself never has the delay removed")
  {
    rtt_estimator_t rtt;
    rtt.on_rtt_sample(100ms, 0ns, false, 25ms);
    rtt.on_rtt_sample(140ms, 30ms, false, 25ms);
    // The adjusted value is 110ms, but min_rtt tracks the raw 140 against 100.
    CHECK(rtt.minimum() == std::chrono::nanoseconds(100ms));
  }
}

TEST_CASE("the derived timers follow sections 6.1.2 and 6.2.1")
{
  rtt_estimator_t rtt;
  rtt.on_rtt_sample(80ms, 0ns, false, 25ms);
  // smoothed = latest = 80ms, rttvar = 40ms.
  CHECK(rtt.pto_base() == std::chrono::nanoseconds(80ms + 160ms));
  // loss_delay = 9/8 * max(latest, smoothed) = 90ms.
  CHECK(rtt.loss_delay() == std::chrono::nanoseconds(90ms));

  SUBCASE("both are floored at the granularity")
  {
    rtt_estimator_t tiny;
    tiny.on_rtt_sample(1ns, 0ns, false, 25ms);
    CHECK(tiny.loss_delay() == loss_granularity);
    CHECK(tiny.pto_base() >= loss_granularity);
  }
}
}

TEST_SUITE("quic loss recovery")
{
TEST_CASE("an ACK acknowledges exactly the packets it names")
{
  loss_recovery_t recovery;
  const recovery_context_t context;

  for (std::uint64_t n = 0; n <= 10; ++n)
  {
    recovery.on_packet_sent(pn_space_t::initial, packet(n, at(0ns)));
  }
  CHECK(recovery.unacknowledged(pn_space_t::initial) == 11);
  CHECK(recovery.bytes_in_flight() == 11 * 1200);

  // Acknowledge 8..10, then 4..5, then 0..1.
  ack_builder_t builder(10, 2);
  builder.add(1, 1);
  builder.add(1, 1);
  auto outcome = recovery.on_ack_received(pn_space_t::initial, builder.build(), at(50ms), context);

  CHECK(numbers(outcome.acknowledged) == std::vector<std::uint64_t>{0, 1, 4, 5, 8, 9, 10});
  // Everything the ACK skipped is at least three packets behind the largest,
  // so the same frame that acknowledges seven packets declares four lost.
  CHECK(numbers(outcome.lost) == std::vector<std::uint64_t>{2, 3, 6, 7});
  CHECK(recovery.bytes_in_flight() == 0);

  SUBCASE("and the ranges match what the tracker would have built for them")
  {
    // The same set, run through the receiver's encoder, must acknowledge the
    // same packets when read by the sender.
    ack_tracker_t tracker;
    for (std::uint64_t n : {0, 1, 4, 5, 8, 9, 10})
    {
      tracker.on_packet_received(n, true, at(0ns));
    }
    auto built = tracker.build_ack(at(0ns));
    REQUIRE(built.has_value());

    loss_recovery_t mirror;
    for (std::uint64_t n = 0; n <= 10; ++n)
    {
      mirror.on_packet_sent(pn_space_t::initial, packet(n, at(0ns)));
    }
    std::array<std::uint8_t, 512> scratch = {};
    ack_range_writer_t writer(scratch);
    for (const auto &range : built->ranges)
    {
      REQUIRE(writer.write(range));
    }
    frame_t frame;
    frame.kind = frame_kind_t::ack;
    frame.largest_acknowledged = built->largest_acknowledged;
    frame.first_ack_range = built->first_ack_range;
    frame.ack_range_count = writer.count();
    frame.ack_ranges = writer.bytes();

    auto mirrored = mirror.on_ack_received(pn_space_t::initial, frame, at(50ms), context);
    CHECK(numbers(mirrored.acknowledged) == std::vector<std::uint64_t>{0, 1, 4, 5, 8, 9, 10});
  }
}

TEST_CASE("acknowledging a packet that was never sent changes nothing")
{
  loss_recovery_t recovery;
  const recovery_context_t context;
  recovery.on_packet_sent(pn_space_t::initial, packet(0, at(0ns)));

  ack_builder_t builder(99, 0);
  auto outcome = recovery.on_ack_received(pn_space_t::initial, builder.build(), at(50ms), context);
  CHECK(outcome.acknowledged.empty());
  CHECK_FALSE(outcome.rtt_updated);
}

TEST_CASE("a packet threshold gap is loss")
{
  loss_recovery_t recovery;
  const recovery_context_t context;
  for (std::uint64_t n = 0; n <= 4; ++n)
  {
    recovery.on_packet_sent(pn_space_t::initial, packet(n, at(0ns)));
  }

  // Acknowledging 3 puts 0 three packets behind the largest.
  ack_builder_t builder(3, 0);
  auto outcome = recovery.on_ack_received(pn_space_t::initial, builder.build(), at(1ms), context);
  CHECK(numbers(outcome.acknowledged) == std::vector<std::uint64_t>{3});
  CHECK(numbers(outcome.lost) == std::vector<std::uint64_t>{0});

  SUBCASE("packets closer than the threshold are not lost yet")
  {
    // 1 and 2 remain, along with 4 which is above the largest acknowledged.
    CHECK(recovery.unacknowledged(pn_space_t::initial) == 3);
  }
}

TEST_CASE("a packet older than the loss delay is loss")
{
  loss_recovery_t recovery;
  const recovery_context_t context;

  recovery.on_packet_sent(pn_space_t::initial, packet(0, at(0ns)));
  recovery.on_packet_sent(pn_space_t::initial, packet(1, at(200ms)));

  // The first ACK establishes an RTT of 100ms, so loss_delay is 112.5ms.
  ack_builder_t builder(1, 0);
  auto outcome = recovery.on_ack_received(pn_space_t::initial, builder.build(), at(300ms), context);
  CHECK(outcome.rtt_updated);
  CHECK(recovery.rtt().latest() == std::chrono::nanoseconds(100ms));

  // Packet 0 was sent at 0 and it is now 300ms: well past 112.5ms.
  CHECK(numbers(outcome.lost) == std::vector<std::uint64_t>{0});
}

TEST_CASE("a packet not yet lost sets a deadline for when it will be")
{
  loss_recovery_t recovery;
  const recovery_context_t context;

  recovery.on_packet_sent(pn_space_t::initial, packet(0, at(100ms)));
  recovery.on_packet_sent(pn_space_t::initial, packet(1, at(100ms)));
  recovery.on_packet_sent(pn_space_t::initial, packet(2, at(100ms)));

  ack_builder_t builder(2, 0);
  auto outcome = recovery.on_ack_received(pn_space_t::initial, builder.build(), at(200ms), context);
  // 0 and 1 are within the packet threshold and were sent recently.
  CHECK(outcome.lost.empty());

  // loss_delay for a 100ms sample is 112.5ms, so they turn into losses at
  // 100ms + 112.5ms.
  auto timer = recovery.loss_detection_timer(at(200ms), context);
  REQUIRE(timer.has_value());
  CHECK(*timer == at(212500us));

  SUBCASE("and the timeout reports them as lost without a probe")
  {
    auto outcome = recovery.on_loss_detection_timeout(at(213ms), context);
    CHECK_FALSE(outcome.probe_space.has_value());
    CHECK(outcome.loss_space == pn_space_t::initial);
    CHECK(numbers(outcome.lost) == std::vector<std::uint64_t>{0, 1});
  }
}

TEST_CASE("the RTT sample comes only from a newly acknowledged largest")
{
  loss_recovery_t recovery;
  const recovery_context_t context;
  recovery.on_packet_sent(pn_space_t::initial, packet(0, at(0ns)));
  recovery.on_packet_sent(pn_space_t::initial, packet(1, at(10ms)));

  ack_builder_t first(1, 1);
  auto outcome = recovery.on_ack_received(pn_space_t::initial, first.build(), at(60ms), context);
  CHECK(outcome.rtt_updated);
  CHECK(recovery.rtt().latest() == std::chrono::nanoseconds(50ms));

  SUBCASE("a repeat of the same ACK reports no new round trip")
  {
    ack_builder_t again(1, 1);
    auto repeat = recovery.on_ack_received(pn_space_t::initial, again.build(), at(500ms), context);
    CHECK_FALSE(repeat.rtt_updated);
    CHECK(recovery.rtt().latest() == std::chrono::nanoseconds(50ms));
  }

  SUBCASE("a packet that was not ack-eliciting gives no sample either")
  {
    loss_recovery_t other;
    other.on_packet_sent(pn_space_t::application, packet(0, at(0ns), false));
    ack_builder_t builder(0, 0);
    auto result = other.on_ack_received(pn_space_t::application, builder.build(), at(80ms), context);
    CHECK(result.acknowledged.size() == 1);
    CHECK_FALSE(result.rtt_updated);
    CHECK_FALSE(other.rtt().has_sample());
  }
}

TEST_CASE("the peer's ack delay is scaled by its exponent")
{
  loss_recovery_t recovery;
  recovery_context_t context;
  context.ack_delay_exponent = 3;
  context.handshake_confirmed = true;
  context.max_ack_delay = 1s;

  recovery.on_packet_sent(pn_space_t::application, packet(0, at(0ns)));
  recovery.on_packet_sent(pn_space_t::application, packet(1, at(0ns)));

  ack_builder_t first(0, 0);
  auto seed = recovery.on_ack_received(pn_space_t::application, first.build(), at(100ms), context);
  CHECK(seed.rtt_updated);

  // An encoded delay of 2500 with exponent 3 is 20000us, which is 20ms.
  ack_builder_t second(1, 0, 2500);
  auto outcome = recovery.on_ack_received(pn_space_t::application, second.build(), at(200ms), context);
  REQUIRE(outcome.rtt_updated);
  CHECK(recovery.rtt().latest() == std::chrono::nanoseconds(200ms));
  // adjusted = 200 - 20 = 180ms, and 200 >= min(100) + 20 so it applies.
  // rttvar   = 3/4 * 50 + 1/4 * |100 - 180| = 57.5ms
  // smoothed = 7/8 * 100 + 1/8 * 180        = 110ms
  CHECK(recovery.rtt().smoothed() == std::chrono::nanoseconds(110ms));
  CHECK(recovery.rtt().variation() == std::chrono::nanoseconds(57500us));
}

TEST_CASE("the PTO backs off and resets")
{
  loss_recovery_t recovery;
  recovery_context_t context;
  context.peer_completed_address_validation = true;

  recovery.on_packet_sent(pn_space_t::initial, packet(0, at(0ns)));
  CHECK(recovery.pto_count() == 0);

  // No RTT sample yet, so the base is the assumed 333ms plus 4 * 166.5ms.
  const auto base = recovery.rtt().pto_base();
  auto timer = recovery.loss_detection_timer(at(0ns), context);
  REQUIRE(timer.has_value());
  CHECK(*timer == at(base));

  auto outcome = recovery.on_loss_detection_timeout(at(base), context);
  REQUIRE(outcome.probe_space.has_value());
  CHECK(*outcome.probe_space == pn_space_t::initial);
  CHECK(recovery.pto_count() == 1);
  CHECK(outcome.lost.empty());

  auto doubled = recovery.loss_detection_timer(at(base), context);
  REQUIRE(doubled.has_value());
  CHECK(*doubled == at(base * 2));

  SUBCASE("an acknowledgement clears the backoff")
  {
    ack_builder_t builder(0, 0);
    auto outcome = recovery.on_ack_received(pn_space_t::initial, builder.build(), at(base + 10ms), context);
    CHECK(outcome.acknowledged.size() == 1);
    CHECK(recovery.pto_count() == 0);
  }
}

TEST_CASE("the application space is not probed before the handshake is confirmed")
{
  loss_recovery_t recovery;
  recovery_context_t context;
  context.handshake_confirmed = false;
  context.max_ack_delay = 25ms;

  recovery.on_packet_sent(pn_space_t::application, packet(0, at(0ns)));
  auto space = recovery.loss_detection_space(at(0ns), context);
  // Section 6.2.1: nothing to probe there yet.
  CHECK_FALSE(space.has_value());

  SUBCASE("and once confirmed its PTO includes max_ack_delay")
  {
    context.handshake_confirmed = true;
    auto timer = recovery.loss_detection_timer(at(0ns), context);
    REQUIRE(timer.has_value());
    CHECK(*timer == at(recovery.rtt().pto_base() + 25ms));
  }
}

TEST_CASE("a client with nothing in flight still probes to break a deadlock")
{
  loss_recovery_t recovery;
  recovery_context_t context;
  // A client that has sent everything it has but has not been validated.
  context.peer_completed_address_validation = false;
  context.has_handshake_keys = false;

  CHECK(recovery.bytes_in_flight() == 0);
  auto timer = recovery.loss_detection_timer(at(100ms), context);
  REQUIRE(timer.has_value());
  CHECK(*timer == at(100ms + recovery.rtt().pto_base()));
  CHECK(recovery.loss_detection_space(at(100ms), context) == pn_space_t::initial);

  SUBCASE("in the handshake space once those keys exist")
  {
    context.has_handshake_keys = true;
    CHECK(recovery.loss_detection_space(at(100ms), context) == pn_space_t::handshake);
  }

  SUBCASE("and not at all once the peer has validated the address")
  {
    context.peer_completed_address_validation = true;
    CHECK_FALSE(recovery.loss_detection_timer(at(100ms), context).has_value());
  }
}

TEST_CASE("discarding a space forgets its packets and keeps the RTT estimate")
{
  loss_recovery_t recovery;
  const recovery_context_t context;

  recovery.on_packet_sent(pn_space_t::initial, packet(0, at(0ns)));
  recovery.on_packet_sent(pn_space_t::initial, packet(1, at(0ns)));
  recovery.on_packet_sent(pn_space_t::handshake, packet(0, at(0ns)));

  ack_builder_t builder(1, 0);
  auto outcome = recovery.on_ack_received(pn_space_t::initial, builder.build(), at(100ms), context);
  REQUIRE(outcome.rtt_updated);
  const auto smoothed = recovery.rtt().smoothed();
  CHECK(recovery.bytes_in_flight() == 2 * 1200);

  recovery.discard_space(pn_space_t::initial);
  CHECK(recovery.unacknowledged(pn_space_t::initial) == 0);
  CHECK(recovery.bytes_in_flight() == 1200);
  // Section A.11: the path did not change, so neither does what is known
  // about it.
  CHECK(recovery.rtt().smoothed() == smoothed);

  SUBCASE("and nothing more is recorded there")
  {
    recovery.on_packet_sent(pn_space_t::initial, packet(2, at(0ns)));
    CHECK(recovery.unacknowledged(pn_space_t::initial) == 0);
    CHECK(recovery.bytes_in_flight() == 1200);
  }

  SUBCASE("while other spaces are untouched")
  {
    CHECK(recovery.unacknowledged(pn_space_t::handshake) == 1);
  }
}

TEST_CASE("what a packet meant survives its loss")
{
  loss_recovery_t recovery;
  const recovery_context_t context;

  sent_packet_t carrying = packet(0, at(0ns));
  carrying.frames.clear();
  carrying.frames.push_back(sent_frame_t{.kind = frame_kind_t::crypto, .offset = 4096, .length = 512});
  carrying.frames.push_back(sent_frame_t{.kind = frame_kind_t::max_data, .offset = 0, .length = 0});
  recovery.on_packet_sent(pn_space_t::handshake, std::move(carrying));
  for (std::uint64_t n = 1; n <= 4; ++n)
  {
    recovery.on_packet_sent(pn_space_t::handshake, packet(n, at(0ns)));
  }

  ack_builder_t builder(4, 0);
  auto outcome = recovery.on_ack_received(pn_space_t::handshake, builder.build(), at(10ms), context);
  REQUIRE(outcome.lost.size() >= 1);

  const auto &lost = outcome.lost.front();
  CHECK(lost.packet_number == 0);
  REQUIRE(lost.frames.size() == 2);
  // The CRYPTO frame is repaired by resending the same bytes, so the offset
  // and length are what a sender needs.
  CHECK(lost.frames[0].kind == frame_kind_t::crypto);
  CHECK(lost.frames[0].offset == 4096);
  CHECK(lost.frames[0].length == 512);
  // MAX_DATA is repaired by sending today's limit, so only the kind matters;
  // this is why the record is not the bytes that went out.
  CHECK(lost.frames[1].kind == frame_kind_t::max_data);
  auto properties = frame_properties(0x10);
  REQUIRE(properties.has_value());
  CHECK(properties->loss_policy == loss_policy_t::resend_current);
}

TEST_CASE("a malformed ACK cannot drive the walk off the end")
{
  loss_recovery_t recovery;
  const recovery_context_t context;
  for (std::uint64_t n = 0; n < 8; ++n)
  {
    recovery.on_packet_sent(pn_space_t::initial, packet(n, at(0ns)));
  }

  SUBCASE("a first range larger than the largest acknowledged")
  {
    ack_builder_t builder(3, 100);
    auto outcome = recovery.on_ack_received(pn_space_t::initial, builder.build(), at(10ms), context);
    CHECK(outcome.acknowledged.empty());
  }

  SUBCASE("a gap that would run below zero")
  {
    ack_builder_t builder(5, 0);
    builder.add(1000, 0);
    auto outcome = recovery.on_ack_received(pn_space_t::initial, builder.build(), at(10ms), context);
    CHECK(numbers(outcome.acknowledged) == std::vector<std::uint64_t>{5});
  }

  SUBCASE("a range length that would run below zero")
  {
    ack_builder_t builder(5, 0);
    builder.add(0, 1000);
    auto outcome = recovery.on_ack_received(pn_space_t::initial, builder.build(), at(10ms), context);
    CHECK(numbers(outcome.acknowledged) == std::vector<std::uint64_t>{5});
  }

  SUBCASE("a frame that is not an ACK at all")
  {
    frame_t ping;
    ping.kind = frame_kind_t::ping;
    auto outcome = recovery.on_ack_received(pn_space_t::initial, ping, at(10ms), context);
    CHECK(outcome.acknowledged.empty());
    CHECK(recovery.unacknowledged(pn_space_t::initial) == 8);
  }
}

TEST_CASE("bytes in flight follow the packets, not the acknowledgements")
{
  loss_recovery_t recovery;
  const recovery_context_t context;

  recovery.on_packet_sent(pn_space_t::application, packet(0, at(0ns), true, 500));
  recovery.on_packet_sent(pn_space_t::application, packet(1, at(0ns), false, 40));
  CHECK(recovery.bytes_in_flight() == 500);
  CHECK(recovery.ack_eliciting_in_flight());

  ack_builder_t builder(1, 1);
  auto outcome = recovery.on_ack_received(pn_space_t::application, builder.build(), at(10ms), context);
  CHECK(outcome.acknowledged.size() == 2);
  CHECK(recovery.bytes_in_flight() == 0);
  CHECK_FALSE(recovery.ack_eliciting_in_flight());
}
}
