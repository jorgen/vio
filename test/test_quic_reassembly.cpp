#include <chrono>
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <ostream>
#include <span>
#include <string>
#include <vector>
#include <doctest/doctest.h>
#include <vio/quic/ack_tracker.h>
#include <vio/quic/crypto_stream.h>

// The two pieces of receive-side bookkeeping a connection needs before it can
// drive a handshake from real datagrams: turning reordered CRYPTO frames back
// into an ordered byte stream, and turning a set of received packet numbers
// back into the descending ACK encoding the wire wants.
//
// Both are pure, so both get hammered rather than sampled.

namespace
{
using namespace vio::quic;
using namespace std::chrono_literals;

std::vector<std::uint8_t> sequence(std::uint64_t start, std::size_t count)
{
  std::vector<std::uint8_t> out;
  out.reserve(count);
  for (std::size_t i = 0; i < count; ++i)
  {
    out.push_back(static_cast<std::uint8_t>((start + i) & 0xff));
  }
  return out;
}

std::string as_text(std::span<const std::uint8_t> data)
{
  return std::string(reinterpret_cast<const char *>(data.data()), data.size());
}

std::vector<std::uint8_t> as_bytes(std::string_view text)
{
  return std::vector<std::uint8_t>(text.begin(), text.end());
}

vio::tick_t at(std::chrono::nanoseconds offset)
{
  return vio::tick_t::from_nanoseconds(offset);
}

// Replays an ACK frame the way a peer would read it, so the test checks the
// wire semantics rather than the internal bookkeeping.
std::vector<std::uint64_t> decode_ack(const ack_frame_t &frame)
{
  std::vector<std::uint64_t> acknowledged;
  std::uint64_t largest = frame.largest_acknowledged;
  std::uint64_t smallest = largest - frame.first_ack_range;
  for (std::uint64_t n = smallest; n <= largest; ++n)
  {
    acknowledged.push_back(n);
  }
  for (const auto &range : frame.ranges)
  {
    // RFC 9000 section 19.3.1.
    largest = smallest - range.gap - 2;
    smallest = largest - range.length;
    for (std::uint64_t n = smallest; n <= largest; ++n)
    {
      acknowledged.push_back(n);
    }
  }
  std::sort(acknowledged.begin(), acknowledged.end());
  return acknowledged;
}
} // namespace

TEST_SUITE("quic crypto stream")
{
TEST_CASE("in-order frames read straight through")
{
  crypto_stream_t stream;
  CHECK(stream.readable().empty());
  CHECK(stream.read_offset() == 0);

  const auto hello = as_bytes("hello ");
  CHECK(stream.insert(0, hello) == crypto_insert_t::ok);
  CHECK(as_text(stream.readable()) == "hello ");

  stream.consume(stream.readable().size());
  CHECK(stream.read_offset() == 6);
  CHECK(stream.readable().empty());
  CHECK(stream.buffered() == 0);

  const auto world = as_bytes("world");
  CHECK(stream.insert(6, world) == crypto_insert_t::ok);
  CHECK(as_text(stream.readable()) == "world");
}

TEST_CASE("a gap holds everything behind it until it is filled")
{
  crypto_stream_t stream;
  const auto tail = as_bytes("world");
  CHECK(stream.insert(6, tail) == crypto_insert_t::ok);
  CHECK(stream.readable().empty());
  CHECK(stream.has_gap());
  CHECK(stream.buffered() == 5);

  const auto head = as_bytes("hello ");
  CHECK(stream.insert(0, head) == crypto_insert_t::ok);
  CHECK_FALSE(stream.has_gap());
  CHECK(as_text(stream.readable()) == "hello world");

  stream.consume(11);
  CHECK(stream.read_offset() == 11);
  CHECK(stream.buffered() == 0);
}

TEST_CASE("chunks are merged however they overlap")
{
  SUBCASE("a duplicate of what was already consumed is dropped")
  {
    crypto_stream_t stream;
    const auto data = as_bytes("abcdef");
    CHECK(stream.insert(0, data) == crypto_insert_t::ok);
    stream.consume(6);
    CHECK(stream.insert(0, data) == crypto_insert_t::ok);
    CHECK(stream.buffered() == 0);
    CHECK(stream.read_offset() == 6);
  }

  SUBCASE("a partial duplicate keeps only the new tail")
  {
    crypto_stream_t stream;
    const auto first = as_bytes("abcd");
    CHECK(stream.insert(0, first) == crypto_insert_t::ok);
    stream.consume(4);
    const auto overlap = as_bytes("cdef");
    CHECK(stream.insert(2, overlap) == crypto_insert_t::ok);
    CHECK(as_text(stream.readable()) == "ef");
  }

  SUBCASE("a chunk that bridges two others joins all three")
  {
    crypto_stream_t stream;
    const auto left = as_bytes("aa");
    const auto right = as_bytes("dd");
    const auto bridge = as_bytes("bbcc");
    CHECK(stream.insert(0, left) == crypto_insert_t::ok);
    CHECK(stream.insert(6, right) == crypto_insert_t::ok);
    CHECK(stream.readable().size() == 2);
    CHECK(stream.insert(2, bridge) == crypto_insert_t::ok);
    CHECK(as_text(stream.readable()) == "aabbccdd");
    CHECK(stream.buffered() == 8);
  }

  SUBCASE("a chunk wholly inside another changes nothing")
  {
    crypto_stream_t stream;
    const auto whole = as_bytes("abcdefgh");
    CHECK(stream.insert(0, whole) == crypto_insert_t::ok);
    const auto inner = as_bytes("cde");
    CHECK(stream.insert(2, inner) == crypto_insert_t::ok);
    CHECK(as_text(stream.readable()) == "abcdefgh");
    CHECK(stream.buffered() == 8);
  }

  SUBCASE("adjacent chunks coalesce without overlapping")
  {
    crypto_stream_t stream;
    CHECK(stream.insert(0, as_bytes("ab")) == crypto_insert_t::ok);
    CHECK(stream.insert(2, as_bytes("cd")) == crypto_insert_t::ok);
    CHECK(stream.insert(4, as_bytes("ef")) == crypto_insert_t::ok);
    CHECK(as_text(stream.readable()) == "abcdef");
    CHECK(stream.buffered() == 6);
  }
}

TEST_CASE("every arrival order of the same stream reconstructs it")
{
  // Six chunks, delivered in every rotation and with duplicates, always end up
  // as the same bytes.
  const std::string message = "the quick brown fox jumps over the lazy dog";
  const std::size_t chunk = 7;

  struct piece_t
  {
    std::uint64_t offset;
    std::vector<std::uint8_t> data;
  };
  std::vector<piece_t> pieces;
  for (std::size_t i = 0; i < message.size(); i += chunk)
  {
    const std::size_t length = std::min(chunk, message.size() - i);
    pieces.push_back(piece_t{.offset = i, .data = as_bytes(std::string_view(message).substr(i, length))});
  }

  for (std::size_t rotation = 0; rotation < pieces.size(); ++rotation)
  {
    CAPTURE(rotation);
    crypto_stream_t stream;
    for (std::size_t i = 0; i < pieces.size(); ++i)
    {
      const auto &piece = pieces[(i + rotation) % pieces.size()];
      REQUIRE(stream.insert(piece.offset, piece.data) == crypto_insert_t::ok);
      // Every chunk delivered twice, because a retransmission is normal.
      REQUIRE(stream.insert(piece.offset, piece.data) == crypto_insert_t::ok);
    }
    CHECK(as_text(stream.readable()) == message);
    CHECK(stream.buffered() == message.size());
  }
}

TEST_CASE("buffering is bounded")
{
  crypto_stream_t stream(16);
  CHECK(stream.buffer_limit() == 16);

  const auto block = sequence(0, 16);
  CHECK(stream.insert(100, block) == crypto_insert_t::ok);
  CHECK(stream.buffered() == 16);

  const auto one_more = sequence(0, 1);
  CHECK(stream.insert(200, one_more) == crypto_insert_t::buffer_exceeded);
  CHECK(stream.buffered() == 16);

  SUBCASE("consuming makes room again")
  {
    crypto_stream_t fresh(8);
    CHECK(fresh.insert(0, sequence(0, 8)) == crypto_insert_t::ok);
    CHECK(fresh.insert(8, sequence(0, 1)) == crypto_insert_t::buffer_exceeded);
    fresh.consume(8);
    CHECK(fresh.buffered() == 0);
    CHECK(fresh.insert(8, sequence(0, 1)) == crypto_insert_t::ok);
  }

  SUBCASE("a merge that does not grow the total is allowed at the limit")
  {
    crypto_stream_t fresh(8);
    CHECK(fresh.insert(0, sequence(0, 4)) == crypto_insert_t::ok);
    CHECK(fresh.insert(4, sequence(0, 4)) == crypto_insert_t::ok);
    CHECK(fresh.buffered() == 8);
    // Wholly duplicate: the union is still eight bytes.
    CHECK(fresh.insert(0, sequence(0, 8)) == crypto_insert_t::ok);
    CHECK(fresh.buffered() == 8);
  }
}

TEST_CASE("an offset past 2^62-1 is refused")
{
  crypto_stream_t stream;
  const auto data = sequence(0, 4);
  // Section 19.6 bounds the sum of offset and length, not the offset alone,
  // so four bytes at varint_max - 4 is the last thing that fits exactly.
  CHECK(stream.insert(varint_max, data) == crypto_insert_t::offset_overflow);
  CHECK(stream.insert(varint_max - 3, data) == crypto_insert_t::offset_overflow);
  CHECK(stream.insert(varint_max - 4, data) == crypto_insert_t::ok);
  CHECK(stream.insert(varint_max + 1, data) == crypto_insert_t::offset_overflow);
}

TEST_CASE("a partial consume leaves the remainder readable")
{
  crypto_stream_t stream;
  CHECK(stream.insert(0, as_bytes("abcdefgh")) == crypto_insert_t::ok);
  stream.consume(3);
  CHECK(stream.read_offset() == 3);
  CHECK(as_text(stream.readable()) == "defgh");
  stream.consume(100);
  CHECK(stream.read_offset() == 8);
  CHECK(stream.readable().empty());
  CHECK(stream.buffered() == 0);
}
}

TEST_SUITE("quic ack tracker")
{
TEST_CASE("a single packet produces a single range")
{
  ack_tracker_t tracker;
  CHECK_FALSE(tracker.has_received());
  CHECK_FALSE(tracker.build_ack(at(0ns)).has_value());

  tracker.on_packet_received(0, true, at(0ns));
  CHECK(tracker.has_received());
  CHECK(tracker.largest_received() == 0);

  auto frame = tracker.build_ack(at(0ns));
  REQUIRE(frame.has_value());
  CHECK(frame->largest_acknowledged == 0);
  CHECK(frame->first_ack_range == 0);
  CHECK(frame->ranges.empty());
  CHECK(decode_ack(*frame) == std::vector<std::uint64_t>{0});
}

TEST_CASE("contiguous packets collapse into one range")
{
  ack_tracker_t tracker;
  for (std::uint64_t n = 0; n <= 9; ++n)
  {
    tracker.on_packet_received(n, true, at(0ns));
  }
  CHECK(tracker.range_count() == 1);

  auto frame = tracker.build_ack(at(0ns));
  REQUIRE(frame.has_value());
  CHECK(frame->largest_acknowledged == 9);
  CHECK(frame->first_ack_range == 9);
  CHECK(frame->ranges.empty());
}

TEST_CASE("gaps become ACK ranges that decode back to what was received")
{
  ack_tracker_t tracker;
  const std::vector<std::uint64_t> received = {0, 1, 2, 5, 6, 9, 20, 21, 22};
  for (std::uint64_t n : received)
  {
    tracker.on_packet_received(n, true, at(0ns));
  }
  CHECK(tracker.range_count() == 4);

  auto frame = tracker.build_ack(at(0ns));
  REQUIRE(frame.has_value());
  CHECK(frame->largest_acknowledged == 22);
  CHECK(frame->first_ack_range == 2);
  CHECK(frame->ranges.size() == 3);
  CHECK(decode_ack(*frame) == received);

  SUBCASE("the gap encoding matches the RFC formula exactly")
  {
    // Ranges descending: [20,22], [9,9], [5,6], [0,2].
    // gap = previous_smallest - largest - 2
    CHECK(frame->ranges[0].gap == 20 - 9 - 2);
    CHECK(frame->ranges[0].length == 0);
    CHECK(frame->ranges[1].gap == 9 - 6 - 2);
    CHECK(frame->ranges[1].length == 1);
    CHECK(frame->ranges[2].gap == 5 - 2 - 2);
    CHECK(frame->ranges[2].length == 2);
  }
}

TEST_CASE("arrival order does not change the ACK")
{
  const std::vector<std::uint64_t> received = {7, 3, 9, 1, 8, 2, 15, 4};
  std::vector<std::uint64_t> sorted = received;
  std::sort(sorted.begin(), sorted.end());

  std::vector<std::uint64_t> order = received;
  for (int rotation = 0; rotation < 8; ++rotation)
  {
    CAPTURE(rotation);
    std::rotate(order.begin(), order.begin() + 1, order.end());
    ack_tracker_t tracker;
    for (std::uint64_t n : order)
    {
      tracker.on_packet_received(n, true, at(0ns));
      // Duplicates must not widen anything.
      tracker.on_packet_received(n, true, at(0ns));
    }
    auto frame = tracker.build_ack(at(0ns));
    REQUIRE(frame.has_value());
    CHECK(frame->largest_acknowledged == 15);
    CHECK(decode_ack(*frame) == sorted);
  }
}

TEST_CASE("a packet that closes a gap merges the ranges on both sides")
{
  ack_tracker_t tracker;
  tracker.on_packet_received(0, true, at(0ns));
  tracker.on_packet_received(2, true, at(0ns));
  CHECK(tracker.range_count() == 2);
  tracker.on_packet_received(1, true, at(0ns));
  CHECK(tracker.range_count() == 1);

  auto frame = tracker.build_ack(at(0ns));
  REQUIRE(frame.has_value());
  CHECK(frame->largest_acknowledged == 2);
  CHECK(frame->first_ack_range == 2);
  CHECK(frame->ranges.empty());
}

TEST_CASE("duplicates are recognised and do not count toward the next ACK")
{
  ack_tracker_t tracker;
  CHECK_FALSE(tracker.is_duplicate(4));
  tracker.on_packet_received(4, true, at(0ns));
  CHECK(tracker.is_duplicate(4));
  CHECK(tracker.ack_eliciting_since_ack() == 1);
  tracker.on_packet_received(4, true, at(0ns));
  CHECK(tracker.ack_eliciting_since_ack() == 1);
  CHECK(tracker.range_count() == 1);
}

TEST_CASE("the range list is bounded, and the floor rises as ranges are dropped")
{
  ack_tracker_t tracker(4);
  // Every other packet number, so each one is its own range.
  for (std::uint64_t n = 0; n < 20; n += 2)
  {
    tracker.on_packet_received(n, true, at(0ns));
  }
  CHECK(tracker.range_count() == 4);
  CHECK(tracker.minimum_tracked() > 0);

  auto frame = tracker.build_ack(at(0ns));
  REQUIRE(frame.has_value());
  CHECK(frame->largest_acknowledged == 18);
  CHECK(frame->ranges.size() == 3);

  SUBCASE("numbers below the floor are refused rather than re-accepted")
  {
    // Having forgotten them, the tracker must not treat them as new: it could
    // no longer tell a replay from a first arrival.
    CHECK(tracker.is_duplicate(0));
    CHECK(tracker.is_duplicate(tracker.minimum_tracked() - 1));
    const auto before = tracker.range_count();
    tracker.on_packet_received(0, true, at(0ns));
    CHECK(tracker.range_count() == before);
  }

  SUBCASE("the largest received is retained regardless")
  {
    CHECK(tracker.largest_received() == 18);
  }
}

TEST_CASE("an ACK is owed after two ack-eliciting packets, or after the delay")
{
  constexpr auto max_ack_delay = std::chrono::nanoseconds(25ms);

  SUBCASE("two ack-eliciting packets are enough on their own")
  {
    ack_tracker_t tracker;
    tracker.on_packet_received(0, true, at(0ns));
    CHECK(tracker.ack_pending());
    CHECK_FALSE(tracker.should_send_ack(at(0ns), max_ack_delay));
    tracker.on_packet_received(1, true, at(1ms));
    CHECK(tracker.should_send_ack(at(1ms), max_ack_delay));
  }

  SUBCASE("one packet waits out the promised delay")
  {
    ack_tracker_t tracker;
    tracker.on_packet_received(0, true, at(0ns));
    CHECK_FALSE(tracker.should_send_ack(at(24ms), max_ack_delay));
    CHECK(tracker.should_send_ack(at(25ms), max_ack_delay));
  }

  SUBCASE("a packet that is not ack-eliciting owes nothing")
  {
    ack_tracker_t tracker;
    tracker.on_packet_received(0, false, at(0ns));
    CHECK_FALSE(tracker.ack_pending());
    CHECK_FALSE(tracker.should_send_ack(at(100ms), max_ack_delay));
    // It is still acknowledged when something else prompts an ACK.
    auto frame = tracker.build_ack(at(0ns));
    REQUIRE(frame.has_value());
    CHECK(frame->largest_acknowledged == 0);
  }

  SUBCASE("sending an ACK clears what was owed")
  {
    ack_tracker_t tracker;
    tracker.on_packet_received(0, true, at(0ns));
    tracker.on_packet_received(1, true, at(0ns));
    CHECK(tracker.should_send_ack(at(0ns), max_ack_delay));
    tracker.on_ack_sent();
    CHECK_FALSE(tracker.ack_pending());
    CHECK(tracker.ack_eliciting_since_ack() == 0);
    CHECK_FALSE(tracker.should_send_ack(at(100ms), max_ack_delay));
    // But the ranges survive, so a later ACK still reports them.
    auto frame = tracker.build_ack(at(0ns));
    REQUIRE(frame.has_value());
    CHECK(frame->largest_acknowledged == 1);
  }

  SUBCASE("the deadline says when, so a caller can arm a timer")
  {
    ack_tracker_t tracker;
    CHECK_FALSE(tracker.ack_deadline(max_ack_delay).has_value());
    tracker.on_packet_received(0, true, at(5ms));
    auto deadline = tracker.ack_deadline(max_ack_delay);
    REQUIRE(deadline.has_value());
    CHECK(*deadline == at(30ms));
    tracker.on_packet_received(1, true, at(6ms));
    // Two ack-eliciting packets: the deadline is now, not later.
    deadline = tracker.ack_deadline(max_ack_delay);
    REQUIRE(deadline.has_value());
    CHECK(*deadline == at(5ms));
  }
}

TEST_CASE("the ack delay is measured from the largest packet and scaled")
{
  ack_tracker_t tracker;
  tracker.on_packet_received(0, true, at(0ns));
  tracker.on_packet_received(1, true, at(1ms));

  SUBCASE("with the default exponent of three")
  {
    auto frame = tracker.build_ack(at(std::chrono::nanoseconds(1ms) + 8us), default_ack_delay_exponent);
    REQUIRE(frame.has_value());
    // Eight microseconds since packet 1 arrived, divided by 2^3.
    CHECK(frame->ack_delay == 1);
  }

  SUBCASE("with an exponent of zero the value is microseconds")
  {
    auto frame = tracker.build_ack(at(std::chrono::nanoseconds(1ms) + 40us), 0);
    REQUIRE(frame.has_value());
    CHECK(frame->ack_delay == 40);
  }

  SUBCASE("an earlier now reports no delay rather than an enormous one")
  {
    auto frame = tracker.build_ack(at(0ns), 0);
    REQUIRE(frame.has_value());
    CHECK(frame->ack_delay == 0);
  }
}

TEST_CASE("a long run of scattered packets round trips through the encoding")
{
  ack_tracker_t tracker(64);
  std::vector<std::uint64_t> received;
  // A deterministic scatter: every third number, then fill some of the holes.
  for (std::uint64_t n = 0; n < 120; n += 3)
  {
    received.push_back(n);
  }
  for (std::uint64_t n = 1; n < 60; n += 7)
  {
    received.push_back(n);
  }
  std::sort(received.begin(), received.end());
  received.erase(std::unique(received.begin(), received.end()), received.end());

  for (std::uint64_t n : received)
  {
    tracker.on_packet_received(n, true, at(0ns));
  }

  auto frame = tracker.build_ack(at(0ns));
  REQUIRE(frame.has_value());
  CHECK(frame->largest_acknowledged == received.back());

  // Only meaningful if nothing was trimmed; the cap is well above the count.
  CHECK(tracker.minimum_tracked() == 0);
  CHECK(decode_ack(*frame) == received);
}
}
