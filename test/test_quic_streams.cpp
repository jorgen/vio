#include <cstdint>
#include <initializer_list>
#include <optional>
#include <ostream>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include <doctest/doctest.h>
#include <vio/quic/streams.h>

// RFC 9000 sections 2 through 4. The two things worth being strict about are
// final size -- both endpoints must agree exactly how much connection credit a
// stream consumed, however it ended -- and the limits, which are the only
// thing stopping a peer from making this endpoint allocate without bound.

namespace
{
using namespace vio::quic;

std::vector<std::uint8_t> as_bytes(std::string_view text)
{
  return std::vector<std::uint8_t>(text.begin(), text.end());
}

std::string as_text(std::span<const std::uint8_t> data)
{
  return std::string(reinterpret_cast<const char *>(data.data()), data.size());
}

streams_config_t client_config(std::uint64_t max_data = 1000, std::uint64_t max_stream_data = 500, std::uint64_t max_streams = 10)
{
  streams_config_t config;
  config.local_initiator = stream_initiator_t::client;
  config.initial_max_data = max_data;
  config.initial_max_stream_data_bidi_local = max_stream_data;
  config.initial_max_stream_data_bidi_remote = max_stream_data;
  config.initial_max_stream_data_uni = max_stream_data;
  config.initial_max_streams_bidi = max_streams;
  config.initial_max_streams_uni = max_streams;
  return config;
}

transport_parameters_t peer_parameters(std::uint64_t max_data = 1000, std::uint64_t max_stream_data = 500, std::uint64_t max_streams = 10)
{
  transport_parameters_t parameters;
  parameters.initial_max_data = max_data;
  parameters.initial_max_stream_data_bidi_local = max_stream_data;
  parameters.initial_max_stream_data_bidi_remote = max_stream_data;
  parameters.initial_max_stream_data_uni = max_stream_data;
  parameters.initial_max_streams_bidi = max_streams;
  parameters.initial_max_streams_uni = max_streams;
  return parameters;
}
} // namespace

TEST_SUITE("quic stream ids")
{
TEST_CASE("the low two bits say who opened it and which way it runs")
{
  // Table 1 of section 2.1.
  CHECK(stream_initiator(0) == stream_initiator_t::client);
  CHECK(stream_direction(0) == stream_direction_t::bidirectional);
  CHECK(stream_initiator(1) == stream_initiator_t::server);
  CHECK(stream_direction(1) == stream_direction_t::bidirectional);
  CHECK(stream_initiator(2) == stream_initiator_t::client);
  CHECK(stream_direction(2) == stream_direction_t::unidirectional);
  CHECK(stream_initiator(3) == stream_initiator_t::server);
  CHECK(stream_direction(3) == stream_direction_t::unidirectional);

  CHECK(stream_index(0) == 0);
  CHECK(stream_index(4) == 1);
  CHECK(stream_index(9) == 2);

  CHECK(make_stream_id(stream_initiator_t::client, stream_direction_t::bidirectional, 0) == 0);
  CHECK(make_stream_id(stream_initiator_t::server, stream_direction_t::bidirectional, 0) == 1);
  CHECK(make_stream_id(stream_initiator_t::client, stream_direction_t::unidirectional, 0) == 2);
  CHECK(make_stream_id(stream_initiator_t::server, stream_direction_t::unidirectional, 3) == 15);

  SUBCASE("and the round trip holds for every combination")
  {
    for (std::uint64_t index = 0; index < 100; ++index)
    {
      for (auto initiator : {stream_initiator_t::client, stream_initiator_t::server})
      {
        for (auto direction : {stream_direction_t::bidirectional, stream_direction_t::unidirectional})
        {
          const auto id = make_stream_id(initiator, direction, index);
          CHECK(stream_initiator(id) == initiator);
          CHECK(stream_direction(id) == direction);
          CHECK(stream_index(id) == index);
        }
      }
    }
  }

  SUBCASE("the limit is on the index, not the identifier")
  {
    // Section 4.6: only ids below max_streams * 4 + first_of_type may open.
    CHECK(stream_index_within_limit(0, 1));
    CHECK_FALSE(stream_index_within_limit(4, 1));
    CHECK(stream_index_within_limit(4, 2));
    CHECK_FALSE(stream_index_within_limit(0, 0));
  }
}
}

TEST_SUITE("quic receive stream")
{
TEST_CASE("data arrives in any order and reads back in one")
{
  receive_stream_t stream(1000);
  std::uint64_t consumed = 0;

  CHECK(stream.receive(6, as_bytes("world"), false, consumed) == stream_error_t::none);
  CHECK(consumed == 11);
  CHECK(stream.readable().empty());

  CHECK(stream.receive(0, as_bytes("hello "), false, consumed) == stream_error_t::none);
  // The highest offset did not move, so no new connection credit is consumed.
  CHECK(consumed == 0);
  CHECK(as_text(stream.readable()) == "hello world");

  stream.consume(11);
  CHECK(stream.read_offset() == 11);
  CHECK(stream.highest_offset() == 11);
}

TEST_CASE("a FIN settles the final size and it cannot change")
{
  receive_stream_t stream(1000);
  std::uint64_t consumed = 0;

  CHECK(stream.receive(0, as_bytes("hello"), true, consumed) == stream_error_t::none);
  REQUIRE(stream.final_size().has_value());
  CHECK(*stream.final_size() == 5);
  CHECK(stream.state() == receive_state_t::data_received);

  SUBCASE("data beyond it is a final size error")
  {
    CHECK(stream.receive(5, as_bytes("more"), false, consumed) == stream_error_t::final_size);
  }

  SUBCASE("a second FIN claiming a different size is too")
  {
    CHECK(stream.receive(0, as_bytes("hello world"), true, consumed) == stream_error_t::final_size);
  }

  SUBCASE("a repeat of the same FIN is fine")
  {
    CHECK(stream.receive(0, as_bytes("hello"), true, consumed) == stream_error_t::none);
    CHECK(consumed == 0);
  }

  SUBCASE("reading it all moves the stream to data read")
  {
    stream.consume(5);
    CHECK(stream.state() == receive_state_t::data_read);
    CHECK(stream.finished());
  }
}

TEST_CASE("a FIN below data already received is refused")
{
  receive_stream_t stream(1000);
  std::uint64_t consumed = 0;
  CHECK(stream.receive(0, as_bytes("hello world"), false, consumed) == stream_error_t::none);
  // Claiming the stream ends at 5 when 11 bytes have arrived is impossible.
  CHECK(stream.receive(0, as_bytes("hello"), true, consumed) == stream_error_t::final_size);
}

TEST_CASE("the advertised limit is enforced")
{
  receive_stream_t stream(10);
  std::uint64_t consumed = 0;
  CHECK(stream.available_window() == 10);
  CHECK(stream.receive(0, as_bytes("0123456789"), false, consumed) == stream_error_t::none);
  CHECK(stream.available_window() == 0);
  CHECK(stream.receive(10, as_bytes("x"), false, consumed) == stream_error_t::flow_control);

  SUBCASE("raising it lets more through")
  {
    stream.set_max_data(20);
    CHECK(stream.receive(10, as_bytes("x"), false, consumed) == stream_error_t::none);
  }

  SUBCASE("a limit only ever moves up")
  {
    stream.set_max_data(5);
    CHECK(stream.max_data() == 10);
  }
}

TEST_CASE("a reset settles the final size too")
{
  receive_stream_t stream(1000);
  std::uint64_t consumed = 0;
  CHECK(stream.receive(0, as_bytes("hello"), false, consumed) == stream_error_t::none);
  CHECK(consumed == 5);

  CHECK(stream.receive_reset(20, consumed) == stream_error_t::none);
  // Section 4.5: the connection-level accounting is brought up to the final
  // size even though those bytes never arrived.
  CHECK(consumed == 15);
  CHECK(stream.state() == receive_state_t::reset_received);
  REQUIRE(stream.final_size().has_value());
  CHECK(*stream.final_size() == 20);

  SUBCASE("a reset below what already arrived is refused")
  {
    receive_stream_t other(1000);
    std::uint64_t used = 0;
    CHECK(other.receive(0, as_bytes("hello"), false, used) == stream_error_t::none);
    CHECK(other.receive_reset(2, used) == stream_error_t::final_size);
  }

  SUBCASE("a reset contradicting a known final size is refused")
  {
    receive_stream_t other(1000);
    std::uint64_t used = 0;
    CHECK(other.receive(0, as_bytes("hello"), true, used) == stream_error_t::none);
    CHECK(other.receive_reset(9, used) == stream_error_t::final_size);
  }

  SUBCASE("a reset beyond the advertised limit is a flow control error")
  {
    receive_stream_t other(10);
    std::uint64_t used = 0;
    CHECK(other.receive_reset(11, used) == stream_error_t::flow_control);
  }

  SUBCASE("data after a reset is ignored rather than treated as an error")
  {
    // The peer may not have seen the reset yet.
    CHECK(stream.receive(0, as_bytes("hello"), false, consumed) == stream_error_t::none);
  }
}
}

TEST_SUITE("quic send stream")
{
TEST_CASE("data is handed out in chunks bounded by the peer's limit")
{
  send_stream_t stream(10);
  CHECK(stream.state() == send_state_t::ready);
  CHECK(stream.write(as_bytes("hello world"), false));
  CHECK(stream.state() == send_state_t::send);

  auto chunk = stream.next_chunk(100, 1000);
  REQUIRE(chunk.has_value());
  // The peer said ten bytes, so ten bytes.
  CHECK(chunk->offset == 0);
  CHECK(as_text(chunk->data) == "hello worl");
  CHECK_FALSE(chunk->fin);
  stream.on_chunk_sent(*chunk);
  CHECK(stream.sent_offset() == 10);

  CHECK(stream.blocked_by_flow_control());
  CHECK_FALSE(stream.next_chunk(100, 1000).has_value());

  SUBCASE("raising the limit releases the rest")
  {
    stream.set_max_data(20);
    CHECK_FALSE(stream.blocked_by_flow_control());
    auto rest = stream.next_chunk(100, 1000);
    REQUIRE(rest.has_value());
    CHECK(as_text(rest->data) == "d");
  }
}

TEST_CASE("the connection window bounds a chunk as well as the stream limit")
{
  send_stream_t stream(1000);
  CHECK(stream.write(as_bytes("hello world"), false));
  auto chunk = stream.next_chunk(100, 4);
  REQUIRE(chunk.has_value());
  CHECK(as_text(chunk->data) == "hell");
}

TEST_CASE("the FIN rides with the last byte, or alone if there is none left")
{
  send_stream_t stream(1000);
  CHECK(stream.write(as_bytes("hi"), true));
  auto chunk = stream.next_chunk(100, 1000);
  REQUIRE(chunk.has_value());
  CHECK(as_text(chunk->data) == "hi");
  CHECK(chunk->fin);
  stream.on_chunk_sent(*chunk);
  CHECK(stream.state() == send_state_t::data_sent);

  SUBCASE("a FIN with nothing after it still goes")
  {
    send_stream_t other(1000);
    CHECK(other.write(as_bytes("hi"), false));
    auto first = other.next_chunk(100, 1000);
    REQUIRE(first.has_value());
    other.on_chunk_sent(*first);
    CHECK(other.write({}, true));
    auto last = other.next_chunk(100, 1000);
    REQUIRE(last.has_value());
    CHECK(last->data.empty());
    CHECK(last->fin);
  }

  SUBCASE("nothing may be written after the FIN")
  {
    CHECK_FALSE(stream.write(as_bytes("more"), false));
  }

  SUBCASE("acknowledging everything finishes the stream")
  {
    stream.on_range_acknowledged(0, 2);
    CHECK(stream.state() == send_state_t::data_received);
  }
}

TEST_CASE("a lost range is sent again before anything new")
{
  send_stream_t stream(1000);
  CHECK(stream.write(as_bytes("0123456789"), false));
  auto first = stream.next_chunk(5, 1000);
  REQUIRE(first.has_value());
  CHECK(as_text(first->data) == "01234");
  stream.on_chunk_sent(*first);

  stream.on_range_lost(0, 5);
  auto repeat = stream.next_chunk(100, 1000);
  REQUIRE(repeat.has_value());
  // Section 13.3: retransmissions go first, and carry the same bytes.
  CHECK(repeat->retransmit);
  CHECK(repeat->offset == 0);
  CHECK(as_text(repeat->data) == "01234");
  stream.on_chunk_sent(*repeat);

  auto next = stream.next_chunk(100, 1000);
  REQUIRE(next.has_value());
  CHECK_FALSE(next->retransmit);
  CHECK(as_text(next->data) == "56789");

  SUBCASE("the same range is not queued twice")
  {
    send_stream_t other(1000);
    CHECK(other.write(as_bytes("hello"), false));
    other.on_range_lost(0, 5);
    other.on_range_lost(0, 5);
    auto chunk = other.next_chunk(100, 1000);
    REQUIRE(chunk.has_value());
    other.on_chunk_sent(*chunk);
    auto again = other.next_chunk(100, 1000);
    REQUIRE(again.has_value());
    CHECK_FALSE(again->retransmit);
  }
}

TEST_CASE("a reset abandons what has not been delivered")
{
  send_stream_t stream(1000);
  CHECK(stream.write(as_bytes("hello"), false));
  auto chunk = stream.next_chunk(2, 1000);
  REQUIRE(chunk.has_value());
  stream.on_chunk_sent(*chunk);
  stream.on_range_lost(0, 2);

  stream.reset(7);
  CHECK(stream.state() == send_state_t::reset_sent);
  REQUIRE(stream.reset_error().has_value());
  CHECK(*stream.reset_error() == 7);
  // Section 4.5: the final size is everything queued, sent or not.
  CHECK(stream.final_size() == 5);
  CHECK_FALSE(stream.next_chunk(100, 1000).has_value());
  CHECK_FALSE(stream.write(as_bytes("more"), false));
}
}

TEST_SUITE("quic streams")
{
TEST_CASE("a peer-initiated stream opens on first use, along with every lower one")
{
  streams_t streams(client_config());
  streams.apply_peer_parameters(peer_parameters());

  // Server-initiated bidirectional stream index 2 is id 9.
  CHECK(streams.receive_stream_frame(9, 0, as_bytes("hi"), false) == streams_error_t::none);
  CHECK(streams.find(9) != nullptr);

  // Section 3.2: 1 and 5 are open too and all three count against the limit,
  // but no state is held for streams that have carried nothing. Materialising
  // them would let one frame naming a high index cost an allocation per
  // implied stream.
  CHECK(streams.remote_streams_opened(stream_direction_t::bidirectional) == 3);
  CHECK(streams.find(1) == nullptr);
  CHECK(streams.find(5) == nullptr);

  SUBCASE("and the data landed on the right one")
  {
    auto *stream = streams.find(9);
    REQUIRE(stream != nullptr);
    CHECK(as_text(stream->receive.readable()) == "hi");
  }

  SUBCASE("a later frame for a lower one is still accepted")
  {
    CHECK(streams.receive_stream_frame(1, 0, as_bytes("late"), false) == streams_error_t::none);
    auto *stream = streams.find(1);
    REQUIRE(stream != nullptr);
    CHECK(as_text(stream->receive.readable()) == "late");
    // And it did not re-count against the limit.
    CHECK(streams.remote_streams_opened(stream_direction_t::bidirectional) == 3);
  }

  SUBCASE("a single frame naming a huge index costs one stream, not that many")
  {
    streams_t wide(client_config(1000, 500, 1000000));
    wide.apply_peer_parameters(peer_parameters());
    const std::uint64_t high = make_stream_id(stream_initiator_t::server, stream_direction_t::bidirectional, 999999);
    CHECK(wide.receive_stream_frame(high, 0, as_bytes("x"), false) == streams_error_t::none);
    CHECK(wide.remote_streams_opened(stream_direction_t::bidirectional) == 1000000);
    CHECK(wide.find(high) != nullptr);
    CHECK(wide.all().size() == 1);
  }
}

TEST_CASE("a peer that exceeds the stream limit is a connection error")
{
  streams_t streams(client_config(1000, 500, 2));
  streams.apply_peer_parameters(peer_parameters());

  // Indices 0 and 1 are allowed; index 2 is not.
  CHECK(streams.receive_stream_frame(1, 0, as_bytes("a"), false) == streams_error_t::none);
  CHECK(streams.receive_stream_frame(5, 0, as_bytes("b"), false) == streams_error_t::none);
  CHECK(streams.receive_stream_frame(9, 0, as_bytes("c"), false) == streams_error_t::stream_limit);
  CHECK(streams_error_code(streams_error_t::stream_limit) == 0x04);
}

TEST_CASE("connection level flow control is charged across all streams")
{
  streams_t streams(client_config(10, 500, 10));
  streams.apply_peer_parameters(peer_parameters());

  CHECK(streams.receive_stream_frame(1, 0, as_bytes("12345"), false) == streams_error_t::none);
  CHECK(streams.data_received() == 5);
  CHECK(streams.receive_stream_frame(5, 0, as_bytes("12345"), false) == streams_error_t::none);
  CHECK(streams.data_received() == 10);
  // One byte more than the connection allows, on a stream well within its own
  // limit: this is what the connection-level limit is for.
  CHECK(streams.receive_stream_frame(9, 0, as_bytes("x"), false) == streams_error_t::flow_control);
  CHECK(streams_error_code(streams_error_t::flow_control) == 0x03);

  SUBCASE("raising the connection limit lets it through")
  {
    streams_t other(client_config(10, 500, 10));
    other.apply_peer_parameters(peer_parameters());
    CHECK(other.receive_stream_frame(1, 0, as_bytes("1234567890"), false) == streams_error_t::none);
    other.set_local_max_data(20);
    CHECK(other.receive_stream_frame(5, 0, as_bytes("x"), false) == streams_error_t::none);
  }
}

TEST_CASE("a reset charges the connection for bytes that never arrived")
{
  streams_t streams(client_config(100, 500, 10));
  streams.apply_peer_parameters(peer_parameters());

  CHECK(streams.receive_stream_frame(1, 0, as_bytes("hello"), false) == streams_error_t::none);
  CHECK(streams.data_received() == 5);
  CHECK(streams.receive_reset_stream(1, 3, 40) == streams_error_t::none);
  // Section 4.5 again: both endpoints must agree on the credit consumed.
  CHECK(streams.data_received() == 40);
}

TEST_CASE("opening is bounded by what the peer allowed")
{
  streams_t streams(client_config());
  auto parameters = peer_parameters(1000, 500, 2);
  streams.apply_peer_parameters(parameters);

  auto first = streams.open(stream_direction_t::bidirectional);
  REQUIRE(first.has_value());
  CHECK(*first == 0);
  auto second = streams.open(stream_direction_t::bidirectional);
  REQUIRE(second.has_value());
  CHECK(*second == 4);
  // Section 4.6: this endpoint must not exceed the limit, so it is told to
  // wait rather than allowed to break it.
  CHECK_FALSE(streams.open(stream_direction_t::bidirectional).has_value());

  SUBCASE("a MAX_STREAMS frame releases more")
  {
    streams.set_peer_max_streams(stream_direction_t::bidirectional, 3);
    auto third = streams.open(stream_direction_t::bidirectional);
    REQUIRE(third.has_value());
    CHECK(*third == 8);
  }

  SUBCASE("unidirectional streams have their own budget")
  {
    auto uni = streams.open(stream_direction_t::unidirectional);
    REQUIRE(uni.has_value());
    CHECK(*uni == 2);
  }
}

TEST_CASE("a locally opened stream gets the limit the peer advertised for it")
{
  streams_t streams(client_config());
  auto parameters = peer_parameters();
  parameters.initial_max_stream_data_bidi_remote = 77;
  parameters.initial_max_stream_data_uni = 33;
  streams.apply_peer_parameters(parameters);

  auto bidi = streams.open(stream_direction_t::bidirectional);
  REQUIRE(bidi.has_value());
  // Section 18.2: for a stream this endpoint opened, the peer's limit is the
  // one it labelled "bidi_remote" -- remote from the peer's point of view.
  CHECK(streams.find(*bidi)->send.max_data() == 77);

  auto uni = streams.open(stream_direction_t::unidirectional);
  REQUIRE(uni.has_value());
  CHECK(streams.find(*uni)->send.max_data() == 33);
}

TEST_CASE("STOP_SENDING turns into a reset of the sending half")
{
  streams_t streams(client_config());
  streams.apply_peer_parameters(peer_parameters());

  auto id = streams.open(stream_direction_t::bidirectional);
  REQUIRE(id.has_value());
  auto *stream = streams.find(*id);
  REQUIRE(stream != nullptr);
  CHECK(stream->send.write(as_bytes("hello"), false));

  CHECK(streams.receive_stop_sending(*id, 9) == streams_error_t::none);
  // Section 3.5: there is no point continuing to send into a void.
  CHECK(stream->send.state() == send_state_t::reset_sent);
  CHECK(stream->reset_pending);
  REQUIRE(stream->stop_sending_error.has_value());
  CHECK(*stream->stop_sending_error == 9);
}

TEST_CASE("a frame for a locally initiated stream that was never opened is a state error")
{
  streams_t streams(client_config());
  streams.apply_peer_parameters(peer_parameters());
  // Stream 0 is client-initiated and this endpoint is the client, but it has
  // not opened it: the peer has no business sending on it.
  CHECK(streams.receive_stream_frame(0, 0, as_bytes("x"), false) == streams_error_t::stream_state);
  CHECK(streams_error_code(streams_error_t::stream_state) == 0x05);
}

TEST_CASE("a unidirectional stream has only the half it is entitled to")
{
  streams_t streams(client_config());
  streams.apply_peer_parameters(peer_parameters());

  // Server-initiated unidirectional: this endpoint may only receive.
  CHECK(streams.receive_stream_frame(3, 0, as_bytes("hi"), false) == streams_error_t::none);
  auto *incoming = streams.find(3);
  REQUIRE(incoming != nullptr);
  CHECK(incoming->has_receive);
  CHECK_FALSE(incoming->has_send);
  // So MAX_STREAM_DATA for it makes no sense.
  CHECK(streams.receive_max_stream_data(3, 100) == streams_error_t::stream_state);

  // One this endpoint opened: send only.
  auto outgoing = streams.open(stream_direction_t::unidirectional);
  REQUIRE(outgoing.has_value());
  auto *mine = streams.find(*outgoing);
  REQUIRE(mine != nullptr);
  CHECK(mine->has_send);
  CHECK_FALSE(mine->has_receive);
  CHECK(streams.receive_stream_frame(*outgoing, 0, as_bytes("x"), false) == streams_error_t::stream_state);
}

TEST_CASE("the connection send window is what the peer allowed minus what has gone")
{
  streams_t streams(client_config());
  streams.apply_peer_parameters(peer_parameters(100));
  CHECK(streams.connection_send_window() == 100);
  streams.on_data_sent(40);
  CHECK(streams.connection_send_window() == 60);
  streams.set_peer_max_data(200);
  CHECK(streams.connection_send_window() == 160);

  SUBCASE("and it never goes negative")
  {
    streams.on_data_sent(1000);
    CHECK(streams.connection_send_window() == 0);
  }
}
}
