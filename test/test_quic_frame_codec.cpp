#include <cstdint>
#include <initializer_list>
#include <optional>
#include <ostream>
#include <span>
#include <string>
#include <vector>
#include <doctest/doctest.h>
#include <vio/crypto.h>
#include <vio/quic/frame_codec.h>

// Frame layouts are from RFC 9000 section 19, read from the raw RFC text.
// The decoder consumes bytes that the AEAD has authenticated but that are
// otherwise a peer's choice, so the truncation cases matter as much as the
// happy path.
//
// Every input below is a named local, never a temporary: a frame_t holds
// spans into the buffer it was decoded from, so a temporary would leave the
// data fields pointing at freed memory.

namespace
{
using namespace vio::quic;

std::vector<std::uint8_t> bytes(std::initializer_list<int> values)
{
  std::vector<std::uint8_t> out;
  out.reserve(values.size());
  for (int value : values)
  {
    out.push_back(static_cast<std::uint8_t>(value));
  }
  return out;
}

std::optional<frame_t> read_one(const std::vector<std::uint8_t> &input, packet_type_t packet = packet_type_t::one_rtt)
{
  frame_reader_t reader(input, packet);
  auto next = reader.next();
  if (!next.has_value() || !next->has_value())
  {
    return std::nullopt;
  }
  return next->value();
}

std::optional<frame_error_t> read_error(const std::vector<std::uint8_t> &input, packet_type_t packet = packet_type_t::one_rtt)
{
  frame_reader_t reader(input, packet);
  auto next = reader.next();
  if (!next.has_value() || next->has_value())
  {
    return std::nullopt;
  }
  return next->error();
}

std::string hex(std::span<const std::uint8_t> data)
{
  return vio::crypto::to_hex(data);
}
} // namespace

TEST_SUITE("quic frame codec")
{
TEST_CASE("PING and HANDSHAKE_DONE are a single byte")
{
  const auto ping_input = bytes({0x01});
  auto ping = read_one(ping_input);
  REQUIRE(ping.has_value());
  CHECK(ping->kind == frame_kind_t::ping);

  const auto done_input = bytes({0x1e});
  auto done = read_one(done_input);
  REQUIRE(done.has_value());
  CHECK(done->kind == frame_kind_t::handshake_done);
}

TEST_CASE("a run of PADDING is coalesced into one frame")
{
  const auto input = bytes({0x00, 0x00, 0x00, 0x00, 0x00});
  auto padding = read_one(input);
  REQUIRE(padding.has_value());
  CHECK(padding->kind == frame_kind_t::padding);
  CHECK(padding->padding_count == 5);

  SUBCASE("the run stops at the next frame")
  {
    const auto mixed = bytes({0x00, 0x00, 0x01});
    frame_reader_t reader(mixed, packet_type_t::one_rtt);
    auto first = reader.next();
    REQUIRE(first.has_value());
    REQUIRE(first->has_value());
    CHECK(first->value().padding_count == 2);
    auto second = reader.next();
    REQUIRE(second.has_value());
    REQUIRE(second->has_value());
    CHECK(second->value().kind == frame_kind_t::ping);
    CHECK(reader.done());
  }
}

TEST_CASE("STREAM decodes its type bits")
{
  SUBCASE("no offset, no length: data runs to the end of the packet")
  {
    const auto input = bytes({0x08, 0x04, 0xaa, 0xbb, 0xcc});
    auto frame = read_one(input);
    REQUIRE(frame.has_value());
    CHECK(frame->kind == frame_kind_t::stream);
    CHECK(frame->stream_id == 4);
    CHECK(frame->offset == 0);
    CHECK_FALSE(frame->fin);
    CHECK(hex(frame->data) == "aabbcc");
  }

  SUBCASE("OFF and LEN and FIN together")
  {
    const auto input = bytes({0x0f, 0x04, 0x40, 0xc8, 0x02, 0xaa, 0xbb});
    auto frame = read_one(input);
    REQUIRE(frame.has_value());
    CHECK(frame->stream_id == 4);
    CHECK(frame->offset == 200);
    CHECK(frame->fin);
    CHECK(hex(frame->data) == "aabb");
  }

  SUBCASE("LEN without OFF")
  {
    const auto input = bytes({0x0a, 0x04, 0x02, 0xaa, 0xbb});
    auto frame = read_one(input);
    REQUIRE(frame.has_value());
    CHECK(frame->offset == 0);
    CHECK_FALSE(frame->fin);
    CHECK(hex(frame->data) == "aabb");
  }

  SUBCASE("a length past the end of the packet is refused")
  {
    const auto input = bytes({0x0a, 0x04, 0x20, 0xaa});
    auto error = read_error(input);
    REQUIRE(error.has_value());
    CHECK(error->code == transport_error_code_t::frame_encoding_error);
  }

  SUBCASE("an offset plus length beyond 2^62-1 is refused")
  {
    const auto input = bytes({0x0e, 0x04, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 0xaa});
    auto error = read_error(input);
    REQUIRE(error.has_value());
    CHECK(error->code == transport_error_code_t::frame_encoding_error);
  }
}

TEST_CASE("ACK decodes its ranges and optional ECN counts")
{
  const auto input = bytes({0x02, 0x0a, 0x03, 0x01, 0x02, 0x01, 0x04});
  auto frame = read_one(input);
  REQUIRE(frame.has_value());
  CHECK(frame->kind == frame_kind_t::ack);
  CHECK(frame->largest_acknowledged == 10);
  CHECK(frame->ack_delay == 3);
  CHECK(frame->ack_range_count == 1);
  CHECK(frame->first_ack_range == 2);
  CHECK_FALSE(frame->ecn.has_value());

  ack_range_reader_t ranges(frame->ack_ranges);
  auto first = ranges.next();
  REQUIRE(first.has_value());
  CHECK(first->gap == 1);
  CHECK(first->length == 4);
  CHECK_FALSE(ranges.next().has_value());

  SUBCASE("type 0x03 carries ECN counts")
  {
    const auto ecn_input = bytes({0x03, 0x0a, 0x03, 0x00, 0x02, 0x05, 0x06, 0x07});
    auto ecn = read_one(ecn_input);
    REQUIRE(ecn.has_value());
    REQUIRE(ecn->ecn.has_value());
    CHECK(ecn->ecn->ect0 == 5);
    CHECK(ecn->ecn->ect1 == 6);
    CHECK(ecn->ecn->ce == 7);
  }

  SUBCASE("several ranges read back in order")
  {
    const auto many = bytes({0x02, 0x40, 0x64, 0x03, 0x03, 0x02, 0x01, 0x04, 0x00, 0x02, 0x05, 0x0a});
    auto multi = read_one(many);
    REQUIRE(multi.has_value());
    CHECK(multi->ack_range_count == 3);
    ack_range_reader_t reader(multi->ack_ranges);
    std::vector<ack_range_t> decoded;
    while (auto range = reader.next())
    {
      decoded.push_back(*range);
    }
    REQUIRE(decoded.size() == 3);
    CHECK(decoded[0].gap == 1);
    CHECK(decoded[0].length == 4);
    CHECK(decoded[1].gap == 0);
    CHECK(decoded[1].length == 2);
    CHECK(decoded[2].gap == 5);
    CHECK(decoded[2].length == 10);
  }

  SUBCASE("a range count larger than the packet could hold is refused")
  {
    const auto bad = bytes({0x02, 0x0a, 0x03, 0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x02});
    auto error = read_error(bad);
    REQUIRE(error.has_value());
    CHECK(error->code == transport_error_code_t::frame_encoding_error);
  }

  SUBCASE("a truncated range list is refused")
  {
    const auto bad = bytes({0x02, 0x0a, 0x03, 0x02, 0x02, 0x01});
    CHECK(read_error(bad).has_value());
  }

  SUBCASE("truncated ECN counts are refused")
  {
    const auto bad = bytes({0x03, 0x0a, 0x03, 0x00, 0x02, 0x05, 0x06});
    CHECK(read_error(bad).has_value());
  }
}

TEST_CASE("the varint-only frames")
{
  const auto reset_input = bytes({0x04, 0x04, 0x0b, 0x40, 0xc8});
  auto reset = read_one(reset_input);
  REQUIRE(reset.has_value());
  CHECK(reset->kind == frame_kind_t::reset_stream);
  CHECK(reset->stream_id == 4);
  CHECK(reset->error_code == 11);
  CHECK(reset->final_size == 200);

  const auto stop_input = bytes({0x05, 0x08, 0x0b});
  auto stop = read_one(stop_input);
  REQUIRE(stop.has_value());
  CHECK(stop->stream_id == 8);
  CHECK(stop->error_code == 11);

  const auto max_data_input = bytes({0x10, 0x40, 0xc8});
  auto max_data = read_one(max_data_input);
  REQUIRE(max_data.has_value());
  CHECK(max_data->maximum == 200);

  const auto max_stream_data_input = bytes({0x11, 0x04, 0x40, 0xc8});
  auto max_stream_data = read_one(max_stream_data_input);
  REQUIRE(max_stream_data.has_value());
  CHECK(max_stream_data->stream_id == 4);
  CHECK(max_stream_data->maximum == 200);

  const auto data_blocked_input = bytes({0x14, 0x40, 0xc8});
  auto data_blocked = read_one(data_blocked_input);
  REQUIRE(data_blocked.has_value());
  CHECK(data_blocked->kind == frame_kind_t::data_blocked);
  CHECK(data_blocked->maximum == 200);

  const auto stream_blocked_input = bytes({0x15, 0x04, 0x40, 0xc8});
  auto stream_blocked = read_one(stream_blocked_input);
  REQUIRE(stream_blocked.has_value());
  CHECK(stream_blocked->kind == frame_kind_t::stream_data_blocked);
  CHECK(stream_blocked->stream_id == 4);

  const auto retire_input = bytes({0x19, 0x07});
  auto retire = read_one(retire_input);
  REQUIRE(retire.has_value());
  CHECK(retire->sequence_number == 7);

  SUBCASE("each is refused when its last field is missing")
  {
    const auto truncated_reset = bytes({0x04, 0x04, 0x0b});
    const auto truncated_stop = bytes({0x05, 0x08});
    const auto truncated_max_stream_data = bytes({0x11, 0x04});
    CHECK(read_error(truncated_reset).has_value());
    CHECK(read_error(truncated_stop).has_value());
    CHECK(read_error(truncated_max_stream_data).has_value());
  }
}

TEST_CASE("MAX_STREAMS and STREAMS_BLOCKED carry the stream type in the low bit")
{
  const auto bidi_input = bytes({0x12, 0x40, 0x64});
  auto bidi = read_one(bidi_input);
  REQUIRE(bidi.has_value());
  CHECK(bidi->bidirectional);
  CHECK(bidi->maximum == 100);

  const auto uni_input = bytes({0x13, 0x40, 0x64});
  auto uni = read_one(uni_input);
  REQUIRE(uni.has_value());
  CHECK_FALSE(uni->bidirectional);

  const auto blocked_input = bytes({0x16, 0x40, 0x64});
  auto blocked_bidi = read_one(blocked_input);
  REQUIRE(blocked_bidi.has_value());
  CHECK(blocked_bidi->kind == frame_kind_t::streams_blocked);
  CHECK(blocked_bidi->bidirectional);

  SUBCASE("a count above 2^60 is a connection error")
  {
    const auto input = bytes({0x12, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01});
    auto error = read_error(input);
    REQUIRE(error.has_value());
    CHECK(error->code == transport_error_code_t::frame_encoding_error);
  }

  SUBCASE("exactly 2^60 is allowed")
  {
    const auto input = bytes({0x12, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
    auto frame = read_one(input);
    REQUIRE(frame.has_value());
    CHECK(frame->maximum == max_stream_count);
  }
}

TEST_CASE("CRYPTO and NEW_TOKEN are length prefixed")
{
  const auto crypto_input = bytes({0x06, 0x00, 0x03, 0xaa, 0xbb, 0xcc});
  auto crypto = read_one(crypto_input);
  REQUIRE(crypto.has_value());
  CHECK(crypto->offset == 0);
  CHECK(hex(crypto->data) == "aabbcc");

  const auto offset_input = bytes({0x06, 0x40, 0xc8, 0x02, 0xaa, 0xbb});
  auto offset_frame = read_one(offset_input);
  REQUIRE(offset_frame.has_value());
  CHECK(offset_frame->offset == 200);
  CHECK(hex(offset_frame->data) == "aabb");

  const auto token_input = bytes({0x07, 0x02, 0xde, 0xad});
  auto token = read_one(token_input);
  REQUIRE(token.has_value());
  CHECK(hex(token->data) == "dead");

  SUBCASE("an empty token is a frame encoding error")
  {
    const auto input = bytes({0x07, 0x00});
    auto error = read_error(input);
    REQUIRE(error.has_value());
    CHECK(error->code == transport_error_code_t::frame_encoding_error);
  }

  SUBCASE("an empty CRYPTO payload is allowed")
  {
    const auto input = bytes({0x06, 0x00, 0x00});
    auto frame = read_one(input);
    REQUIRE(frame.has_value());
    CHECK(frame->data.empty());
  }

  SUBCASE("a length past the end is refused rather than read")
  {
    const auto short_crypto = bytes({0x06, 0x00, 0x10, 0xaa});
    const auto short_token = bytes({0x07, 0x10, 0xaa});
    CHECK(read_error(short_crypto).has_value());
    CHECK(read_error(short_token).has_value());
  }

  SUBCASE("a huge length does not wrap when narrowed")
  {
    const auto input = bytes({0x06, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xaa});
    CHECK(read_error(input).has_value());
  }
}

TEST_CASE("NEW_CONNECTION_ID validates its lengths and ordering")
{
  const auto input = bytes({0x18, 0x02, 0x01, 0x04, 0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f});
  auto frame = read_one(input);
  REQUIRE(frame.has_value());
  CHECK(frame->sequence_number == 2);
  CHECK(frame->retire_prior_to == 1);
  CHECK(hex(frame->connection_id.bytes()) == "aabbccdd");
  CHECK(frame->stateless_reset_token.size() == stateless_reset_token_size);
  CHECK(hex(frame->stateless_reset_token) == "000102030405060708090a0b0c0d0e0f");

  SUBCASE("retire prior to above the sequence number is a frame encoding error")
  {
    const auto bad = bytes({0x18, 0x01, 0x05, 0x04, 0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f});
    auto error = read_error(bad);
    REQUIRE(error.has_value());
    CHECK(error->code == transport_error_code_t::frame_encoding_error);
  }

  SUBCASE("a zero or oversized connection ID length is refused")
  {
    const auto zero_length = bytes({0x18, 0x02, 0x01, 0x00});
    const auto over_length = bytes({0x18, 0x02, 0x01, 0x15});
    CHECK(read_error(zero_length).has_value());
    CHECK(read_error(over_length).has_value());
  }

  SUBCASE("a missing reset token is refused")
  {
    const auto bad = bytes({0x18, 0x02, 0x01, 0x04, 0xaa, 0xbb, 0xcc, 0xdd, 0x00});
    CHECK(read_error(bad).has_value());
  }
}

TEST_CASE("PATH_CHALLENGE and PATH_RESPONSE carry eight fixed bytes")
{
  const auto challenge_input = bytes({0x1a, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08});
  auto challenge = read_one(challenge_input);
  REQUIRE(challenge.has_value());
  CHECK(challenge->kind == frame_kind_t::path_challenge);
  CHECK(challenge->path_data.size() == path_data_size);
  CHECK(hex(challenge->path_data) == "0102030405060708");

  const auto response_input = bytes({0x1b, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08});
  auto response = read_one(response_input);
  REQUIRE(response.has_value());
  CHECK(response->kind == frame_kind_t::path_response);
  CHECK(hex(response->path_data) == "0102030405060708");

  const auto truncated = bytes({0x1a, 0x01, 0x02, 0x03});
  CHECK(read_error(truncated).has_value());
}

TEST_CASE("CONNECTION_CLOSE differs between its two forms")
{
  const auto transport_input = bytes({0x1c, 0x0a, 0x06, 0x02, 0x68, 0x69});
  auto transport = read_one(transport_input);
  REQUIRE(transport.has_value());
  CHECK(transport->error_code == 0x0a);
  CHECK(transport->triggering_frame_type == 0x06);
  CHECK(hex(transport->data) == "6869");

  const auto application_input = bytes({0x1d, 0x0a, 0x02, 0x68, 0x69});
  auto application = read_one(application_input);
  REQUIRE(application.has_value());
  CHECK(application->error_code == 0x0a);
  CHECK(application->triggering_frame_type == 0);
  CHECK(hex(application->data) == "6869");

  SUBCASE("an empty reason phrase is fine")
  {
    const auto input = bytes({0x1d, 0x0a, 0x00});
    auto frame = read_one(input);
    REQUIRE(frame.has_value());
    CHECK(frame->data.empty());
  }

  SUBCASE("a reason phrase length past the end is refused")
  {
    const auto input = bytes({0x1d, 0x0a, 0x10, 0x68});
    CHECK(read_error(input).has_value());
  }
}

TEST_CASE("a frame in the wrong packet type is a protocol violation")
{
  const auto token = bytes({0x07, 0x02, 0xde, 0xad});
  auto error = read_error(token, packet_type_t::initial);
  REQUIRE(error.has_value());
  CHECK(error->code == transport_error_code_t::protocol_violation);

  const auto application_close = bytes({0x1d, 0x0a, 0x00});
  auto close_error = read_error(application_close, packet_type_t::handshake);
  REQUIRE(close_error.has_value());
  CHECK(close_error->code == transport_error_code_t::protocol_violation);

  const auto transport_close = bytes({0x1c, 0x0a, 0x06, 0x00});
  CHECK(read_one(transport_close, packet_type_t::handshake).has_value());

  SUBCASE("ACK is not permitted in 0-RTT")
  {
    const auto ack = bytes({0x02, 0x0a, 0x03, 0x00, 0x02});
    auto ack_error = read_error(ack, packet_type_t::zero_rtt);
    REQUIRE(ack_error.has_value());
    CHECK(ack_error->code == transport_error_code_t::protocol_violation);
  }

  SUBCASE("STREAM is not permitted in Initial")
  {
    const auto stream = bytes({0x08, 0x04, 0xaa});
    auto stream_error = read_error(stream, packet_type_t::initial);
    REQUIRE(stream_error.has_value());
    CHECK(stream_error->code == transport_error_code_t::protocol_violation);
  }

  SUBCASE("CRYPTO and PADDING and PING are permitted in Initial")
  {
    const auto crypto = bytes({0x06, 0x00, 0x01, 0xaa});
    const auto padding = bytes({0x00});
    const auto ping = bytes({0x01});
    CHECK(read_one(crypto, packet_type_t::initial).has_value());
    CHECK(read_one(padding, packet_type_t::initial).has_value());
    CHECK(read_one(ping, packet_type_t::initial).has_value());
  }
}

TEST_CASE("an unknown frame type is a connection error, not something to skip")
{
  const auto input = bytes({0x1f});
  auto error = read_error(input);
  REQUIRE(error.has_value());
  CHECK(error->code == transport_error_code_t::frame_encoding_error);
  CHECK(error->frame_type == 0x1f);

  SUBCASE("a multi-byte unknown type reports the decoded value")
  {
    const auto wide = bytes({0x40, 0x41});
    auto wide_error = read_error(wide);
    REQUIRE(wide_error.has_value());
    CHECK(wide_error->frame_type == 0x41);
  }
}

TEST_CASE("a packet of several frames reads back in order")
{
  const auto input = bytes({0x00, 0x00, 0x01, 0x06, 0x00, 0x03, 0xaa, 0xbb, 0xcc, 0x02, 0x0a, 0x03, 0x01, 0x02, 0x01, 0x04, 0x0f, 0x04, 0x40, 0xc8, 0x02, 0xaa, 0xbb, 0x1e});

  frame_reader_t reader(input, packet_type_t::one_rtt);
  std::vector<frame_kind_t> kinds;
  while (auto next = reader.next())
  {
    REQUIRE(next->has_value());
    kinds.push_back(next->value().kind);
  }
  CHECK(reader.done());
  CHECK(reader.position() == input.size());
  REQUIRE(kinds.size() == 6);
  CHECK(kinds[0] == frame_kind_t::padding);
  CHECK(kinds[1] == frame_kind_t::ping);
  CHECK(kinds[2] == frame_kind_t::crypto);
  CHECK(kinds[3] == frame_kind_t::ack);
  CHECK(kinds[4] == frame_kind_t::stream);
  CHECK(kinds[5] == frame_kind_t::handshake_done);
}

TEST_CASE("every prefix of a valid packet either parses or errors, never reads past the end")
{
  const auto full = bytes({0x01, 0x06, 0x00, 0x03, 0xaa, 0xbb, 0xcc, 0x02, 0x0a, 0x03, 0x01, 0x02, 0x01, 0x04, 0x0f, 0x04, 0x40, 0xc8, 0x02, 0xaa, 0xbb, 0x18, 0x02, 0x01, 0x04, 0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f});

  for (std::size_t length = 0; length <= full.size(); ++length)
  {
    CAPTURE(length);
    const std::vector<std::uint8_t> prefix(full.begin(), full.begin() + static_cast<std::ptrdiff_t>(length));
    frame_reader_t reader(prefix, packet_type_t::one_rtt);
    std::size_t guard = 0;
    while (auto next = reader.next())
    {
      if (!next->has_value())
      {
        break;
      }
      const auto &frame = next->value();
      for (auto view : {frame.data, frame.ack_ranges, frame.stateless_reset_token, frame.path_data})
      {
        if (!view.empty())
        {
          CHECK(view.data() >= prefix.data());
          CHECK(view.data() + view.size() <= prefix.data() + prefix.size());
        }
      }
      REQUIRE(++guard < 64);
    }
    CHECK(reader.position() <= prefix.size());
  }
}

TEST_CASE("every single-byte corruption of a valid packet is handled without reading past the end")
{
  const auto original = bytes({0x06, 0x00, 0x03, 0xaa, 0xbb, 0xcc, 0x02, 0x0a, 0x03, 0x01, 0x02, 0x01, 0x04, 0x0f, 0x04, 0x40, 0xc8, 0x02, 0xaa, 0xbb});

  for (std::size_t index = 0; index < original.size(); ++index)
  {
    for (int value = 0; value < 256; value += 17)
    {
      CAPTURE(index);
      CAPTURE(value);
      std::vector<std::uint8_t> mutated = original;
      mutated[index] = static_cast<std::uint8_t>(value);
      frame_reader_t reader(mutated, packet_type_t::one_rtt);
      std::size_t guard = 0;
      while (auto next = reader.next())
      {
        if (!next->has_value())
        {
          break;
        }
        const auto &frame = next->value();
        for (auto view : {frame.data, frame.ack_ranges, frame.stateless_reset_token, frame.path_data})
        {
          if (!view.empty())
          {
            REQUIRE(view.data() >= mutated.data());
            REQUIRE(view.data() + view.size() <= mutated.data() + mutated.size());
          }
        }
        REQUIRE(++guard < 4096);
      }
      REQUIRE(reader.position() <= mutated.size());
    }
  }
}

TEST_CASE("decoding a packet and re-encoding it reproduces the bytes")
{
  // Each vector uses minimal varints, which is what the writer emits, so the
  // round trip is byte for byte rather than merely equivalent.
  const std::vector<std::vector<std::uint8_t>> packets = {
    bytes({0x00, 0x00, 0x00, 0x00, 0x00}),
    bytes({0x01}),
    bytes({0x1e}),
    bytes({0x02, 0x0a, 0x03, 0x01, 0x02, 0x01, 0x04}),
    bytes({0x03, 0x0a, 0x03, 0x00, 0x02, 0x05, 0x06, 0x07}),
    bytes({0x04, 0x04, 0x0b, 0x40, 0xc8}),
    bytes({0x05, 0x08, 0x0b}),
    bytes({0x06, 0x00, 0x03, 0xaa, 0xbb, 0xcc}),
    bytes({0x06, 0x40, 0xc8, 0x02, 0xaa, 0xbb}),
    bytes({0x07, 0x02, 0xde, 0xad}),
    bytes({0x08, 0x04, 0xaa, 0xbb, 0xcc}),
    bytes({0x0a, 0x04, 0x02, 0xaa, 0xbb}),
    bytes({0x0f, 0x04, 0x40, 0xc8, 0x02, 0xaa, 0xbb}),
    bytes({0x10, 0x40, 0xc8}),
    bytes({0x11, 0x04, 0x40, 0xc8}),
    bytes({0x12, 0x40, 0x64}),
    bytes({0x13, 0x40, 0x64}),
    bytes({0x14, 0x40, 0xc8}),
    bytes({0x15, 0x04, 0x40, 0xc8}),
    bytes({0x16, 0x40, 0x64}),
    bytes({0x17, 0x40, 0x64}),
    bytes({0x18, 0x02, 0x01, 0x04, 0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}),
    bytes({0x19, 0x07}),
    bytes({0x1a, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}),
    bytes({0x1b, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}),
    bytes({0x1c, 0x0a, 0x06, 0x02, 0x68, 0x69}),
    bytes({0x1d, 0x0a, 0x02, 0x68, 0x69}),
    bytes({0x1d, 0x0a, 0x00}),
    bytes({0x00, 0x00, 0x01, 0x06, 0x00, 0x03, 0xaa, 0xbb, 0xcc, 0x02, 0x0a, 0x03, 0x01, 0x02, 0x01, 0x04, 0x0f, 0x04, 0x40, 0xc8, 0x02, 0xaa, 0xbb, 0x1e}),
  };

  for (const auto &packet : packets)
  {
    CAPTURE(hex(packet));
    std::vector<std::uint8_t> out(packet.size() + 32, 0xee);
    frame_writer_t writer(out);
    frame_reader_t reader(packet, packet_type_t::one_rtt);
    std::size_t expected = 0;
    while (auto next = reader.next())
    {
      REQUIRE(next->has_value());
      const auto &frame = next->value();
      expected += frame_encoded_size(frame);
      REQUIRE(writer.write(frame));
      CHECK(writer.written() == expected);
    }
    CHECK(hex(writer.bytes()) == hex(packet));
  }
}

TEST_CASE("frames built by hand survive a round trip")
{
  const auto payload = bytes({0xde, 0xad, 0xbe, 0xef});
  const auto token = bytes({0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10});
  const auto cid_bytes = bytes({0x11, 0x22, 0x33, 0x44, 0x55});
  auto cid = connection_id_t::from_bytes(cid_bytes);
  REQUIRE(cid.has_value());

  std::vector<std::uint8_t> out(512, 0);
  frame_writer_t writer(out);

  SUBCASE("STREAM with a large offset")
  {
    frame_t frame;
    frame.kind = frame_kind_t::stream;
    frame.stream_id = 1073741823;
    frame.offset = 4611686018427387000ULL;
    frame.fin = true;
    frame.data = payload;
    REQUIRE(writer.write(frame));
    CHECK(writer.written() == frame_encoded_size(frame));

    const std::vector<std::uint8_t> wire(writer.bytes().begin(), writer.bytes().end());
    auto decoded = read_one(wire);
    REQUIRE(decoded.has_value());
    CHECK(decoded->kind == frame_kind_t::stream);
    CHECK(decoded->stream_id == 1073741823);
    CHECK(decoded->offset == 4611686018427387000ULL);
    CHECK(decoded->fin);
    CHECK_FALSE(decoded->omit_length);
    CHECK(hex(decoded->data) == "deadbeef");
  }

  SUBCASE("NEW_CONNECTION_ID with a five byte id")
  {
    frame_t frame;
    frame.kind = frame_kind_t::new_connection_id;
    frame.sequence_number = 9;
    frame.retire_prior_to = 4;
    frame.connection_id = *cid;
    frame.stateless_reset_token = token;
    REQUIRE(writer.write(frame));
    CHECK(writer.written() == frame_encoded_size(frame));

    const std::vector<std::uint8_t> wire(writer.bytes().begin(), writer.bytes().end());
    auto decoded = read_one(wire);
    REQUIRE(decoded.has_value());
    CHECK(decoded->sequence_number == 9);
    CHECK(decoded->retire_prior_to == 4);
    CHECK(hex(decoded->connection_id.bytes()) == "1122334455");
    CHECK(hex(decoded->stateless_reset_token) == hex(token));
  }

  SUBCASE("an ACK assembled with ack_range_writer_t")
  {
    std::vector<std::uint8_t> range_buffer(64, 0);
    ack_range_writer_t ranges(range_buffer);
    REQUIRE(ranges.write(ack_range_t{.gap = 3, .length = 7}));
    REQUIRE(ranges.write(ack_range_t{.gap = 1000, .length = 2}));

    frame_t frame;
    frame.kind = frame_kind_t::ack;
    frame.largest_acknowledged = 100000;
    frame.ack_delay = 512;
    frame.first_ack_range = 5;
    frame.ack_range_count = ranges.count();
    frame.ack_ranges = ranges.bytes();
    frame.ecn = ecn_counts_t{.ect0 = 1, .ect1 = 2, .ce = 3};
    REQUIRE(writer.write(frame));
    CHECK(writer.written() == frame_encoded_size(frame));

    const std::vector<std::uint8_t> wire(writer.bytes().begin(), writer.bytes().end());
    auto decoded = read_one(wire);
    REQUIRE(decoded.has_value());
    CHECK(decoded->largest_acknowledged == 100000);
    CHECK(decoded->ack_delay == 512);
    CHECK(decoded->first_ack_range == 5);
    CHECK(decoded->ack_range_count == 2);
    REQUIRE(decoded->ecn.has_value());
    CHECK(decoded->ecn->ect0 == 1);
    CHECK(decoded->ecn->ce == 3);

    ack_range_reader_t back(decoded->ack_ranges);
    auto first = back.next();
    REQUIRE(first.has_value());
    CHECK(first->gap == 3);
    CHECK(first->length == 7);
    auto second = back.next();
    REQUIRE(second.has_value());
    CHECK(second->gap == 1000);
    CHECK(second->length == 2);
    CHECK_FALSE(back.next().has_value());
  }

  SUBCASE("CONNECTION_CLOSE keeps its form across the round trip")
  {
    frame_t transport;
    transport.kind = frame_kind_t::connection_close;
    transport.error_code = 0x0a;
    transport.triggering_frame_type = 0x18;
    transport.data = payload;
    REQUIRE(writer.write(transport));

    frame_t application;
    application.kind = frame_kind_t::connection_close;
    application.application_error = true;
    application.error_code = 0x0102;
    application.data = payload;
    REQUIRE(writer.write(application));

    const std::vector<std::uint8_t> wire(writer.bytes().begin(), writer.bytes().end());
    frame_reader_t reader(wire, packet_type_t::one_rtt);
    auto first = reader.next();
    REQUIRE(first.has_value());
    REQUIRE(first->has_value());
    CHECK_FALSE(first->value().application_error);
    CHECK(first->value().triggering_frame_type == 0x18);
    auto second = reader.next();
    REQUIRE(second.has_value());
    REQUIRE(second->has_value());
    CHECK(second->value().application_error);
    CHECK(second->value().error_code == 0x0102);
    CHECK(reader.done());
  }
}

TEST_CASE("a frame that does not fit leaves the buffer untouched")
{
  const auto payload = bytes({0xde, 0xad, 0xbe, 0xef});
  frame_t frame;
  frame.kind = frame_kind_t::crypto;
  frame.offset = 200;
  frame.data = payload;
  const std::size_t size = frame_encoded_size(frame);

  for (std::size_t capacity = 0; capacity < size; ++capacity)
  {
    CAPTURE(capacity);
    std::vector<std::uint8_t> out(capacity, 0xee);
    const std::vector<std::uint8_t> before = out;
    frame_writer_t writer(out);
    CHECK_FALSE(writer.write(frame));
    CHECK(writer.written() == 0);
    CHECK(out == before);
  }

  std::vector<std::uint8_t> exact(size, 0xee);
  frame_writer_t writer(exact);
  CHECK(writer.write(frame));
  CHECK(writer.written() == size);

  SUBCASE("a rejected frame does not disturb what was already written")
  {
    std::vector<std::uint8_t> out(size, 0xee);
    frame_writer_t partial(out);
    frame_t ping;
    ping.kind = frame_kind_t::ping;
    REQUIRE(partial.write(ping));
    CHECK_FALSE(partial.write(frame));
    CHECK(partial.written() == 1);
    CHECK(hex(partial.bytes()) == "01");
  }
}

TEST_CASE("the writer refuses frames the decoder would reject")
{
  std::vector<std::uint8_t> out(512, 0);
  const auto token = bytes({0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10});
  const auto short_token = bytes({0x01, 0x02});

  SUBCASE("an empty NEW_TOKEN")
  {
    frame_writer_t writer(out);
    frame_t frame;
    frame.kind = frame_kind_t::new_token;
    CHECK_FALSE(writer.write(frame));
  }

  SUBCASE("a stream count above 2^60")
  {
    frame_writer_t writer(out);
    frame_t frame;
    frame.kind = frame_kind_t::max_streams;
    frame.bidirectional = true;
    frame.maximum = max_stream_count + 1;
    CHECK_FALSE(writer.write(frame));
  }

  SUBCASE("NEW_CONNECTION_ID retiring more than it issues")
  {
    frame_writer_t writer(out);
    const auto cid_bytes = bytes({0xaa});
    auto cid = connection_id_t::from_bytes(cid_bytes);
    REQUIRE(cid.has_value());
    frame_t frame;
    frame.kind = frame_kind_t::new_connection_id;
    frame.sequence_number = 1;
    frame.retire_prior_to = 2;
    frame.connection_id = *cid;
    frame.stateless_reset_token = token;
    CHECK_FALSE(writer.write(frame));
  }

  SUBCASE("NEW_CONNECTION_ID with an empty id or a short reset token")
  {
    frame_writer_t writer(out);
    const auto cid_bytes = bytes({0xaa});
    auto cid = connection_id_t::from_bytes(cid_bytes);
    REQUIRE(cid.has_value());

    frame_t empty_id;
    empty_id.kind = frame_kind_t::new_connection_id;
    empty_id.stateless_reset_token = token;
    CHECK_FALSE(writer.write(empty_id));

    frame_t short_reset;
    short_reset.kind = frame_kind_t::new_connection_id;
    short_reset.connection_id = *cid;
    short_reset.stateless_reset_token = short_token;
    CHECK_FALSE(writer.write(short_reset));
  }

  SUBCASE("PATH_CHALLENGE without eight bytes")
  {
    frame_writer_t writer(out);
    frame_t frame;
    frame.kind = frame_kind_t::path_challenge;
    frame.path_data = short_token;
    CHECK_FALSE(writer.write(frame));
  }

  SUBCASE("a STREAM whose offset plus length exceeds 2^62-1")
  {
    frame_writer_t writer(out);
    const auto payload = bytes({0xaa, 0xbb});
    frame_t frame;
    frame.kind = frame_kind_t::stream;
    frame.stream_id = 4;
    frame.offset = varint_max;
    frame.data = payload;
    CHECK_FALSE(writer.write(frame));
  }
}
}
