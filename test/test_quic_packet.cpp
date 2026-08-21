#include <cstdint>
#include <initializer_list>
#include <optional>
#include <ostream>
#include <span>
#include <string>
#include <vector>
#include <doctest/doctest.h>
#include <vio/crypto.h>
#include <vio/quic/packet.h>

// Packet layouts are from RFC 9000 section 17, read from the raw RFC text; the
// header protection offsets are from RFC 9001 section 5.4.2.
//
// Nothing here is authenticated yet, so the interesting half of this file is
// the malformed input: every one of those cases has to end in a discard rather
// than a read past the buffer or a connection error.

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

std::vector<std::uint8_t> filled(std::size_t count, std::uint8_t value)
{
  return std::vector<std::uint8_t>(count, value);
}

std::string hex(std::span<const std::uint8_t> data)
{
  return vio::crypto::to_hex(data);
}

connection_id_t make_id(std::initializer_list<int> values)
{
  const auto raw = bytes(values);
  auto id = connection_id_t::from_bytes(raw);
  REQUIRE(id.has_value());
  return *id;
}

// Builds one packet into out and fakes the AEAD by leaving the expansion
// bytes as they lie: the reader only ever looks at lengths.
struct built_t
{
  packet_layout_t layout;
  std::size_t total = 0;
};

built_t build_long(std::span<std::uint8_t> out, packet_kind_t kind, const connection_id_t &destination, const connection_id_t &source, std::span<const std::uint8_t> token, std::uint64_t packet_number, std::size_t frame_bytes)
{
  packet_builder_t builder(out);
  REQUIRE(builder.begin_long(kind, quic_version_1, destination, source, token, packet_number, std::nullopt));
  auto payload = builder.payload_buffer();
  REQUIRE(payload.size() >= frame_bytes);
  for (std::size_t i = 0; i < frame_bytes; ++i)
  {
    payload[i] = static_cast<std::uint8_t>(0xa0 + (i & 0x0f));
  }
  auto layout = builder.finish(frame_bytes);
  REQUIRE(layout.has_value());
  return built_t{.layout = *layout, .total = layout->packet_length};
}

built_t build_short(std::span<std::uint8_t> out, const connection_id_t &destination, std::uint64_t packet_number, std::size_t frame_bytes)
{
  packet_builder_t builder(out);
  REQUIRE(builder.begin_short(destination, false, false, packet_number, std::nullopt));
  auto payload = builder.payload_buffer();
  REQUIRE(payload.size() >= frame_bytes);
  for (std::size_t i = 0; i < frame_bytes; ++i)
  {
    payload[i] = static_cast<std::uint8_t>(0xb0 + (i & 0x0f));
  }
  auto layout = builder.finish(frame_bytes);
  REQUIRE(layout.has_value());
  return built_t{.layout = *layout, .total = layout->packet_length};
}

std::optional<packet_header_t> read_one(const std::vector<std::uint8_t> &datagram, std::size_t local_id_length)
{
  packet_reader_t reader(datagram, local_id_length);
  auto next = reader.next();
  if (!next.has_value() || !next->has_value())
  {
    return std::nullopt;
  }
  return next->value();
}

std::optional<packet_discard_t> read_discard(const std::vector<std::uint8_t> &datagram, std::size_t local_id_length)
{
  packet_reader_t reader(datagram, local_id_length);
  auto next = reader.next();
  if (!next.has_value() || next->has_value())
  {
    return std::nullopt;
  }
  return next->error();
}
} // namespace

TEST_SUITE("quic packet")
{
TEST_CASE("a long header round trips through the builder and the reader")
{
  const auto destination = make_id({0x01, 0x02, 0x03, 0x04});
  const auto source = make_id({0x05, 0x06, 0x07, 0x08, 0x09});
  const auto token = bytes({0xde, 0xad, 0xbe, 0xef});

  std::vector<std::uint8_t> datagram(256, 0xcc);
  const auto built = build_long(datagram, packet_kind_t::initial, destination, source, token, 7, 24);
  datagram.resize(built.total);

  auto header = read_one(datagram, 0);
  REQUIRE(header.has_value());
  CHECK(header->kind == packet_kind_t::initial);
  CHECK(header->version == quic_version_1);
  CHECK(header->destination_id == destination);
  CHECK(header->source_id == source);
  CHECK(hex(header->token) == "deadbeef");
  CHECK(header->packet.size() == built.total);
  CHECK(header->packet_number_offset == built.layout.packet_number_offset);
  CHECK(header->has_packet_number());

  SUBCASE("the packet number offset matches the RFC 9001 pseudocode")
  {
    // pn_offset = 7 + dcid + scid + len(length), plus the token fields for an
    // Initial packet. The builder reserves two bytes for Length.
    const std::size_t expected = 7 + destination.size() + source.size() + 2 + 1 + token.size();
    CHECK(header->packet_number_offset == expected);
  }

  SUBCASE("the sample sits four bytes past the packet number")
  {
    auto sample = header->header_protection_sample();
    CHECK(sample.size() == header_protection_sample_size);
    CHECK(sample.data() == header->packet.data() + header->packet_number_offset + 4);
  }

  SUBCASE("an Initial with no token writes a zero length")
  {
    std::vector<std::uint8_t> empty_token_datagram(256, 0xcc);
    const auto empty = build_long(empty_token_datagram, packet_kind_t::initial, destination, source, {}, 7, 24);
    empty_token_datagram.resize(empty.total);
    auto parsed = read_one(empty_token_datagram, 0);
    REQUIRE(parsed.has_value());
    CHECK(parsed->token.empty());
  }

  SUBCASE("0-RTT and Handshake carry no token field at all")
  {
    for (auto kind : {packet_kind_t::zero_rtt, packet_kind_t::handshake})
    {
      std::vector<std::uint8_t> other(256, 0xcc);
      const auto made = build_long(other, kind, destination, source, {}, 7, 24);
      other.resize(made.total);
      auto parsed = read_one(other, 0);
      REQUIRE(parsed.has_value());
      CHECK(parsed->kind == kind);
      CHECK(parsed->packet_number_offset == 7 + destination.size() + source.size() + 2);
    }
  }
}

TEST_CASE("a short header round trips and needs the local connection id length")
{
  const auto destination = make_id({0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88});

  std::vector<std::uint8_t> datagram(128, 0xcc);
  const auto built = build_short(datagram, destination, 42, 24);
  datagram.resize(built.total);

  auto header = read_one(datagram, destination.size());
  REQUIRE(header.has_value());
  CHECK(header->kind == packet_kind_t::one_rtt);
  CHECK(header->destination_id == destination);
  // pn_offset = 1 + len(connection_id).
  CHECK(header->packet_number_offset == 1 + destination.size());
  CHECK(header->packet.size() == datagram.size());

  SUBCASE("there is no length prefix on the connection id")
  {
    CHECK(hex(std::span<const std::uint8_t>(datagram).subspan(1, destination.size())) == hex(destination.bytes()));
  }

  SUBCASE("the fixed bit is set and the reserved bits are clear")
  {
    CHECK((datagram[0] & header_form_long) == 0);
    CHECK((datagram[0] & header_fixed_bit) != 0);
    CHECK((datagram[0] & short_reserved_mask) == 0);
  }

  SUBCASE("key phase and spin bit are carried in the first byte")
  {
    std::vector<std::uint8_t> other(128, 0xcc);
    packet_builder_t builder(other);
    REQUIRE(builder.begin_short(destination, true, true, 42, std::nullopt));
    REQUIRE(builder.finish(24).has_value());
    CHECK((other[0] & short_key_phase_bit) != 0);
    CHECK((other[0] & short_spin_bit) != 0);
  }

  SUBCASE("reading it with the wrong id length lands somewhere else entirely")
  {
    // Not an error the reader can detect -- there is nothing on the wire that
    // says how long the field is -- which is exactly why the length has to
    // come from the endpoint that issued the id.
    auto wrong = read_one(datagram, destination.size() - 2);
    REQUIRE(wrong.has_value());
    CHECK_FALSE(wrong->destination_id == destination);
  }
}

TEST_CASE("coalesced packets in one datagram read back in order")
{
  const auto destination = make_id({0x01, 0x02, 0x03, 0x04});
  const auto source = make_id({0x0a, 0x0b});

  std::vector<std::uint8_t> datagram(512, 0xcc);
  std::size_t offset = 0;
  const auto initial = build_long(std::span<std::uint8_t>(datagram).subspan(offset), packet_kind_t::initial, destination, source, {}, 1, 20);
  offset += initial.total;
  const auto handshake = build_long(std::span<std::uint8_t>(datagram).subspan(offset), packet_kind_t::handshake, destination, source, {}, 2, 30);
  offset += handshake.total;
  const auto one_rtt = build_short(std::span<std::uint8_t>(datagram).subspan(offset), destination, 3, 25);
  offset += one_rtt.total;
  datagram.resize(offset);

  packet_reader_t reader(datagram, destination.size());
  std::vector<packet_kind_t> kinds;
  while (auto next = reader.next())
  {
    REQUIRE(next->has_value());
    kinds.push_back(next->value().kind);
  }
  REQUIRE(kinds.size() == 3);
  CHECK(kinds[0] == packet_kind_t::initial);
  CHECK(kinds[1] == packet_kind_t::handshake);
  CHECK(kinds[2] == packet_kind_t::one_rtt);
  CHECK(reader.done());

  SUBCASE("each packet reports only its own bytes")
  {
    packet_reader_t again(datagram, destination.size());
    auto first = again.next();
    REQUIRE(first.has_value());
    REQUIRE(first->has_value());
    CHECK(first->value().packet.size() == initial.total);
    CHECK(first->value().packet.data() == datagram.data());
    auto second = again.next();
    REQUIRE(second.has_value());
    REQUIRE(second->has_value());
    CHECK(second->value().packet.size() == handshake.total);
    CHECK(second->value().packet.data() == datagram.data() + initial.total);
  }
}

TEST_CASE("a malformed packet ends the walk rather than resynchronising")
{
  const auto destination = make_id({0x01, 0x02, 0x03, 0x04});
  const auto source = make_id({0x0a, 0x0b});

  std::vector<std::uint8_t> datagram(512, 0xcc);
  std::size_t offset = 0;
  const auto first = build_long(std::span<std::uint8_t>(datagram).subspan(offset), packet_kind_t::initial, destination, source, {}, 1, 20);
  offset += first.total;
  const auto second = build_long(std::span<std::uint8_t>(datagram).subspan(offset), packet_kind_t::handshake, destination, source, {}, 2, 30);
  offset += second.total;
  datagram.resize(offset);

  // Clear the fixed bit on the second packet.
  datagram[first.total] = static_cast<std::uint8_t>(datagram[first.total] & ~header_fixed_bit);

  packet_reader_t reader(datagram, destination.size());
  auto one = reader.next();
  REQUIRE(one.has_value());
  CHECK(one->has_value());
  auto two = reader.next();
  REQUIRE(two.has_value());
  REQUIRE_FALSE(two->has_value());
  CHECK(two->error() == packet_discard_t::fixed_bit_clear);
  CHECK(reader.done());
  CHECK_FALSE(reader.next().has_value());
}

TEST_CASE("headers that cannot be trusted are discarded")
{
  const auto destination = make_id({0x01, 0x02, 0x03, 0x04});
  const auto source = make_id({0x0a, 0x0b});
  std::vector<std::uint8_t> scratch(256, 0xcc);
  const auto built = build_long(scratch, packet_kind_t::initial, destination, source, {}, 1, 24);
  const std::vector<std::uint8_t> good(scratch.begin(), scratch.begin() + static_cast<std::ptrdiff_t>(built.total));

  SUBCASE("a clear fixed bit on a long header")
  {
    auto bad = good;
    bad[0] = static_cast<std::uint8_t>(bad[0] & ~header_fixed_bit);
    CHECK(read_discard(bad, 0) == packet_discard_t::fixed_bit_clear);
  }

  SUBCASE("a clear fixed bit on a short header")
  {
    const auto bad = bytes({0x00, 0x01, 0x02, 0x03, 0x04});
    CHECK(read_discard(bad, 4) == packet_discard_t::fixed_bit_clear);
  }

  SUBCASE("a connection id longer than version 1 allows")
  {
    auto bad = good;
    bad[5] = 21;
    CHECK(read_discard(bad, 0) == packet_discard_t::connection_id_too_long);

    auto bad_source = good;
    bad_source[5 + 1 + destination.size()] = 21;
    CHECK(read_discard(bad_source, 0) == packet_discard_t::connection_id_too_long);
  }

  SUBCASE("a version this build does not speak")
  {
    auto bad = good;
    bad[1] = 0xff;
    bad[2] = 0x00;
    bad[3] = 0x00;
    bad[4] = 0x1d;
    CHECK(read_discard(bad, 0) == packet_discard_t::unsupported_version);

    // The version outranks every version 1 rule below it, so neither a clear
    // fixed bit nor an oversized connection ID may mask it.
    auto no_fixed = bad;
    no_fixed[0] = static_cast<std::uint8_t>(no_fixed[0] & ~header_fixed_bit);
    CHECK(read_discard(no_fixed, 0) == packet_discard_t::unsupported_version);

    auto long_id = bad;
    long_id[5] = 21;
    CHECK(read_discard(long_id, 0) == packet_discard_t::unsupported_version);
  }

  SUBCASE("a Length that runs past the end of the datagram")
  {
    auto bad = good;
    const std::size_t length_offset = 7 + destination.size() + source.size() + 1;
    bad[length_offset] = 0x7f;
    bad[length_offset + 1] = 0xff;
    CHECK(read_discard(bad, 0) == packet_discard_t::truncated);
  }

  SUBCASE("a packet too short to hold a header protection sample")
  {
    auto bad = good;
    const std::size_t length_offset = 7 + destination.size() + source.size() + 1;
    bad[length_offset] = 0x40;
    bad[length_offset + 1] = 0x05;
    CHECK(read_discard(bad, 0) == packet_discard_t::sample_too_short);

    const auto tiny_short = bytes({0x40, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06});
    CHECK(read_discard(tiny_short, 4) == packet_discard_t::sample_too_short);
  }

  SUBCASE("every prefix either parses or discards, and never reads past the end")
  {
    for (std::size_t length = 1; length <= good.size(); ++length)
    {
      CAPTURE(length);
      const std::vector<std::uint8_t> prefix(good.begin(), good.begin() + static_cast<std::ptrdiff_t>(length));
      packet_reader_t reader(prefix, 4);
      std::size_t guard = 0;
      while (auto next = reader.next())
      {
        if (!next->has_value())
        {
          break;
        }
        const auto &header = next->value();
        REQUIRE(header.packet.data() >= prefix.data());
        REQUIRE(header.packet.data() + header.packet.size() <= prefix.data() + prefix.size());
        REQUIRE(header.packet_number_offset <= header.packet.size());
        if (header.has_packet_number())
        {
          auto sample = header.header_protection_sample();
          REQUIRE(sample.data() + sample.size() <= prefix.data() + prefix.size());
        }
        REQUIRE(++guard < 16);
      }
      CHECK(reader.position() <= prefix.size());
    }
  }

  SUBCASE("every single byte corruption is handled without reading past the end")
  {
    for (std::size_t index = 0; index < good.size(); ++index)
    {
      for (int value = 0; value < 256; value += 23)
      {
        CAPTURE(index);
        CAPTURE(value);
        std::vector<std::uint8_t> mutated = good;
        mutated[index] = static_cast<std::uint8_t>(value);
        packet_reader_t reader(mutated, 4);
        std::size_t guard = 0;
        while (auto next = reader.next())
        {
          if (!next->has_value())
          {
            break;
          }
          const auto &header = next->value();
          REQUIRE(header.packet.data() >= mutated.data());
          REQUIRE(header.packet.data() + header.packet.size() <= mutated.data() + mutated.size());
          if (header.has_packet_number())
          {
            auto sample = header.header_protection_sample();
            REQUIRE(sample.data() + sample.size() <= mutated.data() + mutated.size());
          }
          REQUIRE(++guard < 16);
        }
        REQUIRE(reader.position() <= mutated.size());
      }
    }
  }
}

TEST_CASE("Version Negotiation round trips")
{
  const auto destination = bytes({0x01, 0x02, 0x03, 0x04});
  const auto source = bytes({0x0a, 0x0b, 0x0c});
  const std::vector<std::uint32_t> versions = {quic_version_1, 0xff00001dU};

  std::vector<std::uint8_t> datagram(128, 0xcc);
  const std::size_t written = serialize_version_negotiation(datagram, destination, source, versions);
  REQUIRE(written > 0);
  datagram.resize(written);

  auto header = read_one(datagram, 0);
  REQUIRE(header.has_value());
  CHECK(header->kind == packet_kind_t::version_negotiation);
  CHECK(header->version == quic_version_negotiation);
  CHECK(hex(header->destination_id.bytes()) == "01020304");
  CHECK(hex(header->source_id.bytes()) == "0a0b0c");
  CHECK(header->supported_versions.size() == 8);
  CHECK(hex(header->supported_versions) == "00000001ff00001d");
  CHECK_FALSE(header->has_packet_number());

  SUBCASE("a version list that is not a whole number of versions is refused")
  {
    auto bad = datagram;
    bad.pop_back();
    CHECK(read_discard(bad, 0) == packet_discard_t::invalid_length);
  }

  SUBCASE("an empty version list is refused")
  {
    std::vector<std::uint8_t> empty(datagram.begin(), datagram.end() - 8);
    CHECK(read_discard(empty, 0) == packet_discard_t::invalid_length);
  }

  SUBCASE("the fixed bit is not required, since those seven bits are unused")
  {
    auto no_fixed = datagram;
    no_fixed[0] = static_cast<std::uint8_t>(no_fixed[0] & ~header_fixed_bit);
    auto parsed = read_one(no_fixed, 0);
    REQUIRE(parsed.has_value());
    CHECK(parsed->kind == packet_kind_t::version_negotiation);
  }
}

TEST_CASE("the invariant header reads connection ids version 1 could not hold")
{
  // A server has to echo the connection IDs of a version it does not speak,
  // and those may be up to 255 bytes.
  const auto long_id = filled(40, 0xab);
  std::vector<std::uint8_t> datagram;
  datagram.push_back(header_form_long | header_fixed_bit);
  datagram.insert(datagram.end(), {0xff, 0x00, 0x00, 0x1d});
  datagram.push_back(static_cast<std::uint8_t>(long_id.size()));
  datagram.insert(datagram.end(), long_id.begin(), long_id.end());
  datagram.push_back(0x02);
  datagram.insert(datagram.end(), {0xaa, 0xbb});

  auto invariant = parse_invariant_header(datagram);
  REQUIRE(invariant.has_value());
  CHECK(invariant->long_header);
  CHECK(invariant->version == 0xff00001dU);
  CHECK(invariant->destination_id.size() == 40);
  CHECK(hex(invariant->source_id) == "aabb");

  // The version 1 reader refuses the same bytes, and says why in the one way
  // that lets a server answer with Version Negotiation rather than drop them:
  // the oversized connection ID is not the reason, the version is.
  CHECK(read_discard(datagram, 0) == packet_discard_t::unsupported_version);

  SUBCASE("the echoed ids serialize back into a Version Negotiation packet")
  {
    const std::vector<std::uint32_t> versions = {quic_version_1};
    std::vector<std::uint8_t> out(256, 0);
    const std::size_t written = serialize_version_negotiation(out, invariant->source_id, invariant->destination_id, versions);
    REQUIRE(written > 0);
    out.resize(written);
    auto echoed = parse_invariant_header(out);
    REQUIRE(echoed.has_value());
    CHECK(echoed->version == quic_version_negotiation);
    CHECK(hex(echoed->destination_id) == "aabb");
    CHECK(echoed->source_id.size() == 40);
  }

  SUBCASE("a short header yields only the header form")
  {
    const auto short_datagram = bytes({0x40, 0x01, 0x02});
    auto parsed = parse_invariant_header(short_datagram);
    REQUIRE(parsed.has_value());
    CHECK_FALSE(parsed->long_header);
    CHECK(parsed->destination_id.empty());
  }

  SUBCASE("a truncated long header yields nothing")
  {
    for (std::size_t length = 1; length < datagram.size(); ++length)
    {
      CAPTURE(length);
      const std::vector<std::uint8_t> prefix(datagram.begin(), datagram.begin() + static_cast<std::ptrdiff_t>(length));
      auto parsed = parse_invariant_header(prefix);
      if (parsed.has_value() && parsed->long_header)
      {
        REQUIRE(parsed->destination_id.data() + parsed->destination_id.size() <= prefix.data() + prefix.size());
        REQUIRE(parsed->source_id.data() + parsed->source_id.size() <= prefix.data() + prefix.size());
      }
    }
  }
}

TEST_CASE("Retry round trips")
{
  const auto destination = make_id({0x01, 0x02, 0x03, 0x04});
  const auto source = make_id({0x0a, 0x0b, 0x0c, 0x0d, 0x0e});
  const auto token = bytes({0x74, 0x6f, 0x6b, 0x65, 0x6e});
  const auto tag = filled(retry_integrity_tag_size, 0x5a);

  std::vector<std::uint8_t> datagram(128, 0xcc);
  const std::size_t written = serialize_retry(datagram, quic_version_1, destination, source, token);
  REQUIRE(written > 0);
  for (std::size_t i = 0; i < tag.size(); ++i)
  {
    datagram[written + i] = tag[i];
  }
  datagram.resize(written + tag.size());

  auto header = read_one(datagram, 0);
  REQUIRE(header.has_value());
  CHECK(header->kind == packet_kind_t::retry);
  CHECK(header->destination_id == destination);
  CHECK(header->source_id == source);
  CHECK(hex(header->retry_token) == "746f6b656e");
  CHECK(hex(header->retry_integrity_tag) == hex(tag));
  CHECK_FALSE(header->has_packet_number());

  SUBCASE("a Retry with no room for the integrity tag is discarded")
  {
    std::vector<std::uint8_t> bad(datagram.begin(), datagram.begin() + static_cast<std::ptrdiff_t>(written) - 1);
    CHECK(read_discard(bad, 0) == packet_discard_t::truncated);
  }

  SUBCASE("an empty token leaves the tag alone")
  {
    std::vector<std::uint8_t> other(128, 0xcc);
    const std::size_t head = serialize_retry(other, quic_version_1, destination, source, {});
    REQUIRE(head > 0);
    for (std::size_t i = 0; i < tag.size(); ++i)
    {
      other[head + i] = tag[i];
    }
    other.resize(head + tag.size());
    auto parsed = read_one(other, 0);
    REQUIRE(parsed.has_value());
    CHECK(parsed->retry_token.empty());
    CHECK(hex(parsed->retry_integrity_tag) == hex(tag));
  }
}

TEST_CASE("the builder refuses what it cannot encode")
{
  const auto destination = make_id({0x01, 0x02, 0x03, 0x04});
  const auto source = make_id({0x0a, 0x0b});

  SUBCASE("a buffer too small for the header")
  {
    std::vector<std::uint8_t> tiny(8, 0);
    packet_builder_t builder(tiny);
    CHECK_FALSE(builder.begin_long(packet_kind_t::initial, quic_version_1, destination, source, {}, 1, std::nullopt));
  }

  SUBCASE("Retry and Version Negotiation are not builder packets")
  {
    std::vector<std::uint8_t> out(256, 0);
    packet_builder_t builder(out);
    CHECK_FALSE(builder.begin_long(packet_kind_t::retry, quic_version_1, destination, source, {}, 1, std::nullopt));
    CHECK_FALSE(builder.begin_long(packet_kind_t::version_negotiation, quic_version_1, destination, source, {}, 1, std::nullopt));
    CHECK_FALSE(builder.begin_long(packet_kind_t::one_rtt, quic_version_1, destination, source, {}, 1, std::nullopt));
  }

  SUBCASE("finish before begin")
  {
    std::vector<std::uint8_t> out(256, 0);
    packet_builder_t builder(out);
    CHECK_FALSE(builder.finish(20).has_value());
  }

  SUBCASE("too few frame bytes to sample header protection")
  {
    std::vector<std::uint8_t> out(256, 0);
    packet_builder_t builder(out);
    REQUIRE(builder.begin_short(destination, false, false, 1, std::nullopt));
    const std::size_t minimum = builder.minimum_frame_bytes();
    // A one byte packet number plus a sixteen byte expansion leaves three
    // bytes of frames to reach the twenty the sample needs.
    CHECK(minimum == 3);
    if (minimum > 0)
    {
      CHECK_FALSE(builder.finish(minimum - 1).has_value());
    }
    CHECK(builder.finish(minimum).has_value());
  }

  SUBCASE("more frame bytes than the buffer holds")
  {
    std::vector<std::uint8_t> out(64, 0);
    packet_builder_t builder(out);
    REQUIRE(builder.begin_short(destination, false, false, 1, std::nullopt));
    const std::size_t maximum = builder.maximum_frame_bytes();
    CHECK(maximum == out.size() - (1 + destination.size() + 1) - default_aead_expansion);
    CHECK(builder.finish(maximum).has_value());
    CHECK_FALSE(builder.finish(maximum + 1).has_value());
  }

  SUBCASE("a packet longer than the reserved Length field can express")
  {
    std::vector<std::uint8_t> out(max_reserved_length_field + 64, 0);
    packet_builder_t builder(out);
    REQUIRE(builder.begin_long(packet_kind_t::handshake, quic_version_1, destination, source, {}, 1, std::nullopt));
    CHECK_FALSE(builder.finish(max_reserved_length_field).has_value());
  }
}

TEST_CASE("the Length field covers the packet number and the protected payload")
{
  const auto destination = make_id({0x01, 0x02, 0x03, 0x04});
  const auto source = make_id({0x0a, 0x0b});

  for (std::size_t frame_bytes : {4u, 20u, 100u})
  {
    CAPTURE(frame_bytes);
    std::vector<std::uint8_t> out(256, 0);
    packet_builder_t builder(out);
    REQUIRE(builder.begin_long(packet_kind_t::handshake, quic_version_1, destination, source, {}, 1, std::nullopt));
    auto layout = builder.finish(frame_bytes);
    REQUIRE(layout.has_value());

    const std::size_t length_offset = 7 + destination.size() + source.size();
    const std::uint64_t encoded = ((static_cast<std::uint64_t>(out[length_offset]) & 0x3f) << 8) | out[length_offset + 1];
    CHECK(encoded == layout->packet_number_length + frame_bytes + default_aead_expansion);
    CHECK(layout->header_length == layout->packet_number_offset + layout->packet_number_length);
    CHECK(layout->packet_length == layout->header_length + frame_bytes + default_aead_expansion);
  }
}

TEST_CASE("packet kinds map onto the frame table")
{
  CHECK(frame_packet_type(packet_kind_t::initial) == packet_type_t::initial);
  CHECK(frame_packet_type(packet_kind_t::zero_rtt) == packet_type_t::zero_rtt);
  CHECK(frame_packet_type(packet_kind_t::handshake) == packet_type_t::handshake);
  CHECK(frame_packet_type(packet_kind_t::one_rtt) == packet_type_t::one_rtt);
  CHECK_FALSE(frame_packet_type(packet_kind_t::retry).has_value());
  CHECK_FALSE(frame_packet_type(packet_kind_t::version_negotiation).has_value());
}
}
