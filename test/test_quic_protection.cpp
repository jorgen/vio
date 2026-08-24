#include <array>
#include <cstdint>
#include <optional>
#include <ostream>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include <doctest/doctest.h>
#include <vio/crypto.h>
#include <vio/quic/protection.h>

#include "quic_rfc9001_vectors.h"

// The first point in this stack where the bytes can be checked against
// someone else's. Everything below has only ever been tested against itself,
// so a shared misreading of the RFC would have passed; these vectors are the
// answer key.

namespace
{
using namespace vio::quic;
namespace v = vio::quic::rfc9001;

std::vector<std::uint8_t> from_hex(std::string_view text)
{
  std::vector<std::uint8_t> out;
  out.reserve(text.size() / 2);
  const auto digit = [](char c) -> int { return c >= 'a' ? c - 'a' + 10 : c - '0'; };
  for (std::size_t i = 0; i + 1 < text.size(); i += 2)
  {
    out.push_back(static_cast<std::uint8_t>((digit(text[i]) << 4) | digit(text[i + 1])));
  }
  return out;
}

std::string hex(std::span<const std::uint8_t> data)
{
  return vio::crypto::to_hex(data);
}
} // namespace

TEST_SUITE("quic protection")
{
TEST_CASE("RFC 9369 A.1: version 2 derives its own Initial keys")
{
  // Same connection id as the version 1 vector above, which is the point: the
  // salt and the labels are what differ, so a version 2 endpoint and a version
  // 1 one never arrive at the same keys for the same handshake.
  const auto connection_id = from_hex("8394c8f03e515708");
  auto secrets = derive_initial_secrets(connection_id, quic_version_2);
  REQUIRE(secrets.has_value());

  auto client = derive_key_material(tls_aes_128_gcm_sha256, secrets->client, quic_version_2);
  REQUIRE(client.has_value());
  CHECK(hex(client->key) == "8b1a0bc121284290a29e0971b5cd045d");
  CHECK(hex(client->iv) == "91f73e2351d8fa91660e909f");
  CHECK(hex(client->header_protection) == "45b95e15235d6f45a6b19cbcb0294ba9");

  auto server = derive_key_material(tls_aes_128_gcm_sha256, secrets->server, quic_version_2);
  REQUIRE(server.has_value());
  CHECK(hex(server->key) == "82db637861d55e1d011f19ea71d5d2a7");
  CHECK(hex(server->iv) == "dd13c276499c0249d3310652");
  CHECK(hex(server->header_protection) == "edf6d05c83121201b436e16877593c3a");

  auto v1 = derive_initial_secrets(connection_id);
  REQUIRE(v1.has_value());
  CHECK(hex(v1->client) != hex(secrets->client));
}

TEST_CASE("RFC 9369 3.2: version 2 numbers the long header types differently")
{
  // Each type moves on by one, and retry wraps to zero.
  CHECK(long_packet_type_bits(packet_kind_t::initial, quic_version_2) == 0x10);
  CHECK(long_packet_type_bits(packet_kind_t::zero_rtt, quic_version_2) == 0x20);
  CHECK(long_packet_type_bits(packet_kind_t::handshake, quic_version_2) == 0x30);
  CHECK(long_packet_type_bits(packet_kind_t::retry, quic_version_2) == 0x00);

  CHECK(long_packet_type_bits(packet_kind_t::initial) == 0x00);
  CHECK(long_packet_type_bits(packet_kind_t::retry) == 0x30);

  // The same four codes read back as the kind that wrote them, under either
  // version, and never as each other's.
  for (auto kind : {packet_kind_t::initial, packet_kind_t::zero_rtt, packet_kind_t::handshake, packet_kind_t::retry})
  {
    CHECK(long_packet_kind(long_packet_type_bits(kind, quic_version_1), quic_version_1) == kind);
    CHECK(long_packet_kind(long_packet_type_bits(kind, quic_version_2), quic_version_2) == kind);
    CHECK(long_packet_kind(long_packet_type_bits(kind, quic_version_2), quic_version_1) != kind);
  }
}

TEST_CASE("RFC 9001 A.1: the Initial key schedule")
{
  const auto connection_id = from_hex("8394c8f03e515708");
  auto secrets = derive_initial_secrets(connection_id);
  REQUIRE(secrets.has_value());
  CHECK(hex(secrets->client) == v::client_initial_secret);
  CHECK(hex(secrets->server) == v::server_initial_secret);

  auto client = derive_key_material(tls_aes_128_gcm_sha256, secrets->client);
  REQUIRE(client.has_value());
  CHECK(hex(client->key) == v::client_key);
  CHECK(hex(client->iv) == v::client_iv);
  CHECK(hex(client->header_protection) == v::client_hp);

  auto server = derive_key_material(tls_aes_128_gcm_sha256, secrets->server);
  REQUIRE(server.has_value());
  CHECK(hex(server->key) == v::server_key);
  CHECK(hex(server->iv) == v::server_iv);
  CHECK(hex(server->header_protection) == v::server_hp);

  SUBCASE("the extract step on its own")
  {
    auto initial = vio::crypto::hkdf_extract(vio::crypto::hash_t::sha256, initial_salt_v1, connection_id);
    REQUIRE(initial.has_value());
    CHECK(hex(*initial) == v::initial_secret);
  }
}

TEST_CASE("RFC 9001 A.2: the client Initial packet, byte for byte")
{
  const auto connection_id = from_hex("8394c8f03e515708");
  auto secrets = derive_initial_secrets(connection_id);
  REQUIRE(secrets.has_value());
  auto material = derive_key_material(tls_aes_128_gcm_sha256, secrets->client);
  REQUIRE(material.has_value());

  packet_protection_t keys;
  REQUIRE(keys.init(tls_aes_128_gcm_sha256, secrets->client).has_value());
  header_protection_t header_keys;
  REQUIRE(header_keys.init(tls_aes_128_gcm_sha256, material->header_protection).has_value());

  // Header, then the CRYPTO frame, then PADDING out to the 1162 bytes the
  // RFC describes, then room for the tag.
  const auto header = from_hex(v::a2_header);
  const auto frames = from_hex(v::a2_frames);
  constexpr std::size_t frame_bytes = 1162;
  const packet_layout_t layout{.packet_number_offset = 18, .packet_number_length = 4, .header_length = header.size(), .frame_bytes = frame_bytes, .packet_length = header.size() + frame_bytes + 16};

  std::vector<std::uint8_t> packet(layout.packet_length, 0x00);
  std::copy(header.begin(), header.end(), packet.begin());
  std::copy(frames.begin(), frames.end(), packet.begin() + static_cast<std::ptrdiff_t>(header.size()));

  SUBCASE("the AEAD output is sampled for header protection")
  {
    auto length = keys.encrypt(packet, layout, 2);
    REQUIRE(length.has_value());
    CHECK(*length == layout.packet_length);
    const auto sample = std::span<const std::uint8_t>(packet).subspan(layout.packet_number_offset + 4, 16);
    CHECK(hex(sample) == v::a2_sample);

    REQUIRE(header_keys.apply(packet, layout.packet_number_offset, layout.packet_number_length).has_value());
    CHECK(hex(std::span<const std::uint8_t>(packet).first(header.size())) == v::a2_protected_header);
  }

  SUBCASE("the whole protected packet")
  {
    auto length = protect_packet(keys, header_keys, packet, layout, 2);
    REQUIRE(length.has_value());
    CHECK(*length == 1200);
    CHECK(hex(packet) == v::a2_packet);
  }

  SUBCASE("and it opens again")
  {
    REQUIRE(protect_packet(keys, header_keys, packet, layout, 2).has_value());

    auto opened = unprotect_packet(keys, header_keys, packet, layout.packet_number_offset, 0);
    REQUIRE(opened.has_value());
    CHECK(opened->packet_number == 2);
    CHECK(opened->payload.size() == frame_bytes);
    CHECK(hex(opened->payload.first(frames.size())) == v::a2_frames);
    CHECK(hex(std::span<const std::uint8_t>(packet).first(header.size())) == v::a2_header);
  }
}

TEST_CASE("RFC 9001 A.3: the server Initial packet, byte for byte")
{
  const auto connection_id = from_hex("8394c8f03e515708");
  auto secrets = derive_initial_secrets(connection_id);
  REQUIRE(secrets.has_value());
  auto material = derive_key_material(tls_aes_128_gcm_sha256, secrets->server);
  REQUIRE(material.has_value());

  packet_protection_t keys;
  REQUIRE(keys.init(tls_aes_128_gcm_sha256, secrets->server).has_value());
  header_protection_t header_keys;
  REQUIRE(header_keys.init(tls_aes_128_gcm_sha256, material->header_protection).has_value());

  const auto header = from_hex(v::a3_header);
  const auto frames = from_hex(v::a3_frames);
  const packet_layout_t layout{.packet_number_offset = 18, .packet_number_length = 2, .header_length = header.size(), .frame_bytes = frames.size(), .packet_length = header.size() + frames.size() + 16};

  std::vector<std::uint8_t> packet(layout.packet_length, 0x00);
  std::copy(header.begin(), header.end(), packet.begin());
  std::copy(frames.begin(), frames.end(), packet.begin() + static_cast<std::ptrdiff_t>(header.size()));

  auto length = keys.encrypt(packet, layout, 1);
  REQUIRE(length.has_value());
  const auto sample = std::span<const std::uint8_t>(packet).subspan(layout.packet_number_offset + 4, 16);
  CHECK(hex(sample) == v::a3_sample);

  REQUIRE(header_keys.apply(packet, layout.packet_number_offset, layout.packet_number_length).has_value());
  CHECK(hex(std::span<const std::uint8_t>(packet).first(header.size())) == v::a3_protected_header);
  CHECK(hex(packet) == v::a3_packet);

  SUBCASE("a client opens it with the server keys")
  {
    auto opened = unprotect_packet(keys, header_keys, packet, layout.packet_number_offset, 0);
    REQUIRE(opened.has_value());
    CHECK(opened->packet_number == 1);
    CHECK(hex(opened->payload) == v::a3_frames);
  }
}

TEST_CASE("RFC 9001 A.5: a ChaCha20-Poly1305 short header packet")
{
  const auto secret = from_hex(v::a5_secret);

  auto material = derive_key_material(tls_chacha20_poly1305_sha256, secret);
  REQUIRE(material.has_value());
  CHECK(hex(material->key) == v::a5_key);
  CHECK(hex(material->iv) == v::a5_iv);
  CHECK(hex(material->header_protection) == v::a5_hp);

  auto next = derive_next_secret(tls_chacha20_poly1305_sha256, secret);
  REQUIRE(next.has_value());
  CHECK(hex(*next) == v::a5_ku);

  constexpr std::uint64_t packet_number = 654360564;
  CHECK(hex(packet_nonce(material->iv, packet_number)) == v::a5_nonce);

  packet_protection_t keys;
  REQUIRE(keys.init(tls_chacha20_poly1305_sha256, secret).has_value());
  header_protection_t header_keys;
  REQUIRE(header_keys.init(tls_chacha20_poly1305_sha256, material->header_protection).has_value());

  // An empty destination connection ID, a three byte packet number and a
  // single PING frame: the smallest packet the sampling rule permits, at 21
  // bytes.
  const auto header = from_hex(v::a5_unprotected_header);
  const packet_layout_t layout{.packet_number_offset = 1, .packet_number_length = 3, .header_length = header.size(), .frame_bytes = 1, .packet_length = header.size() + 1 + 16};
  CHECK(layout.packet_length == 21);

  std::vector<std::uint8_t> packet(layout.packet_length, 0x00);
  std::copy(header.begin(), header.end(), packet.begin());
  packet[header.size()] = 0x01;

  auto length = keys.encrypt(packet, layout, packet_number);
  REQUIRE(length.has_value());
  CHECK(hex(std::span<const std::uint8_t>(packet).subspan(header.size())) == v::a5_ciphertext);

  const auto sample = std::span<const std::uint8_t>(packet).subspan(layout.packet_number_offset + 4, 16);
  CHECK(hex(sample) == v::a5_sample);

  REQUIRE(header_keys.apply(packet, layout.packet_number_offset, layout.packet_number_length).has_value());
  CHECK(hex(std::span<const std::uint8_t>(packet).first(header.size())) == v::a5_header);
  CHECK(hex(packet) == v::a5_packet);

  SUBCASE("and it opens again, recovering the full packet number")
  {
    auto opened = unprotect_packet(keys, header_keys, packet, layout.packet_number_offset, packet_number - 1);
    REQUIRE(opened.has_value());
    CHECK(opened->packet_number == packet_number);
    CHECK(hex(opened->payload) == "01");
    CHECK_FALSE(opened->key_phase);
  }
}

TEST_CASE("RFC 9001 A.4: the Retry integrity tag")
{
  const auto original = from_hex(v::a4_odcid);
  const auto retry = from_hex(v::a4_retry);

  CHECK(verify_retry_integrity(original, retry));

  auto tag = retry_integrity_tag(original, std::span<const std::uint8_t>(retry).first(retry.size() - retry_integrity_tag_size));
  REQUIRE(tag.has_value());
  CHECK(hex(*tag) == hex(std::span<const std::uint8_t>(retry).subspan(retry.size() - retry_integrity_tag_size)));

  SUBCASE("a different original connection id does not verify")
  {
    const auto other = from_hex("8394c8f03e515709");
    CHECK_FALSE(verify_retry_integrity(other, retry));
  }

  SUBCASE("a tampered token does not verify")
  {
    for (std::size_t index = 0; index < retry.size(); ++index)
    {
      CAPTURE(index);
      auto tampered = retry;
      tampered[index] = static_cast<std::uint8_t>(tampered[index] ^ 0x01);
      CHECK_FALSE(verify_retry_integrity(original, tampered));
    }
  }

  SUBCASE("a packet with no room for a tag does not verify")
  {
    CHECK_FALSE(verify_retry_integrity(original, std::span<const std::uint8_t>(retry).first(retry_integrity_tag_size)));
    CHECK_FALSE(verify_retry_integrity(original, {}));
  }
}

TEST_CASE("reserved bits are a connection error, but only once the AEAD has passed")
{
  const auto secret = from_hex(v::a5_secret);
  auto material = derive_key_material(tls_chacha20_poly1305_sha256, secret);
  REQUIRE(material.has_value());
  packet_protection_t keys;
  REQUIRE(keys.init(tls_chacha20_poly1305_sha256, secret).has_value());
  header_protection_t header_keys;
  REQUIRE(header_keys.init(tls_chacha20_poly1305_sha256, material->header_protection).has_value());

  const packet_layout_t layout{.packet_number_offset = 1, .packet_number_length = 3, .header_length = 4, .frame_bytes = 8, .packet_length = 4 + 8 + 16};

  const auto build = [&](std::uint8_t first_byte)
  {
    std::vector<std::uint8_t> packet(layout.packet_length, 0x00);
    packet[0] = first_byte;
    packet[1] = 0x00;
    packet[2] = 0xbf;
    packet[3] = 0xf4;
    for (std::size_t i = 0; i < layout.frame_bytes; ++i)
    {
      packet[layout.header_length + i] = 0x01;
    }
    return packet;
  };

  SUBCASE("a sender that sets them produces a packet the receiver rejects")
  {
    // 0x42 is the well-formed first byte; 0x4a sets one of the two reserved
    // bits (mask 0x18) that RFC 9000 section 17.3.1 requires to be zero.
    auto packet = build(0x4a);
    REQUIRE(protect_packet(keys, header_keys, packet, layout, 654360564).has_value());

    auto opened = unprotect_packet(keys, header_keys, packet, layout.packet_number_offset, 654360563);
    REQUIRE_FALSE(opened.has_value());
    CHECK(opened.error() == unprotect_error_t::reserved_bits_set);
    CHECK(is_connection_error(opened.error()));
  }

  SUBCASE("flipping those bits on the wire is not a connection error")
  {
    // The AEAD covers the first byte, so an attacker who flips a reserved bit
    // in a packet they cannot read gets an authentication failure -- which is
    // a discard. Reporting the reserved bits first would have handed them a
    // way to tear the connection down.
    auto packet = build(0x42);
    REQUIRE(protect_packet(keys, header_keys, packet, layout, 654360564).has_value());
    packet[0] = static_cast<std::uint8_t>(packet[0] ^ 0x18);

    auto opened = unprotect_packet(keys, header_keys, packet, layout.packet_number_offset, 654360563);
    REQUIRE_FALSE(opened.has_value());
    CHECK(opened.error() == unprotect_error_t::authentication_failed);
    CHECK_FALSE(is_connection_error(opened.error()));
  }

  SUBCASE("a well formed packet round trips")
  {
    auto packet = build(0x42);
    REQUIRE(protect_packet(keys, header_keys, packet, layout, 654360564).has_value());
    auto opened = unprotect_packet(keys, header_keys, packet, layout.packet_number_offset, 654360563);
    REQUIRE(opened.has_value());
    CHECK(opened->payload.size() == layout.frame_bytes);
  }
}

TEST_CASE("a corrupted packet is discarded, never diagnosed")
{
  const auto connection_id = from_hex("8394c8f03e515708");
  auto secrets = derive_initial_secrets(connection_id);
  REQUIRE(secrets.has_value());
  auto material = derive_key_material(tls_aes_128_gcm_sha256, secrets->server);
  REQUIRE(material.has_value());

  packet_protection_t keys;
  REQUIRE(keys.init(tls_aes_128_gcm_sha256, secrets->server).has_value());
  header_protection_t header_keys;
  REQUIRE(header_keys.init(tls_aes_128_gcm_sha256, material->header_protection).has_value());

  const auto original = from_hex(v::a3_packet);

  SUBCASE("every single byte corruption fails to authenticate")
  {
    for (std::size_t index = 0; index < original.size(); index += 7)
    {
      CAPTURE(index);
      auto packet = original;
      packet[index] = static_cast<std::uint8_t>(packet[index] ^ 0x40);
      auto opened = unprotect_packet(keys, header_keys, packet, 18, 0);
      if (opened.has_value())
      {
        // Corrupting the packet number field alone still authenticates only
        // if it lands on the same value, which xor 0x40 never does.
        FAIL_CHECK("corruption at " << index << " was accepted");
      }
      else
      {
        CHECK_FALSE(is_connection_error(opened.error()));
      }
    }
  }

  SUBCASE("the wrong direction's keys fail to authenticate")
  {
    auto client_material = derive_key_material(tls_aes_128_gcm_sha256, secrets->client);
    REQUIRE(client_material.has_value());
    packet_protection_t wrong;
    REQUIRE(wrong.init(tls_aes_128_gcm_sha256, secrets->client).has_value());
    header_protection_t wrong_header;
    REQUIRE(wrong_header.init(tls_aes_128_gcm_sha256, client_material->header_protection).has_value());

    auto packet = original;
    auto opened = unprotect_packet(wrong, wrong_header, packet, 18, 0);
    REQUIRE_FALSE(opened.has_value());
    CHECK_FALSE(is_connection_error(opened.error()));
  }

  SUBCASE("a packet too short to sample is refused before any key is touched")
  {
    for (std::size_t length = 0; length < 18 + header_protection_minimum_tail; ++length)
    {
      CAPTURE(length);
      std::vector<std::uint8_t> packet(original.begin(), original.begin() + static_cast<std::ptrdiff_t>(length));
      auto opened = unprotect_packet(keys, header_keys, packet, 18, 0);
      REQUIRE_FALSE(opened.has_value());
      CHECK(opened.error() == unprotect_error_t::truncated);
    }
  }
}

TEST_CASE("a key update changes the packet keys and keeps the header key")
{
  const auto secret = from_hex(v::a5_secret);
  auto material = derive_key_material(tls_chacha20_poly1305_sha256, secret);
  REQUIRE(material.has_value());

  packet_protection_t current;
  REQUIRE(current.init(tls_chacha20_poly1305_sha256, secret).has_value());
  auto next = current.next_generation();
  REQUIRE(next.has_value());

  auto next_material = next->material();
  REQUIRE(next_material.has_value());
  CHECK(hex(next_material->key) != hex(material->key));
  CHECK(hex(next_material->iv) != hex(material->iv));

  // The header protection key derived from the new secret is different, which
  // is exactly why it must not be used: section 5.4 keeps the original for the
  // life of the connection so that the Key Phase bit stays hidden.
  CHECK(hex(next_material->header_protection) != hex(material->header_protection));

  header_protection_t header_keys;
  REQUIRE(header_keys.init(tls_chacha20_poly1305_sha256, material->header_protection).has_value());

  const packet_layout_t layout{.packet_number_offset = 1, .packet_number_length = 3, .header_length = 4, .frame_bytes = 8, .packet_length = 4 + 8 + 16};
  std::vector<std::uint8_t> packet(layout.packet_length, 0x00);
  packet[0] = 0x46;
  packet[2] = 0xbf;
  packet[3] = 0xf4;

  // Sent under the new generation, with the key phase bit set and the original
  // header protection key.
  REQUIRE(protect_packet(*next, header_keys, packet, layout, 654360564).has_value());

  SUBCASE("the old generation cannot open it")
  {
    auto packet_copy = packet;
    auto opened = unprotect_packet(current, header_keys, packet_copy, layout.packet_number_offset, 654360563);
    REQUIRE_FALSE(opened.has_value());
    CHECK(opened.error() == unprotect_error_t::authentication_failed);
  }

  SUBCASE("the new one can, and the key phase survives")
  {
    auto header = header_keys.remove(packet, layout.packet_number_offset);
    REQUIRE(header.has_value());
    CHECK(header->key_phase);
    auto opened = next->decrypt(packet, layout.packet_number_offset, *header, 654360563);
    REQUIRE(opened.has_value());
    CHECK(opened->key_phase);
  }
}

TEST_CASE("RFC 9001 section 6.6: the AEAD usage limits")
{
  // Confidentiality bounds how many packets one key may protect.
  CHECK(aead_confidentiality_limit(vio::crypto::aead_t::aes_128_gcm) == (std::uint64_t{1} << 23));
  CHECK(aead_confidentiality_limit(vio::crypto::aead_t::aes_256_gcm) == (std::uint64_t{1} << 23));
  // For ChaCha20 the limit exceeds the number of packets a connection can
  // carry at all, so there is nothing to enforce.
  CHECK(aead_confidentiality_limit(vio::crypto::aead_t::chacha20_poly1305) > (std::uint64_t{1} << 62));

  // Integrity bounds how many forgeries may be attempted against the
  // connection. QUIC needs this where TLS does not, because a packet that
  // fails to authenticate is dropped rather than ending the connection --
  // which is precisely what lets an attacker keep trying.
  CHECK(aead_integrity_limit(vio::crypto::aead_t::aes_128_gcm) == (std::uint64_t{1} << 52));
  CHECK(aead_integrity_limit(vio::crypto::aead_t::aes_256_gcm) == (std::uint64_t{1} << 52));
  CHECK(aead_integrity_limit(vio::crypto::aead_t::chacha20_poly1305) == (std::uint64_t{1} << 36));
}

TEST_CASE("uninitialized keys refuse to work rather than producing garbage")
{
  std::vector<std::uint8_t> packet(64, 0);
  const packet_layout_t layout{.packet_number_offset = 1, .packet_number_length = 3, .header_length = 4, .frame_bytes = 8, .packet_length = 28};

  packet_protection_t keys;
  header_protection_t header_keys;
  CHECK_FALSE(keys.initialized());
  CHECK_FALSE(header_keys.initialized());
  CHECK_FALSE(keys.encrypt(packet, layout, 1).has_value());
  CHECK_FALSE(header_keys.apply(packet, 1, 3).has_value());

  auto removed = header_keys.remove(packet, 1);
  REQUIRE_FALSE(removed.has_value());
  CHECK(removed.error() == unprotect_error_t::not_initialized);
  CHECK_FALSE(is_connection_error(removed.error()));
}
}
