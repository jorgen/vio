#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <doctest/doctest.h>
#include <vio/crypto.h>
#include <vio/crypto_aead.h>

// Vectors are transcribed from the raw RFC 9001 text (Appendix A), not from a
// summary of it. Every value below is printed verbatim in the RFC except the
// A.2 mask, which the RFC prints at the end of A.2 as 437b9aec36.

namespace
{
std::vector<std::uint8_t> unhex(std::string_view hex)
{
  std::vector<std::uint8_t> out;
  out.reserve(hex.size() / 2);
  auto nibble = [](char c) -> int
  {
    if (c >= '0' && c <= '9')
      return c - '0';
    if (c >= 'a' && c <= 'f')
      return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
      return c - 'A' + 10;
    return -1;
  };
  for (std::size_t i = 0; i + 1 < hex.size(); i += 2)
  {
    out.push_back(static_cast<std::uint8_t>((nibble(hex[i]) << 4) | nibble(hex[i + 1])));
  }
  return out;
}

std::string hex_of(std::span<const std::uint8_t> bytes)
{
  return vio::crypto::to_hex(bytes);
}

constexpr std::string_view initial_salt = "38762cf7f55934b34d179ae6a4c80cadccbb7f0a";
constexpr std::string_view destination_cid = "8394c8f03e515708";

std::vector<std::uint8_t> expand_label(std::span<const std::uint8_t> secret, std::string_view label, std::size_t length)
{
  std::vector<std::uint8_t> out(length);
  auto result = vio::crypto::hkdf_expand_label(vio::crypto::hash_t::sha256, secret, label, {}, out);
  REQUIRE(result.has_value());
  return out;
}
} // namespace

TEST_SUITE("crypto_aead")
{
TEST_CASE("RFC 9001 A.1: initial secrets and keys")
{
  const auto salt = unhex(initial_salt);
  const auto cid = unhex(destination_cid);

  auto initial_secret = vio::crypto::hkdf_extract(vio::crypto::hash_t::sha256, salt, cid);
  REQUIRE(initial_secret.has_value());
  CHECK(hex_of(*initial_secret) == "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44");

  const auto client_secret = expand_label(*initial_secret, "client in", 32);
  CHECK(hex_of(client_secret) == "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea");
  CHECK(hex_of(expand_label(client_secret, "quic key", 16)) == "1f369613dd76d5467730efcbe3b1a22d");
  CHECK(hex_of(expand_label(client_secret, "quic iv", 12)) == "fa044b2f42a3fd3b46fb255c");
  CHECK(hex_of(expand_label(client_secret, "quic hp", 16)) == "9f50449e04a0e810283a1e9933adedd2");

  const auto server_secret = expand_label(*initial_secret, "server in", 32);
  CHECK(hex_of(server_secret) == "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b");
  CHECK(hex_of(expand_label(server_secret, "quic key", 16)) == "cf3a5331653c364c88f0f379b6067e37");
  CHECK(hex_of(expand_label(server_secret, "quic iv", 12)) == "0ac1493ca1905853b0bba03e");
  CHECK(hex_of(expand_label(server_secret, "quic hp", 16)) == "c206b8d9b9f0f37644430b490eeaa314");
}

TEST_CASE("RFC 9001 A.2: AES header protection mask")
{
  const auto hp = unhex("9f50449e04a0e810283a1e9933adedd2");
  const auto sample_bytes = unhex("d1b1c98dd7689fb8ec11d242b123dc9b");
  REQUIRE(sample_bytes.size() == vio::crypto::header_protection_sample_size);

  vio::crypto::header_protection_key_t key;
  REQUIRE(key.init(vio::crypto::aead_t::aes_128_gcm, hp).has_value());

  auto mask = key.mask(std::span<const std::uint8_t, vio::crypto::header_protection_sample_size>(sample_bytes.data(), vio::crypto::header_protection_sample_size));
  REQUIRE(mask.has_value());
  CHECK(hex_of(*mask) == "437b9aec36");
}

TEST_CASE("RFC 9001 A.5: ChaCha20 keys, header protection and AEAD")
{
  const auto secret = unhex("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");

  const auto key_bytes = expand_label(secret, "quic key", 32);
  CHECK(hex_of(key_bytes) == "c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8");
  CHECK(hex_of(expand_label(secret, "quic iv", 12)) == "e0459b3474bdd0e44a41c144");
  const auto hp_bytes = expand_label(secret, "quic hp", 32);
  CHECK(hex_of(hp_bytes) == "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4");
  CHECK(hex_of(expand_label(secret, "quic ku", 32)) == "1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9");

  SUBCASE("header protection mask uses the sample as counter and nonce")
  {
    const auto sample_bytes = unhex("5e5cd55c41f69080575d7999c25a5bfb");
    vio::crypto::header_protection_key_t hp_key;
    REQUIRE(hp_key.init(vio::crypto::aead_t::chacha20_poly1305, hp_bytes).has_value());

    auto mask = hp_key.mask(std::span<const std::uint8_t, vio::crypto::header_protection_sample_size>(sample_bytes.data(), vio::crypto::header_protection_sample_size));
    REQUIRE(mask.has_value());
    CHECK(hex_of(*mask) == "aefefe7d03");
  }

  SUBCASE("seal and open the sample packet payload")
  {
    const auto nonce_bytes = unhex("e0459b3474bdd0e46d417eb0");
    const auto aad = unhex("4200bff4");
    const auto plaintext = unhex("01");

    vio::crypto::aead_key_t aead;
    REQUIRE(aead.init(vio::crypto::aead_t::chacha20_poly1305, key_bytes).has_value());

    std::span<const std::uint8_t, vio::crypto::aead_nonce_size> nonce(nonce_bytes.data(), vio::crypto::aead_nonce_size);

    std::vector<std::uint8_t> sealed(plaintext.size() + aead.tag_size());
    auto sealed_len = aead.seal(sealed, nonce, plaintext, aad);
    REQUIRE(sealed_len.has_value());
    CHECK(*sealed_len == sealed.size());
    CHECK(hex_of(sealed) == "655e5cd55c41f69080575d7999c25a5bfb");

    std::vector<std::uint8_t> opened(sealed.size());
    auto opened_len = aead.open(opened, nonce, sealed, aad);
    REQUIRE(opened_len.has_value());
    opened.resize(*opened_len);
    CHECK(hex_of(opened) == "01");
  }

  SUBCASE("a tampered tag fails to open")
  {
    const auto nonce_bytes = unhex("e0459b3474bdd0e46d417eb0");
    const auto aad = unhex("4200bff4");
    auto sealed = unhex("655e5cd55c41f69080575d7999c25a5bfb");
    sealed.back() ^= 0x01;

    vio::crypto::aead_key_t aead;
    REQUIRE(aead.init(vio::crypto::aead_t::chacha20_poly1305, key_bytes).has_value());
    std::span<const std::uint8_t, vio::crypto::aead_nonce_size> nonce(nonce_bytes.data(), vio::crypto::aead_nonce_size);

    std::vector<std::uint8_t> opened(sealed.size());
    CHECK_FALSE(aead.open(opened, nonce, sealed, aad).has_value());
  }

  SUBCASE("the wrong aad fails to open")
  {
    const auto nonce_bytes = unhex("e0459b3474bdd0e46d417eb0");
    const auto aad = unhex("4200bff5");
    const auto sealed = unhex("655e5cd55c41f69080575d7999c25a5bfb");

    vio::crypto::aead_key_t aead;
    REQUIRE(aead.init(vio::crypto::aead_t::chacha20_poly1305, key_bytes).has_value());
    std::span<const std::uint8_t, vio::crypto::aead_nonce_size> nonce(nonce_bytes.data(), vio::crypto::aead_nonce_size);

    std::vector<std::uint8_t> opened(sealed.size());
    CHECK_FALSE(aead.open(opened, nonce, sealed, aad).has_value());
  }
}

TEST_CASE("a header protection key is reusable across packets")
{
  // The ChaCha20 variant keeps one cipher context and re-initialises it with
  // each sample, so the keystream counter has to restart every call. If it
  // did not, the first mask would match the RFC and every later one would
  // silently differ -- and a wrong mask is indistinguishable from a corrupt
  // packet at the peer.
  const auto hp_bytes = unhex("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4");
  const auto sample_bytes = unhex("5e5cd55c41f69080575d7999c25a5bfb");
  const auto other_sample = unhex("d1b1c98dd7689fb8ec11d242b123dc9b");

  vio::crypto::header_protection_key_t key;
  REQUIRE(key.init(vio::crypto::aead_t::chacha20_poly1305, hp_bytes).has_value());

  std::span<const std::uint8_t, vio::crypto::header_protection_sample_size> sample(sample_bytes.data(), vio::crypto::header_protection_sample_size);
  std::span<const std::uint8_t, vio::crypto::header_protection_sample_size> other(other_sample.data(), vio::crypto::header_protection_sample_size);

  for (int i = 0; i < 8; ++i)
  {
    auto mask = key.mask(sample);
    REQUIRE(mask.has_value());
    CHECK(hex_of(*mask) == "aefefe7d03");

    // Interleave a different sample: the context must carry nothing between
    // calls.
    auto elsewhere = key.mask(other);
    REQUIRE(elsewhere.has_value());
    CHECK(hex_of(*elsewhere) != "aefefe7d03");
  }

  SUBCASE("the aes variant is equally repeatable")
  {
    vio::crypto::header_protection_key_t aes_key;
    REQUIRE(aes_key.init(vio::crypto::aead_t::aes_128_gcm, unhex("9f50449e04a0e810283a1e9933adedd2")).has_value());
    for (int i = 0; i < 4; ++i)
    {
      auto mask = aes_key.mask(other);
      REQUIRE(mask.has_value());
      CHECK(hex_of(*mask) == "437b9aec36");
    }
  }
}

TEST_CASE("a failure carries the OpenSSL reason and leaves the error queue clean")
{
  vio::crypto::aead_key_t aead;
  auto failed = aead.init(vio::crypto::aead_t::aes_128_gcm, std::vector<std::uint8_t>(3, 0));
  REQUIRE_FALSE(failed.has_value());
  CHECK_FALSE(failed.error().msg.empty());

  // A later, valid operation must not inherit anything from the failure.
  vio::crypto::aead_key_t good;
  CHECK(good.init(vio::crypto::aead_t::aes_128_gcm, std::vector<std::uint8_t>(16, 0x11)).has_value());
}

TEST_CASE("aes-gcm round trip and key length validation")
{
  const std::vector<std::uint8_t> key_128(16, 0xab);
  const std::vector<std::uint8_t> key_256(32, 0xcd);
  const std::vector<std::uint8_t> nonce_bytes(vio::crypto::aead_nonce_size, 0x42);
  const std::vector<std::uint8_t> aad{1, 2, 3, 4};
  const std::vector<std::uint8_t> plaintext{9, 8, 7, 6, 5};
  std::span<const std::uint8_t, vio::crypto::aead_nonce_size> nonce(nonce_bytes.data(), vio::crypto::aead_nonce_size);

  for (auto algorithm : {vio::crypto::aead_t::aes_128_gcm, vio::crypto::aead_t::aes_256_gcm})
  {
    const auto &key = algorithm == vio::crypto::aead_t::aes_128_gcm ? key_128 : key_256;
    vio::crypto::aead_key_t aead;
    REQUIRE(aead.init(algorithm, key).has_value());
    CHECK(aead.initialized());

    std::vector<std::uint8_t> sealed(plaintext.size() + aead.tag_size());
    REQUIRE(aead.seal(sealed, nonce, plaintext, aad).has_value());

    std::vector<std::uint8_t> opened(sealed.size());
    auto opened_len = aead.open(opened, nonce, sealed, aad);
    REQUIRE(opened_len.has_value());
    opened.resize(*opened_len);
    CHECK(opened == plaintext);
  }

  vio::crypto::aead_key_t wrong;
  CHECK_FALSE(wrong.init(vio::crypto::aead_t::aes_256_gcm, key_128).has_value());
  CHECK_FALSE(wrong.initialized());
}

TEST_CASE("an uninitialized key reports an error rather than crashing")
{
  const std::vector<std::uint8_t> nonce_bytes(vio::crypto::aead_nonce_size, 0);
  std::span<const std::uint8_t, vio::crypto::aead_nonce_size> nonce(nonce_bytes.data(), vio::crypto::aead_nonce_size);
  std::vector<std::uint8_t> buffer(64);

  vio::crypto::aead_key_t aead;
  CHECK_FALSE(aead.initialized());
  CHECK_FALSE(aead.seal(buffer, nonce, {}, {}).has_value());
  CHECK_FALSE(aead.open(buffer, nonce, {}, {}).has_value());

  vio::crypto::header_protection_key_t hp;
  const std::array<std::uint8_t, vio::crypto::header_protection_sample_size> sample = {};
  CHECK_FALSE(hp.initialized());
  CHECK_FALSE(hp.mask(sample).has_value());
}

TEST_CASE("moving a key transfers ownership")
{
  const std::vector<std::uint8_t> key(16, 0x11);
  vio::crypto::aead_key_t source;
  REQUIRE(source.init(vio::crypto::aead_t::aes_128_gcm, key).has_value());

  vio::crypto::aead_key_t moved(std::move(source));
  CHECK(moved.initialized());

  vio::crypto::header_protection_key_t hp_source;
  REQUIRE(hp_source.init(vio::crypto::aead_t::aes_128_gcm, key).has_value());
  vio::crypto::header_protection_key_t hp_moved;
  hp_moved = std::move(hp_source);
  CHECK(hp_moved.initialized());
}
}
