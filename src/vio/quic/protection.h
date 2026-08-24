/*
  Copyright (c) 2025 Jørgen Lind

  Permission is hereby granted, free of charge, to any person obtaining a copy of
  this software and associated documentation files (the "Software"), to deal in
  the Software without restriction, including without limitation the rights to
  use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
  of the Software, and to permit persons to whom the Software is furnished to do
  so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
*/

#pragma once

// RFC 9001 packet protection: the key schedule, the AEAD, and header
// protection.
//
// QUIC protects a packet twice, in an order that matters. Sending seals the
// payload first and then masks part of the header using a sample of the
// ciphertext it just produced; receiving unmasks the header first, because
// until it does it does not know how long the packet number is or which key
// phase the packet belongs to. So the two directions are not symmetric, and
// the receive side is split in two here -- remove(), then decrypt() -- with
// the caller free to pick a key generation in between. protect_packet and
// unprotect_packet glue the halves together for the common case.
//
// Two rules in here are easy to get backwards and expensive to get wrong:
//
// The header protection key is derived once and never changes, not even on a
// key update (section 5.4). That is what lets header protection conceal the
// Key Phase bit -- a key that changed with the phase would have to be selected
// by the phase, which is the thing being hidden. So header_protection_t is a
// separate object with a separate lifetime from packet_protection_t.
//
// The reserved bits are checked only after the AEAD has passed (section 17.2
// of RFC 9000, and section 9.5 of this one). Checking them when header
// protection comes off would let anyone who can write to the network flip two
// bits in a packet they cannot read and have the connection torn down for it.

#include "vio/crypto_aead.h"
#include "vio/error.h"
#include "vio/quic/packet.h"
#include "vio/quic/packet_number.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <limits>
#include <span>
#include <vector>

namespace vio::quic
{
struct cipher_suite_t
{
  crypto::aead_t aead = crypto::aead_t::aes_128_gcm;
  crypto::hash_t hash = crypto::hash_t::sha256;
};

inline constexpr cipher_suite_t tls_aes_128_gcm_sha256{crypto::aead_t::aes_128_gcm, crypto::hash_t::sha256};
inline constexpr cipher_suite_t tls_aes_256_gcm_sha384{crypto::aead_t::aes_256_gcm, crypto::hash_t::sha384};
inline constexpr cipher_suite_t tls_chacha20_poly1305_sha256{crypto::aead_t::chacha20_poly1305, crypto::hash_t::sha256};

// Section 5.2. Version specific by design: a future version gets a new salt so
// a middlebox that only understands this one cannot read its Initial packets.
inline constexpr std::array<std::uint8_t, 20> initial_salt_v1 = {0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a};
// RFC 9369 section 3.1.
inline constexpr std::array<std::uint8_t, 20> initial_salt_v2 = {0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9};

[[nodiscard]] constexpr std::span<const std::uint8_t> initial_salt_for(std::uint32_t version)
{
  return version == quic_version_2 ? std::span<const std::uint8_t>(initial_salt_v2) : std::span<const std::uint8_t>(initial_salt_v1);
}

// RFC 9369 section 3.3: the labels change with the version so that keys derived
// for one cannot be used with the other even where the secret is the same.
struct key_labels_t
{
  const char *key;
  const char *iv;
  const char *header_protection;
  const char *key_update;
};

[[nodiscard]] constexpr key_labels_t key_labels_for(std::uint32_t version)
{
  if (version == quic_version_2)
  {
    return key_labels_t{"quicv2 key", "quicv2 iv", "quicv2 hp", "quicv2 ku"};
  }
  return key_labels_t{"quic key", "quic iv", "quic hp", "quic ku"};
}

// Section 6.6. Overusing a key hands an attacker an advantage that grows with
// the number of packets, so both directions are bounded: how many packets may
// be protected under one key, and how many forgeries may be attempted against
// the connection before it must be abandoned. The integrity limit exists
// because QUIC, unlike TLS, ignores a packet that fails to authenticate rather
// than tearing the connection down -- which is exactly what lets an attacker
// keep guessing.
[[nodiscard]] constexpr std::uint64_t aead_confidentiality_limit(crypto::aead_t aead)
{
  switch (aead)
  {
  case crypto::aead_t::aes_128_gcm:
  case crypto::aead_t::aes_256_gcm:
    return std::uint64_t{1} << 23;
  case crypto::aead_t::chacha20_poly1305:
    // Greater than the number of packets a connection can carry at all, so
    // there is nothing to enforce.
    break;
  }
  return (std::numeric_limits<std::uint64_t>::max)();
}

[[nodiscard]] constexpr std::uint64_t aead_integrity_limit(crypto::aead_t aead)
{
  switch (aead)
  {
  case crypto::aead_t::aes_128_gcm:
  case crypto::aead_t::aes_256_gcm:
    return std::uint64_t{1} << 52;
  case crypto::aead_t::chacha20_poly1305:
    return std::uint64_t{1} << 36;
  }
  return std::uint64_t{1} << 36;
}

// Section 5.8. Fixed for the version, and themselves the output of
// HKDF-Expand-Label over a constant secret.
inline constexpr std::array<std::uint8_t, 16> retry_key_v1 = {0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e};
inline constexpr std::array<std::uint8_t, 12> retry_nonce_v1 = {0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb};
// RFC 9369 section 3.3.
inline constexpr std::array<std::uint8_t, 16> retry_key_v2 = {0x8f, 0xb4, 0xb0, 0x1b, 0x56, 0xac, 0x48, 0xe2, 0x60, 0xfb, 0xcb, 0xce, 0xad, 0x7c, 0xcc, 0x92};
inline constexpr std::array<std::uint8_t, 12> retry_nonce_v2 = {0xd8, 0x69, 0x69, 0xbc, 0x2d, 0x7c, 0x6d, 0x99, 0x90, 0xef, 0xb0, 0x4a};

struct key_material_t
{
  std::vector<std::uint8_t> key;
  std::array<std::uint8_t, crypto::aead_nonce_size> iv = {};
  std::vector<std::uint8_t> header_protection;
};

struct initial_secrets_t
{
  std::vector<std::uint8_t> client;
  std::vector<std::uint8_t> server;
};

// Section 5.1. The "quic iv" length is the AEAD nonce length for every suite
// this version allows, so it is fixed here rather than plumbed.
[[nodiscard]] inline std::expected<key_material_t, error_t> derive_key_material(cipher_suite_t suite, std::span<const std::uint8_t> secret, std::uint32_t version = quic_version_1)
{
  const auto labels = key_labels_for(version);
  key_material_t material;
  const std::size_t key_size = crypto::aead_key_size(suite.aead);
  material.key.resize(key_size);
  material.header_protection.resize(key_size);

  if (auto r = crypto::hkdf_expand_label(suite.hash, secret, labels.key, {}, material.key); !r.has_value())
  {
    return std::unexpected(r.error());
  }
  if (auto r = crypto::hkdf_expand_label(suite.hash, secret, labels.iv, {}, material.iv); !r.has_value())
  {
    return std::unexpected(r.error());
  }
  if (auto r = crypto::hkdf_expand_label(suite.hash, secret, labels.header_protection, {}, material.header_protection); !r.has_value())
  {
    return std::unexpected(r.error());
  }
  return material;
}

// Section 6.1: the secret for the next key phase.
[[nodiscard]] inline std::expected<std::vector<std::uint8_t>, error_t> derive_next_secret(cipher_suite_t suite, std::span<const std::uint8_t> secret, std::uint32_t version = quic_version_1)
{
  std::vector<std::uint8_t> next(crypto::hash_size(suite.hash));
  if (auto r = crypto::hkdf_expand_label(suite.hash, secret, key_labels_for(version).key_update, {}, next); !r.has_value())
  {
    return std::unexpected(r.error());
  }
  return next;
}

// Section 5.2. Both directions come from the Destination Connection ID in the
// client's first Initial packet, which is why anyone who sees that packet can
// read the handshake -- Initial protection is about version-unaware
// middleboxes, not confidentiality.
[[nodiscard]] inline std::expected<initial_secrets_t, error_t> derive_initial_secrets(std::span<const std::uint8_t> client_destination_id, std::uint32_t version = quic_version_1)
{
  auto initial = crypto::hkdf_extract(crypto::hash_t::sha256, initial_salt_for(version), client_destination_id);
  if (!initial.has_value())
  {
    return std::unexpected(initial.error());
  }

  initial_secrets_t secrets;
  secrets.client.resize(crypto::hash_size(crypto::hash_t::sha256));
  secrets.server.resize(crypto::hash_size(crypto::hash_t::sha256));
  if (auto r = crypto::hkdf_expand_label(crypto::hash_t::sha256, *initial, "client in", {}, secrets.client); !r.has_value())
  {
    return std::unexpected(r.error());
  }
  if (auto r = crypto::hkdf_expand_label(crypto::hash_t::sha256, *initial, "server in", {}, secrets.server); !r.has_value())
  {
    return std::unexpected(r.error());
  }
  return secrets;
}

// Section 5.3: the packet number, left-padded to the width of the IV, XORed
// with it.
[[nodiscard]] inline crypto::aead_nonce_t packet_nonce(std::span<const std::uint8_t, crypto::aead_nonce_size> iv, std::uint64_t packet_number)
{
  crypto::aead_nonce_t nonce = {};
  for (std::size_t i = 0; i < crypto::aead_nonce_size; ++i)
  {
    nonce[i] = iv[i];
  }
  for (std::size_t i = 0; i < 8; ++i)
  {
    nonce[crypto::aead_nonce_size - 1 - i] = static_cast<std::uint8_t>(nonce[crypto::aead_nonce_size - 1 - i] ^ static_cast<std::uint8_t>((packet_number >> (8 * i)) & 0xff));
  }
  return nonce;
}

// What went wrong taking a packet apart. All but one of these mean drop the
// packet and carry on: a packet that fails authentication is routine -- a
// stale key, a reordered packet from a discarded epoch, or someone injecting
// bytes -- and reacting to it would hand any observer a way to kill the
// connection.
enum class unprotect_error_t : std::uint8_t
{
  truncated,
  not_initialized,
  crypto_failure,
  authentication_failed,
  reserved_bits_set,
};

[[nodiscard]] constexpr bool is_connection_error(unprotect_error_t error)
{
  return error == unprotect_error_t::reserved_bits_set;
}

// What removing header protection reveals.
struct header_info_t
{
  std::uint8_t first_byte = 0;
  std::size_t packet_number_length = 0;
  std::uint64_t truncated_packet_number = 0;
  bool long_header = false;
  // Short header only, and the reason the header protection key must outlive
  // any one key phase.
  bool key_phase = false;
};

struct opened_packet_t
{
  std::uint64_t packet_number = 0;
  bool key_phase = false;
  // The decrypted frames, written back over the ciphertext.
  std::span<const std::uint8_t> payload;
};

// Section 5.4. One per direction, for the life of the connection.
class header_protection_t
{
public:
  [[nodiscard]] std::expected<void, error_t> init(cipher_suite_t suite, std::span<const std::uint8_t> key)
  {
    return _key.init(suite.aead, key);
  }

  [[nodiscard]] bool initialized() const
  {
    return _key.initialized();
  }

  // Unmasks the first byte and the packet number in place, so that what is
  // left is the header the AEAD authenticated.
  [[nodiscard]] std::expected<header_info_t, unprotect_error_t> remove(std::span<std::uint8_t> packet, std::size_t packet_number_offset)
  {
    if (!initialized())
    {
      return std::unexpected(unprotect_error_t::not_initialized);
    }
    if (packet.size() < packet_number_offset + header_protection_minimum_tail)
    {
      return std::unexpected(unprotect_error_t::truncated);
    }

    std::array<std::uint8_t, crypto::header_protection_sample_size> sample = {};
    for (std::size_t i = 0; i < sample.size(); ++i)
    {
      sample[i] = packet[packet_number_offset + header_protection_sample_skip + i];
    }
    auto mask = _key.mask(sample);
    if (!mask.has_value())
    {
      return std::unexpected(unprotect_error_t::crypto_failure);
    }

    header_info_t info;
    info.long_header = (packet[0] & header_form_long) != 0;
    const std::uint8_t bits = info.long_header ? 0x0f : 0x1f;
    packet[0] = static_cast<std::uint8_t>(packet[0] ^ ((*mask)[0] & bits));
    info.first_byte = packet[0];
    info.key_phase = !info.long_header && (info.first_byte & short_key_phase_bit) != 0;
    info.packet_number_length = static_cast<std::size_t>(info.first_byte & packet_number_length_mask) + 1;

    for (std::size_t i = 0; i < info.packet_number_length; ++i)
    {
      packet[packet_number_offset + i] = static_cast<std::uint8_t>(packet[packet_number_offset + i] ^ (*mask)[1 + i]);
      info.truncated_packet_number = (info.truncated_packet_number << 8) | packet[packet_number_offset + i];
    }
    return info;
  }

  // Masks a packet whose payload has already been sealed: the sample is taken
  // from the ciphertext, so this cannot run before the AEAD.
  [[nodiscard]] std::expected<void, error_t> apply(std::span<std::uint8_t> packet, std::size_t packet_number_offset, std::size_t packet_number_length)
  {
    if (!initialized())
    {
      return std::unexpected(error_t{.code = 1, .msg = "header protection key is not initialized"});
    }
    if (packet_number_length == 0 || packet_number_length > max_packet_number_size || packet.size() < packet_number_offset + header_protection_minimum_tail)
    {
      return std::unexpected(error_t{.code = 1, .msg = "packet is too short to sample for header protection"});
    }

    std::array<std::uint8_t, crypto::header_protection_sample_size> sample = {};
    for (std::size_t i = 0; i < sample.size(); ++i)
    {
      sample[i] = packet[packet_number_offset + header_protection_sample_skip + i];
    }
    auto mask = _key.mask(sample);
    if (!mask.has_value())
    {
      return std::unexpected(mask.error());
    }

    const std::uint8_t bits = (packet[0] & header_form_long) != 0 ? 0x0f : 0x1f;
    packet[0] = static_cast<std::uint8_t>(packet[0] ^ ((*mask)[0] & bits));
    for (std::size_t i = 0; i < packet_number_length; ++i)
    {
      packet[packet_number_offset + i] = static_cast<std::uint8_t>(packet[packet_number_offset + i] ^ (*mask)[1 + i]);
    }
    return {};
  }

private:
  crypto::header_protection_key_t _key;
};

// The AEAD half: one per key phase per direction.
class packet_protection_t
{
public:
  [[nodiscard]] std::expected<void, error_t> init(cipher_suite_t suite, std::span<const std::uint8_t> secret)
  {
    auto material = derive_key_material(suite, secret);
    if (!material.has_value())
    {
      return std::unexpected(material.error());
    }
    if (auto r = _key.init(suite.aead, material->key); !r.has_value())
    {
      return std::unexpected(r.error());
    }
    _suite = suite;
    _iv = material->iv;
    _secret.assign(secret.begin(), secret.end());
    return {};
  }

  [[nodiscard]] bool initialized() const
  {
    return _key.initialized();
  }

  [[nodiscard]] cipher_suite_t suite() const
  {
    return _suite;
  }

  // The header protection key that goes with this secret. Derive it once, from
  // the first generation, and keep it across every key update after that.
  [[nodiscard]] std::expected<key_material_t, error_t> material() const
  {
    return derive_key_material(_suite, _secret);
  }

  // Section 6: the next key phase. Only the AEAD key and IV move; the caller
  // keeps using the header protection it already has.
  [[nodiscard]] std::expected<packet_protection_t, error_t> next_generation() const
  {
    auto next = derive_next_secret(_suite, _secret);
    if (!next.has_value())
    {
      return std::unexpected(next.error());
    }
    packet_protection_t generation;
    if (auto r = generation.init(_suite, *next); !r.has_value())
    {
      return std::unexpected(r.error());
    }
    return generation;
  }

  // Seals the frames in place. packet holds the header followed by
  // layout.frame_bytes of plaintext; on return the payload is ciphertext plus
  // its tag. The associated data is the header through the packet number,
  // which is why this must run before header protection goes on.
  [[nodiscard]] std::expected<std::size_t, error_t> encrypt(std::span<std::uint8_t> packet, const packet_layout_t &layout, std::uint64_t packet_number) const
  {
    if (!initialized())
    {
      return std::unexpected(error_t{.code = 1, .msg = "packet protection key is not initialized"});
    }
    if (packet.size() < layout.packet_length || layout.header_length + layout.frame_bytes > packet.size())
    {
      return std::unexpected(error_t{.code = 1, .msg = "buffer is too small for the packet described by the layout"});
    }

    const auto nonce = packet_nonce(_iv, packet_number);
    const auto aad = packet.first(layout.header_length);
    auto payload = packet.subspan(layout.header_length);
    // Exact aliasing only: LibreSSL allows out <= in, and these are equal.
    auto sealed = _key.seal(payload, nonce, payload.first(layout.frame_bytes), aad);
    if (!sealed.has_value())
    {
      return std::unexpected(sealed.error());
    }
    return layout.header_length + *sealed;
  }

  // Opens the payload in place. header must come from a matching
  // header_protection_t::remove on the same buffer, so that the header this
  // authenticates against is the unmasked one.
  [[nodiscard]] std::expected<opened_packet_t, unprotect_error_t> decrypt(std::span<std::uint8_t> packet, std::size_t packet_number_offset, const header_info_t &header, std::uint64_t largest_packet_number) const
  {
    if (!initialized())
    {
      return std::unexpected(unprotect_error_t::not_initialized);
    }
    const std::size_t payload_offset = packet_number_offset + header.packet_number_length;
    if (packet.size() < payload_offset + crypto::aead_tag_size)
    {
      return std::unexpected(unprotect_error_t::truncated);
    }

    const std::uint64_t packet_number = packet_number_decode(largest_packet_number, header.truncated_packet_number, header.packet_number_length * 8);
    const auto nonce = packet_nonce(_iv, packet_number);
    const auto aad = packet.first(payload_offset);
    auto payload = packet.subspan(payload_offset);

    auto opened = _key.open(payload, nonce, payload, aad);
    if (!opened.has_value())
    {
      return std::unexpected(unprotect_error_t::authentication_failed);
    }

    // Only now. Before the AEAD passes, these two bits are attacker-writable.
    const std::uint8_t reserved = header.long_header ? long_reserved_mask : short_reserved_mask;
    if ((header.first_byte & reserved) != 0)
    {
      return std::unexpected(unprotect_error_t::reserved_bits_set);
    }

    return opened_packet_t{.packet_number = packet_number, .key_phase = header.key_phase, .payload = payload.first(*opened)};
  }

private:
  cipher_suite_t _suite;
  std::vector<std::uint8_t> _secret;
  std::array<std::uint8_t, crypto::aead_nonce_size> _iv = {};
  crypto::aead_key_t _key;
};

// Seal, then mask. Returns the length of the finished packet.
[[nodiscard]] inline std::expected<std::size_t, error_t> protect_packet(const packet_protection_t &keys, header_protection_t &header_keys, std::span<std::uint8_t> packet, const packet_layout_t &layout, std::uint64_t packet_number)
{
  auto length = keys.encrypt(packet, layout, packet_number);
  if (!length.has_value())
  {
    return std::unexpected(length.error());
  }
  if (auto r = header_keys.apply(packet.first(*length), layout.packet_number_offset, layout.packet_number_length); !r.has_value())
  {
    return std::unexpected(r.error());
  }
  return length;
}

// Unmask, then open. Use the two halves directly when a key update is in
// flight: the key phase is only known once the header is unmasked, and which
// generation to open with follows from it.
[[nodiscard]] inline std::expected<opened_packet_t, unprotect_error_t> unprotect_packet(const packet_protection_t &keys, header_protection_t &header_keys, std::span<std::uint8_t> packet, std::size_t packet_number_offset,
                                                                                       std::uint64_t largest_packet_number)
{
  auto header = header_keys.remove(packet, packet_number_offset);
  if (!header.has_value())
  {
    return std::unexpected(header.error());
  }
  return keys.decrypt(packet, packet_number_offset, *header, largest_packet_number);
}

// Section 5.8: AEAD_AES_128_GCM over the Retry Pseudo-Packet, which is the
// Retry packet without its tag, prefixed by the connection ID the client put
// in the Initial this answers. That prefix is what stops anyone who did not
// see the Initial from forging a Retry.
[[nodiscard]] inline std::expected<std::array<std::uint8_t, retry_integrity_tag_size>, error_t> retry_integrity_tag(std::span<const std::uint8_t> original_destination_id, std::span<const std::uint8_t> retry_without_tag, std::uint32_t version = quic_version_1)
{
  if (original_destination_id.size() > max_connection_id_size)
  {
    return std::unexpected(error_t{.code = 1, .msg = "original destination connection id is too long"});
  }

  std::vector<std::uint8_t> pseudo;
  pseudo.reserve(1 + original_destination_id.size() + retry_without_tag.size());
  pseudo.push_back(static_cast<std::uint8_t>(original_destination_id.size()));
  pseudo.insert(pseudo.end(), original_destination_id.begin(), original_destination_id.end());
  pseudo.insert(pseudo.end(), retry_without_tag.begin(), retry_without_tag.end());

  crypto::aead_key_t key;
  if (auto r = key.init(crypto::aead_t::aes_128_gcm, version == quic_version_2 ? std::span<const std::uint8_t>(retry_key_v2) : std::span<const std::uint8_t>(retry_key_v1)); !r.has_value())
  {
    return std::unexpected(r.error());
  }

  std::array<std::uint8_t, retry_integrity_tag_size> tag = {};
  auto sealed = key.seal(tag, version == quic_version_2 ? retry_nonce_v2 : retry_nonce_v1, {}, pseudo);
  if (!sealed.has_value())
  {
    return std::unexpected(sealed.error());
  }
  if (*sealed != tag.size())
  {
    return std::unexpected(error_t{.code = 1, .msg = "unexpected retry tag length"});
  }
  return tag;
}

// Constant time against the tag, since a client checks this on a packet an
// attacker chose.
[[nodiscard]] inline bool verify_retry_integrity(std::span<const std::uint8_t> original_destination_id, std::span<const std::uint8_t> retry_packet)
{
  if (retry_packet.size() <= retry_integrity_tag_size)
  {
    return false;
  }
  auto expected = retry_integrity_tag(original_destination_id, retry_packet.first(retry_packet.size() - retry_integrity_tag_size));
  if (!expected.has_value())
  {
    return false;
  }
  const auto received = retry_packet.subspan(retry_packet.size() - retry_integrity_tag_size);
  std::uint8_t difference = 0;
  for (std::size_t i = 0; i < retry_integrity_tag_size; ++i)
  {
    difference = static_cast<std::uint8_t>(difference | (received[i] ^ (*expected)[i]));
  }
  return difference == 0;
}
} // namespace vio::quic
