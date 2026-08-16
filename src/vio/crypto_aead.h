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

// AEAD, HKDF and header protection.
//
// The primitives a record or packet protection layer needs, with no OpenSSL
// type on the interface. crypto.h covers digests and encodings; this covers
// keyed encryption.

#include "vio/error.h"
#include "vio/vio_export.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string_view>
#include <vector>

namespace vio::crypto
{
enum class aead_t : std::uint8_t
{
  aes_128_gcm,
  aes_256_gcm,
  chacha20_poly1305,
};

enum class hash_t : std::uint8_t
{
  sha256,
  sha384,
};

inline constexpr std::size_t aead_nonce_size = 12;
inline constexpr std::size_t aead_tag_size = 16;
inline constexpr std::size_t header_protection_sample_size = 16;
inline constexpr std::size_t header_protection_mask_size = 5;

using aead_nonce_t = std::array<std::uint8_t, aead_nonce_size>;
using header_protection_sample_t = std::array<std::uint8_t, header_protection_sample_size>;
using header_protection_mask_t = std::array<std::uint8_t, header_protection_mask_size>;

[[nodiscard]] VIO_EXPORT std::size_t hash_size(hash_t hash);
[[nodiscard]] VIO_EXPORT std::size_t aead_key_size(aead_t algorithm);

VIO_EXPORT std::expected<std::vector<std::uint8_t>, error_t> hkdf_extract(hash_t hash, std::span<const std::uint8_t> salt, std::span<const std::uint8_t> secret);

VIO_EXPORT std::expected<void, error_t> hkdf_expand(hash_t hash, std::span<const std::uint8_t> secret, std::span<const std::uint8_t> info, std::span<std::uint8_t> out);

// HKDF-Expand-Label from RFC 8446 section 7.1. The label is prefixed with
// "tls13 " and serialised into an HkdfLabel structure; callers pass the bare
// label ("client in", "quic key", ...).
VIO_EXPORT std::expected<void, error_t> hkdf_expand_label(hash_t hash, std::span<const std::uint8_t> secret, std::string_view label, std::span<const std::uint8_t> context, std::span<std::uint8_t> out);

class VIO_EXPORT aead_key_t
{
public:
  aead_key_t() = default;
  ~aead_key_t();

  aead_key_t(aead_key_t &&other) noexcept;
  aead_key_t &operator=(aead_key_t &&other) noexcept;
  aead_key_t(const aead_key_t &) = delete;
  aead_key_t &operator=(const aead_key_t &) = delete;

  std::expected<void, error_t> init(aead_t algorithm, std::span<const std::uint8_t> key);

  [[nodiscard]] bool initialized() const
  {
    return _ctx != nullptr;
  }

  [[nodiscard]] std::size_t tag_size() const
  {
    return aead_tag_size;
  }

  // out must have room for plaintext.size() + tag_size() bytes; returns the
  // number written.
  [[nodiscard]] std::expected<std::size_t, error_t> seal(std::span<std::uint8_t> out, std::span<const std::uint8_t, aead_nonce_size> nonce, std::span<const std::uint8_t> plaintext, std::span<const std::uint8_t> aad) const;

  // out must have room for ciphertext.size() bytes; returns the number
  // written, which is ciphertext.size() - tag_size().
  [[nodiscard]] std::expected<std::size_t, error_t> open(std::span<std::uint8_t> out, std::span<const std::uint8_t, aead_nonce_size> nonce, std::span<const std::uint8_t> ciphertext, std::span<const std::uint8_t> aad) const;

private:
  void *_ctx = nullptr;
};

// RFC 9001 section 5.4: a five-byte mask derived from a sample of the packet's
// ciphertext. AES keys mask with a single ECB block; ChaCha20 masks with the
// keystream, taking the sample as counter and nonce.
class VIO_EXPORT header_protection_key_t
{
public:
  header_protection_key_t() = default;
  ~header_protection_key_t();

  header_protection_key_t(header_protection_key_t &&other) noexcept;
  header_protection_key_t &operator=(header_protection_key_t &&other) noexcept;
  header_protection_key_t(const header_protection_key_t &) = delete;
  header_protection_key_t &operator=(const header_protection_key_t &) = delete;

  std::expected<void, error_t> init(aead_t algorithm, std::span<const std::uint8_t> key);

  [[nodiscard]] bool initialized() const
  {
    return _impl != nullptr;
  }

  [[nodiscard]] std::expected<header_protection_mask_t, error_t> mask(std::span<const std::uint8_t, header_protection_sample_size> sample) const;

private:
  void *_impl = nullptr;
};
} // namespace vio::crypto
