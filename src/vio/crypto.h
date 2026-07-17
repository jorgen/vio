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

#include "vio/error.h"
#include "vio/vio_export.h"

#include <array>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace vio::crypto
{
inline constexpr size_t sha1_digest_size = 20;
inline constexpr size_t sha256_digest_size = 32;
inline constexpr size_t sha512_digest_size = 64;

using sha1_digest_t = std::array<uint8_t, sha1_digest_size>;
using sha256_digest_t = std::array<uint8_t, sha256_digest_size>;
using sha512_digest_t = std::array<uint8_t, sha512_digest_size>;

VIO_EXPORT sha1_digest_t sha1(std::span<const uint8_t> data);
VIO_EXPORT sha256_digest_t sha256(std::span<const uint8_t> data);
VIO_EXPORT sha512_digest_t sha512(std::span<const uint8_t> data);

VIO_EXPORT sha256_digest_t hmac_sha256(std::span<const uint8_t> key, std::span<const uint8_t> data);
VIO_EXPORT sha512_digest_t hmac_sha512(std::span<const uint8_t> key, std::span<const uint8_t> data);

VIO_EXPORT sha256_digest_t pbkdf2_hmac_sha256(std::span<const uint8_t> password, std::span<const uint8_t> salt, uint32_t iterations);

VIO_EXPORT std::expected<void, error_t> random_bytes(std::span<uint8_t> out);

VIO_EXPORT std::string to_hex(std::span<const uint8_t> data);

VIO_EXPORT std::string base64_encode(std::span<const uint8_t> data);
VIO_EXPORT std::expected<std::vector<uint8_t>, error_t> base64_decode(std::string_view text);

// URL-safe base64 (RFC 4648 §5): '+'/'/' become '-'/'_' and trailing '=' padding
// is omitted. Used by JOSE/JWS (base64url) in the ACME client. Decode is lenient:
// it accepts optional padding and restores it before decoding.
VIO_EXPORT std::string base64url_encode(std::span<const uint8_t> data);
VIO_EXPORT std::expected<std::vector<uint8_t>, error_t> base64url_decode(std::string_view text);
} // namespace vio::crypto
