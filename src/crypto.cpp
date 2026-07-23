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

// OpenSSL/LibreSSL-backed hashing primitives (native builds). The dependency-free encoders
// (to_hex, base64*) live in crypto_encoding.cpp so they can be shared with the wasm build, and the
// standalone SHA-256/HMAC used by the wasm build lives in crypto_sha256.cpp.

#include "vio/crypto.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

namespace vio::crypto
{

sha1_digest_t sha1(std::span<const uint8_t> data)
{
  sha1_digest_t digest;
  SHA1(data.data(), data.size(), digest.data());
  return digest;
}

sha256_digest_t sha256(std::span<const uint8_t> data)
{
  sha256_digest_t digest;
  SHA256(data.data(), data.size(), digest.data());
  return digest;
}

sha512_digest_t sha512(std::span<const uint8_t> data)
{
  sha512_digest_t digest;
  SHA512(data.data(), data.size(), digest.data());
  return digest;
}

sha256_digest_t hmac_sha256(std::span<const uint8_t> key, std::span<const uint8_t> data)
{
  sha256_digest_t digest;
  unsigned int len = 0;
  HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), data.data(), data.size(), digest.data(), &len);
  return digest;
}

sha512_digest_t hmac_sha512(std::span<const uint8_t> key, std::span<const uint8_t> data)
{
  sha512_digest_t digest;
  unsigned int len = 0;
  HMAC(EVP_sha512(), key.data(), static_cast<int>(key.size()), data.data(), data.size(), digest.data(), &len);
  return digest;
}

sha256_digest_t pbkdf2_hmac_sha256(std::span<const uint8_t> password, std::span<const uint8_t> salt, uint32_t iterations)
{
  sha256_digest_t digest;
  PKCS5_PBKDF2_HMAC(reinterpret_cast<const char *>(password.data()), static_cast<int>(password.size()), salt.data(), static_cast<int>(salt.size()), static_cast<int>(iterations), EVP_sha256(), static_cast<int>(digest.size()), digest.data());
  return digest;
}

std::expected<void, error_t> random_bytes(std::span<uint8_t> out)
{
  if (out.empty())
  {
    return {};
  }
  if (RAND_bytes(out.data(), static_cast<int>(out.size())) != 1)
  {
    return std::unexpected(error_t{-1, "RAND_bytes failed to produce random data"});
  }
  return {};
}

} // namespace vio::crypto
