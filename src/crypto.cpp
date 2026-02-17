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

#include "vio/crypto.h"

#include <openssl/hmac.h>
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

std::string to_hex(std::span<const uint8_t> data)
{
  static constexpr char hex_chars[] = "0123456789abcdef";
  std::string result;
  result.reserve(data.size() * 2);
  for (auto byte : data)
  {
    result.push_back(hex_chars[(byte >> 4) & 0x0F]);
    result.push_back(hex_chars[byte & 0x0F]);
  }
  return result;
}

} // namespace vio::crypto
