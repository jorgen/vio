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

namespace
{
constexpr char base64_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int base64_value(char c)
{
  if (c >= 'A' && c <= 'Z')
  {
    return c - 'A';
  }
  if (c >= 'a' && c <= 'z')
  {
    return c - 'a' + 26;
  }
  if (c >= '0' && c <= '9')
  {
    return c - '0' + 52;
  }
  if (c == '+')
  {
    return 62;
  }
  if (c == '/')
  {
    return 63;
  }
  return -1;
}
} // namespace

std::string base64_encode(std::span<const uint8_t> data)
{
  std::string out;
  out.reserve(((data.size() + 2) / 3) * 4);
  size_t i = 0;
  while (i + 3 <= data.size())
  {
    uint32_t chunk = (static_cast<uint32_t>(data[i]) << 16) | (static_cast<uint32_t>(data[i + 1]) << 8) | static_cast<uint32_t>(data[i + 2]);
    out.push_back(base64_alphabet[(chunk >> 18) & 0x3F]);
    out.push_back(base64_alphabet[(chunk >> 12) & 0x3F]);
    out.push_back(base64_alphabet[(chunk >> 6) & 0x3F]);
    out.push_back(base64_alphabet[chunk & 0x3F]);
    i += 3;
  }
  size_t remaining = data.size() - i;
  if (remaining == 1)
  {
    uint32_t chunk = static_cast<uint32_t>(data[i]) << 16;
    out.push_back(base64_alphabet[(chunk >> 18) & 0x3F]);
    out.push_back(base64_alphabet[(chunk >> 12) & 0x3F]);
    out.push_back('=');
    out.push_back('=');
  }
  else if (remaining == 2)
  {
    uint32_t chunk = (static_cast<uint32_t>(data[i]) << 16) | (static_cast<uint32_t>(data[i + 1]) << 8);
    out.push_back(base64_alphabet[(chunk >> 18) & 0x3F]);
    out.push_back(base64_alphabet[(chunk >> 12) & 0x3F]);
    out.push_back(base64_alphabet[(chunk >> 6) & 0x3F]);
    out.push_back('=');
  }
  return out;
}

std::expected<std::vector<uint8_t>, error_t> base64_decode(std::string_view text)
{
  if (text.size() % 4 != 0)
  {
    return std::unexpected(error_t{-1, "base64 input length is not a multiple of 4"});
  }
  std::vector<uint8_t> out;
  out.reserve((text.size() / 4) * 3);
  for (size_t i = 0; i < text.size(); i += 4)
  {
    int v0 = base64_value(text[i]);
    int v1 = base64_value(text[i + 1]);
    if (v0 < 0 || v1 < 0)
    {
      return std::unexpected(error_t{-1, "invalid base64 character"});
    }
    bool pad2 = text[i + 2] == '=';
    bool pad3 = text[i + 3] == '=';
    int v2 = pad2 ? 0 : base64_value(text[i + 2]);
    int v3 = pad3 ? 0 : base64_value(text[i + 3]);
    if ((!pad2 && v2 < 0) || (!pad3 && v3 < 0) || (pad2 && !pad3))
    {
      return std::unexpected(error_t{-1, "invalid base64 padding"});
    }
    uint32_t chunk = (static_cast<uint32_t>(v0) << 18) | (static_cast<uint32_t>(v1) << 12) | (static_cast<uint32_t>(v2) << 6) | static_cast<uint32_t>(v3);
    out.push_back(static_cast<uint8_t>((chunk >> 16) & 0xFF));
    if (!pad2)
    {
      out.push_back(static_cast<uint8_t>((chunk >> 8) & 0xFF));
    }
    if (!pad3)
    {
      out.push_back(static_cast<uint8_t>(chunk & 0xFF));
    }
  }
  return out;
}

std::string base64url_encode(std::span<const uint8_t> data)
{
  std::string out = base64_encode(data);
  size_t n = out.size();
  while (n > 0 && out[n - 1] == '=')
  {
    --n;
  }
  out.resize(n);
  for (char &c : out)
  {
    if (c == '+')
    {
      c = '-';
    }
    else if (c == '/')
    {
      c = '_';
    }
  }
  return out;
}

std::expected<std::vector<uint8_t>, error_t> base64url_decode(std::string_view text)
{
  std::string std_b64;
  std_b64.reserve(text.size() + 3);
  for (char c : text)
  {
    if (c == '-')
    {
      std_b64.push_back('+');
    }
    else if (c == '_')
    {
      std_b64.push_back('/');
    }
    else if (c != '=')
    {
      std_b64.push_back(c);
    }
  }
  while (std_b64.size() % 4 != 0)
  {
    std_b64.push_back('=');
  }
  return base64_decode(std_b64);
}

} // namespace vio::crypto
