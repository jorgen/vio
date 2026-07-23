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

// WebAssembly/Emscripten build of vio::crypto. There is no system OpenSSL/LibreSSL in the browser,
// so this TU provides exactly the primitives AWS SigV4 needs -- SHA-256, HMAC-SHA-256 -- from the
// self-contained implementation in vio/detail/sha2_portable.h, plus random_bytes via getentropy.
// The dependency-free encoders (to_hex, base64*) come from crypto_encoding.cpp. The remaining
// declarations in crypto.h (sha1, sha512, hmac_sha512, pbkdf2_hmac_sha256) are not on the object-store
// read path and are intentionally left undefined here; referencing one is a link error by design.

#include "vio/crypto.h"

#include "vio/detail/sha2_portable.h"

#include <sys/random.h>

namespace vio::crypto
{

sha256_digest_t sha256(std::span<const uint8_t> data)
{
  return detail::sha256_portable(data);
}

sha256_digest_t hmac_sha256(std::span<const uint8_t> key, std::span<const uint8_t> data)
{
  return detail::hmac_sha256_portable(key, data);
}

std::expected<void, error_t> random_bytes(std::span<uint8_t> out)
{
  // getentropy fills at most 256 bytes per call.
  size_t off = 0;
  while (off < out.size())
  {
    size_t chunk = out.size() - off;
    if (chunk > 256)
      chunk = 256;
    if (getentropy(out.data() + off, chunk) != 0)
      return std::unexpected(error_t{-1, "getentropy failed"});
    off += chunk;
  }
  return {};
}

} // namespace vio::crypto
