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

// Self-contained FIPS 180-4 SHA-256 + FIPS 198-1 HMAC-SHA-256. This exists so platforms without a
// system crypto library (WebAssembly/Emscripten) can still do AWS SigV4 signing, which needs only
// these two primitives. Kept header-only + inline in a distinct namespace (vio::detail) so it can be
// unit-tested natively alongside the OpenSSL-backed vio::crypto::sha256 without a link-time symbol
// clash; the wasm crypto TU (crypto_sha256.cpp) forwards vio::crypto::sha256/hmac_sha256 to these.

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>

namespace vio::detail
{

struct sha256_ctx_t
{
  uint32_t state[8];
  uint64_t bitlen;
  uint8_t buffer[64];
  size_t buffer_len;
};

inline uint32_t sha256_rotr(uint32_t x, uint32_t n)
{
  return (x >> n) | (x << (32 - n));
}

inline void sha256_compress(sha256_ctx_t &ctx, const uint8_t *block)
{
  static const uint32_t k[64] = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
                                  0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
                                  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
                                  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                                  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

  uint32_t m[64];
  for (int i = 0; i < 16; i++)
    m[i] = (uint32_t(block[i * 4]) << 24) | (uint32_t(block[i * 4 + 1]) << 16) | (uint32_t(block[i * 4 + 2]) << 8) | uint32_t(block[i * 4 + 3]);
  for (int i = 16; i < 64; i++)
  {
    uint32_t s0 = sha256_rotr(m[i - 15], 7) ^ sha256_rotr(m[i - 15], 18) ^ (m[i - 15] >> 3);
    uint32_t s1 = sha256_rotr(m[i - 2], 17) ^ sha256_rotr(m[i - 2], 19) ^ (m[i - 2] >> 10);
    m[i] = m[i - 16] + s0 + m[i - 7] + s1;
  }

  uint32_t a = ctx.state[0], b = ctx.state[1], c = ctx.state[2], d = ctx.state[3];
  uint32_t e = ctx.state[4], f = ctx.state[5], g = ctx.state[6], h = ctx.state[7];
  for (int i = 0; i < 64; i++)
  {
    uint32_t s1 = sha256_rotr(e, 6) ^ sha256_rotr(e, 11) ^ sha256_rotr(e, 25);
    uint32_t ch = (e & f) ^ (~e & g);
    uint32_t t1 = h + s1 + ch + k[i] + m[i];
    uint32_t s0 = sha256_rotr(a, 2) ^ sha256_rotr(a, 13) ^ sha256_rotr(a, 22);
    uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    uint32_t t2 = s0 + maj;
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }
  ctx.state[0] += a;
  ctx.state[1] += b;
  ctx.state[2] += c;
  ctx.state[3] += d;
  ctx.state[4] += e;
  ctx.state[5] += f;
  ctx.state[6] += g;
  ctx.state[7] += h;
}

inline void sha256_init(sha256_ctx_t &ctx)
{
  ctx.state[0] = 0x6a09e667;
  ctx.state[1] = 0xbb67ae85;
  ctx.state[2] = 0x3c6ef372;
  ctx.state[3] = 0xa54ff53a;
  ctx.state[4] = 0x510e527f;
  ctx.state[5] = 0x9b05688c;
  ctx.state[6] = 0x1f83d9ab;
  ctx.state[7] = 0x5be0cd19;
  ctx.bitlen = 0;
  ctx.buffer_len = 0;
}

inline void sha256_update(sha256_ctx_t &ctx, const uint8_t *data, size_t len)
{
  for (size_t i = 0; i < len; i++)
  {
    ctx.buffer[ctx.buffer_len++] = data[i];
    if (ctx.buffer_len == 64)
    {
      sha256_compress(ctx, ctx.buffer);
      ctx.bitlen += 512;
      ctx.buffer_len = 0;
    }
  }
}

inline void sha256_final(sha256_ctx_t &ctx, uint8_t out[32])
{
  uint64_t total_bits = ctx.bitlen + uint64_t(ctx.buffer_len) * 8;
  // Append 0x80, then zero-pad until 56 bytes mod 64, then the 64-bit big-endian length.
  ctx.buffer[ctx.buffer_len++] = 0x80;
  if (ctx.buffer_len > 56)
  {
    while (ctx.buffer_len < 64)
      ctx.buffer[ctx.buffer_len++] = 0x00;
    sha256_compress(ctx, ctx.buffer);
    ctx.buffer_len = 0;
  }
  while (ctx.buffer_len < 56)
    ctx.buffer[ctx.buffer_len++] = 0x00;
  for (int i = 7; i >= 0; i--)
    ctx.buffer[ctx.buffer_len++] = uint8_t((total_bits >> (i * 8)) & 0xFF);
  sha256_compress(ctx, ctx.buffer);
  for (int i = 0; i < 8; i++)
  {
    out[i * 4] = uint8_t((ctx.state[i] >> 24) & 0xFF);
    out[i * 4 + 1] = uint8_t((ctx.state[i] >> 16) & 0xFF);
    out[i * 4 + 2] = uint8_t((ctx.state[i] >> 8) & 0xFF);
    out[i * 4 + 3] = uint8_t(ctx.state[i] & 0xFF);
  }
}

inline std::array<uint8_t, 32> sha256_portable(std::span<const uint8_t> data)
{
  sha256_ctx_t ctx;
  sha256_init(ctx);
  sha256_update(ctx, data.data(), data.size());
  std::array<uint8_t, 32> out{};
  sha256_final(ctx, out.data());
  return out;
}

inline std::array<uint8_t, 32> hmac_sha256_portable(std::span<const uint8_t> key, std::span<const uint8_t> data)
{
  uint8_t k[64] = {0};
  if (key.size() > 64)
  {
    auto kh = sha256_portable(key);
    std::memcpy(k, kh.data(), 32);
  }
  else if (!key.empty())
  {
    std::memcpy(k, key.data(), key.size());
  }

  uint8_t ipad[64], opad[64];
  for (int i = 0; i < 64; i++)
  {
    ipad[i] = uint8_t(k[i] ^ 0x36);
    opad[i] = uint8_t(k[i] ^ 0x5c);
  }

  sha256_ctx_t inner;
  sha256_init(inner);
  sha256_update(inner, ipad, 64);
  sha256_update(inner, data.data(), data.size());
  uint8_t inner_digest[32];
  sha256_final(inner, inner_digest);

  sha256_ctx_t outer;
  sha256_init(outer);
  sha256_update(outer, opad, 64);
  sha256_update(outer, inner_digest, 32);
  std::array<uint8_t, 32> out{};
  sha256_final(outer, out.data());
  return out;
}

} // namespace vio::detail
