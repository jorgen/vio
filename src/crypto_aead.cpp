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

#include "vio/crypto_aead.h"

#include <cstring>
#include <new>
#include <utility>

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/hkdf.h>

namespace vio::crypto
{
namespace
{
const EVP_MD *md_for(hash_t hash)
{
  return hash == hash_t::sha384 ? EVP_sha384() : EVP_sha256();
}

const EVP_AEAD *aead_for(aead_t algorithm)
{
  switch (algorithm)
  {
  case aead_t::aes_128_gcm:
    return EVP_aead_aes_128_gcm();
  case aead_t::aes_256_gcm:
    return EVP_aead_aes_256_gcm();
  case aead_t::chacha20_poly1305:
    return EVP_aead_chacha20_poly1305();
  }
  return nullptr;
}

error_t crypto_error(const char *what)
{
  return error_t{.code = -1, .msg = what};
}

struct header_protection_impl_t
{
  aead_t algorithm = aead_t::aes_128_gcm;
  AES_KEY aes = {};
  std::array<std::uint8_t, 32> chacha_key = {};
};
} // namespace

std::size_t hash_size(hash_t hash)
{
  return hash == hash_t::sha384 ? 48u : 32u;
}

std::size_t aead_key_size(aead_t algorithm)
{
  switch (algorithm)
  {
  case aead_t::aes_128_gcm:
    return 16;
  case aead_t::aes_256_gcm:
  case aead_t::chacha20_poly1305:
    return 32;
  }
  return 0;
}

std::expected<std::vector<std::uint8_t>, error_t> hkdf_extract(hash_t hash, std::span<const std::uint8_t> salt, std::span<const std::uint8_t> secret)
{
  std::vector<std::uint8_t> prk(EVP_MAX_MD_SIZE);
  std::size_t out_len = prk.size();
  if (HKDF_extract(prk.data(), &out_len, md_for(hash), secret.data(), secret.size(), salt.data(), salt.size()) != 1)
  {
    return std::unexpected(crypto_error("HKDF_extract failed"));
  }
  prk.resize(out_len);
  return prk;
}

std::expected<void, error_t> hkdf_expand(hash_t hash, std::span<const std::uint8_t> secret, std::span<const std::uint8_t> info, std::span<std::uint8_t> out)
{
  if (out.empty())
  {
    return {};
  }
  if (HKDF_expand(out.data(), out.size(), md_for(hash), secret.data(), secret.size(), info.data(), info.size()) != 1)
  {
    return std::unexpected(crypto_error("HKDF_expand failed"));
  }
  return {};
}

std::expected<void, error_t> hkdf_expand_label(hash_t hash, std::span<const std::uint8_t> secret, std::string_view label, std::span<const std::uint8_t> context, std::span<std::uint8_t> out)
{
  static constexpr std::string_view prefix = "tls13 ";
  if (label.size() + prefix.size() > 255 || context.size() > 255 || out.size() > 0xffff)
  {
    return std::unexpected(crypto_error("hkdf_expand_label: HkdfLabel field out of range"));
  }

  std::vector<std::uint8_t> info;
  info.reserve(4 + prefix.size() + label.size() + context.size());
  info.push_back(static_cast<std::uint8_t>((out.size() >> 8) & 0xff));
  info.push_back(static_cast<std::uint8_t>(out.size() & 0xff));
  info.push_back(static_cast<std::uint8_t>(prefix.size() + label.size()));
  info.insert(info.end(), prefix.begin(), prefix.end());
  info.insert(info.end(), label.begin(), label.end());
  info.push_back(static_cast<std::uint8_t>(context.size()));
  info.insert(info.end(), context.begin(), context.end());

  return hkdf_expand(hash, secret, info, out);
}

aead_key_t::~aead_key_t()
{
  if (_ctx != nullptr)
  {
    EVP_AEAD_CTX_free(static_cast<EVP_AEAD_CTX *>(_ctx));
    _ctx = nullptr;
  }
}

aead_key_t::aead_key_t(aead_key_t &&other) noexcept
  : _ctx(std::exchange(other._ctx, nullptr))
{
}

aead_key_t &aead_key_t::operator=(aead_key_t &&other) noexcept
{
  if (this != &other)
  {
    if (_ctx != nullptr)
    {
      EVP_AEAD_CTX_free(static_cast<EVP_AEAD_CTX *>(_ctx));
    }
    _ctx = std::exchange(other._ctx, nullptr);
  }
  return *this;
}

std::expected<void, error_t> aead_key_t::init(aead_t algorithm, std::span<const std::uint8_t> key)
{
  const EVP_AEAD *aead = aead_for(algorithm);
  if (aead == nullptr)
  {
    return std::unexpected(crypto_error("unknown AEAD algorithm"));
  }
  if (key.size() != aead_key_size(algorithm))
  {
    return std::unexpected(crypto_error("AEAD key length does not match the algorithm"));
  }

  EVP_AEAD_CTX *ctx = EVP_AEAD_CTX_new();
  if (ctx == nullptr)
  {
    return std::unexpected(crypto_error("EVP_AEAD_CTX_new failed"));
  }
  if (EVP_AEAD_CTX_init(ctx, aead, key.data(), key.size(), aead_tag_size, nullptr) != 1)
  {
    EVP_AEAD_CTX_free(ctx);
    return std::unexpected(crypto_error("EVP_AEAD_CTX_init failed"));
  }

  if (_ctx != nullptr)
  {
    EVP_AEAD_CTX_free(static_cast<EVP_AEAD_CTX *>(_ctx));
  }
  _ctx = ctx;
  return {};
}

std::expected<std::size_t, error_t> aead_key_t::seal(std::span<std::uint8_t> out, std::span<const std::uint8_t, aead_nonce_size> nonce, std::span<const std::uint8_t> plaintext, std::span<const std::uint8_t> aad) const
{
  if (_ctx == nullptr)
  {
    return std::unexpected(crypto_error("AEAD key not initialized"));
  }
  std::size_t out_len = 0;
  if (EVP_AEAD_CTX_seal(static_cast<const EVP_AEAD_CTX *>(_ctx), out.data(), &out_len, out.size(), nonce.data(), nonce.size(), plaintext.data(), plaintext.size(), aad.data(), aad.size()) != 1)
  {
    return std::unexpected(crypto_error("EVP_AEAD_CTX_seal failed"));
  }
  return out_len;
}

std::expected<std::size_t, error_t> aead_key_t::open(std::span<std::uint8_t> out, std::span<const std::uint8_t, aead_nonce_size> nonce, std::span<const std::uint8_t> ciphertext, std::span<const std::uint8_t> aad) const
{
  if (_ctx == nullptr)
  {
    return std::unexpected(crypto_error("AEAD key not initialized"));
  }
  std::size_t out_len = 0;
  if (EVP_AEAD_CTX_open(static_cast<const EVP_AEAD_CTX *>(_ctx), out.data(), &out_len, out.size(), nonce.data(), nonce.size(), ciphertext.data(), ciphertext.size(), aad.data(), aad.size()) != 1)
  {
    return std::unexpected(crypto_error("EVP_AEAD_CTX_open failed"));
  }
  return out_len;
}

header_protection_key_t::~header_protection_key_t()
{
  delete static_cast<header_protection_impl_t *>(_impl);
  _impl = nullptr;
}

header_protection_key_t::header_protection_key_t(header_protection_key_t &&other) noexcept
  : _impl(std::exchange(other._impl, nullptr))
{
}

header_protection_key_t &header_protection_key_t::operator=(header_protection_key_t &&other) noexcept
{
  if (this != &other)
  {
    delete static_cast<header_protection_impl_t *>(_impl);
    _impl = std::exchange(other._impl, nullptr);
  }
  return *this;
}

std::expected<void, error_t> header_protection_key_t::init(aead_t algorithm, std::span<const std::uint8_t> key)
{
  if (key.size() != aead_key_size(algorithm))
  {
    return std::unexpected(crypto_error("header protection key length does not match the algorithm"));
  }

  auto *impl = new (std::nothrow) header_protection_impl_t();
  if (impl == nullptr)
  {
    return std::unexpected(crypto_error("out of memory"));
  }
  impl->algorithm = algorithm;

  if (algorithm == aead_t::chacha20_poly1305)
  {
    std::memcpy(impl->chacha_key.data(), key.data(), key.size());
  }
  else if (AES_set_encrypt_key(key.data(), static_cast<int>(key.size() * 8), &impl->aes) != 0)
  {
    delete impl;
    return std::unexpected(crypto_error("AES_set_encrypt_key failed"));
  }

  delete static_cast<header_protection_impl_t *>(_impl);
  _impl = impl;
  return {};
}

std::expected<header_protection_mask_t, error_t> header_protection_key_t::mask(std::span<const std::uint8_t, header_protection_sample_size> sample) const
{
  const auto *impl = static_cast<const header_protection_impl_t *>(_impl);
  if (impl == nullptr)
  {
    return std::unexpected(crypto_error("header protection key not initialized"));
  }

  header_protection_mask_t out = {};

  if (impl->algorithm != aead_t::chacha20_poly1305)
  {
    std::array<std::uint8_t, header_protection_sample_size> block = {};
    AES_encrypt(sample.data(), block.data(), &impl->aes);
    std::memcpy(out.data(), block.data(), out.size());
    return out;
  }

  // RFC 9001 section 5.4.4: the sample is the 4-byte little-endian counter
  // followed by the 12-byte nonce, which is exactly EVP_chacha20's 16-byte IV
  // layout, and the mask is the keystream.
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (ctx == nullptr)
  {
    return std::unexpected(crypto_error("EVP_CIPHER_CTX_new failed"));
  }
  if (EVP_EncryptInit_ex(ctx, EVP_chacha20(), nullptr, impl->chacha_key.data(), sample.data()) != 1)
  {
    EVP_CIPHER_CTX_free(ctx);
    return std::unexpected(crypto_error("EVP_EncryptInit_ex failed"));
  }
  const std::array<std::uint8_t, header_protection_mask_size> zeros = {};
  int written = 0;
  if (EVP_EncryptUpdate(ctx, out.data(), &written, zeros.data(), static_cast<int>(zeros.size())) != 1 || written != static_cast<int>(out.size()))
  {
    EVP_CIPHER_CTX_free(ctx);
    return std::unexpected(crypto_error("EVP_EncryptUpdate failed"));
  }
  EVP_CIPHER_CTX_free(ctx);
  return out;
}
} // namespace vio::crypto
