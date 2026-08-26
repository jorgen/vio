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

// The address validation token a server puts in a Retry packet, RFC 9000
// section 8.1.
//
// The RFC deliberately says nothing about what a token contains: it never
// leaves the server that issued it, so its format is that server's business.
// What the RFC does require is what the token must prove, and those
// requirements are what this format is built from.
//
// A token must be unforgeable, or address validation proves nothing -- anyone
// could mint one and skip the round trip that Retry exists to force. It is
// therefore sealed with an AEAD under a secret only the server holds, not
// merely hashed or encoded.
//
// A token must be bound to the connection it was issued for. Section 8.1.4:
// the original destination connection ID is carried inside so a server can
// recover it, and the client address is authenticated as associated data so a
// token issued to one address cannot be replayed from another -- which is the
// whole attack Retry defends against.
//
// A token must expire. Without a lifetime a single captured token is a
// permanent bypass of address validation for that address.

#include "vio/crypto.h"
#include "vio/crypto_aead.h"
#include "vio/quic/connection_id.h"
#include "vio/tick.h"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <vector>

namespace vio::quic
{
inline constexpr std::size_t retry_token_key_size = 32;
inline constexpr std::chrono::nanoseconds default_retry_token_lifetime = std::chrono::seconds(10);

// Section 8.1.3: a token from a NEW_TOKEN frame is meant to be kept and
// presented on a later connection, so it lives far longer than the Retry token
// that only has to survive one round trip.
inline constexpr std::chrono::nanoseconds new_token_lifetime = std::chrono::hours(24);

// Section 8.1.3 and 8.1.4 both hand a client an opaque token, and a server must
// not confuse them. A Retry token is used immediately and carries the
// connection ID the client first chose, which the handshake then requires the
// server to echo. A NEW_TOKEN token is used on some later connection, carries
// no connection ID, and is bound to the client's address without its port --
// the port will almost certainly differ next time, so binding it would make
// the token useless.
//
// Treating one as the other is a real failure and not a theoretical one:
// accepting a NEW_TOKEN token where a Retry token was expected would skip the
// original-connection-ID check that ties a Retry to the exchange it belongs to.
enum class address_token_kind_t : std::uint8_t
{
  retry = 1,
  new_token = 2,
};

// The plaintext: what kind of token, when it was issued, and the connection ID
// the client first chose. The kind is inside the sealed part, so it cannot be
// changed by anyone who does not hold the key.
inline constexpr std::size_t retry_token_plaintext_size = 1 + 8 + 1 + max_connection_id_size;
inline constexpr std::size_t retry_token_size = crypto::aead_nonce_size + retry_token_plaintext_size + crypto::aead_tag_size;

enum class retry_token_error_t : std::uint8_t
{
  malformed,
  // The AEAD refused it: forged, corrupted, or issued under a different key.
  not_authentic,
  // Authentic, but too old to still stand for a validated address.
  expired,
};

// One per server, for as long as it wants tokens it issued to stay valid.
class retry_token_key_t
{
public:
  [[nodiscard]] std::expected<void, error_t> init(std::span<const std::uint8_t> secret)
  {
    return _key.init(crypto::aead_t::aes_256_gcm, secret);
  }

  // Generates a fresh secret. A server that restarts issues tokens under a new
  // one, which invalidates outstanding tokens rather than accepting tokens it
  // cannot account for.
  [[nodiscard]] std::expected<void, error_t> generate()
  {
    std::array<std::uint8_t, retry_token_key_size> secret = {};
    if (auto r = crypto::random_bytes(secret); !r.has_value())
    {
      return std::unexpected(r.error());
    }
    return _key.init(crypto::aead_t::aes_256_gcm, secret);
  }

  [[nodiscard]] bool initialized() const
  {
    return _key.initialized();
  }

  // client_address is authenticated but not carried: the server already knows
  // the address a packet arrived from, and binding the token to it is what
  // stops a token issued to one peer being replayed by another.
  [[nodiscard]] std::expected<std::vector<std::uint8_t>, error_t> issue(const connection_id_t &original_destination_id, std::span<const std::uint8_t> client_address, tick_t now) const
  {
    return issue(address_token_kind_t::retry, original_destination_id, client_address, now);
  }

  // Section 8.1.3: no connection ID, and the caller passes an address without
  // the port so the token survives to the next connection.
  [[nodiscard]] std::expected<std::vector<std::uint8_t>, error_t> issue_new_token(std::span<const std::uint8_t> client_address, tick_t now) const
  {
    return issue(address_token_kind_t::new_token, connection_id_t{}, client_address, now);
  }

  [[nodiscard]] std::expected<std::vector<std::uint8_t>, error_t> issue(address_token_kind_t kind, const connection_id_t &original_destination_id, std::span<const std::uint8_t> client_address, tick_t now) const
  {
    if (!_key.initialized())
    {
      return std::unexpected(error_t{.code = 1, .msg = "retry token key is not initialized"});
    }

    std::array<std::uint8_t, retry_token_plaintext_size> plaintext = {};
    plaintext[0] = static_cast<std::uint8_t>(kind);
    const auto issued = static_cast<std::uint64_t>(now.since_origin().count());
    for (std::size_t i = 0; i < 8; ++i)
    {
      plaintext[1 + i] = static_cast<std::uint8_t>((issued >> (8 * (7 - i))) & 0xff);
    }
    const auto bytes = original_destination_id.bytes();
    plaintext[9] = static_cast<std::uint8_t>(bytes.size());
    std::copy(bytes.begin(), bytes.end(), plaintext.begin() + 10);

    std::vector<std::uint8_t> token(retry_token_size);
    auto nonce_span = std::span<std::uint8_t>(token).first(crypto::aead_nonce_size);
    if (auto r = crypto::random_bytes(nonce_span); !r.has_value())
    {
      return std::unexpected(r.error());
    }
    crypto::aead_nonce_t nonce = {};
    std::copy(nonce_span.begin(), nonce_span.end(), nonce.begin());

    auto sealed = _key.seal(std::span<std::uint8_t>(token).subspan(crypto::aead_nonce_size), nonce, plaintext, client_address);
    if (!sealed.has_value())
    {
      return std::unexpected(sealed.error());
    }
    token.resize(crypto::aead_nonce_size + *sealed);
    return token;
  }

  // What a token turned out to be. The connection ID is meaningful only for a
  // Retry token; a NEW_TOKEN one carries none, by section 8.1.3.
  struct validated_token_t
  {
    address_token_kind_t kind = address_token_kind_t::retry;
    connection_id_t original_destination_id;
  };

  // Returns the connection ID the client originally chose, which the handshake
  // then requires the server to echo back in a transport parameter.
  [[nodiscard]] std::expected<validated_token_t, retry_token_error_t> validate(std::span<const std::uint8_t> token, std::span<const std::uint8_t> client_address, tick_t now, std::chrono::nanoseconds lifetime = default_retry_token_lifetime) const
  {
    if (!_key.initialized() || token.size() != retry_token_size)
    {
      return std::unexpected(retry_token_error_t::malformed);
    }

    crypto::aead_nonce_t nonce = {};
    std::copy(token.begin(), token.begin() + static_cast<std::ptrdiff_t>(crypto::aead_nonce_size), nonce.begin());

    std::array<std::uint8_t, retry_token_plaintext_size> plaintext = {};
    auto opened = _key.open(plaintext, nonce, token.subspan(crypto::aead_nonce_size), client_address);
    if (!opened.has_value() || *opened != plaintext.size())
    {
      // Either forged, corrupted, or presented from an address other than the
      // one it was issued to. All three are the same answer.
      return std::unexpected(retry_token_error_t::not_authentic);
    }

    const auto kind = plaintext[0];
    if (kind != static_cast<std::uint8_t>(address_token_kind_t::retry) && kind != static_cast<std::uint8_t>(address_token_kind_t::new_token))
    {
      return std::unexpected(retry_token_error_t::malformed);
    }

    std::uint64_t issued = 0;
    for (std::size_t i = 0; i < 8; ++i)
    {
      issued = (issued << 8) | plaintext[1 + i];
    }
    const auto age = now.since_origin() - std::chrono::nanoseconds(static_cast<std::int64_t>(issued));
    if (age < std::chrono::nanoseconds::zero() || age > lifetime)
    {
      return std::unexpected(retry_token_error_t::expired);
    }

    const std::size_t length = plaintext[9];
    if (length > max_connection_id_size)
    {
      return std::unexpected(retry_token_error_t::malformed);
    }
    auto id = connection_id_t::from_bytes(std::span<const std::uint8_t>(plaintext).subspan(10, length));
    if (!id.has_value())
    {
      return std::unexpected(retry_token_error_t::malformed);
    }
    return validated_token_t{.kind = static_cast<address_token_kind_t>(kind), .original_destination_id = *id};
  }

private:
  crypto::aead_key_t _key;
};
} // namespace vio::quic
