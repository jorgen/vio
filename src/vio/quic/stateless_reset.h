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

// RFC 9000 section 10.3, the stateless reset: how an endpoint that has lost all
// memory of a connection tells the peer to stop talking to it.
//
// Nothing else in QUIC can do this job. A CONNECTION_CLOSE has to be encrypted
// under keys the endpoint no longer has, and silence leaves the peer retrying
// until its idle timeout. So the reset is deliberately built out of the only
// thing both sides still share: a token the peer was told during the handshake,
// which the endpoint can recompute from a long-lived key and the connection ID
// alone.
//
// Two properties do all the work, and both are easy to lose:
//
//   The token must be unguessable (section 10.3.2). Anyone who can guess one
//   can kill the connection, so it is an HMAC under a secret key rather than
//   anything derived from the connection ID in the open.
//
//   The reset must be indistinguishable from an ordinary short-header packet
//   (section 10.3). If an observer can pick resets out of a flow, the token
//   becomes a signal for off-path attackers to probe.

#include "vio/crypto.h"
#include "vio/error.h"
#include "vio/quic/connection_id.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>

namespace vio::quic
{
// Section 10.3: 21 bytes is the smallest thing that can pass for a 1-RTT
// packet -- two fixed bits, 38 unpredictable bits, and the 16 byte token.
inline constexpr std::size_t minimum_stateless_reset_size = 21;

// Derives every token this endpoint will ever hand out, from one key. An
// endpoint that restarts and reloads the key can still answer for connections
// it has otherwise forgotten, which is the entire point of the mechanism --
// per-connection random tokens would be lost with the connection.
class stateless_reset_key_t
{
public:
  [[nodiscard]] static std::expected<stateless_reset_key_t, error_t> create()
  {
    stateless_reset_key_t key;
    if (auto r = crypto::random_bytes(key._secret); !r.has_value())
    {
      return std::unexpected(r.error());
    }
    return key;
  }

  [[nodiscard]] static stateless_reset_key_t from_secret(std::span<const std::uint8_t> secret)
  {
    stateless_reset_key_t key;
    const auto digest = crypto::sha256(secret);
    std::copy(digest.begin(), digest.end(), key._secret.begin());
    return key;
  }

  [[nodiscard]] stateless_reset_token_t token_for(const connection_id_t &id) const
  {
    const auto digest = crypto::hmac_sha256(_secret, id.bytes());
    stateless_reset_token_t token = {};
    std::copy_n(digest.begin(), token.size(), token.begin());
    return token;
  }

private:
  std::array<std::uint8_t, 32> _secret = {};
};

// Section 10.3.1: the comparison must not leak which byte differed, because
// the token is a secret and a timing signal is enough to recover it a byte at
// a time.
[[nodiscard]] inline bool tokens_equal(std::span<const std::uint8_t> lhs, std::span<const std::uint8_t> rhs)
{
  if (lhs.size() != stateless_reset_token_size || rhs.size() != stateless_reset_token_size)
  {
    return false;
  }
  std::uint8_t difference = 0;
  for (std::size_t i = 0; i < stateless_reset_token_size; ++i)
  {
    difference = static_cast<std::uint8_t>(difference | (lhs[i] ^ rhs[i]));
  }
  return difference == 0;
}

// Section 10.3.1: a datagram is a candidate reset if it is long enough to have
// been a packet at all. The trailing bytes are all a receiver gets to work
// with -- there is nothing else in a reset that identifies it.
[[nodiscard]] inline std::span<const std::uint8_t> trailing_token(std::span<const std::uint8_t> datagram)
{
  if (datagram.size() < minimum_stateless_reset_size)
  {
    return {};
  }
  return datagram.last(stateless_reset_token_size);
}

// Section 10.3. Writes a reset for the given token into out, sized against the
// packet that provoked it, and returns how many bytes it used.
//
// The size rules are not cosmetic. An endpoint MUST NOT send a reset three
// times or more the size of what arrived, or it becomes an amplifier; and a
// reset answering a packet of 43 bytes or fewer is made one byte shorter than
// that packet, so that two endpoints which have both lost state cannot answer
// each other forever -- each exchange shrinks until it is too small to be a
// packet at all.
[[nodiscard]] inline std::expected<std::size_t, error_t> build_stateless_reset(std::span<std::uint8_t> out, const stateless_reset_token_t &token, std::size_t received_size)
{
  if (received_size < minimum_stateless_reset_size + 1)
  {
    // Nothing legal could be sent in reply: a reset must be shorter than a
    // packet this small, and shorter than the minimum is not a packet.
    return std::size_t{0};
  }

  std::size_t size = out.size();
  if (received_size <= 43)
  {
    size = std::min(size, received_size - 1);
  }
  else
  {
    // Well under the three-times ceiling, and large enough that it cannot be
    // told apart from a packet carrying a connection ID.
    size = std::min(size, std::min<std::size_t>(received_size - 1, 64));
  }
  if (size < minimum_stateless_reset_size)
  {
    return std::size_t{0};
  }

  auto unpredictable = out.first(size - stateless_reset_token_size);
  if (auto r = crypto::random_bytes(unpredictable); !r.has_value())
  {
    return std::unexpected(r.error());
  }
  // Section 10.3: the first two bits are what makes this look like a
  // short-header packet -- header form 0, fixed bit 1.
  unpredictable[0] = static_cast<std::uint8_t>((unpredictable[0] & 0x3f) | 0x40);
  std::copy(token.begin(), token.end(), out.begin() + static_cast<std::ptrdiff_t>(size - stateless_reset_token_size));
  return size;
}
} // namespace vio::quic
