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

// The seam between QUIC and TLS 1.3 (RFC 9001 section 4).
//
// QUIC does not run over TLS records; it borrows the TLS handshake and carries
// its messages in CRYPTO frames. LibreSSL exposes that as a set of callbacks:
// handshake bytes come out through add_handshake_data, go back in through
// SSL_provide_quic_data, and traffic secrets arrive through set_read_secret and
// set_write_secret as each encryption level opens. This class is the buffer and
// bookkeeping around those callbacks, and nothing else -- it never touches a
// socket, and it hands out secrets rather than keys so that protection.h stays
// the only place that runs the key schedule.
//
// Two contracts the caller owns:
//
// CRYPTO frames arrive with offsets and can be reordered and duplicated, but
// TLS needs one ordered byte stream per level. Reassembly is the connection
// layer's job; provide_handshake_data expects bytes already in order and will
// happily corrupt a handshake if given them out of order.
//
// A flight can span levels, so a caller drains pending_handshake_data at every
// level after every advance, not just the current one.
//
// 0-RTT is cut here. The level exists because the callbacks name it, and the
// bridge refuses it explicitly rather than silently: early data keys are never
// installed, so a session that somehow negotiated early data fails closed
// instead of sending packets it cannot protect.

#include "vio/error.h"
#include "vio/quic/packet.h"
#include "vio/quic/protection.h"
#include "vio/vio_export.h"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace vio::quic
{
// RFC 9001 section 4.1. The values match LibreSSL's ssl_encryption_level_t, but
// the mapping is written out where it is used rather than relied on here.
enum class encryption_level_t : std::uint8_t
{
  initial,
  early_data,
  handshake,
  application,
};

inline constexpr std::size_t encryption_level_count = 4;

[[nodiscard]] constexpr std::string_view encryption_level_name(encryption_level_t level)
{
  switch (level)
  {
  case encryption_level_t::initial:
    return "initial";
  case encryption_level_t::early_data:
    return "early_data";
  case encryption_level_t::handshake:
    return "handshake";
  case encryption_level_t::application:
    return "application";
  }
  return "unknown";
}

// Which packet type carries CRYPTO frames for a level. RFC 9001 section 4.1.
[[nodiscard]] constexpr std::optional<packet_kind_t> packet_kind_for(encryption_level_t level)
{
  switch (level)
  {
  case encryption_level_t::initial:
    return packet_kind_t::initial;
  case encryption_level_t::handshake:
    return packet_kind_t::handshake;
  case encryption_level_t::application:
    return packet_kind_t::one_rtt;
  case encryption_level_t::early_data:
    // 0-RTT packets carry no CRYPTO frames even where early data is enabled.
    break;
  }
  return std::nullopt;
}

enum class tls_role_t : std::uint8_t
{
  client,
  server,
};

// A traffic secret as TLS produced it, for one level and one direction. The
// key schedule that turns it into keys lives in protection.h.
struct tls_secret_t
{
  encryption_level_t level = encryption_level_t::initial;
  cipher_suite_t suite;
  std::vector<std::uint8_t> secret;
};

struct tls_config_t
{
  tls_role_t role = tls_role_t::server;

  // PEM, for a server. The chain may hold intermediates after the leaf.
  std::vector<std::uint8_t> certificate_chain_pem;
  std::vector<std::uint8_t> private_key_pem;

  // PEM trust anchors for a client. Empty means the platform default.
  std::vector<std::uint8_t> ca_certificates_pem;
  bool verify_peer = true;

  // Offered by a client, chosen by a server. HTTP/3 is "h3".
  std::vector<std::string> alpn;

  // The encoded quic_transport_parameters extension. Its contents are the
  // transport's business, not this layer's.
  std::vector<std::uint8_t> transport_parameters;
};

namespace detail
{
struct tls_context_impl_t;
struct tls_session_impl_t;
} // namespace detail

// Shared across connections: one per listener, or one per client.
class VIO_EXPORT tls_context_t
{
public:
  ~tls_context_t();
  tls_context_t(tls_context_t &&) noexcept;
  tls_context_t &operator=(tls_context_t &&) noexcept;
  tls_context_t(const tls_context_t &) = delete;
  tls_context_t &operator=(const tls_context_t &) = delete;

  [[nodiscard]] static std::expected<tls_context_t, error_t> create(const tls_config_t &config);

  [[nodiscard]] void *native_handle() const;
  [[nodiscard]] tls_role_t role() const;

private:
  tls_context_t() = default;
  friend class tls_session_t;
  std::unique_ptr<detail::tls_context_impl_t> _impl;
};

// One connection's handshake.
class VIO_EXPORT tls_session_t
{
public:
  ~tls_session_t();
  tls_session_t(tls_session_t &&) noexcept;
  tls_session_t &operator=(tls_session_t &&) noexcept;
  tls_session_t(const tls_session_t &) = delete;
  tls_session_t &operator=(const tls_session_t &) = delete;

  // server_name is the SNI a client sends, and is ignored for a server.
  [[nodiscard]] static std::expected<tls_session_t, error_t> create(const tls_context_t &context, std::string_view server_name = {});

  // Sets the quic_transport_parameters extension. Must be called before the
  // handshake produces its first flight. A server needs this separately from
  // the context because one of its parameters --
  // original_destination_connection_id -- is not known until the client's
  // first Initial has arrived.
  [[nodiscard]] std::expected<void, error_t> set_transport_parameters(std::span<const std::uint8_t> parameters);

  // Ordered CRYPTO stream bytes for one level. Reassembly happens above.
  [[nodiscard]] std::expected<void, error_t> provide_handshake_data(encryption_level_t level, std::span<const std::uint8_t> data);

  // Runs the handshake as far as the data provided allows. True once it has
  // completed. Needing more data is not an error and comes back as false.
  [[nodiscard]] std::expected<bool, error_t> advance();

  // Handshake bytes waiting to go into CRYPTO frames at this level. The span
  // is invalidated by consume_handshake_data and by advance.
  [[nodiscard]] std::span<const std::uint8_t> pending_handshake_data(encryption_level_t level) const;
  void consume_handshake_data(encryption_level_t level, std::size_t bytes);
  [[nodiscard]] bool has_pending_handshake_data() const;

  // Secrets that have become available since the last call, in the order TLS
  // produced them.
  [[nodiscard]] std::vector<tls_secret_t> take_read_secrets();
  [[nodiscard]] std::vector<tls_secret_t> take_write_secrets();

  [[nodiscard]] bool handshake_complete() const;

  // A fatal TLS alert, if one was raised. RFC 9000 section 20.1 maps this onto
  // a CONNECTION_CLOSE with error code 0x0100 + the alert.
  [[nodiscard]] std::optional<std::uint8_t> alert() const;

  [[nodiscard]] std::string_view selected_alpn() const;
  [[nodiscard]] std::span<const std::uint8_t> peer_transport_parameters() const;

  [[nodiscard]] void *native_handle() const;

private:
  tls_session_t() = default;
  std::unique_ptr<detail::tls_session_impl_t> _impl;
};

// RFC 9000 section 20.1: a TLS alert becomes CRYPTO_ERROR with the alert in
// the low byte.
[[nodiscard]] constexpr std::uint64_t crypto_error_code(std::uint8_t alert)
{
  return 0x0100 | static_cast<std::uint64_t>(alert);
}
} // namespace vio::quic
