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

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace vio
{
// Forward-declared so this header stays free of OpenSSL includes. Defined in
// ssl_context.h. An app-owned, shared client session cache for TLS resumption.
struct ssl_session_cache_t;

// TLS protocol version bounds. TLS 1.0/1.1 are intentionally unrepresentable:
// they are compiled out of LibreSSL, so TLS 1.2 is the floor for every backend.
enum class tls_protocol_version
{
  tls1_2,
  tls1_3,
};

// Peer certificate verification policy. Replaces the libtls-shaped
// verify_client/verify_optional bool pair with a single explicit choice.
enum class peer_verify_t
{
  disabled, // SSL_VERIFY_NONE
  optional, // SSL_VERIFY_PEER (verify if presented, don't require)
  required, // SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT
};

struct ssl_config_t
{
  std::optional<std::string> ca_file;
  std::optional<std::string> ca_path;
  std::optional<std::string> cert_file;
  std::optional<std::string> key_file;
  std::optional<std::string> ocsp_staple_file;
  std::optional<std::vector<uint8_t>> ca_mem;
  std::optional<std::vector<uint8_t>> cert_mem;
  std::optional<std::vector<uint8_t>> key_mem;
  std::optional<std::vector<uint8_t>> ocsp_staple_mem;

  // TLS 1.2 cipher list (SSL_CTX_set_cipher_list). The libtls alias words
  // ("secure"/"legacy"/...) are no longer accepted; pass an OpenSSL cipher string.
  std::optional<std::string> ciphers;
  // TLS 1.3 cipher suites (SSL_CTX_set_ciphersuites; no-op on BoringSSL).
  std::optional<std::string> ciphersuites;
  // Named groups / curves list, e.g. "X25519:P-256" (replaces the old ecdhecurve).
  std::optional<std::string> groups;

  // ALPN. `alpn_protocols` is the canonical list ({"h2","http/1.1"}); the
  // legacy comma-separated `alpn` string is a deprecated alias used only when
  // `alpn_protocols` is empty. Internally both become the length-prefixed wire
  // vector for SSL_CTX_set_alpn_protos / the server select callback.
  std::vector<std::string> alpn_protocols;
  std::optional<std::string> alpn; // deprecated: comma-separated alias

  // Protocol version bounds (default: min TLS 1.2, max TLS 1.3).
  std::optional<tls_protocol_version> min_protocol;
  std::optional<tls_protocol_version> max_protocol;

  // Peer verification. `peer_verify` takes precedence; if unset the legacy
  // verify_client/verify_optional bools are used as a fallback.
  std::optional<peer_verify_t> peer_verify;
  std::optional<int> verify_depth;

  // TLS key-log hook (wired to SSL_CTX_set_keylog_callback) for Wireshark-style
  // decryption. Receives each SSLKEYLOGFILE line.
  std::function<void(std::string_view)> keylog_callback;

  // Enable cross-connection session resumption caching (SSL_CTX_set_session_cache_mode).
  bool enable_session_cache = false;

  // Client-only: an app-owned shared cache for TLS session resumption. When set,
  // a successful handshake's session is stored keyed by host, and a later
  // connection to the same host resumes it. Must outlive every client using it.
  ssl_session_cache_t *session_cache = nullptr;

  // Client-only: request an OCSP staple (status_request extension). The server's
  // stapled response is then readable via ssl_client_ocsp_response().
  bool request_ocsp_staple = false;

  // --- deprecated libtls-shaped fields (kept for aggregate compatibility) ---
  std::optional<bool> verify_client;   // deprecated: use peer_verify
  std::optional<bool> verify_optional; // deprecated: use peer_verify
  std::optional<uint32_t> protocols;   // deprecated: use min_protocol/max_protocol
  std::optional<uint32_t> dheparams;   // deprecated: TLS 1.3 is ECDHE-only, ignored
  std::optional<uint32_t> ecdhecurve;  // deprecated: use groups
};
} // namespace vio
