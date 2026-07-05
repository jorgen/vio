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

// ---------------------------------------------------------------------------
// vio SSL backend seam.
//
// vio speaks the OpenSSL SSL_*/BIO_* API and does its own socket I/O over
// libuv, so the SSL library only performs crypto through memory BIOs. That
// makes the library pluggable at COMPILE TIME: the same source builds against
// the bundled LibreSSL (its OpenSSL-compat layer), system OpenSSL 3.x, or
// BoringSSL/AWS-LC, which all expose the same symbol names. This header is the
// single seam that (a) includes the OpenSSL headers, (b) selects the backend,
// (c) exposes constexpr feature flags, and (d) provides inline shims for the
// handful of genuinely divergent operations plus the portable in-memory
// cert/key/CA loading helpers the rest of the TLS code uses.
//
// Only the bundled LibreSSL backend is wired & tested today; OpenSSL/BoringSSL
// are drop-in behind this seam.
// ---------------------------------------------------------------------------

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
// NB: intentionally NOT including <openssl/x509v3.h> -- on Windows it collides
// with <wincrypt.h> macros that ssl.h/x509.h undef but x509v3.h does not, and we
// need no symbols from it (X509_VERIFY_PARAM_* / X509_verify_cert_error_string
// come from x509_vfy.h via ssl.h).

#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include <vio/error.h>

// The build system defines exactly one VIO_SSL_BACKEND_* macro (PUBLIC, so it
// propagates to header-only consumers and a mismatch fails at compile/link).
// If none is set (e.g. a consumer forgot the define) auto-detect from the
// library's own macros so the header still works, then verify exactly one.
#if !defined(VIO_SSL_BACKEND_LIBRESSL) && !defined(VIO_SSL_BACKEND_OPENSSL) && !defined(VIO_SSL_BACKEND_BORINGSSL)
#if defined(LIBRESSL_VERSION_NUMBER)
#define VIO_SSL_BACKEND_LIBRESSL 1
#elif defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)
#define VIO_SSL_BACKEND_BORINGSSL 1
#else
#define VIO_SSL_BACKEND_OPENSSL 1
#endif
#endif

#if (defined(VIO_SSL_BACKEND_LIBRESSL) + defined(VIO_SSL_BACKEND_OPENSSL) + defined(VIO_SSL_BACKEND_BORINGSSL)) != 1
#error "Exactly one of VIO_SSL_BACKEND_{LIBRESSL,OPENSSL,BORINGSSL} must be defined"
#endif

namespace vio::ssl
{

// Feature flags. The single rule: gate on the VIO_SSL_BACKEND_* macro plus the
// library's own identity macros, NEVER on the raw OPENSSL_VERSION_NUMBER --
// LibreSSL reports a fake 0x20000000L sentinel there, so a `>= 0x30000000L`
// guard would silently disable code on the baseline backend.
#if defined(VIO_SSL_BACKEND_LIBRESSL)
inline constexpr bool is_libressl = true;
inline constexpr bool is_boringssl = false;
// LibreSSL: TLS 1.0/1.1 are compiled out, so TLS 1.2 is the floor; TLS 1.3 and
// SSL_CTX_set_ciphersuites are available.
inline constexpr bool has_tls13_ciphersuites = true;
#elif defined(VIO_SSL_BACKEND_BORINGSSL)
inline constexpr bool is_libressl = false;
inline constexpr bool is_boringssl = true;
// BoringSSL hardcodes its TLS 1.3 cipher suites and has no SSL_CTX_set_ciphersuites.
inline constexpr bool has_tls13_ciphersuites = false;
#else
inline constexpr bool is_libressl = false;
inline constexpr bool is_boringssl = false;
inline constexpr bool has_tls13_ciphersuites = true;
#endif

// ---- divergent-operation shims -------------------------------------------

// Peer certificate accessor: OpenSSL 3.x renamed SSL_get_peer_certificate to
// SSL_get1_peer_certificate (both return a +1 ref the caller frees).
inline X509 *get1_peer_cert(SSL *ssl)
{
#if defined(VIO_SSL_BACKEND_OPENSSL)
  return SSL_get1_peer_certificate(ssl);
#else
  return SSL_get_peer_certificate(ssl);
#endif
}

// Named-group / curve list configuration.
inline int set_groups_list(SSL_CTX *ctx, const char *groups)
{
#if defined(VIO_SSL_BACKEND_BORINGSSL)
  return SSL_CTX_set1_curves_list(ctx, groups);
#else
  return SSL_CTX_set1_groups_list(ctx, groups);
#endif
}

// TLS 1.3 cipher suite configuration (no-op where unsupported).
inline int set_ciphersuites(SSL_CTX *ctx, const char *suites)
{
  if constexpr (has_tls13_ciphersuites)
  {
    return SSL_CTX_set_ciphersuites(ctx, suites);
  }
  else
  {
    (void)ctx;
    (void)suites;
    return 1;
  }
}

// ---- error extraction -----------------------------------------------------

// Pop and format the top of the thread-local OpenSSL error queue. Returns an
// empty string if the queue is empty.
inline std::string last_error_string()
{
  unsigned long e = ERR_get_error();
  if (e == 0)
  {
    return {};
  }
  char buf[256];
  ERR_error_string_n(e, buf, sizeof(buf));
  return std::string(buf);
}

// ---- portable in-memory material loading ---------------------------------
// These use only BIO_new_mem_buf + PEM_read_bio_* + X509_STORE_add_cert, which
// exist identically on LibreSSL, OpenSSL 3.x and BoringSSL. The LibreSSL-only
// convenience helpers (SSL_CTX_use_certificate_chain_mem, SSL_CTX_load_verify_mem)
// are deliberately avoided so the code is backend-portable.

// Add every PEM certificate in `pem` to the context's trust store.
inline error_t add_ca_pem(SSL_CTX *ctx, std::span<const uint8_t> pem)
{
  BIO *bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
  if (bio == nullptr)
  {
    return error_t{.code = -1, .msg = "BIO_new_mem_buf failed for CA bundle"};
  }
  X509_STORE *store = SSL_CTX_get_cert_store(ctx);
  int added = 0;
  while (X509 *x = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr))
  {
    if (X509_STORE_add_cert(store, x) == 1)
    {
      ++added;
    }
    X509_free(x);
  }
  // PEM_read_bio_X509 leaves a benign "no start line" error on the queue at EOF.
  ERR_clear_error();
  BIO_free(bio);
  if (added == 0)
  {
    return error_t{.code = -1, .msg = "No certificates found in CA bundle"};
  }
  return {};
}

// Load a leaf certificate (and any following chain certs) from PEM into ctx.
inline error_t use_certificate_chain_pem(SSL_CTX *ctx, std::span<const uint8_t> pem)
{
  BIO *bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
  if (bio == nullptr)
  {
    return error_t{.code = -1, .msg = "BIO_new_mem_buf failed for certificate"};
  }
  X509 *leaf = PEM_read_bio_X509_AUX(bio, nullptr, nullptr, nullptr);
  if (leaf == nullptr)
  {
    BIO_free(bio);
    return error_t{.code = -1, .msg = "Failed to parse certificate PEM"};
  }
  if (SSL_CTX_use_certificate(ctx, leaf) != 1)
  {
    X509_free(leaf);
    BIO_free(bio);
    return error_t{.code = -1, .msg = "SSL_CTX_use_certificate failed: " + last_error_string()};
  }
  X509_free(leaf); // use_certificate takes its own reference

  // Remaining PEM blocks are chain certificates. add0 takes ownership.
  error_t err{};
  while (X509 *ca = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr))
  {
    if (SSL_CTX_add0_chain_cert(ctx, ca) != 1)
    {
      X509_free(ca);
      err = error_t{.code = -1, .msg = "SSL_CTX_add0_chain_cert failed: " + last_error_string()};
      break;
    }
  }
  ERR_clear_error();
  BIO_free(bio);
  return err;
}

// Load a private key from PEM into ctx.
inline error_t use_private_key_pem(SSL_CTX *ctx, std::span<const uint8_t> pem)
{
  BIO *bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
  if (bio == nullptr)
  {
    return error_t{.code = -1, .msg = "BIO_new_mem_buf failed for private key"};
  }
  EVP_PKEY *key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
  BIO_free(bio);
  if (key == nullptr)
  {
    return error_t{.code = -1, .msg = "Failed to parse private key PEM"};
  }
  const int rc = SSL_CTX_use_PrivateKey(ctx, key);
  EVP_PKEY_free(key); // use_PrivateKey takes its own reference
  if (rc != 1)
  {
    return error_t{.code = -1, .msg = "SSL_CTX_use_PrivateKey failed: " + last_error_string()};
  }
  return {};
}

// Encode a list of ALPN protocol names into the length-prefixed wire format
// that SSL_CTX_set_alpn_protos and the ALPN select callback consume
// (each entry: one length byte followed by that many name bytes).
inline std::vector<uint8_t> alpn_wire_from_list(const std::vector<std::string> &protocols)
{
  std::vector<uint8_t> wire;
  for (const auto &p : protocols)
  {
    if (p.empty() || p.size() > 255)
    {
      continue;
    }
    wire.push_back(static_cast<uint8_t>(p.size()));
    wire.insert(wire.end(), p.begin(), p.end());
  }
  return wire;
}

} // namespace vio::ssl
