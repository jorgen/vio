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

#include "vio/quic/tls.h"

#include <array>
#include <cstring>
#include <string>
#include <utility>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

namespace vio::quic
{
namespace
{
error_t tls_error(const char *what)
{
  std::string message = what;
  if (const unsigned long code = ERR_get_error(); code != 0)
  {
    char buffer[256] = {};
    ERR_error_string_n(code, buffer, sizeof(buffer));
    message += ": ";
    message += buffer;
  }
  ERR_clear_error();
  return error_t{.code = 1, .msg = std::move(message)};
}

[[nodiscard]] std::optional<encryption_level_t> from_ssl_level(enum ssl_encryption_level_t level)
{
  switch (level)
  {
  case ssl_encryption_initial:
    return encryption_level_t::initial;
  case ssl_encryption_early_data:
    return encryption_level_t::early_data;
  case ssl_encryption_handshake:
    return encryption_level_t::handshake;
  case ssl_encryption_application:
    return encryption_level_t::application;
  }
  return std::nullopt;
}

[[nodiscard]] enum ssl_encryption_level_t to_ssl_level(encryption_level_t level)
{
  switch (level)
  {
  case encryption_level_t::initial:
    return ssl_encryption_initial;
  case encryption_level_t::early_data:
    return ssl_encryption_early_data;
  case encryption_level_t::handshake:
    return ssl_encryption_handshake;
  case encryption_level_t::application:
    return ssl_encryption_application;
  }
  return ssl_encryption_initial;
}

// The three suites RFC 9001 allows. TLS_AES_128_CCM_8_SHA256 is excluded by
// section 5.3 because no header protection is defined for it, and anything
// else means TLS negotiated something this transport cannot protect.
[[nodiscard]] std::optional<cipher_suite_t> suite_from_cipher(const SSL_CIPHER *cipher)
{
  if (cipher == nullptr)
  {
    return std::nullopt;
  }
  switch (SSL_CIPHER_get_value(cipher))
  {
  case 0x1301:
    return tls_aes_128_gcm_sha256;
  case 0x1302:
    return tls_aes_256_gcm_sha384;
  case 0x1303:
    return tls_chacha20_poly1305_sha256;
  default:
    break;
  }
  return std::nullopt;
}

int session_index()
{
  static const int index = SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
  return index;
}
} // namespace

namespace detail
{
struct tls_session_impl_t
{
  SSL *ssl = nullptr;
  std::array<std::vector<std::uint8_t>, encryption_level_count> outgoing;
  // LibreSSL accepts CRYPTO data only at the level it is currently reading,
  // but a peer may legitimately have a Handshake packet in flight before this
  // side has finished with Initial. Holding the bytes here rather than
  // refusing them keeps that ordering problem out of the connection layer.
  std::array<std::vector<std::uint8_t>, encryption_level_count> incoming;
  std::vector<tls_secret_t> read_secrets;
  std::vector<tls_secret_t> write_secrets;
  std::optional<std::uint8_t> alert;
  std::string alpn;
  std::vector<std::uint8_t> peer_transport_parameters;
  bool complete = false;
  // Set when TLS tried to open the early data level. Nothing installs those
  // keys, so the session is finished either way; this only says why.
  bool early_data_refused = false;

  ~tls_session_impl_t()
  {
    if (ssl != nullptr)
    {
      SSL_free(ssl);
    }
  }
};

struct tls_context_impl_t
{
  SSL_CTX *ctx = nullptr;
  tls_role_t role = tls_role_t::server;
  std::vector<std::uint8_t> transport_parameters;
  // Held for the lifetime of the context: the ALPN callback is handed a
  // pointer to this, and SSL_CTX_set_alpn_protos wants the wire encoding.
  std::vector<std::uint8_t> alpn_wire;

  ~tls_context_impl_t()
  {
    if (ctx != nullptr)
    {
      SSL_CTX_free(ctx);
    }
  }
};
} // namespace detail

namespace
{
detail::tls_session_impl_t *session_of(SSL *ssl)
{
  return static_cast<detail::tls_session_impl_t *>(SSL_get_ex_data(ssl, session_index()));
}

int on_set_read_secret(SSL *ssl, enum ssl_encryption_level_t level, const SSL_CIPHER *cipher, const uint8_t *secret, size_t secret_len)
{
  auto *session = session_of(ssl);
  if (session == nullptr)
  {
    return 0;
  }
  auto mapped = from_ssl_level(level);
  auto suite = suite_from_cipher(cipher);
  if (!mapped.has_value() || !suite.has_value())
  {
    return 0;
  }
  if (*mapped == encryption_level_t::early_data)
  {
    // The 0-RTT seam, cut. Failing here is deliberate: accepting the secret
    // and dropping it would leave TLS believing a level is usable that this
    // transport will never protect a packet at.
    session->early_data_refused = true;
    return 0;
  }
  session->read_secrets.push_back(tls_secret_t{.level = *mapped, .suite = *suite, .secret = std::vector<std::uint8_t>(secret, secret + secret_len)});
  return 1;
}

int on_set_write_secret(SSL *ssl, enum ssl_encryption_level_t level, const SSL_CIPHER *cipher, const uint8_t *secret, size_t secret_len)
{
  auto *session = session_of(ssl);
  if (session == nullptr)
  {
    return 0;
  }
  auto mapped = from_ssl_level(level);
  auto suite = suite_from_cipher(cipher);
  if (!mapped.has_value() || !suite.has_value())
  {
    return 0;
  }
  if (*mapped == encryption_level_t::early_data)
  {
    session->early_data_refused = true;
    return 0;
  }
  session->write_secrets.push_back(tls_secret_t{.level = *mapped, .suite = *suite, .secret = std::vector<std::uint8_t>(secret, secret + secret_len)});
  return 1;
}

int on_add_handshake_data(SSL *ssl, enum ssl_encryption_level_t level, const uint8_t *data, size_t len)
{
  auto *session = session_of(ssl);
  auto mapped = from_ssl_level(level);
  if (session == nullptr || !mapped.has_value())
  {
    return 0;
  }
  auto &buffer = session->outgoing[static_cast<std::size_t>(*mapped)];
  buffer.insert(buffer.end(), data, data + len);
  return 1;
}

int on_flush_flight(SSL *ssl)
{
  // Coalescing a flight into as few datagrams as possible is the packetizer's
  // decision, and it can see everything pending at every level, so there is
  // nothing useful to do at this boundary.
  (void)ssl;
  return 1;
}

int on_send_alert(SSL *ssl, enum ssl_encryption_level_t level, uint8_t alert)
{
  (void)level;
  auto *session = session_of(ssl);
  if (session == nullptr)
  {
    return 0;
  }
  // First alert wins: it is the one that describes what actually went wrong.
  if (!session->alert.has_value())
  {
    session->alert = alert;
  }
  return 1;
}

const SSL_QUIC_METHOD *quic_method()
{
  // Designated initialisers on purpose. LibreSSL carries both the old
  // (set_encryption_secrets) and new (set_read_secret/set_write_secret) hooks
  // in one struct and warns that positional initialisation depends on their
  // order; it prefers the new pair when they are set, which is what this uses.
  static const SSL_QUIC_METHOD method = {
    .set_encryption_secrets = nullptr,
    .add_handshake_data = on_add_handshake_data,
    .flush_flight = on_flush_flight,
    .send_alert = on_send_alert,
    .set_read_secret = on_set_read_secret,
    .set_write_secret = on_set_write_secret,
  };
  return &method;
}

// The wire format ALPN wants: each protocol prefixed by its one byte length.
std::vector<std::uint8_t> encode_alpn(const std::vector<std::string> &protocols)
{
  std::vector<std::uint8_t> wire;
  for (const auto &protocol : protocols)
  {
    if (protocol.empty() || protocol.size() > 255)
    {
      return {};
    }
    wire.push_back(static_cast<std::uint8_t>(protocol.size()));
    wire.insert(wire.end(), protocol.begin(), protocol.end());
  }
  return wire;
}

int on_alpn_select(SSL *ssl, const unsigned char **out, unsigned char *out_len, const unsigned char *in, unsigned int in_len, void *arg)
{
  (void)ssl;
  const auto *offered = static_cast<const std::vector<std::uint8_t> *>(arg);
  if (offered == nullptr || offered->empty())
  {
    return SSL_TLSEXT_ERR_NOACK;
  }
  // Server preference: walk our list and take the first the client offered.
  for (std::size_t i = 0; i + 1 <= offered->size();)
  {
    const std::size_t length = (*offered)[i];
    if (length == 0 || i + 1 + length > offered->size())
    {
      break;
    }
    const auto *candidate = offered->data() + i + 1;
    for (unsigned int j = 0; j + 1 <= in_len;)
    {
      const unsigned int client_length = in[j];
      if (client_length == 0 || j + 1 + client_length > in_len)
      {
        break;
      }
      if (client_length == length && std::memcmp(candidate, in + j + 1, length) == 0)
      {
        *out = in + j + 1;
        *out_len = static_cast<unsigned char>(client_length);
        return SSL_TLSEXT_ERR_OK;
      }
      j += 1 + client_length;
    }
    i += 1 + length;
  }
  // RFC 9114 section 3.1: no shared protocol is a fatal alert, not a fallback.
  return SSL_TLSEXT_ERR_ALERT_FATAL;
}

std::expected<void, error_t> load_certificate_chain(SSL_CTX *ctx, std::span<const std::uint8_t> pem)
{
  BIO *bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
  if (bio == nullptr)
  {
    return std::unexpected(tls_error("BIO_new_mem_buf failed"));
  }
  X509 *leaf = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
  if (leaf == nullptr)
  {
    BIO_free(bio);
    return std::unexpected(tls_error("no certificate in the supplied PEM"));
  }
  const int used = SSL_CTX_use_certificate(ctx, leaf);
  X509_free(leaf);
  if (used != 1)
  {
    BIO_free(bio);
    return std::unexpected(tls_error("SSL_CTX_use_certificate failed"));
  }

  // Anything after the leaf is an intermediate.
  while (X509 *chain = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr))
  {
    if (SSL_CTX_add_extra_chain_cert(ctx, chain) != 1)
    {
      X509_free(chain);
      BIO_free(bio);
      return std::unexpected(tls_error("SSL_CTX_add_extra_chain_cert failed"));
    }
  }
  ERR_clear_error();
  BIO_free(bio);
  return {};
}

std::expected<void, error_t> load_private_key(SSL_CTX *ctx, std::span<const std::uint8_t> pem)
{
  BIO *bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
  if (bio == nullptr)
  {
    return std::unexpected(tls_error("BIO_new_mem_buf failed"));
  }
  EVP_PKEY *key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
  BIO_free(bio);
  if (key == nullptr)
  {
    return std::unexpected(tls_error("no private key in the supplied PEM"));
  }
  const int used = SSL_CTX_use_PrivateKey(ctx, key);
  EVP_PKEY_free(key);
  if (used != 1)
  {
    return std::unexpected(tls_error("SSL_CTX_use_PrivateKey failed"));
  }
  if (SSL_CTX_check_private_key(ctx) != 1)
  {
    return std::unexpected(tls_error("private key does not match the certificate"));
  }
  return {};
}

std::expected<void, error_t> load_trust_anchors(SSL_CTX *ctx, std::span<const std::uint8_t> pem)
{
  X509_STORE *store = SSL_CTX_get_cert_store(ctx);
  if (store == nullptr)
  {
    return std::unexpected(tls_error("SSL_CTX_get_cert_store failed"));
  }
  BIO *bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
  if (bio == nullptr)
  {
    return std::unexpected(tls_error("BIO_new_mem_buf failed"));
  }
  std::size_t added = 0;
  while (X509 *certificate = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr))
  {
    const int ok = X509_STORE_add_cert(store, certificate);
    X509_free(certificate);
    if (ok != 1)
    {
      BIO_free(bio);
      return std::unexpected(tls_error("X509_STORE_add_cert failed"));
    }
    ++added;
  }
  ERR_clear_error();
  BIO_free(bio);
  if (added == 0)
  {
    return std::unexpected(error_t{.code = 1, .msg = "no trust anchors in the supplied PEM"});
  }
  return {};
}
} // namespace

tls_context_t::~tls_context_t() = default;
tls_context_t::tls_context_t(tls_context_t &&) noexcept = default;
tls_context_t &tls_context_t::operator=(tls_context_t &&) noexcept = default;

std::expected<tls_context_t, error_t> tls_context_t::create(const tls_config_t &config)
{
  auto impl = std::make_unique<detail::tls_context_impl_t>();
  impl->role = config.role;
  impl->transport_parameters = config.transport_parameters;
  impl->ctx = SSL_CTX_new(config.role == tls_role_t::server ? TLS_server_method() : TLS_client_method());
  if (impl->ctx == nullptr)
  {
    return std::unexpected(tls_error("SSL_CTX_new failed"));
  }

  // QUIC is TLS 1.3 only (RFC 9001 section 4.2), and LibreSSL requires the
  // minimum to be set before the QUIC method is attached.
  if (SSL_CTX_set_min_proto_version(impl->ctx, TLS1_3_VERSION) != 1 || SSL_CTX_set_max_proto_version(impl->ctx, TLS1_3_VERSION) != 1)
  {
    return std::unexpected(tls_error("could not pin TLS 1.3"));
  }
  if (SSL_CTX_set_quic_method(impl->ctx, quic_method()) != 1)
  {
    return std::unexpected(tls_error("SSL_CTX_set_quic_method failed"));
  }

  // Nothing here resumes, and 0-RTT rides on resumption. Turning tickets off
  // is the outermost of the cuts that keep early data unreachable.
  SSL_CTX_set_options(impl->ctx, SSL_OP_NO_TICKET);
  SSL_CTX_set_session_cache_mode(impl->ctx, SSL_SESS_CACHE_OFF);

  if (config.role == tls_role_t::server)
  {
    if (config.certificate_chain_pem.empty() || config.private_key_pem.empty())
    {
      return std::unexpected(error_t{.code = 1, .msg = "a server needs a certificate chain and a private key"});
    }
    if (auto r = load_certificate_chain(impl->ctx, config.certificate_chain_pem); !r.has_value())
    {
      return std::unexpected(r.error());
    }
    if (auto r = load_private_key(impl->ctx, config.private_key_pem); !r.has_value())
    {
      return std::unexpected(r.error());
    }
    impl->alpn_wire = encode_alpn(config.alpn);
    if (!config.alpn.empty() && impl->alpn_wire.empty())
    {
      return std::unexpected(error_t{.code = 1, .msg = "an ALPN protocol is empty or longer than 255 bytes"});
    }
    if (!impl->alpn_wire.empty())
    {
      SSL_CTX_set_alpn_select_cb(impl->ctx, on_alpn_select, &impl->alpn_wire);
    }
  }
  else
  {
    if (config.verify_peer)
    {
      SSL_CTX_set_verify(impl->ctx, SSL_VERIFY_PEER, nullptr);
      if (!config.ca_certificates_pem.empty())
      {
        if (auto r = load_trust_anchors(impl->ctx, config.ca_certificates_pem); !r.has_value())
        {
          return std::unexpected(r.error());
        }
      }
      else if (SSL_CTX_set_default_verify_paths(impl->ctx) != 1)
      {
        return std::unexpected(tls_error("SSL_CTX_set_default_verify_paths failed"));
      }
    }
    else
    {
      SSL_CTX_set_verify(impl->ctx, SSL_VERIFY_NONE, nullptr);
    }

    impl->alpn_wire = encode_alpn(config.alpn);
    if (!config.alpn.empty() && impl->alpn_wire.empty())
    {
      return std::unexpected(error_t{.code = 1, .msg = "an ALPN protocol is empty or longer than 255 bytes"});
    }
  }

  tls_context_t context;
  context._impl = std::move(impl);
  return context;
}

void *tls_context_t::native_handle() const
{
  return _impl == nullptr ? nullptr : _impl->ctx;
}

tls_role_t tls_context_t::role() const
{
  return _impl == nullptr ? tls_role_t::server : _impl->role;
}

tls_session_t::~tls_session_t() = default;
tls_session_t::tls_session_t(tls_session_t &&) noexcept = default;
tls_session_t &tls_session_t::operator=(tls_session_t &&) noexcept = default;

std::expected<tls_session_t, error_t> tls_session_t::create(const tls_context_t &context, std::string_view server_name)
{
  if (context._impl == nullptr || context._impl->ctx == nullptr)
  {
    return std::unexpected(error_t{.code = 1, .msg = "tls context is not initialized"});
  }

  auto impl = std::make_unique<detail::tls_session_impl_t>();
  impl->ssl = SSL_new(context._impl->ctx);
  if (impl->ssl == nullptr)
  {
    return std::unexpected(tls_error("SSL_new failed"));
  }
  if (SSL_set_ex_data(impl->ssl, session_index(), impl.get()) != 1)
  {
    return std::unexpected(tls_error("SSL_set_ex_data failed"));
  }

  // The transport parameters ride in a TLS extension, so they have to be set
  // before the first flight is produced.
  if (!context._impl->transport_parameters.empty() && SSL_set_quic_transport_params(impl->ssl, context._impl->transport_parameters.data(), context._impl->transport_parameters.size()) != 1)
  {
    return std::unexpected(tls_error("SSL_set_quic_transport_params failed"));
  }

  if (context._impl->role == tls_role_t::server)
  {
    SSL_set_accept_state(impl->ssl);
  }
  else
  {
    SSL_set_connect_state(impl->ssl);
    if (!server_name.empty())
    {
      const std::string name(server_name);
      if (SSL_set_tlsext_host_name(impl->ssl, name.c_str()) != 1)
      {
        return std::unexpected(tls_error("SSL_set_tlsext_host_name failed"));
      }
      if (SSL_set1_host(impl->ssl, name.c_str()) != 1)
      {
        return std::unexpected(tls_error("SSL_set1_host failed"));
      }
    }
    if (!context._impl->alpn_wire.empty() && SSL_set_alpn_protos(impl->ssl, context._impl->alpn_wire.data(), static_cast<unsigned int>(context._impl->alpn_wire.size())) != 0)
    {
      return std::unexpected(tls_error("SSL_set_alpn_protos failed"));
    }
  }

  tls_session_t session;
  session._impl = std::move(impl);
  return session;
}

std::expected<void, error_t> tls_session_t::provide_handshake_data(encryption_level_t level, std::span<const std::uint8_t> data)
{
  if (_impl == nullptr || _impl->ssl == nullptr)
  {
    return std::unexpected(error_t{.code = 1, .msg = "tls session is not initialized"});
  }
  if (data.empty())
  {
    return {};
  }
  if (level == encryption_level_t::early_data)
  {
    return std::unexpected(error_t{.code = 1, .msg = "0-RTT is not supported: no CRYPTO data is accepted at the early data level"});
  }

  auto &buffer = _impl->incoming[static_cast<std::size_t>(level)];
  // A peer that never finishes a flight must not be able to make this grow
  // without bound; TLS itself will not read more than a flight at a level.
  const std::size_t limit = SSL_quic_max_handshake_flight_len(_impl->ssl, to_ssl_level(level));
  if (limit != 0 && buffer.size() + data.size() > limit)
  {
    return std::unexpected(error_t{.code = 1, .msg = "buffered CRYPTO data exceeds the maximum handshake flight for this level"});
  }
  buffer.insert(buffer.end(), data.begin(), data.end());
  return {};
}

namespace
{
// Hands over whatever is buffered for the level TLS is currently reading.
// Anything held for a later level waits until the handshake gets there.
std::expected<bool, error_t> feed_ready(detail::tls_session_impl_t &session)
{
  const auto current = from_ssl_level(SSL_quic_read_level(session.ssl));
  if (!current.has_value())
  {
    return false;
  }
  auto &buffer = session.incoming[static_cast<std::size_t>(*current)];
  if (buffer.empty())
  {
    return false;
  }
  if (SSL_provide_quic_data(session.ssl, to_ssl_level(*current), buffer.data(), buffer.size()) != 1)
  {
    return std::unexpected(tls_error("SSL_provide_quic_data failed"));
  }
  buffer.clear();
  return true;
}

bool has_feedable_data(const detail::tls_session_impl_t &session)
{
  const auto current = from_ssl_level(SSL_quic_read_level(session.ssl));
  return current.has_value() && !session.incoming[static_cast<std::size_t>(*current)].empty();
}
} // namespace

std::expected<bool, error_t> tls_session_t::advance()
{
  if (_impl == nullptr || _impl->ssl == nullptr)
  {
    return std::unexpected(error_t{.code = 1, .msg = "tls session is not initialized"});
  }

  while (!_impl->complete)
  {
    // Feed first: the handshake can only consume what it has been given, and
    // the level it will accept may have moved on since the last round.
    if (auto fed = feed_ready(*_impl); !fed.has_value())
    {
      return std::unexpected(fed.error());
    }

    const int rc = SSL_do_handshake(_impl->ssl);
    if (rc == 1)
    {
      _impl->complete = true;
      const unsigned char *alpn = nullptr;
      unsigned int alpn_len = 0;
      SSL_get0_alpn_selected(_impl->ssl, &alpn, &alpn_len);
      if (alpn != nullptr && alpn_len > 0)
      {
        _impl->alpn.assign(reinterpret_cast<const char *>(alpn), alpn_len);
      }
      const uint8_t *params = nullptr;
      size_t params_len = 0;
      SSL_get_peer_quic_transport_params(_impl->ssl, &params, &params_len);
      if (params != nullptr && params_len > 0)
      {
        _impl->peer_transport_parameters.assign(params, params + params_len);
      }
      break;
    }

    const int err = SSL_get_error(_impl->ssl, rc);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
    {
      ERR_clear_error();
      // Processing that flight may have opened the next level, in which case
      // data already held for it can go in now. Otherwise this is simply
      // waiting on the peer, which is not an error.
      if (has_feedable_data(*_impl))
      {
        continue;
      }
      return false;
    }
    if (_impl->early_data_refused)
    {
      ERR_clear_error();
      return std::unexpected(error_t{.code = 1, .msg = "TLS negotiated early data, which this build does not support"});
    }
    if (_impl->alert.has_value())
    {
      ERR_clear_error();
      return std::unexpected(error_t{.code = static_cast<int>(*_impl->alert), .msg = "TLS handshake failed with alert " + std::to_string(*_impl->alert)});
    }
    return std::unexpected(tls_error("SSL_do_handshake failed"));
  }

  if (auto fed = feed_ready(*_impl); !fed.has_value())
  {
    return std::unexpected(fed.error());
  }

  // Session tickets and other post-handshake messages. Nothing here resumes,
  // but the peer may still send them and they must be consumed.
  if (SSL_process_quic_post_handshake(_impl->ssl) != 1)
  {
    const int err = SSL_get_error(_impl->ssl, 0);
    if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
    {
      return std::unexpected(tls_error("SSL_process_quic_post_handshake failed"));
    }
    ERR_clear_error();
  }
  return true;
}

std::span<const std::uint8_t> tls_session_t::pending_handshake_data(encryption_level_t level) const
{
  if (_impl == nullptr)
  {
    return {};
  }
  return _impl->outgoing[static_cast<std::size_t>(level)];
}

void tls_session_t::consume_handshake_data(encryption_level_t level, std::size_t bytes)
{
  if (_impl == nullptr)
  {
    return;
  }
  auto &buffer = _impl->outgoing[static_cast<std::size_t>(level)];
  buffer.erase(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(bytes > buffer.size() ? buffer.size() : bytes));
}

bool tls_session_t::has_pending_handshake_data() const
{
  if (_impl == nullptr)
  {
    return false;
  }
  for (const auto &buffer : _impl->outgoing)
  {
    if (!buffer.empty())
    {
      return true;
    }
  }
  return false;
}

std::vector<tls_secret_t> tls_session_t::take_read_secrets()
{
  if (_impl == nullptr)
  {
    return {};
  }
  return std::exchange(_impl->read_secrets, {});
}

std::vector<tls_secret_t> tls_session_t::take_write_secrets()
{
  if (_impl == nullptr)
  {
    return {};
  }
  return std::exchange(_impl->write_secrets, {});
}

bool tls_session_t::handshake_complete() const
{
  return _impl != nullptr && _impl->complete;
}

std::optional<std::uint8_t> tls_session_t::alert() const
{
  return _impl == nullptr ? std::nullopt : _impl->alert;
}

std::string_view tls_session_t::selected_alpn() const
{
  return _impl == nullptr ? std::string_view{} : std::string_view(_impl->alpn);
}

std::span<const std::uint8_t> tls_session_t::peer_transport_parameters() const
{
  if (_impl == nullptr)
  {
    return {};
  }
  return _impl->peer_transport_parameters;
}

void *tls_session_t::native_handle() const
{
  return _impl == nullptr ? nullptr : _impl->ssl;
}
} // namespace vio::quic
