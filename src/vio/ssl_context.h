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

// ssl_context_t owns a shared SSL_CTX built once per client/server config and
// reused across connections. It maps ssl_config_t onto the backend-portable
// SSL_CTX_* surface (see ssl_backend.h) including ALPN, keylog and the session
// cache. Per-connection SSL*/BIO state lives in ssl_engine_t, not here.

#include <cstring>
#include <expected>
#include <functional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include <vio/error.h>
#include <vio/ssl_backend.h>
#include <vio/ssl_config_t.h>

namespace vio
{

namespace detail
{
inline int keylog_ex_index()
{
  static int idx = SSL_CTX_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
  return idx;
}

inline void keylog_trampoline(const SSL *ssl, const char *line)
{
  SSL_CTX *ctx = SSL_get_SSL_CTX(const_cast<SSL *>(ssl));
  auto *fn = static_cast<std::function<void(std::string_view)> *>(SSL_CTX_get_ex_data(ctx, keylog_ex_index()));
  if (fn != nullptr && *fn)
  {
    (*fn)(std::string_view(line));
  }
}

// Server-side ALPN selection. Hand-rolled (server preference wins) rather than
// SSL_select_next_proto (which honors client preference and, on empty client
// lists, historically returned a dangling pointer -- CVE-2024-5535). `arg` is a
// stable pointer to ssl_context_t::alpn_wire.
inline int alpn_select_trampoline(SSL * /*ssl*/, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg)
{
  const auto *server_wire = static_cast<const std::vector<uint8_t> *>(arg);
  if (server_wire == nullptr || server_wire->empty() || inlen == 0)
  {
    return SSL_TLSEXT_ERR_NOACK;
  }
  const uint8_t *s = server_wire->data();
  const size_t slen = server_wire->size();
  for (size_t i = 0; i + 1 <= slen;)
  {
    const uint8_t sl = s[i];
    if (sl == 0 || i + 1 + sl > slen)
    {
      break;
    }
    const uint8_t *sp = s + i + 1;
    for (unsigned int j = 0; j + 1 <= inlen;)
    {
      const uint8_t cl = in[j];
      if (cl == 0 || j + 1U + cl > inlen)
      {
        break;
      }
      const uint8_t *cp = in + j + 1;
      if (cl == sl && std::memcmp(sp, cp, sl) == 0)
      {
        *out = sp; // points into the stable server wire buffer
        *outlen = sl;
        return SSL_TLSEXT_ERR_OK;
      }
      j += 1U + cl;
    }
    i += 1U + sl;
  }
  return SSL_TLSEXT_ERR_NOACK;
}

inline int to_openssl_version(tls_protocol_version v)
{
  return v == tls_protocol_version::tls1_3 ? TLS1_3_VERSION : TLS1_2_VERSION;
}

inline std::vector<std::string> effective_alpn(const ssl_config_t &config)
{
  if (!config.alpn_protocols.empty())
  {
    return config.alpn_protocols;
  }
  std::vector<std::string> out;
  if (config.alpn)
  {
    std::stringstream ss(*config.alpn);
    std::string item;
    while (std::getline(ss, item, ','))
    {
      if (!item.empty())
      {
        out.push_back(item);
      }
    }
  }
  return out;
}
} // namespace detail

struct ssl_context_t
{
  SSL_CTX *ctx = nullptr;
  bool is_server = false;
  // Stable storage referenced by the SSL_CTX for the context's lifetime.
  std::vector<uint8_t> alpn_wire;
  std::function<void(std::string_view)> keylog;

  ssl_context_t() = default;
  ssl_context_t(const ssl_context_t &) = delete;
  ssl_context_t &operator=(const ssl_context_t &) = delete;
  ssl_context_t(ssl_context_t &&) = delete;
  ssl_context_t &operator=(ssl_context_t &&) = delete;
  ~ssl_context_t()
  {
    if (ctx != nullptr)
    {
      SSL_CTX_free(ctx);
      ctx = nullptr;
    }
  }

  error_t init(bool server, const ssl_config_t &config, const std::string &default_ca)
  {
    is_server = server;
    ctx = SSL_CTX_new(server ? TLS_server_method() : TLS_client_method());
    if (ctx == nullptr)
    {
      return error_t{.code = -1, .msg = "SSL_CTX_new failed: " + ssl::last_error_string()};
    }

    // Protocol version bounds (min clamped to TLS 1.2 -- TLS 1.0/1.1 are gone).
    const int min_v = detail::to_openssl_version(config.min_protocol.value_or(tls_protocol_version::tls1_2));
    const int max_v = detail::to_openssl_version(config.max_protocol.value_or(tls_protocol_version::tls1_3));
    SSL_CTX_set_min_proto_version(ctx, min_v);
    SSL_CTX_set_max_proto_version(ctx, max_v);

    // Let SSL_write accept a moved buffer pointer on retry (we chunk plaintext).
    SSL_CTX_set_mode(ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

    if (auto err = configure_ca(config, default_ca); err.code != 0)
    {
      return err;
    }
    if (auto err = configure_cert_key(config); err.code != 0)
    {
      return err;
    }
    if (auto err = configure_crypto_params(config); err.code != 0)
    {
      return err;
    }
    configure_verify(server, config);
    configure_alpn(server, config);
    configure_keylog(config);
    if (config.enable_session_cache)
    {
      SSL_CTX_set_session_cache_mode(ctx, server ? SSL_SESS_CACHE_SERVER : SSL_SESS_CACHE_CLIENT);
    }
    return {};
  }

private:
  error_t configure_ca(const ssl_config_t &config, const std::string &default_ca)
  {
    if (config.ca_mem)
    {
      return ssl::add_ca_pem(ctx, std::span<const uint8_t>(config.ca_mem->data(), config.ca_mem->size()));
    }
    if (config.ca_file || config.ca_path)
    {
      const char *file = config.ca_file ? config.ca_file->c_str() : nullptr;
      const char *path = config.ca_path ? config.ca_path->c_str() : nullptr;
      if (SSL_CTX_load_verify_locations(ctx, file, path) != 1)
      {
        return error_t{.code = -1, .msg = "SSL_CTX_load_verify_locations failed: " + ssl::last_error_string()};
      }
      return {};
    }
    return ssl::add_ca_pem(ctx, std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(default_ca.data()), default_ca.size()));
  }

  error_t configure_cert_key(const ssl_config_t &config)
  {
    bool have_cert = false;
    bool have_key = false;
    if (config.cert_mem)
    {
      if (auto err = ssl::use_certificate_chain_pem(ctx, std::span<const uint8_t>(config.cert_mem->data(), config.cert_mem->size())); err.code != 0)
      {
        return err;
      }
      have_cert = true;
    }
    else if (config.cert_file)
    {
      if (SSL_CTX_use_certificate_chain_file(ctx, config.cert_file->c_str()) != 1)
      {
        return error_t{.code = -1, .msg = "SSL_CTX_use_certificate_chain_file failed: " + ssl::last_error_string()};
      }
      have_cert = true;
    }

    if (config.key_mem)
    {
      if (auto err = ssl::use_private_key_pem(ctx, std::span<const uint8_t>(config.key_mem->data(), config.key_mem->size())); err.code != 0)
      {
        return err;
      }
      have_key = true;
    }
    else if (config.key_file)
    {
      if (SSL_CTX_use_PrivateKey_file(ctx, config.key_file->c_str(), SSL_FILETYPE_PEM) != 1)
      {
        return error_t{.code = -1, .msg = "SSL_CTX_use_PrivateKey_file failed: " + ssl::last_error_string()};
      }
      have_key = true;
    }

    if (have_cert && have_key && SSL_CTX_check_private_key(ctx) != 1)
    {
      return error_t{.code = -1, .msg = "Private key does not match certificate: " + ssl::last_error_string()};
    }
    return {};
  }

  error_t configure_crypto_params(const ssl_config_t &config)
  {
    if (config.ciphers && SSL_CTX_set_cipher_list(ctx, config.ciphers->c_str()) != 1)
    {
      return error_t{.code = -1, .msg = "SSL_CTX_set_cipher_list failed: " + ssl::last_error_string()};
    }
    if (config.ciphersuites && ssl::set_ciphersuites(ctx, config.ciphersuites->c_str()) != 1)
    {
      return error_t{.code = -1, .msg = "SSL_CTX_set_ciphersuites failed: " + ssl::last_error_string()};
    }
    if (config.groups && ssl::set_groups_list(ctx, config.groups->c_str()) != 1)
    {
      return error_t{.code = -1, .msg = "Failed to set groups: " + ssl::last_error_string()};
    }
    return {};
  }

  void configure_verify(bool server, const ssl_config_t &config)
  {
    peer_verify_t pv;
    if (config.peer_verify)
    {
      pv = *config.peer_verify;
    }
    else if (server)
    {
      // Legacy fallback: verify_client => require, verify_optional => optional.
      pv = config.verify_client.value_or(false) ? peer_verify_t::required : (config.verify_optional.value_or(false) ? peer_verify_t::optional : peer_verify_t::disabled);
    }
    else
    {
      // A client verifies the server certificate by default.
      pv = peer_verify_t::required;
    }

    int mode = SSL_VERIFY_NONE;
    if (server)
    {
      if (pv == peer_verify_t::optional)
      {
        mode = SSL_VERIFY_PEER;
      }
      else if (pv == peer_verify_t::required)
      {
        mode = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
      }
    }
    else
    {
      // For a client, "optional" and "required" both mean verify the server.
      mode = (pv == peer_verify_t::disabled) ? SSL_VERIFY_NONE : SSL_VERIFY_PEER;
    }
    SSL_CTX_set_verify(ctx, mode, nullptr);
    if (config.verify_depth)
    {
      SSL_CTX_set_verify_depth(ctx, *config.verify_depth);
    }
  }

  void configure_alpn(bool server, const ssl_config_t &config)
  {
    alpn_wire = ssl::alpn_wire_from_list(detail::effective_alpn(config));
    if (alpn_wire.empty())
    {
      return; // no ALPN configured -> behave exactly as if unused
    }
    if (server)
    {
      SSL_CTX_set_alpn_select_cb(ctx, detail::alpn_select_trampoline, &alpn_wire);
    }
    else
    {
      // Note: SSL_CTX_set_alpn_protos returns 0 on SUCCESS (inverted).
      SSL_CTX_set_alpn_protos(ctx, alpn_wire.data(), static_cast<unsigned int>(alpn_wire.size()));
    }
  }

  void configure_keylog(const ssl_config_t &config)
  {
    if (config.keylog_callback)
    {
      keylog = config.keylog_callback;
      SSL_CTX_set_ex_data(ctx, detail::keylog_ex_index(), &keylog);
      SSL_CTX_set_keylog_callback(ctx, detail::keylog_trampoline);
    }
  }
};

} // namespace vio
