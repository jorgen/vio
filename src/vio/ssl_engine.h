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

// ssl_engine_t is a per-connection TLS codec with NO socket knowledge. It wraps
// an SSL* plus two in-memory BIOs:
//   rbio -- vio writes inbound CIPHERTEXT here (from the libuv read callback);
//           SSL_read pulls plaintext out of it.
//   wbio -- SSL_write / handshake push outbound CIPHERTEXT here; vio drains it
//           and hands it to uv_write.
// The owning uv_tls_stream_t driver always drains wbio after every engine call,
// so any SSL-produced control record (handshake flight, TLS 1.3 KeyUpdate
// response, alert, close_notify) is sent without the engine ever touching a
// socket. This keeps io_uring/IOCP under libuv invisible to the crypto layer.

#include <cstdint>
#include <string>
#include <vector>

#include <uv.h>

#include <vio/error.h>
#include <vio/ssl_backend.h>
#include <vio/ssl_context.h>

namespace vio
{
// Distinct, stable error codes so a downstream (e.g. HTTP/2) can branch on the
// kind of close instead of string-matching messages.
constexpr int vio_tls_error = 0x715c00;          // TLS protocol / library error
constexpr int vio_tls_clean_shutdown = 0x715c01; // peer sent close_notify (clean EOF)
constexpr int vio_tls_truncated = 0x715c02;      // TCP closed without close_notify (unclean)

// Outcome of an SSL_read / SSL_write / SSL_do_handshake step. After ANY of
// these the driver drains wbio and sends whatever ciphertext was produced.
enum class ssl_status
{
  ok,        // progress made (bytes produced/consumed, or handshake finished)
  want_read, // need more inbound ciphertext (feed rbio, then retry)
  closed,    // peer sent close_notify -- clean end of stream
  fatal,     // unrecoverable TLS error; call make_error()
};

inline bool is_ip_literal(const std::string &host)
{
  unsigned char buf[sizeof(struct in6_addr)];
  return uv_inet_pton(AF_INET, host.c_str(), buf) == 0 || uv_inet_pton(AF_INET6, host.c_str(), buf) == 0;
}

struct ssl_engine_t
{
  SSL *ssl = nullptr;
  BIO *rbio = nullptr; // inbound ciphertext (vio writes, SSL reads)
  BIO *wbio = nullptr; // outbound ciphertext (SSL writes, vio drains)
  bool server = false;
  bool shutdown_sent = false;

  ssl_engine_t() = default;
  ssl_engine_t(const ssl_engine_t &) = delete;
  ssl_engine_t &operator=(const ssl_engine_t &) = delete;
  ssl_engine_t(ssl_engine_t &&) = delete;
  ssl_engine_t &operator=(ssl_engine_t &&) = delete;
  ~ssl_engine_t()
  {
    // SSL_set_bio transferred ownership of rbio/wbio to ssl, so SSL_free frees
    // them too. Only free the BIOs directly if init failed before SSL_set_bio.
    if (ssl != nullptr)
    {
      SSL_free(ssl);
    }
    else
    {
      if (rbio != nullptr)
      {
        BIO_free(rbio);
      }
      if (wbio != nullptr)
      {
        BIO_free(wbio);
      }
    }
  }

  [[nodiscard]] bool initialized() const
  {
    return ssl != nullptr;
  }

  // `host` is the peer name for SNI + certificate verification (a hostname for
  // SNI/SSL_set1_host, an address for X509_VERIFY_PARAM). Empty skips both.
  error_t init(ssl_context_t &context, bool is_server, const std::string &host)
  {
    server = is_server;
    ssl = SSL_new(context.ctx);
    if (ssl == nullptr)
    {
      return error_t{.code = vio_tls_error, .msg = "SSL_new failed: " + ssl::last_error_string()};
    }
    rbio = BIO_new(BIO_s_mem());
    wbio = BIO_new(BIO_s_mem());
    if (rbio == nullptr || wbio == nullptr)
    {
      // SSL_set_bio has not run yet, so ownership was not transferred to ssl --
      // free whichever BIO did allocate so it is not leaked.
      if (rbio != nullptr)
      {
        BIO_free(rbio);
        rbio = nullptr;
      }
      if (wbio != nullptr)
      {
        BIO_free(wbio);
        wbio = nullptr;
      }
      return error_t{.code = vio_tls_error, .msg = "BIO_new(BIO_s_mem()) failed"};
    }
    // An empty memory BIO must report "retry", not EOF, or SSL would treat a
    // momentarily-empty rbio as a closed connection.
    BIO_set_mem_eof_return(rbio, -1);
    BIO_set_mem_eof_return(wbio, -1);
    SSL_set_bio(ssl, rbio, wbio); // takes ownership of both

    if (server)
    {
      SSL_set_accept_state(ssl);
    }
    else
    {
      SSL_set_connect_state(ssl);
      if (!host.empty())
      {
        if (is_ip_literal(host))
        {
          X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl), host.c_str());
        }
        else
        {
          SSL_set_tlsext_host_name(ssl, host.c_str());
          SSL_set1_host(ssl, host.c_str());
        }
      }
    }
    return {};
  }

  // Feed inbound ciphertext (from the libuv read callback) into rbio. A growable
  // memory BIO always accepts all bytes.
  void feed_ciphertext(const char *data, size_t len)
  {
    if (len > 0)
    {
      BIO_write(rbio, data, static_cast<int>(len));
    }
  }

  [[nodiscard]] bool has_output() const
  {
    return wbio != nullptr && BIO_ctrl_pending(wbio) > 0;
  }

  // Append all currently pending outbound ciphertext to `out`. Returns bytes appended.
  size_t drain_into(std::vector<uint8_t> &out)
  {
    size_t total = 0;
    char tmp[16384];
    for (;;)
    {
      const int n = BIO_read(wbio, tmp, static_cast<int>(sizeof(tmp)));
      if (n <= 0)
      {
        break;
      }
      out.insert(out.end(), reinterpret_cast<uint8_t *>(tmp), reinterpret_cast<uint8_t *>(tmp) + n);
      total += static_cast<size_t>(n);
    }
    return total;
  }

  [[nodiscard]] bool is_init_finished() const
  {
    return ssl != nullptr && SSL_is_init_finished(ssl);
  }

  ssl_status do_handshake()
  {
    ERR_clear_error();
    const int r = SSL_do_handshake(ssl);
    if (r == 1)
    {
      return ssl_status::ok;
    }
    const int e = SSL_get_error(ssl, r);
    if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
    {
      return ssl_status::want_read;
    }
    return ssl_status::fatal;
  }

  // Decrypt up to `len` bytes into `buf`. out_n receives the decrypted count.
  ssl_status read_plaintext(void *buf, int len, int &out_n)
  {
    out_n = 0;
    ERR_clear_error();
    const int n = SSL_read(ssl, buf, len);
    if (n > 0)
    {
      out_n = n;
      return ssl_status::ok;
    }
    const int e = SSL_get_error(ssl, n);
    // With a growable memory wbio, WANT_WRITE cannot persist, so treat it like
    // WANT_READ: the driver drains wbio and waits for more inbound ciphertext.
    if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
    {
      return ssl_status::want_read;
    }
    if (e == SSL_ERROR_ZERO_RETURN)
    {
      return ssl_status::closed;
    }
    return ssl_status::fatal;
  }

  // Encrypt up to `len` bytes from `buf`. out_n receives the plaintext consumed.
  ssl_status write_plaintext(const void *buf, int len, int &out_n)
  {
    out_n = 0;
    ERR_clear_error();
    const int n = SSL_write(ssl, buf, len);
    if (n > 0)
    {
      out_n = n;
      return ssl_status::ok;
    }
    const int e = SSL_get_error(ssl, n);
    if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
    {
      // Handshake not finished yet (write-before-handshake) -- retry after a read.
      return ssl_status::want_read;
    }
    if (e == SSL_ERROR_ZERO_RETURN)
    {
      return ssl_status::closed;
    }
    return ssl_status::fatal;
  }

  // Send a one-way close_notify (best effort). Produces ciphertext into wbio for
  // the driver to flush. Idempotent.
  void shutdown()
  {
    if (ssl != nullptr && !shutdown_sent)
    {
      shutdown_sent = true;
      ERR_clear_error();
      SSL_shutdown(ssl);
    }
  }

  // Build an error_t after a `fatal` status: prefer the certificate verification
  // reason, then the OpenSSL error queue.
  error_t make_error()
  {
    if (ssl != nullptr)
    {
      const long vr = SSL_get_verify_result(ssl);
      if (vr != X509_V_OK)
      {
        return error_t{.code = vio_tls_error, .msg = X509_verify_cert_error_string(vr)};
      }
    }
    const std::string s = ssl::last_error_string();
    ERR_clear_error();
    return error_t{.code = vio_tls_error, .msg = s.empty() ? "TLS protocol error" : s};
  }

  // Negotiated ALPN protocol (empty if none / not yet handshaken).
  [[nodiscard]] std::string alpn_selected() const
  {
    if (ssl == nullptr)
    {
      return {};
    }
    const unsigned char *data = nullptr;
    unsigned int len = 0;
    SSL_get0_alpn_selected(ssl, &data, &len);
    if (data == nullptr || len == 0)
    {
      return {};
    }
    return std::string(reinterpret_cast<const char *>(data), len);
  }
};

} // namespace vio
