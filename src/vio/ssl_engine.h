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

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <new>
#include <span>
#include <string>
#include <vector>

#include <vio/detail/exceptions.h>
#include <vio/detail/native.h>
#include <vio/detail/sys.h>
#include <vio/error.h>
#include <vio/ssl_backend.h>
#include <vio/ssl_context.h>

namespace vio
{
constexpr int vio_tls_error = 0x715c00;
constexpr int vio_tls_clean_shutdown = 0x715c01;
constexpr int vio_tls_truncated = 0x715c02;

enum class ssl_status
{
  ok,
  want_read,
  closed,
  fatal,
};

inline bool is_ip_literal(const std::string &host)
{
  unsigned char buffer[sizeof(in6_addr)];
#if defined(_WIN32)
  detail::ensure_winsock();
  return InetPtonA(AF_INET, host.c_str(), buffer) == 1 || InetPtonA(AF_INET6, host.c_str(), buffer) == 1;
#else
  return inet_pton(AF_INET, host.c_str(), buffer) == 1 || inet_pton(AF_INET6, host.c_str(), buffer) == 1;
#endif
}

struct ssl_engine_t;

namespace detail
{
inline int ssl_engine_bio_read(BIO *bio, char *out, int length);
inline int ssl_engine_bio_write(BIO *bio, const char *in, int length);
inline long ssl_engine_bio_ctrl(BIO *bio, int command, long number, void *pointer);

inline BIO_METHOD *ssl_engine_bio_method()
{
  static BIO_METHOD *method = [] {
    BIO_METHOD *created = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_SOURCE_SINK, "vio tls engine");
    if (created == nullptr)
      return created;
    BIO_meth_set_read(created, &ssl_engine_bio_read);
    BIO_meth_set_write(created, &ssl_engine_bio_write);
    BIO_meth_set_ctrl(created, &ssl_engine_bio_ctrl);
    return created;
  }();
  return method;
}

template <typename Buffer>
class ssl_spare_pool_t
{
public:
  static constexpr std::size_t limit = 4;

  [[nodiscard]] Buffer take() noexcept
  {
    if (_count == 0)
      return Buffer{};
    return std::move(_buffers[--_count]);
  }

  void give(Buffer buffer) noexcept
  {
    if (_count < limit)
      _buffers[_count++] = std::move(buffer);
  }

  [[nodiscard]] std::size_t size() const noexcept
  {
    return _count;
  }

private:
  std::array<Buffer, limit> _buffers;
  std::size_t _count = 0;
};

inline ssl_spare_pool_t<std::unique_ptr<std::byte[]>> &ssl_inbound_pool() noexcept
{
  thread_local ssl_spare_pool_t<std::unique_ptr<std::byte[]>> pool;
  return pool;
}

class ssl_output_pool_t
{
public:
  static constexpr std::size_t spare_floor = 4;

  [[nodiscard]] std::vector<std::byte> take() noexcept
  {
    if (_spares.empty())
      return {};
    auto buffer = std::move(_spares.back());
    _spares.pop_back();
    _untouched = (std::min)(_untouched, _spares.size());
    return buffer;
  }

  void give(std::vector<std::byte> buffer) noexcept
  {
    VIO_TRY
    {
      _spares.push_back(std::move(buffer));
    }
    VIO_CATCH_ALL
    {
    }
  }

  [[nodiscard]] std::size_t size() const noexcept
  {
    return _spares.size();
  }

  [[nodiscard]] std::size_t surplus() const noexcept
  {
    return _spares.size() > spare_floor ? _spares.size() - spare_floor : 0;
  }

  void trim() noexcept
  {
    drop_oldest((std::min)(_untouched, surplus()));
  }

  [[nodiscard]] bool claim_trim(const void *owner) noexcept
  {
    if (_trimmer != nullptr || surplus() == 0)
      return false;
    _trimmer = owner;
    return true;
  }

  bool release_trim(const void *owner) noexcept
  {
    if (_trimmer != owner)
      return false;
    _trimmer = nullptr;
    return true;
  }

  [[nodiscard]] bool trim_claimed() const noexcept
  {
    return _trimmer != nullptr;
  }

  void attach() noexcept
  {
    ++_users;
  }

  void detach() noexcept
  {
    if (--_users > 0)
      return;
    _users = 0;
    drop_oldest(surplus());
  }

private:
  void drop_oldest(std::size_t count) noexcept
  {
    _spares.erase(_spares.begin(), _spares.begin() + static_cast<std::ptrdiff_t>(count));
    _untouched = _spares.size();
  }

  std::vector<std::vector<std::byte>> _spares;
  std::size_t _untouched = 0;
  std::ptrdiff_t _users = 0;
  const void *_trimmer = nullptr;
};

inline ssl_output_pool_t &ssl_output_pool() noexcept
{
  thread_local ssl_output_pool_t pool;
  return pool;
}
} // namespace detail

struct ssl_engine_t
{
  static constexpr std::size_t inbound_capacity = 65536;
  static constexpr std::size_t output_retain = 65536 + 65536 / 16 + 1024;

  SSL *ssl = nullptr;
  BIO *rbio = nullptr;
  BIO *wbio = nullptr;
  bool server = false;
  bool shutdown_sent = false;
  std::string peer_name;

  ssl_engine_t() = default;
  ssl_engine_t(const ssl_engine_t &) = delete;
  ssl_engine_t &operator=(const ssl_engine_t &) = delete;
  ssl_engine_t(ssl_engine_t &&) = delete;
  ssl_engine_t &operator=(ssl_engine_t &&) = delete;
  ~ssl_engine_t()
  {
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

  error_t init(ssl_context_t &context, bool is_server, const std::string &host)
  {
    server = is_server;
    ssl = SSL_new(context.ctx);
    if (ssl == nullptr)
    {
      return error_t{.code = vio_tls_error, .msg = "SSL_new failed: " + ssl::last_error_string()};
    }
    BIO_METHOD *method = detail::ssl_engine_bio_method();
    if (method != nullptr)
    {
      rbio = BIO_new(method);
      wbio = BIO_new(method);
    }
    if (rbio == nullptr || wbio == nullptr)
    {
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
      SSL_free(ssl);
      ssl = nullptr;
      return error_t{.code = vio_tls_error, .msg = "BIO_new failed"};
    }
    BIO_set_data(rbio, this);
    BIO_set_init(rbio, 1);
    BIO_set_data(wbio, this);
    BIO_set_init(wbio, 1);
    SSL_set_bio(ssl, rbio, wbio);

    if (server)
    {
      SSL_set_accept_state(ssl);
    }
    else
    {
      SSL_set_connect_state(ssl);
      peer_name = host;
      // Stable pointer used by the session-cache new-session callback to key the
      // stored session; valid for the SSL's lifetime (engine outlives the SSL).
      SSL_set_ex_data(ssl, detail::session_host_ssl_index(), &peer_name);
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
      // Resume a cached session for this host, if one is available.
      if (auto *cache = static_cast<ssl_session_cache_t *>(SSL_CTX_get_ex_data(context.ctx, detail::session_cache_ctx_index())))
      {
        if (SSL_SESSION *cached = cache->get(host))
        {
          SSL_set_session(ssl, cached);
        }
      }
      if (context.client_request_ocsp)
      {
        SSL_set_tlsext_status_type(ssl, TLSEXT_STATUSTYPE_ocsp);
      }
    }
    return {};
  }

  [[nodiscard]] std::span<std::byte> inbound_space(std::size_t capacity = inbound_capacity)
  {
    if (!_in)
    {
      if (capacity == inbound_capacity)
        _in = detail::ssl_inbound_pool().take();
      if (!_in)
        _in.reset(new (std::nothrow) std::byte[capacity]);
      if (!_in)
        return {};
      _in_capacity = capacity;
      _in_head = 0;
      _in_tail = 0;
    }
    if (_in_head == _in_tail)
    {
      _in_head = 0;
      _in_tail = 0;
    }
    else if (_in_tail == _in_capacity && _in_head > 0)
    {
      std::memmove(_in.get(), _in.get() + _in_head, _in_tail - _in_head);
      _in_tail -= _in_head;
      _in_head = 0;
    }
    return {_in.get() + _in_tail, _in_capacity - _in_tail};
  }

  void commit_inbound(std::size_t length) noexcept
  {
    _in_tail += (std::min)(length, _in_capacity - _in_tail);
  }

  [[nodiscard]] std::size_t inbound_size() const noexcept
  {
    return _in_tail - _in_head;
  }

  void release_inbound_if_empty() noexcept
  {
    if (_in_head != _in_tail)
      return;
    if (_in && _in_capacity == inbound_capacity)
      detail::ssl_inbound_pool().give(std::move(_in));
    _in.reset();
    _in_capacity = 0;
    _in_head = 0;
    _in_tail = 0;
  }

  bool feed_ciphertext(const char *data, size_t len)
  {
    if (len == 0)
      return true;
    auto held = inbound_size();
    if (_in_capacity - held < len)
    {
      if (len > (std::numeric_limits<std::size_t>::max)() - held)
        return false;
      auto capacity = (std::max)(inbound_capacity, held + len);
      std::unique_ptr<std::byte[]> grown(new (std::nothrow) std::byte[capacity]);
      if (!grown)
        return false;
      if (held > 0)
        std::memcpy(grown.get(), _in.get() + _in_head, held);
      _in = std::move(grown);
      _in_capacity = capacity;
      _in_head = 0;
      _in_tail = held;
    }
    auto space = inbound_space(_in_capacity);
    if (space.size() < len)
      return false;
    std::memcpy(space.data(), data, len);
    commit_inbound(len);
    return true;
  }

  [[nodiscard]] bool has_input() const
  {
    return inbound_size() > 0 || (ssl != nullptr && SSL_pending(ssl) > 0);
  }

  [[nodiscard]] bool has_output() const
  {
    return output_size() > 0;
  }

  [[nodiscard]] std::size_t output_size() const noexcept
  {
    return _out.size() - _out_head;
  }

  [[nodiscard]] std::size_t output_capacity() const noexcept
  {
    return _out.capacity();
  }

  [[nodiscard]] std::span<const std::byte> pending_output() const noexcept
  {
    return {_out.data() + _out_head, _out.size() - _out_head};
  }

  [[nodiscard]] std::uint64_t output_total() const noexcept
  {
    return _out_total;
  }

  [[nodiscard]] std::uint64_t output_sent() const noexcept
  {
    return _out_sent;
  }

  void reserve_output(std::size_t additional)
  {
    compact_output();
    adopt_pooled_output();
    if (_out.capacity() - _out.size() < additional)
      _out.reserve((std::max)(_out.size() + additional, _out.capacity() * 2));
  }

  void consume_output(std::size_t length) noexcept
  {
    length = (std::min)(length, output_size());
    _out_head += length;
    _out_sent += length;
    if (_out_head == _out.size())
      reset_output();
  }

  void discard_output() noexcept
  {
    _out_sent = _out_total;
    _out_head = _out.size();
    reset_output();
  }

  size_t drain_into(std::vector<uint8_t> &out)
  {
    auto pending = pending_output();
    auto *first = reinterpret_cast<const uint8_t *>(pending.data());
    out.insert(out.end(), first, first + pending.size());
    consume_output(pending.size());
    return pending.size();
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
      return ssl_status::want_read;
    }
    if (e == SSL_ERROR_ZERO_RETURN)
    {
      return ssl_status::closed;
    }
    return ssl_status::fatal;
  }

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

  // True if this connection resumed a previous session (abbreviated handshake).
  [[nodiscard]] bool session_reused() const
  {
    return ssl != nullptr && SSL_session_reused(ssl) == 1;
  }

  // The peer's stapled OCSP response (client side), empty if none was received.
  [[nodiscard]] std::vector<uint8_t> ocsp_response() const
  {
    if (ssl == nullptr)
    {
      return {};
    }
    const unsigned char *resp = nullptr;
    const long n = SSL_get_tlsext_status_ocsp_resp(ssl, &resp);
    if (resp == nullptr || n <= 0)
    {
      return {};
    }
    return std::vector<uint8_t>(resp, resp + n);
  }

private:
  friend int detail::ssl_engine_bio_read(BIO *bio, char *out, int length);
  friend int detail::ssl_engine_bio_write(BIO *bio, const char *in, int length);
  friend long detail::ssl_engine_bio_ctrl(BIO *bio, int command, long number, void *pointer);

  int pull_input(char *out, int length) noexcept
  {
    auto available = inbound_size();
    if (available == 0 || length <= 0)
      return 0;
    auto count = (std::min)(available, static_cast<std::size_t>(length));
    std::memcpy(out, _in.get() + _in_head, count);
    _in_head += count;
    if (_in_head == _in_tail)
    {
      _in_head = 0;
      _in_tail = 0;
    }
    return static_cast<int>(count);
  }

  bool push_output(const char *in, int length)
  {
    if (length <= 0)
      return true;
    compact_output();
    auto *first = reinterpret_cast<const std::byte *>(in);
    VIO_TRY
    {
      adopt_pooled_output();
      _out.insert(_out.end(), first, first + length);
    }
    VIO_CATCH_ALL
    {
      return false;
    }
    _out_total += static_cast<std::uint64_t>(length);
    return true;
  }

  void compact_output()
  {
    if (_out_head == 0)
      return;
    if (_out_head == _out.size())
    {
      _out.clear();
      _out_head = 0;
      return;
    }
    if (_out_head >= output_retain && _out_head * 2 >= _out.size())
    {
      _out.erase(_out.begin(), _out.begin() + static_cast<std::ptrdiff_t>(_out_head));
      _out_head = 0;
    }
  }

  void adopt_pooled_output()
  {
    if (_out.capacity() != 0)
      return;
    _out = detail::ssl_output_pool().take();
    if (_out.capacity() == 0)
      _out.reserve(output_retain);
  }

  void reset_output() noexcept
  {
    _out_head = 0;
    _out.clear();
    if (_out.capacity() == output_retain)
      detail::ssl_output_pool().give(std::move(_out));
    std::vector<std::byte>().swap(_out);
  }

  std::unique_ptr<std::byte[]> _in;
  std::size_t _in_capacity = 0;
  std::size_t _in_head = 0;
  std::size_t _in_tail = 0;
  std::vector<std::byte> _out;
  std::size_t _out_head = 0;
  std::uint64_t _out_total = 0;
  std::uint64_t _out_sent = 0;
};

namespace detail
{
inline int ssl_engine_bio_read(BIO *bio, char *out, int length)
{
  BIO_clear_retry_flags(bio);
  auto *engine = static_cast<ssl_engine_t *>(BIO_get_data(bio));
  if (engine == nullptr || length <= 0)
    return 0;
  int count = engine->pull_input(out, length);
  if (count == 0)
  {
    BIO_set_retry_read(bio);
    return -1;
  }
  return count;
}

inline int ssl_engine_bio_write(BIO *bio, const char *in, int length)
{
  BIO_clear_retry_flags(bio);
  auto *engine = static_cast<ssl_engine_t *>(BIO_get_data(bio));
  if (engine == nullptr)
    return -1;
  if (length <= 0)
    return 0;
  if (!engine->push_output(in, length))
    return -1;
  return length;
}

inline long ssl_engine_bio_ctrl(BIO *bio, int command, long, void *)
{
  auto *engine = static_cast<ssl_engine_t *>(BIO_get_data(bio));
  switch (command)
  {
  case BIO_CTRL_FLUSH:
    return 1;
  case BIO_CTRL_PENDING:
    return engine == nullptr ? 0 : static_cast<long>((std::min)(engine->inbound_size(), static_cast<std::size_t>((std::numeric_limits<long>::max)())));
  case BIO_CTRL_WPENDING:
    return 0;
  default:
    return 0;
  }
}
} // namespace detail

} // namespace vio
