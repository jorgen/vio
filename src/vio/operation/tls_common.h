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

#include <vio/socket_stream.h>
#include <vio/ssl_config_t.h>

#include <string>

#include <tls.h>

namespace vio
{

std::string get_default_ca_certificates();

using tls_config_ptr_t = std::unique_ptr<tls_config, decltype(&tls_config_free)>;
static std::expected<tls_config_ptr_t, error_t> create_tls_config(const ssl_config_t &config, const std::string &default_ca_certificates)
{
  tls_config_ptr_t tls_config(tls_config_new(), &tls_config_free);
  if (!tls_config)
  {
    return std::unexpected(error_t{.code = -1, .msg = "Failed to create TLS config"});
  }

  if (config.ca_mem)
  {
    if (auto result = tls_config_set_ca_mem(tls_config.get(), config.ca_mem->data(), config.ca_mem->size()); result < 0)
      return std::unexpected(error_t{.code = result, .msg = tls_config_error(tls_config.get())});
  }
  else if (config.ca_file || config.ca_path)
  {
    if (auto result = tls_config_set_ca_file(tls_config.get(), config.ca_file ? config.ca_file->c_str() : nullptr); result < 0)
      return std::unexpected(error_t{.code = result, .msg = tls_config_error(tls_config.get())});
    if (auto result = tls_config_set_ca_path(tls_config.get(), config.ca_path ? config.ca_path->c_str() : nullptr); result < 0)
      return std::unexpected(error_t{.code = result, .msg = tls_config_error(tls_config.get())});
  }
  else
  {
    if (auto result = tls_config_set_ca_mem(tls_config.get(), (uint8_t *)default_ca_certificates.data(), default_ca_certificates.size()); result < 0)
      return std::unexpected(error_t{.code = result, .msg = tls_config_error(tls_config.get())});
  }

  if (config.cert_mem && config.key_mem)
  {
    if (auto result = tls_config_set_cert_mem(tls_config.get(), config.cert_mem->data(), config.cert_mem->size()); result < 0)
      return std::unexpected(error_t{.code = result, .msg = tls_config_error(tls_config.get())});
    if (auto result = tls_config_set_key_mem(tls_config.get(), config.key_mem->data(), config.key_mem->size()); result < 0)
      return std::unexpected(error_t{.code = result, .msg = tls_config_error(tls_config.get())});
  }
  else if (config.cert_file && config.key_file)
  {
    if (auto result = tls_config_set_cert_file(tls_config.get(), config.cert_file->c_str()); result < 0)
      return std::unexpected(error_t{.code = result, .msg = tls_config_error(tls_config.get())});
    if (auto result = tls_config_set_key_file(tls_config.get(), config.key_file->c_str()); result < 0)
      return std::unexpected(error_t{.code = result, .msg = tls_config_error(tls_config.get())});
  }

  if (config.ocsp_staple_mem)
  {
    if (auto result = tls_config_set_ocsp_staple_mem(tls_config.get(), config.ocsp_staple_mem->data(), config.ocsp_staple_mem->size()); result < 0)
      return std::unexpected(error_t{.code = result, .msg = tls_config_error(tls_config.get())});
  }
  else if (config.ocsp_staple_file)
  {
    if (auto result = tls_config_set_ocsp_staple_file(tls_config.get(), config.ocsp_staple_file->c_str()); result < 0)
      return std::unexpected(error_t{.code = result, .msg = tls_config_error(tls_config.get())});
  }

  if (config.ciphers)
    if (auto result = tls_config_set_ciphers(tls_config.get(), config.ciphers->c_str()); result < 0)
      return std::unexpected(error_t{.code = result, .msg = tls_config_error(tls_config.get())});

  if (config.alpn)
    if (auto result = tls_config_set_alpn(tls_config.get(), config.alpn->c_str()); result < 0)
      return std::unexpected(error_t{.code = result, .msg = tls_config_error(tls_config.get())});

  if (config.protocols)
    if (auto result = tls_config_set_protocols(tls_config.get(), *config.protocols); result < 0)
      return std::unexpected(error_t{.code = result, .msg = tls_config_error(tls_config.get())});

  // if (config.dheparams)
  //   if (auto result = tls_config_set_dheparams(tls_config.get(), *config.dheparams); result < 0)
  //     return std::unexpected(error_t{result, tls_config_error(tls_config.get())});

  // if (config.ecdhecurve)
  //   if (auto result = tls_config_set_ecdhecurve(tls_config.get(), *config.ecdhecurve); result < 0)
  //     return std::unexpected(error_t{result, tls_config_error(tls_config.get())});

  if (config.verify_client)
  {
    tls_config_verify_client(tls_config.get());
  }

  if (config.verify_depth)
  {
    tls_config_set_verify_depth(tls_config.get(), *config.verify_depth);
  }

  if (config.verify_optional)
  {
    tls_config_verify(tls_config.get());
  }
  return tls_config;
}

inline error_t apply_ssl_config_to_tls_ctx(const ssl_config_t &config, const std::string &default_ca_certificates, tls *tls_ctx)
{
  auto tls_config = create_tls_config(config, default_ca_certificates);
  if (!tls_config)
  {
    return tls_config.error();
  }

  if (auto result = tls_configure(tls_ctx, tls_config.value().get()); result < 0)
  {
    return error_t{.code = result, .msg = tls_error(tls_ctx)};
  }
  return {};
}

template <typename T>
struct tls_stream_t
{
  T &connection_handler;

  void close()
  {
    connection_handler.close();
  }

  std::expected<std::pair<stream_io_result_t, uint32_t>, error_t> read(void *target, uint32_t size)
  {
    tls *tls_ctx = connection_handler.stream_tls_ctx;
    assert(tls_ctx);
    const auto r = tls_read(tls_ctx, target, size);
    if (r == TLS_WANT_POLLIN)
    {
      return std::make_pair(stream_io_result_t::poll_in, uint32_t(0));
    }
    if (r == TLS_WANT_POLLOUT)
    {
      return std::make_pair(stream_io_result_t::poll_out, uint32_t(0));
    }
    if (r == 0)
    {
      return std::unexpected(error_t{.code = -1, .msg = "TLS connection closed"});
    }
    if (r < 0)
    {
      return std::unexpected(error_t{.code = int(r), .msg = tls_error(tls_ctx)});
    }
    return std::make_pair(stream_io_result_t::ok, uint32_t(r));
  }

  std::expected<std::pair<stream_io_result_t, uint32_t>, error_t> write(void *source, uint32_t size)
  {
    tls *tls_ctx = connection_handler.stream_tls_ctx;
    assert(tls_ctx);
    auto written = tls_write(tls_ctx, source, size);
    if (written == TLS_WANT_POLLIN)
    {
      return std::make_pair(stream_io_result_t::poll_in, uint32_t(0));
    }
    if (written == TLS_WANT_POLLOUT)
    {
      return std::make_pair(stream_io_result_t::poll_out, uint32_t(0));
    }
    if (written < 0)
    {
      return std::unexpected(error_t{.code = int(written), .msg = tls_error(tls_ctx)});
    }
    return std::make_pair(stream_io_result_t::ok, uint32_t(written));
  }
};

} // namespace vio