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

#include <optional>
#include <string>
#include <vector>

#include <tls.h>

namespace vio
{
struct ssl_config
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
  std::optional<std::string> ciphers;
  std::optional<std::string> alpn;
  std::optional<bool> verify_client;
  std::optional<bool> verify_depth;
  std::optional<bool> verify_optional;
  std::optional<uint32_t> protocols;
  std::optional<uint32_t> dheparams;
  std::optional<uint32_t> ecdhecurve;
};

std::string get_default_ca_certificates();

using tls_config_ptr_t = std::unique_ptr<tls_config, decltype(&tls_config_free)>;
static std::expected<tls_config_ptr_t, error_t> create_tls_config(const ssl_config &config, const std::string &default_ca_certificates)
{
  tls_config_ptr_t tls_config(tls_config_new(), &tls_config_free);
  if (!tls_config)
  {
    return std::unexpected(error_t{-1, "Failed to create TLS config"});
  }

  if (config.ca_mem)
  {
    if (auto result = tls_config_set_ca_mem(tls_config.get(), config.ca_mem->data(), config.ca_mem->size()); result < 0)
      return std::unexpected(error_t{result, tls_config_error(tls_config.get())});
  }
  else if (config.ca_file || config.ca_path)
  {
    if (auto result = tls_config_set_ca_file(tls_config.get(), config.ca_file ? config.ca_file->c_str() : nullptr); result < 0)
      return std::unexpected(error_t{result, tls_config_error(tls_config.get())});
    if (auto result = tls_config_set_ca_path(tls_config.get(), config.ca_path ? config.ca_path->c_str() : nullptr); result < 0)
      return std::unexpected(error_t{result, tls_config_error(tls_config.get())});
  }
  else
  {
    if (auto result = tls_config_set_ca_mem(tls_config.get(), (uint8_t *)default_ca_certificates.data(), default_ca_certificates.size()); result < 0)
      return std::unexpected(error_t{result, tls_config_error(tls_config.get())});
  }

  if (config.cert_mem && config.key_mem)
  {
    if (auto result = tls_config_set_cert_mem(tls_config.get(), config.cert_mem->data(), config.cert_mem->size()); result < 0)
      return std::unexpected(error_t{result, tls_config_error(tls_config.get())});
    if (auto result = tls_config_set_key_mem(tls_config.get(), config.key_mem->data(), config.key_mem->size()); result < 0)
      return std::unexpected(error_t{result, tls_config_error(tls_config.get())});
  }
  else if (config.cert_file && config.key_file)
  {
    if (auto result = tls_config_set_cert_file(tls_config.get(), config.cert_file->c_str()); result < 0)
      return std::unexpected(error_t{result, tls_config_error(tls_config.get())});
    if (auto result = tls_config_set_key_file(tls_config.get(), config.key_file->c_str()); result < 0)
      return std::unexpected(error_t{result, tls_config_error(tls_config.get())});
  }

  if (config.ocsp_staple_mem)
  {
    if (auto result = tls_config_set_ocsp_staple_mem(tls_config.get(), config.ocsp_staple_mem->data(), config.ocsp_staple_mem->size()); result < 0)
      return std::unexpected(error_t{result, tls_config_error(tls_config.get())});
  }
  else if (config.ocsp_staple_file)
  {
    if (auto result = tls_config_set_ocsp_staple_file(tls_config.get(), config.ocsp_staple_file->c_str()); result < 0)
      return std::unexpected(error_t{result, tls_config_error(tls_config.get())});
  }

  if (config.ciphers)
    if (auto result = tls_config_set_ciphers(tls_config.get(), config.ciphers->c_str()); result < 0)
      return std::unexpected(error_t{result, tls_config_error(tls_config.get())});

  if (config.alpn)
    if (auto result = tls_config_set_alpn(tls_config.get(), config.alpn->c_str()); result < 0)
      return std::unexpected(error_t{result, tls_config_error(tls_config.get())});

  if (config.protocols)
    if (auto result = tls_config_set_protocols(tls_config.get(), *config.protocols); result < 0)
      return std::unexpected(error_t{result, tls_config_error(tls_config.get())});

  if (config.dheparams)
    // if (auto result = tls_config_set_dheparams(tls_config.get(), *config.dheparams); result < 0)
    //   return std::unexpected(error_t{result, tls_config_error(tls_config.get())});

    if (config.ecdhecurve)
      // if (auto result = tls_config_set_ecdhecurve(tls_config.get(), *config.ecdhecurve); result < 0)
      //   return std::unexpected(error_t{result, tls_config_error(tls_config.get())});

      if (config.verify_client)
        tls_config_verify_client(tls_config.get());

  if (config.verify_depth)
    tls_config_set_verify_depth(tls_config.get(), *config.verify_depth);

  if (config.verify_optional)
    tls_config_verify(tls_config.get());
  return tls_config;
}

inline std::expected<void, error_t> apply_ssl_config_to_tls_ctx(const ssl_config &config, const std::string &default_ca_certificates, tls *tls_ctx)
{
  auto tls_config = create_tls_config(config, default_ca_certificates);
  if (!tls_config)
    return std::unexpected(tls_config.error());

  if (auto result = tls_configure(tls_ctx, tls_config.value().get()); result < 0)
  {
    return std::unexpected(error_t{result, tls_error(tls_ctx)});
  }
  return {};
}

} // namespace vio