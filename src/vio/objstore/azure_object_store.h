/*
  Copyright (c) 2024 Jørgen Lind

  Permission is hereby granted, free of charge, to any person obtaining a copy of
  this software and associated documentation files (the "Software"), to deal in
  the Software without restriction, including without limitation the rights to
  use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
  of the Software, and to permit persons to whom the Software is furnished to do
  so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
*/
#pragma once

#include <vio/objstore/http_object_store.h>
#include <vio/objstore/signing.h>

#include <cstdint>
#include <span>
#include <string>

namespace vio::objstore
{

// Azure Blob Storage using either Shared Key (account key) or a SAS token. Real Azure uses a
// virtual-host endpoint (https://<account>.blob.core.windows.net/<container>/<blob>); the local
// emulator (Azurite) puts the account in the path (http://127.0.0.1:10000/<account>/<container>/<blob>).
class azure_io_manager_t : public http_io_manager_t
{
public:
  struct config_t
  {
    bool https = true;
    std::string host;   // "<account>.blob.core.windows.net" or "127.0.0.1"
    uint16_t port = 0;  // 0 => default for the scheme
    std::string account;
    std::string account_key_base64; // Shared Key auth (base64). Empty when using a SAS.
    std::string sas;                // SAS query string without leading '?'. When set, used instead of Shared Key.
    std::string container;
    std::string prefix;             // blob-name prefix within the container (may be empty)
    bool account_in_path = false;   // Azurite: the account appears in the URL path
    std::string api_version = "2021-08-06";
  };

  azure_io_manager_t(event_loop_t &loop, config_t cfg)
    : http_io_manager_t(loop)
    , _cfg(std::move(cfg))
  {
    _allow_plaintext = !_cfg.https;
  }

protected:
  http::request_t build_request(const std::string &method, const std::string &name, std::span<const uint8_t> payload, const io_range_t *range) const override
  {
    std::string amz_date, date_stamp, rfc1123;
    utc_now(amz_date, date_stamp, rfc1123);

    std::string blob = _cfg.prefix.empty() ? name : (_cfg.prefix + "/" + name);
    // The request URI path. Azurite carries the account in the path; real Azure carries it in the host.
    std::string path = _cfg.account_in_path ? ("/" + _cfg.account + "/" + _cfg.container + "/" + blob) : ("/" + _cfg.container + "/" + blob);

    std::string host_value = host_header(_cfg.https, _cfg.host, _cfg.port);
    std::string url = (_cfg.https ? "https://" : "http://") + host_value + uri_encode(path, true);

    std::string range_str;
    if (range && range->size >= 0 && method == "GET")
      range_str = "bytes=" + std::to_string(range->offset) + "-" + std::to_string(range->offset + range->size - 1);

    const bool is_put = (method == "PUT");

    std::vector<signed_header_t> x_ms;
    x_ms.push_back({"x-ms-date", rfc1123});
    x_ms.push_back({"x-ms-version", _cfg.api_version});
    if (is_put)
      x_ms.push_back({"x-ms-blob-type", "BlockBlob"});

    http::request_t req;
    req.method = method;
    req.allow_plaintext = _allow_plaintext;
    req.ca_mem = _ca_mem;
    for (const auto &h : x_ms)
      req.headers.push_back({h.name, h.value});

    if (!_cfg.sas.empty())
    {
      url += (url.find('?') == std::string::npos ? "?" : "&") + _cfg.sas;
    }
    else
    {
      std::string content_length = (is_put && payload.size() > 0) ? std::to_string(payload.size()) : std::string();
      // Canonicalized resource is "/{account}{uri-path}"; for Azurite the account legitimately repeats.
      std::string canonical_resource = "/" + _cfg.account + path;
      std::string authorization = azure_sharedkey_authorization(method, _cfg.account, _cfg.account_key_base64, canonical_resource, x_ms, content_length, "", range_str);
      req.headers.push_back({"Authorization", authorization});
    }

    req.url = std::move(url);
    if (!range_str.empty())
      req.headers.push_back({"Range", range_str});
    return req;
  }

private:
  config_t _cfg;
};

} // namespace vio::objstore
