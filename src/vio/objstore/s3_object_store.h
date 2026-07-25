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

#include <vio/crypto.h>
#include <vio/objstore/credentials.h>
#include <vio/objstore/http_object_store.h>
#include <vio/objstore/signing.h>

#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>

namespace vio::objstore
{

// S3-compatible object store (AWS S3, minio, ...) using AWS Signature Version 4. Supports both
// path-style (https://endpoint/bucket/key, used by minio/custom endpoints) and virtual-host style
// (https://bucket.endpoint/key, the AWS default).
class s3_io_manager_t : public http_io_manager_t
{
public:
  struct config_t
  {
    bool https = true;
    std::string host;   // endpoint host, e.g. "s3.us-east-1.amazonaws.com" or "127.0.0.1"
    uint16_t port = 0;  // 0 => default for the scheme
    std::string region = "us-east-1";
    std::string bucket;
    std::string prefix; // key prefix within the bucket (may be empty; no leading/trailing '/')
    std::string access_key;
    std::string secret_key;
    std::string session_token; // AWS STS temporary-credential token (empty for long-lived keys)
    bool path_style = false;
    // Optional async credentials source. When set, it supplies (and refreshes) the access_key / secret_key
    // / session_token used to sign each request, overriding the static values above; when null, the static
    // values are signed with as-is. Built by resolve_credential_chain (create_object_store.h) for a plain
    // AWS URL with no explicit credentials.
    std::shared_ptr<credentials_provider_t> provider;
  };

  s3_io_manager_t(event_loop_t &loop, config_t cfg)
    : http_io_manager_t(loop)
    , _cfg(std::move(cfg))
    , _provider(_cfg.provider)
    , _current{_cfg.access_key, _cfg.secret_key, _cfg.session_token, std::nullopt}
  {
    _allow_plaintext = !_cfg.https;
  }

protected:
  // Refresh _current from the credentials provider before each signed request. A no-op when there is no
  // provider (static credentials), so the injected-config / connection-string paths are unchanged.
  task_t<std::expected<void, error_t>> ensure_credentials() override
  {
    if (!_provider)
      co_return std::expected<void, error_t>{};
    auto creds = co_await _provider->credentials(_loop);
    if (!creds)
      co_return std::unexpected(creds.error());
    _current = std::move(*creds);
    co_return std::expected<void, error_t>{};
  }

  http::request_t build_request(const std::string &method, const std::string &name, std::span<const uint8_t> payload, const io_range_t *range) const override
  {
    std::string amz_date, date_stamp, rfc1123;
    utc_now(amz_date, date_stamp, rfc1123);

    std::string key = _cfg.prefix.empty() ? name : (_cfg.prefix + "/" + name);

    std::string canonical_uri;
    std::string url_host;
    if (_cfg.path_style)
    {
      canonical_uri = "/" + uri_encode(_cfg.bucket, false) + "/" + uri_encode(key, true);
      url_host = _cfg.host;
    }
    else
    {
      canonical_uri = "/" + uri_encode(key, true);
      url_host = _cfg.bucket + "." + _cfg.host;
    }

    std::string host_value = host_header(_cfg.https, url_host, _cfg.port);
    std::string url = (_cfg.https ? "https://" : "http://") + host_value + canonical_uri;

    http::request_t req;
    req.method = method;
    req.url = std::move(url);
    req.allow_plaintext = _allow_plaintext;
    req.ca_mem = _ca_mem;
    // Host and Content-Length are added by vio::http::fetch; do not duplicate them here.
    if (range && range->size >= 0 && method == "GET")
      req.headers.push_back({"Range", "bytes=" + std::to_string(range->offset) + "-" + std::to_string(range->offset + range->size - 1)});

    // Anonymous access to a public bucket: with no credentials, send an UNSIGNED request. A SigV4 signature
    // computed from an empty access key would be rejected by S3 even for a public object; omitting the
    // Authorization header lets S3 serve objects that a bucket policy has made publicly readable.
    if (_current.access_key.empty() || _current.secret_key.empty())
      return req;

    // Signed (AWS Signature Version 4). The credential material comes from _current (kept fresh by
    // ensure_credentials); the endpoint / region / addressing come from _cfg.
    std::string payload_sha = crypto::to_hex(crypto::sha256(payload));
    std::vector<signed_header_t> signed_headers = {{"host", host_value}, {"x-amz-content-sha256", payload_sha}, {"x-amz-date", amz_date}};
    // STS temporary credentials require x-amz-security-token to be a *signed* header (and sent on the wire).
    // aws_sigv4_authorization lowercases + sorts the header list, so append order is irrelevant.
    if (!_current.session_token.empty())
      signed_headers.push_back({"x-amz-security-token", _current.session_token});
    std::string authorization = aws_sigv4_authorization(method, canonical_uri, "", signed_headers, payload_sha, _current.access_key, _current.secret_key, _cfg.region, "s3", amz_date, date_stamp);
    req.headers.push_back({"x-amz-date", amz_date});
    req.headers.push_back({"x-amz-content-sha256", payload_sha});
    if (!_current.session_token.empty())
      req.headers.push_back({"x-amz-security-token", _current.session_token});
    req.headers.push_back({"Authorization", authorization});
    return req;
  }

private:
  config_t _cfg;
  std::shared_ptr<credentials_provider_t> _provider; // null => sign with the static _current credentials
  credentials_t _current;                            // the credentials build_request signs with
};

} // namespace vio::objstore
