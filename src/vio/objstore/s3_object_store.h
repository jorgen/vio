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
#include <vio/objstore/http_object_store.h>
#include <vio/objstore/signing.h>

#include <cstdint>
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
  };

  s3_io_manager_t(event_loop_t &loop, config_t cfg)
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

    std::string payload_sha = crypto::to_hex(crypto::sha256(payload));

    std::vector<signed_header_t> signed_headers = {{"host", host_value}, {"x-amz-content-sha256", payload_sha}, {"x-amz-date", amz_date}};
    // STS temporary credentials require x-amz-security-token to be a *signed* header (and sent on the
    // wire). aws_sigv4_authorization lowercases + sorts the header list, so append order is irrelevant.
    if (!_cfg.session_token.empty())
      signed_headers.push_back({"x-amz-security-token", _cfg.session_token});
    std::string authorization = aws_sigv4_authorization(method, canonical_uri, "", signed_headers, payload_sha, _cfg.access_key, _cfg.secret_key, _cfg.region, "s3", amz_date, date_stamp);

    http::request_t req;
    req.method = method;
    req.url = std::move(url);
    req.allow_plaintext = _allow_plaintext;
    req.ca_mem = _ca_mem;
    // Host and Content-Length are added by vio::http::fetch; do not duplicate them here.
    req.headers.push_back({"x-amz-date", amz_date});
    req.headers.push_back({"x-amz-content-sha256", payload_sha});
    if (!_cfg.session_token.empty())
      req.headers.push_back({"x-amz-security-token", _cfg.session_token});
    req.headers.push_back({"Authorization", authorization});
    if (range && range->size >= 0 && method == "GET")
      req.headers.push_back({"Range", "bytes=" + std::to_string(range->offset) + "-" + std::to_string(range->offset + range->size - 1)});
    return req;
  }

private:
  config_t _cfg;
};

} // namespace vio::objstore
