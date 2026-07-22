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

#include <vio/objstore/object_store.h>
#include <vio/operation/http_client.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace vio::objstore
{

// Common HTTP object-store machinery for the S3 and Azure backends: the four io_manager operations as
// GET / PUT / HEAD / DELETE over vio::http::fetch, plus response/status handling. Providers supply a
// fully-signed request via build_request().
class http_io_manager_t : public io_manager_t
{
public:
  explicit http_io_manager_t(event_loop_t &loop)
    : _loop(loop)
  {
  }

  task_t<std::expected<uint64_t, error_t>> read_object(std::string name, uint8_t *dst, io_range_t range) override
  {
    auto req = build_request("GET", name, std::span<const uint8_t>{}, &range);
    auto resp = co_await http::fetch(_loop, req);
    if (!resp.has_value())
      co_return std::unexpected(resp.error());
    if (resp->status != 200 && resp->status != 206)
      co_return std::unexpected(http_error(resp->status, "read_object " + name, resp->body));
    uint64_t want = range.size >= 0 ? uint64_t(range.size) : resp->body.size();
    uint64_t n = resp->body.size() < want ? resp->body.size() : want;
    if (n > 0)
      memcpy(dst, resp->body.data(), n);
    co_return n;
  }

  task_t<std::expected<void, error_t>> write_object(std::string name, std::shared_ptr<uint8_t[]> data, uint64_t size) override
  {
    std::span<const uint8_t> payload(data.get(), size);
    auto req = build_request("PUT", name, payload, nullptr);
    req.body.assign(reinterpret_cast<const char *>(data.get()), size);
    auto resp = co_await http::fetch(_loop, req);
    if (!resp.has_value())
      co_return std::unexpected(resp.error());
    if (resp->status != 200 && resp->status != 201)
      co_return std::unexpected(http_error(resp->status, "write_object " + name, resp->body));
    co_return {};
  }

  task_t<std::expected<object_info_t, error_t>> object_info(std::string name) override
  {
    auto req = build_request("HEAD", name, std::span<const uint8_t>{}, nullptr);
    auto resp = co_await http::fetch(_loop, req);
    if (!resp.has_value())
      co_return std::unexpected(resp.error());
    object_info_t out;
    if (resp->status == 404)
    {
      out.exists = false;
      co_return out;
    }
    if (resp->status != 200)
      co_return std::unexpected(http_error(resp->status, "object_info " + name, resp->body));
    out.exists = true;
    std::string cl(resp->header("content-length"));
    if (!cl.empty())
      out.size = std::strtoull(cl.c_str(), nullptr, 10);
    co_return out;
  }

  task_t<std::expected<void, error_t>> remove_object(std::string name) override
  {
    auto req = build_request("DELETE", name, std::span<const uint8_t>{}, nullptr);
    auto resp = co_await http::fetch(_loop, req);
    if (!resp.has_value())
      co_return std::unexpected(resp.error());
    // Idempotent: a missing object (404/410) is success, as are 200/202/204.
    if (resp->status == 200 || resp->status == 202 || resp->status == 204 || resp->status == 404 || resp->status == 410)
      co_return {};
    co_return std::unexpected(http_error(resp->status, "remove_object " + name, resp->body));
  }

protected:
  // Build and sign the request for the given op. `payload` is the exact body (empty for GET/HEAD/DELETE);
  // `range` is non-null only for a ranged GET. Sets url/method/headers/body and, from the members below,
  // allow_plaintext and ca_mem.
  virtual http::request_t build_request(const std::string &method, const std::string &name, std::span<const uint8_t> payload, const io_range_t *range) const = 0;

  // The Host header value vio::http::fetch will send for (scheme, host, port): host, plus ":port" only
  // when the port is non-default. Providers must sign this exact value.
  static std::string host_header(bool https, const std::string &host, uint16_t port)
  {
    uint16_t def = https ? 443 : 80;
    if (port == 0 || port == def)
      return host;
    return host + ":" + std::to_string(port);
  }

  // Current UTC time in the formats the providers need (numeric formats and RFC 1123 English names,
  // both locale-independent).
  static void utc_now(std::string &amz_date, std::string &date_stamp, std::string &rfc1123_date)
  {
    static const char *days[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
    static const char *months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    time_t t = time(nullptr);
    struct tm g;
#ifdef _WIN32
    gmtime_s(&g, &t);
#else
    gmtime_r(&t, &g);
#endif
    char buf[64];
    snprintf(buf, sizeof(buf), "%04d%02d%02dT%02d%02d%02dZ", g.tm_year + 1900, g.tm_mon + 1, g.tm_mday, g.tm_hour, g.tm_min, g.tm_sec);
    amz_date = buf;
    snprintf(buf, sizeof(buf), "%04d%02d%02d", g.tm_year + 1900, g.tm_mon + 1, g.tm_mday);
    date_stamp = buf;
    snprintf(buf, sizeof(buf), "%s, %02d %s %04d %02d:%02d:%02d GMT", days[g.tm_wday], g.tm_mday, months[g.tm_mon], g.tm_year + 1900, g.tm_hour, g.tm_min, g.tm_sec);
    rfc1123_date = buf;
  }

  event_loop_t &_loop;
  bool _allow_plaintext = false;              // permit http:// (e.g. a local minio/azurite over plain HTTP)
  std::optional<std::vector<uint8_t>> _ca_mem; // optional custom CA bundle for a private endpoint

private:
  static error_t http_error(int status, const std::string &op, const std::string &body)
  {
    error_t e;
    e.code = -1;
    std::string snippet = body.substr(0, 400);
    e.msg = op + " failed: HTTP " + std::to_string(status) + (snippet.empty() ? "" : (" " + snippet));
    return e;
  }
};

} // namespace vio::objstore
