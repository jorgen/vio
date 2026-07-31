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
#ifndef __EMSCRIPTEN__
#include <vio/objstore/http_cache.h>
#endif

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

#ifndef __EMSCRIPTEN__
// Process-global default HTTP cache. When installed, every http_io_manager created afterwards uses it for
// GET responses unless it is given a different one via set_cache(). The application owns the http_cache_t
// (it must outlive the io_managers); vio never writes to disk unless the app opts in by installing one.
inline http_cache_t *&default_http_cache()
{
  static http_cache_t *cache = nullptr;
  return cache;
}
inline void set_default_http_cache(http_cache_t *cache)
{
  default_http_cache() = cache;
}
#endif

// Common HTTP object-store machinery for the S3 and Azure backends: the four io_manager operations as
// GET / PUT / HEAD / DELETE over vio::http::fetch, plus response/status handling. Providers supply a
// fully-signed request via build_request().
class http_io_manager_t : public io_manager_t
{
public:
  explicit http_io_manager_t(event_loop_t &loop)
    : _loop(loop)
  {
#ifndef __EMSCRIPTEN__
    _cache = default_http_cache();
#endif
  }

#ifndef __EMSCRIPTEN__
  // Override the HTTP cache for this store (nullptr disables caching). Defaults to the process-global cache.
  void set_cache(http_cache_t *cache)
  {
    _cache = cache;
  }
#endif

  task_t<std::expected<uint64_t, error_t>> read_object(std::string name, uint8_t *dst, io_range_t range) override
  {
    if (auto creds = co_await ensure_credentials(); !creds)
      co_return std::unexpected(creds.error());
    auto req = build_request("GET", name, std::span<const uint8_t>{}, &range);
    auto resp = co_await do_fetch(req);
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

  task_t<std::expected<uint64_t, error_t>> read_object_all(std::string name, uint8_t *dst, uint64_t capacity) override
  {
    if (auto creds = co_await ensure_credentials(); !creds)
      co_return std::unexpected(creds.error());
    auto req = build_request("GET", name, std::span<const uint8_t>{}, nullptr); // never a Range header
    auto resp = co_await do_fetch(req);
    if (!resp.has_value())
      co_return std::unexpected(resp.error());
    if (resp->status != 200 && resp->status != 206)
      co_return std::unexpected(http_error(resp->status, "read_object_all " + name, resp->body));
    if (resp->body.size() > capacity)
      co_return std::unexpected(error_t{.code = 1, .msg = "Object larger than caller buffer: " + name});
    if (!resp->body.empty())
      memcpy(dst, resp->body.data(), resp->body.size());
    co_return uint64_t(resp->body.size());
  }

  task_t<std::expected<void, error_t>> write_object(std::string name, std::shared_ptr<uint8_t[]> data, uint64_t size) override
  {
    if (auto creds = co_await ensure_credentials(); !creds)
      co_return std::unexpected(creds.error());
    std::span<const uint8_t> payload(data.get(), size);
    auto req = build_request("PUT", name, payload, nullptr);
    req.body.assign(reinterpret_cast<const char *>(data.get()), size);
    auto resp = co_await do_fetch(req);
    if (!resp.has_value())
      co_return std::unexpected(resp.error());
    if (resp->status != 200 && resp->status != 201)
      co_return std::unexpected(http_error(resp->status, "write_object " + name, resp->body));
    co_return {};
  }

  task_t<std::expected<object_info_t, error_t>> object_info(std::string name) override
  {
    if (auto creds = co_await ensure_credentials(); !creds)
      co_return std::unexpected(creds.error());
    auto req = build_request("HEAD", name, std::span<const uint8_t>{}, nullptr);
    auto resp = co_await do_fetch(req);
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
    if (auto creds = co_await ensure_credentials(); !creds)
      co_return std::unexpected(creds.error());
    auto req = build_request("DELETE", name, std::span<const uint8_t>{}, nullptr);
    auto resp = co_await do_fetch(req);
    if (!resp.has_value())
      co_return std::unexpected(resp.error());
    // Idempotent: a missing object (404/410) is success, as are 200/202/204.
    if (resp->status == 200 || resp->status == 202 || resp->status == 204 || resp->status == 404 || resp->status == 410)
      co_return {};
    co_return std::unexpected(http_error(resp->status, "remove_object " + name, resp->body));
  }

protected:
  // Single choke point for all four ops. On native it reuses a per-store keep-alive connection pool; on
  // wasm the browser owns connection reuse, so it forwards to the emscripten_fetch path unchanged.
  task_t<std::expected<http::response_t, error_t>> do_fetch(const http::request_t &req)
  {
#ifndef __EMSCRIPTEN__
    // GET responses go through the on-disk HTTP cache (browser semantics): a fresh entry is served without
    // touching the network; a stale one is revalidated with a conditional GET (a 304 refreshes it for free).
    // Non-GET ops and the no-cache configuration fall straight through to the keep-alive fetch.
    if (_cache && req.method == "GET")
    {
      std::string range;
      for (const auto &h : req.headers)
        if (http::detail::header_name_equals(h.name, "Range"))
          range = h.value;

      auto hit = _cache->lookup(req.url, range);
      if (hit.state == http_cache_t::state_t::fresh)
        co_return std::move(hit.response);

      http::request_t r = req;
      if (hit.state == http_cache_t::state_t::stale)
      {
        if (!hit.etag.empty())
          r.headers.push_back(http::header_t{"If-None-Match", hit.etag});
        if (!hit.last_modified.empty())
          r.headers.push_back(http::header_t{"If-Modified-Since", hit.last_modified});
      }

      auto resp = co_await http::fetch(_loop, r, nullptr, &_pool);
      if (resp.has_value())
      {
        if (resp->status == 304)
        {
          if (auto served = _cache->note_not_modified(req.url, range, *resp))
            co_return std::move(*served); // revalidated: serve the stored body as 200
        }
        else
        {
          _cache->store(req.url, range, *resp, req.cache_immutable);
        }
      }
      co_return resp;
    }
    co_return co_await http::fetch(_loop, req, nullptr, &_pool);
#else
    co_return co_await http::fetch(_loop, req, nullptr);
#endif
  }

  // Build and sign the request for the given op. `payload` is the exact body (empty for GET/HEAD/DELETE);
  // `range` is non-null only for a ranged GET. Sets url/method/headers/body and, from the members below,
  // allow_plaintext and ca_mem.
  virtual http::request_t build_request(const std::string &method, const std::string &name, std::span<const uint8_t> payload, const io_range_t *range) const = 0;

  // Refresh the credentials build_request will sign with, if they are temporary and near expiry. Called
  // once before build_request in each of the four operations above. The default does nothing (static
  // credentials, and Azure, which does not use this path); the S3 backend overrides it to consult its
  // credentials provider. Returning an error fails the operation (e.g. an expired `aws login` session).
  virtual task_t<std::expected<void, error_t>> ensure_credentials()
  {
    co_return std::expected<void, error_t>{};
  }

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
#ifndef __EMSCRIPTEN__
  // Per-store, per-loop keep-alive pool reused across all four ops (native transport only; the browser
  // build lets emscripten_fetch handle connection reuse). Declared last so it is torn down first.
  http::connection_pool_t _pool;
  http_cache_t *_cache = nullptr; // shared, app-owned HTTP cache (nullptr => no caching)
#endif

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
