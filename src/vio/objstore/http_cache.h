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

// A persistent, on-disk HTTP response cache modelled on a browser's: entries are kept fresh via
// Cache-Control (max-age / immutable / no-store / no-cache), Expires, or -- when the origin advertises
// neither, as S3 does -- a Last-Modified heuristic (10% of the resource's age). Stale entries are
// revalidated with a conditional GET (If-None-Match / If-Modified-Since); a 304 refreshes the stored copy
// with no body transfer. The store is bounded by a byte budget with LRU eviction. Location and size are
// configurable with browser-like defaults (OS cache dir, 1 GiB), overridable via the environment.
//
// Native only: the browser build has its own HTTP cache, so this whole header is compiled out there.

#ifndef __EMSCRIPTEN__

#include <vio/operation/http_client.h> // response_t, request_t, header_t, detail::header_name_equals

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace vio::objstore
{

struct http_cache_config_t
{
  std::string directory;  // empty => default_http_cache_dir()
  uint64_t max_bytes = 0; // 0 => default (1 GiB)
};

namespace cache_detail
{
inline std::string getenv_str(const char *name)
{
  const char *v = std::getenv(name);
  return v ? std::string(v) : std::string();
}

// OS-appropriate default cache directory, honoring VIO_HTTP_CACHE_DIR first.
inline std::string default_dir()
{
  if (auto e = getenv_str("VIO_HTTP_CACHE_DIR"); !e.empty())
    return e;
#if defined(_WIN32)
  std::string base = getenv_str("LOCALAPPDATA");
  if (base.empty())
    base = getenv_str("TEMP");
  return base + "\\vio\\http";
#elif defined(__APPLE__)
  std::string home = getenv_str("HOME");
  return home + "/Library/Caches/vio/http";
#else
  std::string base = getenv_str("XDG_CACHE_HOME");
  if (base.empty())
    base = getenv_str("HOME") + "/.cache";
  return base + "/vio/http";
#endif
}

inline uint64_t default_max_bytes()
{
  if (auto e = getenv_str("VIO_HTTP_CACHE_MAX_BYTES"); !e.empty())
  {
    uint64_t v = std::strtoull(e.c_str(), nullptr, 10);
    if (v > 0)
      return v;
  }
  return uint64_t(1) << 30; // 1 GiB
}

inline uint64_t now_unix()
{
  return uint64_t(::time(nullptr));
}

// 64-bit FNV-1a; used only to derive an on-disk filename from a cache key (the full key is stored in the
// entry metadata, and the in-memory index is keyed by the full key, so a hash collision cannot cause a
// wrong hit -- at worst two keys would contend for one filename, which is astronomically unlikely at 64 bits).
inline uint64_t fnv1a(std::string_view s)
{
  uint64_t h = 1469598103934665603ull;
  for (unsigned char c : s)
  {
    h ^= c;
    h *= 1099511628211ull;
  }
  return h;
}

inline std::string to_hex(uint64_t v)
{
  static const char *d = "0123456789abcdef";
  std::string out(16, '0');
  for (int i = 15; i >= 0; --i)
  {
    out[i] = d[v & 0xf];
    v >>= 4;
  }
  return out;
}

// Parse an RFC 1123 HTTP-date ("Sun, 06 Nov 1994 08:49:37 GMT") to a unix timestamp. Returns nullopt on a
// format we don't recognise (RFC 850 / asctime are rare for these headers and treated as unparseable).
inline std::optional<uint64_t> parse_http_date(std::string_view s)
{
  // Skip the leading weekday and comma/space: find the first space.
  auto sp = s.find(' ');
  if (sp == std::string_view::npos)
    return std::nullopt;
  s.remove_prefix(sp + 1);
  int day = 0, year = 0, hour = 0, min = 0, sec = 0;
  char mon[4] = {0, 0, 0, 0};
  // "06 Nov 1994 08:49:37"
  if (std::sscanf(std::string(s).c_str(), "%d %3s %d %d:%d:%d", &day, mon, &year, &hour, &min, &sec) != 6)
    return std::nullopt;
  static const char *months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
  int m = -1;
  for (int i = 0; i < 12; ++i)
    if (std::string_view(mon) == months[i])
    {
      m = i;
      break;
    }
  if (m < 0)
    return std::nullopt;
  std::tm tm{};
  tm.tm_mday = day;
  tm.tm_mon = m;
  tm.tm_year = year - 1900;
  tm.tm_hour = hour;
  tm.tm_min = min;
  tm.tm_sec = sec;
#if defined(_WIN32)
  time_t t = _mkgmtime(&tm);
#else
  time_t t = timegm(&tm);
#endif
  if (t < 0)
    return std::nullopt;
  return uint64_t(t);
}

struct cache_control_t
{
  bool no_store = false;
  bool no_cache = false;
  bool immutable = false;
  long long max_age = -1; // -1 => absent
};

inline cache_control_t parse_cache_control(std::string_view v)
{
  cache_control_t cc;
  size_t pos = 0;
  while (pos < v.size())
  {
    size_t comma = v.find(',', pos);
    std::string_view tok = v.substr(pos, comma == std::string_view::npos ? std::string_view::npos : comma - pos);
    pos = (comma == std::string_view::npos) ? v.size() : comma + 1;
    while (!tok.empty() && (tok.front() == ' ' || tok.front() == '\t'))
      tok.remove_prefix(1);
    while (!tok.empty() && (tok.back() == ' ' || tok.back() == '\t'))
      tok.remove_suffix(1);
    if (http::detail::header_name_equals(tok, "no-store"))
      cc.no_store = true;
    else if (http::detail::header_name_equals(tok, "no-cache"))
      cc.no_cache = true;
    else if (http::detail::header_name_equals(tok, "immutable"))
      cc.immutable = true;
    else if (tok.size() > 8 && http::detail::header_name_equals(tok.substr(0, 8), "max-age="))
      cc.max_age = std::atoll(std::string(tok.substr(8)).c_str());
  }
  return cc;
}
} // namespace cache_detail

// Persistent on-disk HTTP cache. Thread-safe (an internal mutex guards the index), so a single instance may
// back several io_managers on different event loops. Disk I/O is synchronous; a local cache read replaces a
// network round-trip, so this is a large net win, but it does briefly occupy the calling loop thread.
class http_cache_t
{
public:
  explicit http_cache_t(http_cache_config_t cfg = {})
    : _cfg(std::move(cfg))
  {
    if (_cfg.directory.empty())
      _cfg.directory = cache_detail::default_dir();
    if (_cfg.max_bytes == 0)
      _cfg.max_bytes = cache_detail::default_max_bytes();
    std::error_code ec;
    std::filesystem::create_directories(_cfg.directory, ec);
    load_index();
  }

  enum class state_t
  {
    miss,
    fresh,
    stale
  };

  struct lookup_t
  {
    state_t state = state_t::miss;
    http::response_t response;  // populated when state == fresh
    std::string etag;           // validators for a conditional revalidation when state == stale
    std::string last_modified;
  };

  // GET-path lookup. `range` is the request's Range header value ("" when absent) -- it is part of the key
  // so distinct byte ranges of the same URL never alias.
  lookup_t lookup(const std::string &url, const std::string &range)
  {
    const std::string key = key_of(url, range);
    std::lock_guard<std::mutex> lock(_mutex);
    auto it = _entries.find(key);
    if (it == _entries.end())
      return {};
    entry_t &e = it->second;
    e.last_access = cache_detail::now_unix();

    if (cache_detail::now_unix() < e.fresh_until)
    {
      std::string body;
      if (!load_body(key, body) || body.size() != e.body_size)
      {
        drop_locked(it); // body vanished/corrupt -> treat as a miss
        return {};
      }
      lookup_t out;
      out.state = state_t::fresh;
      out.response = to_response(e, std::move(body));
      return out;
    }

    lookup_t out;
    out.state = state_t::stale;
    out.etag = e.etag;
    out.last_modified = e.last_modified;
    return out;
  }

  // A conditional revalidation returned 304 Not Modified: refresh the stored entry's freshness from the 304
  // headers and return the stored body as a synthesized 200 response. nullopt if the entry disappeared.
  std::optional<http::response_t> note_not_modified(const std::string &url, const std::string &range, const http::response_t &resp304)
  {
    const std::string key = key_of(url, range);
    std::lock_guard<std::mutex> lock(_mutex);
    auto it = _entries.find(key);
    if (it == _entries.end())
      return std::nullopt;
    entry_t &e = it->second;
    std::string body;
    if (!load_body(key, body) || body.size() != e.body_size)
    {
      drop_locked(it);
      return std::nullopt;
    }
    const uint64_t now = cache_detail::now_unix();
    e.stored = now;
    e.last_access = now;
    e.fresh_until = compute_fresh_until(resp304, now, e.immutable, e.last_modified);
    write_meta(e); // persist the refreshed freshness
    return to_response(e, std::move(body));
  }

  // A GET returned 200/206: store it if cacheable. `request_immutable` forces the entry to never revalidate
  // (the caller asserts the resource is content-immutable, e.g. a content-addressed object).
  void store(const std::string &url, const std::string &range, const http::response_t &resp, bool request_immutable)
  {
    if (resp.status != 200 && resp.status != 206)
      return;
    const auto cc = cache_detail::parse_cache_control(resp.header("Cache-Control"));
    if (cc.no_store)
      return;

    const std::string key = key_of(url, range);
    entry_t e;
    e.key = key;
    e.status = resp.status;
    e.stored = cache_detail::now_unix();
    e.last_access = e.stored;
    e.immutable = request_immutable || cc.immutable;
    e.etag = std::string(resp.header("ETag"));
    e.last_modified = std::string(resp.header("Last-Modified"));
    e.content_type = std::string(resp.header("Content-Type"));
    e.body_size = resp.body.size();
    e.fresh_until = compute_fresh_until(resp, e.stored, e.immutable, e.last_modified);

    std::lock_guard<std::mutex> lock(_mutex);
    if (!write_body(key, resp.body))
      return;
    write_meta(e);
    auto [it, inserted] = _entries.insert_or_assign(key, e);
    (void)it;
    if (inserted)
      _total_bytes += e.body_size;
    else
      recompute_total_locked();
    evict_locked();
  }

  [[nodiscard]] uint64_t total_bytes() const
  {
    return _total_bytes;
  }
  [[nodiscard]] const std::string &directory() const
  {
    return _cfg.directory;
  }

private:
  struct entry_t
  {
    std::string key;
    int status = 0;
    uint64_t stored = 0;
    uint64_t fresh_until = 0;
    bool immutable = false;
    std::string etag;
    std::string last_modified;
    std::string content_type;
    uint64_t body_size = 0;
    uint64_t last_access = 0;
  };

  static std::string key_of(const std::string &url, const std::string &range)
  {
    return range.empty() ? ("GET " + url) : ("GET " + url + " R:" + range);
  }
  std::string base_path(const std::string &key) const
  {
    return _cfg.directory + "/" + cache_detail::to_hex(cache_detail::fnv1a(key));
  }

  static uint64_t compute_fresh_until(const http::response_t &resp, uint64_t now, bool immutable, const std::string &fallback_last_modified)
  {
    if (immutable)
      return now + (uint64_t(10) * 365 * 24 * 3600); // effectively forever
    const auto cc = cache_detail::parse_cache_control(resp.header("Cache-Control"));
    if (cc.immutable)
      return now + (uint64_t(10) * 365 * 24 * 3600);
    if (cc.no_cache)
      return now; // must revalidate every time, but the body is kept for cheap 304s
    if (cc.max_age >= 0)
      return now + uint64_t(cc.max_age);
    if (auto exp = cache_detail::parse_http_date(resp.header("Expires")))
      return *exp;
    // Heuristic freshness (RFC 9111 4.2.2): 10% of the resource's age at store time. This is what makes an
    // old, Cache-Control-less S3 object cache for a long time without an explicit hint.
    std::string lm = std::string(resp.header("Last-Modified"));
    if (lm.empty())
      lm = fallback_last_modified;
    if (auto lmt = cache_detail::parse_http_date(lm); lmt && *lmt <= now)
    {
      uint64_t age = now - *lmt;
      uint64_t heuristic = age / 10;
      const uint64_t cap = uint64_t(365) * 24 * 3600; // cap heuristic freshness at one year
      if (heuristic > cap)
        heuristic = cap;
      return now + heuristic;
    }
    return now; // no freshness information -> always revalidate
  }

  http::response_t to_response(const entry_t &e, std::string body) const
  {
    http::response_t r;
    r.status = e.status;
    if (!e.content_type.empty())
      r.headers.push_back(http::header_t{"Content-Type", e.content_type});
    if (!e.etag.empty())
      r.headers.push_back(http::header_t{"ETag", e.etag});
    if (!e.last_modified.empty())
      r.headers.push_back(http::header_t{"Last-Modified", e.last_modified});
    r.headers.push_back(http::header_t{"Content-Length", std::to_string(body.size())});
    r.body = std::move(body);
    return r;
  }

  bool load_body(const std::string &key, std::string &out) const
  {
    std::ifstream f(base_path(key) + ".body", std::ios::binary);
    if (!f)
      return false;
    std::ostringstream ss;
    ss << f.rdbuf();
    out = ss.str();
    return true;
  }

  bool write_body(const std::string &key, const std::string &body) const
  {
    std::ofstream f(base_path(key) + ".body", std::ios::binary | std::ios::trunc);
    if (!f)
      return false;
    f.write(body.data(), std::streamsize(body.size()));
    return bool(f);
  }

  // Metadata sidecar: one "name=value" per line. Values (url/etag/dates) never contain a newline.
  void write_meta(const entry_t &e) const
  {
    std::ofstream f(base_path(e.key) + ".meta", std::ios::binary | std::ios::trunc);
    if (!f)
      return;
    f << "vio-http-cache/1\n";
    f << "key=" << e.key << "\n";
    f << "status=" << e.status << "\n";
    f << "stored=" << e.stored << "\n";
    f << "fresh_until=" << e.fresh_until << "\n";
    f << "immutable=" << (e.immutable ? 1 : 0) << "\n";
    f << "size=" << e.body_size << "\n";
    f << "last_access=" << e.last_access << "\n";
    f << "etag=" << e.etag << "\n";
    f << "last_modified=" << e.last_modified << "\n";
    f << "content_type=" << e.content_type << "\n";
  }

  static bool parse_meta(const std::string &path, entry_t &e)
  {
    std::ifstream f(path, std::ios::binary);
    if (!f)
      return false;
    std::string line;
    if (!std::getline(f, line) || line != "vio-http-cache/1")
      return false;
    while (std::getline(f, line))
    {
      auto eq = line.find('=');
      if (eq == std::string::npos)
        continue;
      std::string k = line.substr(0, eq);
      std::string v = line.substr(eq + 1);
      if (k == "key")
        e.key = v;
      else if (k == "status")
        e.status = std::atoi(v.c_str());
      else if (k == "stored")
        e.stored = std::strtoull(v.c_str(), nullptr, 10);
      else if (k == "fresh_until")
        e.fresh_until = std::strtoull(v.c_str(), nullptr, 10);
      else if (k == "immutable")
        e.immutable = v == "1";
      else if (k == "size")
        e.body_size = std::strtoull(v.c_str(), nullptr, 10);
      else if (k == "last_access")
        e.last_access = std::strtoull(v.c_str(), nullptr, 10);
      else if (k == "etag")
        e.etag = v;
      else if (k == "last_modified")
        e.last_modified = v;
      else if (k == "content_type")
        e.content_type = v;
    }
    return !e.key.empty();
  }

  void load_index()
  {
    std::error_code ec;
    std::lock_guard<std::mutex> lock(_mutex);
    _entries.clear();
    _total_bytes = 0;
    for (std::filesystem::directory_iterator it(_cfg.directory, ec), end; !ec && it != end; it.increment(ec))
    {
      if (it->path().extension() != ".meta")
        continue;
      entry_t e;
      if (!parse_meta(it->path().string(), e))
        continue;
      // Drop an index entry whose body is missing or the wrong size.
      std::error_code se;
      auto bsize = std::filesystem::file_size(base_path(e.key) + ".body", se);
      if (se || bsize != e.body_size)
        continue;
      _total_bytes += e.body_size;
      _entries.emplace(e.key, std::move(e));
    }
    evict_locked();
  }

  void drop_locked(std::unordered_map<std::string, entry_t>::iterator it)
  {
    std::error_code ec;
    std::filesystem::remove(base_path(it->second.key) + ".body", ec);
    std::filesystem::remove(base_path(it->second.key) + ".meta", ec);
    if (_total_bytes >= it->second.body_size)
      _total_bytes -= it->second.body_size;
    _entries.erase(it);
  }

  void recompute_total_locked()
  {
    _total_bytes = 0;
    for (auto &kv : _entries)
      _total_bytes += kv.second.body_size;
  }

  void evict_locked()
  {
    while (_total_bytes > _cfg.max_bytes && !_entries.empty())
    {
      auto victim = _entries.begin();
      for (auto it = _entries.begin(); it != _entries.end(); ++it)
        if (it->second.last_access < victim->second.last_access)
          victim = it;
      drop_locked(victim);
    }
  }

  http_cache_config_t _cfg;
  std::mutex _mutex;
  std::unordered_map<std::string, entry_t> _entries;
  uint64_t _total_bytes = 0;
};

} // namespace vio::objstore

#endif // !__EMSCRIPTEN__
