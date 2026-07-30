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

#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include <vio/cancellation.h>
#include <vio/error.h>
#include <vio/event_loop.h>
#include <vio/task.h>

// The native transport is libuv TCP + LibreSSL TLS (with ada for URL parsing). In the browser build
// these are unavailable and unwanted; the transport is provided by emscripten_fetch instead (see the
// #ifdef __EMSCRIPTEN__ block at the bottom of this header).
#ifndef __EMSCRIPTEN__
#include <ada.h>

#include <vio/operation/dns.h>
#include <vio/operation/tcp.h>
#include <vio/operation/tls_client.h>
#endif

namespace vio::http
{

struct header_t
{
  std::string name;
  std::string value;
};

namespace detail
{
inline bool header_name_equals(std::string_view a, std::string_view b)
{
  if (a.size() != b.size())
    return false;
  for (std::size_t i = 0; i < a.size(); ++i)
  {
    if (std::tolower(static_cast<unsigned char>(a[i])) != std::tolower(static_cast<unsigned char>(b[i])))
      return false;
  }
  return true;
}
} // namespace detail

struct request_t
{
  std::string method = "GET";
  std::string url;
  std::vector<header_t> headers;
  std::string body;
  int max_redirects = 0;        // 0 = do not follow redirects (the default single-shot behaviour)
  bool allow_plaintext = false; // opt-in: permit http:// (plain HTTP is refused by default)
  bool cache_immutable = false; // hint to an http_cache_t: treat this resource as content-immutable (never
                                // revalidate). For content-addressed objects the caller knows can't change.
  // Verify the https peer against this PEM CA bundle instead of the system trust
  // store (e.g. a private/test ACME CA like Pebble). Unset => the default bundle.
  std::optional<std::vector<uint8_t>> ca_mem;
};

struct response_t
{
  int status = 0;
  std::vector<header_t> headers;
  std::string body;

  [[nodiscard]] std::string_view header(std::string_view name) const
  {
    for (const auto &h : headers)
    {
      if (detail::header_name_equals(h.name, name))
        return h.value;
    }
    return {};
  }
};

#ifndef __EMSCRIPTEN__
namespace detail
{
inline std::expected<response_t, error_t> parse_response(const std::string &raw)
{
  auto header_end = raw.find("\r\n\r\n");
  if (header_end == std::string::npos)
    return std::unexpected(error_t{.code = -1, .msg = "http: no header terminator"});

  std::string_view header_section(raw.data(), header_end);
  std::string raw_body = raw.substr(header_end + 4);

  response_t response;
  auto first_line_end = header_section.find("\r\n");
  std::string_view status_line = header_section.substr(0, first_line_end);
  auto sp1 = status_line.find(' ');
  if (sp1 == std::string_view::npos)
    return std::unexpected(error_t{.code = -1, .msg = "http: malformed status line"});
  auto sp2 = status_line.find(' ', sp1 + 1);
  auto count = (sp2 == std::string_view::npos) ? std::string_view::npos : sp2 - sp1 - 1;
  response.status = std::atoi(std::string(status_line.substr(sp1 + 1, count)).c_str());

  std::string_view remaining = (first_line_end == std::string_view::npos) ? std::string_view{} : header_section.substr(first_line_end + 2);
  while (!remaining.empty())
  {
    auto line_end = remaining.find("\r\n");
    std::string_view line = remaining.substr(0, line_end);
    if (auto colon = line.find(':'); colon != std::string_view::npos)
    {
      std::string_view key = line.substr(0, colon);
      std::string_view val = line.substr(colon + 1);
      while (!val.empty() && (val.front() == ' ' || val.front() == '\t'))
        val.remove_prefix(1);
      response.headers.push_back(header_t{std::string(key), std::string(val)});
    }
    if (line_end == std::string_view::npos)
      break;
    remaining = remaining.substr(line_end + 2);
  }

  if (header_name_equals(response.header("Transfer-Encoding"), "chunked"))
  {
    std::string decoded;
    std::string_view src = raw_body;
    while (!src.empty())
    {
      auto nl = src.find("\r\n");
      if (nl == std::string_view::npos)
        break;
      auto chunk_size = std::strtoul(std::string(src.substr(0, nl)).c_str(), nullptr, 16);
      src = src.substr(nl + 2);
      if (chunk_size == 0)
        break;
      if (src.size() < chunk_size)
        break;
      decoded.append(src.data(), chunk_size);
      src = src.substr(chunk_size);
      if (src.starts_with("\r\n"))
        src = src.substr(2);
    }
    response.body = std::move(decoded);
  }
  else
  {
    response.body = std::move(raw_body);
  }

  return response;
}
// Minimal HTTP/1.1 response framing + a keep-alive connection pool. Reusing a connection requires stopping
// the read at the message boundary (Content-Length / chunked / empty-body status) instead of at the peer's
// close, so these helpers frame the response and decide whether the connection is safe to keep.
struct frame_info_t
{
  int status = 0;
  bool http_1_1 = false;
  bool chunked = false;
  bool conn_close = false;       // response asked to close the connection
  long long content_length = -1; // -1 => header absent
};

inline frame_info_t parse_frame_info(std::string_view header_block)
{
  frame_info_t fi;
  auto eol = header_block.find("\r\n");
  std::string_view status_line = header_block.substr(0, eol == std::string_view::npos ? header_block.size() : eol);
  fi.http_1_1 = status_line.substr(0, 9) == "HTTP/1.1 ";
  if (auto sp = status_line.find(' '); sp != std::string_view::npos)
    fi.status = std::atoi(std::string(status_line.substr(sp + 1)).c_str());
  std::string_view rest = (eol == std::string_view::npos) ? std::string_view{} : header_block.substr(eol + 2);
  while (!rest.empty())
  {
    auto le = rest.find("\r\n");
    std::string_view line = rest.substr(0, le == std::string_view::npos ? rest.size() : le);
    if (auto c = line.find(':'); c != std::string_view::npos)
    {
      std::string_view k = line.substr(0, c);
      std::string_view v = line.substr(c + 1);
      while (!v.empty() && (v.front() == ' ' || v.front() == '\t'))
        v.remove_prefix(1);
      while (!v.empty() && (v.back() == ' ' || v.back() == '\t'))
        v.remove_suffix(1);
      if (header_name_equals(k, "Content-Length"))
        fi.content_length = std::atoll(std::string(v).c_str());
      else if (header_name_equals(k, "Transfer-Encoding") && header_name_equals(v, "chunked"))
        fi.chunked = true;
      else if (header_name_equals(k, "Connection") && header_name_equals(v, "close"))
        fi.conn_close = true;
    }
    if (le == std::string_view::npos)
      break;
    rest = rest.substr(le + 2);
  }
  return fi;
}

// Has the chunked body that starts at `body` reached its terminating 0-length chunk?
inline bool chunked_complete(std::string_view body)
{
  std::string_view s = body;
  while (!s.empty())
  {
    auto nl = s.find("\r\n");
    if (nl == std::string_view::npos)
      return false;
    unsigned long sz = std::strtoul(std::string(s.substr(0, nl)).c_str(), nullptr, 16);
    s = s.substr(nl + 2);
    if (sz == 0)
      return true; // last chunk seen (trailers ignored)
    if (s.size() < sz + 2)
      return false;
    s = s.substr(sz + 2);
  }
  return false;
}

inline bool is_stream_end(const error_t &e)
{
  return e.code == UV_EOF || e.code == vio_tls_clean_shutdown || e.code == vio_tls_truncated;
}

struct framed_response_t
{
  std::string raw;       // headers + body, trimmed to exactly the framed message when length-delimited
  bool complete = false; // a full response was read
  bool reusable = false; // the connection is safe to keep alive (self-delimited, no trailing bytes, keep-alive)
};

// Read one HTTP/1.1 response with correct message framing. Returns as soon as the body boundary is reached
// (Content-Length / chunked / empty-body status / HEAD) rather than waiting for the peer to close, so the
// connection can be pooled. Falls back to close-delimited (read-to-end) when no length is advertised.
template <typename Reader>
inline vio::task_t<std::expected<framed_response_t, error_t>> read_framed(Reader &reader, bool is_head)
{
  framed_response_t out;
  std::string &raw = out.raw;
  bool have_headers = false;
  std::size_t body_start = 0;
  frame_info_t fi;

  for (;;)
  {
    if (!have_headers)
    {
      if (auto he = raw.find("\r\n\r\n"); he != std::string::npos)
      {
        have_headers = true;
        body_start = he + 4;
        fi = parse_frame_info(std::string_view(raw).substr(0, he));
        if (is_head || fi.status == 204 || fi.status == 304)
          fi.content_length = 0;
      }
    }
    if (have_headers)
    {
      if (fi.chunked)
      {
        if (chunked_complete(std::string_view(raw).substr(body_start)))
        {
          out.complete = true;
          out.reusable = false; // conservative: never pool chunked responses
          co_return out;
        }
      }
      else if (fi.content_length >= 0)
      {
        const std::size_t want = body_start + static_cast<std::size_t>(fi.content_length);
        if (raw.size() >= want)
        {
          const bool overshoot = raw.size() > want;
          raw.resize(want); // hand parse_response exactly the framed message
          out.complete = true;
          out.reusable = fi.http_1_1 && !fi.conn_close && !overshoot;
          co_return out;
        }
      }
      // else: no length advertised -> close-delimited; fall through and read until the stream ends.
    }

    auto chunk = co_await reader;
    if (!chunk)
    {
      if (is_stream_end(chunk.error()) && have_headers && !fi.chunked && fi.content_length < 0)
      {
        out.complete = true; // close-delimited body ends here (legacy read-to-EOF)
        out.reusable = false;
        co_return out;
      }
      co_return std::unexpected(chunk.error()); // truncated or a transport error
    }
    raw.append(chunk.value().buf.base, chunk.value().buf.len);
  }
}
} // namespace detail

// A pooled, already-connected transport, kept alive between requests to the same origin. https uses `tls`,
// plaintext http uses `tcp`; exactly one is set.
struct pooled_connection_t
{
  std::string key;
  std::optional<ssl_client_t> tls;
  std::optional<tcp_t> tcp;
  uint64_t idle_since_ms = 0;
};

// Keep-alive connection pool for vio::http::fetch. Single event-loop / single-thread: every method runs
// inside a fetch coroutine on that loop's thread, so no locking is needed. It must outlive every fetch that
// uses it and every connection it hands out. Pass `&pool` as the last argument to fetch()/fetch_once() to
// enable keep-alive; omit it (or pass nullptr) for the legacy fresh-connection-per-request behaviour.
struct connection_pool_t
{
  connection_pool_t() = default;
  connection_pool_t(const connection_pool_t &) = delete;
  connection_pool_t &operator=(const connection_pool_t &) = delete;

  // Declared first => destroyed last, after any idle ssl_client_t whose SSL_CTX ex_data references it.
  ssl_session_cache_t session_cache;
  std::unordered_map<std::string, std::vector<pooled_connection_t>> idle;

  std::size_t max_idle_per_host = 8;
  uint64_t idle_timeout_ms = 30'000;

  // telemetry
  uint64_t reuses = 0;
  uint64_t creations = 0;
  uint64_t discards_stale = 0;

  static std::string make_key(std::string_view scheme, std::string_view host, std::uint16_t port)
  {
    std::string k;
    k.reserve(scheme.size() + host.size() + 8);
    k.append(scheme).append("://").append(host).append(":").append(std::to_string(port));
    return k;
  }

  // Pop a warm connection (LIFO) for `key`, discarding entries idle past the timeout. Fully synchronous
  // (no co_await between pick and remove) so two coroutines can never be handed the same connection.
  std::optional<pooled_connection_t> acquire(event_loop_t &loop, const std::string &key)
  {
    auto it = idle.find(key);
    if (it == idle.end())
      return std::nullopt;
    const uint64_t now = uv_now(loop.loop());
    auto &vec = it->second;
    while (!vec.empty())
    {
      pooled_connection_t c = std::move(vec.back());
      vec.pop_back();
      if (now - c.idle_since_ms > idle_timeout_ms)
        continue; // too old: let it drop (closes), try the next
      return c;
    }
    return std::nullopt;
  }

  void release(event_loop_t &loop, pooled_connection_t &&c)
  {
    auto &vec = idle[c.key];
    if (vec.size() >= max_idle_per_host)
      return; // over cap: drop -> connection closes on destruction
    c.idle_since_ms = uv_now(loop.loop());
    vec.push_back(std::move(c));
  }
};

// One request over a verified TLS (or opt-in plaintext) connection. With `pool == nullptr` this opens a
// fresh connection, sends Connection: close, and reads the whole response (legacy behaviour). With a pool
// it sends Connection: keep-alive, reuses a warm connection when available (retrying once on a fresh one if
// the pooled connection was stale), frames the response by Content-Length/chunked, and returns the
// connection to the pool when it is safe to reuse. No redirect following (see fetch below), no transparent
// decompression (Accept-Encoding: identity).
inline vio::task_t<std::expected<response_t, error_t>> fetch_once(event_loop_t &loop, const request_t &request, cancellation_t *cancel = nullptr, connection_pool_t *pool = nullptr)
{
  auto parsed = ada::parse<ada::url_aggregator>(request.url);
  if (!parsed)
    co_return std::unexpected(error_t{.code = -1, .msg = "http: invalid url"});
  const ada::url_aggregator &url = *parsed;

  const bool is_https = url.get_protocol() == "https:";
  const bool is_http = url.get_protocol() == "http:";
  if (!is_https && !(is_http && request.allow_plaintext))
    co_return std::unexpected(error_t{.code = -1, .msg = "http: only https is supported"});

  std::string host(url.get_hostname());
  std::string_view port_sv = url.get_port();
  const std::uint16_t default_port = is_https ? std::uint16_t{443} : std::uint16_t{80};
  std::uint16_t port = port_sv.empty() ? default_port : static_cast<std::uint16_t>(std::atoi(std::string(port_sv).c_str()));

  std::string target(url.get_pathname());
  if (target.empty())
    target = "/";
  target.append(url.get_search());

  std::string wire;
  wire.reserve(256 + request.body.size());
  wire.append(request.method).append(" ").append(target).append(" HTTP/1.1\r\n");
  wire.append("Host: ").append(host);
  if ((is_https && port != 443) || (is_http && port != 80))
    wire.append(":").append(std::to_string(port));
  wire.append("\r\n");
  wire.append("User-Agent: vio-http/0.1\r\n");
  wire.append("Accept-Encoding: identity\r\n");
  wire.append(pool ? "Connection: keep-alive\r\n" : "Connection: close\r\n");
  for (const auto &h : request.headers)
    wire.append(h.name).append(": ").append(h.value).append("\r\n");
  if (!request.body.empty())
    wire.append("Content-Length: ").append(std::to_string(request.body.size())).append("\r\n");
  wire.append("\r\n");
  wire.append(request.body);

  const std::string key = connection_pool_t::make_key(is_https ? "https" : "http", host, port);
  const bool is_head = request.method == "HEAD";

  std::optional<pooled_connection_t> pc;
  bool from_pool = false;
  if (pool)
  {
    pc = pool->acquire(loop, key);
    from_pool = pc.has_value();
  }

  for (int attempt = 0;; ++attempt)
  {
    // Establish a fresh connection unless we are reusing a warm one from the pool.
    if (!pc)
    {
      pooled_connection_t fresh;
      fresh.key = key;
      if (is_https)
      {
        ssl_config_t tls_config;
        if (request.ca_mem)
          tls_config.ca_mem = request.ca_mem;
        if (pool)
        {
          // Cross-connection TLS session resumption shortens even the fresh-connection handshake.
          tls_config.session_cache = &pool->session_cache;
          tls_config.enable_session_cache = true;
        }
        auto client = ssl_client_create(loop, tls_config);
        if (!client)
          co_return std::unexpected(client.error());
        auto connected = co_await ssl_client_connect(client.value(), host, port, cancel);
        if (!connected)
          co_return std::unexpected(connected.error());
        fresh.tls = std::move(client.value());
      }
      else
      {
        // Plaintext HTTP (opt-in): resolve the host, stamp the port onto the address, and drive a plain
        // TCP connection with the same request wire. Unreachable unless request.allow_plaintext was set.
        address_info_t hints;
        hints.socktype = SOCK_STREAM;
        auto resolved = co_await get_addrinfo(loop, host, hints, cancel);
        if (!resolved)
          co_return std::unexpected(resolved.error());
        if (resolved->empty())
          co_return std::unexpected(error_t{.code = -1, .msg = "http: host did not resolve"});
        sockaddr *sa = resolved->front().get_sockaddr();
        if (sa == nullptr)
          co_return std::unexpected(error_t{.code = -1, .msg = "http: no address for host"});
        if (sa->sa_family == AF_INET)
          reinterpret_cast<sockaddr_in *>(sa)->sin_port = htons(port);
        else if (sa->sa_family == AF_INET6)
          reinterpret_cast<sockaddr_in6 *>(sa)->sin6_port = htons(port);
        auto tcp = tcp_create(loop);
        if (!tcp)
          co_return std::unexpected(tcp.error());
        auto connected = co_await tcp_connect(tcp.value(), sa, cancel);
        if (!connected)
          co_return std::unexpected(connected.error());
        fresh.tcp = std::move(tcp.value());
      }
      pc = std::move(fresh);
      from_pool = false;
      if (pool)
        pool->creations++;
    }

    // Send the request and read exactly one framed response. The reader lives only inside this block, so
    // it is destroyed (reads disarmed) before the connection may be returned to the pool.
    std::optional<error_t> req_err;
    detail::framed_response_t framed;
    {
      uv_buf_t buf;
      buf.base = wire.data();
      buf.len = static_cast<decltype(buf.len)>(wire.size());
      if (pc->tls)
      {
        auto written = co_await ssl_client_write(pc->tls.value(), buf, cancel);
        if (!written)
          req_err = written.error();
        else if (auto rr = ssl_client_create_reader(pc->tls.value()); !rr)
          req_err = rr.error();
        else
        {
          auto reader = std::move(rr.value());
          auto fr = co_await detail::read_framed(reader, is_head);
          if (!fr)
            req_err = fr.error();
          else
            framed = std::move(fr.value());
        }
      }
      else
      {
        auto written = co_await write_tcp(pc->tcp.value(), reinterpret_cast<const uint8_t *>(wire.data()), wire.size(), cancel);
        if (!written)
          req_err = written.error();
        else if (auto rr = tcp_create_reader(pc->tcp.value()); !rr)
          req_err = rr.error();
        else
        {
          auto reader = std::move(rr.value());
          auto fr = co_await detail::read_framed(reader, is_head);
          if (!fr)
            req_err = fr.error();
          else
            framed = std::move(fr.value());
        }
      }
    }

    if (req_err)
    {
      // A pooled connection the server had already half-closed fails here; retry ONCE on a fresh one.
      if (from_pool && attempt == 0 && !is_cancelled(*req_err))
      {
        if (pool)
          pool->discards_stale++;
        pc.reset(); // drop -> close
        from_pool = false;
        continue;
      }
      co_return std::unexpected(*req_err);
    }

    if (pool && from_pool)
      pool->reuses++;

    auto response = detail::parse_response(framed.raw);
    if (!response)
    {
      pc.reset();
      co_return std::unexpected(response.error());
    }

    if (pool && framed.complete && framed.reusable)
      pool->release(loop, std::move(*pc)); // keep alive for the next request
    else
      pc.reset(); // legacy fresh-connection path, or a connection the peer is closing
    co_return std::move(*response);
  }
}

// HTTPS/1.1 GET/POST that follows up to request.max_redirects hops (3xx with a Location). Only
// same-scheme https redirects are followed; a redirect to a non-https target is refused. On
// 303 (and 301/302 for a POST) the method is downgraded to GET and the body dropped, per the
// browser fetch model. With max_redirects == 0 this behaves exactly like fetch_once.
inline vio::task_t<std::expected<response_t, error_t>> fetch(event_loop_t &loop, const request_t &request, cancellation_t *cancel = nullptr, connection_pool_t *pool = nullptr)
{
  request_t current = request;
  for (int hops = 0;; ++hops)
  {
    auto response = co_await fetch_once(loop, current, cancel, pool);
    if (!response.has_value())
      co_return response;

    const int status = response->status;
    const bool is_redirect = status == 301 || status == 302 || status == 303 || status == 307 || status == 308;
    if (!is_redirect || hops >= request.max_redirects)
      co_return response;

    std::string_view location = response->header("Location");
    if (location.empty())
      co_return response;

    auto base = ada::parse<ada::url_aggregator>(current.url);
    if (!base)
      co_return std::unexpected(error_t{.code = -1, .msg = "http: bad base url on redirect"});
    auto next = ada::parse<ada::url_aggregator>(location, &*base);
    if (!next)
      co_return std::unexpected(error_t{.code = -1, .msg = "http: bad redirect location"});
    if (next->get_protocol() != "https:")
      co_return std::unexpected(error_t{.code = -1, .msg = "http: redirect to non-https blocked"});

    current.url = std::string(next->get_href());
    if (status == 303 || ((status == 301 || status == 302) && current.method == "POST"))
    {
      current.method = "GET";
      current.body.clear();
    }
  }
}
#endif // !__EMSCRIPTEN__

} // namespace vio::http

#ifdef __EMSCRIPTEN__
#include <vio/platform/wasm/http_fetch_impl.h>
#endif
