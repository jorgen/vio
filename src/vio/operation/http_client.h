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
} // namespace detail

// One request over a fresh verified TLS connection (SSL_VERIFY_PEER + hostname check), sent with
// Connection: close; reads the whole response (Content-Length or chunked). No keep-alive, no
// redirect following (see fetch below), no transparent decompression (Accept-Encoding: identity).
inline vio::task_t<std::expected<response_t, error_t>> fetch_once(event_loop_t &loop, const request_t &request, cancellation_t *cancel = nullptr)
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
  wire.append("Connection: close\r\n");
  for (const auto &h : request.headers)
    wire.append(h.name).append(": ").append(h.value).append("\r\n");
  if (!request.body.empty())
    wire.append("Content-Length: ").append(std::to_string(request.body.size())).append("\r\n");
  wire.append("\r\n");
  wire.append(request.body);

  std::string raw;

  if (is_https)
  {
    ssl_config_t tls_config;
    if (request.ca_mem)
      tls_config.ca_mem = request.ca_mem;
    auto client = ssl_client_create(loop, tls_config);
    if (!client)
      co_return std::unexpected(client.error());

    auto connected = co_await ssl_client_connect(client.value(), host, port, cancel);
    if (!connected)
      co_return std::unexpected(connected.error());

    uv_buf_t buf;
    buf.base = wire.data();
    buf.len = static_cast<decltype(buf.len)>(wire.size());
    auto written = co_await ssl_client_write(client.value(), buf, cancel);
    if (!written)
      co_return std::unexpected(written.error());

    auto reader_result = ssl_client_create_reader(client.value());
    if (!reader_result)
      co_return std::unexpected(reader_result.error());
    auto reader = std::move(reader_result.value());

    while (true)
    {
      auto chunk = co_await reader;
      if (!chunk)
        break;
      raw.append(chunk.value().buf.base, chunk.value().buf.len);
    }
  }
  else
  {
    // Plaintext HTTP (opt-in): resolve the host, stamp the port onto the address, and drive a plain
    // TCP connection with the same request wire. Used for same-host reverse proxying to an internal
    // backend; unreachable unless request.allow_plaintext was set.
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

    auto written = co_await write_tcp(tcp.value(), reinterpret_cast<const uint8_t *>(wire.data()), wire.size(), cancel);
    if (!written)
      co_return std::unexpected(written.error());

    auto reader_result = tcp_create_reader(tcp.value());
    if (!reader_result)
      co_return std::unexpected(reader_result.error());
    auto reader = std::move(reader_result.value());

    while (true)
    {
      auto chunk = co_await reader;
      if (!chunk)
        break;
      raw.append(chunk.value().buf.base, chunk.value().buf.len);
    }
  }

  co_return detail::parse_response(raw);
}

// HTTPS/1.1 GET/POST that follows up to request.max_redirects hops (3xx with a Location). Only
// same-scheme https redirects are followed; a redirect to a non-https target is refused. On
// 303 (and 301/302 for a POST) the method is downgraded to GET and the body dropped, per the
// browser fetch model. With max_redirects == 0 this behaves exactly like fetch_once.
inline vio::task_t<std::expected<response_t, error_t>> fetch(event_loop_t &loop, const request_t &request, cancellation_t *cancel = nullptr)
{
  request_t current = request;
  for (int hops = 0;; ++hops)
  {
    auto response = co_await fetch_once(loop, current, cancel);
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
