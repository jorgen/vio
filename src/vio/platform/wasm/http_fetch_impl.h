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

// WebAssembly/Emscripten transport for vio::http::fetch, backed by the browser Fetch API via
// emscripten_fetch. This provides the SAME vio::http::fetch / fetch_once signatures as the native
// libuv+LibreSSL implementation in http_client.h, so the object-store layer (http_object_store.h,
// s3_object_store.h) compiles and runs unchanged. Included by http_client.h under #ifdef __EMSCRIPTEN__.
//
// Semantics match the native transport: any completed HTTP response (including 4xx/5xx) is returned as
// a response_t with its real status and body -- callers inspect resp->status (e.g. 404 => object
// missing). Only a genuine transport failure (status 0) yields std::unexpected. Redirects are followed
// by the browser, so fetch == fetch_once here.

#include <vio/operation/http_client.h> // header_t / request_t / response_t (guarded so this is a no-op re-entry)

#include <vio/cancellation.h>
#include <vio/error.h>
#include <vio/event_loop.h>
#include <vio/task.h>

#include <coroutine>
#include <cstring>
#include <expected>
#include <string>
#include <vector>

#include <emscripten/fetch.h>

namespace vio::http
{

namespace detail
{
// Parse the raw response header block emscripten returns ("Name: value\r\n...", possibly with a leading
// status line) into header_t entries. Lines without a ':' (e.g. the status line) are skipped.
inline std::vector<header_t> parse_fetch_headers(const std::string &raw)
{
  std::vector<header_t> out;
  size_t pos = 0;
  while (pos < raw.size())
  {
    size_t eol = raw.find('\n', pos);
    std::string line = raw.substr(pos, (eol == std::string::npos ? raw.size() : eol) - pos);
    pos = (eol == std::string::npos) ? raw.size() : eol + 1;
    if (!line.empty() && line.back() == '\r')
      line.pop_back();
    auto colon = line.find(':');
    if (colon == std::string::npos)
      continue;
    std::string name = line.substr(0, colon);
    std::string value = line.substr(colon + 1);
    size_t a = value.find_first_not_of(" \t");
    value = (a == std::string::npos) ? std::string() : value.substr(a);
    out.push_back({std::move(name), std::move(value)});
  }
  return out;
}
} // namespace detail

// Awaitable wrapping a single emscripten_fetch. It is co_awaited as a prvalue temporary, so it is
// materialized directly in the coroutine frame (no move) and stays alive across the suspension --
// hence attr / body / header storage remain valid until the fetch completes.
struct fetch_awaitable_t
{
  std::string url;
  std::string method;
  std::string body;
  std::vector<std::string> header_strings; // name0, value0, name1, value1, ...
  std::vector<const char *> header_ptrs;    // null-terminated for attr.requestHeaders
  emscripten_fetch_attr_t attr;
  std::expected<response_t, error_t> result;
  std::coroutine_handle<> continuation;
  event_loop_t *loop;

  fetch_awaitable_t(event_loop_t &event_loop, const request_t &request)
    : url(request.url)
    , method(request.method)
    , body(request.body)
    , loop(&event_loop)
  {
    header_strings.reserve(request.headers.size() * 2);
    for (const auto &h : request.headers)
    {
      header_strings.push_back(h.name);
      header_strings.push_back(h.value);
    }
    header_ptrs.reserve(header_strings.size() + 1);
    for (const auto &s : header_strings)
      header_ptrs.push_back(s.c_str());
    header_ptrs.push_back(nullptr);

    emscripten_fetch_attr_init(&attr);
    std::strncpy(attr.requestMethod, method.c_str(), sizeof(attr.requestMethod) - 1);
    attr.attributes = EMSCRIPTEN_FETCH_LOAD_TO_MEMORY | EMSCRIPTEN_FETCH_REPLACE;
    attr.requestHeaders = header_ptrs.data();
    if (!body.empty())
    {
      attr.requestData = body.data();
      attr.requestDataSize = body.size();
    }
    attr.onsuccess = &fetch_awaitable_t::on_complete;
    attr.onerror = &fetch_awaitable_t::on_complete;
    attr.userData = this;
  }

  [[nodiscard]] bool await_ready() const noexcept
  {
    return false;
  }

  void await_suspend(std::coroutine_handle<> h) noexcept
  {
    continuation = h;
    emscripten_fetch(&attr, url.c_str());
  }

  std::expected<response_t, error_t> await_resume() noexcept
  {
    return std::move(result);
  }

  // One handler for both success and error: emscripten routes HTTP error statuses (e.g. 404) to
  // onerror, but callers need those statuses, so build a response_t whenever the request actually
  // reached the server (status != 0) and only fail on a transport-level error.
  static void on_complete(emscripten_fetch_t *fetch)
  {
    auto *self = static_cast<fetch_awaitable_t *>(fetch->userData);
    if (fetch->status == 0)
    {
      self->result = std::unexpected(error_t{.code = -1, .msg = std::string("http fetch transport error: ") + fetch->statusText});
    }
    else
    {
      response_t r;
      r.status = fetch->status;
      size_t hlen = emscripten_fetch_get_response_headers_length(fetch);
      if (hlen > 0)
      {
        std::string hbuf(hlen + 1, '\0');
        emscripten_fetch_get_response_headers(fetch, hbuf.data(), hlen + 1);
        hbuf.resize(std::strlen(hbuf.c_str()));
        r.headers = detail::parse_fetch_headers(hbuf);
      }
      if (fetch->numBytes > 0 && fetch->data != nullptr)
        r.body.assign(fetch->data, static_cast<size_t>(fetch->numBytes));
      self->result = std::move(r);
    }
    // Resume on the event loop, NOT here: emscripten_fetch is not reentrant, so the resumed coroutine
    // must not issue its next fetch from inside this callback. Posting to the loop lets the fetch
    // callback unwind first; the resume runs on the loop's next cooperative poll.
    auto *loop = self->loop;
    auto continuation = self->continuation;
    emscripten_fetch_close(fetch); // does not touch *self
    loop->run_in_loop([continuation]() { continuation.resume(); });
    // Signal the app that async work completed outside a frame, so an on-demand renderer can schedule a
    // redraw to pump this resume + draw the new data. No-op if no wake hook is registered.
    vio::wasm::wake();
  }
};

inline vio::task_t<std::expected<response_t, error_t>> fetch_once(event_loop_t &loop, const request_t &request, cancellation_t *cancel = nullptr)
{
  (void)cancel; // cancellation via emscripten_fetch_close is not wired up in this first cut
  co_return co_await fetch_awaitable_t(loop, request);
}

inline vio::task_t<std::expected<response_t, error_t>> fetch(event_loop_t &loop, const request_t &request, cancellation_t *cancel = nullptr)
{
  (void)cancel;
  // The browser's Fetch follows redirects itself, so this matches native fetch()'s redirect-following.
  co_return co_await fetch_awaitable_t(loop, request);
}

} // namespace vio::http
