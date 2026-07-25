/*
  Copyright (c) 2025 Jørgen Lind

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

// Concrete credentials_provider_t implementations. This is an internal vio header (compiled into the
// library via aws_credentials.cpp and included by the credential unit test); it is not part of vio's
// public surface, so consumers never see it. The file-backed providers here (environment, static, login
// cache) resolve synchronously; the HTTP-backed providers (SSO, STS assume-role, instance metadata) are
// added in later phases and live in the same namespace.

#include <vio/crypto.h>
#include <vio/detail/aws_time.h>
#include <vio/detail/home_dir.h>
#include <vio/objstore/aws_json.h>
#include <vio/objstore/credentials.h>

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace vio::objstore
{

// Credentials read straight from the AWS_* environment variables. Reports an error (so a chain moves on)
// when the required variables are unset.
class environment_credentials_provider_t : public credentials_provider_t
{
public:
  task_t<std::expected<credentials_t, error_t>> credentials(event_loop_t & /*loop*/) override
  {
    const char *ak = std::getenv("AWS_ACCESS_KEY_ID");
    const char *sk = std::getenv("AWS_SECRET_ACCESS_KEY");
    if (!ak || !*ak || !sk || !*sk)
      co_return std::unexpected(error_t{.code = -1, .msg = "environment: AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY not set"});
    credentials_t c;
    c.access_key = ak;
    c.secret_key = sk;
    if (const char *st = std::getenv("AWS_SESSION_TOKEN"); st && *st)
      c.session_token = st;
    if (const char *ex = std::getenv("AWS_CREDENTIAL_EXPIRATION"); ex && *ex)
      c.expiration = vio::detail::parse_iso8601_utc(ex);
    co_return c;
  }
};

// A fixed set of credentials (e.g. supplied explicitly by a caller). Never expires / never refreshes.
class static_credentials_provider_t : public credentials_provider_t
{
public:
  explicit static_credentials_provider_t(credentials_t creds)
    : _creds(std::move(creds))
  {
  }

  task_t<std::expected<credentials_t, error_t>> credentials(event_loop_t & /*loop*/) override
  {
    co_return _creds;
  }

private:
  credentials_t _creds;
};

// A provider that always fails with a fixed message. Used to give a clear, actionable error for a profile
// whose credential source is recognized but not yet supported natively (superseded as later phases land).
class error_credentials_provider_t : public credentials_provider_t
{
public:
  explicit error_credentials_provider_t(std::string message)
    : _message(std::move(message))
  {
  }

  task_t<std::expected<credentials_t, error_t>> credentials(event_loop_t & /*loop*/) override
  {
    co_return std::unexpected(error_t{.code = -1, .msg = _message});
  }

private:
  std::string _message;
};

// New `aws login` (DPoP) flow: credentials are cached by the CLI directly at
// <cache_dir>/<sha256(login_session)>.json. This provider re-reads that file as expiry approaches so an
// externally-refreshed cache (a fresh `aws login`, or a background refresh) is picked up automatically;
// it does NOT perform the DPoP refresh itself (undocumented). Once the cached credentials have actually
// expired it returns a clear "run `aws login`" error.
class login_cache_credentials_provider_t : public credentials_provider_t
{
public:
  // `cache_dir` is the directory holding the per-session json files (normally ~/.aws/login/cache).
  login_cache_credentials_provider_t(std::string login_session, std::string cache_dir)
    : _login_session(std::move(login_session))
    , _cache_dir(std::move(cache_dir))
  {
  }

  task_t<std::expected<credentials_t, error_t>> credentials(event_loop_t & /*loop*/) override
  {
    const auto now = std::chrono::system_clock::now();
    // Serve the cached credentials while comfortably valid; otherwise re-read the file (which also picks
    // up an external refresh).
    if (_cached && (!_cached->expiration || now < *_cached->expiration - credentials_refresh_skew))
      co_return *_cached;

    const std::string path = cache_file_path();
    auto text = vio::detail::read_file(path);
    if (!text)
      co_return std::unexpected(error_t{.code = -1, .msg = "aws login credentials not found (" + path + ") -- run `aws login`"});

    auto parsed = parse_login_cache(*text);
    if (!parsed)
      co_return std::unexpected(parsed.error());

    credentials_t c;
    c.access_key = std::move(parsed->access_key_id);
    c.secret_key = std::move(parsed->secret_access_key);
    c.session_token = std::move(parsed->session_token);
    c.expiration = parsed->expiration;

    // Valid until its actual expiry (the skew only governs when we re-read, not when we hard-fail -- the
    // DPoP flow cannot refresh, so we serve the credentials until they truly expire).
    if (!c.expiration || now < *c.expiration)
    {
      _cached = c;
      co_return c;
    }
    _cached.reset();
    co_return std::unexpected(error_t{.code = -1, .msg = "aws login credentials expired -- run `aws login`"});
  }

private:
  std::string cache_file_path() const
  {
    std::span<const uint8_t> bytes(reinterpret_cast<const uint8_t *>(_login_session.data()), _login_session.size());
    std::string name = vio::crypto::to_hex(vio::crypto::sha256(bytes)) + ".json";
    return vio::detail::path_join(_cache_dir, name);
  }

  std::string _login_session;
  std::string _cache_dir;
  std::optional<credentials_t> _cached;
};

// Base for providers whose refresh is an async fetch (SSO / STS assume-role / instance metadata). Caches
// the last result and only re-fetches once it is missing or within the refresh skew of expiry, so
// credentials() is a cheap cache hit on the common path and temporary credentials renew transparently.
class caching_credentials_provider_t : public credentials_provider_t
{
public:
  task_t<std::expected<credentials_t, error_t>> credentials(event_loop_t &loop) final
  {
    const auto now = std::chrono::system_clock::now();
    if (_cached && (!_cached->expiration || now < *_cached->expiration - credentials_refresh_skew))
      co_return *_cached;
    auto fetched = co_await fetch(loop);
    if (!fetched)
      co_return std::unexpected(std::move(fetched.error()));
    _cached = *fetched;
    co_return *fetched;
  }

protected:
  // Perform the actual (re)fetch; called only when the cache is missing or near expiry.
  virtual task_t<std::expected<credentials_t, error_t>> fetch(event_loop_t &loop) = 0;

private:
  std::optional<credentials_t> _cached;
};

// Tries each provider in order; the first that yields credentials wins. If all fail, returns the last
// error (the providers are ordered so the most informative source is last, e.g. env before the profile's
// own provider).
class chain_credentials_provider_t : public credentials_provider_t
{
public:
  explicit chain_credentials_provider_t(std::vector<std::shared_ptr<credentials_provider_t>> providers)
    : _providers(std::move(providers))
  {
  }

  task_t<std::expected<credentials_t, error_t>> credentials(event_loop_t &loop) override
  {
    error_t last{.code = -1, .msg = "no credentials found (set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY, configure ~/.aws, or run `aws login`)"};
    for (auto &p : _providers)
    {
      auto r = co_await p->credentials(loop);
      if (r)
        co_return *r;
      last = std::move(r.error());
    }
    co_return std::unexpected(std::move(last));
  }

private:
  std::vector<std::shared_ptr<credentials_provider_t>> _providers;
};

} // namespace vio::objstore
