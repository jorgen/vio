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

#include <vio/objstore/connection_string.h>
#include <vio/objstore/credentials.h>
#include <vio/objstore/memory_object_store.h>
#include <vio/objstore/object_store.h>
#include <vio/objstore/s3_object_store.h>
#ifndef __EMSCRIPTEN__
// The directory and Azure backends reach libuv (file I/O); exclude them from the browser build, which
// has no POSIX filesystem and talks to S3 over emscripten_fetch. aws_config supplies the native ~/.aws
// credential provider chain (also unavailable in the browser).
#include <vio/objstore/aws_config.h>
#include <vio/objstore/azure_object_store.h>
#include <vio/objstore/file_object_store.h>
#endif

#include <cstdint>
#include <cstdlib>
#include <memory>
#include <optional>
#include <string>
#include <utility>

namespace vio::objstore
{

namespace detail
{
inline std::string getenv_str(const char *name)
{
  const char *v = std::getenv(name);
  return v ? std::string(v) : std::string();
}

// "scheme://rest" -> {scheme, rest}. A bare string (no "://") has an empty scheme.
inline std::pair<std::string, std::string> split_scheme(const std::string &url)
{
  auto sep = url.find("://");
  if (sep == std::string::npos)
    return {std::string(), url};
  return {url.substr(0, sep), url.substr(sep + 3)};
}

// Parse "scheme://host[:port]" (any trailing path is ignored). Returns false if malformed.
inline bool parse_endpoint(const std::string &url, bool &https, std::string &host, uint16_t &port)
{
  auto sep = url.find("://");
  if (sep == std::string::npos)
    return false;
  https = url.substr(0, sep) == "https";
  std::string rest = url.substr(sep + 3);
  auto slash = rest.find('/');
  std::string hostport = slash == std::string::npos ? rest : rest.substr(0, slash);
  auto colon = hostport.find(':');
  if (colon == std::string::npos)
  {
    host = hostport;
    port = 0;
  }
  else
  {
    host = hostport.substr(0, colon);
    port = uint16_t(std::atoi(hostport.substr(colon + 1).c_str()));
  }
  return !host.empty();
}

// Split "bucket/prefix" into the first segment and the remaining prefix (trailing '/' stripped).
inline void split_bucket_prefix(const std::string &path, std::string &bucket, std::string &prefix)
{
  auto slash = path.find('/');
  if (slash == std::string::npos)
  {
    bucket = path;
    prefix.clear();
  }
  else
  {
    bucket = path.substr(0, slash);
    prefix = path.substr(slash + 1);
  }
  while (!prefix.empty() && prefix.back() == '/')
    prefix.pop_back();
}

// Optional process-global S3 config. When set, create_io_manager uses its credentials / endpoint /
// region for s3:// URLs instead of reading AWS_* env vars -- the injection point for embedding contexts
// (a browser holding temporary STS credentials) where getenv is not meaningful. Only bucket/prefix are
// taken from the URL. NOTE: process-global, so it assumes a single active S3 credential set at a time.
inline std::optional<s3_io_manager_t::config_t> &s3_config_override()
{
  static std::optional<s3_io_manager_t::config_t> cfg;
  return cfg;
}

struct resolved_s3_config_t
{
  s3_io_manager_t::config_t cfg;
  bool has_credentials = false; // explicit access_key + secret_key were supplied (connection string / env)
  bool custom_endpoint = false; // a non-AWS endpoint (minio / localstack / ...) was configured
  bool anonymous = false;       // anonymous (public-bucket) access requested -> send unsigned requests
};

// Resolve an S3 config from a connection string and the environment, EXCEPT the credential-presence
// policy. Per-field precedence, highest first: connection-string key > AWS_* environment variable >
// built-in default. Bucket/prefix always come from the URL path. Accepts snake_case canonical keys and
// common CamelCase/AWS aliases (case-insensitive). Errors only on structural problems (missing bucket,
// malformed endpoint) -- NOT on missing credentials, so create_s3 can fall back to the provider chain.
inline std::expected<resolved_s3_config_t, error_t> resolve_s3_config_base(const std::string &path, const connection_options_t &conn)
{
  resolved_s3_config_t out;
  s3_io_manager_t::config_t &cfg = out.cfg;
  split_bucket_prefix(path, cfg.bucket, cfg.prefix);
  if (cfg.bucket.empty())
    return std::unexpected(error_t{.code = -1, .msg = "s3 url missing bucket (expected s3://bucket/prefix)"});

  cfg.access_key = conn.get({"access_key_id", "accesskeyid", "aws_access_key_id"}).value_or(getenv_str("AWS_ACCESS_KEY_ID"));
  cfg.secret_key = conn.get({"secret_access_key", "secretaccesskey", "secretkey", "aws_secret_access_key", "aws_secret_key"}).value_or(getenv_str("AWS_SECRET_ACCESS_KEY"));
  cfg.session_token = conn.get({"session_token", "sessiontoken", "aws_session_token"}).value_or(getenv_str("AWS_SESSION_TOKEN"));

  cfg.region = conn.get({"region", "aws_region"}).value_or(getenv_str("AWS_REGION"));
  if (cfg.region.empty())
    cfg.region = getenv_str("AWS_DEFAULT_REGION");
  if (cfg.region.empty())
    cfg.region = "us-east-1";

  std::string endpoint;
  if (auto e = conn.get({"endpoint", "endpoint_url", "endpointoverride", "aws_endpoint_url"}))
    endpoint = *e;
  else if (endpoint = getenv_str("AWS_ENDPOINT_URL"); endpoint.empty())
    endpoint = getenv_str("AWS_S3_ENDPOINT");

  if (!endpoint.empty())
  {
    if (!parse_endpoint(endpoint, cfg.https, cfg.host, cfg.port))
      return std::unexpected(error_t{.code = -1, .msg = "invalid s3 endpoint: '" + endpoint + "'"});
    cfg.path_style = true; // custom endpoints (minio) default to path-style
    out.custom_endpoint = true;
  }
  else
  {
    cfg.https = true;
    cfg.host = "s3." + cfg.region + ".amazonaws.com";
    cfg.path_style = false;
  }

  if (auto ps = conn.get({"path_style", "pathstyle", "force_path_style"}))
    cfg.path_style = conn_detail::parse_bool(*ps, cfg.path_style);
  else if (std::string fps = getenv_str("AWS_S3_FORCE_PATH_STYLE"); !fps.empty())
    cfg.path_style = conn_detail::parse_bool(fps, cfg.path_style);

  // Anonymous (public bucket): opt in with anonymous=/public=/no_sign_request=true. The request is sent
  // unsigned, so any supplied credentials are dropped -- empty credentials are the signal build_request
  // uses to skip SigV4. Handy for a public dataset read from the browser (no credential chain there).
  if (auto a = conn.get({"anonymous", "public", "no_sign_request", "nosignrequest"}))
    out.anonymous = conn_detail::parse_bool(*a, false);
  if (out.anonymous)
  {
    cfg.access_key.clear();
    cfg.secret_key.clear();
    cfg.session_token.clear();
  }

  out.has_credentials = !cfg.access_key.empty() && !cfg.secret_key.empty();
  return out;
}

// Resolve an S3 config, requiring credentials to be explicitly present (connection string / env). Used by
// the process-global override path (apply_connection_override), which pins a fully-specified config.
inline std::expected<s3_io_manager_t::config_t, error_t> resolve_s3_config(const std::string &path, const connection_options_t &conn)
{
  auto r = resolve_s3_config_base(path, conn);
  if (!r)
    return std::unexpected(r.error());
  if (!r->has_credentials && !r->anonymous)
    return std::unexpected(error_t{.code = -1, .msg = "s3: credentials missing (set access_key_id/secret_access_key in the connection string or AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY, or anonymous=true for a public bucket)"});
  return std::move(r->cfg);
}

inline std::expected<std::unique_ptr<io_manager_t>, error_t> create_s3(const std::string &path, const connection_options_t &conn, event_loop_t &loop)
{
  // With no connection string, an injected process-global config (e.g. browser temp credentials) still
  // wins over the environment. A supplied connection string takes precedence over the override.
  if (conn.empty())
  {
    if (auto &override_cfg = s3_config_override(); override_cfg.has_value())
    {
      s3_io_manager_t::config_t merged = *override_cfg;
      std::string bucket, prefix;
      split_bucket_prefix(path, bucket, prefix);
      if (merged.bucket.empty())
        merged.bucket = std::move(bucket);
      if (merged.prefix.empty())
        merged.prefix = std::move(prefix);
      return std::unique_ptr<io_manager_t>(std::make_unique<s3_io_manager_t>(loop, std::move(merged)));
    }
  }

  auto r = resolve_s3_config_base(path, conn);
  if (!r)
    return std::unexpected(r.error());
  s3_io_manager_t::config_t cfg = std::move(r->cfg);

  if (!r->has_credentials)
  {
    if (r->anonymous)
    {
      // Explicit anonymous access to a public bucket: construct with no credentials -> unsigned requests.
      return std::unique_ptr<io_manager_t>(std::make_unique<s3_io_manager_t>(loop, std::move(cfg)));
    }
#ifndef __EMSCRIPTEN__
    if (r->custom_endpoint)
      return std::unexpected(error_t{.code = -1, .msg = "s3: credentials missing for custom endpoint (set access_key_id/secret_access_key in the connection string or AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY)"});
    // Plain AWS endpoint, no explicit credentials: fall back to the native ~/.aws credential provider
    // chain (static keys / `aws login` / SSO / assume-role / instance metadata). Temporary credentials
    // are refreshed per request by s3_io_manager_t. The profile may also supply the region.
    std::optional<std::string> profile;
    if (auto p = conn.get({"profile", "aws_profile"}); p && !p->empty())
      profile = *p;
    auto chain = resolve_credential_chain(profile);
    cfg.provider = std::move(chain.provider);
    const bool region_pinned = conn.get({"region", "aws_region"}).has_value() || !getenv_str("AWS_REGION").empty() || !getenv_str("AWS_DEFAULT_REGION").empty();
    if (!region_pinned && chain.region && !chain.region->empty())
    {
      cfg.region = *chain.region;
      cfg.host = "s3." + cfg.region + ".amazonaws.com";
    }
#else
    return std::unexpected(error_t{.code = -1, .msg = "s3: credentials missing (set access_key_id/secret_access_key in the connection string or AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY)"});
#endif
  }

  return std::unique_ptr<io_manager_t>(std::make_unique<s3_io_manager_t>(loop, std::move(cfg)));
}

#ifndef __EMSCRIPTEN__
inline std::optional<azure_io_manager_t::config_t> &azure_config_override()
{
  static std::optional<azure_io_manager_t::config_t> cfg;
  return cfg;
}

// Resolve an Azure config from a connection string and the environment (connection key > AZURE_* env >
// default). Container/prefix always come from the URL path.
inline std::expected<azure_io_manager_t::config_t, error_t> resolve_azure_config(const std::string &path, const connection_options_t &conn)
{
  azure_io_manager_t::config_t cfg;
  split_bucket_prefix(path, cfg.container, cfg.prefix);
  if (cfg.container.empty())
    return std::unexpected(error_t{.code = -1, .msg = "azure url missing container (expected az://container/prefix)"});

  cfg.account = conn.get({"account", "account_name", "accountname"}).value_or(getenv_str("AZURE_STORAGE_ACCOUNT"));
  cfg.account_key_base64 = conn.get({"account_key", "accountkey", "account_key_base64"}).value_or(getenv_str("AZURE_STORAGE_KEY"));
  cfg.sas = conn.get({"sas", "shared_access_signature", "sharedaccesssignature"}).value_or(getenv_str("AZURE_STORAGE_SAS"));
  if (cfg.account.empty())
    return std::unexpected(error_t{.code = -1, .msg = "azure: account missing (set account in the connection string or AZURE_STORAGE_ACCOUNT)"});

  std::string endpoint;
  if (auto e = conn.get({"endpoint", "blob_endpoint", "blobendpoint"}))
    endpoint = *e;
  else if (endpoint = getenv_str("AZURE_BLOB_ENDPOINT"); endpoint.empty())
    endpoint = getenv_str("AZURE_STORAGE_ENDPOINT");

  if (!endpoint.empty())
  {
    if (!parse_endpoint(endpoint, cfg.https, cfg.host, cfg.port))
      return std::unexpected(error_t{.code = -1, .msg = "invalid azure endpoint: '" + endpoint + "'"});
    cfg.account_in_path = true; // azurite / custom endpoints carry the account in the path
  }
  else
  {
    cfg.https = true;
    cfg.host = cfg.account + ".blob.core.windows.net";
    cfg.account_in_path = false;
  }

  if (cfg.sas.empty() && cfg.account_key_base64.empty())
    return std::unexpected(error_t{.code = -1, .msg = "azure: set account_key or sas (or AZURE_STORAGE_KEY / AZURE_STORAGE_SAS)"});
  return cfg;
}

inline std::expected<std::unique_ptr<io_manager_t>, error_t> create_azure(const std::string &path, const connection_options_t &conn, event_loop_t &loop)
{
  if (conn.empty())
  {
    if (auto &override_cfg = azure_config_override(); override_cfg.has_value())
    {
      azure_io_manager_t::config_t merged = *override_cfg;
      std::string container, prefix;
      split_bucket_prefix(path, container, prefix);
      if (merged.container.empty())
        merged.container = std::move(container);
      if (merged.prefix.empty())
        merged.prefix = std::move(prefix);
      return std::unique_ptr<io_manager_t>(std::make_unique<azure_io_manager_t>(loop, std::move(merged)));
    }
  }
  auto cfg = resolve_azure_config(path, conn);
  if (!cfg)
    return std::unexpected(cfg.error());
  return std::unique_ptr<io_manager_t>(std::make_unique<azure_io_manager_t>(loop, std::move(*cfg)));
}
#endif // __EMSCRIPTEN__
} // namespace detail

// Build an S3 io_manager from an explicit config, with credentials/endpoint injected by the caller
// rather than read from the environment. This is the entry point for embedding contexts -- e.g. a
// browser that obtains temporary STS credentials (access key + secret + session token) from JS -- where
// getenv is not meaningful. The caller fills config_t (bucket/prefix/region/host/path_style/creds).
inline std::unique_ptr<io_manager_t> create_s3_with_config(s3_io_manager_t::config_t cfg, event_loop_t &loop)
{
  return std::make_unique<s3_io_manager_t>(loop, std::move(cfg));
}

// Install / clear the process-global S3 config that create_io_manager (below) uses for s3:// URLs in
// place of AWS_* env vars. Lets a URL-driven pipeline (e.g. the converter storage backend) run against
// caller-injected temporary credentials. Only bucket/prefix are still taken from each URL.
inline void set_s3_config_override(s3_io_manager_t::config_t cfg)
{
  detail::s3_config_override() = std::move(cfg);
}

inline void clear_s3_config_override()
{
  detail::s3_config_override().reset();
}

#ifndef __EMSCRIPTEN__
// Azure counterparts of the S3 config override (used for az:// URLs when no connection string is given).
inline void set_azure_config_override(azure_io_manager_t::config_t cfg)
{
  detail::azure_config_override() = std::move(cfg);
}

inline void clear_azure_config_override()
{
  detail::azure_config_override().reset();
}
#endif

// Parse `connection_string` and install it as the process-global config override for the URL's provider
// (s3 / azure), so a later create_io_manager(url) [environment overload] uses it. A no-op for file / dir /
// mem URLs. Convenience for single-output tools (the converter); a multi-endpoint tool (e.g. a copy tool
// with two different stores) should instead pass the connection to create_io_manager(url, connection, ...)
// per side rather than rely on the single global override.
inline std::expected<void, error_t> apply_connection_override(const std::string &url, std::string_view connection_string)
{
  auto conn = parse_connection_string(connection_string);
  if (!conn)
    return std::unexpected(conn.error());
  auto [scheme, path] = detail::split_scheme(url);
  if (scheme == "s3")
  {
    auto cfg = detail::resolve_s3_config(path, *conn);
    if (!cfg)
      return std::unexpected(cfg.error());
    set_s3_config_override(std::move(*cfg));
  }
#ifndef __EMSCRIPTEN__
  else if (scheme == "az" || scheme == "azure")
  {
    auto cfg = detail::resolve_azure_config(path, *conn);
    if (!cfg)
      return std::unexpected(cfg.error());
    set_azure_config_override(std::move(*cfg));
  }
#endif
  return {};
}

// Build an io_manager from a URL + an (already-parsed) connection string. Schemes: mem://name,
// dir:///path, s3://bucket/prefix, az://container/prefix. For cloud stores, credentials/endpoint/region
// come from `conn` first, then the standard AWS_* / AZURE_* environment variables, then built-in defaults
// (see resolve_s3_config / resolve_azure_config). dir/mem ignore `conn`.
inline std::expected<std::unique_ptr<io_manager_t>, error_t> create_io_manager(const std::string &url, const connection_options_t &conn, event_loop_t &loop)
{
  auto [scheme, path] = detail::split_scheme(url);
#ifndef __EMSCRIPTEN__
  if (scheme == "dir")
    return std::unique_ptr<io_manager_t>(std::make_unique<file_dir_io_manager_t>(path, loop));
#endif
  if (scheme == "mem")
    return std::unique_ptr<io_manager_t>(std::make_unique<memory_io_manager_t>());
  if (scheme == "s3")
    return detail::create_s3(path, conn, loop);
#ifndef __EMSCRIPTEN__
  if (scheme == "az" || scheme == "azure")
    return detail::create_azure(path, conn, loop);
#endif
  return std::unexpected(error_t{.code = -1, .msg = "Unsupported object-store scheme: '" + scheme + "'"});
}

// As above, taking a raw connection string (parsed here). An empty string means "environment + defaults".
inline std::expected<std::unique_ptr<io_manager_t>, error_t> create_io_manager(const std::string &url, std::string_view connection_string, event_loop_t &loop)
{
  auto conn = parse_connection_string(connection_string);
  if (!conn)
    return std::unexpected(conn.error());
  return create_io_manager(url, *conn, loop);
}

// Environment-only overload (credentials from AWS_* / AZURE_* env vars, or the process-global override).
inline std::expected<std::unique_ptr<io_manager_t>, error_t> create_io_manager(const std::string &url, event_loop_t &loop)
{
  return create_io_manager(url, connection_options_t{}, loop);
}

} // namespace vio::objstore
