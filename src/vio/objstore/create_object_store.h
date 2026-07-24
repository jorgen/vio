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

#include <vio/objstore/memory_object_store.h>
#include <vio/objstore/object_store.h>
#include <vio/objstore/s3_object_store.h>
#ifndef __EMSCRIPTEN__
// The directory and Azure backends reach libuv (file I/O); exclude them from the browser build, which
// has no POSIX filesystem and talks to S3 over emscripten_fetch.
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

inline std::expected<std::unique_ptr<io_manager_t>, error_t> create_s3(const std::string &path, event_loop_t &loop)
{
  s3_io_manager_t::config_t cfg;
  split_bucket_prefix(path, cfg.bucket, cfg.prefix);
  if (cfg.bucket.empty())
    return std::unexpected(error_t{.code = -1, .msg = "s3 url missing bucket (expected s3://bucket/prefix)"});

  // Injected config (browser temp credentials): take creds/endpoint/region from it, bucket/prefix from URL.
  if (auto &override_cfg = s3_config_override(); override_cfg.has_value())
  {
    s3_io_manager_t::config_t merged = *override_cfg;
    if (merged.bucket.empty())
      merged.bucket = cfg.bucket;
    if (merged.prefix.empty())
      merged.prefix = cfg.prefix;
    return std::unique_ptr<io_manager_t>(std::make_unique<s3_io_manager_t>(loop, std::move(merged)));
  }

  cfg.access_key = getenv_str("AWS_ACCESS_KEY_ID");
  cfg.secret_key = getenv_str("AWS_SECRET_ACCESS_KEY");
  cfg.session_token = getenv_str("AWS_SESSION_TOKEN");
  cfg.region = getenv_str("AWS_REGION");
  if (cfg.region.empty())
    cfg.region = getenv_str("AWS_DEFAULT_REGION");
  if (cfg.region.empty())
    cfg.region = "us-east-1";

  std::string endpoint = getenv_str("AWS_ENDPOINT_URL");
  if (endpoint.empty())
    endpoint = getenv_str("AWS_S3_ENDPOINT");
  if (!endpoint.empty())
  {
    if (!parse_endpoint(endpoint, cfg.https, cfg.host, cfg.port))
      return std::unexpected(error_t{.code = -1, .msg = "invalid AWS_ENDPOINT_URL"});
    cfg.path_style = true; // custom endpoints (minio) default to path-style
  }
  else
  {
    cfg.https = true;
    cfg.host = "s3." + cfg.region + ".amazonaws.com";
    cfg.path_style = false;
  }
  std::string fps = getenv_str("AWS_S3_FORCE_PATH_STYLE");
  if (fps == "1" || fps == "true" || fps == "TRUE")
    cfg.path_style = true;

  if (cfg.access_key.empty() || cfg.secret_key.empty())
    return std::unexpected(error_t{.code = -1, .msg = "s3: set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY"});
  return std::unique_ptr<io_manager_t>(std::make_unique<s3_io_manager_t>(loop, std::move(cfg)));
}

#ifndef __EMSCRIPTEN__
inline std::expected<std::unique_ptr<io_manager_t>, error_t> create_azure(const std::string &path, event_loop_t &loop)
{
  azure_io_manager_t::config_t cfg;
  split_bucket_prefix(path, cfg.container, cfg.prefix);
  if (cfg.container.empty())
    return std::unexpected(error_t{.code = -1, .msg = "azure url missing container (expected az://container/prefix)"});
  cfg.account = getenv_str("AZURE_STORAGE_ACCOUNT");
  cfg.account_key_base64 = getenv_str("AZURE_STORAGE_KEY");
  cfg.sas = getenv_str("AZURE_STORAGE_SAS");
  if (cfg.account.empty())
    return std::unexpected(error_t{.code = -1, .msg = "azure: set AZURE_STORAGE_ACCOUNT"});

  std::string endpoint = getenv_str("AZURE_BLOB_ENDPOINT");
  if (endpoint.empty())
    endpoint = getenv_str("AZURE_STORAGE_ENDPOINT");
  if (!endpoint.empty())
  {
    if (!parse_endpoint(endpoint, cfg.https, cfg.host, cfg.port))
      return std::unexpected(error_t{.code = -1, .msg = "invalid AZURE_BLOB_ENDPOINT"});
    cfg.account_in_path = true; // azurite / custom endpoints carry the account in the path
  }
  else
  {
    cfg.https = true;
    cfg.host = cfg.account + ".blob.core.windows.net";
    cfg.account_in_path = false;
  }

  if (cfg.sas.empty() && cfg.account_key_base64.empty())
    return std::unexpected(error_t{.code = -1, .msg = "azure: set AZURE_STORAGE_KEY or AZURE_STORAGE_SAS"});
  return std::unique_ptr<io_manager_t>(std::make_unique<azure_io_manager_t>(loop, std::move(cfg)));
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

// Build an io_manager from a URL. Schemes: mem://name, dir:///path, s3://bucket/prefix,
// az://container/prefix. Cloud credentials/endpoints come from the standard environment variables
// (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_REGION / AWS_ENDPOINT_URL / AWS_S3_FORCE_PATH_STYLE;
// AZURE_STORAGE_ACCOUNT / AZURE_STORAGE_KEY / AZURE_STORAGE_SAS / AZURE_BLOB_ENDPOINT).
inline std::expected<std::unique_ptr<io_manager_t>, error_t> create_io_manager(const std::string &url, event_loop_t &loop)
{
  auto [scheme, path] = detail::split_scheme(url);
#ifndef __EMSCRIPTEN__
  if (scheme == "dir")
    return std::unique_ptr<io_manager_t>(std::make_unique<file_dir_io_manager_t>(path, loop));
#endif
  if (scheme == "mem")
    return std::unique_ptr<io_manager_t>(std::make_unique<memory_io_manager_t>());
  if (scheme == "s3")
    return detail::create_s3(path, loop);
#ifndef __EMSCRIPTEN__
  if (scheme == "az" || scheme == "azure")
    return detail::create_azure(path, loop);
#endif
  return std::unexpected(error_t{.code = -1, .msg = "Unsupported object-store scheme: '" + scheme + "'"});
}

} // namespace vio::objstore
