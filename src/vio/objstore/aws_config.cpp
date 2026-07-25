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

#include <vio/objstore/aws_config.h>

#include <vio/crypto.h>
#include <vio/detail/home_dir.h>
#include <vio/detail/ini.h>
#include <vio/objstore/aws_imds_client.h>
#include <vio/objstore/aws_profile.h>
#include <vio/objstore/aws_sso_client.h>
#include <vio/objstore/aws_sts_client.h>
#include <vio/objstore/credentials_providers.h>

#include <chrono>
#include <cstdlib>
#include <memory>
#include <span>
#include <utility>
#include <vector>

namespace vio::objstore
{
namespace
{
std::string getenv_str(const char *name)
{
  const char *v = std::getenv(name);
  return v ? std::string(v) : std::string();
}

std::span<const uint8_t> to_span(std::string_view s)
{
  return {reinterpret_cast<const uint8_t *>(s.data()), s.size()};
}

credentials_t to_credentials(const parsed_credentials_t &p)
{
  return credentials_t{p.access_key_id, p.secret_access_key, p.session_token, p.expiration};
}

// Classic IAM Identity Center (SSO): read the cached bearer token, refresh it via OIDC when it has expired
// (grant_type=refresh_token), and exchange it for temporary role credentials via the SSO portal. The
// refreshed bearer token is kept in memory only -- we deliberately do not rewrite the CLI's token cache
// file (structify would drop fields we do not model, and a partial rewrite could confuse the CLI), so each
// process performs at most one OIDC refresh per session. The caching base renews the role credentials as
// they approach expiry.
class sso_credentials_provider_t : public caching_credentials_provider_t
{
public:
  sso_credentials_provider_t(std::string sso_region, std::string account_id, std::string role_name, std::string token_cache_path)
    : _sso_region(std::move(sso_region))
    , _account_id(std::move(account_id))
    , _role_name(std::move(role_name))
    , _token_cache_path(std::move(token_cache_path))
  {
  }

protected:
  task_t<std::expected<credentials_t, error_t>> fetch(event_loop_t &loop) override
  {
    if (!_loaded)
    {
      auto text = vio::detail::read_file(_token_cache_path);
      if (!text)
        co_return std::unexpected(error_t{.code = -1, .msg = "sso token cache not found (" + _token_cache_path + ") -- run `aws sso login`"});
      auto tok = parse_sso_token_cache(*text);
      if (!tok)
        co_return std::unexpected(tok.error());
      _access_token = std::move(tok->access_token);
      _refresh_token = std::move(tok->refresh_token);
      _client_id = std::move(tok->client_id);
      _client_secret = std::move(tok->client_secret);
      _expires_at = tok->expires_at;
      if (tok->region.empty() == false && _sso_region.empty())
        _sso_region = tok->region;
      _loaded = true;
    }

    const auto now = std::chrono::system_clock::now();
    if (_expires_at && now >= *_expires_at - credentials_refresh_skew)
    {
      if (_refresh_token.empty() || _client_id.empty() || _client_secret.empty())
        co_return std::unexpected(error_t{.code = -1, .msg = "sso session expired and cannot be refreshed -- run `aws sso login`"});
      auto refreshed = co_await oidc_create_token(loop, _sso_region, _client_id, _client_secret, _refresh_token);
      if (!refreshed)
        co_return std::unexpected(refreshed.error());
      _access_token = std::move(refreshed->access_token);
      if (!refreshed->refresh_token.empty())
        _refresh_token = std::move(refreshed->refresh_token);
      if (refreshed->expires_in > 0)
        _expires_at = now + std::chrono::seconds(refreshed->expires_in);
    }

    auto role = co_await sso_get_role_credentials(loop, _sso_region, _access_token, _account_id, _role_name);
    if (!role)
      co_return std::unexpected(role.error());
    co_return to_credentials(*role);
  }

private:
  std::string _sso_region;
  std::string _account_id;
  std::string _role_name;
  std::string _token_cache_path;
  bool _loaded = false;
  std::string _access_token;
  std::string _refresh_token;
  std::string _client_id;
  std::string _client_secret;
  std::optional<std::chrono::system_clock::time_point> _expires_at;
};

// STS assume-role: obtain base credentials from a wrapped provider (the source_profile's provider) and
// exchange them for temporary role credentials, re-assuming as they approach expiry.
class assume_role_credentials_provider_t : public caching_credentials_provider_t
{
public:
  assume_role_credentials_provider_t(std::shared_ptr<credentials_provider_t> base, std::string region, std::string role_arn, std::string external_id)
    : _base(std::move(base))
    , _region(std::move(region))
    , _role_arn(std::move(role_arn))
    , _external_id(std::move(external_id))
  {
  }

protected:
  task_t<std::expected<credentials_t, error_t>> fetch(event_loop_t &loop) override
  {
    auto base = co_await _base->credentials(loop);
    if (!base)
      co_return std::unexpected(base.error());
    auto role = co_await sts_assume_role(loop, *base, _region, _role_arn, "vio-session", _external_id);
    if (!role)
      co_return std::unexpected(role.error());
    co_return to_credentials(*role);
  }

private:
  std::shared_ptr<credentials_provider_t> _base;
  std::string _region;
  std::string _role_arn;
  std::string _external_id;
};

// EC2/ECS instance-metadata credentials (the last-resort provider).
class instance_metadata_credentials_provider_t : public caching_credentials_provider_t
{
protected:
  task_t<std::expected<credentials_t, error_t>> fetch(event_loop_t &loop) override
  {
    auto r = co_await instance_metadata_credentials(loop);
    if (!r)
      co_return std::unexpected(r.error());
    co_return to_credentials(*r);
  }
};

// Build the provider for a single resolved profile (no environment / instance-metadata fallback -- the
// caller composes those). Returns nullptr when the profile itself configures no credential source. Recurses
// for an assume-role source_profile, bounded by `depth`.
std::shared_ptr<credentials_provider_t> build_profile_provider(const resolved_profile_t &rp, const std::string &aws_dir, const vio::detail::ini_file_t &config, const vio::detail::ini_file_t &credentials, int depth)
{
  switch (rp.source)
  {
  case credential_source_t::static_keys:
    return std::make_shared<static_credentials_provider_t>(credentials_t{rp.access_key_id, rp.secret_access_key, rp.session_token, std::nullopt});
  case credential_source_t::login_session:
  {
    std::string cache_dir;
    if (!aws_dir.empty())
      cache_dir = vio::detail::path_join(vio::detail::path_join(aws_dir, "login"), "cache");
    return std::make_shared<login_cache_credentials_provider_t>(rp.login_session, std::move(cache_dir));
  }
  case credential_source_t::sso:
  {
    // The bearer token is cached under ~/.aws/sso/cache/<sha1(session-name-or-start-url)>.json.
    const std::string cache_key = !rp.sso_session.empty() ? rp.sso_session : rp.sso_start_url;
    std::string token_path;
    if (!aws_dir.empty() && !cache_key.empty())
    {
      const std::string sha1hex = vio::crypto::to_hex(vio::crypto::sha1(to_span(cache_key)));
      token_path = vio::detail::path_join(vio::detail::path_join(vio::detail::path_join(aws_dir, "sso"), "cache"), sha1hex + ".json");
    }
    return std::make_shared<sso_credentials_provider_t>(rp.sso_region, rp.sso_account_id, rp.sso_role_name, std::move(token_path));
  }
  case credential_source_t::assume_role:
  {
    if (depth >= 4)
      return std::make_shared<error_credentials_provider_t>("assume-role source_profile chain is too deep (possible cycle)");
    std::shared_ptr<credentials_provider_t> base;
    if (!rp.source_profile.empty())
    {
      const resolved_profile_t src = resolve_profile(config, credentials, rp.source_profile);
      base = build_profile_provider(src, aws_dir, config, credentials, depth + 1);
    }
    if (!base)
      base = std::make_shared<environment_credentials_provider_t>();
    std::string region = rp.region.empty() ? std::string("us-east-1") : rp.region;
    return std::make_shared<assume_role_credentials_provider_t>(std::move(base), std::move(region), rp.role_arn, rp.external_id);
  }
  case credential_source_t::none:
    return nullptr;
  }
  return nullptr;
}
} // namespace

credential_chain_t resolve_credential_chain(std::optional<std::string> profile_opt)
{
  std::string profile = profile_opt.value_or(std::string());
  if (profile.empty())
    profile = getenv_str("AWS_PROFILE");
  if (profile.empty())
    profile = "default";

  auto home = vio::detail::home_dir();
  const std::string aws_dir = home ? vio::detail::path_join(*home, ".aws") : std::string();

  std::string config_path = getenv_str("AWS_CONFIG_FILE");
  if (config_path.empty() && !aws_dir.empty())
    config_path = vio::detail::path_join(aws_dir, "config");
  std::string creds_path = getenv_str("AWS_SHARED_CREDENTIALS_FILE");
  if (creds_path.empty() && !aws_dir.empty())
    creds_path = vio::detail::path_join(aws_dir, "credentials");

  vio::detail::ini_file_t config, credentials;
  if (!config_path.empty())
    if (auto text = vio::detail::read_file(config_path))
      config = vio::detail::parse_ini(*text);
  if (!creds_path.empty())
    if (auto text = vio::detail::read_file(creds_path))
      credentials = vio::detail::parse_ini(*text);

  const resolved_profile_t rp = resolve_profile(config, credentials, profile);

  credential_chain_t out;
  if (!rp.region.empty())
    out.region = rp.region;

  std::vector<std::shared_ptr<credentials_provider_t>> chain;
  // Environment variables are always consulted first (the standard AWS precedence).
  chain.push_back(std::make_shared<environment_credentials_provider_t>());

  if (auto profile_provider = build_profile_provider(rp, aws_dir, config, credentials, 0))
  {
    // The profile names a concrete source (static keys / `aws login` / SSO / assume-role). Surface its
    // error directly on failure -- e.g. "run `aws login`" -- rather than falling through to an instance-
    // metadata probe that would be meaningless (and slow) off EC2/ECS.
    chain.push_back(std::move(profile_provider));
  }
  else
  {
    // No profile-configured source: after the environment, try the container/instance metadata service.
    chain.push_back(std::make_shared<instance_metadata_credentials_provider_t>());
  }

  out.provider = std::make_shared<chain_credentials_provider_t>(std::move(chain));
  return out;
}

} // namespace vio::objstore
