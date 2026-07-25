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

// structify-backed implementation of the AWS JSON parsers declared in aws_json.h. structify is used only
// here so the dependency stays private to vio (consumers see only aws_json.h's plain structs). Each JSON
// shape is a local struct reflected with STFY_OBJECT; structify skips unknown fields and tolerates missing
// ones, so we validate the fields we require ourselves after a successful parse.

#include <vio/objstore/aws_json.h>

#include <structify/structify.h>

namespace vio::objstore
{
namespace
{
// --- login cache: ~/.aws/login/cache/<sha256(login_session)>.json ---------------------------------------
struct login_access_token_json_t
{
  std::string accessKeyId;
  std::string secretAccessKey;
  std::string sessionToken;
  std::string accountId;
  std::string expiresAt; // ISO-8601 UTC
  STFY_OBJECT(STFY_MEMBER(accessKeyId), STFY_MEMBER(secretAccessKey), STFY_MEMBER(sessionToken), STFY_MEMBER(accountId), STFY_MEMBER(expiresAt));
};

struct login_cache_json_t
{
  login_access_token_json_t accessToken;
  std::string tokenType;
  STFY_OBJECT(STFY_MEMBER(accessToken), STFY_MEMBER(tokenType));
};

// --- SSO GetRoleCredentials response --------------------------------------------------------------------
struct sso_role_credentials_json_t
{
  std::string accessKeyId;
  std::string secretAccessKey;
  std::string sessionToken;
  int64_t expiration = 0; // epoch milliseconds
  STFY_OBJECT(STFY_MEMBER(accessKeyId), STFY_MEMBER(secretAccessKey), STFY_MEMBER(sessionToken), STFY_MEMBER(expiration));
};

struct sso_role_credentials_response_json_t
{
  sso_role_credentials_json_t roleCredentials;
  STFY_OBJECT(STFY_MEMBER(roleCredentials));
};

// --- EC2/ECS instance-metadata credentials --------------------------------------------------------------
struct imds_credentials_json_t
{
  std::string AccessKeyId;
  std::string SecretAccessKey;
  std::string Token;
  std::string Expiration; // ISO-8601 UTC
  STFY_OBJECT(STFY_MEMBER(AccessKeyId), STFY_MEMBER(SecretAccessKey), STFY_MEMBER(Token), STFY_MEMBER(Expiration));
};

// --- classic SSO token cache: ~/.aws/sso/cache/<sha1>.json -----------------------------------------------
struct sso_token_cache_json_t
{
  std::string accessToken;
  std::string refreshToken;
  std::string clientId;
  std::string clientSecret;
  std::string region;
  std::string startUrl;
  std::string expiresAt; // ISO-8601 UTC
  STFY_OBJECT(STFY_MEMBER(accessToken), STFY_MEMBER(refreshToken), STFY_MEMBER(clientId), STFY_MEMBER(clientSecret), STFY_MEMBER(region), STFY_MEMBER(startUrl), STFY_MEMBER(expiresAt));
};

// --- OIDC CreateToken response --------------------------------------------------------------------------
struct oidc_create_token_json_t
{
  std::string accessToken;
  std::string refreshToken;
  int64_t expiresIn = 0; // seconds
  STFY_OBJECT(STFY_MEMBER(accessToken), STFY_MEMBER(refreshToken), STFY_MEMBER(expiresIn));
};

template <typename T>
bool parse_json(std::string_view json, T &out)
{
  STFY::ParseContext ctx(json.data(), json.size());
  return ctx.parseTo(out) == STFY::Error::NoError;
}

error_t make_error(std::string msg)
{
  return error_t{.code = -1, .msg = std::move(msg)};
}
} // namespace

std::expected<parsed_credentials_t, error_t> parse_login_cache(std::string_view json)
{
  login_cache_json_t doc;
  if (!parse_json(json, doc))
    return std::unexpected(make_error("aws login cache: invalid JSON"));
  if (doc.accessToken.accessKeyId.empty() || doc.accessToken.secretAccessKey.empty())
    return std::unexpected(make_error("aws login cache: missing accessToken credentials"));
  parsed_credentials_t out;
  out.access_key_id = std::move(doc.accessToken.accessKeyId);
  out.secret_access_key = std::move(doc.accessToken.secretAccessKey);
  out.session_token = std::move(doc.accessToken.sessionToken);
  if (!doc.accessToken.expiresAt.empty())
    out.expiration = vio::detail::parse_iso8601_utc(doc.accessToken.expiresAt);
  return out;
}

std::expected<parsed_credentials_t, error_t> parse_sso_role_credentials(std::string_view json)
{
  sso_role_credentials_response_json_t doc;
  if (!parse_json(json, doc))
    return std::unexpected(make_error("sso GetRoleCredentials: invalid JSON"));
  const auto &rc = doc.roleCredentials;
  if (rc.accessKeyId.empty() || rc.secretAccessKey.empty())
    return std::unexpected(make_error("sso GetRoleCredentials: missing roleCredentials"));
  parsed_credentials_t out;
  out.access_key_id = rc.accessKeyId;
  out.secret_access_key = rc.secretAccessKey;
  out.session_token = rc.sessionToken;
  if (rc.expiration > 0)
    out.expiration = vio::detail::from_unix_millis(rc.expiration);
  return out;
}

std::expected<parsed_credentials_t, error_t> parse_imds_credentials(std::string_view json)
{
  imds_credentials_json_t doc;
  if (!parse_json(json, doc))
    return std::unexpected(make_error("instance metadata credentials: invalid JSON"));
  if (doc.AccessKeyId.empty() || doc.SecretAccessKey.empty())
    return std::unexpected(make_error("instance metadata credentials: missing fields"));
  parsed_credentials_t out;
  out.access_key_id = std::move(doc.AccessKeyId);
  out.secret_access_key = std::move(doc.SecretAccessKey);
  out.session_token = std::move(doc.Token);
  if (!doc.Expiration.empty())
    out.expiration = vio::detail::parse_iso8601_utc(doc.Expiration);
  return out;
}

std::expected<sso_token_cache_t, error_t> parse_sso_token_cache(std::string_view json)
{
  sso_token_cache_json_t doc;
  if (!parse_json(json, doc))
    return std::unexpected(make_error("sso token cache: invalid JSON"));
  if (doc.accessToken.empty())
    return std::unexpected(make_error("sso token cache: missing accessToken"));
  sso_token_cache_t out;
  out.access_token = std::move(doc.accessToken);
  out.refresh_token = std::move(doc.refreshToken);
  out.client_id = std::move(doc.clientId);
  out.client_secret = std::move(doc.clientSecret);
  out.region = std::move(doc.region);
  out.start_url = std::move(doc.startUrl);
  if (!doc.expiresAt.empty())
    out.expires_at = vio::detail::parse_iso8601_utc(doc.expiresAt);
  return out;
}

std::expected<oidc_token_t, error_t> parse_oidc_create_token(std::string_view json)
{
  oidc_create_token_json_t doc;
  if (!parse_json(json, doc))
    return std::unexpected(make_error("oidc CreateToken: invalid JSON"));
  if (doc.accessToken.empty())
    return std::unexpected(make_error("oidc CreateToken: missing accessToken"));
  oidc_token_t out;
  out.access_token = std::move(doc.accessToken);
  out.refresh_token = std::move(doc.refreshToken);
  out.expires_in = doc.expiresIn;
  return out;
}

} // namespace vio::objstore
