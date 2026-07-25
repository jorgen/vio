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

// Parsers for the small AWS JSON documents the credential chain reads: the `aws login` cache, the classic
// SSO token cache, the SSO-portal GetRoleCredentials response, the OIDC CreateToken response, and the
// EC2/ECS instance-metadata credentials. The parsing is done with structify (a struct-reflection JSON
// library) in aws_credentials.cpp; that dependency is kept entirely inside the .cpp so consumers of vio
// never see it -- these declarations return plain structs. Each parser tolerates unknown extra fields
// (e.g. the login cache's dpopKey / idToken / refreshToken, which the chain does not use).

#include <vio/detail/aws_time.h>
#include <vio/error.h>
#include <vio/vio_export.h>

#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>

namespace vio::objstore
{

// SigV4 credentials extracted from a cache file / API response.
struct parsed_credentials_t
{
  std::string access_key_id;
  std::string secret_access_key;
  std::string session_token;
  std::optional<vio::detail::aws_time_point_t> expiration;
};

// `~/.aws/login/cache/<sha256(login_session)>.json`: nested accessToken.{accessKeyId,secretAccessKey,
// sessionToken,expiresAt(ISO-8601)}. Fails if the SigV4 fields are absent.
VIO_EXPORT std::expected<parsed_credentials_t, error_t> parse_login_cache(std::string_view json);

// SSO-portal GetRoleCredentials response: roleCredentials.{accessKeyId,secretAccessKey,sessionToken,
// expiration(epoch ms)}.
VIO_EXPORT std::expected<parsed_credentials_t, error_t> parse_sso_role_credentials(std::string_view json);

// EC2/ECS instance-metadata credentials document: {AccessKeyId,SecretAccessKey,Token,Expiration(ISO-8601)}.
VIO_EXPORT std::expected<parsed_credentials_t, error_t> parse_imds_credentials(std::string_view json);

// Classic `~/.aws/sso/cache/<sha1>.json` bearer-token cache.
struct sso_token_cache_t
{
  std::string access_token;
  std::string refresh_token;
  std::string client_id;
  std::string client_secret;
  std::string region;
  std::string start_url;
  std::optional<vio::detail::aws_time_point_t> expires_at;
};

VIO_EXPORT std::expected<sso_token_cache_t, error_t> parse_sso_token_cache(std::string_view json);

// OIDC CreateToken response (SSO token refresh): {accessToken,expiresIn(seconds),refreshToken}.
struct oidc_token_t
{
  std::string access_token;
  std::string refresh_token;
  int64_t expires_in = 0;
};

VIO_EXPORT std::expected<oidc_token_t, error_t> parse_oidc_create_token(std::string_view json);

} // namespace vio::objstore
