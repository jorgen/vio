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

// Thin coroutine clients for the two IAM Identity Center (classic SSO) endpoints the credential chain
// needs: the SSO portal's GetRoleCredentials (exchange a bearer token for temporary role credentials) and
// OIDC CreateToken with grant_type=refresh_token (renew the bearer token). Both are HTTPS calls over
// vio::http::fetch; responses are parsed by aws_json.h. Native only.

#include <vio/objstore/aws_json.h>
#include <vio/objstore/signing.h> // uri_encode
#include <vio/operation/http_client.h>

#include <string>

namespace vio::objstore
{
namespace sso_detail
{
// Escape a string for inclusion inside a JSON string literal (enough for the opaque token/id/secret
// values sent in the OIDC request body).
inline std::string json_escape(std::string_view s)
{
  std::string out;
  out.reserve(s.size() + 8);
  for (char c : s)
  {
    switch (c)
    {
    case '"':
      out += "\\\"";
      break;
    case '\\':
      out += "\\\\";
      break;
    case '\n':
      out += "\\n";
      break;
    case '\r':
      out += "\\r";
      break;
    case '\t':
      out += "\\t";
      break;
    default:
      if (static_cast<unsigned char>(c) < 0x20)
      {
        static const char *hex = "0123456789abcdef";
        out += "\\u00";
        out += hex[(c >> 4) & 0xF];
        out += hex[c & 0xF];
      }
      else
        out += c;
    }
  }
  return out;
}
} // namespace sso_detail

// Exchange a valid SSO bearer token for temporary role credentials via the SSO portal.
inline task_t<std::expected<parsed_credentials_t, error_t>> sso_get_role_credentials(event_loop_t &loop, const std::string &sso_region, const std::string &access_token, const std::string &account_id,
                                                                                     const std::string &role_name)
{
  http::request_t req;
  req.method = "GET";
  req.url = "https://portal.sso." + sso_region + ".amazonaws.com/federation/credentials?role_name=" + uri_encode(role_name, false) + "&account_id=" + uri_encode(account_id, false);
  req.headers.push_back({"x-amz-sso_bearer_token", access_token});
  req.headers.push_back({"Accept", "application/json"});

  auto resp = co_await http::fetch(loop, req);
  if (!resp)
    co_return std::unexpected(resp.error());
  if (resp->status != 200)
    co_return std::unexpected(error_t{.code = -1, .msg = "sso GetRoleCredentials failed: HTTP " + std::to_string(resp->status) + " " + resp->body.substr(0, 300)});
  co_return parse_sso_role_credentials(resp->body);
}

// Renew an SSO bearer token using the stored refresh token (OIDC CreateToken, grant_type=refresh_token).
inline task_t<std::expected<oidc_token_t, error_t>> oidc_create_token(event_loop_t &loop, const std::string &sso_region, const std::string &client_id, const std::string &client_secret,
                                                                      const std::string &refresh_token)
{
  http::request_t req;
  req.method = "POST";
  req.url = "https://oidc." + sso_region + ".amazonaws.com/token";
  req.headers.push_back({"Content-Type", "application/json"});
  req.body = std::string("{\"clientId\":\"") + sso_detail::json_escape(client_id) + "\",\"clientSecret\":\"" + sso_detail::json_escape(client_secret) + "\",\"grantType\":\"refresh_token\",\"refreshToken\":\"" +
             sso_detail::json_escape(refresh_token) + "\"}";

  auto resp = co_await http::fetch(loop, req);
  if (!resp)
    co_return std::unexpected(resp.error());
  if (resp->status != 200)
    co_return std::unexpected(error_t{.code = -1, .msg = "sso OIDC CreateToken failed: HTTP " + std::to_string(resp->status) + " " + resp->body.substr(0, 300)});
  co_return parse_oidc_create_token(resp->body);
}

} // namespace vio::objstore
