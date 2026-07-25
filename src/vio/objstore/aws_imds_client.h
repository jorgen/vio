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

// EC2/ECS instance-metadata credentials over plaintext HTTP to the link-local metadata service. ECS is
// preferred when its environment variables are present (a definitive container signal); otherwise IMDSv2
// (token PUT then GET) is used for EC2 instance-role credentials, unless disabled via the standard
// AWS_EC2_METADATA_DISABLED=true. On a machine that is neither ECS nor EC2 the metadata address is
// typically unreachable and this fails quickly, but there is no built-in timeout -- set
// AWS_EC2_METADATA_DISABLED=true to skip the EC2 probe entirely. Native only.

#include <vio/objstore/aws_json.h>
#include <vio/operation/http_client.h>

#include <cstdlib>
#include <string>

namespace vio::objstore
{
namespace imds_detail
{
inline std::string trim(std::string s)
{
  size_t b = 0, e = s.size();
  while (b < e && (s[b] == ' ' || s[b] == '\t' || s[b] == '\r' || s[b] == '\n'))
    ++b;
  while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t' || s[e - 1] == '\r' || s[e - 1] == '\n'))
    --e;
  return s.substr(b, e - b);
}
} // namespace imds_detail

// Fetch credentials from an ECS container-credentials endpoint (full URL, optional Authorization header).
inline task_t<std::expected<parsed_credentials_t, error_t>> ecs_container_credentials(event_loop_t &loop, const std::string &url, const std::string &authorization)
{
  http::request_t req;
  req.method = "GET";
  req.url = url;
  req.allow_plaintext = true;
  if (!authorization.empty())
    req.headers.push_back({"Authorization", authorization});
  auto resp = co_await http::fetch(loop, req);
  if (!resp)
    co_return std::unexpected(resp.error());
  if (resp->status != 200)
    co_return std::unexpected(error_t{.code = -1, .msg = "ecs container credentials failed: HTTP " + std::to_string(resp->status) + " " + resp->body.substr(0, 200)});
  co_return parse_imds_credentials(resp->body);
}

// Fetch EC2 instance-role credentials via IMDSv2 (session-token PUT, then role lookup, then credentials).
inline task_t<std::expected<parsed_credentials_t, error_t>> imdsv2_credentials(event_loop_t &loop)
{
  const std::string base = "http://169.254.169.254";

  http::request_t token_req;
  token_req.method = "PUT";
  token_req.url = base + "/latest/api/token";
  token_req.allow_plaintext = true;
  token_req.headers.push_back({"X-aws-ec2-metadata-token-ttl-seconds", "21600"});
  auto token_resp = co_await http::fetch(loop, token_req);
  if (!token_resp)
    co_return std::unexpected(token_resp.error());
  if (token_resp->status != 200 || token_resp->body.empty())
    co_return std::unexpected(error_t{.code = -1, .msg = "IMDSv2 token request failed: HTTP " + std::to_string(token_resp->status)});
  const std::string token = imds_detail::trim(token_resp->body);

  http::request_t role_req;
  role_req.method = "GET";
  role_req.url = base + "/latest/meta-data/iam/security-credentials/";
  role_req.allow_plaintext = true;
  role_req.headers.push_back({"X-aws-ec2-metadata-token", token});
  auto role_resp = co_await http::fetch(loop, role_req);
  if (!role_resp)
    co_return std::unexpected(role_resp.error());
  if (role_resp->status != 200)
    co_return std::unexpected(error_t{.code = -1, .msg = "IMDS role lookup failed: HTTP " + std::to_string(role_resp->status)});
  const std::string role = imds_detail::trim(role_resp->body);
  if (role.empty())
    co_return std::unexpected(error_t{.code = -1, .msg = "IMDS: no instance role attached"});

  http::request_t cred_req;
  cred_req.method = "GET";
  cred_req.url = base + "/latest/meta-data/iam/security-credentials/" + role;
  cred_req.allow_plaintext = true;
  cred_req.headers.push_back({"X-aws-ec2-metadata-token", token});
  auto cred_resp = co_await http::fetch(loop, cred_req);
  if (!cred_resp)
    co_return std::unexpected(cred_resp.error());
  if (cred_resp->status != 200)
    co_return std::unexpected(error_t{.code = -1, .msg = "IMDS credentials failed: HTTP " + std::to_string(cred_resp->status)});
  co_return parse_imds_credentials(cred_resp->body);
}

// Resolve credentials from the container (ECS) or instance (EC2) metadata service.
inline task_t<std::expected<parsed_credentials_t, error_t>> instance_metadata_credentials(event_loop_t &loop)
{
  if (const char *rel = std::getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"); rel && *rel)
  {
    const char *auth = std::getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN");
    co_return co_await ecs_container_credentials(loop, std::string("http://169.254.170.2") + rel, auth ? auth : "");
  }
  if (const char *full = std::getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI"); full && *full)
  {
    const char *auth = std::getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN");
    co_return co_await ecs_container_credentials(loop, full, auth ? auth : "");
  }
  if (const char *dis = std::getenv("AWS_EC2_METADATA_DISABLED"); dis && std::string(dis) == "true")
    co_return std::unexpected(error_t{.code = -1, .msg = "no credentials found and EC2 instance metadata is disabled (AWS_EC2_METADATA_DISABLED=true)"});
  co_return co_await imdsv2_credentials(loop);
}

} // namespace vio::objstore
