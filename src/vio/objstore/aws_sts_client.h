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

// STS AssumeRole client: sign a POST with the base (source-profile) credentials via SigV4 and exchange a
// role ARN for temporary credentials. The response is XML; the four fields we need are extracted by
// targeted tag lookup (the tags are unprefixed in the AssumeRole response) rather than a full XML parser.
// Native only.

#include <vio/crypto.h>
#include <vio/detail/aws_time.h>
#include <vio/objstore/aws_json.h> // parsed_credentials_t
#include <vio/objstore/credentials.h>
#include <vio/objstore/signing.h>
#include <vio/operation/http_client.h>

#include <string>
#include <vector>

namespace vio::objstore
{
namespace sts_detail
{
// Extract the text content of the first <tag>...</tag> (unprefixed) in `xml`, or "" if absent.
inline std::string xml_tag(std::string_view xml, std::string_view tag)
{
  std::string open = "<" + std::string(tag) + ">";
  std::string close = "</" + std::string(tag) + ">";
  auto a = xml.find(open);
  if (a == std::string_view::npos)
    return {};
  a += open.size();
  auto b = xml.find(close, a);
  if (b == std::string_view::npos)
    return {};
  return std::string(xml.substr(a, b - a));
}

inline std::span<const uint8_t> bspan(std::string_view s)
{
  return {reinterpret_cast<const uint8_t *>(s.data()), s.size()};
}
} // namespace sts_detail

// Parse an STS AssumeRole XML response into credentials (accessKeyId / secretAccessKey / sessionToken /
// expiration).
inline std::expected<parsed_credentials_t, error_t> parse_sts_assume_role_xml(std::string_view xml)
{
  parsed_credentials_t out;
  out.access_key_id = sts_detail::xml_tag(xml, "AccessKeyId");
  out.secret_access_key = sts_detail::xml_tag(xml, "SecretAccessKey");
  out.session_token = sts_detail::xml_tag(xml, "SessionToken");
  if (out.access_key_id.empty() || out.secret_access_key.empty())
    return std::unexpected(error_t{.code = -1, .msg = "sts AssumeRole: no Credentials in response"});
  std::string exp = sts_detail::xml_tag(xml, "Expiration");
  if (!exp.empty())
    out.expiration = vio::detail::parse_iso8601_utc(exp);
  return out;
}

// Call STS AssumeRole with the base credentials, returning temporary role credentials.
inline task_t<std::expected<parsed_credentials_t, error_t>> sts_assume_role(event_loop_t &loop, const credentials_t &base, const std::string &region, const std::string &role_arn,
                                                                            const std::string &role_session_name, const std::string &external_id)
{
  const std::string sts_region = region.empty() ? std::string("us-east-1") : region;
  const std::string host = "sts." + sts_region + ".amazonaws.com";

  std::string body = "Action=AssumeRole&Version=2011-06-15&RoleArn=" + uri_encode(role_arn, false) + "&RoleSessionName=" + uri_encode(role_session_name, false);
  if (!external_id.empty())
    body += "&ExternalId=" + uri_encode(external_id, false);

  std::string amz_date, date_stamp;
  vio::detail::aws_utc_now(amz_date, date_stamp);
  std::string payload_sha = crypto::to_hex(crypto::sha256(sts_detail::bspan(body)));

  std::vector<signed_header_t> signed_headers = {
    {"host", host}, {"content-type", "application/x-www-form-urlencoded"}, {"x-amz-content-sha256", payload_sha}, {"x-amz-date", amz_date}};
  if (!base.session_token.empty())
    signed_headers.push_back({"x-amz-security-token", base.session_token});
  std::string authorization = aws_sigv4_authorization("POST", "/", "", signed_headers, payload_sha, base.access_key, base.secret_key, sts_region, "sts", amz_date, date_stamp);

  http::request_t req;
  req.method = "POST";
  req.url = "https://" + host + "/";
  req.headers.push_back({"x-amz-date", amz_date});
  req.headers.push_back({"x-amz-content-sha256", payload_sha});
  req.headers.push_back({"Content-Type", "application/x-www-form-urlencoded"});
  if (!base.session_token.empty())
    req.headers.push_back({"x-amz-security-token", base.session_token});
  req.headers.push_back({"Authorization", authorization});
  req.body = std::move(body);

  auto resp = co_await http::fetch(loop, req);
  if (!resp)
    co_return std::unexpected(resp.error());
  if (resp->status != 200)
    co_return std::unexpected(error_t{.code = -1, .msg = "sts AssumeRole failed: HTTP " + std::to_string(resp->status) + " " + resp->body.substr(0, 300)});
  co_return parse_sts_assume_role_xml(resp->body);
}

} // namespace vio::objstore
