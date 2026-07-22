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

#include <vio/crypto.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

// Request signing for the cloud object stores: AWS Signature Version 4 (S3) and Azure Blob Shared Key.
// Pure functions over vio::crypto, unit-testable against published vectors.
namespace vio::objstore
{

struct signed_header_t
{
  std::string name;
  std::string value;
};

namespace detail
{
inline std::span<const uint8_t> bspan(std::string_view s)
{
  return {reinterpret_cast<const uint8_t *>(s.data()), s.size()};
}
inline std::span<const uint8_t> bspan(const crypto::sha256_digest_t &d)
{
  return {d.data(), d.size()};
}
inline std::string to_lower(std::string_view s)
{
  std::string r(s);
  for (auto &c : r)
    c = char(std::tolower(static_cast<unsigned char>(c)));
  return r;
}
inline std::string trim(std::string_view s)
{
  size_t a = 0, b = s.size();
  while (a < b && (s[a] == ' ' || s[a] == '\t'))
    a++;
  while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t'))
    b--;
  return std::string(s.substr(a, b - a));
}
} // namespace detail

// RFC 3986 percent-encoding. When keep_slash is true, '/' is left unescaped (for a canonical URI
// path); the unreserved characters A-Za-z0-9 - _ . ~ are never escaped.
inline std::string uri_encode(std::string_view s, bool keep_slash)
{
  static const char *hex = "0123456789ABCDEF";
  std::string out;
  out.reserve(s.size() * 3);
  for (unsigned char c : s)
  {
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~')
      out.push_back(char(c));
    else if (c == '/' && keep_slash)
      out.push_back('/');
    else
    {
      out.push_back('%');
      out.push_back(hex[c >> 4]);
      out.push_back(hex[c & 0xF]);
    }
  }
  return out;
}

// AWS Signature Version 4. Returns the value for the Authorization header. `headers` must contain
// exactly the headers to be signed (e.g. host, x-amz-date, x-amz-content-sha256) and must also be sent
// on the wire. canonical_uri is the already-encoded path; canonical_query is "" for a plain object op.
inline std::string aws_sigv4_authorization(const std::string &method, const std::string &canonical_uri, const std::string &canonical_query, const std::vector<signed_header_t> &headers,
                                           const std::string &payload_sha256_hex, const std::string &access_key, const std::string &secret_key, const std::string &region, const std::string &service,
                                           const std::string &amz_date, const std::string &date_stamp)
{
  using namespace detail;
  std::vector<std::pair<std::string, std::string>> hs;
  hs.reserve(headers.size());
  for (const auto &h : headers)
    hs.emplace_back(to_lower(h.name), trim(h.value));
  std::sort(hs.begin(), hs.end(), [](const auto &a, const auto &b) { return a.first < b.first; });

  std::string canonical_headers;
  std::string signed_headers;
  for (size_t i = 0; i < hs.size(); i++)
  {
    canonical_headers += hs[i].first + ":" + hs[i].second + "\n";
    if (i)
      signed_headers += ";";
    signed_headers += hs[i].first;
  }

  std::string canonical_request = method + "\n" + canonical_uri + "\n" + canonical_query + "\n" + canonical_headers + "\n" + signed_headers + "\n" + payload_sha256_hex;
  std::string cr_hash = crypto::to_hex(crypto::sha256(bspan(canonical_request)));

  std::string scope = date_stamp + "/" + region + "/" + service + "/aws4_request";
  std::string string_to_sign = std::string("AWS4-HMAC-SHA256\n") + amz_date + "\n" + scope + "\n" + cr_hash;

  std::string k0 = "AWS4" + secret_key;
  auto k_date = crypto::hmac_sha256(bspan(k0), bspan(date_stamp));
  auto k_region = crypto::hmac_sha256(bspan(k_date), bspan(region));
  auto k_service = crypto::hmac_sha256(bspan(k_region), bspan(service));
  auto k_signing = crypto::hmac_sha256(bspan(k_service), bspan(std::string_view("aws4_request")));
  std::string signature = crypto::to_hex(crypto::hmac_sha256(bspan(k_signing), bspan(string_to_sign)));

  return "AWS4-HMAC-SHA256 Credential=" + access_key + "/" + scope + ", SignedHeaders=" + signed_headers + ", Signature=" + signature;
}

// Azure Blob "Shared Key" authorization. Returns "SharedKey <account>:<base64-signature>".
// canonical_resource is "/<account><uri-path>" (plus any sorted query, "\nname:value"). x_ms_headers
// are the x-ms-* headers to canonicalize. content_length is "" for GET/HEAD/DELETE (and a zero-length
// body); range is "" or "bytes=a-b".
inline std::string azure_sharedkey_authorization(const std::string &method, const std::string &account, const std::string &account_key_base64, const std::string &canonical_resource,
                                                 const std::vector<signed_header_t> &x_ms_headers, const std::string &content_length, const std::string &content_type, const std::string &range)
{
  using namespace detail;
  std::vector<std::pair<std::string, std::string>> hs;
  hs.reserve(x_ms_headers.size());
  for (const auto &h : x_ms_headers)
    hs.emplace_back(to_lower(h.name), trim(h.value));
  std::sort(hs.begin(), hs.end(), [](const auto &a, const auto &b) { return a.first < b.first; });

  std::string canonical_headers;
  for (const auto &h : hs)
    canonical_headers += h.first + ":" + h.second + "\n";

  std::string sts = method + "\n"           // VERB
                    + "\n"                   // Content-Encoding
                    + "\n"                   // Content-Language
                    + content_length + "\n"  // Content-Length ("" when zero)
                    + "\n"                   // Content-MD5
                    + content_type + "\n"    // Content-Type
                    + "\n"                   // Date (empty; x-ms-date is used)
                    + "\n"                   // If-Modified-Since
                    + "\n"                   // If-Match
                    + "\n"                   // If-None-Match
                    + "\n"                   // If-Unmodified-Since
                    + range + "\n"           // Range
                    + canonical_headers      // CanonicalizedHeaders (each ends with \n)
                    + canonical_resource;    // CanonicalizedResource

  auto key = crypto::base64_decode(account_key_base64);
  if (!key.has_value())
    return {};
  auto sig = crypto::hmac_sha256(std::span<const uint8_t>(key->data(), key->size()), bspan(sts));
  return "SharedKey " + account + ":" + crypto::base64_encode(bspan(sig));
}

} // namespace vio::objstore
