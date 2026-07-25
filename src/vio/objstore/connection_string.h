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

// Vendor-neutral connection-string parsing for object stores. The grammar is a semicolon-separated list
// of key=value pairs, e.g.
//     region=eu-north-1;access_key_id=AKIA...;secret_access_key=...;endpoint=https://minio:9000
// Keys are case-insensitive (lowercased on parse); each pair is split on its FIRST '=' so a value may
// itself contain '='. Whitespace around keys and values is trimmed, empty entries (a stray ';') are
// ignored, and a duplicate key is an error. Interpreting the keys for a specific provider (S3, Azure) is
// done by resolve_s3_config / resolve_azure_config in create_object_store.h -- the grammar here is
// provider-agnostic; the provider is chosen by the URL scheme.

#include <vio/error.h>

#include <cctype>
#include <expected>
#include <initializer_list>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace vio::objstore
{

namespace conn_detail
{
inline std::string trim(std::string_view s)
{
  size_t b = 0, e = s.size();
  while (b < e && std::isspace(static_cast<unsigned char>(s[b])))
    ++b;
  while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1])))
    --e;
  return std::string(s.substr(b, e - b));
}

inline std::string to_lower(std::string s)
{
  for (auto &c : s)
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}

// Interpret a textual boolean. Recognizes 1/true/yes/on and 0/false/no/off (case-insensitive); anything
// else yields `fallback`.
inline bool parse_bool(std::string_view v, bool fallback)
{
  std::string l = to_lower(trim(v));
  if (l == "1" || l == "true" || l == "yes" || l == "on")
    return true;
  if (l == "0" || l == "false" || l == "no" || l == "off")
    return false;
  return fallback;
}
} // namespace conn_detail

struct connection_options_t
{
  std::unordered_map<std::string, std::string> values; // keys are lowercased

  // First present value among the given aliases (which must already be lowercase).
  [[nodiscard]] std::optional<std::string> get(std::initializer_list<std::string_view> aliases) const
  {
    for (auto a : aliases)
    {
      auto it = values.find(std::string(a));
      if (it != values.end())
        return it->second;
    }
    return std::nullopt;
  }

  [[nodiscard]] bool empty() const
  {
    return values.empty();
  }
};

// Parse a connection string (see the file header for the grammar). Errors on a malformed entry (no '=',
// empty key) or a duplicate key.
inline std::expected<connection_options_t, error_t> parse_connection_string(std::string_view s)
{
  connection_options_t out;
  size_t pos = 0;
  while (pos < s.size())
  {
    size_t semi = s.find(';', pos);
    std::string_view entry = (semi == std::string_view::npos) ? s.substr(pos) : s.substr(pos, semi - pos);
    pos = (semi == std::string_view::npos) ? s.size() : semi + 1;

    std::string trimmed = conn_detail::trim(entry);
    if (trimmed.empty())
      continue;
    auto eq = trimmed.find('=');
    if (eq == std::string::npos)
      return std::unexpected(error_t{.code = -1, .msg = "connection string entry missing '=': '" + trimmed + "'"});
    std::string key = conn_detail::to_lower(conn_detail::trim(std::string_view(trimmed).substr(0, eq)));
    std::string value = conn_detail::trim(std::string_view(trimmed).substr(eq + 1));
    if (key.empty())
      return std::unexpected(error_t{.code = -1, .msg = "connection string entry has an empty key"});
    if (!out.values.emplace(key, std::move(value)).second)
      return std::unexpected(error_t{.code = -1, .msg = "duplicate connection string key: '" + key + "'"});
  }
  return out;
}

} // namespace vio::objstore
