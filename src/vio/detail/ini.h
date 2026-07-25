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

// A minimal INI parser for the AWS shared config / credentials files (`~/.aws/config`,
// `~/.aws/credentials`). Grammar: `[section]` headers and `key = value` pairs; `#` and `;` start a
// line comment; blank lines are ignored; keys and values are trimmed. Section names are kept verbatim
// (so `[default]`, `[profile dev]`, `[sso-session my-sso]` are distinct) but matched case-insensitively;
// keys are lowercased. Sub-property indentation (used by some SDKs for nested settings) is not expanded
// -- these files never use it for the fields we read. This is deliberately not a general INI library.

#include <cctype>
#include <map>
#include <string>
#include <string_view>

namespace vio::detail
{

class ini_file_t
{
public:
  // section name (lowercased) -> (key (lowercased) -> raw trimmed value)
  std::map<std::string, std::map<std::string, std::string>> sections;

  // The value for `key` in `section`, or nullptr if absent. `section`/`key` are matched case-insensitively.
  [[nodiscard]] const std::string *get(std::string_view section, std::string_view key) const
  {
    auto s = sections.find(to_lower(section));
    if (s == sections.end())
      return nullptr;
    auto k = s->second.find(to_lower(key));
    return k == s->second.end() ? nullptr : &k->second;
  }

  [[nodiscard]] bool has_section(std::string_view section) const
  {
    return sections.find(to_lower(section)) != sections.end();
  }

  static std::string to_lower(std::string_view s)
  {
    std::string r(s);
    for (auto &c : r)
      c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return r;
  }

private:
  friend ini_file_t parse_ini(std::string_view);
};

namespace ini_detail
{
inline std::string_view trim(std::string_view s)
{
  size_t b = 0, e = s.size();
  while (b < e && std::isspace(static_cast<unsigned char>(s[b])))
    ++b;
  while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1])))
    --e;
  return s.substr(b, e - b);
}
} // namespace ini_detail

inline ini_file_t parse_ini(std::string_view text)
{
  ini_file_t out;
  std::string current; // lowercased current section; empty until the first header
  size_t pos = 0;
  while (pos < text.size())
  {
    size_t nl = text.find('\n', pos);
    std::string_view raw = (nl == std::string_view::npos) ? text.substr(pos) : text.substr(pos, nl - pos);
    pos = (nl == std::string_view::npos) ? text.size() : nl + 1;

    std::string_view line = ini_detail::trim(raw);
    if (line.empty() || line.front() == '#' || line.front() == ';')
      continue;

    if (line.front() == '[')
    {
      auto close = line.find(']');
      if (close == std::string_view::npos)
        continue; // malformed header; skip
      current = ini_file_t::to_lower(ini_detail::trim(line.substr(1, close - 1)));
      out.sections.try_emplace(current);
      continue;
    }

    if (current.empty())
      continue; // key/value before any section header -- ignore

    auto eq = line.find('=');
    if (eq == std::string_view::npos)
      continue; // not a key=value line
    std::string key = ini_file_t::to_lower(ini_detail::trim(line.substr(0, eq)));
    std::string value(ini_detail::trim(line.substr(eq + 1)));
    if (key.empty())
      continue;
    out.sections[current][key] = std::move(value);
  }
  return out;
}

} // namespace vio::detail
