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

// Small filesystem helpers used by the native AWS credential provider chain: locate the user's home
// directory, join paths, and read a whole (small) local file. These touch the filesystem with a plain
// std::ifstream -- the AWS config / credential / SSO-cache files are tiny, so the brief synchronous read
// on the loop thread is acceptable (unlike bulk object I/O, which goes through the async file layer).

#include <cstdlib>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>

namespace vio::detail
{

// The user's home directory, or nullopt if it cannot be determined. HOME on POSIX, USERPROFILE on Windows.
inline std::optional<std::string> home_dir()
{
#if defined(_WIN32)
  if (const char *up = std::getenv("USERPROFILE"); up && *up)
    return std::string(up);
  const char *drive = std::getenv("HOMEDRIVE");
  const char *path = std::getenv("HOMEPATH");
  if (drive && path)
    return std::string(drive) + path;
  return std::nullopt;
#else
  if (const char *home = std::getenv("HOME"); home && *home)
    return std::string(home);
  return std::nullopt;
#endif
}

// Join two path components with the platform separator, avoiding a doubled separator.
inline std::string path_join(std::string_view a, std::string_view b)
{
#if defined(_WIN32)
  constexpr char sep = '\\';
#else
  constexpr char sep = '/';
#endif
  if (a.empty())
    return std::string(b);
  if (b.empty())
    return std::string(a);
  std::string out(a);
  if (out.back() != '/' && out.back() != '\\')
    out.push_back(sep);
  if (b.front() == '/' || b.front() == '\\')
    b.remove_prefix(1);
  out.append(b);
  return out;
}

// Read an entire file into a string. nullopt if it cannot be opened (missing / no permission).
inline std::optional<std::string> read_file(const std::string &path)
{
  std::ifstream file(path, std::ios::binary);
  if (!file)
    return std::nullopt;
  return std::string(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
}

// Overwrite `path` with `content` (the directory must already exist). Returns false on failure. Used to
// persist a refreshed SSO token back to ~/.aws/sso/cache.
inline bool write_file(const std::string &path, std::string_view content)
{
  std::ofstream file(path, std::ios::binary | std::ios::trunc);
  if (!file)
    return false;
  file.write(content.data(), static_cast<std::streamsize>(content.size()));
  return static_cast<bool>(file);
}

} // namespace vio::detail
