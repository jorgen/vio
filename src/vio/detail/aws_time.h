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

// Time parsing for AWS credential expiry stamps. Two forms appear:
//   * ISO-8601 UTC strings, e.g. "2026-07-25T14:00:00Z" (login cache `expiresAt`, SSO token `expiresAt`).
//     A trailing fractional-second part and a "+00:00" offset are tolerated; only UTC is expected.
//   * Unix epoch milliseconds as a JSON number (SSO GetRoleCredentials `expiration`).

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <optional>
#include <string>
#include <string_view>

namespace vio::detail
{

using aws_time_point_t = std::chrono::system_clock::time_point;

// Convert a broken-down UTC calendar time to a time_point without touching the process TZ (timegm on
// POSIX, _mkgmtime on Windows).
inline aws_time_point_t from_utc_tm(std::tm &tm)
{
#if defined(_WIN32)
  std::time_t t = _mkgmtime(&tm);
#else
  std::time_t t = timegm(&tm);
#endif
  return std::chrono::system_clock::from_time_t(t);
}

// Parse an ISO-8601 UTC timestamp ("YYYY-MM-DDTHH:MM:SS[.fff][Z|+00:00]"). Returns nullopt if the leading
// "YYYY-MM-DDTHH:MM:SS" cannot be read. Fractional seconds and the zone suffix are accepted but the sub-
// second part is discarded (credential TTLs are whole seconds).
inline std::optional<aws_time_point_t> parse_iso8601_utc(std::string_view s)
{
  int year = 0, mon = 0, day = 0, hour = 0, min = 0, sec = 0;
  // sscanf needs a NUL-terminated buffer; the strings are short and fixed-shape.
  char buf[40];
  size_t n = s.size() < sizeof(buf) - 1 ? s.size() : sizeof(buf) - 1;
  for (size_t i = 0; i < n; ++i)
    buf[i] = s[i];
  buf[n] = '\0';
  if (std::sscanf(buf, "%4d-%2d-%2dT%2d:%2d:%2d", &year, &mon, &day, &hour, &min, &sec) != 6)
    return std::nullopt;
  std::tm tm{};
  tm.tm_year = year - 1900;
  tm.tm_mon = mon - 1;
  tm.tm_mday = day;
  tm.tm_hour = hour;
  tm.tm_min = min;
  tm.tm_sec = sec;
  return from_utc_tm(tm);
}

// A Unix epoch-milliseconds count to a time_point.
inline aws_time_point_t from_unix_millis(int64_t ms)
{
  return aws_time_point_t(std::chrono::milliseconds(ms));
}

// Current UTC time in the two numeric formats SigV4 needs: amz_date "YYYYMMDDTHHMMSSZ" and date_stamp
// "YYYYMMDD" (both locale-independent). Mirrors http_object_store.h's utc_now for the standalone signing
// done by the STS client.
inline void aws_utc_now(std::string &amz_date, std::string &date_stamp)
{
  std::time_t t = std::time(nullptr);
  std::tm g{};
#if defined(_WIN32)
  gmtime_s(&g, &t);
#else
  gmtime_r(&t, &g);
#endif
  char buf[32];
  std::snprintf(buf, sizeof(buf), "%04d%02d%02dT%02d%02d%02dZ", g.tm_year + 1900, g.tm_mon + 1, g.tm_mday, g.tm_hour, g.tm_min, g.tm_sec);
  amz_date = buf;
  std::snprintf(buf, sizeof(buf), "%04d%02d%02d", g.tm_year + 1900, g.tm_mon + 1, g.tm_mday);
  date_stamp = buf;
}

} // namespace vio::detail
