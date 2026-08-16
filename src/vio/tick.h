/*
  Copyright (c) 2025 Jørgen Lind

  Permission is hereby granted, free of charge, to any person obtaining a copy of
  this software and associated documentation files (the "Software"), to deal in
  the Software without restriction, including without limitation the rights to
  use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
  of the Software, and to permit persons to whom the Software is furnished to do
  so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
*/

#pragma once

// A monotonic instant with an unspecified origin.
//
// tick_t exists so that time enters a protocol state machine only as a
// parameter, never by reading a clock: a machine that takes tick_t can be
// driven by a simulated clock in a test and by loop_now() in production, with
// no code path differing between the two.
//
// The origin is unspecified deliberately. Two tick_t values are only
// comparable if they came from the same producer, so the type does not convert
// to or from std::chrono::steady_clock -- uv_hrtime() and steady_clock have
// different zeroes, and mixing them yields differences that look plausible on
// one machine and are wildly wrong on another.

#include <chrono>
#include <compare>

namespace vio
{
class tick_t
{
public:
  constexpr tick_t() = default;

  static constexpr tick_t from_nanoseconds(std::chrono::nanoseconds since_origin)
  {
    return tick_t(since_origin);
  }

  [[nodiscard]] constexpr std::chrono::nanoseconds since_origin() const
  {
    return _since_origin;
  }

  constexpr tick_t &operator+=(std::chrono::nanoseconds delta)
  {
    _since_origin += delta;
    return *this;
  }

  constexpr tick_t &operator-=(std::chrono::nanoseconds delta)
  {
    _since_origin -= delta;
    return *this;
  }

  friend constexpr tick_t operator+(tick_t point, std::chrono::nanoseconds delta)
  {
    return tick_t(point._since_origin + delta);
  }

  friend constexpr tick_t operator-(tick_t point, std::chrono::nanoseconds delta)
  {
    return tick_t(point._since_origin - delta);
  }

  friend constexpr std::chrono::nanoseconds operator-(tick_t lhs, tick_t rhs)
  {
    return lhs._since_origin - rhs._since_origin;
  }

  friend constexpr bool operator==(tick_t lhs, tick_t rhs) = default;
  friend constexpr auto operator<=>(tick_t lhs, tick_t rhs) = default;

private:
  explicit constexpr tick_t(std::chrono::nanoseconds since_origin)
    : _since_origin(since_origin)
  {
  }

  std::chrono::nanoseconds _since_origin{};
};
} // namespace vio
