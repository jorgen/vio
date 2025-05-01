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

namespace vio
{
template <typename T, typename Closer>
class auto_close_t
{
public:
  auto_close_t() noexcept
    : m_value()
    , m_closer(nullptr)
    , m_close(false)
  {
  }

  explicit auto_close_t(T &&value, Closer closer) noexcept
    : m_value(std::move(value))
    , m_closer(closer)
    , m_close(true)
  {
  }

  auto_close_t(const auto_close_t &) = delete;
  auto_close_t &operator=(const auto_close_t &) = delete;

  auto_close_t(auto_close_t &&other) noexcept
    : m_value(std::move(other.m_value))
    , m_closer(std::move(other.m_closer))
    , m_close(other.m_close)
  {
    other.m_close = false;
  }

  auto_close_t &operator=(auto_close_t &&other) noexcept
  {
    if (this != &other)
    {
      if (m_close)
        m_closer(&m_value);
      m_value = std::move(other.m_value);
      m_closer = std::move(other.m_closer);
      m_close = other.m_close;
      other.m_close = false;
    }
    return *this;
  }

  ~auto_close_t()
  {
    if (m_close)
      m_closer(&m_value);
  }

  T *operator->()
  {
    return &m_value;
  }
  const T *operator->() const
  {
    return &m_value;
  }

  T &operator*()
  {
    return m_value;
  }
  const T &operator*() const
  {
    return m_value;
  }

private:
  T m_value;
  Closer m_closer;
  bool m_close;
};

} // namespace vio