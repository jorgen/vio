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

#include <type_traits>

namespace vio
{
template <typename T>
class bit_mask_t
{
  using U = typename std::underlying_type<T>::type;

public:
  constexpr bit_mask_t()
    : _flags()
  {
  }
  constexpr bit_mask_t(const bit_mask_t<T> &other) = default;

  template <typename... ARGS>
  bit_mask_t(T flag, ARGS... args)
    : bit_mask_t(args...)
  {
    _flags |= static_cast<U>(flag);
  }
  constexpr bit_mask_t(T flag)
    : _flags(static_cast<U>(flag))
  {
  }

  explicit constexpr bit_mask_t(U u)
    : _flags(u)
  {
  }

  constexpr bit_mask_t<T> operator~() const
  {
    return bit_mask(~_flags);
  }
  constexpr bit_mask_t<T> operator|(const bit_mask_t<T> &other) const
  {
    return bit_mask<T>(_flags | other._flags);
  }
  constexpr bit_mask_t<T> operator&(const bit_mask_t<T> &other) const
  {
    return bit_mask<T>(_flags & other._flags);
  }
  constexpr bit_mask_t<T> operator&(const T &other) const
  {
    return bit_mask<T>(_flags & static_cast<U>(other));
  }
  constexpr bit_mask_t<T> operator^(const bit_mask_t<T> &other) const
  {
    return bit_mask<T>(_flags ^ other._flags);
  }
  bit_mask_t<T> &operator|=(const bit_mask_t<T> &other)
  {
    _flags |= other._flags;
    return *this;
  }
  bit_mask_t<T> &operator&=(const bit_mask_t<T> &other)
  {
    _flags &= other._flags;
    return *this;
  }
  bit_mask_t<T> &operator^=(const bit_mask_t<T> &other)
  {
    _flags ^= other._flags;
    return *this;
  }

  constexpr operator bool() const
  {
    return _flags;
  }

  U value() const
  {
    return _flags;
  }

private:
  U _flags;
  template <typename V>
  friend constexpr bit_mask_t<V> operator|(V a, bit_mask_t<V> &b);
  template <typename V>
  friend constexpr bit_mask_t<V> operator&(V a, const bit_mask_t<V> &b);
  template <typename V>
  friend constexpr bit_mask_t<V> operator^(V a, const bit_mask_t<V> &b);
};

template <typename T>
constexpr bit_mask_t<T> operator|(T a, bit_mask_t<T> &b)
{
  return bit_mask_t<T>(static_cast<typename std::underlying_type<T>::type>(a) | b._flags);
}
template <typename T>
constexpr bit_mask_t<T> operator&(T a, const bit_mask_t<T> &b)
{
  return bit_mask_t<T>(static_cast<typename std::underlying_type<T>::type>(a) & b._flags);
}
template <typename T>
constexpr bit_mask_t<T> operator^(T a, const bit_mask_t<T> &b)
{
  return bit_mask_t<T>(static_cast<typename std::underlying_type<T>::type>(a) ^ b._flags);
}

// this is to eager
// template<typename T>
// constexpr  inline bit_mask<T> operator|(T a, T b) { return bit_mask<T>(static_cast<typename std::underlying_type<T>::type>(a) | static_cast<typename std::underlying_type<T>::type>(b)); }
// template<typename T>
// constexpr  inline bit_mask<T> operator&(T a, T b) { return bit_mask<T>(static_cast<typename std::underlying_type<T>::type>(a) & static_cast<typename std::underlying_type<T>::type>(b)); }
// template<typename T>
// constexpr  inline bit_mask<T> operator^(T a, T b) { return bit_mask<T>(static_cast<typename std::underlying_type<T>::type>(a) ^ static_cast<typename std::underlying_type<T>::type>(b)); }
} // namespace vio