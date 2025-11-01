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

#include "handle_closer.h"
#include <type_traits>
#include <utility>

namespace vio
{

template <typename T, typename = void>
struct has_reference_counted_first_param : std::false_type
{
};

template <template <typename...> class DataT, typename... ARGS>
struct has_reference_counted_first_param<DataT<ARGS...>, std::void_t<decltype(DataT<ARGS...>(std::declval<reference_counted_t &>(), std::declval<ARGS>()...))>> : std::true_type
{
};

template <typename T, typename... Args>
struct has_call_operator_impl
{
private:
  template <typename U>
  static auto test(int) -> decltype(std::declval<U>()(std::declval<Args>()...), std::true_type{});

  template <typename>
  static std::false_type test(...);

public:
  static constexpr bool value = decltype(test<T>(0))::value;
};

template <typename T, typename... Args>
inline constexpr bool has_call_operator = has_call_operator_impl<T, Args...>::value;

// Forward declaration
template <template <typename...> class DataT, bool HasParent, typename... ARGS>
class data_wrapper_impl_t;

// Primary template - wrapped version (reference counted)
template <template <typename...> class DataT, typename... ARGS>
class data_wrapper_impl_t<DataT, false, ARGS...>
{
  ref_counted_t<DataT<ARGS...>> data;

public:
  // Forward all constructors to the wrapped data type
  template <typename... CtorArgs>
  explicit data_wrapper_impl_t(CtorArgs &&...args)
    : data(new DataT<ARGS...>(std::forward<CtorArgs>(args)...))
  {
  }

  DataT<ARGS...> *operator->()
  {
    return data.get();
  }
  const DataT<ARGS...> *operator->() const
  {
    return data.get();
  }

  DataT<ARGS...> &get()
  {
    return *data;
  }
  const DataT<ARGS...> &get() const
  {
    return *data;
  }

  // Conditionally enable operator() if it exists on DataT
  template <typename... CallArgs>
  auto operator()(CallArgs &&...args) -> std::enable_if_t<has_call_operator<DataT<ARGS...>, CallArgs...>>
  {
    (*data)(std::forward<CallArgs>(args)...);
  }
};

// Specialization - flattened version (direct members)
template <template <typename...> class DataT, typename... ARGS>
class data_wrapper_impl_t<DataT, true, ARGS...> : public DataT<ARGS...>
{
public:
  // Forward all constructors to the base data type
  template <typename... CtorArgs>
  explicit data_wrapper_impl_t(CtorArgs &&...args)
    : DataT<ARGS...>(std::forward<CtorArgs>(args)...)
  {
  }

  DataT<ARGS...> *operator->()
  {
    return this;
  }
  const DataT<ARGS...> *operator->() const
  {
    return this;
  }

  DataT<ARGS...> &get()
  {
    return *this;
  }
  const DataT<ARGS...> &get() const
  {
    return *this;
  }

  // Conditionally enable operator() if it exists on DataT
  // For the flattened version, the base class operator() is already accessible
  template <typename... CallArgs>
  auto operator()(CallArgs &&...args) -> std::enable_if_t<has_call_operator<DataT<ARGS...>, CallArgs...>>
  {
    DataT<ARGS...>::operator()(std::forward<CallArgs>(args)...);
  }
};

// Type alias factory for creating wrappers around data types
template <template <typename...> class DataT, typename... ARGS>
using data_wrapper_t = data_wrapper_impl_t<DataT, has_reference_counted_first_param<DataT<ARGS...>>::value, ARGS...>;

} // namespace vio