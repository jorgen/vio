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

// Keeping a caller's bytes alive for the lifetime of a write.
//
// A cancellable write resumes its awaiter early while the in-flight uv write is
// still reading the buffer, so vio must own the bytes until the real write
// callback fires. owned_payload_t type-erases the lifetime of an arbitrary
// moved-in buffer (std::string, std::vector, or any owning contiguous byte
// range); the write reads a uv_buf_t computed from it at submit time.

#include <concepts>
#include <ranges>
#include <type_traits>
#include <utility>

namespace vio
{
struct owned_payload_t
{
  virtual ~owned_payload_t() = default;
};

template <typename T>
struct owned_payload_impl_t : owned_payload_t
{
  T value;
  explicit owned_payload_impl_t(T &&v)
    : value(std::move(v))
  {
  }
};

template <typename T>
concept owned_byte_range = std::ranges::contiguous_range<T> && std::ranges::sized_range<T> && std::move_constructible<T> && sizeof(std::ranges::range_value_t<T>) == 1 &&
                           std::is_trivially_copyable_v<std::ranges::range_value_t<T>> && !std::ranges::view<std::remove_cvref_t<T>>;
} // namespace vio
