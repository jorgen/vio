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

#include <cstddef>
#include <span>
#include <utility>

namespace vio
{
using alloc_cb_t = std::span<std::byte> (*)(void *user_ptr, std::size_t suggested_size);
using dealloc_cb_t = void (*)(void *user_ptr, std::span<std::byte> buffer);

class unique_buf_t
{
public:
  unique_buf_t() = default;

  unique_buf_t(std::span<std::byte> buffer, dealloc_cb_t dealloc, void *user_handle) noexcept
    : _data(buffer.data())
    , _size(buffer.size())
    , _capacity(buffer.size())
    , _dealloc(dealloc)
    , _user_handle(user_handle)
  {
  }

  unique_buf_t(const unique_buf_t &) = delete;
  unique_buf_t &operator=(const unique_buf_t &) = delete;

  unique_buf_t(unique_buf_t &&other) noexcept
    : _data(std::exchange(other._data, nullptr))
    , _size(std::exchange(other._size, 0))
    , _capacity(std::exchange(other._capacity, 0))
    , _dealloc(std::exchange(other._dealloc, nullptr))
    , _user_handle(std::exchange(other._user_handle, nullptr))
  {
  }

  unique_buf_t &operator=(unique_buf_t &&other) noexcept
  {
    if (this != &other)
    {
      reset();
      _data = std::exchange(other._data, nullptr);
      _size = std::exchange(other._size, 0);
      _capacity = std::exchange(other._capacity, 0);
      _dealloc = std::exchange(other._dealloc, nullptr);
      _user_handle = std::exchange(other._user_handle, nullptr);
    }
    return *this;
  }

  ~unique_buf_t()
  {
    reset();
  }

  void reset() noexcept
  {
    if (_data && _dealloc)
      _dealloc(_user_handle, std::span<std::byte>(_data, _capacity));
    _data = nullptr;
    _size = 0;
    _capacity = 0;
    _dealloc = nullptr;
    _user_handle = nullptr;
  }

  void resize(std::size_t size) noexcept
  {
    _size = size <= _capacity ? size : _capacity;
  }

  [[nodiscard]] std::byte *data() const noexcept
  {
    return _data;
  }

  [[nodiscard]] char *chars() const noexcept
  {
    return reinterpret_cast<char *>(_data);
  }

  [[nodiscard]] std::size_t size() const noexcept
  {
    return _size;
  }

  [[nodiscard]] std::size_t capacity() const noexcept
  {
    return _capacity;
  }

  [[nodiscard]] bool empty() const noexcept
  {
    return _size == 0;
  }

  [[nodiscard]] std::span<std::byte> span() const noexcept
  {
    return {_data, _size};
  }

  [[nodiscard]] void *user_handle() const noexcept
  {
    return _user_handle;
  }

private:
  std::byte *_data = nullptr;
  std::size_t _size = 0;
  std::size_t _capacity = 0;
  dealloc_cb_t _dealloc = nullptr;
  void *_user_handle = nullptr;
};

inline std::span<std::byte> default_alloc(void * /*user_ptr*/, std::size_t suggested_size)
{
  return {new std::byte[suggested_size], suggested_size};
}

inline void default_dealloc(void * /*user_ptr*/, std::span<std::byte> buffer)
{
  delete[] buffer.data();
}

inline void noop_dealloc(void * /*user_ptr*/, std::span<std::byte> /*buffer*/)
{
}
} // namespace vio
