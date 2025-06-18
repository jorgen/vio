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
using alloc_cb_t = void (*)(void *user_ptr, size_t suggested_size, uv_buf_t *buf);
using dealloc_cb_t = void (*)(void *user_ptr, uv_buf_t *buf);
struct unique_buf_t
{
  uv_buf_t buf{};
  dealloc_cb_t dealloc_cb{};
  void *user_handle{};
  unique_buf_t() = default;
  unique_buf_t(uv_buf_t b, dealloc_cb_t cb, void *handle)
    : buf(b)
    , dealloc_cb(cb)
    , user_handle(handle)
  {
  }
  unique_buf_t(const unique_buf_t &) = delete;
  unique_buf_t &operator=(const unique_buf_t &) = delete;
  unique_buf_t(unique_buf_t &&other) noexcept
    : buf(other.buf)
    , dealloc_cb(other.dealloc_cb)
    , user_handle(other.user_handle)
  {
    other.buf.base = nullptr;
    other.dealloc_cb = nullptr;
    other.user_handle = nullptr;
  }
  unique_buf_t &operator=(unique_buf_t &&other) noexcept
  {
    if (this != &other)
    {
      if (buf.base && dealloc_cb)
        dealloc_cb(user_handle, &buf);
      buf = other.buf;
      dealloc_cb = other.dealloc_cb;
      user_handle = other.user_handle;
      other.buf.base = nullptr;
      other.dealloc_cb = nullptr;
      other.user_handle = nullptr;
    }
    return *this;
  }
  ~unique_buf_t()
  {
    if (buf.base && dealloc_cb)
      dealloc_cb(user_handle, &buf);
  }

  uv_buf_t *operator->()
  {
    return &buf;
  }
};

inline void default_alloc(void *, size_t suggested_size, uv_buf_t *buf)
{
  if (buf == nullptr)
  {
    return;
  }
  buf->base = new char[suggested_size];
  buf->len = suggested_size;
}

inline void default_dealloc(void *, uv_buf_t *data)
{
  delete[] data->base;
  data->base = nullptr;
  data->len = 0;
}

} // namespace vio