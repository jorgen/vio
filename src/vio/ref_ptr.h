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

#include <atomic>
#include <utility>

template <typename T>
struct refcounted_allocation_t
{
  std::atomic<int> refcount;
  T object;

  template <typename... Args>
  explicit refcounted_allocation_t(Args &&...args)
    : refcount(1)
    , object(std::forward<Args>(args)...)
  {
  }

  explicit refcounted_allocation_t(const T &obj)
    : refcount(1)
    , object(obj)
  {
  }

  explicit refcounted_allocation_t(T &&obj)
    : refcount(1)
    , object(std::move(obj))
  {
  }

  void ref()
  {
    refcount.fetch_add(1, std::memory_order_relaxed);
  }

  void unref()
  {
    if (refcount.fetch_sub(1, std::memory_order_acquire) == 1)
    {
      std::atomic_thread_fence(std::memory_order_release);
      delete this;
    }
  }
};

template <typename T>
class ref_ptr_t
{
public:
  ref_ptr_t()
    : alloc_ptr_(nullptr)
  {
  }

  explicit ref_ptr_t(const T &obj)
  {
    alloc_ptr_ = new refcounted_allocation_t<T>(obj);
  }

  explicit ref_ptr_t(T &&obj)
  {
    alloc_ptr_ = new refcounted_allocation_t<T>(std::move(obj));
  }

  ref_ptr_t(const ref_ptr_t &other)
  {
    alloc_ptr_ = other.alloc_ptr_;
    if (alloc_ptr_ != nullptr)
    {
      alloc_ptr_->ref();
    }
  }

  ref_ptr_t(ref_ptr_t &&other) noexcept
  {
    alloc_ptr_ = other.alloc_ptr_;
    other.alloc_ptr_ = nullptr;
  }

  ~ref_ptr_t()
  {
    if (alloc_ptr_ != nullptr)
    {
      alloc_ptr_->unref();
    }
  }

  ref_ptr_t &operator=(const ref_ptr_t &other)
  {
    if (this != &other)
    {
      if (alloc_ptr_ != nullptr)
      {
        alloc_ptr_->unref();
      }
      alloc_ptr_ = other.alloc_ptr_;
      if (alloc_ptr_ != nullptr)
      {
        alloc_ptr_->ref();
      }
    }
    return *this;
  }

  ref_ptr_t &operator=(ref_ptr_t &&other) noexcept
  {
    if (this != &other)
    {
      if (alloc_ptr_ != nullptr)
      {
        alloc_ptr_->unref();
      }
      alloc_ptr_ = other.alloc_ptr_;
      other.alloc_ptr_ = nullptr;
    }
    return *this;
  }

  T *ptr()
  {
    return alloc_ptr_ ? &alloc_ptr_->object : nullptr;
  }

  const T *ptr() const
  {
    return alloc_ptr_ ? &alloc_ptr_->object : nullptr;
  }

  T *operator->()
  {
    return alloc_ptr_ ? &alloc_ptr_->object : nullptr;
  }

  const T *operator->() const
  {
    return alloc_ptr_ ? &alloc_ptr_->object : nullptr;
  }

  T &operator*()
  {
    return alloc_ptr_->object;
  }

  const T &operator*() const
  {
    return alloc_ptr_->object;
  }

  void *release_to_raw()
  {
    refcounted_allocation_t<T> *temp = alloc_ptr_;
    alloc_ptr_ = nullptr;
    return temp;
  }

  static ref_ptr_t from_raw(void *raw_ptr)
  {
    ref_ptr_t tmp;
    tmp.alloc_ptr_ = static_cast<refcounted_allocation_t<T> *>(raw_ptr);
    return tmp;
  }

  template <typename... Args>
  ref_ptr_t make_ref_ptr(Args &&...args)
  {
    ref_ptr_t tmp;
    tmp.alloc_ptr_ = new refcounted_allocation_t<T>(std::forward<Args>(args)...);
    return tmp;
  }

private:
  refcounted_allocation_t<T> *alloc_ptr_;
};

template <typename T, typename... Args>
ref_ptr_t<T> make_ref_ptr(Args &&...args)
{
  return ref_ptr_t<T>().make_ref_ptr(std::forward<Args>(args)...);
}