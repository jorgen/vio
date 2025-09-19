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

#include "uv.h"

#include <functional>
#include <vector>

namespace vio
{
struct reference_counted_t
{
  std::size_t ref_count{1};
  std::vector<std::function<void()>> destroy_callbacks;

  void inc()
  {
    ++ref_count;
  }

  bool dec()
  {
    if (--ref_count == 0)
    {
      auto callbacks = std::move(destroy_callbacks);
      for (auto it = callbacks.rbegin(); it != callbacks.rend(); ++it)
      {
        (*it)();
      }
      return ref_count == 0;
    }
    return false;
  }

  void register_destroy_callback(std::function<void()> callback)
  {
    destroy_callbacks.push_back(std::move(callback));
  }
};

template <typename UV_HANDLE_T>
struct handle_closer_t
{
  reference_counted_t &parent;
  UV_HANDLE_T handle;

  uv_handle_t *uv_handle()
  {
    return static_cast<uv_handle_t *>(&handle);
  }
};

} // namespace vio