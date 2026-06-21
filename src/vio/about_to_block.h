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

#include <functional>

namespace vio
{

class about_to_block_t
{
public:
  about_to_block_t() = default;
  about_to_block_t(const about_to_block_t &) = default;
  about_to_block_t(about_to_block_t &&) = default;
  about_to_block_t &operator=(const about_to_block_t &) = default;
  about_to_block_t &operator=(about_to_block_t &&) = default;
  virtual ~about_to_block_t() = default;

  virtual void about_to_block() = 0;

  template <typename Ret, typename Class, typename... Args>
  std::function<void(Args &&...)> bind(Ret (Class::*f)(Args &&...))
  {
    return [this, f](Args &&...args) { return ((*static_cast<Class *>(this)).*f)(std::move(args)...); };
  }
};

} // namespace vio
