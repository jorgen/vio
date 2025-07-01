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

#include <array>

namespace vio
{
template <typename T, size_t size>
struct ring_buffer_t
{
  [[nodiscard]] bool empty() const
  {
    return _buffer_front == _buffer_back;
  }

  [[nodiscard]] bool full() const
  {
    return (_buffer_back + 1) % size == _buffer_front;
  }

  T &front()
  {
    assert(!empty());
    return _buffer_queue[_buffer_front];
  }
  const T &front() const
  {
    assert(!empty());
    return _buffer_queue[_buffer_front];
  }

  T pop_front()
  {
    assert(!empty());
    T ret = std::move(front());
    _buffer_queue[_buffer_front].~T();
    _buffer_front = (_buffer_front + 1) % size;
    return ret;
  }

  void discard_front()
  {
    assert(!empty());
    T ret = std::move(front());
    _buffer_queue[_buffer_front].~T();
    _buffer_front = (_buffer_front + 1) % size;
  }

  T &back()
  {
    assert(!empty());
    return _buffer_queue[(_buffer_back - 1 + size) % size];
  }
  const T &back() const
  {
    assert(!empty());
    return _buffer_queue[(_buffer_back - 1 + size) % size];
  }

  T &push(T &&value)
  {
    assert(!full());
    _buffer_queue[_buffer_back] = std::move(value);
    _buffer_back = (_buffer_back + 1) % size;
    return back();
  }
  T &push(const T &value)
  {
    assert(!full());
    _buffer_queue[_buffer_back] = value;
    _buffer_back = (_buffer_back + 1) % size;
    return back();
  }

  template <typename... Args>
  T &emplace(Args... args)
  {
    assert(!full());
    _buffer_queue[_buffer_back] = T(args...);
    _buffer_back = (_buffer_back + 1) % size;
    return _buffer_queue[_buffer_back];
  }

  T &replace_back(T &&value)
  {
    assert(!empty());
    _buffer_queue[_buffer_back] = std::move(value);
    return back();
  }

private:
  int _buffer_front = 0;
  int _buffer_back = 0;
  std::array<T, size> _buffer_queue;
};

} // namespace vio