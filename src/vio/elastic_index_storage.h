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

#include "dynamic_bitset.h"
#include <cassert>
#include <queue>
#include <vector>

namespace vio
{
template <typename T, std::size_t PreferredSize = 10>
class elastic_index_storage_t
{
  static_assert(PreferredSize > 0, "PreferredSize must be greater than 0");

public:
  elastic_index_storage_t()
  {
    _used_bits.resize(PreferredSize);
    _processed_bits.resize(PreferredSize);
    _data.resize(PreferredSize);
  }

  std::size_t activate()
  {
    std::size_t idx = _used_bits.find_first_clear_bit();
    if (idx == dynamic_bitset_t::INVALID_INDEX)
    {
      grow_storage();
      idx = _used_bits.find_first_clear_bit();
    }
    if (_data.size() <= idx)
    {
      grow_storage();
    }
    _used_bits.set(idx);

    _processed_bits.clear(idx);
    _insertion_queue.push(idx);

    return idx;
  }

  std::size_t activate_with_value(const T &value)
  {
    std::size_t idx = activate();
    _data[idx] = value;
    return idx;
  }

  void deactivate(std::size_t index)
  {
    assert(index < _data.size() && "Index out of range");
    _data[index] = T();
    _used_bits.clear(index);

    if (std::size_t rightmost_active = _used_bits.find_rightmost_set_bit(); rightmost_active == dynamic_bitset_t::INVALID_INDEX || rightmost_active < PreferredSize)
    {
      resize_storage(PreferredSize);
    }
  }

  void deactivate_current()
  {
    assert(_insertion_queue.size() > 0 && "No current item");
    deactivate(_insertion_queue.front());
  }

  [[nodiscard]] bool current_item_is_active() const
  {
    return !_insertion_queue.empty() && _used_bits.test(_insertion_queue.front());
  }

  T &current_item()
  {
    assert(_insertion_queue.size() > 0 && "No current item");
    assert(_used_bits.test(_insertion_queue.front()) && "The current item is inactive.");
    return _data[_insertion_queue.front()];
  }

  bool next()
  {
    while (!_insertion_queue.empty())
    {
      _insertion_queue.pop();
      if (_insertion_queue.empty())
      {
        return false;
      }

      std::size_t candidate = _insertion_queue.front();
      assert(_processed_bits.test(candidate) == false);
      if (_used_bits.test(candidate))
      {
        _processed_bits.set(candidate);
        return true;
      }
    }
    return false;
  }

  T &operator[](std::size_t index)
  {
    assert(index < _data.size() && _used_bits.test(index) && "Invalid index access");
    return _data[index];
  }

  const T &operator[](std::size_t index) const
  {
    assert(index < _data.size() && _used_bits.test(index) && "Invalid index access");
    return _data[index];
  }

  [[nodiscard]] bool is_active(std::size_t index) const
  {
    return (index < _data.size() && _used_bits.test(index));
  }

  [[nodiscard]] bool is_processed(std::size_t index) const
  {
    return (index < _data.size() && _processed_bits.test(index));
  }

  [[nodiscard]] std::size_t size() const
  {
    return _data.size();
  }

private:
  void resize_storage(std::size_t new_size)
  {
    _used_bits.resize(new_size);
    _processed_bits.resize(new_size);
    _data.resize(new_size);
  }

  void grow_storage()
  {
    std::size_t new_size = _data.size() < 2 ? 2 : (_data.size() * 3 / 2);
    resize_storage(new_size);
  }

  std::vector<T> _data;

  dynamic_bitset_t _used_bits;
  dynamic_bitset_t _processed_bits;

  std::queue<std::size_t> _insertion_queue;
};
} // namespace vio