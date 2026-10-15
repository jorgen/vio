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

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <vector>

namespace vio::detail
{
template <typename Rep, typename Period>
[[nodiscard]] std::int64_t delay_nanoseconds(std::chrono::duration<Rep, Period> delay) noexcept
{
  constexpr double saturation = 9.2e18;
  if (!(delay > std::chrono::duration<Rep, Period>::zero()))
    return 0;
  if (!(std::chrono::duration<double, std::nano>(delay).count() < saturation))
    return std::numeric_limits<std::int64_t>::max();
  return static_cast<std::int64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(delay).count());
}

struct timer_node_t
{
  using fire_fn_t = void (*)(timer_node_t *node);
  static constexpr std::size_t not_armed = std::numeric_limits<std::size_t>::max();

  fire_fn_t fire = nullptr;
  void *owner = nullptr;
  std::int64_t deadline = 0;
  std::uint64_t sequence = 0;
  std::size_t index = not_armed;
  bool keeps_alive = true;

  [[nodiscard]] bool armed() const noexcept
  {
    return index != not_armed;
  }
};

class timer_heap_t
{
public:
  [[nodiscard]] bool empty() const noexcept
  {
    return _heap.empty();
  }

  [[nodiscard]] std::size_t size() const noexcept
  {
    return _heap.size();
  }

  [[nodiscard]] timer_node_t *top() const noexcept
  {
    return _heap.empty() ? nullptr : _heap.front();
  }

  [[nodiscard]] std::uint64_t next_sequence() const noexcept
  {
    return _next_sequence;
  }

  void insert(timer_node_t &node)
  {
    node.sequence = _next_sequence++;
    _heap.push_back(&node);
    node.index = _heap.size() - 1;
    sift_up(node.index);
  }

  void erase(timer_node_t &node) noexcept
  {
    if (!node.armed())
      return;
    auto index = node.index;
    auto *last = _heap.back();
    _heap.pop_back();
    node.index = timer_node_t::not_armed;
    if (last == &node)
      return;
    place(index, last);
    if (index > 0 && before(_heap[index], _heap[(index - 1) / 2]))
      sift_up(index);
    else
      sift_down(index);
  }

private:
  static bool before(const timer_node_t *a, const timer_node_t *b) noexcept
  {
    return a->deadline < b->deadline || (a->deadline == b->deadline && a->sequence < b->sequence);
  }

  void place(std::size_t index, timer_node_t *node) noexcept
  {
    _heap[index] = node;
    node->index = index;
  }

  void sift_up(std::size_t index) noexcept
  {
    auto *node = _heap[index];
    while (index > 0)
    {
      auto parent = (index - 1) / 2;
      if (!before(node, _heap[parent]))
        break;
      place(index, _heap[parent]);
      index = parent;
    }
    place(index, node);
  }

  void sift_down(std::size_t index) noexcept
  {
    auto *node = _heap[index];
    auto count = _heap.size();
    for (;;)
    {
      auto child = index * 2 + 1;
      if (child >= count)
        break;
      if (child + 1 < count && before(_heap[child + 1], _heap[child]))
        ++child;
      if (!before(_heap[child], node))
        break;
      place(index, _heap[child]);
      index = child;
    }
    place(index, node);
  }

  std::vector<timer_node_t *> _heap;
  std::uint64_t _next_sequence = 0;
};
} // namespace vio::detail
