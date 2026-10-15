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

#include <cstdint>

#include "vio/vio_export.h"

namespace vio::detail
{
[[noreturn]] VIO_EXPORT void abort_destroyed_in_flight(const char *what) noexcept;

struct io_op_t
{
  using complete_fn_t = void (*)(io_op_t *op);

  ~io_op_t()
  {
    if (parked)
      abort_destroyed_in_flight("socket operation");
  }

  complete_fn_t complete = nullptr;
  void *owner = nullptr;
  io_op_t *next = nullptr;
  io_op_t *prev = nullptr;
  std::uint32_t epoch = 0;
  std::uint8_t interest = 0;
  bool parked = false;
  bool keeps_alive = true;
};

class op_list_t
{
public:
  [[nodiscard]] bool empty() const noexcept
  {
    return _head == nullptr;
  }

  void push_back(io_op_t &op) noexcept
  {
    op.next = nullptr;
    op.prev = _tail;
    if (_tail)
      _tail->next = &op;
    else
      _head = &op;
    _tail = &op;
  }

  void remove(io_op_t &op) noexcept
  {
    if (op.prev)
      op.prev->next = op.next;
    else
      _head = op.next;
    if (op.next)
      op.next->prev = op.prev;
    else
      _tail = op.prev;
    op.next = nullptr;
    op.prev = nullptr;
  }

  [[nodiscard]] io_op_t *front() const noexcept
  {
    return _head;
  }

  io_op_t *take_all() noexcept
  {
    auto *head = _head;
    _head = nullptr;
    _tail = nullptr;
    return head;
  }

private:
  io_op_t *_head = nullptr;
  io_op_t *_tail = nullptr;
};

struct posted_t
{
  using run_fn_t = void (*)(posted_t *node);

  run_fn_t run = nullptr;
  run_fn_t discard = nullptr;
  void *owner = nullptr;
  posted_t *next = nullptr;
  bool queued = false;
};

class posted_list_t
{
public:
  [[nodiscard]] bool empty() const noexcept
  {
    return _head == nullptr;
  }

  void push_back(posted_t &node) noexcept
  {
    node.next = nullptr;
    if (_tail)
      _tail->next = &node;
    else
      _head = &node;
    _tail = &node;
  }

  posted_t *take_all() noexcept
  {
    auto *head = _head;
    _head = nullptr;
    _tail = nullptr;
    return head;
  }

  posted_t *pop_front() noexcept
  {
    auto *head = _head;
    if (!head)
      return nullptr;
    _head = head->next;
    if (!_head)
      _tail = nullptr;
    head->next = nullptr;
    return head;
  }

  void prepend(posted_t *head) noexcept
  {
    if (!head)
      return;
    auto *last = head;
    while (last->next)
      last = last->next;
    last->next = _head;
    if (!_tail)
      _tail = last;
    _head = head;
  }

  bool remove(posted_t &node) noexcept
  {
    posted_t *previous = nullptr;
    for (auto *it = _head; it; previous = it, it = it->next)
    {
      if (it != &node)
        continue;
      if (previous)
        previous->next = it->next;
      else
        _head = it->next;
      if (_tail == it)
        _tail = previous;
      it->next = nullptr;
      return true;
    }
    return false;
  }

private:
  posted_t *_head = nullptr;
  posted_t *_tail = nullptr;
};
} // namespace vio::detail
