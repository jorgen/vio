/*
  Copyright (c) 2026 Jørgen Lind

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
#include <cstdint>
#include <deque>
#include <memory>
#include <span>
#include <vector>

#include "vio/operation/process.h"

namespace vio::detail
{
inline constexpr std::size_t process_read_buffer_size = 65536;

class process_op_list_t
{
public:
  [[nodiscard]] bool empty() const noexcept
  {
    return _head == nullptr;
  }

  [[nodiscard]] process_op_t *front() const noexcept
  {
    return _head;
  }

  void push_back(process_op_t &op) noexcept
  {
    op.next = nullptr;
    op.prev = _tail;
    if (_tail)
      _tail->next = &op;
    else
      _head = &op;
    _tail = &op;
  }

  void remove(process_op_t &op) noexcept
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

private:
  process_op_t *_head = nullptr;
  process_op_t *_tail = nullptr;
};

struct process_write_chunk_t
{
  std::vector<std::byte> copy;
  std::unique_ptr<owned_payload_t> owned;
  std::span<const std::byte> bytes;
  std::size_t sent = 0;
};

class process_write_queue_t
{
public:
  int enqueue(std::span<const std::byte> data, std::unique_ptr<owned_payload_t> owned, std::uint64_t &target)
  {
    if (error != 0)
      return error;
    if (!data.empty())
    {
      auto &chunk = chunks.emplace_back();
      if (owned)
      {
        chunk.owned = std::move(owned);
        chunk.bytes = data;
      }
      else
      {
        chunk.copy.assign(data.begin(), data.end());
        chunk.bytes = chunk.copy;
      }
      enqueued += data.size();
    }
    target = enqueued;
    return 0;
  }

  void sent_directly(std::size_t count) noexcept
  {
    enqueued += count;
    written += count;
  }

  [[nodiscard]] std::span<const std::byte> front() const noexcept
  {
    if (chunks.empty())
      return {};
    auto &chunk = chunks.front();
    return chunk.bytes.subspan(chunk.sent);
  }

  void advance(std::size_t count) noexcept
  {
    written += count;
    auto &chunk = chunks.front();
    chunk.sent += count;
    if (chunk.sent >= chunk.bytes.size())
      chunks.pop_front();
  }

  void fail(int code) noexcept
  {
    if (error == 0)
      error = code;
    chunks.clear();
  }

  [[nodiscard]] bool settles(const process_op_t &op) const noexcept
  {
    return written >= op.target || error != 0;
  }

  std::deque<process_write_chunk_t> chunks;
  std::uint64_t enqueued = 0;
  std::uint64_t written = 0;
  int error = 0;
};

inline process_op_t *process_take_settled_writer(process_op_list_t &waiters, const process_write_queue_t &queue) noexcept
{
  for (auto *op = waiters.front(); op; op = op->next)
  {
    if (!queue.settles(*op))
      continue;
    waiters.remove(*op);
    op->parked = false;
    op->error = queue.written >= op->target ? 0 : queue.error;
    return op;
  }
  return nullptr;
}

inline unique_buf_t process_allocate_read_buffer()
{
  auto memory = default_alloc(nullptr, process_read_buffer_size);
  return unique_buf_t(memory, default_dealloc, nullptr);
}
} // namespace vio::detail
