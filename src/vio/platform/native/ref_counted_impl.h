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
#include <functional>
#include <vector>

#include "vio/loop/loop_core.h"

namespace vio
{
struct reference_counted_t
{
  std::atomic<std::size_t> ref_count{1};
  std::vector<std::function<void()>> destroy_callbacks;
  std::vector<detail::resource_t *> closables;
  int close_pending{0};
  bool in_destroy_sequence{false};
  std::function<void()> destroyer;

  explicit reference_counted_t(std::function<void()> on_destroy)
    : destroyer(std::move(on_destroy))
  {
  }

  void inc()
  {
    ref_count.fetch_add(1, std::memory_order_relaxed);
  }

  bool dec()
  {
    if (ref_count.fetch_sub(1, std::memory_order_acq_rel) != 1)
      return false;
    if (in_destroy_sequence)
      return false;
    in_destroy_sequence = true;

    std::vector<std::function<void()>> callbacks;
    std::swap(callbacks, destroy_callbacks);
    for (auto it = callbacks.rbegin(); it != callbacks.rend(); ++it)
      (*it)();
    if (ref_count.load(std::memory_order_relaxed) != 0)
    {
      in_destroy_sequence = false;
      return false;
    }
    if (!closables.empty())
    {
      std::vector<detail::resource_t *> resources;
      std::swap(resources, closables);
      close_pending += static_cast<int>(resources.size());
      for (auto it = resources.rbegin(); it != resources.rend(); ++it)
        (*it)->close(&reference_counted_t::on_closed, this);
      return false;
    }
    if (close_pending > 0)
      return false;
    destroyer();
    return true;
  }

  void register_destroy_callback(std::function<void()> callback)
  {
    destroy_callbacks.push_back(std::move(callback));
  }

  void register_closable(detail::resource_t &resource)
  {
    closables.push_back(&resource);
  }

private:
  static void on_closed(void *context)
  {
    auto *self = static_cast<reference_counted_t *>(context);
    if (--self->close_pending == 0)
      self->destroyer();
  }
};
} // namespace vio
