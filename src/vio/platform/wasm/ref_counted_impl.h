#pragma once

#include <atomic>
#include <functional>
#include <vector>

namespace vio
{

struct reference_counted_t
{
  std::atomic<std::size_t> ref_count{1};
  std::vector<std::function<void()>> destroy_callbacks;
  bool in_destroy_sequence{false};
  std::function<void()> destroyer;

  explicit reference_counted_t(std::function<void()> destroyer)
    : destroyer(std::move(destroyer))
  {
  }

  void inc()
  {
    ref_count.fetch_add(1, std::memory_order_relaxed);
  }

  bool dec()
  {
    if (ref_count.fetch_sub(1, std::memory_order_acq_rel) == 1)
    {
      if (in_destroy_sequence)
      {
        return false;
      }
      in_destroy_sequence = true;

      std::vector<std::function<void()>> callbacks;
      std::swap(callbacks, destroy_callbacks);
      for (auto it = callbacks.rbegin(); it != callbacks.rend(); ++it)
      {
        (*it)();
      }
      if (ref_count.load(std::memory_order_relaxed) != 0)
      {
        in_destroy_sequence = false;
        return false;
      }
      destroyer();
      return true;
    }
    return false;
  }

  void register_destroy_callback(std::function<void()> callback)
  {
    destroy_callbacks.push_back(std::move(callback));
  }
};

} // namespace vio
