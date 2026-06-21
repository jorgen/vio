#pragma once

#include <atomic>
#include <functional>
#include <vector>

#include <uv.h>

namespace vio
{

struct reference_counted_t
{
  std::atomic<std::size_t> ref_count{1};
  std::vector<std::function<void()>> destroy_callbacks;
  std::vector<uv_handle_t *> closable_handles;
  int close_pending{0};
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
      if (!closable_handles.empty())
      {
        close_pending = static_cast<int>(closable_handles.size());
        for (auto it = closable_handles.rbegin(); it != closable_handles.rend(); ++it)
        {
          auto *handle = *it;
          handle->data = this;
          uv_close(handle, on_handle_closed);
        }
        closable_handles.clear();
        return false;
      }
      if (close_pending > 0)
      {
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

  void register_closable_handle(uv_handle_t *handle)
  {
    closable_handles.push_back(handle);
  }

  template <typename UV_HANDLE>
  void register_closable_handle(UV_HANDLE *handle)
  {
    closable_handles.push_back(reinterpret_cast<uv_handle_t *>(handle));
  }

private:
  static void on_handle_closed(uv_handle_t *handle)
  {
    auto *self = static_cast<reference_counted_t *>(handle->data);
    handle->data = nullptr;
    if (--self->close_pending == 0)
    {
      self->destroyer();
    }
  }
};

} // namespace vio
