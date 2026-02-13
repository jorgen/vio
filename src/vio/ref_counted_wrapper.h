#pragma once

#include <atomic>
#include <concepts>
#include <functional>
#include <type_traits>
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
  std::function<void()> destroyer;

  explicit reference_counted_t(std::function<void()> &&destroyer)
    : destroyer(std::move(destroyer))
  {
  }

  void inc()
  {
    ref_count.fetch_add(1, std::memory_order_relaxed);
  }

  bool dec()
  {
    if (ref_count.fetch_sub(1, std::memory_order_acquire) == 1)
    {
      std::vector<std::function<void()>> callbacks;
      std::swap(callbacks, destroy_callbacks);
      for (auto it = callbacks.rbegin(); it != callbacks.rend(); ++it)
      {
        (*it)();
      }
      if (ref_count.load(std::memory_order_relaxed) != 0)
      {
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

template <typename Data>
class wrapper_t
{
public:
  struct storage_t
  {
    reference_counted_t ref_count;
    Data data;

    storage_t()
      requires std::default_initializable<Data>
      : ref_count([this] { delete this; })
      , data{}
    {
    }

    template <typename... Args>
    explicit storage_t(Args &&...args)
      : ref_count([this] { delete this; })
      , data(std::forward<Args>(args)...)
    {
    }
  };

private:
  storage_t *storage;

  // Private constructor for from_raw - does not allocate
  explicit wrapper_t(storage_t *ptr)
    : storage(ptr)
  {
  }

public:
  wrapper_t()
    requires std::default_initializable<Data>
    : storage(new storage_t())
  {
  }

  template <typename... Args>
    requires(sizeof...(Args) > 0) && (sizeof...(Args) != 1 || !(std::same_as<std::remove_cvref_t<Args>, wrapper_t> || ...))
  explicit wrapper_t(Args &&...args)
    : storage(new storage_t(std::forward<Args>(args)...))
  {
  }

  wrapper_t(const wrapper_t &other)
    : storage(other.storage)
  {
    if (storage)
    {
      storage->ref_count.inc();
    }
  }

  wrapper_t(wrapper_t &&other) noexcept
    : storage(other.storage)
  {
    other.storage = nullptr;
  }

  wrapper_t &operator=(const wrapper_t &other)
  {
    if (this != &other)
    {
      if (storage && storage->ref_count.dec())
      {
        // Object was destroyed, storage is now invalid
        storage = nullptr;
      }
      storage = other.storage;
      if (storage)
      {
        storage->ref_count.inc();
      }
    }
    return *this;
  }

  wrapper_t &operator=(wrapper_t &&other) noexcept
  {
    if (this != &other)
    {
      if (storage && storage->ref_count.dec())
      {
        // Object was destroyed, storage is now invalid
        storage = nullptr;
      }
      storage = other.storage;
      other.storage = nullptr;
    }
    return *this;
  }

  ~wrapper_t()
  {
    if (storage)
    {
      storage->ref_count.dec();
    }
  }

  void release()
  {
    if (storage)
    {
      storage->ref_count.dec();
      storage = nullptr;
    }
  }

  void *release_to_raw()
  {
    storage_t *temp = storage;
    storage = nullptr;
    return temp;
  }

  static wrapper_t from_raw(void *raw_ptr)
  {
    return wrapper_t(static_cast<storage_t *>(raw_ptr));
  }

  static wrapper_t null()
  {
    return wrapper_t(static_cast<storage_t *>(nullptr));
  }

  template <typename UV_HANDLE>
  void inc_ref_and_store_in_handle(UV_HANDLE &handle)
  {
    if (storage)
    {
      storage->ref_count.inc();
    }
    handle.data = storage;
  }

  Data *operator->()
  {
    return &storage->data;
  }
  const Data *operator->() const
  {
    return &storage->data;
  }

  Data &data()
  {
    return storage->data;
  }
  const Data &data() const
  {
    return storage->data;
  }

  reference_counted_t *ref_counted()
  {
    return storage ? &storage->ref_count : nullptr;
  }
  const reference_counted_t *ref_counted() const
  {
    return storage ? &storage->ref_count : nullptr;
  }

  template <typename UV_HANDLE>
  void register_handle(UV_HANDLE *handle)
  {
    storage->ref_count.register_closable_handle(handle);
  }

  void on_destroy(std::function<void()> callback)
  {
    storage->ref_count.register_destroy_callback(std::move(callback));
  }

  explicit operator bool() const noexcept
  {
    return storage != nullptr;
  }
};

template <typename Data, typename... Args>
wrapper_t<Data> make_wrapper(Args &&...args)
{
  return wrapper_t<Data>(std::forward<Args>(args)...);
}

} // namespace vio