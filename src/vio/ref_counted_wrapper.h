#pragma once

#include <atomic>
#include <functional>
#include <memory>
#include <type_traits>
#include <vector>

namespace vio
{

struct reference_counted_t
{
  std::atomic<std::size_t> ref_count{1};
  std::vector<std::function<void()>> destroy_callbacks;
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
      if (ref_count.load(std::memory_order_relaxed) == 0)
      {
        destroyer();
        return true;
      }
    }
    return false;
  }

  void register_destroy_callback(std::function<void()> callback)
  {
    destroy_callbacks.push_back(std::move(callback));
  }
};

template <typename Data, bool IsOwned>
class wrapper_t;

template <typename Data>
class wrapper_t<Data, true>
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

  explicit operator bool() const noexcept
  {
    return storage != nullptr;
  }
};

template <typename Data>
class wrapper_t<Data, false>
{
private:
  reference_counted_t *parent_ref_count;
  Data data_;

public:
  explicit wrapper_t(reference_counted_t *parent)
    : parent_ref_count(parent)
    , data_(parent)
  {
  }

  template <typename... Args>
  explicit wrapper_t(reference_counted_t *parent, Args &&...args)
    : parent_ref_count(parent)
    , data_(parent, std::forward<Args>(args)...)
  {
  }

  wrapper_t(const wrapper_t &) = delete;
  wrapper_t(wrapper_t &&) = delete;
  wrapper_t &operator=(const wrapper_t &) = delete;
  wrapper_t &operator=(wrapper_t &&) = delete;

  ~wrapper_t() = default;

  void release()
  {
    parent_ref_count = nullptr;
  }

  Data *operator->()
  {
    return &data_;
  }
  const Data *operator->() const
  {
    return &data_;
  }

  Data &data()
  {
    return data_;
  }
  const Data &data() const
  {
    return data_;
  }

  reference_counted_t *ref_counted()
  {
    return parent_ref_count;
  }
  const reference_counted_t *ref_counted() const
  {
    return parent_ref_count;
  }
};

template <typename Data>
using inline_wrapper_t = wrapper_t<Data, false>;

template <typename Data>
using owned_wrapper_t = wrapper_t<Data, true>;

template <typename Data, typename... Args>
owned_wrapper_t<Data> make_owned_wrapper(Args &&...args)
{
  return owned_wrapper_t<Data>(std::forward<Args>(args)...);
}

} // namespace vio