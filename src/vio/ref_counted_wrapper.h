#pragma once

#include <functional>
#include <memory>
#include <type_traits>
#include <vector>

namespace vio
{

struct reference_counted_t
{
  std::size_t ref_count{1};
  std::vector<std::function<void()>> destroy_callbacks;
  std::function<void()> destroyer;

  explicit reference_counted_t(std::function<void()> &&destroyer)
    : destroyer(std::move(destroyer))
  {
  }

  void inc()
  {
    ++ref_count;
  }

  bool dec()
  {
    if (--ref_count == 0)
    {
      std::vector<std::function<void()>> callbacks;
      std::swap(callbacks, destroy_callbacks);
      for (auto it = callbacks.rbegin(); it != callbacks.rend(); ++it)
      {
        (*it)();
      }
      if (ref_count == 0)
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
      : ref_count([this] { delete this; })
      , data(&ref_count)
    {
    }

    template <typename... Args>
    explicit storage_t(Args &&...args)
      : ref_count([this] { delete this; })
      , data(&ref_count, std::forward<Args>(args)...)
    {
    }
  };

private:
  storage_t *storage;

public:
  wrapper_t()
    : storage(new storage_t())
  {
  }

  template <typename... Args>
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

} // namespace vio