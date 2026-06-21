#pragma once

#include <concepts>
#include <functional>
#include <type_traits>

#ifdef __EMSCRIPTEN__
#include "vio/platform/wasm/ref_counted_impl.h"
#else
#include "vio/platform/uv/ref_counted_impl.h"
#endif

namespace vio
{

template <typename Data>
class ref_ptr_t
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
  storage_t *_storage;

  // Private constructor for from_raw - does not allocate
  explicit ref_ptr_t(storage_t *ptr)
    : _storage(ptr)
  {
  }

public:
  ref_ptr_t()
    requires std::default_initializable<Data>
    : _storage(new storage_t())
  {
  }

  template <typename... Args>
    requires(sizeof...(Args) > 0) && (sizeof...(Args) != 1 || !(std::same_as<std::remove_cvref_t<Args>, ref_ptr_t> || ...))
  explicit ref_ptr_t(Args &&...args)
    : _storage(new storage_t(std::forward<Args>(args)...))
  {
  }

  ref_ptr_t(const ref_ptr_t &other)
    : _storage(other._storage)
  {
    if (_storage)
    {
      _storage->ref_count.inc();
    }
  }

  ref_ptr_t(ref_ptr_t &&other) noexcept
    : _storage(other._storage)
  {
    other._storage = nullptr;
  }

  ref_ptr_t &operator=(const ref_ptr_t &other)
  {
    if (this != &other)
    {
      if (_storage && _storage->ref_count.dec())
      {
        // Object was destroyed, _storage is now invalid
        _storage = nullptr;
      }
      _storage = other._storage;
      if (_storage)
      {
        _storage->ref_count.inc();
      }
    }
    return *this;
  }

  ref_ptr_t &operator=(ref_ptr_t &&other) noexcept
  {
    if (this != &other)
    {
      if (_storage && _storage->ref_count.dec())
      {
        // Object was destroyed, _storage is now invalid
        _storage = nullptr;
      }
      _storage = other._storage;
      other._storage = nullptr;
    }
    return *this;
  }

  ~ref_ptr_t()
  {
    if (_storage)
    {
      _storage->ref_count.dec();
    }
  }

  void release()
  {
    if (_storage)
    {
      _storage->ref_count.dec();
      _storage = nullptr;
    }
  }

  void *release_to_raw()
  {
    storage_t *temp = _storage;
    _storage = nullptr;
    return temp;
  }

  static ref_ptr_t from_raw(void *raw_ptr)
  {
    return ref_ptr_t(static_cast<storage_t *>(raw_ptr));
  }

  static ref_ptr_t null()
  {
    return ref_ptr_t(static_cast<storage_t *>(nullptr));
  }

#ifndef __EMSCRIPTEN__
  template <typename UV_HANDLE>
  void inc_ref_and_store_in_handle(UV_HANDLE &handle)
  {
    if (_storage)
    {
      _storage->ref_count.inc();
    }
    handle.data = _storage;
  }
#endif

  Data *operator->()
  {
    return &_storage->data;
  }
  const Data *operator->() const
  {
    return &_storage->data;
  }

  Data &data()
  {
    return _storage->data;
  }
  const Data &data() const
  {
    return _storage->data;
  }

  [[nodiscard]] reference_counted_t *ref_counted()
  {
    return _storage ? &_storage->ref_count : nullptr;
  }
  [[nodiscard]] const reference_counted_t *ref_counted() const
  {
    return _storage ? &_storage->ref_count : nullptr;
  }

#ifndef __EMSCRIPTEN__
  template <typename UV_HANDLE>
  void register_handle(UV_HANDLE *handle)
  {
    _storage->ref_count.register_closable_handle(handle);
  }
#endif

  void on_destroy(std::function<void()> callback)
  {
    _storage->ref_count.register_destroy_callback(std::move(callback));
  }

  explicit operator bool() const noexcept
  {
    return _storage != nullptr;
  }
};

template <typename Data, typename... Args>
ref_ptr_t<Data> make_ref_ptr(Args &&...args)
{
  return ref_ptr_t<Data>(std::forward<Args>(args)...);
}

} // namespace vio
