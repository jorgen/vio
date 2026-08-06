/*
  Copyright (c) 2024 Jørgen Lind

  Permission is hereby granted, free of charge, to any person obtaining a copy of
  this software and associated documentation files (the "Software"), to deal in
  the Software without restriction, including without limitation the rights to
  use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
  of the Software, and to permit persons to whom the Software is furnished to do
  so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
*/
#pragma once

#include <vio/objstore/object_store.h>

#include <cstring>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace vio::objstore
{

// An in-memory object store (like OpenVDS's in-memory IOManager): backs mem:// datasets and is the
// subclassable base for fault-injecting test doubles (override any op to fail deterministically).
//
// NAMED stores are shared process-wide. Without them a mem:// URL is close to useless for anything
// that hands a dataset from one component to another -- a writer and a reader on the SAME url each
// got their own empty store, so the reader always saw nothing. Naming makes mem:// behave like every
// other scheme: the url identifies the data, not the handle.
//
// The registry holds a STRONG reference, so a named store outlives the managers that use it. That is
// the point (write, close, reopen) and it means the bytes stay until the process exits or someone
// calls reset_named_store. Tests that reuse a name should reset it, or they inherit the previous
// run's objects.
//
// An unnamed manager keeps a private store, exactly as before.
class memory_io_manager_t : public io_manager_t
{
public:
  // The shared bytes. Held by shared_ptr so a manager can outlive the registry entry and vice versa.
  struct store_t
  {
    std::mutex mutex;
    std::unordered_map<std::string, std::vector<uint8_t>> objects;
  };

  // Private store, reachable only through this manager.
  memory_io_manager_t()
    : _store(std::make_shared<store_t>())
  {
  }

  // Shared store: every manager built with the same name sees the same objects.
  explicit memory_io_manager_t(const std::string &name)
    : _store(named_store(name))
  {
  }

  // Look up (or create) a named store directly, for a caller that wants to seed or inspect one
  // without going through a manager.
  static std::shared_ptr<store_t> named_store(const std::string &name)
  {
    auto &reg = registry();
    std::unique_lock<std::mutex> lock(reg.mutex);
    auto it = reg.stores.find(name);
    if (it != reg.stores.end())
      return it->second;
    auto store = std::make_shared<store_t>();
    reg.stores.emplace(name, store);
    return store;
  }

  // Forget a named store. Managers already holding it keep working on their copy of the shared_ptr;
  // the next lookup of `name` starts empty. Returns true if there was one. Mostly for tests.
  static bool reset_named_store(const std::string &name)
  {
    auto &reg = registry();
    std::unique_lock<std::mutex> lock(reg.mutex);
    return reg.stores.erase(name) > 0;
  }

  static void reset_all_named_stores()
  {
    auto &reg = registry();
    std::unique_lock<std::mutex> lock(reg.mutex);
    reg.stores.clear();
  }

  task_t<std::expected<uint64_t, error_t>> read_object_all(std::string name, uint8_t *dst, uint64_t capacity) override
  {
    std::unique_lock<std::mutex> lock(_store->mutex);
    auto it = _store->objects.find(name);
    if (it == _store->objects.end())
      co_return std::unexpected(error_t{.code = 1, .msg = "Object not found: " + name});
    const auto &bytes = it->second;
    if (bytes.size() > capacity)
      co_return std::unexpected(error_t{.code = 1, .msg = "Object larger than caller buffer: " + name});
    if (!bytes.empty())
      memcpy(dst, bytes.data(), bytes.size());
    co_return uint64_t(bytes.size());
  }

  task_t<std::expected<uint64_t, error_t>> read_object(std::string name, uint8_t *dst, io_range_t range) override
  {
    std::unique_lock<std::mutex> lock(_store->mutex);
    auto it = _store->objects.find(name);
    if (it == _store->objects.end())
      co_return std::unexpected(error_t{.code = 1, .msg = "Object not found: " + name});
    const auto &bytes = it->second;
    uint64_t offset = range.offset < 0 ? 0 : uint64_t(range.offset);
    uint64_t size = range.size < 0 ? (bytes.size() > offset ? bytes.size() - offset : 0) : uint64_t(range.size);
    if (offset + size > bytes.size())
      co_return std::unexpected(error_t{.code = 1, .msg = "Read out of range for object: " + name});
    if (size > 0)
      memcpy(dst, bytes.data() + offset, size);
    co_return size;
  }

  task_t<std::expected<void, error_t>> write_object(std::string name, std::shared_ptr<uint8_t[]> data, uint64_t size) override
  {
    std::unique_lock<std::mutex> lock(_store->mutex);
    std::vector<uint8_t> bytes(size);
    if (size > 0)
      memcpy(bytes.data(), data.get(), size);
    _store->objects[std::move(name)] = std::move(bytes);
    co_return {};
  }

  task_t<std::expected<object_info_t, error_t>> object_info(std::string name) override
  {
    std::unique_lock<std::mutex> lock(_store->mutex);
    auto it = _store->objects.find(name);
    object_info_t out;
    out.exists = it != _store->objects.end();
    out.size = out.exists ? it->second.size() : 0;
    co_return out;
  }

  task_t<std::expected<void, error_t>> remove_object(std::string name) override
  {
    std::unique_lock<std::mutex> lock(_store->mutex);
    _store->objects.erase(name);
    co_return {};
  }

protected:
  std::shared_ptr<store_t> _store;

private:
  struct registry_t
  {
    std::mutex mutex;
    std::unordered_map<std::string, std::shared_ptr<store_t>> stores;
  };

  // Magic static: thread-safe initialisation, and it outlives every manager.
  static registry_t &registry()
  {
    static registry_t instance;
    return instance;
  }
};

} // namespace vio::objstore
