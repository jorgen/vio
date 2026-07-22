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
#include <mutex>
#include <unordered_map>
#include <vector>

namespace vio::objstore
{

// An in-memory object store (like OpenVDS's in-memory IOManager): backs ephemeral mem:// datasets and
// is the subclassable base for fault-injecting test doubles (override any op to fail deterministically).
class memory_io_manager_t : public io_manager_t
{
public:
  memory_io_manager_t() = default;

  task_t<std::expected<uint64_t, error_t>> read_object(std::string name, uint8_t *dst, io_range_t range) override
  {
    std::unique_lock<std::mutex> lock(_mutex);
    auto it = _objects.find(name);
    if (it == _objects.end())
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
    std::unique_lock<std::mutex> lock(_mutex);
    std::vector<uint8_t> bytes(size);
    if (size > 0)
      memcpy(bytes.data(), data.get(), size);
    _objects[std::move(name)] = std::move(bytes);
    co_return {};
  }

  task_t<std::expected<object_info_t, error_t>> object_info(std::string name) override
  {
    std::unique_lock<std::mutex> lock(_mutex);
    auto it = _objects.find(name);
    object_info_t out;
    out.exists = it != _objects.end();
    out.size = out.exists ? it->second.size() : 0;
    co_return out;
  }

  task_t<std::expected<void, error_t>> remove_object(std::string name) override
  {
    std::unique_lock<std::mutex> lock(_mutex);
    _objects.erase(name);
    co_return {};
  }

protected:
  std::mutex _mutex;
  std::unordered_map<std::string, std::vector<uint8_t>> _objects;
};

} // namespace vio::objstore
