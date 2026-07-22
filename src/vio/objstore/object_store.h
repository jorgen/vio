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

#include <vio/error.h>
#include <vio/event_loop.h>
#include <vio/task.h>

#include <cstdint>
#include <expected>
#include <memory>
#include <string>

// A coroutine object-store abstraction (modeled on OpenVDS's IOManager): whole-object writes and
// range-capable reads over a pluggable backend. Backends: in-memory, a local directory of files, and
// the cloud object stores (S3-compatible via AWS SigV4, Azure Blob via Shared Key / SAS). All methods
// run on a vio event loop and return std::expected<T, error_t>.
namespace vio::objstore
{

// A byte range within an object. size < 0 means "to the end of the object" (the whole object when
// offset is 0), mirroring OpenVDS's IORange.
struct io_range_t
{
  int64_t offset = 0;
  int64_t size = -1;
};

struct object_info_t
{
  bool exists = false;
  uint64_t size = 0;
};

class io_manager_t
{
public:
  virtual ~io_manager_t() = default;

  // Read (a range of) an object into dst (caller-owned, large enough for the range). Returns the
  // number of bytes read. A missing object is an error.
  virtual task_t<std::expected<uint64_t, error_t>> read_object(std::string name, uint8_t *dst, io_range_t range = {}) = 0;

  // Write a whole object (create or atomically replace) from `size` bytes of `data`.
  virtual task_t<std::expected<void, error_t>> write_object(std::string name, std::shared_ptr<uint8_t[]> data, uint64_t size) = 0;

  // Existence + size. A missing object is object_info_t{exists=false}, not an error.
  virtual task_t<std::expected<object_info_t, error_t>> object_info(std::string name) = 0;

  // Remove an object. Removing a missing object is not an error (idempotent).
  virtual task_t<std::expected<void, error_t>> remove_object(std::string name) = 0;
};

// The create_io_manager(url, loop) factory is in <vio/objstore/create_object_store.h>.

} // namespace vio::objstore
