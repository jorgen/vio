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
#include <vio/operation/file.h>

#include <uv.h>

#include <optional>
#include <string>

#ifndef _WIN32
#include <sys/stat.h>
#endif

namespace vio::objstore
{

// One file per object under a directory: object "name" -> "<dir>/<name>". Writes are atomic (a unique
// temp file, fsync, rename over the final name), so a torn/partial object is never visible; reads are
// ranged file reads.
class file_dir_io_manager_t : public io_manager_t
{
public:
  file_dir_io_manager_t(std::string dir, event_loop_t &loop)
    : _dir(std::move(dir))
    , _loop(loop)
  {
  }

  task_t<std::expected<uint64_t, error_t>> read_object(std::string name, uint8_t *dst, io_range_t range) override
  {
    std::string path = _dir + "/" + name;
    auto open_result = open_file(_loop, path, file_open_flags_t(file_open_flag_t::rdonly), 0);
    if (!open_result.has_value())
      co_return std::unexpected(error_t{.code = 1, .msg = "Object not found: " + name});
    auto &file = open_result.value();

    uint64_t offset = range.offset < 0 ? 0 : uint64_t(range.offset);
    uint64_t size;
    if (range.size < 0)
    {
      auto st = stat_file(_loop, path);
      if (!st.has_value())
        co_return std::unexpected(error_t{.code = 1, .msg = "Could not stat object: " + name});
      uint64_t fsize = uint64_t(st.value().st_size);
      size = fsize > offset ? fsize - offset : 0;
    }
    else
    {
      size = uint64_t(range.size);
    }

    if (size == 0)
      co_return uint64_t(0);

    auto r = co_await read_file(_loop, *file, dst, size, int64_t(offset));
    if (!r.has_value())
      co_return std::unexpected(r.error());
    co_return uint64_t(r.value());
  }

  task_t<std::expected<void, error_t>> write_object(std::string name, std::shared_ptr<uint8_t[]> data, uint64_t size) override
  {
    // Ensure the directory exists (idempotent; only reached on a write path).
#ifdef _WIN32
    int dir_mode = 0;
#else
    int dir_mode = S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH;
#endif
    (void)mkdir_path(_loop, _dir, dir_mode);

    std::string tmpl = _dir + "/.tmp_XXXXXX";
    auto tmp = mkstemp_file(_loop, tmpl);
    if (!tmp.has_value())
      co_return std::unexpected(tmp.error());

    std::optional<auto_close_file_t> tmp_file(std::move(tmp.value().first));
    std::string tmp_path = std::move(tmp.value().second);

    if (size > 0)
    {
      auto wr = co_await write_file(_loop, **tmp_file, data.get(), size, 0);
      if (!wr.has_value())
      {
        tmp_file.reset();
        (void)unlink_file(_loop, tmp_path);
        co_return std::unexpected(wr.error());
      }
    }

    uv_fs_t fsync_req = {};
    uv_fs_fsync(_loop.loop(), &fsync_req, (**tmp_file).handle, NULL);
    uv_fs_req_cleanup(&fsync_req);

    tmp_file.reset(); // close before rename (required on Windows)

    auto rn = rename_file(_loop, tmp_path, _dir + "/" + name);
    if (!rn.has_value())
    {
      (void)unlink_file(_loop, tmp_path);
      co_return std::unexpected(rn.error());
    }
    co_return {};
  }

  task_t<std::expected<object_info_t, error_t>> object_info(std::string name) override
  {
    auto st = stat_file(_loop, _dir + "/" + name);
    object_info_t out;
    out.exists = st.has_value();
    out.size = st.has_value() ? uint64_t(st.value().st_size) : 0;
    co_return out;
  }

  task_t<std::expected<void, error_t>> remove_object(std::string name) override
  {
    (void)unlink_file(_loop, _dir + "/" + name); // idempotent
    co_return {};
  }

private:
  std::string _dir;
  event_loop_t &_loop;
};

} // namespace vio::objstore
