#include "require_expected.h"

#include <chrono>
#include <cstdio>
#include <optional>
#include <doctest/doctest.h>
#include <vio/event_loop.h>
#include <vio/event_pipe.h>
#include <vio/operation/file.h>
#include <vio/task.h>

static vio::task_t<void> write_a_test_file(vio::event_loop_t &event_loop)
{
  auto tmp_file = vio::mkstemp_file(event_loop, "test_write_then_read_XXXXXX");
  REQUIRE(tmp_file.has_value());
  auto file = std::move(tmp_file.value().first);
  auto path = std::move(tmp_file.value().second);
  std::string to_write = "Hello world";
  auto write_result = co_await vio::write_file(event_loop, *file, reinterpret_cast<uint8_t *>(to_write.data()), to_write.size(), 0);
  if (!write_result.has_value())
  {
    fprintf(stderr, "Write operation failed: %s\n", write_result.error().msg.c_str());
  }
  REQUIRE(write_result.has_value());
  REQUIRE(write_result.value() == to_write.size());

  file = vio::make_auto_close_file({.event_loop = &event_loop, .handle = -1});

  auto opened_file = vio::open_file(event_loop, path, vio::file_open_flag_t::rdonly, 0);
  REQUIRE(opened_file.has_value());
  file = std::move(opened_file.value());
  std::string buffer(to_write.size(), '\0');
  auto read_result = co_await vio::read_file(event_loop, *file, reinterpret_cast<uint8_t *>(buffer.data()), to_write.size(), 0);
  REQUIRE(read_result.has_value());
  REQUIRE(read_result.value() == to_write.size());
  REQUIRE(buffer == to_write);
  event_loop.stop();
}

TEST_SUITE("File I/O")
{
TEST_CASE("test basic file")
{
  vio::event_loop_t event_loop;
  std::optional<vio::task_t<void>> task;
  event_loop.run_in_loop([&] { task.emplace(write_a_test_file(event_loop)); });
  event_loop.run();
}

static vio::task_t<void> test_sync_file_ops(vio::event_loop_t &event_loop)
{
  auto tmp = vio::mkstemp_file(event_loop, "test_sync_file_ops_XXXXXX");
  REQUIRE(tmp.has_value());
  auto file_handle = std::move(tmp.value().first);
  auto source_path = std::move(tmp.value().second);
  {
    std::string text = "Some test data";
    auto write_result = co_await vio::write_file(event_loop, *file_handle, reinterpret_cast<const uint8_t *>(text.data()), text.size(), 0);
    REQUIRE(write_result.has_value());
    REQUIRE(write_result.value() == text.size());
  }

  file_handle = vio::make_auto_close_file({.event_loop = &event_loop, .handle = -1});

  const std::string new_path = source_path + "_renamed";
  {
    auto rename_result = vio::rename_file(event_loop, source_path, new_path);
    REQUIRE(rename_result.has_value());
  }
  {
    auto stat_result = vio::stat_file(event_loop, new_path);
    REQUIRE(stat_result.has_value());
    // Optionally check if file size is bigger than 0
    REQUIRE(stat_result->st_size > 0);
  }
  {
    auto unlink_result = vio::unlink_file(event_loop, new_path);
    REQUIRE(unlink_result.has_value());
  }

  event_loop.stop();
  co_return;
}

static vio::task_t<void> test_mkdir_rmdir(vio::event_loop_t &event_loop)
{
  char dir_template[] = "test_mkdir_rmdir_XXXXXX";
  auto dir_name_result = vio::mkdtemp_path(event_loop, dir_template);
  REQUIRE(dir_name_result.has_value());
  const std::string &dir_name = dir_name_result.value();
  {
    auto rmdir_result = vio::rmdir_path(event_loop, dir_name);
    REQUIRE(rmdir_result.has_value());
  }

  auto mkdir_result = vio::mkdir_path(event_loop, dir_name, 0700);
  REQUIRE(mkdir_result.has_value());
  {
    auto stat_result = vio::stat_file(event_loop, dir_name);
    REQUIRE(stat_result.has_value());
    REQUIRE((stat_result->st_mode & S_IFDIR) != 0);
  }
  {
    auto rmdir_result = vio::rmdir_path(event_loop, dir_name);
    REQUIRE(rmdir_result.has_value());
  }

  event_loop.stop();
  co_return;
}

static vio::task_t<void> test_send_file(vio::event_loop_t &event_loop)
{
  auto source = vio::mkstemp_file(event_loop, "test_send_file_src_XXXXXX");
  REQUIRE(source.has_value());
  auto src_file = std::move(source.value().first);
  auto source_path = std::move(source.value().second);

  std::string test_data = "Send file data content";
  {
    auto write_res = co_await vio::write_file(event_loop, *src_file, reinterpret_cast<const uint8_t *>(test_data.data()), test_data.size(), 0);
    REQUIRE(write_res.has_value());
    REQUIRE(write_res.value() == test_data.size());
  }

  auto dest = vio::mkstemp_file(event_loop, "test_send_file_dest_XXXXXX");
  REQUIRE(dest.has_value());
  auto dst_file = std::move(dest.value().first);
  auto dest_path = std::move(dest.value().second);
  {
    auto send_result = co_await vio::send_file(event_loop, *dst_file, *src_file, 0, test_data.size());
    REQUIRE(send_result.has_value());
    REQUIRE(send_result.value() == test_data.size());
  }
  {
    dst_file = vio::make_auto_close_file({.event_loop = &event_loop, .handle = -1});
    auto opened_dst = vio::open_file(event_loop, dest_path, vio::file_open_flag_t::rdonly, 0);
    REQUIRE(opened_dst.has_value());
    dst_file = std::move(opened_dst.value());

    std::string buffer(test_data.size(), '\0');
    auto read_res = co_await vio::read_file(event_loop, *dst_file, reinterpret_cast<uint8_t *>(buffer.data()), test_data.size(), 0);
    REQUIRE(read_res.has_value());
    REQUIRE(read_res.value() == test_data.size());
    REQUIRE(buffer == test_data);
  }

  src_file = vio::make_auto_close_file({.event_loop = &event_loop, .handle = -1});
  dst_file = vio::make_auto_close_file({.event_loop = &event_loop, .handle = -1});
  auto unlink_source_path = vio::unlink_file(event_loop, source_path);
  REQUIRE_EXPECTED(unlink_source_path);
  auto unlink_dest_path = vio::unlink_file(event_loop, dest_path);
  REQUIRE_EXPECTED(unlink_dest_path);

  event_loop.stop();
  co_return;
}

TEST_CASE("test extra file functions")
{
  SUBCASE("test_sync_file_ops")
  {
    vio::event_loop_t event_loop;
    std::optional<vio::task_t<void>> task;
    event_loop.run_in_loop([&] { task.emplace(test_sync_file_ops(event_loop)); });
    event_loop.run();
  }

  SUBCASE("test_mkdir_rmdir")
  {
    vio::event_loop_t event_loop;
    std::optional<vio::task_t<void>> task;
    event_loop.run_in_loop([&] { task.emplace(test_mkdir_rmdir(event_loop)); });
    event_loop.run();
  }

  SUBCASE("test_send_file")
  {
    vio::event_loop_t event_loop;
    std::optional<vio::task_t<void>> task;
    event_loop.run_in_loop([&] { task.emplace(test_send_file(event_loop)); });
    event_loop.run();
  }
}
} // TEST_SUITE