#include <chrono>
#include <doctest/doctest.h>
#include <vio/event_loop.h>
#include <vio/event_pipe.h>
#include <vio/operation/file.h>
#include <vio/task.h>

vio::task_t<void> write_a_test_file(vio::event_loop_t &event_loop)
{
  auto tmp_file = vio::mkstemp_file(event_loop, "test_write_then_read_XXXXXX");
  REQUIRE(tmp_file.has_value());
  auto file = std::move(tmp_file.value().first);
  auto path = std::move(tmp_file.value().second);
  std::string to_write = "Hello world";
  auto write_result = co_await vio::write_file(event_loop, *file , (uint8_t *)to_write.data(), to_write.size(), 0);
  if (!write_result.has_value())
  {
    fprintf(stderr, "Write operation failed: %s\n", write_result.error().msg.c_str());
  }
  REQUIRE(write_result.has_value());
  REQUIRE(write_result.value() == to_write.size());

  file = vio::make_auto_close_file({&event_loop, -1});

  auto opened_file = vio::open_file(event_loop, path, vio::file_open_flag_t::rdonly, 0);
  REQUIRE(opened_file.has_value());
  file = std::move(opened_file.value());
  std::string buffer(to_write.size(), '\0');
  auto read_result = co_await vio::read_file(event_loop, *file, (uint8_t *)buffer.data(), to_write.size(), 0);
  REQUIRE(read_result.has_value());
  REQUIRE(read_result.value() == to_write.size());
  REQUIRE(buffer == to_write);
  event_loop.stop();
}

TEST_CASE("test basic file")
{
  vio::event_loop_t event_loop;
  event_loop.run_in_loop([&event_loop] { write_a_test_file(event_loop); });
  event_loop.run();
}
vio::task_t<void> test_sync_file_ops(vio::event_loop_t &event_loop)
{
  auto tmp = vio::mkstemp_file(event_loop, "test_sync_file_ops_XXXXXX");
  REQUIRE(tmp.has_value());
  auto fileHandle = std::move(tmp.value().first);
  auto sourcePath = std::move(tmp.value().second);

  {
    std::string text = "Some test data";
    auto writeResult = co_await vio::write_file(event_loop, *fileHandle,
                                               reinterpret_cast<const uint8_t*>(text.data()),
                                               text.size(), 0);
    REQUIRE(writeResult.has_value());
    REQUIRE(writeResult.value() == text.size());
  }

  fileHandle = vio::make_auto_close_file({&event_loop, -1});

  std::string newPath = sourcePath + "_renamed";

  {
    auto rename_result = vio::rename_file(event_loop, sourcePath, newPath);
    REQUIRE(rename_result.has_value());
  }

  {
    auto statResult = vio::stat_file(event_loop, newPath);
    REQUIRE(statResult.has_value());
    // Optionally check if file size is bigger than 0
    REQUIRE(statResult->st_size > 0);
  }

  {
    auto unlink_result = vio::unlink_file(event_loop, newPath);
    REQUIRE(unlink_result.has_value());
  }

  event_loop.stop();
  co_return;
}

vio::task_t<void> test_mkdir_rmdir(vio::event_loop_t &event_loop)
{
  char dirTemplate[] = "test_mkdir_rmdir_XXXXXX";
  auto dir_name_result = vio::mkdtemp_path(event_loop, dirTemplate);
  REQUIRE(dir_name_result.has_value());
  const std::string& dirName = dir_name_result.value();

  {
    auto rmdirResult = vio::rmdir_path(event_loop, dirName);
    REQUIRE(rmdirResult.has_value());
  }

  auto mkdirResult = vio::mkdir_path(event_loop, dirName, 0700);
  REQUIRE(mkdirResult.has_value());

  {
    auto statResult = vio::stat_file(event_loop, dirName);
    REQUIRE(statResult.has_value());
    REQUIRE((statResult->st_mode & S_IFDIR) != 0);
  }

  {
    auto rmdirResult = vio::rmdir_path(event_loop, dirName);
    REQUIRE(rmdirResult.has_value());
  }

  event_loop.stop();
  co_return;
}

vio::task_t<void> test_send_file(vio::event_loop_t &event_loop)
{
  auto source = vio::mkstemp_file(event_loop, "test_send_file_src_XXXXXX");
  REQUIRE(source.has_value());
  auto srcFile    = std::move(source.value().first);
  auto sourcePath = std::move(source.value().second);

  std::string testData = "Send file data content";
  {
    auto writeRes = co_await vio::write_file(event_loop, *srcFile,
                                             reinterpret_cast<const uint8_t*>(testData.data()),
                                             testData.size(), 0);
    REQUIRE(writeRes.has_value());
    REQUIRE(writeRes.value() == testData.size());
  }

  auto dest = vio::mkstemp_file(event_loop, "test_send_file_dest_XXXXXX");
  REQUIRE(dest.has_value());
  auto dstFile    = std::move(dest.value().first);
  auto destPath   = std::move(dest.value().second);

  {
    auto sendResult = co_await vio::send_file(event_loop, *dstFile, *srcFile, 0, testData.size());
    REQUIRE(sendResult.has_value());
    REQUIRE(sendResult.value() == testData.size());
  }

  {
    dstFile = vio::make_auto_close_file({&event_loop, -1});
    auto openedDst = vio::open_file(event_loop, destPath, vio::file_open_flag_t::rdonly, 0);
    REQUIRE(openedDst.has_value());
    dstFile = std::move(openedDst.value());

    std::string buffer(testData.size(), '\0');
    auto readRes = co_await vio::read_file(event_loop, *dstFile,
                                           reinterpret_cast<uint8_t*>(buffer.data()),
                                           testData.size(), 0);
    REQUIRE(readRes.has_value());
    REQUIRE(readRes.value() == testData.size());
    REQUIRE(buffer == testData);
  }

  srcFile = vio::make_auto_close_file({&event_loop, -1});
  dstFile = vio::make_auto_close_file({&event_loop, -1});
  vio::unlink_file(event_loop, sourcePath);
  vio::unlink_file(event_loop, destPath);

  event_loop.stop();
  co_return;
}

TEST_CASE("test extra file functions")
{
  SUBCASE("test_sync_file_ops")
  {
    vio::event_loop_t event_loop;
    event_loop.run_in_loop([&event_loop] { test_sync_file_ops(event_loop); });
    event_loop.run();
  }

  SUBCASE("test_mkdir_rmdir")
  {
    vio::event_loop_t event_loop;
    event_loop.run_in_loop([&event_loop] { test_mkdir_rmdir(event_loop); });
    event_loop.run();
  }

  SUBCASE("test_send_file")
  {
    vio::event_loop_t event_loop;
    event_loop.run_in_loop([&event_loop] { test_send_file(event_loop); });
    event_loop.run();
  }
}