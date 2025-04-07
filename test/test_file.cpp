#include <chrono>
#include <doctest/doctest.h>
#include <vio/event_loop.h>
#include <vio/event_pipe.h>
#include <vio/operation/file.h>
#include <vio/task.h>

vio::task_t<void> write_a_test_file(vio::event_loop_t &event_loop)
{
  auto tmp_file = vio::mkstemp_file(event_loop, "test_write_then_read_XXXXXX");
  CHECK(tmp_file.has_value());
  auto file = std::move(tmp_file.value().first);
  auto path = std::move(tmp_file.value().second);
  std::string to_write = "Hello world";
  auto write_result = co_await vio::write_file(event_loop, *file , (uint8_t *)to_write.data(), to_write.size(), 0);
  CHECK(write_result.has_value());
  CHECK(write_result.value() == to_write.size());

  //close file
  file = vio::auto_close_t<vio::file_t>({&event_loop, -1});

  auto opened_file = vio::open_file(event_loop, path, vio::file_open_flag_t::rdonly, 0);
  CHECK(opened_file.has_value());
  file = std::move(opened_file.value());
  std::string buffer(to_write.size(), '\0');
  auto read_result = co_await vio::read_file(event_loop, *file, (uint8_t *)buffer.data(), to_write.size(), 0);
  CHECK(read_result.has_value());
  CHECK(read_result.value() == to_write.size());
  CHECK(buffer == to_write);
  event_loop.stop();
}

TEST_CASE("test basic file")
{
  vio::event_loop_t event_loop;
  event_loop.run_in_loop([&event_loop] { write_a_test_file(event_loop); });
  event_loop.run();
}
#include <chrono>
#include <doctest/doctest.h>
#include <vio/event_loop.h>
#include <vio/event_pipe.h>
#include <vio/operation/file.h>
#include <vio/task.h>
#include <cstdio>
#include <cstdlib>

// Reuse the same pattern as in "test basic file" for consistency.

// --------------------------------------------------------
// Test synchronous file operations (rename, unlink, stat).
// --------------------------------------------------------
vio::task_t<void> test_sync_file_ops(vio::event_loop_t &event_loop)
{
  // 1) Create a temporary file:
  auto tmp = vio::mkstemp_file(event_loop, "test_sync_file_ops_XXXXXX");
  CHECK(tmp.has_value());
  auto fileHandle = std::move(tmp.value().first);
  auto sourcePath = std::move(tmp.value().second);

  // 2) Optionally write some data:
  {
    std::string text = "Some test data";
    auto writeResult = co_await vio::write_file(event_loop, *fileHandle,
                                               reinterpret_cast<const uint8_t*>(text.data()),
                                               text.size(), 0);
    CHECK(writeResult.has_value());
    CHECK(writeResult.value() == text.size());
  }

  // Close the file before rename
  fileHandle = vio::auto_close_t<vio::file_t>({&event_loop, -1});

  // 3) Generate a new random path for rename:
  std::string newPath = sourcePath + "_renamed";

  // 4) Rename the file:
  {
    auto rename_result = vio::rename_file(event_loop, sourcePath, newPath);
    CHECK(rename_result.has_value());
  }

  // 5) Stat the file:
  {
    auto statResult = vio::stat_file(event_loop, newPath);
    CHECK(statResult.has_value());
    // Optionally check if file size is bigger than 0
    CHECK(statResult->st_size > 0);
  }

  // 6) Unlink(remove) the file:
  {
    auto unlink_result = vio::unlink_file(event_loop, newPath);
    CHECK(unlink_result.has_value());
  }

  event_loop.stop();
  co_return;
}

// --------------------------------------------------------
// Test mkdir, rmdir using random directory name.
// --------------------------------------------------------
vio::task_t<void> test_mkdir_rmdir(vio::event_loop_t &event_loop)
{
  // We can just generate a random directory name
  // (no built-in mkdtemp in libuv).
  // This is a simple random suffix approach.
  char dirTemplate[] = "test_mkdir_rmdir_XXXXXX";
  auto dir_name_result = vio::mkdtemp_path(event_loop, dirTemplate);
  CHECK(dir_name_result.has_value());
  const std::string& dirName = dir_name_result.value();

  // 1) Ensure we remove any leftover from a previous run
  // (ignore error if it doesn't exist)
  vio::rmdir_path(event_loop, dirName);

  // 2) mkdir
  auto mkdirResult = vio::mkdir_path(event_loop, dirName, 0700);
  CHECK(mkdirResult.has_value());

  // 3) Optionally check with stat:
  {
    auto statResult = vio::stat_file(event_loop, dirName);
    CHECK(statResult.has_value());
    // st_mode has the type bits in the upper part; check if directory
    CHECK((statResult->st_mode & S_IFDIR) != 0);
  }

  // 4) rmdir
  {
    auto rmdirResult = vio::rmdir_path(event_loop, dirName);
    CHECK(rmdirResult.has_value());
  }

  event_loop.stop();
  co_return;
}

// --------------------------------------------------------
// Test send_file using two temporary files.
// --------------------------------------------------------
vio::task_t<void> test_send_file(vio::event_loop_t &event_loop)
{
  // 1) Create source file
  auto source = vio::mkstemp_file(event_loop, "test_send_file_src_XXXXXX");
  CHECK(source.has_value());
  auto srcFile    = std::move(source.value().first);
  auto sourcePath = std::move(source.value().second);

  // Write data to the source file
  std::string testData = "Send file data content";
  {
    auto writeRes = co_await vio::write_file(event_loop, *srcFile,
                                             reinterpret_cast<const uint8_t*>(testData.data()),
                                             testData.size(), 0);
    CHECK(writeRes.has_value());
    CHECK(writeRes.value() == testData.size());
  }

  // 2) Create destination file
  auto dest = vio::mkstemp_file(event_loop, "test_send_file_dest_XXXXXX");
  CHECK(dest.has_value());
  auto dstFile    = std::move(dest.value().first);
  auto destPath   = std::move(dest.value().second);

  // 3) Co_await send_file from source to dest
  {
    // Send entire contents (testData.size())
    auto sendResult = co_await vio::send_file(event_loop, *dstFile, *srcFile, 0, testData.size());
    CHECK(sendResult.has_value());
    CHECK(sendResult.value() == testData.size());
  }

  // 4) Read from destination to confirm content
  {
    // Rewind the handle
    dstFile = vio::auto_close_t<vio::file_t>({&event_loop, -1});
    auto openedDst = vio::open_file(event_loop, destPath, vio::file_open_flag_t::rdonly, 0);
    CHECK(openedDst.has_value());
    dstFile = std::move(openedDst.value());

    std::string buffer(testData.size(), '\0');
    auto readRes = co_await vio::read_file(event_loop, *dstFile,
                                           reinterpret_cast<uint8_t*>(buffer.data()),
                                           testData.size(), 0);
    CHECK(readRes.has_value());
    CHECK(readRes.value() == testData.size());
    CHECK(buffer == testData);
  }

  // 5) Cleanup (close + unlink both files)
  srcFile = vio::auto_close_t<vio::file_t>({&event_loop, -1});
  dstFile = vio::auto_close_t<vio::file_t>({&event_loop, -1});
  vio::unlink_file(event_loop, sourcePath);
  vio::unlink_file(event_loop, destPath);

  event_loop.stop();
  co_return;
}

// --------------------------------------------------------
// Integrate with the existing test runner
// --------------------------------------------------------
TEST_CASE("test extra file functions")
{
  // We run each test in a separate run of the event loop
  // so they don't interfere with each other.
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