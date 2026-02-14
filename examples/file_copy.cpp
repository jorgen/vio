#include <print>
#include <string>

#include <vio/run.h>
#include <vio/operation/file.h>

int main()
{
  return vio::run([](vio::event_loop_t &event_loop) -> vio::task_t<int>
  {
    // Create a temp file
    auto tmp = vio::mkstemp_file(event_loop, "vio_example_XXXXXX");
    if (!tmp)
    {
      std::println(stderr, "mkstemp_file failed: {}", tmp.error().msg);
      co_return 1;
    }
    auto file = std::move(tmp->first);
    auto path = std::move(tmp->second);
    std::println("Created temp file: {}", path);

    // Write data
    std::string content = "Hello from vio async file I/O!";
    auto write_result = co_await vio::write_file(event_loop, *file, reinterpret_cast<const uint8_t *>(content.data()), content.size(), 0);
    if (!write_result)
    {
      std::println(stderr, "write_file failed: {}", write_result.error().msg);
      co_return 1;
    }
    std::println("Wrote {} bytes", write_result.value());

    // Close the file by replacing with an invalid handle
    file = vio::make_auto_close_file({.event_loop = &event_loop, .handle = -1});

    // Reopen for reading
    auto opened = vio::open_file(event_loop, path, vio::file_open_flag_t::rdonly, 0);
    if (!opened)
    {
      std::println(stderr, "open_file failed: {}", opened.error().msg);
      co_return 1;
    }
    file = std::move(opened.value());

    // Read data back
    std::string buffer(content.size(), '\0');
    auto read_result = co_await vio::read_file(event_loop, *file, reinterpret_cast<uint8_t *>(buffer.data()), content.size(), 0);
    if (!read_result)
    {
      std::println(stderr, "read_file failed: {}", read_result.error().msg);
      co_return 1;
    }
    std::println("Read {} bytes: \"{}\"", read_result.value(), buffer);

    // Verify contents match
    if (buffer != content)
    {
      std::println(stderr, "Contents mismatch!");
      co_return 1;
    }
    std::println("Contents match!");

    // Close before stat/unlink
    file = vio::make_auto_close_file({.event_loop = &event_loop, .handle = -1});

    // Stat the file
    auto stat_result = vio::stat_file(event_loop, path);
    if (!stat_result)
    {
      std::println(stderr, "stat_file failed: {}", stat_result.error().msg);
      co_return 1;
    }
    std::println("File size: {} bytes", stat_result->st_size);

    // Clean up
    auto unlink_result = vio::unlink_file(event_loop, path);
    if (!unlink_result)
    {
      std::println(stderr, "unlink_file failed: {}", unlink_result.error().msg);
      co_return 1;
    }
    std::println("Deleted temp file");
    std::println("Done!");
    co_return 0;
  });
}
