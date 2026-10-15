#include "require_expected.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <doctest/doctest.h>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>
#include <vio/event_loop.h>
#include <vio/event_pipe.h>
#include <vio/loop/blocking_pool.h>
#include <vio/objstore/file_object_store.h>
#include <vio/operation/file.h>
#include <vio/task.h>

#if defined(_WIN32)
#include <vio/detail/native.h>
#else
#include <cerrno>
#include <csignal>
#include <fcntl.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#if defined(__SANITIZE_THREAD__)
#define VIO_FILE_TEST_UNDER_TSAN 1
#elif defined(__has_feature)
#if __has_feature(thread_sanitizer)
#define VIO_FILE_TEST_UNDER_TSAN 1
#endif
#endif

namespace
{
class lazy_buffer_t
{
public:
  explicit lazy_buffer_t(std::size_t size)
    : _size(size)
  {
#if defined(_WIN32)
    _data = static_cast<std::uint8_t *>(::VirtualAlloc(nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
#else
#if defined(MAP_NORESERVE)
    constexpr int flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE;
#else
    constexpr int flags = MAP_PRIVATE | MAP_ANONYMOUS;
#endif
    void *mapped = ::mmap(nullptr, size, PROT_READ | PROT_WRITE, flags, -1, 0);
    _data = mapped == MAP_FAILED ? nullptr : static_cast<std::uint8_t *>(mapped);
#endif
  }

  lazy_buffer_t(const lazy_buffer_t &) = delete;
  lazy_buffer_t &operator=(const lazy_buffer_t &) = delete;

  ~lazy_buffer_t()
  {
    if (!_data)
      return;
#if defined(_WIN32)
    ::VirtualFree(_data, 0, MEM_RELEASE);
#else
    ::munmap(_data, _size);
#endif
  }

  std::uint8_t *data() const
  {
    return _data;
  }

  std::string text(std::size_t count) const
  {
    return {reinterpret_cast<const char *>(_data), count};
  }

private:
  std::uint8_t *_data = nullptr;
  std::size_t _size;
};

struct pool_gate_t
{
  std::mutex mutex;
  std::condition_variable wake;
  bool open = false;
  int finished = 0;
  std::vector<vio::detail::pool_job_t> jobs;

  explicit pool_gate_t(std::size_t count)
    : jobs(count)
  {
  }

  void block(vio::event_loop_t &event_loop, vio::detail::pool_queue queue)
  {
    for (auto &job : jobs)
    {
      job.owner = this;
      job.work = [](vio::detail::pool_job_t *raw) {
        auto *gate = static_cast<pool_gate_t *>(raw->owner);
        std::unique_lock lock(gate->mutex);
        gate->wake.wait(lock, [gate] { return gate->open; });
      };
      job.done = [](vio::detail::pool_job_t *raw, bool) { ++static_cast<pool_gate_t *>(raw->owner)->finished; };
      vio::detail::pool_submit(vio::detail::core(event_loop), job, queue);
    }
  }

  void release()
  {
    {
      std::lock_guard lock(mutex);
      open = true;
    }
    wake.notify_all();
  }
};

constexpr std::size_t more_than_any_pool = 1025;

const std::uint8_t *bytes_of(const std::string &text)
{
  return reinterpret_cast<const std::uint8_t *>(text.data());
}

std::uint8_t *bytes_of(std::string &text)
{
  return reinterpret_cast<std::uint8_t *>(text.data());
}

void close_now(vio::auto_close_file_t &file, vio::event_loop_t &event_loop)
{
  file = vio::make_auto_close_file({.event_loop = &event_loop, .handle = -1});
}

#if !defined(_WIN32) && !defined(VIO_FILE_TEST_UNDER_TSAN)
int copy_through_the_pool()
{
  vio::event_loop_t event_loop;
  int outcome = 1;
  event_loop.run_in_loop([&] {
    return [](vio::event_loop_t &ev, int &outcome) -> vio::task_t<void> {
      auto source = vio::mkstemp_file(ev, "test_file_fork_src_XXXXXX");
      auto dest = vio::mkstemp_file(ev, "test_file_fork_dst_XXXXXX");
      if (source)
        (void)vio::unlink_file(ev, source->second);
      if (dest)
        (void)vio::unlink_file(ev, dest->second);
      if (!source || !dest)
      {
        outcome = 2;
        ev.stop();
        co_return;
      }
      const std::string text = "fork";
      auto wrote = vio::write_file_sync(*source->first, bytes_of(text), text.size(), 0);
      auto sent = co_await vio::send_file(ev, *dest->first, *source->first, 0, text.size());
      auto synced = co_await vio::fsync_file(ev, *dest->first);
      std::string back(text.size(), '\0');
      auto read = co_await vio::read_file(ev, *dest->first, bytes_of(back), back.size(), 0);
      const bool copied = wrote && sent && sent.value() == text.size() && synced && read && read.value() == text.size() && back == text;
      outcome = copied ? 0 : 3;
      close_now(source->first, ev);
      close_now(dest->first, ev);
      ev.stop();
    }(event_loop, outcome);
  });
  event_loop.run();
  return outcome;
}

int status_of_forked(int (*body)())
{
  const pid_t child = ::fork();
  if (child < 0)
    return -1;
  if (child == 0)
  {
    sigset_t alarm_only;
    sigemptyset(&alarm_only);
    sigaddset(&alarm_only, SIGALRM);
    ::pthread_sigmask(SIG_UNBLOCK, &alarm_only, nullptr);
    std::signal(SIGALRM, SIG_DFL);
    ::alarm(10);
    ::_exit(body());
  }
  int status = 0;
  while (::waitpid(child, &status, 0) < 0)
  {
    if (errno != EINTR)
      return -1;
  }
  return status;
}
#endif
} // namespace

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
  close_now(file, event_loop);
  auto removed = vio::unlink_file(event_loop, path);
  REQUIRE_EXPECTED(removed);
  event_loop.stop();
}

TEST_SUITE("File I/O")
{
TEST_CASE("test basic file")
{
  vio::event_loop_t event_loop;
  event_loop.run_in_loop([&] { return write_a_test_file(event_loop); });
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
    auto again = vio::mkdir_path(event_loop, dir_name, 0700);
    REQUIRE_FALSE(again.has_value());
    CHECK(again.error().code == vio::errc::file_exists);
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
    event_loop.run_in_loop([&] { return test_sync_file_ops(event_loop); });
    event_loop.run();
  }

  SUBCASE("test_mkdir_rmdir")
  {
    vio::event_loop_t event_loop;
    event_loop.run_in_loop([&] { return test_mkdir_rmdir(event_loop); });
    event_loop.run();
  }

  SUBCASE("test_send_file")
  {
    vio::event_loop_t event_loop;
    event_loop.run_in_loop([&] { return test_send_file(event_loop); });
    event_loop.run();
  }
}

TEST_CASE("fsync and fdatasync complete on the loop")
{
  vio::event_loop_t event_loop;
  event_loop.run_in_loop([&] {
    return [](vio::event_loop_t &ev) -> vio::task_t<void> {
      auto tmp = vio::mkstemp_file(ev, "test_fsync_XXXXXX");
      REQUIRE(tmp.has_value());
      auto file = std::move(tmp->first);
      auto path = std::move(tmp->second);
      const std::string text = "durable";
      auto written = co_await vio::write_file(ev, *file, bytes_of(text), text.size(), 0);
      REQUIRE_EXPECTED(written);
      auto synced = co_await vio::fsync_file(ev, *file);
      REQUIRE_EXPECTED(synced);
      CHECK(synced.value() == 0);
      auto data_synced = co_await vio::fdatasync_file(ev, *file);
      REQUIRE_EXPECTED(data_synced);
      CHECK(data_synced.value() == 0);
      close_now(file, ev);
      CHECK(vio::unlink_file(ev, path).has_value());
      ev.stop();
    }(event_loop);
  });
  event_loop.run();
}

TEST_CASE("synchronous file calls work on a thread that is not running the loop")
{
  vio::event_loop_t event_loop;
  std::string failure;
  std::thread worker([&event_loop, &failure] {
    auto fail = [&failure](const char *what) {
      if (failure.empty())
        failure = what;
    };
    auto tmp = vio::mkstemp_file(event_loop, "test_sync_thread_XXXXXX");
    if (!tmp)
      return fail("mkstemp");
    auto file = std::move(tmp->first);
    const std::string path = tmp->second;
    const std::string text = "0123456789";
    auto written = vio::write_file_sync(*file, bytes_of(text), text.size(), 0);
    if (!written || *written != text.size())
      fail("write");
    std::string back(4, '\0');
    auto read = vio::read_file_sync(*file, bytes_of(back), back.size(), 3);
    if (!read || *read != 4 || back != "3456")
      fail("read");
    if (!vio::truncate_file(*file, 6))
      fail("truncate");
    auto status = vio::fstat_file(*file);
    if (!status || status->st_size != 6)
      fail("fstat");
    if (!vio::fsync_file_sync(*file) || !vio::fdatasync_file_sync(*file))
      fail("sync");
    auto past_end = vio::read_file_sync(*file, bytes_of(back), back.size(), 100);
    if (!past_end || *past_end != 0)
      fail("read past end");
    if (vio::truncate_file(*file, -1))
      fail("negative truncate");
    close_now(file, event_loop);
    auto by_path = vio::stat_file(event_loop, path);
    if (!by_path || by_path->st_size != 6)
      fail("stat");
    if (!vio::unlink_file(event_loop, path))
      fail("unlink");
  });
  worker.join();
  CHECK_MESSAGE(failure.empty(), failure);
}

TEST_CASE("errors carry vio codes and bad input fails before reaching the system")
{
  vio::event_loop_t event_loop;

  auto missing = vio::open_file(event_loop, "test_file_that_does_not_exist_9f2c", vio::file_open_flag_t::rdonly, 0);
  REQUIRE_FALSE(missing.has_value());
  CHECK(missing.error().code == vio::errc::no_such_file);
  CHECK(missing.error().msg == vio::error_message(vio::errc::no_such_file));

  std::string with_nul("test_file_nul");
  with_nul.push_back('\0');
  with_nul += "suffix";
  auto nul_open = vio::open_file(event_loop, with_nul, vio::file_open_flags_t(vio::file_open_flag_t::creat, vio::file_open_flag_t::wronly), 0600);
  REQUIRE_FALSE(nul_open.has_value());
  CHECK(nul_open.error().code == vio::errc::invalid_argument);
  CHECK(vio::stat_file(event_loop, "test_file_nul").error().code == vio::errc::no_such_file);
  CHECK(vio::unlink_file(event_loop, with_nul).error().code == vio::errc::invalid_argument);
  CHECK(vio::mkdir_path(event_loop, with_nul, 0700).error().code == vio::errc::invalid_argument);

  auto both_modes = vio::open_file(event_loop, "test_file_both_modes", vio::file_open_flags_t(vio::file_open_flag_t::wronly, vio::file_open_flag_t::rdwr), 0600);
  REQUIRE_FALSE(both_modes.has_value());
  CHECK(both_modes.error().code == vio::errc::invalid_argument);

  auto bad_template = vio::mkstemp_file(event_loop, "test_file_no_placeholder");
  REQUIRE_FALSE(bad_template.has_value());
  CHECK(bad_template.error().code == vio::errc::invalid_argument);
  auto bad_dir_template = vio::mkdtemp_path(event_loop, "test_dir_XXXXX");
  REQUIRE_FALSE(bad_dir_template.has_value());
  CHECK(bad_dir_template.error().code == vio::errc::invalid_argument);

  auto tmp = vio::mkstemp_file(event_loop, "test_file_excl_XXXXXX");
  REQUIRE(tmp.has_value());
  auto exclusive = vio::open_file(event_loop, tmp->second, vio::file_open_flags_t(vio::file_open_flag_t::creat, vio::file_open_flag_t::excl, vio::file_open_flag_t::wronly), 0600);
  REQUIRE_FALSE(exclusive.has_value());
  CHECK(exclusive.error().code == vio::errc::file_exists);
  close_now(tmp->first, event_loop);
  CHECK(vio::unlink_file(event_loop, tmp->second).has_value());
  auto gone = vio::unlink_file(event_loop, tmp->second);
  REQUIRE_FALSE(gone.has_value());
  CHECK(gone.error().code == vio::errc::no_such_file);
}

TEST_CASE("stat reports size, type and times with nanoseconds")
{
  vio::event_loop_t event_loop;
  auto tmp = vio::mkstemp_file(event_loop, "test_file_stat_XXXXXX");
  REQUIRE(tmp.has_value());
  const std::string text = "12345";
  REQUIRE(vio::write_file_sync(*tmp->first, bytes_of(text), text.size(), 0).has_value());

  auto by_handle = vio::fstat_file(*tmp->first);
  REQUIRE_EXPECTED(by_handle);
  auto by_path = vio::stat_file(event_loop, tmp->second);
  REQUIRE_EXPECTED(by_path);
  for (const vio::file_stat_t &status : {by_handle.value(), by_path.value()})
  {
    CHECK(status.st_size == text.size());
    CHECK((status.st_mode & S_IFMT) == S_IFREG);
    CHECK(status.st_mtim.tv_sec > 1600000000);
    CHECK(status.st_mtim.tv_nsec >= 0);
    CHECK(status.st_mtim.tv_nsec < 1000000000);
    CHECK(status.st_atim.tv_nsec < 1000000000);
    CHECK(status.st_ctim.tv_nsec < 1000000000);
    CHECK(status.st_birthtim.tv_sec > 1600000000);
    CHECK(status.st_nlink >= 1);
  }
  CHECK(by_handle->st_ino == by_path->st_ino);
  close_now(tmp->first, event_loop);
  CHECK(vio::unlink_file(event_loop, tmp->second).has_value());
}

TEST_CASE("a length above 4 GiB is clamped, not cut to its low 32 bits")
{
  if constexpr (sizeof(std::size_t) > 4)
  {
    vio::event_loop_t event_loop;
    event_loop.run_in_loop([&] {
      return [](vio::event_loop_t &ev) -> vio::task_t<void> {
        auto tmp = vio::mkstemp_file(ev, "test_file_length_XXXXXX");
        REQUIRE(tmp.has_value());
        auto file = std::move(tmp->first);
        auto path = std::move(tmp->second);
        const std::string text = "Hello world";
        REQUIRE(vio::write_file_sync(*file, bytes_of(text), text.size(), 0).has_value());

        const std::size_t huge = (std::size_t(1) << 32) + 3;
        lazy_buffer_t buffer(huge);
        if (buffer.data())
        {
          auto async_read = co_await vio::read_file(ev, *file, buffer.data(), huge, 0);
          REQUIRE_EXPECTED(async_read);
          CHECK(async_read.value() == text.size());
          CHECK(buffer.text(text.size()) == text);

          std::fill_n(buffer.data(), text.size(), std::uint8_t(0));
          auto sync_read = vio::read_file_sync(*file, buffer.data(), huge, 0);
          REQUIRE_EXPECTED(sync_read);
          CHECK(sync_read.value() == text.size());
          CHECK(buffer.text(text.size()) == text);
        }
        else
        {
          MESSAGE("no address space for a buffer above 4 GiB");
        }

        close_now(file, ev);
        CHECK(vio::unlink_file(ev, path).has_value());
        ev.stop();
      }(event_loop);
    });
    event_loop.run();
  }
}

TEST_CASE("positional reads issued together each read their own offset")
{
  vio::event_loop_t event_loop;
  event_loop.run_in_loop([&] {
    return [](vio::event_loop_t &ev) -> vio::task_t<void> {
      auto tmp = vio::mkstemp_file(ev, "test_file_parallel_XXXXXX");
      REQUIRE(tmp.has_value());
      auto file = std::move(tmp->first);
      auto path = std::move(tmp->second);
      std::string text;
      for (int i = 0; i < 64; ++i)
        text.push_back(static_cast<char>('A' + i % 26));
      REQUIRE(vio::write_file_sync(*file, bytes_of(text), text.size(), 0).has_value());

      std::string got(text.size(), '\0');
      std::vector<vio::future_t<vio::file_io_state_t>> reads;
      for (std::size_t i = 0; i < text.size(); ++i)
        reads.push_back(vio::read_file(ev, *file, bytes_of(got) + i, 1, static_cast<std::int64_t>(i)));
      std::size_t total = 0;
      for (auto &read : reads)
      {
        auto result = co_await read;
        REQUIRE_EXPECTED(result);
        total += result.value();
      }
      CHECK(total == text.size());
      CHECK(got == text);

      close_now(file, ev);
      CHECK(vio::unlink_file(ev, path).has_value());
      ev.stop();
    }(event_loop);
  });
  event_loop.run();
}

TEST_CASE("a negative offset reads and writes at the current position")
{
  vio::event_loop_t event_loop;
  event_loop.run_in_loop([&] {
    return [](vio::event_loop_t &ev) -> vio::task_t<void> {
      auto tmp = vio::mkstemp_file(ev, "test_file_position_XXXXXX");
      REQUIRE(tmp.has_value());
      auto file = std::move(tmp->first);
      auto path = std::move(tmp->second);
      const std::string first = "ab";
      const std::string second = "cd";
      auto wrote_first = co_await vio::write_file(ev, *file, bytes_of(first), first.size(), -1);
      REQUIRE_EXPECTED(wrote_first);
      auto wrote_second = co_await vio::write_file(ev, *file, bytes_of(second), second.size(), -1);
      REQUIRE_EXPECTED(wrote_second);
      std::string back(4, '\0');
      auto read = co_await vio::read_file(ev, *file, bytes_of(back), back.size(), 0);
      REQUIRE_EXPECTED(read);
      CHECK(read.value() == 4);
      CHECK(back == "abcd");
      auto at_end = co_await vio::read_file(ev, *file, bytes_of(back), back.size(), -1);
      REQUIRE_EXPECTED(at_end);
      CHECK(at_end.value() == 0);
      close_now(file, ev);
      CHECK(vio::unlink_file(ev, path).has_value());
      ev.stop();
    }(event_loop);
  });
  event_loop.run();
}

TEST_CASE("a positional read or write leaves the current position where it was")
{
  vio::event_loop_t event_loop;
  bool completed = false;
  event_loop.run_in_loop([&] {
    return [](vio::event_loop_t &ev, bool &completed) -> vio::task_t<void> {
      auto tmp = vio::mkstemp_file(ev, "test_file_keep_position_XXXXXX");
      REQUIRE(tmp.has_value());
      auto file = std::move(tmp->first);
      auto path = std::move(tmp->second);
      const std::string abcd = "abcd";
      const std::string ef = "ef";
      const std::string z = "Z";
      const std::string gh = "gh";
      const std::string ij = "ij";
      const std::string y = "Y";
      const std::string kl = "kl";
      std::string two(2, '\0');

      auto wrote_abcd = co_await vio::write_file(ev, *file, bytes_of(abcd), abcd.size(), -1);
      REQUIRE_EXPECTED(wrote_abcd);
      auto read_front = co_await vio::read_file(ev, *file, bytes_of(two), two.size(), 0);
      REQUIRE_EXPECTED(read_front);
      CHECK(read_front.value() == 2);
      CHECK(two == "ab");
      auto wrote_ef = co_await vio::write_file(ev, *file, bytes_of(ef), ef.size(), -1);
      REQUIRE_EXPECTED(wrote_ef);
      auto wrote_z = co_await vio::write_file(ev, *file, bytes_of(z), z.size(), 1);
      REQUIRE_EXPECTED(wrote_z);
      auto wrote_gh = co_await vio::write_file(ev, *file, bytes_of(gh), gh.size(), -1);
      REQUIRE_EXPECTED(wrote_gh);

      auto read_sync = vio::read_file_sync(*file, bytes_of(two), 1, 0);
      REQUIRE_EXPECTED(read_sync);
      CHECK(read_sync.value() == 1);
      auto wrote_ij = vio::write_file_sync(*file, bytes_of(ij), ij.size(), -1);
      REQUIRE_EXPECTED(wrote_ij);
      auto wrote_y = vio::write_file_sync(*file, bytes_of(y), y.size(), 0);
      REQUIRE_EXPECTED(wrote_y);
      auto wrote_kl = vio::write_file_sync(*file, bytes_of(kl), kl.size(), -1);
      REQUIRE_EXPECTED(wrote_kl);

      auto at_end = co_await vio::read_file(ev, *file, bytes_of(two), two.size(), -1);
      REQUIRE_EXPECTED(at_end);
      CHECK(at_end.value() == 0);
      std::string whole(16, '\0');
      auto read_whole = vio::read_file_sync(*file, bytes_of(whole), whole.size(), 0);
      REQUIRE_EXPECTED(read_whole);
      CHECK(whole.substr(0, read_whole.value()) == "YZcdefghijkl");

      close_now(file, ev);
      CHECK(vio::unlink_file(ev, path).has_value());
      completed = true;
      ev.stop();
    }(event_loop, completed);
  });
  event_loop.run();
  CHECK(completed);
}

TEST_CASE("send_file starts at the input offset and stops at the length")
{
  vio::event_loop_t event_loop;
  event_loop.run_in_loop([&] {
    return [](vio::event_loop_t &ev) -> vio::task_t<void> {
      auto source = vio::mkstemp_file(ev, "test_send_offset_src_XXXXXX");
      auto dest = vio::mkstemp_file(ev, "test_send_offset_dst_XXXXXX");
      REQUIRE(source.has_value());
      REQUIRE(dest.has_value());
      const std::string text = "0123456789";
      REQUIRE(vio::write_file_sync(*source->first, bytes_of(text), text.size(), 0).has_value());
      auto sent = co_await vio::send_file(ev, *dest->first, *source->first, 3, 4);
      REQUIRE_EXPECTED(sent);
      CHECK(sent.value() == 4);
      auto past_end = co_await vio::send_file(ev, *dest->first, *source->first, 100, 4);
      REQUIRE_EXPECTED(past_end);
      CHECK(past_end.value() == 0);
      std::string back(8, '\0');
      auto read = vio::read_file_sync(*dest->first, bytes_of(back), back.size(), 0);
      REQUIRE_EXPECTED(read);
      CHECK(read.value() == 4);
      CHECK(back.substr(0, 4) == "3456");
      close_now(source->first, ev);
      close_now(dest->first, ev);
      CHECK(vio::unlink_file(ev, source->second).has_value());
      CHECK(vio::unlink_file(ev, dest->second).has_value());
      ev.stop();
    }(event_loop);
  });
  event_loop.run();
}

TEST_CASE("a read still queued when cancelled ends with errc::canceled and leaves the buffer alone")
{
  vio::event_loop_t event_loop;
  pool_gate_t gate(more_than_any_pool);
  bool finished = false;
  event_loop.run_in_loop([&] {
    return [](vio::event_loop_t &ev, pool_gate_t &gate, bool &finished) -> vio::task_t<void> {
      auto tmp = vio::mkstemp_file(ev, "test_file_cancel_XXXXXX");
      REQUIRE(tmp.has_value());
      auto file = std::move(tmp->first);
      auto path = std::move(tmp->second);
      const std::string text = "do not read me";
      REQUIRE(vio::write_file_sync(*file, bytes_of(text), text.size(), 0).has_value());

      const bool queued_on_pool = !vio::detail::core(ev).backend().supports_async_files();
      gate.block(ev, vio::detail::pool_queue::file);
      std::string buffer(text.size(), '.');
      vio::cancellation_t cancel;
      auto pending = vio::read_file(ev, *file, bytes_of(buffer), buffer.size(), 0, &cancel);
      cancel.cancel();
      auto result = co_await pending;
      if (queued_on_pool)
      {
        CHECK_FALSE(result.has_value());
        if (!result.has_value())
        {
          CHECK(result.error().code == vio::errc::canceled);
          CHECK(vio::is_cancelled(result.error()));
        }
        CHECK(buffer == std::string(text.size(), '.'));
      }
      else
      {
        CHECK((result.has_value() || vio::is_cancelled(result.error())));
      }
      gate.release();

      close_now(file, ev);
      CHECK(vio::unlink_file(ev, path).has_value());
      finished = true;
      ev.stop();
    }(event_loop, gate, finished);
  });
  event_loop.run();
  CHECK(finished);
  CHECK(gate.finished == static_cast<int>(more_than_any_pool));
}

#if !defined(_WIN32)
TEST_CASE("files vio opens are closed on exec")
{
  vio::event_loop_t event_loop;
  auto tmp = vio::mkstemp_file(event_loop, "test_file_cloexec_XXXXXX");
  REQUIRE(tmp.has_value());
  const int temporary_flags = ::fcntl(tmp->first->handle, F_GETFD);
  REQUIRE(temporary_flags != -1);
  CHECK((temporary_flags & FD_CLOEXEC) != 0);
  auto opened = vio::open_file(event_loop, tmp->second, vio::file_open_flag_t::rdonly, 0);
  REQUIRE_EXPECTED(opened);
  const int opened_flags = ::fcntl(opened.value()->handle, F_GETFD);
  REQUIRE(opened_flags != -1);
  CHECK((opened_flags & FD_CLOEXEC) != 0);
  close_now(opened.value(), event_loop);
  close_now(tmp->first, event_loop);
  CHECK(vio::unlink_file(event_loop, tmp->second).has_value());
}
#endif

#if !defined(_WIN32) && !defined(VIO_FILE_TEST_UNDER_TSAN)
TEST_CASE("file work runs in a process forked after the file pool started")
{
  REQUIRE(copy_through_the_pool() == 0);
  const int status = status_of_forked(&copy_through_the_pool);
  REQUIRE(status != -1);
  CHECK_MESSAGE(WIFEXITED(status), "the child was killed by signal " << (WIFSIGNALED(status) ? WTERMSIG(status) : 0));
  CHECK(WEXITSTATUS(status) == 0);
}
#endif

TEST_CASE("cancelling a read that already completed changes nothing")
{
  vio::event_loop_t event_loop;
  event_loop.run_in_loop([&] {
    return [](vio::event_loop_t &ev) -> vio::task_t<void> {
      auto tmp = vio::mkstemp_file(ev, "test_file_late_cancel_XXXXXX");
      REQUIRE(tmp.has_value());
      auto file = std::move(tmp->first);
      auto path = std::move(tmp->second);
      const std::string text = "read me";
      REQUIRE(vio::write_file_sync(*file, bytes_of(text), text.size(), 0).has_value());
      vio::cancellation_t cancel;
      std::string buffer(text.size(), '\0');
      auto result = co_await vio::read_file(ev, *file, bytes_of(buffer), buffer.size(), 0, &cancel);
      cancel.cancel();
      REQUIRE_EXPECTED(result);
      CHECK(result.value() == text.size());
      CHECK(buffer == text);
      close_now(file, ev);
      CHECK(vio::unlink_file(ev, path).has_value());
      ev.stop();
    }(event_loop);
  });
  event_loop.run();
}
TEST_CASE("the file object store writes nested keys in full and refuses names that leave its directory")
{
  vio::event_loop_t event_loop;
  auto root = vio::mkdtemp_path(event_loop, "test_file_store_XXXXXX");
  REQUIRE(root.has_value());
  bool completed = false;
  event_loop.run_in_loop([&] {
    return [](vio::event_loop_t &ev, std::string root, bool &completed) -> vio::task_t<void> {
      vio::objstore::file_dir_io_manager_t store(root + "/objects", ev);
      constexpr std::size_t size = 1000;
      auto data = std::make_shared<std::uint8_t[]>(size);
      for (std::size_t i = 0; i < size; ++i)
        data[i] = static_cast<std::uint8_t>(i * 7);

      auto nested = co_await store.write_object("one/two/three", data, size);
      REQUIRE_EXPECTED(nested);
      auto info = co_await store.object_info("one/two/three");
      REQUIRE_EXPECTED(info);
      CHECK(info->exists);
      CHECK(info->size == size);
      std::vector<std::uint8_t> back(size);
      auto tail = co_await store.read_object("one/two/three", back.data(), {990, -1});
      REQUIRE_EXPECTED(tail);
      CHECK(tail.value() == 10);
      CHECK(back[9] == data[999]);
      auto whole = co_await store.read_object_all("one/two/three", back.data(), back.size());
      REQUIRE_EXPECTED(whole);
      CHECK(whole.value() == size);
      CHECK(std::equal(back.begin(), back.end(), data.get()));

      for (const char *name : {"../outside", "one/../../outside", "/absolute", "", "back\\slash"})
      {
        auto written = co_await store.write_object(name, data, size);
        CHECK_FALSE(written.has_value());
        if (!written.has_value())
          CHECK(written.error().code == vio::errc::invalid_argument);
        auto read = co_await store.read_object(name, back.data(), {0, 1});
        CHECK_FALSE(read.has_value());
        auto status = co_await store.object_info(name);
        CHECK_FALSE(status.has_value());
        auto removed = co_await store.remove_object(name);
        CHECK_FALSE(removed.has_value());
      }
      CHECK_FALSE(vio::stat_file(ev, root + "/outside").has_value());

      auto removed = co_await store.remove_object("one/two/three");
      REQUIRE_EXPECTED(removed);
      CHECK(vio::rmdir_path(ev, root + "/objects/one/two").has_value());
      CHECK(vio::rmdir_path(ev, root + "/objects/one").has_value());
      CHECK(vio::rmdir_path(ev, root + "/objects").has_value());
      completed = true;
      ev.stop();
    }(event_loop, root.value(), completed);
  });
  event_loop.run();
  CHECK(completed);
  CHECK(vio::rmdir_path(event_loop, root.value()).has_value());
}
} // TEST_SUITE
