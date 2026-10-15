#include <doctest/doctest.h>
#include <vio/event_loop.h>
#include <vio/event_pipe.h>

#include <cstddef>
#include <memory>
#include <new>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace
{
class guarded_region_t
{
public:
  explicit guarded_region_t(std::size_t size)
  {
#if defined(_WIN32)
    SYSTEM_INFO info{};
    ::GetSystemInfo(&info);
    const std::size_t page = info.dwPageSize;
    _size = (size + page - 1) / page * page;
    _data = ::VirtualAlloc(nullptr, _size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
#else
    const auto page = static_cast<std::size_t>(::sysconf(_SC_PAGESIZE));
    _size = (size + page - 1) / page * page;
    _data = ::mmap(nullptr, _size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (_data == MAP_FAILED)
      _data = nullptr;
#endif
  }

  guarded_region_t(const guarded_region_t &) = delete;
  guarded_region_t &operator=(const guarded_region_t &) = delete;

  ~guarded_region_t()
  {
    if (!_data)
      return;
#if defined(_WIN32)
    ::VirtualFree(_data, 0, MEM_RELEASE);
#else
    ::munmap(_data, _size);
#endif
  }

  [[nodiscard]] void *data() const noexcept
  {
    return _data;
  }

  [[nodiscard]] bool forbid_access() noexcept
  {
#if defined(_WIN32)
    DWORD previous = 0;
    return ::VirtualProtect(_data, _size, PAGE_NOACCESS, &previous) != 0;
#else
    return ::mprotect(_data, _size, PROT_NONE) == 0;
#endif
  }

private:
  void *_data = nullptr;
  std::size_t _size = 0;
};
} // namespace

TEST_CASE("an event pipe destroyed after its loop does not touch the loop")
{
  guarded_region_t region(sizeof(vio::event_loop_t));
  REQUIRE(region.data() != nullptr);
  auto *loop = new (region.data()) vio::event_loop_t();
  int delivered = 0;
  auto values = std::make_unique<vio::event_pipe_t<int>>(*loop, [&delivered](int &&value) { delivered += value; });
  auto signal = std::make_unique<vio::event_pipe_t<void>>(*loop, [&delivered] { ++delivered; });
  values->post_event(2);
  signal->post_event();
  loop->run_in_loop([loop] { loop->stop(); });
  loop->run();
  values->post_event(40);
  signal->post_event();
  loop->~event_loop_t();
  REQUIRE(region.forbid_access());

  values.reset();
  signal.reset();
  CHECK(delivered == 3);
}

TEST_CASE("an event pipe declared before the thread that runs its loop is destroyed after it")
{
  struct holder_t
  {
    std::unique_ptr<vio::event_pipe_t<int>> pipe;
    vio::thread_with_event_loop_t thread;
  };
  int delivered = 0;
  {
    holder_t holder;
    holder.pipe = std::make_unique<vio::event_pipe_t<int>>(holder.thread.event_loop(), [&delivered](int &&value) { delivered += value; });
    holder.thread.stop_and_join();
    holder.pipe->post_event(7);
  }
  CHECK(delivered == 0);
}
