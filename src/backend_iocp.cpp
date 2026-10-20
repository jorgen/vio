/*
Copyright (c) 2025 Jørgen Lind

  Permission is hereby granted, free of charge, to any person obtaining a copy of
  this software and associated documentation files (the "Software"), to deal in
  the Software without restriction, including without limitation the rights to
  use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
  of the Software, and to permit persons to whom the Software is furnished to do
  so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
*/


#if defined(_WIN32)

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <memory>
#include <new>
#include <type_traits>
#include <utility>
#include <vector>

#include "backends.h"
#include "vio/detail/sys.h"
#include "vio/errc.h"
#include "vio/loop/loop_core.h"

namespace vio::detail
{
namespace
{
constexpr LONG status_success = 0;
constexpr LONG status_pending = 0x00000103;
constexpr LONG status_cancelled = static_cast<LONG>(0xC0000120UL);
constexpr ULONG ioctl_afd_poll = 0x00012024;
constexpr ULONG file_open_disposition = 1;
constexpr DWORD sio_base_handle = 0x48000022;
constexpr DWORD sio_bsp_handle_select = 0x4800001C;
constexpr DWORD sio_bsp_handle_poll = 0x4800001D;
constexpr int max_provider_layers = 16;

constexpr ULONG afd_poll_receive = 0x0001;
constexpr ULONG afd_poll_send = 0x0004;
constexpr ULONG afd_poll_disconnect = 0x0008;
constexpr ULONG afd_poll_abort = 0x0010;
constexpr ULONG afd_poll_local_close = 0x0020;
constexpr ULONG afd_poll_accept = 0x0080;
constexpr ULONG afd_poll_connect_fail = 0x0100;

constexpr ULONG read_events = afd_poll_receive | afd_poll_disconnect | afd_poll_abort | afd_poll_accept | afd_poll_connect_fail;
constexpr ULONG write_events = afd_poll_send | afd_poll_connect_fail | afd_poll_abort;

constexpr ULONG_PTR afd_key = 0x41464400;
constexpr ULONG_PTR wake_key = 0x57414B45;
constexpr ULONG max_entries = 128;
constexpr std::size_t max_group_members = 32;
constexpr int shutdown_drain_rounds = 100;
constexpr DWORD shutdown_drain_wait_ms = 10;

struct io_status_block_t
{
  union
  {
    LONG status;
    void *pointer;
  };
  ULONG_PTR information;
};

struct unicode_string_t
{
  USHORT length;
  USHORT maximum_length;
  wchar_t *buffer;
};

struct object_attributes_t
{
  ULONG length;
  HANDLE root_directory;
  unicode_string_t *object_name;
  ULONG attributes;
  void *security_descriptor;
  void *security_quality_of_service;
};

struct afd_poll_handle_info_t
{
  HANDLE handle;
  ULONG events;
  LONG status;
};

struct afd_poll_info_t
{
  LONGLONG timeout;
  ULONG handle_count;
  ULONG exclusive;
  afd_poll_handle_info_t handles[1];
};

using io_apc_routine_t = void(NTAPI *)(void *context, io_status_block_t *status, ULONG reserved);
using nt_create_file_t = LONG(NTAPI *)(HANDLE *file, ACCESS_MASK access, object_attributes_t *attributes, io_status_block_t *status, LARGE_INTEGER *allocation, ULONG file_attributes, ULONG share, ULONG disposition, ULONG options, void *ea, ULONG ea_length);
using nt_device_io_control_file_t = LONG(NTAPI *)(HANDLE file, HANDLE event, io_apc_routine_t routine, void *context, io_status_block_t *status, ULONG code, void *input, ULONG input_length, void *output, ULONG output_length);
using nt_cancel_io_file_ex_t = LONG(NTAPI *)(HANDLE file, io_status_block_t *request, io_status_block_t *status);
using rtl_nt_status_to_dos_error_t = ULONG(NTAPI *)(LONG status);

struct nt_api_t
{
  nt_create_file_t create_file = nullptr;
  nt_device_io_control_file_t device_io_control_file = nullptr;
  nt_cancel_io_file_ex_t cancel_io_file_ex = nullptr;
  rtl_nt_status_to_dos_error_t status_to_dos_error = nullptr;
};

template <typename function_t>
function_t load_function(HMODULE module, const char *name) noexcept
{
  return reinterpret_cast<function_t>(reinterpret_cast<void (*)()>(::GetProcAddress(module, name)));
}

const nt_api_t *nt_api() noexcept
{
  static const nt_api_t api = [] {
    nt_api_t loaded;
    HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
      return loaded;
    loaded.create_file = load_function<nt_create_file_t>(ntdll, "NtCreateFile");
    loaded.device_io_control_file = load_function<nt_device_io_control_file_t>(ntdll, "NtDeviceIoControlFile");
    loaded.cancel_io_file_ex = load_function<nt_cancel_io_file_ex_t>(ntdll, "NtCancelIoFileEx");
    loaded.status_to_dos_error = load_function<rtl_nt_status_to_dos_error_t>(ntdll, "RtlNtStatusToDosError");
    return loaded;
  }();
  if (!api.create_file || !api.device_io_control_file || !api.cancel_io_file_ex || !api.status_to_dos_error)
    return nullptr;
  return &api;
}

[[noreturn]] void fatal(const char *what, unsigned long error) noexcept
{
  std::fprintf(stderr, "vio: %s failed (%lu)\n", what, error);
  std::abort();
}

bool query_provider_socket(SOCKET socket, DWORD control, SOCKET &out) noexcept
{
  SOCKET result = INVALID_SOCKET;
  DWORD bytes = 0;
  if (::WSAIoctl(socket, control, nullptr, 0, &result, sizeof(result), &bytes, nullptr, nullptr) == SOCKET_ERROR)
    return false;
  if (result == INVALID_SOCKET)
    return false;
  out = result;
  return true;
}

int resolve_base_socket(SOCKET socket, SOCKET &base) noexcept
{
  for (int layer = 0; layer < max_provider_layers; ++layer)
  {
    if (query_provider_socket(socket, sio_base_handle, base))
      return 0;
    const int error = ::WSAGetLastError();
    if (error == WSAENOTSOCK)
      return errc_from_wsa(error);
    SOCKET next = INVALID_SOCKET;
    if ((!query_provider_socket(socket, sio_bsp_handle_poll, next) || next == socket) && (!query_provider_socket(socket, sio_bsp_handle_select, next) || next == socket))
      return errc_from_wsa(error);
    socket = next;
  }
  return errc::not_supported;
}

DWORD wait_milliseconds(std::int64_t timeout_ns, unsigned repeat) noexcept
{
  if (timeout_ns < 0)
    return INFINITE;
  if (timeout_ns == 0)
    return 0;
  constexpr std::int64_t longest = static_cast<std::int64_t>(INFINITE) - 1;
  std::int64_t milliseconds = timeout_ns / 1000000 + (timeout_ns % 1000000 != 0 ? 1 : 0);
  if (repeat >= 2)
    milliseconds += std::int64_t{1} << (repeat - 2 < 20 ? repeat - 2 : 20);
  return static_cast<DWORD>(milliseconds < longest ? milliseconds : longest);
}

std::int64_t deadline_after(std::int64_t timeout_ns) noexcept
{
  const std::int64_t now = loop_core_t::now();
  if (timeout_ns > std::numeric_limits<std::int64_t>::max() - now)
    return std::numeric_limits<std::int64_t>::max();
  return now + timeout_ns;
}

ULONG events_for(std::uint8_t interest) noexcept
{
  ULONG events = 0;
  if (interest & interest_read)
    events |= read_events;
  if (interest & interest_write)
    events |= write_events;
  return events;
}

std::uint8_t interest_for(ULONG events) noexcept
{
  std::uint8_t interest = 0;
  if (events & (afd_poll_receive | afd_poll_disconnect | afd_poll_accept))
    interest |= interest_read;
  if (events & afd_poll_send)
    interest |= interest_write;
  return interest;
}

struct afd_group_t
{
  explicit afd_group_t(HANDLE handle) noexcept
    : device(handle)
  {
  }
  afd_group_t(const afd_group_t &) = delete;
  afd_group_t &operator=(const afd_group_t &) = delete;
  ~afd_group_t()
  {
    ::CloseHandle(device);
  }

  HANDLE device;
  std::size_t members = 0;
};

enum class poll_status : std::uint8_t
{
  idle,
  pending,
  cancelled
};

enum class list_id : std::uint8_t
{
  none,
  updates,
  failed,
  retired
};

struct poll_state_t
{
  io_status_block_t iosb;
  afd_poll_info_t info;
  io_watch_t *watch;
  afd_group_t *group;
  posted_t *done;
  poll_state_t *list_previous;
  poll_state_t *list_next;
  poll_state_t *all_previous;
  poll_state_t *all_next;
  HANDLE base;
  ULONG submitted;
  poll_status status;
  list_id list;
  bool deleted;
  bool dead;
};

static_assert(std::is_standard_layout_v<poll_state_t>);
static_assert(offsetof(poll_state_t, iosb) == 0);

poll_state_t *state_from(OVERLAPPED *overlapped) noexcept
{
  return reinterpret_cast<poll_state_t *>(reinterpret_cast<io_status_block_t *>(overlapped));
}

class state_list_t
{
public:
  explicit state_list_t(list_id id) noexcept
    : _id(id)
  {
  }

  [[nodiscard]] bool empty() const noexcept
  {
    return _head == nullptr;
  }

  void push_back(poll_state_t &state) noexcept
  {
    state.list = _id;
    state.list_next = nullptr;
    state.list_previous = _tail;
    if (_tail)
      _tail->list_next = &state;
    else
      _head = &state;
    _tail = &state;
  }

  void remove(poll_state_t &state) noexcept
  {
    if (state.list_previous)
      state.list_previous->list_next = state.list_next;
    else
      _head = state.list_next;
    if (state.list_next)
      state.list_next->list_previous = state.list_previous;
    else
      _tail = state.list_previous;
    state.list_previous = nullptr;
    state.list_next = nullptr;
    state.list = list_id::none;
  }

  poll_state_t *pop_front() noexcept
  {
    auto *state = _head;
    if (state)
      remove(*state);
    return state;
  }

private:
  poll_state_t *_head = nullptr;
  poll_state_t *_tail = nullptr;
  list_id _id;
};

class iocp_backend_t final : public backend_t
{
public:
  iocp_backend_t(loop_core_t &loop, HANDLE port, const nt_api_t &nt) noexcept
    : backend_t(loop)
    , _port(port)
    , _nt(nt)
  {
  }

  ~iocp_backend_t() override
  {
    for (; _entries_next < _entries_count; ++_entries_next)
    {
      const auto &entry = _entries[_entries_next];
      if (entry.lpCompletionKey != afd_key || entry.lpOverlapped == nullptr)
        continue;
      auto *state = state_from(entry.lpOverlapped);
      if (state->status == poll_status::idle)
        continue;
      state->status = poll_status::idle;
      --_outstanding;
    }
    for (auto *state = _all; state; state = state->all_next)
    {
      if (state->status == poll_status::pending)
        cancel(*state);
    }
    drain_outstanding();
    _groups.clear();
    drain_outstanding();
    std::size_t held = 0;
    for (auto *state = _all; state;)
    {
      auto *next = state->all_next;
      if (state->status == poll_status::idle)
      {
        if (state->watch)
          state->watch->backend_state = nullptr;
        delete state;
      }
      else
      {
        ++held;
      }
      state = next;
    }
    if (held > 0)
      std::fprintf(stderr, "vio: iocp backend destroyed while the kernel still holds %zu socket poll(s); leaking them\n", held);
    ::CloseHandle(_port);
  }

  [[nodiscard]] const char *name() const noexcept override
  {
    return "iocp";
  }

  [[nodiscard]] int add_watch(io_watch_t &watch) override
  {
    SOCKET base = INVALID_SOCKET;
    if (int result = resolve_base_socket(watch.socket, base); result < 0)
      return result;
    int error = 0;
    auto *group = acquire_group(error);
    if (!group)
      return error;
    auto *state = new (std::nothrow) poll_state_t{};
    if (!state)
    {
      release_group(*group);
      return errc::out_of_memory;
    }
    state->watch = &watch;
    state->group = group;
    state->base = reinterpret_cast<HANDLE>(base);
    state->all_next = _all;
    if (_all)
      _all->all_previous = state;
    _all = state;
    watch.backend_state = state;
    watch.closed = false;
    watch.armed = 0;
    return 0;
  }

  void remove_watch(io_watch_t &watch, posted_t &done) override
  {
    watch.closed = true;
    watch.armed = 0;
    auto *state = static_cast<poll_state_t *>(std::exchange(watch.backend_state, nullptr));
    if (!state)
    {
      _loop.defer(done);
      return;
    }
    unlink(*state);
    state->deleted = true;
    state->watch = nullptr;
    state->done = &done;
    if (state->status == poll_status::pending)
      cancel(*state);
    if (state->status == poll_status::idle)
      finish_removal(*state);
  }

  void wake() noexcept override
  {
    ::PostQueuedCompletionStatus(_port, 0, wake_key, nullptr);
  }

  void poll(std::int64_t timeout_ns) override
  {
    release_retired();
    flush_updates();
    if (_entries_next < _entries_count)
    {
      deliver();
      dispatch_failed();
      return;
    }
    if (!_failed.empty())
      timeout_ns = 0;
    const std::int64_t deadline = timeout_ns > 0 ? deadline_after(timeout_ns) : 0;
    for (unsigned repeat = 0;; ++repeat)
    {
      ULONG count = 0;
      if (::GetQueuedCompletionStatusEx(_port, _entries, max_entries, &count, wait_milliseconds(timeout_ns, repeat), FALSE))
      {
        _entries_next = 0;
        _entries_count = count;
        deliver();
        break;
      }
      const DWORD error = ::GetLastError();
      if (error != WAIT_TIMEOUT)
        fatal("GetQueuedCompletionStatusEx", error);
      if (timeout_ns <= 0)
        break;
      const std::int64_t now = loop_core_t::now();
      if (now >= deadline)
        break;
      timeout_ns = deadline - now;
    }
    dispatch_failed();
  }

protected:
  void arm(io_watch_t &watch, std::uint8_t interest) override
  {
    auto *state = static_cast<poll_state_t *>(watch.backend_state);
    if (!state || watch.closed || state->list != list_id::none || state->status == poll_status::cancelled)
      return;
    if (state->status == poll_status::pending && (events_for(interest) & ~state->submitted) == 0)
      return;
    _updates.push_back(*state);
  }

private:
  afd_group_t *acquire_group(int &error)
  {
    afd_group_t *group = _spare && _spare->members < max_group_members ? _spare : nullptr;
    for (auto it = _groups.rbegin(); !group && it != _groups.rend(); ++it)
    {
      if ((*it)->members < max_group_members)
        group = it->get();
    }
    if (!group)
    {
      group = open_group(error);
      if (!group)
        return nullptr;
    }
    ++group->members;
    _spare = group;
    return group;
  }

  void release_group(afd_group_t &group) noexcept
  {
    --group.members;
    _spare = &group;
  }

  afd_group_t *open_group(int &error)
  {
    wchar_t device_name[] = L"\\Device\\Afd\\Vio";
    unicode_string_t name{static_cast<USHORT>(sizeof(device_name) - sizeof(wchar_t)), static_cast<USHORT>(sizeof(device_name)), device_name};
    object_attributes_t attributes{static_cast<ULONG>(sizeof(object_attributes_t)), nullptr, &name, 0, nullptr, nullptr};
    io_status_block_t status_block{};
    HANDLE device = nullptr;
    const LONG status = _nt.create_file(&device, SYNCHRONIZE, &attributes, &status_block, nullptr, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, file_open_disposition, 0, nullptr, 0);
    if (status != status_success)
    {
      error = errc_from_win32(_nt.status_to_dos_error(status));
      return nullptr;
    }
    auto group = std::unique_ptr<afd_group_t>(new (std::nothrow) afd_group_t(device));
    if (!group)
    {
      ::CloseHandle(device);
      error = errc::out_of_memory;
      return nullptr;
    }
    if (!::CreateIoCompletionPort(device, _port, afd_key, 0) || !::SetFileCompletionNotificationModes(device, FILE_SKIP_SET_EVENT_ON_HANDLE))
    {
      error = errc_from_win32(::GetLastError());
      return nullptr;
    }
    _groups.push_back(std::move(group));
    return _groups.back().get();
  }

  bool submit(poll_state_t &state, ULONG events) noexcept
  {
    events |= afd_poll_local_close;
    state.info.timeout = std::numeric_limits<LONGLONG>::max();
    state.info.handle_count = 1;
    state.info.exclusive = FALSE;
    state.info.handles[0].handle = state.base;
    state.info.handles[0].events = events;
    state.info.handles[0].status = 0;
    state.iosb.status = status_pending;
    state.iosb.information = 0;
    const LONG status = _nt.device_io_control_file(state.group->device, nullptr, nullptr, &state.iosb, &state.iosb, ioctl_afd_poll, &state.info, sizeof(state.info), &state.info, sizeof(state.info));
    if (status < 0)
      return false;
    state.status = poll_status::pending;
    state.submitted = events;
    ++_outstanding;
    return true;
  }

  void cancel(poll_state_t &state) noexcept
  {
    io_status_block_t ignored{};
    _nt.cancel_io_file_ex(state.group->device, &state.iosb, &ignored);
    state.status = poll_status::cancelled;
    state.submitted = 0;
  }

  void update(poll_state_t &state) noexcept
  {
    auto &watch = *state.watch;
    ULONG wanted = 0;
    if (!watch.readers.empty())
      wanted |= read_events;
    if (!watch.writers.empty())
      wanted |= write_events;
    if (wanted == 0)
      return;
    if (state.dead)
    {
      _failed.push_back(state);
      return;
    }
    switch (state.status)
    {
    case poll_status::cancelled:
      return;
    case poll_status::pending:
      if ((wanted & ~state.submitted) != 0)
        cancel(state);
      return;
    case poll_status::idle:
      if (submit(state, wanted))
        watch.armed = interest_for(wanted);
      else
        _failed.push_back(state);
      return;
    }
  }

  void flush_updates() noexcept
  {
    while (auto *state = _updates.pop_front())
      update(*state);
  }

  void deliver()
  {
    while (_entries_next < _entries_count)
    {
      const auto entry = _entries[_entries_next++];
      handle(entry);
    }
  }

  void handle(const OVERLAPPED_ENTRY &entry)
  {
    if (entry.lpCompletionKey != afd_key || entry.lpOverlapped == nullptr)
      return;
    complete(*state_from(entry.lpOverlapped));
  }

  void complete(poll_state_t &state)
  {
    if (state.status == poll_status::idle)
      return;
    --_outstanding;
    state.status = poll_status::idle;
    state.submitted = 0;
    if (state.deleted)
    {
      finish_removal(state);
      return;
    }
    auto &watch = *state.watch;
    watch.armed = 0;
    bool readable = false;
    bool writable = false;
    const LONG status = state.iosb.status;
    if (status == status_cancelled)
    {
    }
    else if (status < 0)
    {
      readable = true;
      writable = true;
    }
    else if (state.info.handle_count >= 1)
    {
      const ULONG events = state.info.handles[0].events;
      if (events & afd_poll_local_close)
      {
        state.dead = true;
        readable = true;
        writable = true;
      }
      else
      {
        readable = (events & read_events) != 0;
        writable = (events & write_events) != 0;
      }
    }
    if (readable || writable)
      dispatch(watch, readable, writable);
    if (state.deleted || state.list != list_id::none)
      return;
    if (!watch.readers.empty() || !watch.writers.empty())
      _updates.push_back(state);
  }

  void dispatch_failed()
  {
    while (auto *state = _failed.pop_front())
    {
      if (!state->deleted)
        dispatch(*state->watch, true, true);
    }
  }

  void finish_removal(poll_state_t &state) noexcept
  {
    _loop.defer(*std::exchange(state.done, nullptr));
    release_group(*state.group);
    _retired.push_back(state);
  }

  void unlink(poll_state_t &state) noexcept
  {
    switch (state.list)
    {
    case list_id::updates:
      _updates.remove(state);
      return;
    case list_id::failed:
      _failed.remove(state);
      return;
    case list_id::retired:
      _retired.remove(state);
      return;
    case list_id::none:
      return;
    }
  }

  void release_retired() noexcept
  {
    while (auto *state = _retired.pop_front())
    {
      if (state->all_previous)
        state->all_previous->all_next = state->all_next;
      else
        _all = state->all_next;
      if (state->all_next)
        state->all_next->all_previous = state->all_previous;
      delete state;
    }
  }

  void drain_outstanding() noexcept
  {
    OVERLAPPED_ENTRY entries[max_entries];
    for (int round = 0; _outstanding > 0 && round < shutdown_drain_rounds; ++round)
    {
      ULONG count = 0;
      if (!::GetQueuedCompletionStatusEx(_port, entries, max_entries, &count, shutdown_drain_wait_ms, FALSE))
      {
        if (::GetLastError() == WAIT_TIMEOUT)
          continue;
        return;
      }
      for (ULONG i = 0; i < count; ++i)
      {
        if (entries[i].lpCompletionKey != afd_key || entries[i].lpOverlapped == nullptr)
          continue;
        auto *state = state_from(entries[i].lpOverlapped);
        if (state->status == poll_status::idle)
          continue;
        state->status = poll_status::idle;
        --_outstanding;
      }
    }
  }

  HANDLE _port;
  const nt_api_t &_nt;
  std::vector<std::unique_ptr<afd_group_t>> _groups;
  afd_group_t *_spare = nullptr;
  state_list_t _updates{list_id::updates};
  state_list_t _failed{list_id::failed};
  state_list_t _retired{list_id::retired};
  poll_state_t *_all = nullptr;
  std::size_t _outstanding = 0;
  OVERLAPPED_ENTRY _entries[max_entries] = {};
  ULONG _entries_next = 0;
  ULONG _entries_count = 0;
};
} // namespace

std::unique_ptr<backend_t> make_iocp_backend(loop_core_t &loop, int &error)
{
  ensure_winsock();
  const nt_api_t *nt = nt_api();
  if (!nt)
  {
    error = errc::not_supported;
    return nullptr;
  }
  HANDLE port = ::CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 1);
  if (!port)
  {
    error = errc_from_win32(::GetLastError());
    return nullptr;
  }
  auto backend = std::unique_ptr<iocp_backend_t>(new (std::nothrow) iocp_backend_t(loop, port, *nt));
  if (!backend)
  {
    ::CloseHandle(port);
    error = errc::out_of_memory;
    return nullptr;
  }
  return backend;
}
} // namespace vio::detail

#if defined(VIO_INTERNAL_TESTS)
#include <doctest/doctest.h>

#include <chrono>
#include <functional>
#include <string>
#include <thread>

#include "vio/loop/socket.h"

namespace vio::detail
{
namespace
{
constexpr std::int64_t iocp_test_deadline_ns = std::int64_t{10} * 1000000000;

struct iocp_test_pair_t
{
  SOCKET client = INVALID_SOCKET;
  SOCKET server = INVALID_SOCKET;
};

SOCKET iocp_test_listener(sockaddr_storage &bound, int &bound_length)
{
  SOCKET listener = INVALID_SOCKET;
  REQUIRE(socket_open(AF_INET, SOCK_STREAM, IPPROTO_TCP, listener) == 0);
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  REQUIRE(socket_bind(listener, reinterpret_cast<const sockaddr *>(&address), static_cast<int>(sizeof(address))) == 0);
  REQUIRE(socket_listen(listener, 128) == 0);
  bound_length = static_cast<int>(sizeof(bound));
  REQUIRE(socket_name(listener, bound, bound_length) == 0);
  return listener;
}

iocp_test_pair_t iocp_test_pair()
{
  sockaddr_storage bound{};
  int bound_length = 0;
  SOCKET listener = iocp_test_listener(bound, bound_length);
  iocp_test_pair_t pair;
  REQUIRE(socket_open(AF_INET, SOCK_STREAM, IPPROTO_TCP, pair.client) == 0);
  const int connected = socket_connect(pair.client, reinterpret_cast<const sockaddr *>(&bound), bound_length);
  REQUIRE((connected == 0 || connected == errc::in_progress));
  const auto give_up = std::chrono::steady_clock::now() + std::chrono::seconds(5);
  for (;;)
  {
    const int accepted = socket_accept(listener, pair.server, nullptr, nullptr);
    if (accepted == 0)
      break;
    REQUIRE(accepted == errc::again);
    REQUIRE(std::chrono::steady_clock::now() < give_up);
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  for (;;)
  {
    sockaddr_storage peer{};
    int peer_length = static_cast<int>(sizeof(peer));
    if (socket_peer_name(pair.client, peer, peer_length) == 0)
      break;
    REQUIRE(std::chrono::steady_clock::now() < give_up);
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  socket_close(listener);
  return pair;
}

struct iocp_probe_t : io_op_t
{
  int completions = 0;
  std::function<void(iocp_probe_t &)> on_complete;

  iocp_probe_t()
  {
    owner = this;
    keeps_alive = false;
    complete = [](io_op_t *op) {
      auto &self = *static_cast<iocp_probe_t *>(op->owner);
      ++self.completions;
      if (self.on_complete)
        self.on_complete(self);
    };
  }
};

struct iocp_step_t
{
  posted_t node;
  std::function<void()> body;

  iocp_step_t()
  {
    node.owner = this;
    node.run = [](posted_t *raw) { static_cast<iocp_step_t *>(raw->owner)->body(); };
  }
};

struct iocp_fixture_t
{
  loop_core_t loop{backend_kind::iocp};
  std::vector<socket_resource_t *> sockets;
  timer_node_t watchdog;
  iocp_step_t start;
  std::int64_t deadline_ns;
  bool timed_out = false;

  explicit iocp_fixture_t(std::int64_t deadline = iocp_test_deadline_ns)
    : deadline_ns(deadline)
  {
    watchdog.owner = this;
    watchdog.keeps_alive = false;
    watchdog.fire = [](timer_node_t *node) {
      auto &self = *static_cast<iocp_fixture_t *>(node->owner);
      self.timed_out = true;
      self.finish();
    };
  }

  iocp_fixture_t(const iocp_fixture_t &) = delete;
  iocp_fixture_t &operator=(const iocp_fixture_t &) = delete;

  ~iocp_fixture_t()
  {
    loop.remove_timer(watchdog);
    for (auto *resource : sockets)
    {
      if (!resource)
        continue;
      finish();
      loop.run();
      return;
    }
  }

  socket_resource_t *adopt(SOCKET socket)
  {
    auto *resource = new socket_resource_t(loop, "iocp test socket");
    sockets.push_back(resource);
    REQUIRE(resource->adopt(socket) == 0);
    return resource;
  }

  static void release_parked(socket_resource_t &resource) noexcept
  {
    while (auto *op = resource.watch.readers.front())
      resource.cancel(*op);
    while (auto *op = resource.watch.writers.front())
      resource.cancel(*op);
  }

  void finish()
  {
    loop.remove_timer(watchdog);
    for (auto *&resource : sockets)
    {
      if (!resource)
        continue;
      resource->close(
        [](void *raw) {
          auto *closed = static_cast<socket_resource_t *>(raw);
          release_parked(*closed);
          delete closed;
        },
        resource);
      resource = nullptr;
    }
    loop.stop();
  }

  void run(std::function<void()> body)
  {
    REQUIRE(std::string(loop.backend_name()) == "iocp");
    start.body = std::move(body);
    loop.add_timer(watchdog, loop_core_t::now() + deadline_ns);
    loop.post(start.node);
    loop.run();
    CHECK(loop.open_resources() == 0);
  }
};

std::int64_t iocp_send_byte(socket_resource_t *socket)
{
  std::byte byte{0x2a};
  return socket_send(socket->native(), const_bytes_t(&byte, 1));
}
} // namespace

TEST_CASE("iocp: timeouts round up to whole milliseconds")
{
  CHECK(wait_milliseconds(-1, 0) == INFINITE);
  CHECK(wait_milliseconds(0, 0) == 0);
  CHECK(wait_milliseconds(1, 0) == 1);
  CHECK(wait_milliseconds(1000000, 0) == 1);
  CHECK(wait_milliseconds(1000001, 0) == 2);
  CHECK(wait_milliseconds(5000000, 1) == 5);
  CHECK(wait_milliseconds(5000000, 2) == 6);
  CHECK(wait_milliseconds(5000000, 4) == 9);
  CHECK(wait_milliseconds(std::numeric_limits<std::int64_t>::max(), 0) == INFINITE - 1);
  CHECK(wait_milliseconds(1, 200) == 1 + (DWORD{1} << 20));
}

TEST_CASE("iocp: a writer parked behind a pending read poll still wakes")
{
  iocp_fixture_t fixture;
  auto pair = iocp_test_pair();
  auto *server = fixture.adopt(pair.server);
  fixture.adopt(pair.client);
  iocp_probe_t reader;
  iocp_probe_t writer;
  iocp_step_t second;
  writer.on_complete = [&](iocp_probe_t &) {
    server->cancel(reader);
    fixture.finish();
  };
  second.body = [&] { server->wait(interest_write, writer); };
  fixture.run([&] {
    std::byte buffer[1];
    const bool would_block = socket_recv(server->native(), buffer) == errc::again;
    CHECK(would_block);
    if (!would_block)
    {
      fixture.finish();
      return;
    }
    server->wait(interest_read, reader);
    fixture.loop.post(second.node);
  });
  CHECK_FALSE(fixture.timed_out);
  CHECK(writer.completions == 1);
  CHECK(reader.completions == 0);
}

TEST_CASE("iocp: a test that outlives its deadline ends with its operations released")
{
  iocp_fixture_t fixture(std::int64_t{100} * 1000000);
  auto pair = iocp_test_pair();
  auto *server = fixture.adopt(pair.server);
  fixture.adopt(pair.client);
  iocp_probe_t reader;
  fixture.run([&] {
    std::byte buffer[1];
    CHECK(socket_recv(server->native(), buffer) == errc::again);
    server->wait(interest_read, reader);
  });
  CHECK(fixture.timed_out);
  CHECK_FALSE(reader.parked);
  CHECK(reader.completions == 0);
}

TEST_CASE("iocp: sockets beyond one AFD device all wake")
{
  constexpr int lanes = 40;
  iocp_fixture_t fixture;
  std::vector<socket_resource_t *> servers;
  std::vector<socket_resource_t *> clients;
  std::vector<std::unique_ptr<iocp_probe_t>> readers;
  int woke = 0;
  for (int i = 0; i < lanes; ++i)
  {
    auto pair = iocp_test_pair();
    servers.push_back(fixture.adopt(pair.server));
    clients.push_back(fixture.adopt(pair.client));
    auto reader = std::make_unique<iocp_probe_t>();
    auto *server = servers.back();
    reader->on_complete = [&woke, &fixture, server](iocp_probe_t &op) {
      std::byte buffer[8];
      auto got = socket_recv(server->native(), buffer);
      if (got == errc::again)
      {
        server->wait(interest_read, op);
        return;
      }
      CHECK(got == 1);
      if (++woke == lanes)
        fixture.finish();
    };
    readers.push_back(std::move(reader));
  }
  iocp_step_t second;
  second.body = [&] {
    for (auto *client : clients)
      CHECK(iocp_send_byte(client) == 1);
  };
  fixture.run([&] {
    for (int i = 0; i < lanes; ++i)
      servers[i]->wait(interest_read, *readers[i]);
    fixture.loop.post(second.node);
  });
  CHECK_FALSE(fixture.timed_out);
  CHECK(woke == lanes);
}

TEST_CASE("iocp: a listening socket wakes its reader for a connection")
{
  iocp_fixture_t fixture;
  sockaddr_storage bound{};
  int bound_length = 0;
  auto *listener = fixture.adopt(iocp_test_listener(bound, bound_length));
  SOCKET client = INVALID_SOCKET;
  REQUIRE(socket_open(AF_INET, SOCK_STREAM, IPPROTO_TCP, client) == 0);
  auto *connecting = fixture.adopt(client);
  iocp_probe_t reader;
  int accepted = -1;
  reader.on_complete = [&](iocp_probe_t &op) {
    SOCKET socket = INVALID_SOCKET;
    accepted = socket_accept(listener->native(), socket, nullptr, nullptr);
    if (accepted == errc::again)
    {
      listener->wait(interest_read, op);
      return;
    }
    if (accepted == 0)
      socket_close(socket);
    fixture.finish();
  };
  fixture.run([&] {
    listener->wait(interest_read, reader);
    const int connected = socket_connect(connecting->native(), reinterpret_cast<const sockaddr *>(&bound), bound_length);
    CHECK((connected == 0 || connected == errc::in_progress));
  });
  CHECK_FALSE(fixture.timed_out);
  CHECK(accepted == 0);
}

TEST_CASE("iocp: a refused connect wakes the writer and reports the refusal")
{
  iocp_fixture_t fixture;
  sockaddr_storage bound{};
  int bound_length = 0;
  socket_close(iocp_test_listener(bound, bound_length));
  SOCKET client = INVALID_SOCKET;
  REQUIRE(socket_open(AF_INET, SOCK_STREAM, IPPROTO_TCP, client) == 0);
  auto *connecting = fixture.adopt(client);
  iocp_probe_t writer;
  int pending = 0;
  writer.on_complete = [&](iocp_probe_t &) {
    pending = socket_pending_error(connecting->native());
    fixture.finish();
  };
  fixture.run([&] {
    const int connected = socket_connect(connecting->native(), reinterpret_cast<const sockaddr *>(&bound), bound_length);
    CHECK(connected == errc::in_progress);
    if (connected != errc::in_progress)
    {
      fixture.finish();
      return;
    }
    connecting->wait(interest_write, writer);
  });
  CHECK_FALSE(fixture.timed_out);
  CHECK(writer.completions == 1);
  CHECK(pending == errc::connection_refused);
}

TEST_CASE("iocp: a reader parked on a socket whose peer resets is woken")
{
  iocp_fixture_t fixture;
  auto pair = iocp_test_pair();
  auto *server = fixture.adopt(pair.server);
  iocp_probe_t reader;
  std::int64_t received = 0;
  reader.on_complete = [&](iocp_probe_t &) {
    std::byte buffer[8];
    received = socket_recv(server->native(), buffer);
    fixture.finish();
  };
  iocp_step_t second;
  second.body = [&] {
    linger abort_on_close{};
    abort_on_close.l_onoff = 1;
    abort_on_close.l_linger = 0;
    CHECK(socket_set_option(pair.client, SOL_SOCKET, SO_LINGER, &abort_on_close, static_cast<int>(sizeof(abort_on_close))) == 0);
    CHECK(socket_close(pair.client) == 0);
  };
  fixture.run([&] {
    server->wait(interest_read, reader);
    fixture.loop.post(second.node);
  });
  CHECK_FALSE(fixture.timed_out);
  CHECK(reader.completions == 1);
  CHECK(received == errc::connection_reset);
}
} // namespace vio::detail
#endif

#endif
