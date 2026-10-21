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

#pragma once

#if defined(__linux__)

#include <atomic>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>

#include <linux/io_uring.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "vio/detail/sys.h"
#include "vio/errc.h"

#if defined(__NR_io_uring_setup) && defined(__NR_io_uring_enter) && defined(__NR_io_uring_register) && defined(IORING_FEAT_EXT_ARG) && defined(IORING_ENTER_EXT_ARG)
#define VIO_HAS_IO_URING 1
#endif

#if defined(VIO_HAS_IO_URING)

#ifndef IORING_SETUP_SUBMIT_ALL
#define IORING_SETUP_SUBMIT_ALL (1U << 7)
#endif
#ifndef IORING_SETUP_COOP_TASKRUN
#define IORING_SETUP_COOP_TASKRUN (1U << 8)
#endif
#ifndef IORING_SETUP_TASKRUN_FLAG
#define IORING_SETUP_TASKRUN_FLAG (1U << 9)
#endif
#ifndef IORING_SETUP_NO_SQARRAY
#define IORING_SETUP_NO_SQARRAY (1U << 16)
#endif
#ifndef IORING_SQ_TASKRUN
#define IORING_SQ_TASKRUN (1U << 2)
#endif
#ifndef IORING_CQE_F_MORE
#define IORING_CQE_F_MORE (1U << 1)
#endif
#ifndef IORING_POLL_ADD_MULTI
#define IORING_POLL_ADD_MULTI (1U << 0)
#endif
#ifndef IORING_ASYNC_CANCEL_ALL
#define IORING_ASYNC_CANCEL_ALL (1U << 0)
#endif
#ifndef IORING_ASYNC_CANCEL_ANY
#define IORING_ASYNC_CANCEL_ANY (1U << 2)
#endif

namespace vio::detail
{
struct uring_completion_t
{
  std::uint64_t user_data;
  std::int32_t res;
  std::uint32_t flags;
};

class uring_ring_t
{
public:
  uring_ring_t() = default;
  uring_ring_t(const uring_ring_t &) = delete;
  uring_ring_t &operator=(const uring_ring_t &) = delete;

  [[nodiscard]] int fd() const noexcept
  {
    return _fd;
  }

  ~uring_ring_t()
  {
    if (_sqes)
      ::munmap(_sqes, _sqes_size);
    if (_rings)
      ::munmap(_rings, _rings_size);
    if (_fd >= 0)
      ::close(_fd);
  }

  [[nodiscard]] int init(unsigned entries, unsigned completion_entries) noexcept
  {
    static constexpr unsigned base_flags = IORING_SETUP_CQSIZE | IORING_SETUP_CLAMP | IORING_SETUP_SUBMIT_ALL;
    static constexpr unsigned optional_flags[] = {
      IORING_SETUP_COOP_TASKRUN | IORING_SETUP_TASKRUN_FLAG | IORING_SETUP_NO_SQARRAY,
      IORING_SETUP_COOP_TASKRUN | IORING_SETUP_TASKRUN_FLAG,
      0,
    };
    io_uring_params params{};
    int fd = -1;
    int last_error = EINVAL;
    for (unsigned extra : optional_flags)
    {
      params = io_uring_params{};
      params.flags = base_flags | extra;
      params.cq_entries = completion_entries;
      long result = ::syscall(__NR_io_uring_setup, entries, &params);
      if (result >= 0)
      {
        fd = static_cast<int>(result);
        break;
      }
      last_error = errno;
      if (last_error != EINVAL)
        break;
    }
    if (fd < 0)
      return last_error == EINVAL ? errc::not_supported : errc_from_errno(last_error);
    _fd = fd;
    _setup_flags = params.flags;
    _features = params.features;

    constexpr unsigned required = IORING_FEAT_SINGLE_MMAP | IORING_FEAT_NODROP | IORING_FEAT_EXT_ARG;
    if ((_features & required) != required)
      return errc::not_supported;

    std::size_t sq_size = params.sq_off.array + params.sq_entries * sizeof(unsigned);
    if (_setup_flags & IORING_SETUP_NO_SQARRAY)
      sq_size = 0;
    std::size_t cq_size = params.cq_off.cqes + params.cq_entries * sizeof(io_uring_cqe);
    _rings_size = sq_size > cq_size ? sq_size : cq_size;
    void *rings = ::mmap(nullptr, _rings_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, _fd, IORING_OFF_SQ_RING);
    if (rings == MAP_FAILED)
      return errc_from_errno(errno);
    _rings = rings;
    _sqes_size = params.sq_entries * sizeof(io_uring_sqe);
    void *sqes = ::mmap(nullptr, _sqes_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, _fd, IORING_OFF_SQES);
    if (sqes == MAP_FAILED)
      return errc_from_errno(errno);
    _sqes = static_cast<io_uring_sqe *>(sqes);

    auto *base = static_cast<unsigned char *>(_rings);
    _sq_head = reinterpret_cast<unsigned *>(base + params.sq_off.head);
    _sq_tail_shared = reinterpret_cast<unsigned *>(base + params.sq_off.tail);
    _sq_flags = reinterpret_cast<unsigned *>(base + params.sq_off.flags);
    _sq_mask = *reinterpret_cast<unsigned *>(base + params.sq_off.ring_mask);
    _sq_entries = *reinterpret_cast<unsigned *>(base + params.sq_off.ring_entries);
    _cq_head_shared = reinterpret_cast<unsigned *>(base + params.cq_off.head);
    _cq_tail = reinterpret_cast<unsigned *>(base + params.cq_off.tail);
    _cq_mask = *reinterpret_cast<unsigned *>(base + params.cq_off.ring_mask);
    _cq_entries = *reinterpret_cast<unsigned *>(base + params.cq_off.ring_entries);
    _cqes = reinterpret_cast<io_uring_cqe *>(base + params.cq_off.cqes);
    if (!(_setup_flags & IORING_SETUP_NO_SQARRAY))
    {
      auto *array = reinterpret_cast<unsigned *>(base + params.sq_off.array);
      for (unsigned i = 0; i < _sq_entries; ++i)
        array[i] = i;
    }
    _sq_tail = load_acquire(_sq_tail_shared);
    _cq_head = load_acquire(_cq_head_shared);
    return 0;
  }

  [[nodiscard]] bool probe(const unsigned char *opcodes, std::size_t count) const noexcept
  {
    constexpr unsigned slots = 256;
    constexpr std::size_t bytes = sizeof(io_uring_probe) + slots * sizeof(io_uring_probe_op);
    auto storage = std::make_unique<std::uint64_t[]>((bytes + sizeof(std::uint64_t) - 1) / sizeof(std::uint64_t));
    auto *result = reinterpret_cast<io_uring_probe *>(storage.get());
    if (::syscall(__NR_io_uring_register, _fd, IORING_REGISTER_PROBE, result, slots) < 0)
      return false;
    for (std::size_t i = 0; i < count; ++i)
    {
      unsigned op = opcodes[i];
      if (op > result->last_op || op >= slots || !(result->ops[op].flags & IO_URING_OP_SUPPORTED))
        return false;
    }
    return true;
  }

  [[nodiscard]] unsigned setup_flags() const noexcept
  {
    return _setup_flags;
  }
  [[nodiscard]] unsigned features() const noexcept
  {
    return _features;
  }
  [[nodiscard]] unsigned sq_entries() const noexcept
  {
    return _sq_entries;
  }
  [[nodiscard]] unsigned cq_entries() const noexcept
  {
    return _cq_entries;
  }

  [[nodiscard]] io_uring_sqe *get_sqe() noexcept
  {
    if (_sq_tail - load_acquire(_sq_head) >= _sq_entries)
      return nullptr;
    auto *sqe = &_sqes[_sq_tail & _sq_mask];
    std::memset(sqe, 0, sizeof(*sqe));
    ++_sq_tail;
    return sqe;
  }

  [[nodiscard]] unsigned tail() const noexcept
  {
    return _sq_tail;
  }

  [[nodiscard]] io_uring_sqe *unsubmitted(unsigned index) noexcept
  {
    unsigned head = load_acquire(_sq_head);
    if (index - head >= _sq_tail - head)
      return nullptr;
    return &_sqes[index & _sq_mask];
  }

  [[nodiscard]] unsigned pending() const noexcept
  {
    return _sq_tail - load_acquire(_sq_head);
  }

  [[nodiscard]] unsigned sq_flags() const noexcept
  {
    return std::atomic_ref<unsigned>(*_sq_flags).load(std::memory_order_acquire);
  }

  [[nodiscard]] int enter(unsigned min_complete, unsigned flags, const io_uring_getevents_arg *arg) noexcept
  {
    std::atomic_ref<unsigned>(*_sq_tail_shared).store(_sq_tail, std::memory_order_release);
    unsigned to_submit = pending();
    long result = ::syscall(__NR_io_uring_enter, _fd, to_submit, min_complete, flags, arg, arg ? sizeof(*arg) : 0);
    if (result < 0)
      return -errno;
    return static_cast<int>(result);
  }

  [[nodiscard]] unsigned ready() const noexcept
  {
    return load_acquire(_cq_tail) - _cq_head;
  }

  unsigned take(uring_completion_t *out, unsigned capacity) noexcept
  {
    unsigned available = ready();
    unsigned count = available < capacity ? available : capacity;
    for (unsigned i = 0; i < count; ++i)
    {
      const auto &cqe = _cqes[(_cq_head + i) & _cq_mask];
      out[i].user_data = cqe.user_data;
      out[i].res = cqe.res;
      out[i].flags = cqe.flags;
    }
    _cq_head += count;
    std::atomic_ref<unsigned>(*_cq_head_shared).store(_cq_head, std::memory_order_release);
    return count;
  }

private:
  static unsigned load_acquire(unsigned *value) noexcept
  {
    return std::atomic_ref<unsigned>(*value).load(std::memory_order_acquire);
  }

  int _fd = -1;
  unsigned _setup_flags = 0;
  unsigned _features = 0;
  void *_rings = nullptr;
  std::size_t _rings_size = 0;
  io_uring_sqe *_sqes = nullptr;
  std::size_t _sqes_size = 0;
  unsigned *_sq_head = nullptr;
  unsigned *_sq_tail_shared = nullptr;
  unsigned *_sq_flags = nullptr;
  unsigned _sq_mask = 0;
  unsigned _sq_entries = 0;
  unsigned _sq_tail = 0;
  unsigned *_cq_head_shared = nullptr;
  unsigned *_cq_tail = nullptr;
  io_uring_cqe *_cqes = nullptr;
  unsigned _cq_mask = 0;
  unsigned _cq_entries = 0;
  unsigned _cq_head = 0;
};
} // namespace vio::detail

#endif
#endif
