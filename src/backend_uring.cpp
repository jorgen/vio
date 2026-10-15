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

#if defined(__linux__)

#include <cstdint>

#include "backends.h"
#include "uring_ring.h"
#include "vio/errc.h"

#if defined(VIO_HAS_IO_URING) && UINTPTR_MAX > 0xffffffffu

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <utility>
#include <vector>

#include <poll.h>
#include <sys/eventfd.h>
#include <time.h>
#include <unistd.h>

#include "vio/detail/sys.h"
#include "vio/loop/loop_core.h"

namespace vio::detail
{
namespace
{
constexpr unsigned submission_entries = 1024;
constexpr unsigned completion_entries = submission_entries * 4;
constexpr unsigned completion_batch = 256;
constexpr std::size_t max_file_transfer = 0x7ffff000;
constexpr long first_submit_pause_ns = 50000;
constexpr long last_submit_pause_ns = 10000000;
constexpr std::int64_t max_submit_stall_ns = std::int64_t{30} * 1000000000;
constexpr int max_futile_submits = 1000;

#if defined(VIO_INTERNAL_TESTS)
struct uring_submit_fault_t
{
  unsigned refusals = 0;
  unsigned refused = 0;
  std::int64_t paused_ns = 0;
};
uring_submit_fault_t *uring_submit_fault = nullptr;
#endif

constexpr std::uint64_t tag_mask = 7;
constexpr std::uint64_t tag_ignore = 0;
constexpr std::uint64_t tag_read = 1;
constexpr std::uint64_t tag_write = 2;
constexpr std::uint64_t tag_file = 3;
constexpr std::uint64_t tag_wake = 4;

constexpr std::uint8_t armed_read = interest_read;
constexpr std::uint8_t armed_write = interest_write;
constexpr std::uint8_t armed_polls = armed_read | armed_write;
constexpr std::uint8_t write_edge_triggered = 4;

constexpr unsigned read_events = POLLIN | POLLRDHUP;
constexpr unsigned write_events = POLLOUT;

static_assert(alignof(io_watch_t) > tag_mask);
static_assert(alignof(file_op_t) > tag_mask);

[[noreturn]] void fatal(const char *what, int error) noexcept
{
  std::fprintf(stderr, "vio: io_uring %s (%s)\n", what, std::strerror(error));
  std::abort();
}

std::uint64_t thread_token() noexcept
{
  static std::atomic<std::uint64_t> next{1};
  thread_local std::uint64_t token = next.fetch_add(1, std::memory_order_relaxed);
  return token;
}

std::uint32_t poll_mask(std::uint32_t mask) noexcept
{
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  return (mask << 16) | (mask >> 16);
#else
  return mask;
#endif
}

std::uint64_t watch_data(io_watch_t &watch, std::uint64_t tag) noexcept
{
  return reinterpret_cast<std::uintptr_t>(&watch) | tag;
}

std::uint64_t tag_for(std::uint8_t interest) noexcept
{
  return interest == interest_read ? tag_read : tag_write;
}

std::uintptr_t slot_bits(std::uint8_t interest) noexcept
{
  return interest == interest_read ? 0 : 16;
}

class uring_backend_t final : public backend_t
{
public:
  explicit uring_backend_t(loop_core_t &loop) noexcept
    : backend_t(loop)
  {
  }

  ~uring_backend_t() override
  {
    if (_files_in_flight > 0)
      abandon_files();
    if (_wake_fd >= 0)
      ::close(_wake_fd);
  }

  [[nodiscard]] int init() noexcept
  {
    if (int result = _ring.init(submission_entries, completion_entries); result < 0)
      return result;
    static constexpr unsigned char socket_ops[] = {IORING_OP_NOP, IORING_OP_POLL_ADD, IORING_OP_ASYNC_CANCEL};
    if (!_ring.probe(socket_ops, sizeof(socket_ops)))
      return errc::not_supported;
    static constexpr unsigned char file_ops[] = {IORING_OP_READ, IORING_OP_WRITE, IORING_OP_FSYNC};
    _async_files = (_ring.features() & IORING_FEAT_RW_CUR_POS) && _ring.probe(file_ops, sizeof(file_ops));
    auto coop = _ring.setup_flags() & IORING_SETUP_COOP_TASKRUN;
    _enter_to_reap = coop && !(_ring.setup_flags() & IORING_SETUP_TASKRUN_FLAG);
    _wake_fd = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (_wake_fd < 0)
      return errc_from_errno(errno);
    return 0;
  }

  [[nodiscard]] const char *name() const noexcept override
  {
    return "io_uring";
  }

  [[nodiscard]] int add_watch(io_watch_t &watch) override
  {
    watch.closed = false;
    watch.armed = 0;
    watch.backend_state = nullptr;
    return 0;
  }

  void remove_watch(io_watch_t &watch, posted_t &done) override
  {
    if (watch.closed)
    {
      if (watch.armed & armed_polls)
      {
        std::fprintf(stderr, "vio: io_uring watch removed twice while the kernel still holds it\n");
        std::abort();
      }
      _loop.defer(done);
      return;
    }
    watch.closed = true;
    for (std::uint8_t interest : {interest_read, interest_write})
    {
      if (!(watch.armed & interest))
        continue;
      auto data = watch_data(watch, tag_for(interest));
      auto slot = static_cast<unsigned>((reinterpret_cast<std::uintptr_t>(watch.backend_state) >> slot_bits(interest)) & 0xffff);
      auto *queued = _ring.unsubmitted(slot_index(slot));
      if (queued && queued->user_data == data)
      {
        std::memset(queued, 0, sizeof(*queued));
        queued->opcode = IORING_OP_NOP;
        queued->user_data = tag_ignore;
        watch.armed &= static_cast<std::uint8_t>(~interest);
        continue;
      }
      cancel(data, 0);
    }
    if (watch.armed & armed_polls)
    {
      watch.backend_state = &done;
      return;
    }
    watch.backend_state = nullptr;
    _loop.defer(done);
  }

  void wake() noexcept override
  {
    std::uint64_t one = 1;
    while (::write(_wake_fd, &one, sizeof(one)) < 0 && errno == EINTR)
    {
    }
  }

  void poll(std::int64_t timeout_ns) override
  {
    auto token = thread_token();
    if (!_wake_armed || _wake_thread != token)
      arm_wake(token);

    bool block = timeout_ns != 0 && _backlog.empty() && _ring.ready() == 0;
    bool enter = block || _ring.pending() > 0 || _enter_to_reap || (_ring.sq_flags() & (IORING_SQ_TASKRUN | IORING_SQ_CQ_OVERFLOW));
    if (enter)
      submit_and_wait(block ? timeout_ns : 0);
    reap();
  }

  [[nodiscard]] bool supports_async_files() const noexcept override
  {
    return _async_files;
  }

  void submit_file(file_op_t &op) override
  {
    auto *sqe = acquire_sqe();
    sqe->fd = op.file;
    switch (op.kind)
    {
    case file_op_kind::read:
    case file_op_kind::write:
      sqe->opcode = op.kind == file_op_kind::read ? IORING_OP_READ : IORING_OP_WRITE;
      sqe->addr = reinterpret_cast<std::uintptr_t>(op.data);
      sqe->len = static_cast<std::uint32_t>(op.size < max_file_transfer ? op.size : max_file_transfer);
      sqe->off = op.offset < 0 ? ~std::uint64_t(0) : static_cast<std::uint64_t>(op.offset);
      break;
    case file_op_kind::fsync:
      sqe->opcode = IORING_OP_FSYNC;
      break;
    case file_op_kind::fdatasync:
      sqe->opcode = IORING_OP_FSYNC;
      sqe->fsync_flags = IORING_FSYNC_DATASYNC;
      break;
    }
    sqe->user_data = reinterpret_cast<std::uintptr_t>(&op) | tag_file;
    op.in_flight = true;
    op.result = 0;
    ++_files_in_flight;
    _loop.retain();
  }

  void cancel_file(file_op_t &op) noexcept override
  {
    if (!op.in_flight)
      return;
    cancel(reinterpret_cast<std::uintptr_t>(&op) | tag_file, 0);
  }

protected:
  void arm(io_watch_t &watch, std::uint8_t interest) override
  {
    if (watch.closed || (watch.armed & interest))
      return;
    auto *sqe = acquire_sqe();
    auto index = _ring.tail() - 1;
    sqe->opcode = IORING_OP_POLL_ADD;
    sqe->fd = watch.socket;
    sqe->poll32_events = poll_mask(interest == interest_read ? read_events : write_events);
    if (interest == interest_write && (watch.armed & write_edge_triggered))
      sqe->len = IORING_POLL_ADD_MULTI;
    sqe->user_data = watch_data(watch, tag_for(interest));
    watch.armed |= interest;
    auto state = reinterpret_cast<std::uintptr_t>(watch.backend_state);
    state &= ~(std::uintptr_t(0xffff) << slot_bits(interest));
    state |= std::uintptr_t(index & 0xffff) << slot_bits(interest);
    watch.backend_state = reinterpret_cast<void *>(state);
  }

private:
  unsigned slot_index(unsigned slot) const noexcept
  {
    auto tail = _ring.tail();
    return tail - ((tail - slot) & 0xffff);
  }

  io_uring_sqe *acquire_sqe()
  {
    long pause_ns = first_submit_pause_ns;
    std::int64_t stalled_ns = 0;
    int futile = 0;
    for (;;)
    {
      if (auto *sqe = _ring.get_sqe())
        return sqe;
      int result = enter_for_space();
      if (result > 0)
        continue;
      if (result == -EAGAIN)
      {
        if (stalled_ns >= max_submit_stall_ns)
          fatal("submission queue stays full", EAGAIN);
        pause_for_space(pause_ns);
        stalled_ns += pause_ns;
        pause_ns = pause_ns * 2 < last_submit_pause_ns ? pause_ns * 2 : last_submit_pause_ns;
        continue;
      }
      if (result < 0 && result != -EINTR && result != -EBUSY)
        fatal("submission failed", -result);
      if (++futile >= max_futile_submits)
        fatal("submission queue stays full", result < 0 ? -result : EBUSY);
      if (result == -EBUSY)
        stash();
    }
  }

  int enter_for_space() noexcept
  {
#if defined(VIO_INTERNAL_TESTS)
    if (uring_submit_fault && uring_submit_fault->refused < uring_submit_fault->refusals)
    {
      ++uring_submit_fault->refused;
      return -EAGAIN;
    }
#endif
    return _ring.enter(0, 0, nullptr);
  }

  static void pause_for_space(long pause_ns) noexcept
  {
#if defined(VIO_INTERNAL_TESTS)
    if (uring_submit_fault)
    {
      uring_submit_fault->paused_ns += pause_ns;
      return;
    }
#endif
    timespec pause{0, pause_ns};
    ::nanosleep(&pause, nullptr);
  }

  void stash()
  {
    uring_completion_t batch[completion_batch];
    for (;;)
    {
      auto count = _ring.take(batch, completion_batch);
      if (count == 0)
        break;
      _backlog.insert(_backlog.end(), batch, batch + count);
    }
    io_uring_getevents_arg arg{};
    int result = _ring.enter(0, IORING_ENTER_GETEVENTS | IORING_ENTER_EXT_ARG, &arg);
    if (result == -EBADR)
      fatal("dropped completions", EBADR);
  }

  void cancel(std::uint64_t data, std::uint32_t flags)
  {
    auto *sqe = acquire_sqe();
    sqe->opcode = IORING_OP_ASYNC_CANCEL;
    sqe->fd = -1;
    sqe->addr = data;
    sqe->cancel_flags = flags;
    sqe->user_data = tag_ignore;
  }

  void arm_wake(std::uint64_t token)
  {
    if (_wake_armed)
      cancel(wake_data(), 0);
    ++_wake_generation;
    auto *sqe = acquire_sqe();
    sqe->opcode = IORING_OP_POLL_ADD;
    sqe->fd = _wake_fd;
    sqe->poll32_events = poll_mask(POLLIN);
    sqe->len = IORING_POLL_ADD_MULTI;
    sqe->user_data = wake_data();
    _wake_armed = true;
    _wake_thread = token;
  }

  [[nodiscard]] std::uint64_t wake_data() const noexcept
  {
    return (_wake_generation << 3) | tag_wake;
  }

  void submit_and_wait(std::int64_t timeout_ns)
  {
    io_uring_getevents_arg arg{};
    __kernel_timespec timeout{};
    unsigned min_complete = 0;
    if (timeout_ns != 0)
    {
      min_complete = 1;
      if (timeout_ns > 0)
      {
        timeout.tv_sec = timeout_ns / 1000000000;
        timeout.tv_nsec = timeout_ns % 1000000000;
        arg.ts = reinterpret_cast<std::uintptr_t>(&timeout);
      }
    }
    int result = _ring.enter(min_complete, IORING_ENTER_GETEVENTS | IORING_ENTER_EXT_ARG, &arg);
    if (result >= 0)
      return;
    switch (-result)
    {
    case EINTR:
    case ETIME:
    case EAGAIN:
    case EBUSY:
      return;
    case EBADR:
      fatal("dropped completions", EBADR);
    default:
      fatal("wait failed", -result);
    }
  }

  void reap()
  {
    if (!_backlog.empty())
    {
      std::vector<uring_completion_t> backlog;
      backlog.swap(_backlog);
      for (const auto &completion : backlog)
        handle(completion);
    }
    unsigned budget = _ring.cq_entries() * 2;
    uring_completion_t batch[completion_batch];
    while (budget > 0)
    {
      auto count = _ring.take(batch, completion_batch < budget ? completion_batch : budget);
      if (count == 0)
      {
        if (!(_ring.sq_flags() & IORING_SQ_CQ_OVERFLOW))
          return;
        io_uring_getevents_arg arg{};
        int result = _ring.enter(0, IORING_ENTER_GETEVENTS | IORING_ENTER_EXT_ARG, &arg);
        if (result == -EBADR)
          fatal("dropped completions", EBADR);
        if (_ring.ready() == 0)
          return;
        continue;
      }
      budget -= count;
      for (unsigned i = 0; i < count; ++i)
        handle(batch[i]);
    }
  }

  void handle(const uring_completion_t &completion)
  {
    auto tag = completion.user_data & tag_mask;
    auto pointer = completion.user_data & ~tag_mask;
    switch (tag)
    {
    case tag_read:
    case tag_write:
      on_watch(*reinterpret_cast<io_watch_t *>(pointer), tag == tag_read ? interest_read : interest_write, completion.res, completion.flags);
      return;
    case tag_file:
      on_file(*reinterpret_cast<file_op_t *>(pointer), completion.res);
      return;
    case tag_wake:
      if (completion.user_data == wake_data() && !(completion.flags & IORING_CQE_F_MORE))
        _wake_armed = false;
      return;
    default:
      return;
    }
  }

  void on_watch(io_watch_t &watch, std::uint8_t interest, std::int32_t result, std::uint32_t flags)
  {
    bool more = (flags & IORING_CQE_F_MORE) != 0;
    if (!more)
      watch.armed &= static_cast<std::uint8_t>(~interest);
    if (watch.closed)
    {
      if (!(watch.armed & armed_polls) && watch.backend_state)
      {
        auto *done = static_cast<posted_t *>(std::exchange(watch.backend_state, nullptr));
        _loop.defer(*done);
      }
      return;
    }
    bool readable;
    bool writable;
    if (result < 0)
    {
      readable = interest == interest_read;
      writable = interest == interest_write;
    }
    else
    {
      auto events = static_cast<std::uint32_t>(result);
      bool failed = (events & (POLLERR | POLLHUP)) != 0;
      readable = failed || (events & (POLLIN | POLLRDHUP)) != 0;
      writable = failed || (events & POLLOUT) != 0;
      if (interest == interest_write && !writable)
        watch.armed |= write_edge_triggered;
    }
    if (readable || writable)
      dispatch(watch, readable, writable);
    if (watch.closed)
      return;
    if (!watch.readers.empty())
      arm(watch, interest_read);
    if (!watch.writers.empty())
      arm(watch, interest_write);
  }

  void on_file(file_op_t &op, std::int32_t result)
  {
    op.in_flight = false;
    op.result = result < 0 ? errc_from_errno(-result) : result;
    --_files_in_flight;
    _loop.release();
    op.complete(&op);
  }

  void abandon_files() noexcept
  {
    cancel(0, IORING_ASYNC_CANCEL_ANY | IORING_ASYNC_CANCEL_ALL);
    uring_completion_t batch[completion_batch];
    while (_files_in_flight > 0)
    {
      io_uring_getevents_arg arg{};
      int result = _ring.enter(1, IORING_ENTER_GETEVENTS | IORING_ENTER_EXT_ARG, &arg);
      if (result < 0 && result != -EINTR && result != -ETIME && result != -EAGAIN && result != -EBUSY)
        fatal("could not wait for file operations at shutdown", -result);
      auto drain = [&](const uring_completion_t &completion) {
        if ((completion.user_data & tag_mask) != tag_file)
          return;
        reinterpret_cast<file_op_t *>(completion.user_data & ~tag_mask)->in_flight = false;
        --_files_in_flight;
      };
      for (const auto &completion : _backlog)
        drain(completion);
      _backlog.clear();
      for (unsigned count; (count = _ring.take(batch, completion_batch)) > 0;)
        for (unsigned i = 0; i < count; ++i)
          drain(batch[i]);
    }
  }

  uring_ring_t _ring;
  std::vector<uring_completion_t> _backlog;
  int _wake_fd = -1;
  std::uint64_t _wake_generation = 0;
  std::uint64_t _wake_thread = 0;
  std::size_t _files_in_flight = 0;
  bool _wake_armed = false;
  bool _async_files = false;
  bool _enter_to_reap = false;
};
} // namespace

std::unique_ptr<backend_t> make_uring_backend(loop_core_t &loop, int &error)
{
  auto backend = std::make_unique<uring_backend_t>(loop);
  if (int result = backend->init(); result < 0)
  {
    error = result;
    return nullptr;
  }
  return backend;
}
} // namespace vio::detail

#if defined(VIO_INTERNAL_TESTS)
#include <doctest/doctest.h>

#include <chrono>
#include <csignal>
#include <string>
#include <thread>

#include <fcntl.h>
#include <sys/wait.h>

#if defined(__SANITIZE_THREAD__)
#define VIO_URING_TEST_UNDER_TSAN 1
#elif defined(__has_feature)
#if __has_feature(thread_sanitizer)
#define VIO_URING_TEST_UNDER_TSAN 1
#endif
#endif

#if !defined(VIO_URING_TEST_UNDER_TSAN)
namespace vio::detail
{
namespace
{
constexpr int uring_test_skipped = 77;
constexpr std::size_t uring_test_read_size = 8;

struct uring_test_child_t
{
  int status = -1;
  std::string message;
};

template <typename Body>
uring_test_child_t uring_test_in_child(Body body)
{
  uring_test_child_t result;
  int ends[2];
  if (::pipe(ends) != 0)
    return result;
  pid_t child = ::fork();
  if (child < 0)
  {
    ::close(ends[0]);
    ::close(ends[1]);
    return result;
  }
  if (child == 0)
  {
    std::signal(SIGABRT, SIG_DFL);
    ::dup2(ends[1], 2);
    ::close(ends[0]);
    ::_exit(body());
  }
  ::close(ends[1]);
  const auto give_up = std::chrono::steady_clock::now() + std::chrono::seconds(60);
  char buffer[512];
  for (;;)
  {
    const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(give_up - std::chrono::steady_clock::now()).count();
    if (left <= 0)
      break;
    pollfd readable{ends[0], POLLIN, 0};
    int ready = ::poll(&readable, 1, static_cast<int>(left));
    if (ready < 0 && errno == EINTR)
      continue;
    if (ready <= 0)
      break;
    auto got = ::read(ends[0], buffer, sizeof(buffer));
    if (got > 0)
    {
      result.message.append(buffer, static_cast<std::size_t>(got));
      continue;
    }
    if (got < 0 && errno == EINTR)
      continue;
    break;
  }
  ::close(ends[0]);
  int status = 0;
  for (;;)
  {
    pid_t done = ::waitpid(child, &status, WNOHANG);
    if (done == child)
    {
      result.status = status;
      return result;
    }
    if (done < 0 && errno != EINTR)
      return result;
    if (std::chrono::steady_clock::now() > give_up)
    {
      ::kill(child, SIGKILL);
      ::waitpid(child, &status, 0);
      return result;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
}

struct uring_test_batch_t
{
  uring_test_batch_t(loop_core_t &loop, int file, std::size_t count)
    : loop(loop)
    , file(file)
    , ops(count)
    , bytes(count * uring_test_read_size)
  {
    start.owner = this;
    start.run = [](posted_t *node) { static_cast<uring_test_batch_t *>(node->owner)->submit(); };
  }

  void submit()
  {
    for (std::size_t i = 0; i < ops.size(); ++i)
    {
      auto &op = ops[i];
      op.owner = this;
      op.complete = [](file_op_t *done) {
        auto *self = static_cast<uring_test_batch_t *>(done->owner);
        if (done->result != static_cast<std::int64_t>(uring_test_read_size))
          ++self->failed;
        if (++self->completed == self->ops.size())
          self->loop.stop();
      };
      op.kind = file_op_kind::read;
      op.file = file;
      op.offset = 0;
      op.data = bytes.data() + i * uring_test_read_size;
      op.size = uring_test_read_size;
      loop.backend().submit_file(op);
    }
  }

  loop_core_t &loop;
  int file;
  std::vector<file_op_t> ops;
  std::vector<std::byte> bytes;
  std::size_t completed = 0;
  std::size_t failed = 0;
  posted_t start;
};

int uring_test_submit_through_refusals(unsigned refusals)
{
  loop_core_t loop(backend_kind::io_uring);
  if (std::string(loop.backend_name()) != "io_uring" || !loop.backend().supports_async_files())
    return uring_test_skipped;
  int file = ::open("/dev/zero", O_RDONLY | O_CLOEXEC);
  if (file < 0)
    return uring_test_skipped;
  uring_test_batch_t batch(loop, file, submission_entries + submission_entries / 4);
  uring_submit_fault_t fault;
  fault.refusals = refusals;
  uring_submit_fault = &fault;
  loop.post(batch.start);
  loop.run();
  uring_submit_fault = nullptr;
  ::close(file);
  if (fault.refused != refusals)
    return 3;
  if (batch.completed != batch.ops.size() || batch.failed != 0)
    return 4;
  if (fault.paused_ns <= std::int64_t{10} * 1000000000)
    return 5;
  return 0;
}

bool uring_test_skipped_in(const uring_test_child_t &child)
{
  return child.status != -1 && WIFEXITED(child.status) && WEXITSTATUS(child.status) == uring_test_skipped;
}
} // namespace

TEST_CASE("io_uring: a submission queue the kernel refuses for over a thousand pauses still submits once it recovers")
{
  auto child = uring_test_in_child([] { return uring_test_submit_through_refusals(1500); });
  REQUIRE(child.status != -1);
  if (uring_test_skipped_in(child))
  {
    MESSAGE("io_uring with file operations is not available here; skipped");
    return;
  }
  CHECK(WIFEXITED(child.status));
  CHECK(WEXITSTATUS(child.status) == 0);
  CHECK(child.message.find("stays full") == std::string::npos);
}

TEST_CASE("io_uring: a submission queue the kernel refuses past the stall budget aborts naming the refusal")
{
  auto child = uring_test_in_child([] { return uring_test_submit_through_refusals(4000); });
  REQUIRE(child.status != -1);
  if (uring_test_skipped_in(child))
  {
    MESSAGE("io_uring with file operations is not available here; skipped");
    return;
  }
  CHECK(WIFSIGNALED(child.status));
  CHECK(WTERMSIG(child.status) == SIGABRT);
  CHECK(child.message.find(std::string("submission queue stays full (") + std::strerror(EAGAIN) + ")") != std::string::npos);
}
} // namespace vio::detail
#endif
#endif

#else

namespace vio::detail
{
std::unique_ptr<backend_t> make_uring_backend(loop_core_t &, int &error)
{
  error = errc::not_supported;
  return nullptr;
}
} // namespace vio::detail

#endif
#endif
