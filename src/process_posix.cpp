/*
  Copyright (c) 2026 Jørgen Lind

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

#if !defined(_WIN32)

#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/syscall.h>
#endif

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#include <sys/event.h>
#define VIO_PROCESS_KQUEUE 1
#endif

#include "process_common.h"
#include "vio/detail/sys.h"
#include "vio/errc.h"
#include "vio/loop/loop_core.h"

#if defined(__APPLE__)
#include <crt_externs.h>
#define VIO_PROCESS_ENVIRON (*_NSGetEnviron())
#else
extern char **environ;
#define VIO_PROCESS_ENVIRON environ
#endif

#if defined(__linux__) && !defined(SYS_pidfd_open)
#define SYS_pidfd_open 434
#endif

namespace vio::detail
{
namespace
{
constexpr std::int64_t exit_poll_interval_ns = 20'000'000;
constexpr std::int64_t hangup_grace_ns = 2'000'000'000;
constexpr int exec_failure_status = 127;

int set_cloexec(int fd) noexcept
{
  int flags = ::fcntl(fd, F_GETFD, 0);
  if (flags < 0 || ::fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0)
    return errc_from_errno(errno);
  return 0;
}

int set_nonblocking(int fd) noexcept
{
  int flags = ::fcntl(fd, F_GETFL, 0);
  if (flags < 0 || ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
    return errc_from_errno(errno);
  return 0;
}

void close_quietly(int &fd) noexcept
{
  if (fd >= 0)
    ::close(fd);
  fd = -1;
}

winsize to_winsize(const pty_size_t &size) noexcept
{
  winsize ws{};
  ws.ws_col = size.columns;
  ws.ws_row = size.rows;
  ws.ws_xpixel = size.pixel_width;
  ws.ws_ypixel = size.pixel_height;
  return ws;
}

exit_status_t decode_wait_status(int status) noexcept
{
  exit_status_t decoded;
  if (WIFEXITED(status))
  {
    decoded.exit_code = WEXITSTATUS(status);
  }
  else if (WIFSIGNALED(status))
  {
    decoded.signal = WTERMSIG(status);
    decoded.exit_code = 128 + decoded.signal;
  }
  else
  {
    decoded.exit_code = -1;
  }
  return decoded;
}

struct spawn_plan_t
{
  std::vector<std::string> environment;
  std::vector<std::string> candidates;
  std::vector<char *> argv;
  std::vector<char *> envp;
  std::vector<const char *> candidate_paths;
};

int build_environment(const process_options_t &options, std::vector<std::string> &environment)
{
  char **inherited = VIO_PROCESS_ENVIRON;
  if (options.inherit_environment && inherited)
  {
    for (char **entry = inherited; *entry; ++entry)
      environment.emplace_back(*entry);
  }
  for (auto &variable : options.environment)
  {
    if (variable.name.empty() || variable.name.find('=') != std::string::npos)
      return errc::invalid_argument;
    std::string entry = variable.name + "=" + variable.value;
    bool replaced = false;
    for (auto &existing : environment)
    {
      if (existing.size() > variable.name.size() && existing.compare(0, variable.name.size(), variable.name) == 0 && existing[variable.name.size()] == '=')
      {
        existing = entry;
        replaced = true;
        break;
      }
    }
    if (!replaced)
      environment.push_back(std::move(entry));
  }
  return 0;
}

void build_candidates(const std::string &program, const std::vector<std::string> &environment, std::vector<std::string> &candidates)
{
  if (program.find('/') != std::string::npos)
  {
    candidates.push_back(program);
    return;
  }
  std::string path = "/usr/bin:/bin";
  for (auto &entry : environment)
  {
    if (entry.compare(0, 5, "PATH=") == 0)
    {
      path = entry.substr(5);
      break;
    }
  }
  std::size_t start = 0;
  for (;;)
  {
    auto end = path.find(':', start);
    auto directory = path.substr(start, end == std::string::npos ? std::string::npos : end - start);
    if (directory.empty())
      directory = ".";
    candidates.push_back(directory + "/" + program);
    if (end == std::string::npos)
      break;
    start = end + 1;
  }
}

int open_pty(const pty_size_t &size, int &master, int &slave)
{
#if defined(__linux__)
  master = ::posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
#else
  master = ::posix_openpt(O_RDWR | O_NOCTTY);
#endif
  if (master < 0)
    return errc_from_errno(errno);
  int result = set_cloexec(master);
  if (result == 0)
    result = set_nonblocking(master);
  if (result == 0 && (::grantpt(master) != 0 || ::unlockpt(master) != 0))
    result = errc_from_errno(errno);
  std::string slave_name;
  if (result == 0)
  {
#if defined(__linux__)
    char name[256];
    if (::ptsname_r(master, name, sizeof(name)) != 0)
      result = errc_from_errno(errno);
    else
      slave_name = name;
#else
    static std::mutex ptsname_mutex;
    std::lock_guard lock(ptsname_mutex);
    const char *name = ::ptsname(master);
    if (!name)
      result = errc_from_errno(errno);
    else
      slave_name = name;
#endif
  }
  if (result == 0)
  {
    slave = ::open(slave_name.c_str(), O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (slave < 0)
      result = errc_from_errno(errno);
  }
  if (result == 0)
  {
    auto ws = to_winsize(size);
    if (::ioctl(master, TIOCSWINSZ, &ws) != 0)
      result = errc_from_errno(errno);
  }
#if defined(IUTF8)
  if (result == 0)
  {
    termios attributes{};
    if (::tcgetattr(slave, &attributes) == 0)
    {
      attributes.c_iflag |= IUTF8;
      ::tcsetattr(slave, TCSANOW, &attributes);
    }
  }
#endif
  if (result != 0)
  {
    close_quietly(master);
    close_quietly(slave);
  }
  return result;
}

int open_error_pipe(int (&fds)[2])
{
#if defined(__linux__)
  if (::pipe2(fds, O_CLOEXEC) != 0)
    return errc_from_errno(errno);
#else
  if (::pipe(fds) != 0)
    return errc_from_errno(errno);
  int result = set_cloexec(fds[0]);
  if (result == 0)
    result = set_cloexec(fds[1]);
  if (result != 0)
  {
    ::close(fds[0]);
    ::close(fds[1]);
    return result;
  }
#endif
  return 0;
}

[[noreturn]] void child_fail(int report, int error) noexcept
{
  ssize_t written;
  do
    written = ::write(report, &error, sizeof(error));
  while (written < 0 && errno == EINTR);
  ::_exit(exec_failure_status);
}

[[noreturn]] void run_child(int slave, int report, const char *working_directory, char *const *argv, char *const *envp, const char *const *candidates, std::size_t candidate_count) noexcept
{
  struct sigaction default_action{};
  default_action.sa_handler = SIG_DFL;
  sigemptyset(&default_action.sa_mask);
  for (int signal_number = 1; signal_number < NSIG; ++signal_number)
  {
    if (signal_number != SIGKILL && signal_number != SIGSTOP)
      ::sigaction(signal_number, &default_action, nullptr);
  }
  if (::setsid() < 0)
    child_fail(report, errno);
  if (::ioctl(slave, TIOCSCTTY, 0) < 0)
    child_fail(report, errno);
  for (int target = 0; target < 3; ++target)
  {
    if (::dup2(slave, target) < 0)
      child_fail(report, errno);
  }
  if (slave > 2)
    ::close(slave);
  if (working_directory && ::chdir(working_directory) != 0)
    child_fail(report, errno);
  sigset_t empty;
  sigemptyset(&empty);
  ::sigprocmask(SIG_SETMASK, &empty, nullptr);
  int error = ENOENT;
  bool denied = false;
  for (std::size_t i = 0; i < candidate_count; ++i)
  {
    ::execve(candidates[i], argv, envp);
    error = errno;
    if (error == EACCES)
      denied = true;
    else if (error != ENOENT && error != ENOTDIR)
      break;
  }
  child_fail(report, denied && (error == ENOENT || error == ENOTDIR) ? EACCES : error);
}
} // namespace

class process_core_t final : public resource_t
{
public:
  explicit process_core_t(loop_core_t &loop) noexcept
    : resource_t(loop, "process")
  {
    _read_ready.owner = this;
    _read_ready.complete = &process_core_t::on_readable;
    _write_ready.owner = this;
    _write_ready.complete = &process_core_t::on_writable;
    _exit_ready.owner = this;
    _exit_ready.complete = &process_core_t::on_exit_ready;
    _exit_ready.keeps_alive = false;
    _poll_timer.owner = this;
    _poll_timer.fire = &process_core_t::on_poll;
    _poll_timer.keeps_alive = false;
    _grace_timer.owner = this;
    _grace_timer.fire = &process_core_t::on_grace;
    _grace_timer.keeps_alive = false;
    _master_removed.owner = this;
    _master_removed.run = &process_core_t::on_removed;
    _exit_removed.owner = this;
    _exit_removed.run = &process_core_t::on_removed;
    _settle_writers.owner = this;
    _settle_writers.run = &process_core_t::on_settle_writers;
  }

  ~process_core_t() override
  {
    close_quietly(_master);
    close_quietly(_exit_fd);
  }

  int start(pid_t pid, int master, int exit_fd)
  {
    _pid = pid;
    _master = master;
    _master_watch.socket = master;
    if (int result = loop().backend().open_watch(_master_watch); result < 0)
      return result;
    _master_registered = true;
    _exit_fd = exit_fd;
    if (_exit_fd >= 0)
    {
      _exit_watch.socket = _exit_fd;
      if (loop().backend().open_watch(_exit_watch) == 0)
        _exit_registered = true;
      else
        close_quietly(_exit_fd);
    }
    if (!check_exit())
      arm_exit();
    return 0;
  }

  [[nodiscard]] std::int64_t pid() const noexcept
  {
    return _pid;
  }

  int resize(const pty_size_t &size) noexcept
  {
    if (_master < 0 || closing())
      return errc::bad_descriptor;
    auto ws = to_winsize(size);
    if (::ioctl(_master, TIOCSWINSZ, &ws) != 0)
      return errc_from_errno(errno);
    return 0;
  }

  int kill(int signal) noexcept
  {
    if (_exited)
      return errc::no_such_process;
    if (::kill(_pid, signal) != 0)
      return errc_from_errno(errno);
    return 0;
  }

  bool exit_status(exit_status_t &status) const noexcept
  {
    if (!_exited)
      return false;
    status = _status;
    return true;
  }

  int claim_reader(bool claim) noexcept
  {
    if (claim && _reader_claimed)
      return errc::busy;
    _reader_claimed = claim;
    return 0;
  }

  process_op_t *parked_reader() const noexcept
  {
    return _reader;
  }

  int write(std::span<const std::byte> data, std::unique_ptr<owned_payload_t> owned, std::uint64_t &target)
  {
    if (_master < 0 || closing())
      return errc::bad_descriptor;
    if (_writes.error != 0)
      return _writes.error;
    if (_writes.chunks.empty() && !_write_ready.parked)
    {
      auto sent = write_direct(data);
      if (sent < 0)
      {
        _writes.fail(static_cast<int>(sent));
        return static_cast<int>(sent);
      }
      _writes.sent_directly(static_cast<std::size_t>(sent));
      data = data.subspan(static_cast<std::size_t>(sent));
      if (data.empty())
      {
        target = _writes.enqueued;
        return 0;
      }
    }
    if (int result = _writes.enqueue(data, std::move(owned), target); result < 0)
      return result;
    if (!_write_ready.parked && drain() && !_write_waiters.empty())
      loop().defer(_settle_writers);
    return 0;
  }

  bool submit(process_op_t &op)
  {
    switch (op.kind)
    {
    case process_op_kind::read:
      if (_master < 0 || closing())
      {
        op.error = errc::bad_descriptor;
        return true;
      }
      if (_reader)
      {
        op.error = errc::already_in_progress;
        return true;
      }
      if (attempt_read(op))
        return true;
      _reader = &op;
      op.parked = true;
      if (!_read_ready.parked)
        loop().backend().wait(_master_watch, interest_read, _read_ready);
      return false;
    case process_op_kind::write:
      if (_writes.settles(op))
      {
        op.error = _writes.written >= op.target ? 0 : _writes.error;
        return true;
      }
      op.parked = true;
      _write_waiters.push_back(op);
      return false;
    case process_op_kind::wait:
      if (_exited)
      {
        op.status = _status;
        return true;
      }
      op.parked = true;
      _wait_waiters.push_back(op);
      loop().retain();
      return false;
    }
    return true;
  }

  bool cancel(process_op_t &op) noexcept
  {
    if (!op.parked)
      return false;
    op.parked = false;
    switch (op.kind)
    {
    case process_op_kind::read:
      if (_reader == &op)
      {
        _reader = nullptr;
        loop().backend().cancel_wait(_master_watch, _read_ready);
      }
      break;
    case process_op_kind::write:
      _write_waiters.remove(op);
      break;
    case process_op_kind::wait:
      _wait_waiters.remove(op);
      loop().release();
      break;
    }
    return true;
  }

private:
  void do_close() noexcept override
  {
    const bool inherited = loop().inherited();
    loop().backend().cancel_wait(_master_watch, _read_ready);
    loop().backend().cancel_wait(_master_watch, _write_ready);
    if (inherited)
      loop().unpost_inherited(_settle_writers);
    else
      loop().unpost(_settle_writers);
    if (_reader)
    {
      _reader->parked = false;
      _reader = nullptr;
    }
    while (auto *op = _write_waiters.front())
    {
      _write_waiters.remove(*op);
      op->parked = false;
    }
    while (auto *op = _wait_waiters.front())
    {
      _wait_waiters.remove(*op);
      op->parked = false;
      loop().release();
    }
    _writes.fail(errc::bad_descriptor);
    if (_master_registered)
    {
      _master_registered = false;
      ++_pending_removals;
      loop().backend().close_watch(_master_watch, _master_removed);
    }
    close_quietly(_master);
    if (inherited)
    {
      _exited = true;
    }
    else if (!_exited)
    {
      ::kill(_pid, SIGHUP);
      loop().add_timer(_grace_timer, loop_core_t::deadline_after(hangup_grace_ns));
    }
    continue_close();
  }

  void continue_close() noexcept
  {
    if (_pending_removals > 0)
      return;
    if (!_exited)
    {
      arm_exit();
      return;
    }
    loop().remove_timer(_poll_timer);
    loop().remove_timer(_grace_timer);
    if (_exit_registered)
    {
      _exit_registered = false;
      loop().backend().cancel_wait(_exit_watch, _exit_ready);
      ++_pending_removals;
      loop().backend().close_watch(_exit_watch, _exit_removed);
      close_quietly(_exit_fd);
      return;
    }
    close_quietly(_exit_fd);
    if (!_finished)
    {
      _finished = true;
      close_finished();
    }
  }

  bool attempt_read(process_op_t &op)
  {
    if (_read_error != 0)
    {
      op.error = _read_error;
      return true;
    }
    if (_spare.data() == nullptr)
      _spare = process_allocate_read_buffer();
    auto memory = std::span<std::byte>(_spare.data(), process_read_buffer_size);
    std::size_t filled = 0;
    int ending = 0;
    while (filled < memory.size())
    {
      auto got = ::read(_master, memory.data() + filled, memory.size() - filled);
      if (got > 0)
      {
        filled += static_cast<std::size_t>(got);
        continue;
      }
      if (got == 0)
      {
        ending = errc::eof;
        break;
      }
      if (errno == EINTR)
        continue;
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        break;
      ending = errno == EIO ? errc::eof : errc_from_errno(errno);
      break;
    }
    if (ending != 0)
      _read_error = ending;
    if (filled > 0)
    {
      _spare.resize(filled);
      op.buffer = std::move(_spare);
      return true;
    }
    if (ending != 0)
    {
      op.error = ending;
      return true;
    }
    return false;
  }

  std::int64_t write_direct(std::span<const std::byte> data) noexcept
  {
    std::size_t total = 0;
    while (total < data.size())
    {
      auto sent = ::write(_master, data.data() + total, data.size() - total);
      if (sent > 0)
      {
        total += static_cast<std::size_t>(sent);
        continue;
      }
      if (sent < 0 && errno == EINTR)
        continue;
      if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        break;
      if (total > 0)
        break;
      return sent < 0 && errno != EIO ? errc_from_errno(errno) : errc::broken_pipe;
    }
    return static_cast<std::int64_t>(total);
  }

  bool drain()
  {
    bool progressed = false;
    for (;;)
    {
      auto bytes = _writes.front();
      if (bytes.empty())
        return progressed;
      auto sent = ::write(_master, bytes.data(), bytes.size());
      if (sent > 0)
      {
        _writes.advance(static_cast<std::size_t>(sent));
        progressed = true;
        continue;
      }
      if (sent < 0 && errno == EINTR)
        continue;
      if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
      {
        if (!_write_ready.parked)
          loop().backend().wait(_master_watch, interest_write, _write_ready);
        return progressed;
      }
      _writes.fail(sent < 0 && errno != EIO ? errc_from_errno(errno) : errc::broken_pipe);
      return true;
    }
  }

  void settle_writers()
  {
    while (auto *op = process_take_settled_writer(_write_waiters, _writes))
      op->complete(op);
  }

  bool check_exit() noexcept
  {
    if (_exited)
      return true;
    int status = 0;
    pid_t reaped;
    do
      reaped = ::waitpid(_pid, &status, WNOHANG);
    while (reaped < 0 && errno == EINTR);
    if (reaped == 0)
      return false;
    _exited = true;
    if (reaped == _pid)
      _status = decode_wait_status(status);
    else
      _status.exit_code = -1;
    return true;
  }

  void arm_exit()
  {
    if (_exited)
      return;
    if (_exit_registered)
    {
      if (!_exit_ready.parked)
        loop().backend().wait(_exit_watch, interest_read, _exit_ready);
      return;
    }
    if (!_poll_timer.armed())
      loop().add_timer(_poll_timer, loop_core_t::deadline_after(exit_poll_interval_ns));
  }

  void exited()
  {
    loop().remove_timer(_grace_timer);
    while (auto *op = _wait_waiters.front())
    {
      _wait_waiters.remove(*op);
      op->parked = false;
      op->status = _status;
      loop().release();
      op->complete(op);
    }
    if (closing())
      continue_close();
  }

  void exit_signalled()
  {
    if (check_exit())
      exited();
    else
      arm_exit();
  }

  static void on_readable(io_op_t *raw)
  {
    auto &self = *static_cast<process_core_t *>(raw->owner);
    auto *op = self._reader;
    if (!op)
      return;
    if (!self.attempt_read(*op))
    {
      self.loop().backend().wait(self._master_watch, interest_read, self._read_ready);
      return;
    }
    self._reader = nullptr;
    op->parked = false;
    op->complete(op);
  }

  static void on_writable(io_op_t *raw)
  {
    auto &self = *static_cast<process_core_t *>(raw->owner);
    self.drain();
    self.settle_writers();
  }

  static void on_settle_writers(posted_t *node)
  {
    static_cast<process_core_t *>(node->owner)->settle_writers();
  }

  static void on_exit_ready(io_op_t *raw)
  {
    static_cast<process_core_t *>(raw->owner)->exit_signalled();
  }

  static void on_poll(timer_node_t *node)
  {
    static_cast<process_core_t *>(node->owner)->exit_signalled();
  }

  static void on_grace(timer_node_t *node)
  {
    auto &self = *static_cast<process_core_t *>(node->owner);
    if (!self._exited)
      ::kill(self._pid, SIGKILL);
  }

  static void on_removed(posted_t *node)
  {
    auto &self = *static_cast<process_core_t *>(node->owner);
    --self._pending_removals;
    self.continue_close();
  }

  pid_t _pid = -1;
  int _master = -1;
  int _exit_fd = -1;
  io_watch_t _master_watch;
  io_watch_t _exit_watch;
  io_op_t _read_ready;
  io_op_t _write_ready;
  io_op_t _exit_ready;
  timer_node_t _poll_timer;
  timer_node_t _grace_timer;
  posted_t _master_removed;
  posted_t _exit_removed;
  posted_t _settle_writers;
  process_op_t *_reader = nullptr;
  process_op_list_t _write_waiters;
  process_op_list_t _wait_waiters;
  process_write_queue_t _writes;
  unique_buf_t _spare;
  exit_status_t _status;
  int _read_error = 0;
  int _pending_removals = 0;
  bool _master_registered = false;
  bool _exit_registered = false;
  bool _reader_claimed = false;
  bool _exited = false;
  bool _finished = false;
};

namespace
{
int open_exit_descriptor(pid_t pid) noexcept
{
#if defined(__linux__)
  long fd = ::syscall(SYS_pidfd_open, pid, 0);
  return fd < 0 ? -1 : static_cast<int>(fd);
#elif defined(VIO_PROCESS_KQUEUE)
  int queue = ::kqueue();
  if (queue < 0)
    return -1;
  struct kevent change;
  EV_SET(&change, static_cast<uintptr_t>(pid), EVFILT_PROC, EV_ADD | EV_CLEAR, NOTE_EXIT, 0, nullptr);
  if (set_cloexec(queue) != 0 || ::kevent(queue, &change, 1, nullptr, 0, nullptr) != 0)
  {
    ::close(queue);
    return -1;
  }
  return queue;
#else
  (void)pid;
  return -1;
#endif
}

void reap_blocking(pid_t pid) noexcept
{
  while (::waitpid(pid, nullptr, 0) < 0 && errno == EINTR)
  {
  }
}
} // namespace

void process_core_deleter_t::operator()(process_core_t *core) const noexcept
{
  delete core;
}

process_core_t *process_core_spawn(loop_core_t &loop, const process_options_t &options, int &error)
{
  if (options.program.empty())
  {
    error = errc::invalid_argument;
    return nullptr;
  }
  spawn_plan_t plan;
  if (int result = build_environment(options, plan.environment); result < 0)
  {
    error = result;
    return nullptr;
  }
  build_candidates(options.program, plan.environment, plan.candidates);
  plan.argv.push_back(const_cast<char *>(options.program.c_str()));
  for (auto &argument : options.arguments)
    plan.argv.push_back(const_cast<char *>(argument.c_str()));
  plan.argv.push_back(nullptr);
  for (auto &entry : plan.environment)
    plan.envp.push_back(entry.data());
  plan.envp.push_back(nullptr);
  for (auto &candidate : plan.candidates)
    plan.candidate_paths.push_back(candidate.c_str());
  const char *working_directory = options.working_directory.empty() ? nullptr : options.working_directory.c_str();

  int master = -1;
  int slave = -1;
  if (int result = open_pty(options.size, master, slave); result < 0)
  {
    error = result;
    return nullptr;
  }
  int report[2] = {-1, -1};
  if (int result = open_error_pipe(report); result < 0)
  {
    close_quietly(master);
    close_quietly(slave);
    error = result;
    return nullptr;
  }

  sigset_t all;
  sigset_t previous;
  sigfillset(&all);
  ::pthread_sigmask(SIG_SETMASK, &all, &previous);
  pid_t pid = ::fork();
  if (pid == 0)
  {
    ::close(report[0]);
    run_child(slave, report[1], working_directory, plan.argv.data(), plan.envp.data(), plan.candidate_paths.data(), plan.candidate_paths.size());
  }
  const int fork_error = errno;
  ::pthread_sigmask(SIG_SETMASK, &previous, nullptr);
  close_quietly(slave);
  close_quietly(report[1]);
  if (pid < 0)
  {
    close_quietly(report[0]);
    close_quietly(master);
    error = errc_from_errno(fork_error);
    return nullptr;
  }

  int child_error = 0;
  ssize_t got;
  do
    got = ::read(report[0], &child_error, sizeof(child_error));
  while (got < 0 && errno == EINTR);
  close_quietly(report[0]);
  if (got == static_cast<ssize_t>(sizeof(child_error)))
  {
    reap_blocking(pid);
    close_quietly(master);
    error = errc_from_errno(child_error);
    return nullptr;
  }

  int exit_fd = open_exit_descriptor(pid);
  auto *core = new process_core_t(loop);
  if (int result = core->start(pid, master, exit_fd); result < 0)
  {
    ::kill(pid, SIGKILL);
    reap_blocking(pid);
    delete core;
    error = result;
    return nullptr;
  }
  return core;
}

resource_t &process_core_resource(process_core_t &core) noexcept
{
  return core;
}

std::int64_t process_core_pid(const process_core_t &core) noexcept
{
  return core.pid();
}

int process_core_resize(process_core_t &core, const pty_size_t &size) noexcept
{
  return core.resize(size);
}

int process_core_kill(process_core_t &core, int signal) noexcept
{
  return core.kill(signal);
}

bool process_core_exit_status(const process_core_t &core, exit_status_t &status) noexcept
{
  return core.exit_status(status);
}

int process_core_claim_reader(process_core_t &core, bool claim) noexcept
{
  return core.claim_reader(claim);
}

process_op_t *process_core_parked_reader(process_core_t &core) noexcept
{
  return core.parked_reader();
}

int process_core_write(process_core_t &core, std::span<const std::byte> data, std::unique_ptr<owned_payload_t> owned, std::uint64_t &target)
{
  return core.write(data, std::move(owned), target);
}

bool process_core_submit(process_core_t &core, process_op_t &op)
{
  return core.submit(op);
}

bool process_core_cancel(process_core_t &core, process_op_t &op) noexcept
{
  return core.cancel(op);
}
} // namespace vio::detail

#endif
