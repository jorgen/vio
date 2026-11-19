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

#if defined(_WIN32)

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "process_common.h"
#include "vio/detail/native.h"
#include "vio/detail/sys.h"
#include "vio/errc.h"
#include "vio/loop/blocking_pool.h"
#include "vio/loop/loop_core.h"

namespace vio::detail
{
namespace
{
using pseudo_console_t = void *;
using create_pseudo_console_t = HRESULT(WINAPI *)(COORD size, HANDLE input, HANDLE output, DWORD flags, pseudo_console_t *console);
using resize_pseudo_console_t = HRESULT(WINAPI *)(pseudo_console_t console, COORD size);
using close_pseudo_console_t = void(WINAPI *)(pseudo_console_t console);

constexpr DWORD_PTR proc_thread_attribute_pseudoconsole = 0x00020016;
constexpr DWORD pipe_buffer_size = 65536;
constexpr std::size_t max_write_chunk = std::size_t{1} << 20;

struct conpty_api_t
{
  create_pseudo_console_t create = nullptr;
  resize_pseudo_console_t resize = nullptr;
  close_pseudo_console_t close = nullptr;
  bool bundled = false;
};

template <typename function_t>
function_t load_function(HMODULE module, const char *name) noexcept
{
  return reinterpret_cast<function_t>(reinterpret_cast<void (*)()>(::GetProcAddress(module, name)));
}

const conpty_api_t *conpty_api() noexcept
{
  static const conpty_api_t api = [] {
    conpty_api_t loaded;
    if (HMODULE bundled = ::LoadLibraryExW(L"conpty.dll", nullptr, LOAD_LIBRARY_SEARCH_APPLICATION_DIR))
    {
      loaded.create = load_function<create_pseudo_console_t>(bundled, "ConptyCreatePseudoConsole");
      loaded.resize = load_function<resize_pseudo_console_t>(bundled, "ConptyResizePseudoConsole");
      loaded.close = load_function<close_pseudo_console_t>(bundled, "ConptyClosePseudoConsole");
      if (loaded.create && loaded.resize && loaded.close)
      {
        loaded.bundled = true;
        return loaded;
      }
      loaded = {};
    }
    HMODULE kernel = ::GetModuleHandleW(L"kernel32.dll");
    if (!kernel)
      return loaded;
    loaded.create = load_function<create_pseudo_console_t>(kernel, "CreatePseudoConsole");
    loaded.resize = load_function<resize_pseudo_console_t>(kernel, "ResizePseudoConsole");
    loaded.close = load_function<close_pseudo_console_t>(kernel, "ClosePseudoConsole");
    return loaded;
  }();
  if (!api.create || !api.resize || !api.close)
    return nullptr;
  return &api;
}

DWORD glyph_width_flags(pty_glyph_width_t width) noexcept
{
  switch (width)
  {
  case pty_glyph_width_t::wcwidth:
    return 0x10;
  case pty_glyph_width_t::graphemes:
    return 0x08;
  default:
    return 0;
  }
}

int errc_from_hresult(HRESULT result) noexcept
{
  if (HRESULT_FACILITY(result) == FACILITY_WIN32)
    return errc_from_win32(HRESULT_CODE(result));
  return errc::unknown;
}

COORD to_coord(const pty_size_t &size) noexcept
{
  auto clamp = [](std::uint16_t value) { return static_cast<SHORT>(std::min<std::uint16_t>(std::max<std::uint16_t>(value, 1), 0x7fff)); };
  return COORD{clamp(size.columns), clamp(size.rows)};
}

int widen(std::string_view text, std::wstring &out) noexcept
{
  out.clear();
  if (text.empty())
    return 0;
  const int length = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0);
  if (length <= 0)
    return errc::invalid_argument;
  out.resize(static_cast<std::size_t>(length));
  ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), out.data(), length);
  return 0;
}

void append_argument(std::wstring &command, const std::wstring &argument)
{
  if (!argument.empty() && argument.find_first_of(L" \t\n\v\"") == std::wstring::npos)
  {
    command += argument;
    return;
  }
  command += L'"';
  for (auto it = argument.begin();; ++it)
  {
    std::size_t backslashes = 0;
    while (it != argument.end() && *it == L'\\')
    {
      ++it;
      ++backslashes;
    }
    if (it == argument.end())
    {
      command.append(backslashes * 2, L'\\');
      break;
    }
    if (*it == L'"')
      command.append(backslashes * 2 + 1, L'\\');
    else
      command.append(backslashes, L'\\');
    command += *it;
  }
  command += L'"';
}

int build_command_line(const process_options_t &options, std::wstring &command)
{
  std::wstring program;
  if (int result = widen(options.program, program); result < 0)
    return result;
  if (program.find(L'"') != std::wstring::npos)
    return errc::invalid_argument;
  if (program.find_first_of(L" \t") != std::wstring::npos)
    command = L'"' + program + L'"';
  else
    command = program;
  for (auto &argument : options.arguments)
  {
    std::wstring wide;
    if (int result = widen(argument, wide); result < 0)
      return result;
    command += L' ';
    append_argument(command, wide);
  }
  return 0;
}

std::wstring_view variable_name(const std::wstring &entry) noexcept
{
  auto end = entry.find(L'=', 1);
  return std::wstring_view(entry).substr(0, end == std::wstring::npos ? entry.size() : end);
}

int compare_names(std::wstring_view left, std::wstring_view right) noexcept
{
  return ::CompareStringOrdinal(left.data(), static_cast<int>(left.size()), right.data(), static_cast<int>(right.size()), TRUE);
}

int build_environment(const process_options_t &options, std::vector<wchar_t> &block)
{
  std::vector<std::wstring> entries;
  if (options.inherit_environment)
  {
    if (wchar_t *strings = ::GetEnvironmentStringsW())
    {
      for (const wchar_t *entry = strings; *entry; entry += std::wcslen(entry) + 1)
        entries.emplace_back(entry);
      ::FreeEnvironmentStringsW(strings);
    }
  }
  for (auto &variable : options.environment)
  {
    if (variable.name.empty() || variable.name.find('=') != std::string::npos)
      return errc::invalid_argument;
    std::wstring name;
    std::wstring value;
    if (int result = widen(variable.name, name); result < 0)
      return result;
    if (int result = widen(variable.value, value); result < 0)
      return result;
    std::wstring entry = name + L"=" + value;
    auto existing = std::find_if(entries.begin(), entries.end(), [&](const std::wstring &candidate) { return compare_names(variable_name(candidate), name) == CSTR_EQUAL; });
    if (existing != entries.end())
      *existing = std::move(entry);
    else
      entries.push_back(std::move(entry));
  }
  std::sort(entries.begin(), entries.end(), [](const std::wstring &left, const std::wstring &right) { return compare_names(variable_name(left), variable_name(right)) == CSTR_LESS_THAN; });
  block.clear();
  for (auto &entry : entries)
  {
    block.insert(block.end(), entry.begin(), entry.end());
    block.push_back(L'\0');
  }
  if (block.empty())
    block.push_back(L'\0');
  block.push_back(L'\0');
  return 0;
}

int create_pipe_pair(const std::wstring &name, bool inbound, HANDLE &ours, HANDLE &theirs) noexcept
{
  const DWORD direction = inbound ? PIPE_ACCESS_INBOUND : PIPE_ACCESS_OUTBOUND;
  ours = ::CreateNamedPipeW(name.c_str(), direction | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, pipe_buffer_size,
                            pipe_buffer_size, 0, nullptr);
  if (ours == INVALID_HANDLE_VALUE)
  {
    ours = nullptr;
    return errc_from_win32(::GetLastError());
  }
  theirs = ::CreateFileW(name.c_str(), inbound ? GENERIC_WRITE : GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
  if (theirs == INVALID_HANDLE_VALUE)
  {
    const DWORD error = ::GetLastError();
    ::CloseHandle(ours);
    ours = nullptr;
    theirs = nullptr;
    return errc_from_win32(error);
  }
  return 0;
}

std::wstring unique_pipe_name(const wchar_t *direction)
{
  static std::atomic<unsigned> counter{0};
  return L"\\\\.\\pipe\\vio-pty-" + std::to_wstring(::GetCurrentProcessId()) + L"-" + std::to_wstring(counter.fetch_add(1)) + L"-" + std::to_wstring(::GetTickCount64()) + L"-" + direction;
}

void close_handle(HANDLE &handle) noexcept
{
  if (handle)
    ::CloseHandle(handle);
  handle = nullptr;
}

int read_error(unsigned long error) noexcept
{
  switch (error)
  {
  case ERROR_BROKEN_PIPE:
  case ERROR_HANDLE_EOF:
  case ERROR_PIPE_NOT_CONNECTED:
  case ERROR_NO_DATA:
    return errc::eof;
  case ERROR_OPERATION_ABORTED:
    return errc::canceled;
  default:
    return errc_from_win32(error);
  }
}

int write_error(unsigned long error) noexcept
{
  switch (error)
  {
  case ERROR_BROKEN_PIPE:
  case ERROR_NO_DATA:
  case ERROR_PIPE_NOT_CONNECTED:
    return errc::broken_pipe;
  case ERROR_OPERATION_ABORTED:
    return errc::canceled;
  default:
    return errc_from_win32(error);
  }
}
} // namespace

class process_core_t final : public resource_t
{
public:
  explicit process_core_t(loop_core_t &loop) noexcept
    : resource_t(loop, "process")
  {
    _read_io.owner = this;
    _read_io.complete = &process_core_t::on_read_complete;
    _read_io.keeps_alive = false;
    _write_io.owner = this;
    _write_io.complete = &process_core_t::on_write_complete;
    _exit_ready.owner = this;
    _exit_ready.complete = &process_core_t::on_exit_ready;
    _exit_ready.keeps_alive = false;
    _exit_removed.owner = this;
    _exit_removed.run = &process_core_t::on_removed;
    _settle_writers.owner = this;
    _settle_writers.run = &process_core_t::on_settle_writers;
    _close_job.owner = this;
    _close_job.work = &process_core_t::close_console_work;
    _close_job.done = &process_core_t::close_console_done;
  }

  ~process_core_t() override
  {
    close_handle(_input);
    close_handle(_output);
    close_handle(_process);
  }

  int start(const conpty_api_t &api, pseudo_console_t console, HANDLE process, DWORD pid, HANDLE input, HANDLE output)
  {
    _api = &api;
    _console = console;
    _process = process;
    _pid = pid;
    _input = input;
    _output = output;
    auto &backend = loop().backend();
    if (int result = backend.associate_handle(_input); result < 0)
      return result;
    if (int result = backend.associate_handle(_output); result < 0)
      return result;
    _exit_watch.object = _process;
    if (int result = backend.add_handle_watch(_exit_watch); result < 0)
      return result;
    _exit_registered = true;
    if (int result = backend.wait_handle(_exit_watch, _exit_ready); result < 0)
      return result;
    return 0;
  }

  void abandon_start() noexcept
  {
    ::TerminateProcess(_process, 1);
    if (_exit_registered)
    {
      loop().backend().cancel_handle_wait(_exit_watch, _exit_ready);
      _exit_registered = false;
      loop().backend().remove_handle_watch(_exit_watch, _exit_removed);
      loop().unpost(_exit_removed);
    }
    close_handle(_output);
    close_handle(_input);
    if (_console)
      _api->close(std::exchange(_console, nullptr));
  }

  [[nodiscard]] std::int64_t pid() const noexcept
  {
    return _pid;
  }

  int resize(const pty_size_t &size) noexcept
  {
    if (closing())
      return errc::bad_descriptor;
    if (!_console)
      return errc::no_such_process;
    if (HRESULT result = _api->resize(_console, to_coord(size)); FAILED(result))
      return errc_from_hresult(result);
    return 0;
  }

  int kill(int signal) noexcept
  {
    if (_exited || closing())
      return errc::no_such_process;
    if (!::TerminateProcess(_process, static_cast<UINT>(128 + signal)))
      return errc_from_win32(::GetLastError());
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
    if (!_input || closing())
      return errc::bad_descriptor;
    if (int result = _writes.enqueue(data, std::move(owned), target); result < 0)
      return result;
    if (!_write_io.in_flight)
      start_write();
    return 0;
  }

  bool submit(process_op_t &op)
  {
    switch (op.kind)
    {
    case process_op_kind::read:
      if (!_output || closing())
      {
        op.error = errc::bad_descriptor;
        return true;
      }
      if (_reader)
      {
        op.error = errc::already_in_progress;
        return true;
      }
      if (take_stashed(op))
        return true;
      if (!_read_io.in_flight && _read_error == 0)
        start_read();
      if (take_stashed(op))
        return true;
      if (!_read_io.in_flight)
      {
        op.error = _read_error != 0 ? _read_error : errc::io_error;
        return true;
      }
      _reader = &op;
      op.parked = true;
      loop().retain();
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
        loop().release();
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
    loop().unpost(_settle_writers);
    if (_reader)
    {
      _reader->parked = false;
      _reader = nullptr;
      loop().release();
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
    if (_exit_registered)
    {
      _exit_registered = false;
      loop().backend().cancel_handle_wait(_exit_watch, _exit_ready);
      ++_pending_removals;
      loop().backend().remove_handle_watch(_exit_watch, _exit_removed);
    }
    if (_write_io.in_flight)
      ::CancelIoEx(_input, &_write_io.overlapped);
    if (_read_io.in_flight)
      ::CancelIoEx(_output, &_read_io.overlapped);
    continue_close();
  }

  void continue_close() noexcept
  {
    if (_input && !_write_io.in_flight)
      close_handle(_input);
    if (_output && !_read_io.in_flight)
      close_handle(_output);
    if (!_output)
      release_console();
    if (_pending_removals > 0 || _read_io.in_flight || _write_io.in_flight || _close_job_running)
      return;
    close_handle(_process);
    if (!_finished)
    {
      _finished = true;
      close_finished();
    }
  }

  void release_console() noexcept
  {
    if (!_console || _close_job_running)
      return;
    _closing_console = std::exchange(_console, nullptr);
    _close_job_running = true;
    pool_submit(loop(), _close_job, pool_queue::file);
  }

  bool take_stashed(process_op_t &op) noexcept
  {
    if (_stash.data() != nullptr)
    {
      op.buffer = std::move(_stash);
      return true;
    }
    if (_read_error != 0 && !_read_io.in_flight)
    {
      op.error = _read_error;
      return true;
    }
    return false;
  }

  void start_read()
  {
    _read_buffer = process_allocate_read_buffer();
    auto &backend = loop().backend();
    backend.begin_overlapped(_read_io);
    if (::ReadFile(_output, _read_buffer.data(), static_cast<DWORD>(process_read_buffer_size), nullptr, &_read_io.overlapped))
      return;
    const DWORD error = ::GetLastError();
    if (error == ERROR_IO_PENDING)
      return;
    backend.abandon_overlapped(_read_io);
    _read_buffer.reset();
    _read_error = read_error(error);
  }

  void read_completed(const overlapped_op_t &io)
  {
    if (closing())
    {
      _read_buffer.reset();
      continue_close();
      return;
    }
    if (io.error == 0 && io.transferred == 0)
    {
      _read_buffer.reset();
      if (_reader)
        start_read();
      if (!_read_io.in_flight)
        deliver_read();
      return;
    }
    if (io.error == 0)
    {
      _read_buffer.resize(io.transferred);
      _stash = std::move(_read_buffer);
    }
    else
    {
      _read_buffer.reset();
      _read_error = read_error(io.error);
    }
    deliver_read();
  }

  void deliver_read()
  {
    auto *op = _reader;
    if (!op)
      return;
    if (!take_stashed(*op))
      return;
    _reader = nullptr;
    op->parked = false;
    loop().release();
    op->complete(op);
  }

  void start_write()
  {
    auto bytes = _writes.front();
    if (bytes.empty() || !_input)
      return;
    const auto size = static_cast<DWORD>(std::min(bytes.size(), max_write_chunk));
    auto &backend = loop().backend();
    backend.begin_overlapped(_write_io);
    if (::WriteFile(_input, bytes.data(), size, nullptr, &_write_io.overlapped))
      return;
    const DWORD error = ::GetLastError();
    if (error == ERROR_IO_PENDING)
      return;
    backend.abandon_overlapped(_write_io);
    _writes.fail(write_error(error));
    if (!_write_waiters.empty())
      loop().defer(_settle_writers);
  }

  void write_completed(const overlapped_op_t &io)
  {
    if (closing())
    {
      continue_close();
      return;
    }
    if (io.error != 0)
      _writes.fail(write_error(io.error));
    else
      _writes.advance(io.transferred);
    start_write();
    settle_writers();
  }

  void settle_writers()
  {
    while (auto *op = process_take_settled_writer(_write_waiters, _writes))
      op->complete(op);
  }

  void exited()
  {
    DWORD code = 0;
    if (::GetExitCodeProcess(_process, &code))
      _status.exit_code = static_cast<int>(code);
    else
      _status.exit_code = -1;
    _exited = true;
    release_console();
    while (auto *op = _wait_waiters.front())
    {
      _wait_waiters.remove(*op);
      op->parked = false;
      op->status = _status;
      loop().release();
      op->complete(op);
    }
  }

  static void on_read_complete(overlapped_op_t *io)
  {
    static_cast<process_core_t *>(io->owner)->read_completed(*io);
  }

  static void on_write_complete(overlapped_op_t *io)
  {
    static_cast<process_core_t *>(io->owner)->write_completed(*io);
  }

  static void on_exit_ready(io_op_t *op)
  {
    static_cast<process_core_t *>(op->owner)->exited();
  }

  static void on_settle_writers(posted_t *node)
  {
    static_cast<process_core_t *>(node->owner)->settle_writers();
  }

  static void on_removed(posted_t *node)
  {
    auto &self = *static_cast<process_core_t *>(node->owner);
    --self._pending_removals;
    self.continue_close();
  }

  static void close_console_work(pool_job_t *job)
  {
    auto &self = *static_cast<process_core_t *>(job->owner);
    self._api->close(self._closing_console);
  }

  static void close_console_done(pool_job_t *job, bool)
  {
    auto &self = *static_cast<process_core_t *>(job->owner);
    self._closing_console = nullptr;
    self._close_job_running = false;
    if (self.closing())
      self.continue_close();
  }

  const conpty_api_t *_api = nullptr;
  pseudo_console_t _console = nullptr;
  pseudo_console_t _closing_console = nullptr;
  HANDLE _process = nullptr;
  HANDLE _input = nullptr;
  HANDLE _output = nullptr;
  DWORD _pid = 0;
  overlapped_op_t _read_io;
  overlapped_op_t _write_io;
  handle_watch_t _exit_watch;
  io_op_t _exit_ready;
  posted_t _exit_removed;
  posted_t _settle_writers;
  pool_job_t _close_job;
  process_op_t *_reader = nullptr;
  process_op_list_t _write_waiters;
  process_op_list_t _wait_waiters;
  process_write_queue_t _writes;
  unique_buf_t _read_buffer;
  unique_buf_t _stash;
  exit_status_t _status;
  int _read_error = 0;
  int _pending_removals = 0;
  bool _exit_registered = false;
  bool _close_job_running = false;
  bool _reader_claimed = false;
  bool _exited = false;
  bool _finished = false;
};

void process_core_deleter_t::operator()(process_core_t *core) const noexcept
{
  delete core;
}

process_core_t *process_core_spawn(loop_core_t &loop, const process_options_t &options, int &error)
{
  const conpty_api_t *api = conpty_api();
  if (!api)
  {
    error = errc::not_supported;
    return nullptr;
  }
  if (options.program.empty())
  {
    error = errc::invalid_argument;
    return nullptr;
  }
  std::wstring command;
  if (int result = build_command_line(options, command); result < 0)
  {
    error = result;
    return nullptr;
  }
  std::vector<wchar_t> environment;
  if (int result = build_environment(options, environment); result < 0)
  {
    error = result;
    return nullptr;
  }
  std::wstring working_directory;
  if (int result = widen(options.working_directory, working_directory); result < 0)
  {
    error = result;
    return nullptr;
  }

  HANDLE output = nullptr;
  HANDLE console_output = nullptr;
  if (int result = create_pipe_pair(unique_pipe_name(L"out"), true, output, console_output); result < 0)
  {
    error = result;
    return nullptr;
  }
  HANDLE input = nullptr;
  HANDLE console_input = nullptr;
  if (int result = create_pipe_pair(unique_pipe_name(L"in"), false, input, console_input); result < 0)
  {
    close_handle(output);
    close_handle(console_output);
    error = result;
    return nullptr;
  }

  pseudo_console_t console = nullptr;
  const HRESULT created = api->create(to_coord(options.size), console_input, console_output, api->bundled ? glyph_width_flags(options.glyph_width) : 0, &console);
  close_handle(console_input);
  close_handle(console_output);
  if (FAILED(created))
  {
    close_handle(output);
    close_handle(input);
    error = errc_from_hresult(created);
    return nullptr;
  }

  SIZE_T attribute_size = 0;
  ::InitializeProcThreadAttributeList(nullptr, 1, 0, &attribute_size);
  std::vector<std::byte> attribute_storage(attribute_size);
  auto *attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attribute_storage.data());
  int failure = 0;
  bool attributes_ready = false;
  if (!::InitializeProcThreadAttributeList(attributes, 1, 0, &attribute_size))
    failure = errc_from_win32(::GetLastError());
  else
    attributes_ready = true;
  if (failure == 0 && !::UpdateProcThreadAttribute(attributes, 0, proc_thread_attribute_pseudoconsole, console, sizeof(console), nullptr, nullptr))
    failure = errc_from_win32(::GetLastError());

  PROCESS_INFORMATION information{};
  if (failure == 0)
  {
    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.lpAttributeList = attributes;
    if (!::CreateProcessW(nullptr, command.data(), nullptr, nullptr, FALSE, EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT, environment.data(),
                          working_directory.empty() ? nullptr : working_directory.c_str(), &startup.StartupInfo, &information))
      failure = errc_from_win32(::GetLastError());
  }
  if (attributes_ready)
    ::DeleteProcThreadAttributeList(attributes);
  if (failure != 0)
  {
    close_handle(output);
    close_handle(input);
    api->close(console);
    error = failure;
    return nullptr;
  }
  ::CloseHandle(information.hThread);

  auto *core = new process_core_t(loop);
  if (int result = core->start(*api, console, information.hProcess, information.dwProcessId, input, output); result < 0)
  {
    core->abandon_start();
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

#if defined(VIO_INTERNAL_TESTS) && defined(_MSC_VER)
#include <doctest/doctest.h>

#include <shellapi.h>

#pragma comment(lib, "shell32.lib")

namespace vio::detail
{
TEST_CASE("process: a command line survives CommandLineToArgvW")
{
  process_options_t options;
  options.program = "C:\\Program Files\\vio test\\app.exe";
  options.arguments = {"plain", "", "with space", "quote\"inside", "trailing\\", "back\\\\slash \"q\"", "tab\there", "\\\\server\\share\\", "\xc3\xbcnic\xc3\xb8" "de", "\"", "\\\"", "a\\\\b c"};
  std::wstring command;
  REQUIRE(build_command_line(options, command) == 0);
  int count = 0;
  LPWSTR *argv = ::CommandLineToArgvW(command.c_str(), &count);
  REQUIRE(argv != nullptr);
  REQUIRE(count == static_cast<int>(options.arguments.size() + 1));
  std::wstring expected;
  REQUIRE(widen(options.program, expected) == 0);
  CHECK(std::wstring(argv[0]) == expected);
  for (std::size_t i = 0; i < options.arguments.size(); ++i)
  {
    REQUIRE(widen(options.arguments[i], expected) == 0);
    CHECK(std::wstring(argv[i + 1]) == expected);
  }
  ::LocalFree(argv);

  options.program = "has\"quote.exe";
  CHECK(build_command_line(options, command) == errc::invalid_argument);
}

TEST_CASE("process: environment overrides match names without regard to case")
{
  process_options_t options;
  options.inherit_environment = false;
  options.environment = {{"Path", "C:\\one"}, {"ZETA", "z"}, {"alpha", "a"}, {"PATH", "C:\\two"}};
  std::vector<wchar_t> block;
  REQUIRE(build_environment(options, block) == 0);
  std::vector<std::wstring> entries;
  for (const wchar_t *entry = block.data(); *entry; entry += std::wcslen(entry) + 1)
    entries.emplace_back(entry);
  REQUIRE(entries.size() == 3);
  CHECK(entries[0] == L"alpha=a");
  CHECK(entries[1] == L"PATH=C:\\two");
  CHECK(entries[2] == L"ZETA=z");

  options.environment = {{"BAD=NAME", "x"}};
  CHECK(build_environment(options, block) == errc::invalid_argument);
}
} // namespace vio::detail
#endif

#endif
