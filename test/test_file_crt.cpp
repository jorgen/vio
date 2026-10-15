#include <doctest/doctest.h>
#include <vio/detail/sys_file.h>
#include <vio/errc.h>

#if defined(_MSC_VER)
#include <crtdbg.h>

namespace
{
class crt_report_to_stderr_t
{
public:
  crt_report_to_stderr_t()
    : _mode(_CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE))
    , _file(_CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR))
  {
  }
  crt_report_to_stderr_t(const crt_report_to_stderr_t &) = delete;
  crt_report_to_stderr_t &operator=(const crt_report_to_stderr_t &) = delete;
  ~crt_report_to_stderr_t()
  {
    _CrtSetReportMode(_CRT_ASSERT, _mode);
    _CrtSetReportFile(_CRT_ASSERT, _file);
  }

private:
  int _mode;
  _HFILE _file;
};
} // namespace

TEST_CASE("a file descriptor the CRT does not know is refused rather than ending the process")
{
  crt_report_to_stderr_t report;
  const vio::native_file_t unknown = 0x3ffffff0;
  CHECK(vio::detail::fs_handle(unknown) == INVALID_HANDLE_VALUE);
  CHECK(vio::detail::fs_close(unknown) == vio::errc::bad_descriptor);
}
#endif
