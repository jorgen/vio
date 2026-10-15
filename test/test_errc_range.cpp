#include <doctest/doctest.h>
#include <vio/errc.h>

#include <array>

TEST_CASE("vio error codes sit below every code libuv defines")
{
  constexpr int lowest_libuv_code = -4095;
  constexpr std::array codes = {vio::errc::eof,         vio::errc::canceled,           vio::errc::again,          vio::errc::connection_reset, vio::errc::bad_descriptor,
                                vio::errc::no_such_file, vio::errc::resource_busy_or_locked, vio::errc::dns_address_family, vio::errc::dns_again,        vio::errc::dns_canceled,
                                vio::errc::dns_bad_hints, vio::errc::unknown};
  for (int code : codes)
    CHECK(code < lowest_libuv_code);
}
