#include <doctest/doctest.h>

#include <vio/event_loop.h>
#include <vio/operation/tls_client.h>

#include <string>

TEST_SUITE("ca certificates")
{
  // get_default_ca_certificates() caches the bundle in a program-lifetime static
  // and libressl copies the bytes into its own config, so it should hand back a
  // reference rather than copying the (100-300KB) bundle on every connection.
  TEST_CASE("returns a shared reference, not a per-call copy")
  {
    const std::string &first = vio::get_default_ca_certificates();
    const std::string &second = vio::get_default_ca_certificates();

    // Same object on every call -> returned by reference.
    CHECK_EQ(&first, &second);
    CHECK_FALSE(first.empty());
  }
}
