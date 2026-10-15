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
