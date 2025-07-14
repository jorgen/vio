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

#include <optional>
#include <string>
#include <vector>

struct ssl_config
{
  std::optional<std::string> ca_file;
  std::optional<std::string> ca_path;
  std::optional<std::string> cert_file;
  std::optional<std::string> key_file;
  std::optional<std::string> ocsp_staple_file;
  std::optional<std::vector<uint8_t>> ca_mem;
  std::optional<std::vector<uint8_t>> cert_mem;
  std::optional<std::vector<uint8_t>> key_mem;
  std::optional<std::vector<uint8_t>> ocsp_staple_mem;
  std::optional<std::string> ciphers;
  std::optional<std::string> alpn;
  std::optional<bool> verify_client;
  std::optional<bool> verify_depth;
  std::optional<bool> verify_optional;
  std::optional<uint32_t> protocols;
  std::optional<uint32_t> dheparams;
  std::optional<uint32_t> ecdhecurve;
};
