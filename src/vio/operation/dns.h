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
#include "uv.h"
#include "vio/error.h"
#include "vio/event_loop.h"
#include "vio/uv_coro.h"

#include <coroutine>
#include <expected>
#include <string>
#include <vector>

namespace vio
{

class address_info_t
{
public:
  int flags = 0;
  int family = 0;
  int socktype = 0;
  int protocol = 0;
  std::string canonname;
  std::vector<uint8_t> addr;

  address_info_t() = default;

  explicit address_info_t(const addrinfo &info)
    : flags(info.ai_flags)
    , family(info.ai_family)
    , socktype(info.ai_socktype)
    , protocol(info.ai_protocol)
  {
    if (info.ai_addr != nullptr && info.ai_addrlen > 0)
    {
      addr.resize(info.ai_addrlen);
      std::memcpy(addr.data(), info.ai_addr, info.ai_addrlen);
    }

    if (info.ai_canonname != nullptr)
    {
      canonname = info.ai_canonname;
    }
  }

  [[nodiscard]] struct sockaddr *get_sockaddr()
  {
    return addr.empty() ? nullptr : reinterpret_cast<struct sockaddr *>(addr.data());
  }

  [[nodiscard]] const struct sockaddr *get_sockaddr() const
  {
    return addr.empty() ? nullptr : reinterpret_cast<const struct sockaddr *>(addr.data());
  }
};

using address_info_list_t = std::vector<address_info_t>;

inline addrinfo convert_to_addrinfo(const address_info_t &info)
{
  addrinfo result{};
  result.ai_flags = info.flags;
  result.ai_family = info.family;
  result.ai_socktype = info.socktype;
  result.ai_protocol = info.protocol;
  result.ai_canonname = info.canonname.empty() ? nullptr : const_cast<char *>(info.canonname.c_str());
  return result;
}

inline address_info_list_t convert_addrinfo_list(const addrinfo *info)
{
  address_info_list_t result;
  result.reserve(5);
  for (const addrinfo *current = info; current != nullptr; current = current->ai_next)
  {
    result.emplace_back(*current);
  }
  return result;
}

struct get_addrinfo_state_t
{
  std::string host;
  uv_getaddrinfo_t req = {};
  std::expected<address_info_list_t, error_t> result;
  std::coroutine_handle<> continuation;
  bool done = false;

  [[nodiscard]] bool await_ready() const noexcept
  {
    return done;
  }

  bool await_suspend(std::coroutine_handle<> continuation) noexcept
  {
    if (done)
    {
      return false;
    }
    this->continuation = continuation;
    return true;
  }

  auto await_resume() noexcept
  {
    return std::move(result);
  }
};

inline future_t<get_addrinfo_state_t> get_addrinfo(event_loop_t &event_loop, const std::string &host, const address_info_t &hints = address_info_t{})
{
  using ret_t = decltype(get_addrinfo(event_loop, host, hints));
  using future_ref_ptr_t = ret_t::future_ref_ptr_t;
  ret_t ret;
  ret.state_ptr->host = host;
  auto hints_converted = convert_to_addrinfo(hints);
  auto req = &ret.state_ptr->req;
  {
    auto copy = ret.state_ptr;
    req->data = copy.release_to_raw();
  }
  auto callback = [](uv_getaddrinfo_t *req, int status, addrinfo *res)
  {
    auto state = future_ref_ptr_t::from_raw(req->data);
    state->done = true;
    if (status < 0)
    {
      std::string msg(uv_strerror(status));
      error_t err = {.code = status, .msg = msg};
      state->result = std::unexpected(err);
    }
    else
    {
      state->result = convert_addrinfo_list(res);
    }

    uv_freeaddrinfo(res);

    if (state->continuation)
    {
      state->continuation.resume();
    }
  };
  auto r = uv_getaddrinfo(event_loop.loop(), req, callback, host.c_str(), nullptr, &hints_converted);
  if (r < 0)
  {
    // Mark as done right away and set the error.
    ret.state_ptr->done = true;
    ret.state_ptr->result = std::unexpected(error_t{.code = r, .msg = uv_strerror(r)});
  }
  return ret;
}

struct name_info_result_t
{
  std::string host;
  std::string service;
};
struct getnameinfo_state_t
{
  uv_getnameinfo_t req;
  std::expected<name_info_result_t, error_t> result;
  std::coroutine_handle<> continuation;
  bool done = false;

  [[nodiscard]] bool await_ready() const noexcept
  {
    return done;
  }

  bool await_suspend(std::coroutine_handle<> continuation) noexcept
  {
    if (done)
    {
      return false;
    }
    this->continuation = continuation;
    return true;
  }

  auto await_resume() noexcept
  {
    return std::move(result);
  }
};

inline future_t<getnameinfo_state_t> get_nameinfo(event_loop_t &event_loop, const address_info_t &addr, int hints = NI_NUMERICHOST | NI_NUMERICSERV)
{
  using ret_t = future_t<getnameinfo_state_t>;
  using future_ref_ptr_t = ret_t::future_ref_ptr_t;
  ret_t ret;
  auto req = &ret.state_ptr->req;
  {
    auto copy = ret.state_ptr;
    req->data = copy.release_to_raw();
  }
  auto callback = [](uv_getnameinfo_t *req, int status, const char *hostname, const char *service)
  {
    auto state = future_ref_ptr_t::from_raw(req->data);
    state->done = true;
    if (status < 0)
    {
      std::string msg(uv_strerror(status));
      error_t err = {.code = status, .msg = msg};
      state->result = std::unexpected(err);
    }
    else
    {
      state->result = {std::string(hostname), std::string(service)};
    }

    if (state->continuation)
    {
      state->continuation.resume();
    }
  };
  auto r = uv_getnameinfo(event_loop.loop(), req, callback, addr.get_sockaddr(), hints);
  if (r < 0)
  {
    ret.state_ptr->done = true;
    ret.state_ptr->result = std::unexpected(error_t{.code = r, .msg = uv_strerror(r)});
  }
  return ret;
}

} // namespace vio