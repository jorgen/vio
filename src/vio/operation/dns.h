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

#include <algorithm>
#include <coroutine>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <string>
#include <utility>
#include <vector>

#include <ada/ada_idna.h>

#include "vio/cancellation.h"
#include "vio/detail/exceptions.h"
#include "vio/detail/native.h"
#include "vio/detail/sys.h"
#include "vio/errc.h"
#include "vio/error.h"
#include "vio/event_loop.h"
#include "vio/future.h"
#include "vio/loop/blocking_pool.h"
#include "vio/ref_counted_wrapper.h"

#if !defined(_WIN32)
#include <netdb.h>
#endif

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
  detail::pool_job_t job;
  int hint_flags = 0;
  int hint_family = 0;
  int hint_socktype = 0;
  int hint_protocol = 0;
  int status = 0;
  address_info_list_t addresses;
  void *parked = nullptr;
  std::expected<address_info_list_t, error_t> result;
  std::coroutine_handle<> continuation;
  registration_t cancel_registration;
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

struct name_info_result_t
{
  std::string host;
  std::string service;
};

struct getnameinfo_state_t
{
  detail::pool_job_t job;
  sockaddr_storage address = {};
  int address_length = 0;
  int flags = 0;
  int status = 0;
  name_info_result_t names;
  void *parked = nullptr;
  std::expected<name_info_result_t, error_t> result;
  std::coroutine_handle<> continuation;
  registration_t cancel_registration;
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

namespace detail
{
inline int dns_prepare_host(const std::string &host, std::string &out)
{
  if (host.find('\0') != std::string::npos)
    return errc::invalid_argument;
  if (std::all_of(host.begin(), host.end(), [](char c) { return static_cast<unsigned char>(c) < 0x80; }))
  {
    out = host;
    return 0;
  }
  out = ada::idna::to_ascii(host);
  return out.empty() ? errc::invalid_argument : 0;
}

inline std::size_t dns_address_length(const address_info_t &address) noexcept
{
  const sockaddr *socket_address = address.get_sockaddr();
  if (socket_address == nullptr || address.addr.size() < sizeof(sockaddr))
    return 0;
  std::size_t needed = 0;
  if (socket_address->sa_family == AF_INET)
    needed = sizeof(sockaddr_in);
  else if (socket_address->sa_family == AF_INET6)
    needed = sizeof(sockaddr_in6);
  return address.addr.size() >= needed ? needed : 0;
}

template <typename State>
void dns_resume(State &state)
{
  state.done = true;
  state.cancel_registration.reset();
  if (state.continuation)
    state.continuation.resume();
}

template <typename State>
void dns_cancel(State &state)
{
  if (state.done)
    return;
  pool_cancel(state.job);
  state.result = std::unexpected(make_error(errc::canceled));
  dns_resume(state);
}

template <typename State>
void dns_submit(event_loop_t &event_loop, future_t<State> &ret, pool_job_t::work_fn_t work, pool_job_t::done_fn_t done, cancellation_t *cancel)
{
  auto &state = ret.state_ptr.data();
  state.job.owner = &state;
  state.job.work = work;
  state.job.done = done;
  auto parked = ret.state_ptr;
  state.parked = parked.release_to_raw();
  pool_submit(detail::core(event_loop), state.job, pool_queue::dns);
  if (cancel)
  {
    auto *raw = &state;
    state.cancel_registration = cancel->register_callback([raw]() { dns_cancel(*raw); });
  }
}

inline void get_addrinfo_work(pool_job_t *job)
{
  auto *state = static_cast<get_addrinfo_state_t *>(job->owner);
#if defined(_WIN32)
  ensure_winsock();
#endif
  addrinfo hints{};
  hints.ai_flags = state->hint_flags;
  hints.ai_family = state->hint_family;
  hints.ai_socktype = state->hint_socktype;
  hints.ai_protocol = state->hint_protocol;
  addrinfo *list = nullptr;
  const int code = ::getaddrinfo(state->host.c_str(), nullptr, &hints, &list);
  if (code != 0)
  {
    state->status = errc_from_gai(code);
    return;
  }
  VIO_TRY
  {
    state->addresses = convert_addrinfo_list(list);
  }
  VIO_CATCH_ALL
  {
    state->status = errc::dns_memory;
  }
  ::freeaddrinfo(list);
}

inline void get_addrinfo_done(pool_job_t *job, bool)
{
  auto *state = static_cast<get_addrinfo_state_t *>(job->owner);
  auto owned = ref_ptr_t<get_addrinfo_state_t>::from_raw(std::exchange(state->parked, nullptr));
  if (state->done)
  {
    address_info_list_t().swap(state->addresses);
    return;
  }
  if (state->status < 0)
    state->result = std::unexpected(make_error(state->status));
  else
    state->result = std::move(state->addresses);
  dns_resume(*state);
}

inline void get_nameinfo_work(pool_job_t *job)
{
  auto *state = static_cast<getnameinfo_state_t *>(job->owner);
#if defined(_WIN32)
  ensure_winsock();
#endif
  char host[1025] = {};
  char service[32] = {};
  const int code = ::getnameinfo(reinterpret_cast<const sockaddr *>(&state->address), static_cast<socklen_t>(state->address_length), host, sizeof(host), service, sizeof(service), state->flags);
  if (code != 0)
  {
    state->status = errc_from_gai(code);
    return;
  }
  VIO_TRY
  {
    state->names.host = host;
    state->names.service = service;
  }
  VIO_CATCH_ALL
  {
    state->status = errc::dns_memory;
  }
}

inline void get_nameinfo_done(pool_job_t *job, bool)
{
  auto *state = static_cast<getnameinfo_state_t *>(job->owner);
  auto owned = ref_ptr_t<getnameinfo_state_t>::from_raw(std::exchange(state->parked, nullptr));
  if (state->done)
    return;
  if (state->status < 0)
    state->result = std::unexpected(make_error(state->status));
  else
    state->result = std::move(state->names);
  dns_resume(*state);
}
} // namespace detail

inline future_t<get_addrinfo_state_t> get_addrinfo(event_loop_t &event_loop, const std::string &host, const address_info_t &hints = address_info_t{}, cancellation_t *cancel = nullptr)
{
  future_t<get_addrinfo_state_t> ret;
  auto &state = ret.state_ptr.data();

  if (cancel && cancel->is_cancelled())
  {
    state.done = true;
    state.result = std::unexpected(error_t{.code = vio_cancelled, .msg = "cancelled"});
    return ret;
  }

  if (int code = detail::dns_prepare_host(host, state.host); code < 0)
  {
    state.done = true;
    state.result = std::unexpected(make_error(code));
    return ret;
  }

  state.hint_flags = hints.flags;
  state.hint_family = hints.family;
  state.hint_socktype = hints.socktype;
  state.hint_protocol = hints.protocol;
  detail::dns_submit(event_loop, ret, &detail::get_addrinfo_work, &detail::get_addrinfo_done, cancel);
  return ret;
}

inline future_t<getnameinfo_state_t> get_nameinfo(event_loop_t &event_loop, const address_info_t &addr, int hints = NI_NUMERICHOST | NI_NUMERICSERV, cancellation_t *cancel = nullptr)
{
  future_t<getnameinfo_state_t> ret;
  auto &state = ret.state_ptr.data();

  if (cancel && cancel->is_cancelled())
  {
    state.done = true;
    state.result = std::unexpected(error_t{.code = vio_cancelled, .msg = "cancelled"});
    return ret;
  }

  const std::size_t length = detail::dns_address_length(addr);
  if (length == 0)
  {
    state.done = true;
    state.result = std::unexpected(make_error(errc::invalid_argument));
    return ret;
  }

  std::memcpy(&state.address, addr.addr.data(), length);
  state.address_length = static_cast<int>(length);
  state.flags = hints;
  detail::dns_submit(event_loop, ret, &detail::get_nameinfo_work, &detail::get_nameinfo_done, cancel);
  return ret;
}

} // namespace vio
