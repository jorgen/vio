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

#include "vio/buffer_pool.h"
#include "vio/cancellation.h"
#include "vio/detail/sys_udp.h"
#include "vio/error.h"
#include "vio/event_loop.h"
#include "vio/loop/socket.h"
#include "vio/owned_payload.h"
#include "vio/ref_counted_wrapper.h"
#include "vio/unique_buf.h"

#include <algorithm>
#include <array>
#include <coroutine>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <expected>
#include <memory>
#include <optional>
#include <ranges>
#include <span>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#if !defined(_WIN32)
#include <net/if.h>
#endif

namespace vio
{

struct udp_datagram_t
{
  unique_buf_t data;
  sockaddr_storage sender_addr = {};

  const sockaddr *get_sender() const
  {
    return reinterpret_cast<const sockaddr *>(&sender_addr);
  }

  int sender_port() const
  {
    if (sender_addr.ss_family == AF_INET)
    {
      return ntohs(reinterpret_cast<const sockaddr_in *>(&sender_addr)->sin_port);
    }
    if (sender_addr.ss_family == AF_INET6)
    {
      return ntohs(reinterpret_cast<const sockaddr_in6 *>(&sender_addr)->sin6_port);
    }
    return -1;
  }
};

// RFC 3168: the two-bit ECN field, in the values it takes on the wire. It sits
// in the low bits of the IPv4 TOS byte and the IPv6 traffic class byte.
enum class udp_ecn_t : std::uint8_t
{
  not_ect = 0x00,
  ect1 = 0x01,
  ect0 = 0x02,
  ce = 0x03,
};

enum class udp_bind_flags : unsigned int
{
  none = 0,
  ipv6_only = 1,
  reuseaddr = 4,
  reuseport = 8,
};

[[nodiscard]] constexpr udp_bind_flags operator|(udp_bind_flags a, udp_bind_flags b) noexcept
{
  return static_cast<udp_bind_flags>(static_cast<unsigned int>(a) | static_cast<unsigned int>(b));
}

[[nodiscard]] constexpr udp_bind_flags operator&(udp_bind_flags a, udp_bind_flags b) noexcept
{
  return static_cast<udp_bind_flags>(static_cast<unsigned int>(a) & static_cast<unsigned int>(b));
}

enum class udp_membership_t
{
  leave_group = 0,
  join_group = 1,
};

// Datagrams a reader has taken off the socket but the consumer has not yet
// collected. Bounded: a peer that sends faster than the consumer drains must
// cost bounded memory.
inline constexpr std::size_t udp_default_recv_queue_limit = 1024;
inline constexpr std::size_t udp_receive_buffer_size = 64 * 1024;
inline constexpr std::size_t udp_recv_burst = 32;
inline constexpr std::size_t udp_recvmmsg_batch = 16;
inline constexpr std::size_t udp_max_batch_size = 64;

namespace detail
{
#if defined(__linux__)
inline constexpr bool udp_has_recvmmsg = true;
#else
inline constexpr bool udp_has_recvmmsg = false;
#endif

template <typename T>
class fifo_t
{
public:
  [[nodiscard]] bool empty() const noexcept
  {
    return _head == _items.size();
  }

  [[nodiscard]] std::size_t size() const noexcept
  {
    return _items.size() - _head;
  }

  T &front() noexcept
  {
    return _items[_head];
  }

  void pop_front()
  {
    ++_head;
    if (_head == _items.size())
    {
      _items.clear();
      _head = 0;
    }
  }

  template <typename... Args>
  void emplace_back(Args &&...args)
  {
    _items.emplace_back(std::forward<Args>(args)...);
  }

  template <typename Predicate>
  void erase_if(Predicate predicate)
  {
    std::vector<T> kept;
    for (std::size_t i = _head; i < _items.size(); ++i)
    {
      if (!predicate(_items[i]))
      {
        kept.push_back(std::move(_items[i]));
      }
    }
    _items = std::move(kept);
    _head = 0;
  }

private:
  std::vector<T> _items;
  std::size_t _head = 0;
};

template <typename T>
void *ref_storage(ref_ptr_t<T> &pointer) noexcept
{
  void *raw = pointer.release_to_raw();
  pointer = ref_ptr_t<T>::from_raw(raw);
  return raw;
}

template <typename T>
void *ref_retain(void *storage) noexcept
{
  static_cast<typename ref_ptr_t<T>::storage_t *>(storage)->ref_count.inc();
  return storage;
}

struct udp_target_t
{
  sockaddr_in6 mapped = {};
  const sockaddr *address = nullptr;
  int length = 0;
};
} // namespace detail

struct udp_send_state_t
{
  detail::io_op_t op;
  std::coroutine_handle<> continuation;
  std::expected<void, error_t> result;
  const std::uint8_t *data = nullptr;
  std::size_t length = 0;
  sockaddr_storage address = {};
  int address_length = 0;
  std::uint64_t generation = 0;
  bool started = false;
  bool done = false;
};

struct udp_recv_state_t
{
  bool active = false;
  bool started = false;
  bool is_cancelled = false;
  detail::fifo_t<std::expected<udp_datagram_t, error_t>> buffer_queue;
  std::size_t recv_queue_limit = udp_default_recv_queue_limit;
  std::uint64_t dropped_datagrams = 0;
  std::uint64_t truncated_datagrams = 0;
  std::uint64_t recv_errors = 0;
  std::coroutine_handle<> continuation;
  alloc_cb_t alloc_buffer_cb = default_alloc;
  dealloc_cb_t dealloc_buffer_cb = default_dealloc;
  void *alloc_cb_data = nullptr;
  std::vector<std::span<std::byte>> spare;
  detail::io_op_t op;
  detail::posted_t retry;
  std::uint32_t drained_epoch = 0;
  bool drained = true;
  bool drained_known = false;
};

namespace detail
{
inline void udp_return_spares(udp_recv_state_t &recv) noexcept
{
  for (auto buffer : recv.spare)
  {
    recv.dealloc_buffer_cb(recv.alloc_cb_data, buffer);
  }
  recv.spare.clear();
}
} // namespace detail

struct udp_state_t
{
  explicit udp_state_t(event_loop_t &loop)
    : event_loop(loop)
    , socket(detail::core(loop), "udp")
  {
  }

  udp_state_t(const udp_state_t &) = delete;
  udp_state_t &operator=(const udp_state_t &) = delete;
  udp_state_t(udp_state_t &&) = delete;
  udp_state_t &operator=(udp_state_t &&) = delete;

  ~udp_state_t()
  {
    detail::udp_return_spares(recv);
  }

  event_loop_t &event_loop;
  detail::socket_resource_t socket;
  udp_send_state_t send;
  udp_recv_state_t recv;
  void *self = nullptr;
  int family = AF_UNSPEC;
  bool connected = false;
  bool use_recvmmsg = false;
  bool datagram_reader = false;
};

namespace detail
{
[[nodiscard]] inline bool udp_flag_set(udp_bind_flags flags, udp_bind_flags flag) noexcept
{
  return (flags & flag) != udp_bind_flags::none;
}

[[nodiscard]] inline int udp_apply_bind_flags(native_socket_t native, int family, udp_bind_flags flags) noexcept
{
  if (udp_flag_set(flags, udp_bind_flags::reuseaddr))
  {
#if defined(SO_REUSEPORT) && !defined(__linux__) && !defined(_WIN32)
    if (int result = udp_set_int_option(native, SOL_SOCKET, SO_REUSEPORT, 1); result < 0)
    {
      return result;
    }
#else
    if (int result = udp_set_int_option(native, SOL_SOCKET, SO_REUSEADDR, 1); result < 0)
    {
      return result;
    }
#endif
  }
  if (udp_flag_set(flags, udp_bind_flags::reuseport))
  {
#if defined(__linux__) && defined(SO_REUSEPORT)
    if (int result = udp_set_int_option(native, SOL_SOCKET, SO_REUSEPORT, 1); result < 0)
    {
      return result;
    }
#else
    return errc::not_supported;
#endif
  }
#if defined(IPV6_V6ONLY)
  if (family == AF_INET6)
  {
    const bool only = udp_flag_set(flags, udp_bind_flags::ipv6_only);
    if (int result = udp_set_int_option(native, IPPROTO_IPV6, IPV6_V6ONLY, only ? 1 : 0); result < 0 && only)
    {
      return result;
    }
  }
#else
  (void)family;
#endif
  return 0;
}

[[nodiscard]] inline int udp_bind_socket(udp_state_t &state, const sockaddr *address, udp_bind_flags flags) noexcept
{
  const int length = udp_address_length(address);
  if (length <= 0)
  {
    return errc::invalid_argument;
  }
  const auto known = udp_bind_flags::ipv6_only | udp_bind_flags::reuseaddr | udp_bind_flags::reuseport;
  if ((static_cast<unsigned int>(flags) & ~static_cast<unsigned int>(known)) != 0)
  {
    return errc::invalid_argument;
  }
  if (udp_flag_set(flags, udp_bind_flags::ipv6_only) && address->sa_family != AF_INET6)
  {
    return errc::invalid_argument;
  }
#if !defined(__linux__)
  if (udp_flag_set(flags, udp_bind_flags::reuseport))
  {
    return errc::not_supported;
  }
#endif
  native_socket_t native = state.socket.native();
  const bool fresh = native == invalid_native_socket;
  if (fresh)
  {
    if (int result = socket_open(address->sa_family, SOCK_DGRAM, 0, native); result < 0)
    {
      return result;
    }
  }
  int result = udp_apply_bind_flags(native, address->sa_family, flags);
  if (result == 0)
  {
    result = socket_bind(native, address, length);
  }
  if (result < 0)
  {
    if (fresh)
    {
      (void)socket_close(native);
    }
    return result;
  }
  if (fresh)
  {
    if (int adopted = state.socket.adopt(native); adopted < 0)
    {
      (void)socket_close(native);
      state.socket.watch.socket = invalid_native_socket;
      return adopted;
    }
    state.family = address->sa_family;
  }
  return 0;
}

[[nodiscard]] inline int udp_ensure_socket(udp_state_t &state, int family, udp_bind_flags flags = udp_bind_flags::none) noexcept
{
  if (state.socket.native() != invalid_native_socket)
  {
    return 0;
  }
  sockaddr_storage any = {};
  if (family == AF_INET6)
  {
    reinterpret_cast<sockaddr_in6 *>(&any)->sin6_family = AF_INET6;
  }
  else
  {
    auto *in = reinterpret_cast<sockaddr_in *>(&any);
    in->sin_family = AF_INET;
    in->sin_addr.s_addr = htonl(INADDR_ANY);
  }
  return udp_bind_socket(state, reinterpret_cast<const sockaddr *>(&any), flags);
}

[[nodiscard]] inline int udp_require_socket(const udp_state_t &state) noexcept
{
  return state.socket.native() == invalid_native_socket ? errc::bad_descriptor : 0;
}

inline void udp_map_ipv4(const sockaddr *address, sockaddr_in6 &mapped) noexcept
{
  const auto *in4 = reinterpret_cast<const sockaddr_in *>(address);
  mapped = {};
  mapped.sin6_family = AF_INET6;
  mapped.sin6_port = in4->sin_port;
  auto *bytes = reinterpret_cast<std::uint8_t *>(&mapped.sin6_addr);
  bytes[10] = 0xff;
  bytes[11] = 0xff;
  std::memcpy(bytes + 12, &in4->sin_addr, 4);
}

[[nodiscard]] inline int udp_prepare_target(udp_state_t &state, const sockaddr *address, udp_target_t &target) noexcept
{
  if (address == nullptr)
  {
    if (!state.connected)
    {
      return errc::destination_address_required;
    }
    target.address = nullptr;
    target.length = 0;
    return 0;
  }
  const int length = udp_address_length(address);
  if (length <= 0)
  {
    return errc::address_family_not_supported;
  }
  if (state.connected)
  {
    return errc::already_connected;
  }
  if (int result = udp_ensure_socket(state, address->sa_family); result < 0)
  {
    return result;
  }
  if (address->sa_family == AF_INET && state.family == AF_INET6)
  {
    udp_map_ipv4(address, target.mapped);
    target.address = reinterpret_cast<const sockaddr *>(&target.mapped);
    target.length = static_cast<int>(sizeof(sockaddr_in6));
    return 0;
  }
  target.address = address;
  target.length = length;
  return 0;
}

[[nodiscard]] inline std::expected<void, error_t> udp_result(int code)
{
  if (code < 0)
  {
    return std::unexpected(make_error(code));
  }
  return {};
}

[[nodiscard]] inline std::expected<void, error_t> udp_send_result(std::int64_t sent)
{
  if (sent < 0)
  {
    return std::unexpected(make_error(static_cast<int>(sent)));
  }
  return {};
}

inline void udp_on_send_ready(io_op_t *op);
inline void udp_abandon_send(udp_state_t &state, std::uint64_t generation);
} // namespace detail

template <typename State>
struct udp_future_t
{
  ref_ptr_t<udp_state_t> handle;
  State *state;
  std::optional<error_t> rejected;
  std::uint64_t generation = 0;
  bool pending = false;

  udp_future_t(ref_ptr_t<udp_state_t> socket, State &operation_state)
    : handle(std::move(socket))
    , state(&operation_state)
  {
  }

  udp_future_t(ref_ptr_t<udp_state_t> socket, State &operation_state, error_t error)
    : handle(std::move(socket))
    , state(&operation_state)
    , rejected(std::move(error))
  {
  }

  udp_future_t(const udp_future_t &) = delete;
  udp_future_t &operator=(const udp_future_t &) = delete;
  udp_future_t &operator=(udp_future_t &&) = delete;

  udp_future_t(udp_future_t &&other) noexcept
    : handle(std::move(other.handle))
    , state(other.state)
    , rejected(std::move(other.rejected))
    , generation(other.generation)
    , pending(std::exchange(other.pending, false))
  {
  }

  ~udp_future_t()
  {
    if (pending && handle)
    {
      detail::udp_abandon_send(handle.data(), generation);
    }
  }

  bool await_ready() noexcept
  {
    return rejected.has_value() || state->done;
  }

  bool await_suspend(std::coroutine_handle<> continuation) noexcept
  {
    if (state->done)
    {
      return false;
    }
    state->continuation = continuation;
    return true;
  }

  std::expected<void, error_t> await_resume() noexcept
  {
    pending = false;
    if (rejected.has_value())
    {
      return std::unexpected(std::move(*rejected));
    }
    return state->result;
  }
};

struct udp_t
{
  ref_ptr_t<udp_state_t> handle;
};

// recvmmsg reads several datagrams per syscall. It is a Linux facility; the
// request is ignored elsewhere, so asking for it unconditionally is safe and
// udp_using_recvmmsg reports what was actually obtained.
enum class udp_recvmmsg_t : std::uint8_t
{
  off,
  on,
};

inline std::expected<udp_t, error_t> udp_create(event_loop_t &loop, udp_recvmmsg_t recvmmsg = udp_recvmmsg_t::off)
{
  udp_t udp{ref_ptr_t<udp_state_t>(loop)};
  udp.handle->self = detail::ref_storage(udp.handle);
  udp.handle->use_recvmmsg = recvmmsg == udp_recvmmsg_t::on;
  udp.handle.register_resource(udp.handle->socket);
  return udp;
}

inline bool udp_using_recvmmsg(udp_t &udp)
{
  return detail::udp_has_recvmmsg && udp.handle->use_recvmmsg;
}

inline std::expected<void, error_t> udp_bind(udp_t &udp, const sockaddr *addr, udp_bind_flags flags = udp_bind_flags::none)
{
  return detail::udp_result(detail::udp_bind_socket(udp.handle.data(), addr, flags));
}

inline std::expected<void, error_t> udp_disconnect(udp_t &udp)
{
  auto &state = udp.handle.data();
  if (!state.connected)
  {
    return std::unexpected(make_error(errc::not_connected));
  }
  sockaddr_storage none = {};
#if !defined(_WIN32)
  none.ss_family = AF_UNSPEC;
#endif
  const int result = detail::socket_connect(state.socket.native(), reinterpret_cast<const sockaddr *>(&none), static_cast<int>(sizeof(sockaddr)));
#if defined(_WIN32)
  const bool ignored = false;
#elif defined(__linux__)
  const bool ignored = result == errc::address_family_not_supported;
#else
  const bool ignored = result == errc::address_family_not_supported || result == errc::invalid_argument;
#endif
  if (result < 0 && !ignored)
  {
    return std::unexpected(make_error(result));
  }
  state.connected = false;
  return {};
}

inline std::expected<void, error_t> udp_connect(udp_t &udp, const sockaddr *addr)
{
  if (addr == nullptr)
  {
    return udp_disconnect(udp);
  }
  auto &state = udp.handle.data();
  if (state.connected)
  {
    return std::unexpected(make_error(errc::already_connected));
  }
  if (detail::udp_address_length(addr) <= 0)
  {
    return std::unexpected(make_error(errc::address_family_not_supported));
  }
  if (int result = detail::udp_ensure_socket(state, addr->sa_family); result < 0)
  {
    return std::unexpected(make_error(result));
  }
  sockaddr_in6 mapped = {};
  const sockaddr *target = addr;
  int length = detail::udp_address_length(addr);
  if (addr->sa_family == AF_INET && state.family == AF_INET6)
  {
    detail::udp_map_ipv4(addr, mapped);
    target = reinterpret_cast<const sockaddr *>(&mapped);
    length = static_cast<int>(sizeof(mapped));
  }
  if (int result = detail::socket_connect(state.socket.native(), target, length); result < 0)
  {
    return std::unexpected(make_error(result));
  }
  state.connected = true;
  return {};
}

inline std::expected<sockaddr_storage, error_t> udp_sockname(udp_t &udp)
{
  if (int result = detail::udp_require_socket(udp.handle.data()); result < 0)
  {
    return std::unexpected(make_error(result));
  }
  sockaddr_storage address = {};
  int length = 0;
  if (int result = detail::socket_name(udp.handle->socket.native(), address, length); result < 0)
  {
    return std::unexpected(make_error(result));
  }
  return address;
}

namespace detail
{
[[nodiscard]] inline int udp_set_small_option(native_socket_t native, int level, int name, int value) noexcept
{
#if defined(__OpenBSD__) || defined(__sun) || defined(_AIX)
  const unsigned char narrow = static_cast<unsigned char>(value);
  return socket_set_option(native, level, name, &narrow, static_cast<int>(sizeof(narrow)));
#else
  return udp_set_int_option(native, level, name, value);
#endif
}

[[nodiscard]] inline std::expected<void, error_t> udp_option(udp_t &udp, int level, int name, int value)
{
  if (int result = udp_require_socket(udp.handle.data()); result < 0)
  {
    return std::unexpected(make_error(result));
  }
  return udp_result(udp_set_int_option(udp.handle->socket.native(), level, name, value));
}

[[nodiscard]] inline bool udp_parse_ipv6(const char *text, in6_addr &address, std::uint32_t &scope)
{
  std::string host(text);
  std::string zone;
  if (const auto percent = host.find('%'); percent != std::string::npos)
  {
    zone = host.substr(percent + 1);
    host.resize(percent);
  }
  if (inet_pton(AF_INET6, host.c_str(), &address) != 1)
  {
    return false;
  }
  scope = 0;
  if (!zone.empty())
  {
    char *end = nullptr;
    const unsigned long number = std::strtoul(zone.c_str(), &end, 10);
    if (end != nullptr && *end == '\0')
    {
      scope = static_cast<std::uint32_t>(number);
    }
#if !defined(_WIN32)
    else
    {
      scope = if_nametoindex(zone.c_str());
      if (scope == 0)
      {
        return false;
      }
    }
#else
    else
    {
      return false;
    }
#endif
  }
  return true;
}
} // namespace detail

inline std::expected<void, error_t> udp_set_broadcast(udp_t &udp, bool on)
{
  return detail::udp_option(udp, SOL_SOCKET, SO_BROADCAST, on ? 1 : 0);
}

inline std::expected<void, error_t> udp_set_ttl(udp_t &udp, int ttl)
{
  if (ttl < 1 || ttl > 255)
  {
    return std::unexpected(make_error(errc::invalid_argument));
  }
  if (udp.handle->family == AF_INET6)
  {
    return detail::udp_option(udp, IPPROTO_IPV6, IPV6_UNICAST_HOPS, ttl);
  }
  return detail::udp_option(udp, IPPROTO_IP, IP_TTL, ttl);
}

inline std::expected<void, error_t> udp_set_multicast_loop(udp_t &udp, bool on)
{
  if (int result = detail::udp_require_socket(udp.handle.data()); result < 0)
  {
    return std::unexpected(make_error(result));
  }
  const auto native = udp.handle->socket.native();
  if (udp.handle->family == AF_INET6)
  {
    return detail::udp_result(detail::udp_set_int_option(native, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, on ? 1 : 0));
  }
  return detail::udp_result(detail::udp_set_small_option(native, IPPROTO_IP, IP_MULTICAST_LOOP, on ? 1 : 0));
}

inline std::expected<void, error_t> udp_set_multicast_ttl(udp_t &udp, int ttl)
{
  if (int result = detail::udp_require_socket(udp.handle.data()); result < 0)
  {
    return std::unexpected(make_error(result));
  }
  const auto native = udp.handle->socket.native();
  if (udp.handle->family == AF_INET6)
  {
    if (ttl < -1 || ttl > 255)
    {
      return std::unexpected(make_error(errc::invalid_argument));
    }
    return detail::udp_result(detail::udp_set_int_option(native, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, ttl));
  }
  if (ttl < 0 || ttl > 255)
  {
    return std::unexpected(make_error(errc::invalid_argument));
  }
  return detail::udp_result(detail::udp_set_small_option(native, IPPROTO_IP, IP_MULTICAST_TTL, ttl));
}

inline std::expected<void, error_t> udp_set_membership(udp_t &udp, const char *multicast_addr, const char *interface_addr, udp_membership_t membership)
{
  if (multicast_addr == nullptr)
  {
    return std::unexpected(make_error(errc::invalid_argument));
  }
  auto &state = udp.handle.data();
  const bool join = membership == udp_membership_t::join_group;
  in_addr group4 = {};
  if (inet_pton(AF_INET, multicast_addr, &group4) == 1)
  {
    if (int result = detail::udp_ensure_socket(state, AF_INET, udp_bind_flags::reuseaddr); result < 0)
    {
      return std::unexpected(make_error(result));
    }
    ip_mreq request = {};
    request.imr_multiaddr = group4;
    request.imr_interface.s_addr = htonl(INADDR_ANY);
    if (interface_addr != nullptr && inet_pton(AF_INET, interface_addr, &request.imr_interface) != 1)
    {
      return std::unexpected(make_error(errc::invalid_argument));
    }
    return detail::udp_result(detail::socket_set_option(state.socket.native(), IPPROTO_IP, join ? IP_ADD_MEMBERSHIP : IP_DROP_MEMBERSHIP, &request, static_cast<int>(sizeof(request))));
  }
  in6_addr group6 = {};
  std::uint32_t ignored_scope = 0;
  if (!detail::udp_parse_ipv6(multicast_addr, group6, ignored_scope))
  {
    return std::unexpected(make_error(errc::invalid_argument));
  }
  if (int result = detail::udp_ensure_socket(state, AF_INET6, udp_bind_flags::reuseaddr); result < 0)
  {
    return std::unexpected(make_error(result));
  }
  ipv6_mreq request = {};
  request.ipv6mr_multiaddr = group6;
  if (interface_addr != nullptr)
  {
    in6_addr interface_address = {};
    std::uint32_t scope = 0;
    if (!detail::udp_parse_ipv6(interface_addr, interface_address, scope))
    {
      return std::unexpected(make_error(errc::invalid_argument));
    }
    request.ipv6mr_interface = scope;
  }
  return detail::udp_result(detail::socket_set_option(state.socket.native(), IPPROTO_IPV6, join ? IPV6_JOIN_GROUP : IPV6_LEAVE_GROUP, &request, static_cast<int>(sizeof(request))));
}

inline std::expected<void, error_t> udp_set_send_buffer_size(udp_t &udp, int bytes)
{
  if (bytes <= 0)
  {
    return std::unexpected(make_error(errc::invalid_argument));
  }
  return detail::udp_option(udp, SOL_SOCKET, SO_SNDBUF, bytes);
}

inline std::expected<void, error_t> udp_set_recv_buffer_size(udp_t &udp, int bytes)
{
  if (bytes <= 0)
  {
    return std::unexpected(make_error(errc::invalid_argument));
  }
  return detail::udp_option(udp, SOL_SOCKET, SO_RCVBUF, bytes);
}

namespace detail
{
[[nodiscard]] inline std::expected<int, error_t> udp_int_option(udp_t &udp, int level, int name)
{
  if (int result = udp_require_socket(udp.handle.data()); result < 0)
  {
    return std::unexpected(make_error(result));
  }
  int value = 0;
  int length = static_cast<int>(sizeof(value));
  if (int result = socket_get_option(udp.handle->socket.native(), level, name, &value, length); result < 0)
  {
    return std::unexpected(make_error(result));
  }
  return value;
}
} // namespace detail

inline std::expected<int, error_t> udp_send_buffer_size(udp_t &udp)
{
  return detail::udp_int_option(udp, SOL_SOCKET, SO_SNDBUF);
}

inline std::expected<int, error_t> udp_recv_buffer_size(udp_t &udp)
{
  return detail::udp_int_option(udp, SOL_SOCKET, SO_RCVBUF);
}

namespace detail
{
inline void udp_on_send_ready(io_op_t *op)
{
  auto owned = ref_ptr_t<udp_state_t>::from_raw(op->owner);
  auto &state = owned.data();
  auto &send = state.send;
  const auto *to = send.address_length > 0 ? reinterpret_cast<const sockaddr *>(&send.address) : nullptr;
  const auto sent = socket_sendto(state.socket.native(), std::as_bytes(std::span(send.data, send.length)), to, send.address_length);
  if (sent == errc::again)
  {
    op->owner = owned.release_to_raw();
    state.socket.wait(interest_write, *op);
    return;
  }
  send.started = false;
  send.done = true;
  send.result = udp_send_result(sent);
  if (send.continuation)
  {
    auto continuation = std::exchange(send.continuation, {});
    continuation.resume();
  }
}

inline void udp_abandon_send(udp_state_t &state, std::uint64_t generation)
{
  auto &send = state.send;
  if (!send.started || send.done || send.generation != generation)
  {
    return;
  }
  state.socket.cancel(send.op);
  send.started = false;
  send.done = true;
  send.continuation = {};
  send.result = std::unexpected(error_t{.code = vio_cancelled, .msg = "cancelled"});
  ref_ptr_t<udp_state_t>::from_raw(send.op.owner);
}
} // namespace detail

using udp_send_future_t = udp_future_t<udp_send_state_t>;
inline udp_send_future_t send_udp(udp_t &udp, const uint8_t *data, std::size_t length, const sockaddr *addr)
{
  auto &state = udp.handle.data();
  auto &send = state.send;
  if (send.started)
  {
    return udp_send_future_t(udp.handle, send, error_t{.code = errc::already_in_progress, .msg = "It's an error to have more than one send in flight at a time"});
  }
  detail::udp_target_t target;
  if (int result = detail::udp_prepare_target(state, addr, target); result < 0)
  {
    return udp_send_future_t(udp.handle, send, make_error(result));
  }
  const auto sent = detail::socket_sendto(state.socket.native(), std::as_bytes(std::span(data, length)), target.address, target.length);
  send.continuation = {};
  if (sent != errc::again)
  {
    send.done = true;
    send.result = detail::udp_send_result(sent);
    return udp_send_future_t(udp.handle, send);
  }
  send.started = true;
  send.done = false;
  send.result = {};
  send.data = data;
  send.length = length;
  send.address = {};
  send.address_length = target.length;
  if (target.address != nullptr)
  {
    std::memcpy(&send.address, target.address, static_cast<std::size_t>(target.length));
  }
  ++send.generation;
  auto parked = udp.handle;
  send.op.owner = parked.release_to_raw();
  send.op.complete = &detail::udp_on_send_ready;
  state.socket.wait(detail::interest_write, send.op);
  udp_send_future_t future(udp.handle, send);
  future.generation = send.generation;
  future.pending = true;
  return future;
}

inline udp_send_future_t send_udp(udp_t &udp, const uint8_t *data, std::size_t length)
{
  return send_udp(udp, data, length, nullptr);
}

// An owning, awaitable send. Unlike send_udp above there is one of these per
// call rather than one per socket, so any number may be in flight at once.
struct udp_send_op_t
{
  detail::io_op_t io;
  ref_ptr_t<udp_state_t> socket = ref_ptr_t<udp_state_t>::null();
  std::unique_ptr<owned_payload_t> payload;
  std::span<const std::byte> bytes;
  sockaddr_storage address = {};
  int address_length = 0;
  std::coroutine_handle<> continuation;
  std::expected<void, error_t> result;
  registration_t cancel_registration;
  bool completed = false;
  bool detached = false;
};

namespace detail
{
// The op outlives whichever of the two finishes first. Whoever is last to let
// go frees it: the completion when the awaiter has already been abandoned, the
// awaiter when the completion has already happened.
inline void udp_send_release(udp_send_op_t *op)
{
  if (op->completed)
  {
    delete op;
    return;
  }
  op->detached = true;
}

inline void udp_send_op_ready(io_op_t *io)
{
  auto *op = static_cast<udp_send_op_t *>(io->owner);
  auto &state = op->socket.data();
  const auto *to = op->address_length > 0 ? reinterpret_cast<const sockaddr *>(&op->address) : nullptr;
  const auto sent = socket_sendto(state.socket.native(), op->bytes, to, op->address_length);
  if (sent == errc::again)
  {
    state.socket.wait(interest_write, *io);
    return;
  }
  op->completed = true;
  op->cancel_registration.reset();
  if (op->detached)
  {
    delete op;
    return;
  }
  op->result = udp_send_result(sent);
  if (op->continuation)
  {
    auto continuation = std::exchange(op->continuation, {});
    continuation.resume();
  }
}

inline void udp_send_op_cancel(udp_send_op_t *op)
{
  if (op->completed)
  {
    return;
  }
  op->socket->socket.cancel(op->io);
  op->completed = true;
  op->result = std::unexpected(error_t{.code = vio_cancelled, .msg = "cancelled"});
  if (op->detached)
  {
    delete op;
    return;
  }
  if (op->continuation)
  {
    auto continuation = std::exchange(op->continuation, {});
    continuation.resume();
  }
}
} // namespace detail

// NOLINTNEXTLINE(cppcoreguidelines-special-member-functions)
struct udp_send_awaitable_t
{
  udp_send_op_t *op = nullptr;
  std::expected<void, error_t> immediate;

  explicit udp_send_awaitable_t(udp_send_op_t *operation)
    : op(operation)
  {
  }

  explicit udp_send_awaitable_t(std::expected<void, error_t> result)
    : immediate(std::move(result))
  {
  }

  udp_send_awaitable_t(const udp_send_awaitable_t &) = delete;
  udp_send_awaitable_t &operator=(const udp_send_awaitable_t &) = delete;

  udp_send_awaitable_t(udp_send_awaitable_t &&other) noexcept
    : op(std::exchange(other.op, nullptr))
    , immediate(std::move(other.immediate))
  {
  }

  ~udp_send_awaitable_t()
  {
    if (op != nullptr)
    {
      detail::udp_send_release(op);
    }
  }

  [[nodiscard]] bool await_ready() const noexcept
  {
    return op == nullptr || op->completed;
  }

  void await_suspend(std::coroutine_handle<> continuation) noexcept
  {
    op->continuation = continuation;
  }

  std::expected<void, error_t> await_resume() noexcept
  {
    if (op == nullptr)
    {
      return std::move(immediate);
    }
    auto result = std::move(op->result);
    detail::udp_send_release(op);
    op = nullptr;
    return result;
  }
};

template <typename Bytes>
  requires owned_byte_range<Bytes>
udp_send_awaitable_t send_udp(udp_t &udp, Bytes &&bytes, const sockaddr *addr, cancellation_t *cancel = nullptr)
{
  using payload_t = std::remove_cvref_t<Bytes>;
  using value_t = std::ranges::range_value_t<payload_t>;
  if (cancel != nullptr && cancel->is_cancelled())
  {
    return udp_send_awaitable_t(std::expected<void, error_t>(std::unexpected(error_t{.code = vio_cancelled, .msg = "cancelled"})));
  }
  auto &state = udp.handle.data();
  detail::udp_target_t target;
  if (int result = detail::udp_prepare_target(state, addr, target); result < 0)
  {
    return udp_send_awaitable_t(std::expected<void, error_t>(std::unexpected(make_error(result))));
  }
  const auto view = std::as_bytes(std::span<const value_t>(std::ranges::data(bytes), std::ranges::size(bytes)));
  const auto sent = detail::socket_sendto(state.socket.native(), view, target.address, target.length);
  if (sent != errc::again)
  {
    return udp_send_awaitable_t(detail::udp_send_result(sent));
  }

  auto *op = new udp_send_op_t();
  op->socket = udp.handle;
  auto owned = std::make_unique<owned_payload_impl_t<payload_t>>(std::forward<Bytes>(bytes));
  op->bytes = std::as_bytes(std::span<const value_t>(std::ranges::data(owned->value), std::ranges::size(owned->value)));
  op->payload = std::move(owned);
  op->address_length = target.length;
  if (target.address != nullptr)
  {
    std::memcpy(&op->address, target.address, static_cast<std::size_t>(target.length));
  }
  op->io.owner = op;
  op->io.complete = &detail::udp_send_op_ready;
  state.socket.wait(detail::interest_write, op->io);

  if (cancel != nullptr)
  {
    op->cancel_registration = cancel->register_callback([op]() { detail::udp_send_op_cancel(op); });
  }
  return udp_send_awaitable_t(op);
}

// Synchronous send. Unlike send_udp above there is no operation and no
// reference parked for the duration, so any number of these may be issued back
// to back -- which is what a server talking to many peers from one socket
// needs, and what send_udp explicitly refuses.
//
// A full socket buffer surfaces as an error with code errc::again; that is the
// caller's signal to stop draining and retry later, not a failure.
inline std::expected<std::size_t, error_t> udp_try_send(udp_t &udp, std::span<const uint8_t> bytes, const sockaddr *addr)
{
  auto &state = udp.handle.data();
  detail::udp_target_t target;
  if (int result = detail::udp_prepare_target(state, addr, target); result < 0)
  {
    return std::unexpected(make_error(result));
  }
  const auto sent = detail::socket_sendto(state.socket.native(), std::as_bytes(bytes), target.address, target.length);
  if (sent < 0)
  {
    return std::unexpected(make_error(static_cast<int>(sent)));
  }
  return static_cast<std::size_t>(sent);
}

struct udp_out_datagram_t
{
  std::span<const uint8_t> bytes;
  const sockaddr *addr = nullptr;
};

// Sends up to udp_max_batch_size datagrams in one call, mapping to sendmmsg
// where the platform has it. Returns how many were accepted, which may be
// fewer than requested; the caller resumes from that offset.
inline std::expected<unsigned int, error_t> udp_try_send_batch(udp_t &udp, std::span<const udp_out_datagram_t> datagrams)
{
  if (datagrams.empty())
  {
    return 0u;
  }
  auto &state = udp.handle.data();
  std::size_t count = datagrams.size() < udp_max_batch_size ? datagrams.size() : udp_max_batch_size;
  std::array<detail::udp_target_t, udp_max_batch_size> targets;
  std::array<detail::udp_out_message_t, udp_max_batch_size> messages;
  for (std::size_t i = 0; i < count; ++i)
  {
    if (int result = detail::udp_prepare_target(state, datagrams[i].addr, targets[i]); result < 0)
    {
      if (i == 0)
      {
        return std::unexpected(make_error(result));
      }
      count = i;
      break;
    }
    messages[i].bytes = std::as_bytes(datagrams[i].bytes);
    messages[i].to = targets[i].address;
    messages[i].to_length = targets[i].length;
  }
  const auto sent = detail::udp_send_many(state.socket.native(), messages.data(), count);
  if (sent < 0)
  {
    return std::unexpected(make_error(static_cast<int>(sent)));
  }
  return static_cast<unsigned int>(sent);
}

inline std::expected<native_socket_t, error_t> udp_fileno(udp_t &udp)
{
  if (int result = detail::udp_require_socket(udp.handle.data()); result < 0)
  {
    return std::unexpected(make_error(result));
  }
  return udp.handle->socket.native();
}

// Binds one socket that accepts both IPv6 and IPv4-mapped peers. IPV6_V6ONLY
// is cleared unless udp_bind_flags::ipv6_only is given, so binding [::] is
// enough; hosts without IPv6 fall back to 0.0.0.0.
inline std::expected<void, error_t> udp_bind_dual_stack(udp_t &udp, std::uint16_t port)
{
  sockaddr_in6 any6 = {};
  any6.sin6_family = AF_INET6;
  any6.sin6_port = htons(port);
  if (udp_bind(udp, reinterpret_cast<const sockaddr *>(&any6)).has_value())
  {
    return {};
  }
  sockaddr_in any4 = {};
  any4.sin_family = AF_INET;
  any4.sin_port = htons(port);
  any4.sin_addr.s_addr = htonl(INADDR_ANY);
  return udp_bind(udp, reinterpret_cast<const sockaddr *>(&any4));
}

// Refused once a reader is running, and that refusal is the point: buffers
// already handed out were taken from the old allocator but would be returned
// to the new one. A pool would take a foreign block onto its free list and
// later hand it back as though it were pool-sized, which is a heap overflow
// several datagrams after the mistake.
inline std::expected<void, error_t> udp_set_allocator(udp_t &udp, alloc_cb_t alloc, dealloc_cb_t dealloc, void *user_data)
{
  if (udp.handle->recv.started || udp.handle->recv.active)
  {
    return std::unexpected(error_t{.code = errc::busy, .msg = "the allocator cannot change while a reader is active; set it before udp_create_reader"});
  }
  udp.handle->recv.alloc_buffer_cb = alloc;
  udp.handle->recv.dealloc_buffer_cb = dealloc;
  udp.handle->recv.alloc_cb_data = user_data;
  return {};
}

// The pool must outlive the socket: every datagram still in the receive queue
// holds a pointer to it as its deallocator's user handle.
inline std::expected<void, error_t> udp_use_buffer_pool(udp_t &udp, buffer_pool_t &pool)
{
  return udp_set_allocator(udp, &buffer_pool_t::alloc_cb, &buffer_pool_t::dealloc_cb, &pool);
}

inline void udp_set_recv_queue_limit(udp_t &udp, std::size_t datagrams)
{
  udp.handle->recv.recv_queue_limit = datagrams == 0 ? 1 : datagrams;
}

struct udp_recv_stats_t
{
  std::size_t queued = 0;
  std::uint64_t dropped_datagrams = 0;
  std::uint64_t truncated_datagrams = 0;
  std::uint64_t recv_errors = 0;
};

// Drops and errors are silent by design -- neither should tear a socket down --
// so this is the only way to notice them.
inline udp_recv_stats_t udp_recv_stats(udp_t &udp)
{
  return udp_recv_stats_t{.queued = udp.handle->recv.buffer_queue.size(),
                          .dropped_datagrams = udp.handle->recv.dropped_datagrams,
                          .truncated_datagrams = udp.handle->recv.truncated_datagrams,
                          .recv_errors = udp.handle->recv.recv_errors};
}

namespace detail
{
[[nodiscard]] inline std::span<std::byte> udp_take_spare(udp_recv_state_t &recv)
{
  if (!recv.spare.empty())
  {
    auto buffer = recv.spare.back();
    recv.spare.pop_back();
    return buffer;
  }
  return recv.alloc_buffer_cb(recv.alloc_cb_data, udp_receive_buffer_size);
}

inline void udp_recv_fill(udp_state_t &state)
{
  auto &recv = state.recv;
  const std::size_t limit = recv.recv_queue_limit == 0 ? 1 : recv.recv_queue_limit;
  const std::size_t queued = recv.buffer_queue.size();
  std::size_t budget = queued < limit ? std::min(limit - queued, udp_recv_burst) : 0;
  recv.drained = false;
  const native_socket_t native = state.socket.native();
  std::size_t errors = 0;
  bool probe = false;
  while (budget > 0)
  {
    const std::size_t want = udp_has_recvmmsg && state.use_recvmmsg && !probe ? std::min(budget, udp_recvmmsg_batch) : 1;
    std::array<udp_message_t, udp_recvmmsg_batch> messages;
    std::array<sockaddr_storage, udp_recvmmsg_batch> names;
    std::array<std::span<std::byte>, udp_recvmmsg_batch> buffers;
    std::size_t prepared = 0;
    for (; prepared < want; ++prepared)
    {
      auto buffer = udp_take_spare(recv);
      if (buffer.data() == nullptr || buffer.empty())
      {
        break;
      }
      buffers[prepared] = buffer;
      messages[prepared] = udp_message_t{.data = buffer.data(), .capacity = buffer.size(), .name = &names[prepared]};
    }
    if (prepared == 0)
    {
      recv.buffer_queue.emplace_back(std::unexpected(error_t{.code = errc::no_buffer_space, .msg = "the receive allocator returned no buffer"}));
      return;
    }
    const auto received = udp_receive(native, messages.data(), prepared);
    if (received < 0)
    {
      for (std::size_t i = 0; i < prepared; ++i)
      {
        recv.spare.push_back(buffers[i]);
      }
      if (received == errc::again)
      {
        recv.drained = true;
        recv.drained_known = true;
        recv.drained_epoch = state.socket.watch.epoch;
        return;
      }
      if (udp_is_terminal_receive_error(received))
      {
        recv.buffer_queue.emplace_back(std::unexpected(make_error(static_cast<int>(received))));
        return;
      }
      ++recv.recv_errors;
      if (++errors >= udp_recv_burst)
      {
        return;
      }
      continue;
    }
    const auto count = static_cast<std::size_t>(received);
    for (std::size_t i = 0; i < prepared; ++i)
    {
      if (i >= count)
      {
        recv.spare.push_back(buffers[i]);
        continue;
      }
      const auto &message = messages[i];
      if (message.truncated)
      {
        ++recv.truncated_datagrams;
        recv.spare.push_back(buffers[i]);
        continue;
      }
      udp_datagram_t datagram;
      datagram.data = unique_buf_t(buffers[i], recv.dealloc_buffer_cb, recv.alloc_cb_data);
      datagram.data.resize(message.length);
      if (message.name_length > 0)
      {
        std::memcpy(&datagram.sender_addr, &names[i], std::min(static_cast<std::size_t>(message.name_length), sizeof(sockaddr_storage)));
      }
      recv.buffer_queue.emplace_back(std::move(datagram));
    }
    probe = count < prepared;
    budget -= std::min(budget, count);
  }
}

inline void udp_recv_park(udp_state_t &state);

inline void udp_recv_wake(udp_state_t &state)
{
  auto &recv = state.recv;
  if (!recv.continuation)
  {
    return;
  }
  if (recv.started && !recv.is_cancelled)
  {
    udp_recv_fill(state);
    if (recv.buffer_queue.empty())
    {
      udp_recv_park(state);
      return;
    }
  }
  auto continuation = std::exchange(recv.continuation, {});
  continuation.resume();
}

inline void udp_recv_on_readable(io_op_t *op)
{
  udp_recv_wake(*static_cast<udp_state_t *>(op->owner));
}

inline void udp_recv_on_retry(posted_t *node)
{
  auto owned = ref_ptr_t<udp_state_t>::from_raw(node->owner);
  udp_recv_wake(owned.data());
}

inline void udp_recv_on_discard(posted_t *node)
{
  ref_ptr_t<udp_state_t>::from_raw(node->owner);
}

inline void udp_recv_park(udp_state_t &state)
{
  auto &recv = state.recv;
  if (recv.drained)
  {
    state.socket.wait(interest_read, recv.op);
    return;
  }
  if (recv.retry.queued)
  {
    return;
  }
  recv.retry.owner = ref_retain<udp_state_t>(state.self);
  core(state.event_loop).defer(recv.retry);
}

[[nodiscard]] inline bool udp_recv_try(udp_state_t &state)
{
  auto &recv = state.recv;
  if (!recv.drained)
  {
    return false;
  }
  if (recv.drained_known && state.socket.watch.epoch == recv.drained_epoch)
  {
    return false;
  }
  udp_recv_fill(state);
  return !recv.buffer_queue.empty();
}

inline void udp_recv_stop(udp_state_t &state)
{
  auto &recv = state.recv;
  recv.started = false;
  recv.active = false;
  if (recv.op.parked)
  {
    state.socket.cancel(recv.op);
  }
  udp_return_spares(recv);
}
} // namespace detail

class udp_reader_t
{
public:
  udp_reader_t(const udp_reader_t &) = delete;
  udp_reader_t &operator=(const udp_reader_t &) = delete;

  udp_reader_t(udp_reader_t &&other) noexcept
    : handle(std::move(other.handle))
    , _is_valid(other._is_valid)
  {
    other._is_valid = false;
  }

  udp_reader_t &operator=(udp_reader_t &&other) noexcept
  {
    if (this != &other)
    {
      stop();
      handle = std::move(other.handle);
      _is_valid = other._is_valid;
      other._is_valid = false;
    }
    return *this;
  }

  ~udp_reader_t()
  {
    stop();
  }

  void cancel()
  {
    auto &recv = handle->recv;
    if (recv.is_cancelled)
    {
      return;
    }
    recv.is_cancelled = true;
    detail::udp_recv_stop(handle.data());
    recv.buffer_queue.emplace_back(std::unexpected(error_t{.code = errc::canceled, .msg = "Operation was cancelled"}));
    if (recv.continuation)
    {
      auto continuation = std::exchange(recv.continuation, {});
      continuation.resume();
    }
  }

  [[nodiscard]] bool is_cancelled() const
  {
    return handle->recv.is_cancelled;
  }

  struct awaiter_t
  {
    ref_ptr_t<udp_state_t> state;
    std::coroutine_handle<> waiting = {};
    bool busy = false;

    explicit awaiter_t(ref_ptr_t<udp_state_t> socket)
      : state(std::move(socket))
    {
    }

    awaiter_t(const awaiter_t &) = delete;
    awaiter_t &operator=(const awaiter_t &) = delete;

    ~awaiter_t()
    {
      if (waiting && state->recv.continuation == waiting)
      {
        state->recv.continuation = {};
        if (state->recv.op.parked)
        {
          state->socket.cancel(state->recv.op);
        }
      }
    }

    [[nodiscard]] bool await_ready()
    {
      auto &recv = state->recv;
      if (!recv.buffer_queue.empty() || recv.is_cancelled || !recv.started)
      {
        return true;
      }
      if (recv.continuation)
      {
        busy = true;
        return true;
      }
      return detail::udp_recv_try(state.data());
    }

    void await_suspend(std::coroutine_handle<> h)
    {
      waiting = h;
      state->recv.continuation = h;
      detail::udp_recv_park(state.data());
    }

    std::expected<udp_datagram_t, error_t> await_resume()
    {
      waiting = {};
      if (busy)
      {
        return std::unexpected(error_t{.code = errc::already_in_progress, .msg = "another coroutine is already waiting on this reader"});
      }
      auto &queue = state->recv.buffer_queue;
      if (queue.empty())
      {
        return std::unexpected(error_t{.code = errc::canceled, .msg = "Operation was cancelled"});
      }
      auto result = std::move(queue.front());
      queue.pop_front();
      return result;
    }
  };

  awaiter_t operator co_await()
  {
    return awaiter_t(this->handle);
  }

  ref_ptr_t<udp_state_t> handle;
  friend std::expected<udp_reader_t, error_t> udp_create_reader(udp_t &udp);

private:
  explicit udp_reader_t(const udp_t &udp)
    : handle(udp.handle)
    , _is_valid(true)
  {
  }

  void stop()
  {
    if (!_is_valid || !handle)
    {
      return;
    }
    _is_valid = false;
    if (handle->recv.started)
    {
      detail::udp_recv_stop(handle.data());
      handle->recv.continuation = {};
    }
  }

  bool _is_valid = false;
};

// Drains what has already arrived without suspending, so a read loop can take
// a whole batch per wake-up instead of one datagram per resume. Returns how
// many entries were written; zero means nothing is queued and the caller
// should co_await the reader.
inline std::size_t udp_reader_take_batch(udp_reader_t &reader, std::span<std::expected<udp_datagram_t, error_t>> out)
{
  auto &state = reader.handle.data();
  auto &recv = state.recv;
  if (recv.buffer_queue.empty() && recv.started && !recv.is_cancelled && !recv.continuation)
  {
    if (!recv.drained || !recv.drained_known || state.socket.watch.epoch != recv.drained_epoch)
    {
      detail::udp_recv_fill(state);
    }
  }
  auto &queue = recv.buffer_queue;
  std::size_t taken = 0;
  while (taken < out.size() && !queue.empty())
  {
    out[taken] = std::move(queue.front());
    queue.pop_front();
    ++taken;
  }
  return taken;
}

inline std::expected<udp_reader_t, error_t> udp_create_reader(udp_t &udp)
{
  if (!udp.handle)
  {
    return std::unexpected(error_t{.code = errc::bad_descriptor, .msg = "Can not create a reader for a closed udp socket"});
  }
  auto &state = udp.handle.data();
  auto &recv = state.recv;
  if (recv.active)
  {
    return std::unexpected(error_t{.code = errc::busy, .msg = "Can not create multiple active readers for a udp socket. Destroy other reader, before making a new one."});
  }
  if (state.datagram_reader)
  {
    return std::unexpected(error_t{.code = errc::busy, .msg = "a datagram_reader_t is already reading this socket"});
  }
  if (int result = detail::udp_ensure_socket(state, AF_INET); result < 0)
  {
    return std::unexpected(make_error(result));
  }
  recv.buffer_queue.erase_if([](const std::expected<udp_datagram_t, error_t> &entry) { return !entry.has_value(); });
  recv.active = true;
  recv.started = true;
  recv.is_cancelled = false;
  recv.drained = true;
  recv.drained_known = false;
  recv.continuation = {};
  recv.op.owner = &state;
  recv.op.complete = &detail::udp_recv_on_readable;
  recv.retry.run = &detail::udp_recv_on_retry;
  recv.retry.discard = &detail::udp_recv_on_discard;
  recv.spare.reserve(udp_recvmmsg_batch);
  return udp_reader_t{udp};
}

} // namespace vio
