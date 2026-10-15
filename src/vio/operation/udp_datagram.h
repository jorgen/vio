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
#include "vio/detail/sys_udp.h"
#include "vio/error.h"
#include "vio/event_loop.h"
#include "vio/loop/socket.h"
#include "vio/operation/udp.h"
#include "vio/ref_counted_wrapper.h"

#include <algorithm>
#include <coroutine>
#include <cstdint>
#include <cstring>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace vio
{
struct datagram_t
{
  std::span<std::uint8_t> data;
  const sockaddr *peer = nullptr;
  const sockaddr *local = nullptr;
  udp_ecn_t ecn = udp_ecn_t::not_ect;
  std::size_t segment_size = 0;
  bool truncated = false;

  [[nodiscard]] const sockaddr *sender() const
  {
    return peer;
  }
};

namespace detail
{
// How many datagrams one wakeup will take before yielding. A readable socket
// usually has more than one waiting, and the syscall is the expensive part.
inline constexpr std::size_t datagram_batch = 32;
inline constexpr std::size_t datagram_capacity = 2048;
inline constexpr std::size_t coalesced_batch = 8;
// With receive coalescing the kernel hands back many datagrams as one buffer,
// so the read has to be able to hold them. 64 KiB is the ceiling both Linux
// and Windows work to.
inline constexpr std::size_t coalesced_capacity = 65536;
// Room for the control messages a datagram can carry. Generous: the kernel
// truncates rather than fails, and a truncated control buffer silently loses
// the codepoint.
inline constexpr std::size_t datagram_control_capacity = 192;
inline constexpr std::size_t datagram_error_budget = 32;
inline constexpr std::size_t datagram_smallest_capacity = 512;

struct alignas(16) datagram_control_t
{
  std::byte bytes[datagram_control_capacity];
};

struct datagram_reader_state_t
{
  explicit datagram_reader_state_t(ref_ptr_t<udp_state_t> socket)
    : udp(std::move(socket))
  {
  }

  datagram_reader_state_t(const datagram_reader_state_t &) = delete;
  datagram_reader_state_t &operator=(const datagram_reader_state_t &) = delete;
  datagram_reader_state_t(datagram_reader_state_t &&) = delete;
  datagram_reader_state_t &operator=(datagram_reader_state_t &&) = delete;

  ~datagram_reader_state_t()
  {
    if (arena)
    {
      unpoison_memory(arena.get(), slot_size * slot_count);
    }
  }

  ref_ptr_t<udp_state_t> udp;
  io_op_t op;
  posted_t retry;
  std::coroutine_handle<> continuation;
  std::vector<datagram_t> batch;
  std::size_t cursor = 0;
  std::unique_ptr<std::byte[]> arena;
  std::unique_ptr<sockaddr_storage[]> names;
  std::unique_ptr<sockaddr_storage[]> locals;
  std::unique_ptr<datagram_control_t[]> controls;
  std::unique_ptr<udp_message_t[]> messages;
  std::size_t slot_size = 0;
  std::size_t slot_count = 0;
  std::size_t want_slot_size = datagram_capacity;
  std::size_t want_slot_count = datagram_batch;
  std::size_t base_capacity = datagram_capacity;
  std::size_t coalescing = 0;
  // Calls made and datagrams they carried. The ratio is what receive
  // coalescing changes.
  std::uint64_t reads = 0;
  std::uint64_t datagrams = 0;
  std::uint64_t truncated = 0;
  std::uint64_t errors = 0;
  void *self = nullptr;
  int pending_error = 0;
  std::uint32_t drained_epoch = 0;
  std::uint16_t local_port = 0;
  bool drained = true;
  bool drained_known = false;
  bool cancelled = false;
  bool stopped = false;
  bool want_batch = false;
};

inline void datagram_allocate(datagram_reader_state_t &state)
{
  if (state.arena)
  {
    unpoison_memory(state.arena.get(), state.slot_size * state.slot_count);
  }
  state.arena.reset();
  state.slot_size = state.want_slot_size;
  state.slot_count = state.want_slot_count;
  state.arena = std::make_unique_for_overwrite<std::byte[]>(state.slot_size * state.slot_count);
  state.names = std::make_unique<sockaddr_storage[]>(state.slot_count);
  state.locals = std::make_unique<sockaddr_storage[]>(state.slot_count);
  state.controls = std::make_unique<datagram_control_t[]>(state.slot_count);
  state.messages = std::make_unique<udp_message_t[]>(state.slot_count);
  state.batch.reserve(state.slot_count);
}

inline void datagram_split(datagram_reader_state_t &state, std::size_t slot)
{
  const auto &message = state.messages[slot];
  const auto control = udp_parse_control(message);
  const sockaddr *peer = message.name_length > 0 ? reinterpret_cast<const sockaddr *>(&state.names[slot]) : nullptr;
  const sockaddr *local = nullptr;
  if (control.has_local)
  {
    auto &stored = state.locals[slot];
    stored = control.local;
    if (stored.ss_family == AF_INET)
    {
      reinterpret_cast<sockaddr_in *>(&stored)->sin_port = htons(state.local_port);
    }
    else if (stored.ss_family == AF_INET6)
    {
      reinterpret_cast<sockaddr_in6 *>(&stored)->sin6_port = htons(state.local_port);
    }
    local = reinterpret_cast<const sockaddr *>(&stored);
  }
  const auto ecn = static_cast<udp_ecn_t>(control.ecn & 0x03u);
  auto *base = reinterpret_cast<std::uint8_t *>(state.arena.get() + slot * state.slot_size);
  const std::size_t length = std::min(message.length, state.slot_size);
  if (message.truncated)
  {
    ++state.truncated;
  }
  const std::size_t segment = control.segment_size;
  if (segment == 0 || segment >= length)
  {
    state.batch.push_back(datagram_t{.data = std::span<std::uint8_t>(base, length), .peer = peer, .local = local, .ecn = ecn, .segment_size = 0, .truncated = message.truncated});
    if (!message.truncated)
    {
      ++state.datagrams;
    }
    return;
  }
  // Coalesced: every segment is full-length except the last. They came from
  // one flow, so they share a sender and a codepoint.
  for (std::size_t offset = 0; offset < length; offset += segment)
  {
    const std::size_t piece = std::min(segment, length - offset);
    const bool cut = message.truncated && offset + piece >= length;
    state.batch.push_back(datagram_t{.data = std::span<std::uint8_t>(base + offset, piece), .peer = peer, .local = local, .ecn = ecn, .segment_size = segment, .truncated = cut});
    if (!cut)
    {
      ++state.datagrams;
    }
  }
}

inline void datagram_refill(datagram_reader_state_t &state)
{
  state.batch.clear();
  state.cursor = 0;
  state.drained = false;
  if (!state.arena || state.slot_size != state.want_slot_size || state.slot_count != state.want_slot_count)
  {
    datagram_allocate(state);
  }
  const std::size_t arena_size = state.slot_size * state.slot_count;
  unpoison_memory(state.arena.get(), arena_size);
  for (std::size_t i = 0; i < state.slot_count; ++i)
  {
    state.messages[i] = udp_message_t{.data = state.arena.get() + i * state.slot_size,
                                      .capacity = state.slot_size,
                                      .name = &state.names[i],
                                      .control = state.controls[i].bytes,
                                      .control_capacity = sizeof(state.controls[i].bytes)};
  }
  const native_socket_t native = state.udp->socket.native();
  std::size_t used = 0;
  std::size_t errors = 0;
  while (used < state.slot_count)
  {
    const auto received = udp_receive(native, &state.messages[used], state.slot_count - used);
    if (received < 0)
    {
      if (received == errc::again)
      {
        state.drained = true;
        state.drained_known = true;
        state.drained_epoch = state.udp->socket.watch.epoch;
        break;
      }
      if (udp_is_terminal_receive_error(received))
      {
        state.pending_error = static_cast<int>(received);
        break;
      }
      ++state.errors;
      if (++errors >= datagram_error_budget)
      {
        break;
      }
      continue;
    }
    ++state.reads;
    const auto count = std::min(static_cast<std::size_t>(received), state.slot_count - used);
    for (std::size_t i = used; i < used + count; ++i)
    {
      datagram_split(state, i);
    }
    used += count;
  }
  poison_memory(state.arena.get(), arena_size);
  for (const auto &datagram : state.batch)
  {
    unpoison_memory(datagram.data.data(), datagram.data.size());
  }
}

[[nodiscard]] inline bool datagram_single_available(datagram_reader_state_t &state) noexcept
{
  while (state.cursor < state.batch.size() && state.batch[state.cursor].truncated)
  {
    ++state.cursor;
  }
  return state.cursor < state.batch.size();
}

[[nodiscard]] inline bool datagram_has(datagram_reader_state_t &state, bool want_batch) noexcept
{
  return want_batch ? state.cursor < state.batch.size() : datagram_single_available(state);
}

inline void datagram_park(datagram_reader_state_t &state)
{
  if (state.drained)
  {
    state.udp->socket.wait(interest_read, state.op);
    return;
  }
  if (state.retry.queued)
  {
    return;
  }
  state.retry.owner = ref_retain<datagram_reader_state_t>(state.self);
  core(state.udp->event_loop).defer(state.retry);
}

inline void datagram_wake(datagram_reader_state_t &state)
{
  if (!state.continuation || state.stopped)
  {
    return;
  }
  if (!state.cancelled)
  {
    datagram_refill(state);
    if (!datagram_has(state, state.want_batch) && state.pending_error == 0)
    {
      datagram_park(state);
      return;
    }
  }
  auto continuation = std::exchange(state.continuation, {});
  continuation.resume();
}

inline void datagram_on_readable(io_op_t *op)
{
  datagram_wake(*static_cast<datagram_reader_state_t *>(op->owner));
}

inline void datagram_on_retry(posted_t *node)
{
  auto owned = ref_ptr_t<datagram_reader_state_t>::from_raw(node->owner);
  datagram_wake(owned.data());
}

inline void datagram_on_discard(posted_t *node)
{
  ref_ptr_t<datagram_reader_state_t>::from_raw(node->owner);
}

template <bool Batch>
struct datagram_awaiter_t
{
  using value_t = std::conditional_t<Batch, std::span<const datagram_t>, datagram_t>;

  ref_ptr_t<datagram_reader_state_t> state;
  std::coroutine_handle<> waiting = {};
  bool busy = false;

  explicit datagram_awaiter_t(ref_ptr_t<datagram_reader_state_t> reader)
    : state(std::move(reader))
  {
  }

  datagram_awaiter_t(const datagram_awaiter_t &) = delete;
  datagram_awaiter_t &operator=(const datagram_awaiter_t &) = delete;

  ~datagram_awaiter_t()
  {
    if (!waiting || !state)
    {
      return;
    }
    auto &reader = state.data();
    if (reader.continuation != waiting)
    {
      return;
    }
    reader.continuation = {};
    if (!reader.stopped && reader.op.parked)
    {
      reader.udp->socket.cancel(reader.op);
    }
  }

  [[nodiscard]] bool await_ready()
  {
    if (!state)
    {
      return true;
    }
    auto &reader = state.data();
    if (reader.cancelled || reader.stopped || datagram_has(reader, Batch) || reader.pending_error != 0)
    {
      return true;
    }
    if (reader.continuation)
    {
      busy = true;
      return true;
    }
    if (!reader.drained)
    {
      return false;
    }
    if (reader.drained_known && reader.udp->socket.watch.epoch == reader.drained_epoch)
    {
      return false;
    }
    datagram_refill(reader);
    return datagram_has(reader, Batch) || reader.pending_error != 0;
  }

  void await_suspend(std::coroutine_handle<> continuation)
  {
    auto &reader = state.data();
    waiting = continuation;
    reader.continuation = continuation;
    reader.want_batch = Batch;
    datagram_park(reader);
  }

  std::expected<value_t, error_t> await_resume()
  {
    waiting = {};
    if (busy)
    {
      return std::unexpected(error_t{.code = errc::already_in_progress, .msg = "another coroutine is already waiting on this reader"});
    }
    if (!state)
    {
      return std::unexpected(error_t{.code = errc::invalid_argument, .msg = "reader is not open"});
    }
    auto &reader = state.data();
    if (reader.cancelled || reader.stopped)
    {
      return std::unexpected(error_t{.code = errc::canceled, .msg = "Operation was cancelled"});
    }
    if (datagram_has(reader, Batch))
    {
      if constexpr (Batch)
      {
        std::span<const datagram_t> items(reader.batch.data() + reader.cursor, reader.batch.size() - reader.cursor);
        reader.cursor = reader.batch.size();
        return items;
      }
      else
      {
        return reader.batch[reader.cursor++];
      }
    }
    const int code = std::exchange(reader.pending_error, 0);
    return std::unexpected(make_error(code != 0 ? code : errc::again));
  }
};
} // namespace detail

// An IPv4 destination as a dual-stack socket reports it: ::ffff:a.b.c.d. The
// datagram leaves as IPv4, which decides which options the kernel will read
// for it.
[[nodiscard]] inline bool is_ipv4_mapped(const sockaddr *address)
{
  if (address == nullptr || address->sa_family != AF_INET6)
  {
    return false;
  }
  static constexpr std::uint8_t prefix[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
  const auto *bytes = reinterpret_cast<const std::uint8_t *>(&reinterpret_cast<const sockaddr_in6 *>(address)->sin6_addr);
  return std::memcmp(bytes, prefix, sizeof(prefix)) == 0;
}

namespace detail
{
[[nodiscard]] inline std::expected<std::size_t, error_t> datagram_send(udp_t &udp, std::span<const std::uint8_t> bytes, const sockaddr *address, udp_ecn_t ecn, std::size_t segment_size)
{
  // RFC 3168 forbids an endpoint from setting CE itself -- only a router may --
  // and Windows enforces it with WSAEINVAL. Nothing here should ever ask for it.
  if (ecn == udp_ecn_t::ce)
  {
    return std::unexpected(error_t{.code = errc::invalid_argument, .msg = "only a router may set the congestion experienced codepoint"});
  }
  auto &state = udp.handle.data();
  udp_target_t target;
  if (int result = udp_prepare_target(state, address, target); result < 0)
  {
    return std::unexpected(make_error(result));
  }
  udp_send_options_t options;
  options.ecn = static_cast<std::uint8_t>(ecn);
  options.segment_size = static_cast<std::uint16_t>(segment_size);
  if (ecn != udp_ecn_t::not_ect)
  {
    // Which control message carries the codepoint follows the family the
    // datagram actually leaves as, and one addressed to an IPv4-mapped address
    // leaves as IPv4 however the socket is bound. That path reads IP_TOS;
    // IPV6_TCLASS is accepted there and quietly does nothing, so marking it
    // that way puts the packets on the wire unmarked.
    const sockaddr *leaving = target.address;
    sockaddr_storage peer = {};
    if (leaving == nullptr)
    {
      int length = 0;
      if (socket_peer_name(state.socket.native(), peer, length) == 0)
      {
        leaving = reinterpret_cast<const sockaddr *>(&peer);
      }
    }
    options.ecn_ipv6 = leaving != nullptr && leaving->sa_family == AF_INET6 && !is_ipv4_mapped(leaving);
  }
  const auto sent = udp_send(state.socket.native(), std::as_bytes(bytes), target.address, target.length, options);
  if (sent < 0)
  {
    return std::unexpected(make_error(static_cast<int>(sent)));
  }
  return static_cast<std::size_t>(sent);
}
} // namespace detail

// Sends one datagram with an explicit ECN codepoint.
//
// The codepoint goes in a control message, per datagram, rather than on the
// socket. That is not a stylistic choice: Windows has no socket option for the
// outgoing codepoint at all -- IP_ECN is a control message type there, and
// IP_RECVECN, the only related socket option, governs receiving. Marking per
// datagram is also the better shape, because a socket carrying several
// connections would otherwise have to mark all of them the same way and give
// up ECN for all of them when one path failed validation.
[[nodiscard]] inline std::expected<std::size_t, error_t> send_datagram(udp_t &udp, std::span<const std::uint8_t> bytes, const sockaddr *address, udp_ecn_t ecn)
{
  return detail::datagram_send(udp, bytes, address, ecn, 0);
}

// Sends several datagrams as one buffer, letting the kernel cut it into pieces
// of segment_size on the way out.
//
// This is the send-side offload -- UDP_SEGMENT on Linux, USO on Windows -- and
// it is the change that moves throughput most, because it divides the number of
// system calls per megabyte by however many segments fit in a batch.
//
// The shape it demands: every segment must be exactly segment_size except the
// last, which may be shorter. There is no length list, so that rule is the only
// thing that makes the batch decodable, and a caller that mixes sizes silently
// corrupts the stream rather than failing.
//
// Whether the kernel or the interface actually honours it is not knowable in
// advance; if it refuses, the error comes back and the caller falls back to
// sending one at a time.
[[nodiscard]] inline std::expected<std::size_t, error_t> send_segments(udp_t &udp, std::span<const std::uint8_t> bytes, std::size_t segment_size, const sockaddr *address, udp_ecn_t ecn)
{
  if (segment_size == 0 || bytes.empty())
  {
    return std::size_t{0};
  }
  if (bytes.size() <= segment_size)
  {
    return send_datagram(udp, bytes, address, ecn);
  }
  if (segment_size > 0xffff)
  {
    return std::unexpected(error_t{.code = errc::invalid_argument, .msg = "a segment cannot be larger than a datagram"});
  }
  return detail::datagram_send(udp, bytes, address, ecn, segment_size);
}

class datagram_reader_t
{
public:
  using awaiter_t = detail::datagram_awaiter_t<false>;
  using batch_awaiter_t = detail::datagram_awaiter_t<true>;

  datagram_reader_t(const datagram_reader_t &) = delete;
  datagram_reader_t &operator=(const datagram_reader_t &) = delete;

  datagram_reader_t(datagram_reader_t &&other) noexcept
    : _state(std::move(other._state))
  {
  }

  datagram_reader_t &operator=(datagram_reader_t &&other) noexcept
  {
    if (this != &other)
    {
      stop();
      _state = std::move(other._state);
    }
    return *this;
  }

  ~datagram_reader_t()
  {
    stop();
  }

  [[nodiscard]] static std::expected<datagram_reader_t, error_t> create(event_loop_t &loop, udp_t &udp)
  {
    (void)loop;
    auto fd = udp_fileno(udp);
    if (!fd.has_value())
    {
      return std::unexpected(fd.error());
    }
    auto &socket = udp.handle.data();
    if (socket.recv.active)
    {
      return std::unexpected(error_t{.code = errc::busy, .msg = "a udp_reader_t is already reading this socket"});
    }
    if (socket.datagram_reader)
    {
      return std::unexpected(error_t{.code = errc::busy, .msg = "a datagram_reader_t is already reading this socket"});
    }
#if defined(_WIN32)
    if (detail::udp_wsa_recvmsg(*fd) == nullptr)
    {
      return std::unexpected(error_t{.code = errc::not_supported, .msg = "could not resolve WSARecvMsg"});
    }
#endif
    ref_ptr_t<detail::datagram_reader_state_t> state(udp.handle);
    auto &reader = state.data();
    reader.self = detail::ref_storage(state);
    reader.op.owner = &reader;
    reader.op.complete = &detail::datagram_on_readable;
    reader.retry.run = &detail::datagram_on_retry;
    reader.retry.discard = &detail::datagram_on_discard;
    socket.datagram_reader = true;

    datagram_reader_t created;
    created._state = std::move(state);
    return created;
  }

  // Asks the kernel to hand back several datagrams in one read, coalesced into
  // a single buffer, and to report the segment size so they can be taken apart
  // again. Reading a megabyte then costs a fraction of the system calls.
  //
  // This is a receive-side offload -- UDP_GRO on Linux, URO on Windows -- so
  // whether it does anything depends on the kernel and the interface. Asking
  // for it and being refused is not a failure worth reporting upward; the
  // reads simply arrive one at a time as before.
  [[nodiscard]] std::expected<void, error_t> receive_coalesced(std::size_t max_size)
  {
    if (!_state)
    {
      return std::unexpected(error_t{.code = errc::invalid_argument, .msg = "reader is not open"});
    }
    auto &reader = _state.data();
    const auto native = reader.udp->socket.native();
    if (max_size == 0)
    {
      if (reader.coalescing != 0)
      {
        (void)detail::udp_set_receive_coalesced(native, 0);
      }
      reader.coalescing = 0;
      reader.want_slot_size = reader.base_capacity;
      reader.want_slot_count = detail::datagram_batch;
      return {};
    }
    const std::size_t value = std::min(max_size, detail::coalesced_capacity);
    if (const int result = detail::udp_set_receive_coalesced(native, value); result < 0)
    {
      return std::unexpected(error_t{.code = result, .msg = "the socket would not coalesce receives"});
    }
    reader.coalescing = value;
#if defined(_WIN32)
    reader.want_slot_size = value + reader.base_capacity;
#else
    reader.want_slot_size = std::max(detail::coalesced_capacity, reader.base_capacity);
#endif
    reader.want_slot_count = detail::coalesced_batch;
    return {};
  }

  [[nodiscard]] std::expected<void, error_t> receive_datagram_size(std::size_t max_size)
  {
    if (!_state)
    {
      return std::unexpected(error_t{.code = errc::invalid_argument, .msg = "reader is not open"});
    }
    if (max_size < detail::datagram_smallest_capacity || max_size > detail::coalesced_capacity)
    {
      return std::unexpected(error_t{.code = errc::invalid_argument, .msg = "a datagram buffer must hold between 512 bytes and 64 KiB"});
    }
    auto &reader = _state.data();
    reader.base_capacity = max_size;
    if (reader.coalescing == 0)
    {
      reader.want_slot_size = max_size;
    }
    return {};
  }

  // Asks the kernel to report the ECN codepoint of arriving datagrams. Without
  // this the control message never appears and every datagram reads as not_ect.
  [[nodiscard]] std::expected<void, error_t> receive_ecn(bool on)
  {
    if (!_state)
    {
      return std::unexpected(error_t{.code = errc::invalid_argument, .msg = "reader is not open"});
    }
    if (const int result = detail::udp_set_receive_ecn(_state.data().udp->socket.native(), on); result < 0)
    {
      return std::unexpected(error_t{.code = result, .msg = "could not ask for the ECN codepoint"});
    }
    return {};
  }

  [[nodiscard]] std::expected<void, error_t> receive_local_address(bool on)
  {
    if (!_state)
    {
      return std::unexpected(error_t{.code = errc::invalid_argument, .msg = "reader is not open"});
    }
    auto &reader = _state.data();
    const auto native = reader.udp->socket.native();
    if (on)
    {
      sockaddr_storage name = {};
      int length = 0;
      if (const int result = detail::socket_name(native, name, length); result < 0)
      {
        return std::unexpected(make_error(result));
      }
      reader.local_port = name.ss_family == AF_INET6 ? ntohs(reinterpret_cast<const sockaddr_in6 *>(&name)->sin6_port) : ntohs(reinterpret_cast<const sockaddr_in *>(&name)->sin_port);
    }
    if (const int result = detail::udp_set_receive_local_address(native, on); result < 0)
    {
      return std::unexpected(error_t{.code = result, .msg = "could not ask for the local address"});
    }
    return {};
  }

  // The next datagram already in hand, without suspending. One wakeup usually
  // pulls a run of them off the socket, and a caller that wants to answer them
  // together has to be able to see the whole run first.
  [[nodiscard]] std::optional<std::expected<datagram_t, error_t>> try_next()
  {
    if (!_state)
    {
      return std::nullopt;
    }
    auto &reader = _state.data();
    if (reader.cancelled || reader.stopped || !detail::datagram_single_available(reader))
    {
      return std::nullopt;
    }
    return std::expected<datagram_t, error_t>(reader.batch[reader.cursor++]);
  }

  [[nodiscard]] std::uint64_t reads() const
  {
    return _state ? _state.data().reads : 0;
  }

  [[nodiscard]] std::uint64_t datagrams() const
  {
    return _state ? _state.data().datagrams : 0;
  }

  [[nodiscard]] std::uint64_t truncated() const
  {
    return _state ? _state.data().truncated : 0;
  }

  [[nodiscard]] std::uint64_t errors() const
  {
    return _state ? _state.data().errors : 0;
  }

  void cancel()
  {
    if (!_state)
    {
      return;
    }
    auto &reader = _state.data();
    if (reader.cancelled)
    {
      return;
    }
    reader.cancelled = true;
    if (!reader.continuation)
    {
      return;
    }
    if (reader.op.parked)
    {
      reader.udp->socket.cancel(reader.op);
    }
    auto continuation = std::exchange(reader.continuation, {});
    continuation.resume();
  }

  awaiter_t operator co_await()
  {
    return awaiter_t(_state);
  }

  batch_awaiter_t receive()
  {
    return batch_awaiter_t(_state);
  }

private:
  datagram_reader_t() = default;

  void stop()
  {
    if (!_state)
    {
      return;
    }
    auto state = std::move(_state);
    auto &reader = state.data();
    if (reader.stopped)
    {
      return;
    }
    reader.stopped = true;
    reader.continuation = {};
    if (reader.op.parked)
    {
      reader.udp->socket.cancel(reader.op);
    }
    reader.udp->datagram_reader = false;
    reader.udp.release();
  }

  ref_ptr_t<detail::datagram_reader_state_t> _state = ref_ptr_t<detail::datagram_reader_state_t>::null();
};
} // namespace vio
