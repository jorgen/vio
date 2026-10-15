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

#include "vio/quic/endpoint.h"

#include "vio/crypto.h"
#include "vio/errc.h"
#include "vio/loop/loop_core.h"
#include "vio/operation/udp_datagram.h"
#include "vio/quic/packet.h"
#include "vio/quic/stateless_reset.h"

#include <algorithm>
#include <array>
#include <cstring>

namespace vio::quic
{
namespace
{
// The largest datagram this endpoint will read or write. Section 14 sets the
// floor at 1200; going much above the common path MTU only invites
// fragmentation.
constexpr std::size_t max_datagram = 1500;

// How often the timer wakes when no connection has asked for anything sooner.
// QUIC's own timers are in the tens of milliseconds at their tightest, so this
// is fine enough not to be the thing that delays them.
constexpr std::chrono::milliseconds timer_granularity{2};

// How many datagrams one batch may carry. Linux caps a segmented send at 64
// pieces, which is also comfortably more than a single flush usually produces.
constexpr int max_batch_datagrams = 64;

// A segmented send is one message to the kernel, so the whole batch has to fit
// what a UDP datagram may hold. Sixty-four segments of the usual size is past
// that and the kernel answers EMSGSIZE, so the batch is bounded by bytes as
// well as by count.
constexpr std::size_t max_batch_bytes = 65535;

// What one coalesced read may hold. Large enough that a burst arrives in a
// single call, small enough to stay a sensible allocation per endpoint.
constexpr std::size_t coalesced_receive_size = 64 * 1024;

// The address as bytes, for the two places that need to compare or authenticate
// one: section 9.3 asks whether the peer has moved, and section 8.1.4 binds a
// Retry token to the address it was issued to. Only equality and opacity are
// required of the encoding, so this is the smallest thing that carries the
// whole address.
struct address_key_t
{
  std::array<std::uint8_t, 1 + 16 + 2> bytes = {};
  std::size_t size = 0;

  [[nodiscard]] std::span<const std::uint8_t> view() const
  {
    return {bytes.data(), size};
  }
};

[[nodiscard]] address_key_t address_key(const sockaddr *address)
{
  address_key_t out;
  if (address == nullptr)
  {
    return out;
  }
  if (address->sa_family == AF_INET)
  {
    const auto *in4 = reinterpret_cast<const sockaddr_in *>(address);
    out.size = 1 + 4 + 2;
    out.bytes[0] = 4;
    std::memcpy(out.bytes.data() + 1, &in4->sin_addr, 4);
    std::memcpy(out.bytes.data() + 5, &in4->sin_port, 2);
    return out;
  }
  if (address->sa_family == AF_INET6)
  {
    const auto *in6 = reinterpret_cast<const sockaddr_in6 *>(address);
    out.size = 1 + 16 + 2;
    out.bytes[0] = 6;
    std::memcpy(out.bytes.data() + 1, &in6->sin6_addr, 16);
    std::memcpy(out.bytes.data() + 17, &in6->sin6_port, 2);
    return out;
  }
  return out;
}

[[nodiscard]] const sockaddr *unmap_ipv4(const sockaddr *address, sockaddr_in &storage)
{
  if (!is_ipv4_mapped(address))
  {
    return address;
  }
  const auto *in6 = reinterpret_cast<const sockaddr_in6 *>(address);
  storage = {};
  storage.sin_family = AF_INET;
  storage.sin_port = in6->sin6_port;
  std::memcpy(&storage.sin_addr, reinterpret_cast<const std::uint8_t *>(&in6->sin6_addr) + 12, 4);
  return reinterpret_cast<const sockaddr *>(&storage);
}

[[nodiscard]] std::vector<std::uint8_t> address_bytes(const sockaddr *address)
{
  const auto key = address_key(address);
  return {key.bytes.begin(), key.bytes.begin() + static_cast<std::ptrdiff_t>(key.size)};
}

// The inverse of address_bytes, for the one caller that is handed an address as
// bytes rather than as a sockaddr: a PATH_RESPONSE the connection says must go
// to a path it is not on.
[[nodiscard]] bool address_from_bytes(std::span<const std::uint8_t> bytes, sockaddr_storage &out)
{
  std::memset(&out, 0, sizeof(out));
  if (bytes.size() == 1 + 4 + 2 && bytes[0] == 4)
  {
    auto *in4 = reinterpret_cast<sockaddr_in *>(&out);
    in4->sin_family = AF_INET;
    std::memcpy(&in4->sin_addr, bytes.data() + 1, 4);
    std::memcpy(&in4->sin_port, bytes.data() + 5, 2);
    return true;
  }
  if (bytes.size() == 1 + 16 + 2 && bytes[0] == 6)
  {
    auto *in6 = reinterpret_cast<sockaddr_in6 *>(&out);
    in6->sin6_family = AF_INET6;
    std::memcpy(&in6->sin6_addr, bytes.data() + 1, 16);
    std::memcpy(&in6->sin6_port, bytes.data() + 17, 2);
    return true;
  }
  return false;
}

// Section 8.1.3: the same address with the port left off. A NEW_TOKEN token is
// meant to be redeemed on a later connection, and the client's port will
// almost certainly have changed by then, so binding one to the port would make
// it unredeemable.
[[nodiscard]] std::vector<std::uint8_t> host_address_bytes(const sockaddr *address)
{
  auto out = address_bytes(address);
  if (out.size() >= 2)
  {
    out.resize(out.size() - 2);
  }
  return out;
}
} // namespace

namespace detail
{
struct connection_entry_t
{
  // What a connection_handle_t names. Never reused, so a handle to a collected
  // connection resolves to nothing rather than to whatever took its place.
  std::uint64_t id = 0;
  std::unique_ptr<connection_t> connection;
  sockaddr_storage peer = {};
  std::vector<std::uint8_t> peer_bytes;
  // Every connection ID this entry is reachable by, so they can be withdrawn
  // from the routing table together when it goes.
  std::vector<connection_id_t> routed;
  bool draining = false;
  tick_t draining_since;
  bool announced = false;
};

struct held_run_t
{
  std::size_t size = 0;
  std::size_t segment = 0;
  sockaddr_storage peer = {};
  ecn_codepoint_t ecn = ecn_codepoint_t::not_ect;
};

void endpoint_tick(::vio::detail::timer_node_t *node);
void endpoint_writable(::vio::detail::io_op_t *op);

struct endpoint_impl_t
{
  endpoint_impl_t(event_loop_t &event_loop, const tls_context_t *answering, const tls_context_t *dialling, endpoint_config_t configuration, udp_t socket)
    : loop(event_loop)
    , server_context(answering)
    , client_context(dialling)
    , config(std::move(configuration))
    , udp(std::move(socket))
  {
    ticker.owner = this;
    ticker.fire = &endpoint_tick;
    ticker.keeps_alive = false;
    writable.owner = this;
    writable.complete = &endpoint_writable;
  }

  endpoint_impl_t(const endpoint_impl_t &) = delete;
  endpoint_impl_t &operator=(const endpoint_impl_t &) = delete;

  ~endpoint_impl_t()
  {
    ::vio::detail::core(loop).remove_timer(ticker);
    if (writable.parked)
    {
      udp.handle->socket.cancel(writable);
    }
  }

  event_loop_t &loop;
  // A tls_context_t is built for one role -- it chooses TLS_server_method or
  // TLS_client_method and gates the ticket and early-data machinery on that --
  // so an endpoint that both answers and dials needs one of each. Which of
  // them is present is what decides what this endpoint can do; neither is
  // owned, and both must outlive it.
  const tls_context_t *server_context = nullptr;
  const tls_context_t *client_context = nullptr;
  endpoint_config_t config;
  udp_t udp;
  // flush_entry hands control to the application, which endpoint.h invites to
  // call connect() or flush() from there. Both mutate `connections` -- one by
  // push_back, which reallocates, the other by reap, which erases -- so the
  // walks below iterate by index and reaping is deferred until the outermost
  // one has finished. Without this the iteration cursor is left dangling into
  // freed storage and the next step writes through it.
  int walking = 0;

  std::vector<std::unique_ptr<connection_entry_t>> connections;
  std::unordered_map<connection_id_t, connection_entry_t *> by_id;
  std::unordered_map<std::uint64_t, connection_entry_t *> by_handle;
  // The identity an application actually has: the callbacks hand out a
  // connection_t and never a handle, so this is what lets one connection be
  // flushed without walking every connection the endpoint holds.
  std::unordered_map<const connection_t *, connection_entry_t *> by_connection;
  std::uint64_t next_connection_id = 1;
  connection_ready_t on_connection;
  connection_active_t on_activity;
  connection_ready_t on_connection_gone;
  bool running = false;
  // One buffer for the whole endpoint, grown once and reused: a batch is built
  // by polling datagrams straight into it rather than copying them in.
  std::vector<std::uint8_t> batch;
  // Whether the send-side offload is worth attempting.
  bool segmenting = false;
  ::vio::detail::timer_node_t ticker;
  ::vio::detail::io_op_t writable;
  std::vector<std::uint8_t> held;
  std::vector<held_run_t> held_runs;
  bool blocked = false;
  endpoint_stats_t stats;
  // Section 10.3.3 suggests a ceiling on stateless resets. The reason is not
  // amplification -- every reset is smaller than the packet that drew it -- but
  // work: each one costs an HMAC and a draw from the random pool, so without a
  // limit a stream of spoofed short-header datagrams buys an attacker that
  // much of this endpoint's CPU per packet they send.
  std::size_t reset_allowance = 0;
  tick_t reset_allowance_refilled;
  bool reset_allowance_started = false;
};
} // namespace detail

using detail::connection_entry_t;
using detail::endpoint_impl_t;
using detail::held_run_t;

namespace
{
void route_by(endpoint_impl_t &impl, connection_entry_t &entry, const connection_id_t &id)
{
  if (id.empty() || std::find(entry.routed.begin(), entry.routed.end(), id) != entry.routed.end())
  {
    return;
  }
  // A route another connection already holds is left where it is. Overwriting
  // it would silently steal every datagram addressed to that connection, and
  // the theft outlives the thief: reap withdraws the ids in entry.routed, so
  // whichever of the two is collected first takes the route away from the
  // other.
  if (const auto existing = impl.by_id.find(id); existing != impl.by_id.end() && existing->second != &entry)
  {
    return;
  }
  entry.routed.push_back(id);
  impl.by_id[id] = &entry;
}

void index_connection(endpoint_impl_t &impl, connection_entry_t &entry)
{
  const auto issued = entry.connection->issued_connection_ids();
  for (const auto &id : issued)
  {
    route_by(impl, entry, id);
  }

  // Section 7.2: a client goes on addressing the connection ID it invented
  // until it has seen the server's choice and switched. Routing only on what
  // this endpoint issued would leave every retransmit of that first Initial
  // unmatched, and each one would be read as a new connection. The value is
  // not known until the first Initial has been processed, so this runs on
  // every flush rather than once at accept.
  //
  // Only for a connection this endpoint answered. On one it dialled, the same
  // field holds the id this endpoint invented to address the peer, which the
  // peer never sends back -- and that id is in plaintext in every Initial that
  // went out, so routing on it lets anyone who saw one steer a datagram to a
  // connection that cannot authenticate them. On an endpoint that also
  // answers, that is an inbound handshake refused rather than accepted.
  connection_id_t original;
  if (entry.connection->role() == tls_role_t::server)
  {
    original = entry.connection->original_destination_id();
  }
  route_by(impl, entry, original);

  // Section 5.1.1: an id the peer has retired is one this endpoint no longer
  // answers to, so it comes out of the table. Leaving it in would keep a
  // rotating connection's every past id routable for the life of the
  // connection -- the table would only ever grow, and a datagram addressed to
  // a withdrawn id would be delivered instead of drawing a stateless reset.
  const auto still_routed = [&](const connection_id_t &id)
  { return (!original.empty() && id == original) || std::find(issued.begin(), issued.end(), id) != issued.end(); };

  for (auto it = entry.routed.begin(); it != entry.routed.end();)
  {
    if (still_routed(*it))
    {
      ++it;
      continue;
    }
    impl.by_id.erase(*it);
    it = entry.routed.erase(it);
  }
}

// An endpoint that was never bound gets its socket here. The family has to
// match the peer it is about to be used for: a socket bound to 0.0.0.0 cannot
// send to an IPv6 address at all, so a client dialling one has to say which it
// needs rather than take the default and fail.
void ensure_socket(endpoint_impl_t &impl, int family = AF_INET)
{
  if (udp_fileno(impl.udp).has_value())
  {
    return;
  }
  if (family == AF_INET6)
  {
    sockaddr_in6 any = {};
    any.sin6_family = AF_INET6;
    if (udp_bind(impl.udp, reinterpret_cast<const sockaddr *>(&any)).has_value())
    {
      return;
    }
  }
  sockaddr_in any = {};
  any.sin_family = AF_INET;
  any.sin_addr.s_addr = htonl(INADDR_ANY);
  (void)udp_bind(impl.udp, reinterpret_cast<const sockaddr *>(&any));
}

[[nodiscard]] connection_entry_t *find_connection(endpoint_impl_t &impl, std::span<const std::uint8_t> datagram)
{
  const auto invariant = parse_invariant_header(datagram);
  if (!invariant.has_value())
  {
    return nullptr;
  }

  // A long header states the length; a short header does not, so the only way
  // to find the field is to know how long this endpoint makes them. That is
  // why section 5.1 fixes the length for the life of the endpoint.
  std::span<const std::uint8_t> destination = invariant->destination_id;
  if (!invariant->long_header)
  {
    const auto length = impl.config.connection.local_connection_id_length;
    if (datagram.size() < 1 + length)
    {
      return nullptr;
    }
    destination = datagram.subspan(1, length);
  }

  auto id = connection_id_t::from_bytes(destination);
  if (!id.has_value())
  {
    return nullptr;
  }
  const auto found = impl.by_id.find(*id);
  return found == impl.by_id.end() ? nullptr : found->second;
}

[[nodiscard]] bool version_supported(const endpoint_impl_t &impl, std::uint32_t version)
{
  return std::find(impl.config.supported_versions.begin(), impl.config.supported_versions.end(), version) != impl.config.supported_versions.end();
}

#if defined(VIO_INTERNAL_TESTS)
using send_fault_t = int (*)(std::size_t datagrams);
send_fault_t send_fault = nullptr;

[[nodiscard]] int injected_outcome(std::size_t datagrams)
{
  return send_fault != nullptr ? send_fault(datagrams) : 0;
}
#endif

enum class send_failure_t
{
  blocked,
  refused,
  other,
};

[[nodiscard]] send_failure_t classify_send_failure(int code)
{
  switch (code)
  {
  case errc::again:
  case errc::no_buffer_space:
  case errc::interrupted:
    return send_failure_t::blocked;
  case errc::not_supported:
  case errc::io_error:
  case errc::invalid_argument:
  case errc::no_protocol_option:
  case errc::protocol_not_supported:
  case errc::not_implemented:
  case errc::unknown:
    return send_failure_t::refused;
  default:
    return send_failure_t::other;
  }
}

[[nodiscard]] std::size_t address_size(const sockaddr *address)
{
  return address->sa_family == AF_INET6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in);
}

// The codepoint travels with the datagram rather than sitting on the socket,
// so two connections on one port can disagree about ECN -- one still marking,
// one that has given up on its path -- without either affecting the other.
[[nodiscard]] int send_one(endpoint_impl_t &impl, std::span<const std::uint8_t> bytes, const sockaddr *address, ecn_codepoint_t ecn)
{
#if defined(VIO_INTERNAL_TESTS)
  if (const int injected = injected_outcome(1); injected != 0)
  {
    return injected < 0 ? injected : 0;
  }
#endif
  if (ecn == ecn_codepoint_t::not_ect)
  {
    const auto sent = udp_try_send(impl.udp, bytes, address);
    return sent.has_value() ? 0 : sent.error().code;
  }
  const auto sent = send_datagram(impl.udp, bytes, address, static_cast<udp_ecn_t>(ecn));
  return sent.has_value() ? 0 : sent.error().code;
}

[[nodiscard]] int send_segmented(endpoint_impl_t &impl, std::span<const std::uint8_t> bytes, std::size_t segment, std::size_t count, const sockaddr *address, ecn_codepoint_t ecn)
{
#if defined(VIO_INTERNAL_TESTS)
  if (const int injected = injected_outcome(count); injected != 0)
  {
    return injected < 0 ? injected : 0;
  }
#else
  (void)count;
#endif
  const auto sent = send_segments(impl.udp, bytes, segment, address, static_cast<udp_ecn_t>(ecn));
  return sent.has_value() ? 0 : sent.error().code;
}

void send_to(endpoint_impl_t &impl, std::span<const std::uint8_t> bytes, const sockaddr *address, ecn_codepoint_t ecn = ecn_codepoint_t::not_ect)
{
  // A datagram that cannot be handed to the socket is dropped rather than
  // retried: QUIC treats loss as ordinary, and every path here has a
  // retransmission behind it.
  (void)send_one(impl, bytes, address, ecn);
}

[[nodiscard]] std::size_t transmit(endpoint_impl_t &impl, std::span<const std::uint8_t> bytes, std::size_t segment, const sockaddr *address, ecn_codepoint_t ecn)
{
  const std::size_t count = (bytes.size() + segment - 1) / segment;
  if (count > 1 && impl.segmenting)
  {
    const int code = send_segmented(impl, bytes, segment, count, address, ecn);
    if (code == 0)
    {
      ++impl.stats.sends;
      impl.stats.datagrams_sent += count;
      return bytes.size();
    }
    // A batch too large for one message says nothing about whether the offload
    // works, and abandoning it for the life of the endpoint over one is how a
    // connection ends up making a system call per packet for everything after
    // its window first grew.
    const auto failure = classify_send_failure(code);
    if (failure == send_failure_t::blocked)
    {
      return 0;
    }
    if (failure == send_failure_t::refused)
    {
      impl.segmenting = false;
    }
  }

  for (std::size_t offset = 0; offset < bytes.size(); offset += segment)
  {
    const std::size_t piece = (std::min)(segment, bytes.size() - offset);
    if (const int code = send_one(impl, bytes.subspan(offset, piece), address, ecn); code < 0 && classify_send_failure(code) == send_failure_t::blocked)
    {
      return offset;
    }
    ++impl.stats.sends;
    ++impl.stats.datagrams_sent;
  }
  return bytes.size();
}

void wait_writable(endpoint_impl_t &impl)
{
  auto &socket = impl.udp.handle->socket;
  if (impl.writable.parked || !socket.is_open())
  {
    return;
  }
  socket.wait(::vio::detail::interest_write, impl.writable);
}

void hold(endpoint_impl_t &impl, std::span<const std::uint8_t> bytes, std::size_t segment, const sockaddr *address, ecn_codepoint_t ecn)
{
  held_run_t run;
  run.size = bytes.size();
  run.segment = segment;
  run.ecn = ecn;
  std::memcpy(&run.peer, address, address_size(address));
  impl.held.insert(impl.held.end(), bytes.begin(), bytes.end());
  impl.held_runs.push_back(run);
  impl.blocked = true;
  wait_writable(impl);
}

void send_or_hold(endpoint_impl_t &impl, std::span<const std::uint8_t> bytes, std::size_t segment, const sockaddr *address, ecn_codepoint_t ecn)
{
  if (bytes.empty() || segment == 0)
  {
    return;
  }
  const std::size_t sent = impl.blocked ? 0 : transmit(impl, bytes, segment, address, ecn);
  if (sent < bytes.size())
  {
    hold(impl, bytes.subspan(sent), segment, address, ecn);
  }
}

[[nodiscard]] bool release_held(endpoint_impl_t &impl)
{
  if (!impl.blocked)
  {
    return true;
  }
  impl.blocked = false;
  std::size_t offset = 0;
  std::size_t index = 0;
  for (; index < impl.held_runs.size(); ++index)
  {
    auto &run = impl.held_runs[index];
    const std::span<const std::uint8_t> bytes(impl.held.data() + offset, run.size);
    const std::size_t sent = transmit(impl, bytes, run.segment, reinterpret_cast<const sockaddr *>(&run.peer), run.ecn);
    offset += sent;
    if (sent < run.size)
    {
      run.size -= sent;
      break;
    }
  }
  if (index == impl.held_runs.size())
  {
    impl.held.clear();
    impl.held_runs.clear();
    if (impl.writable.parked)
    {
      impl.udp.handle->socket.cancel(impl.writable);
    }
    return true;
  }
  impl.held.erase(impl.held.begin(), impl.held.begin() + static_cast<std::ptrdiff_t>(offset));
  impl.held_runs.erase(impl.held_runs.begin(), impl.held_runs.begin() + static_cast<std::ptrdiff_t>(index));
  impl.blocked = true;
  wait_writable(impl);
  return false;
}

// Section 6.1. Built entirely from the packet that arrived, so a server can
// answer a version it does not speak without allocating anything for it.
void send_version_negotiation(endpoint_impl_t &impl, const invariant_header_t &invariant, const sockaddr *address)
{
  auto destination = connection_id_t::from_bytes(invariant.source_id);
  auto source = connection_id_t::from_bytes(invariant.destination_id);
  if (!destination.has_value() || !source.has_value())
  {
    return;
  }
  std::array<std::uint8_t, max_datagram> out = {};
  const auto size = build_version_negotiation(out, *destination, *source, impl.config.supported_versions);
  if (size > 0)
  {
    send_to(impl, std::span<const std::uint8_t>(out).first(size), address);
  }
}

// Section 10.3. The reply to a datagram for a connection this endpoint has no
// memory of. It is only useful once the peer holds a token, which means only
// after a handshake got far enough for one to have been sent, so a long header
// -- which in this version only appears during the handshake -- is left alone.
// Refilled once a second rather than continuously: a reset is a rare answer to
// a genuine loss of state, so a modest steady allowance is generous for the
// real case and stingy for a flood.
constexpr std::size_t stateless_resets_per_second = 64;

[[nodiscard]] bool allow_stateless_reset(endpoint_impl_t &impl, tick_t now)
{
  if (!impl.reset_allowance_started || now - impl.reset_allowance_refilled >= std::chrono::seconds(1))
  {
    impl.reset_allowance = stateless_resets_per_second;
    impl.reset_allowance_refilled = now;
    impl.reset_allowance_started = true;
  }
  if (impl.reset_allowance == 0)
  {
    return false;
  }
  --impl.reset_allowance;
  return true;
}

void send_stateless_reset(endpoint_impl_t &impl, std::span<const std::uint8_t> datagram, const sockaddr *address, tick_t now)
{
  if (impl.config.stateless_reset_key == nullptr)
  {
    return;
  }
  // Everything that decides whether a reset is possible at all comes before
  // the allowance is spent. A long header names its own connection ID length,
  // so it never needs a reset and never gets one -- but charging the allowance
  // first meant every one of them burned one of the sixty-four this endpoint
  // has each second, and a flood drained the budget that exists to protect the
  // short-header packets a reset can actually answer.
  const auto invariant = parse_invariant_header(datagram);
  if (!invariant.has_value() || invariant->long_header)
  {
    return;
  }
  const auto length = impl.config.connection.local_connection_id_length;
  if (length == 0 || datagram.size() < 1 + length)
  {
    return;
  }
  auto id = connection_id_t::from_bytes(datagram.subspan(1, length));
  if (!id.has_value())
  {
    return;
  }

  // Spent here, where the next thing done is the HMAC it exists to ration.
  if (!allow_stateless_reset(impl, now))
  {
    return;
  }
  const auto token = impl.config.stateless_reset_key->token_for(*id);
  std::array<std::uint8_t, max_datagram> out = {};
  auto size = build_stateless_reset(out, token, datagram.size());
  if (!size.has_value() || *size == 0)
  {
    return;
  }
  send_to(impl, std::span<const std::uint8_t>(out).first(*size), address);
}

// The Initial header, token included, without committing to anything. The
// endpoint needs the token before it decides whether this datagram is worth a
// connection at all.
[[nodiscard]] std::optional<packet_header_t> peek_initial(const endpoint_impl_t &impl, std::span<const std::uint8_t> datagram)
{
  packet_reader_t reader(datagram, impl.config.connection.local_connection_id_length);
  auto next = reader.next();
  if (!next.has_value() || !next->has_value())
  {
    return std::nullopt;
  }
  const auto header = next->value();
  if (header.kind != packet_kind_t::initial)
  {
    return std::nullopt;
  }
  return header;
}

// Whether this Initial's token proves the address, cheaply and without building
// anything. Both kinds are accepted: a Retry token, bound to the full address,
// and a NEW_TOKEN token from an earlier connection, bound to the address without
// its port. The endpoint has to ask this itself -- branching on whether a token
// is merely *present* means one junk byte skips the stateless Retry entirely and
// buys a connection, a TLS session and three key schedules, which is exactly the
// cost the Retry exists to avoid.
[[nodiscard]] bool token_proves_address(const endpoint_impl_t &impl, const packet_header_t &header, const sockaddr *address, tick_t now)
{
  if (header.token.empty())
  {
    return false;
  }
  const auto full = address_bytes(address);
  if (!full.empty())
  {
    auto retry = impl.config.retry_key->validate(header.token, full, now);
    if (retry.has_value() && retry->kind == address_token_kind_t::retry)
    {
      return true;
    }
  }
  const auto host = host_address_bytes(address);
  if (!host.empty())
  {
    auto reused = impl.config.retry_key->validate(header.token, host, now, new_token_lifetime);
    if (reused.has_value() && reused->kind == address_token_kind_t::new_token)
    {
      return true;
    }
  }
  return false;
}

// Section 8.1.2, done the way the section intends: without building anything.
//
// A Retry exists so that a server need not spend state on an address that has
// not been proven. Answering from inside a connection object would defeat it --
// the connection, its TLS session and its key schedules would already have been
// allocated by the time the Retry went out, and a flood of Initials with
// spoofed source addresses would cost exactly as much as if there were no Retry
// at all. So this is built from the packet that arrived and nothing else, and
// the state that would have held the exchange together is instead sealed into
// the token: the connection ID the client first chose, which section 7.3 makes
// the server echo back so the client can tell the Retry was genuine.
void send_retry(endpoint_impl_t &impl, const packet_header_t &header, const sockaddr *address, tick_t now)
{
  // The connection ID the client is told to use from here on. It is invented
  // now and never remembered; the client returns it as the Destination
  // Connection ID of its next Initial, and that is where it comes back from.
  std::array<std::uint8_t, max_connection_id_size> chosen = {};
  auto bytes = std::span<std::uint8_t>(chosen).first(impl.config.connection.local_connection_id_length);
  if (!bytes.empty() && !crypto::random_bytes(bytes).has_value())
  {
    return;
  }
  auto source = connection_id_t::from_bytes(bytes);
  if (!source.has_value())
  {
    return;
  }

  auto token = impl.config.retry_key->issue(header.destination_id, address_bytes(address), now);
  if (!token.has_value())
  {
    return;
  }

  std::array<std::uint8_t, max_datagram> out = {};
  const std::size_t head = serialize_retry(out, header.version, header.source_id, *source, *token);
  if (head == 0 || out.size() < head + retry_integrity_tag_size)
  {
    return;
  }
  // Section 5.8 of RFC 9001: the tag is what proves this came from someone who
  // saw the client's Initial, rather than anyone who can write a packet.
  auto tag = retry_integrity_tag(header.destination_id.bytes(), std::span<const std::uint8_t>(out).first(head), header.version);
  if (!tag.has_value())
  {
    return;
  }
  std::copy(tag->begin(), tag->end(), out.begin() + static_cast<std::ptrdiff_t>(head));
  send_to(impl, std::span<const std::uint8_t>(out).first(head + retry_integrity_tag_size), address);
}

// Named for the connection ID the client first chose, which is the one
// identifier both ends agree on before anything else is settled -- so a trace
// from each side of the same connection can be found and loaded together.
void attach_qlog(endpoint_impl_t &impl, connection_t &connection, const connection_id_t &odcid, bool server, tick_t reference)
{
  if (impl.config.qlog_directory.empty())
  {
    return;
  }
  std::string path = impl.config.qlog_directory;
  if (!path.empty() && path.back() != '/' && path.back() != '\\')
  {
    path.push_back('/');
  }
  static constexpr char digits[] = "0123456789abcdef";
  for (const auto byte : odcid.bytes())
  {
    path.push_back(digits[byte >> 4]);
    path.push_back(digits[byte & 0x0f]);
  }
  path.append(server ? ".server.qlog" : ".client.qlog");
  connection.set_qlog(qlog_writer_t::create(path, server ? "server" : "client", odcid.bytes(), reference));
}

[[nodiscard]] connection_entry_t *accept_connection(endpoint_impl_t &impl, std::span<const std::uint8_t> datagram, const sockaddr *address, const packet_header_t &header, tick_t now)
{
  // Having something to answer with is what makes an endpoint answerable. An
  // endpoint that only dials drops an arriving Initial here rather than
  // building a connection it has no certificate to finish.
  if (impl.server_context == nullptr)
  {
    return nullptr;
  }
  if (impl.config.max_connections != 0 && impl.connections.size() >= impl.config.max_connections)
  {
    return nullptr;
  }

  // Section 14.1: a datagram carrying an Initial is at least 1200 bytes. A
  // smaller one cannot be a genuine connection attempt, and accepting it would
  // let a tiny packet buy a whole connection's worth of state.
  if (datagram.size() < 1200)
  {
    return nullptr;
  }

  auto config = impl.config.connection;
  // Written here rather than taken from the template, because one endpoint may
  // now hold connections of both roles and the template cannot be right for
  // both. The same is done on the dialling side.
  config.role = tls_role_t::server;
  if (impl.config.retry_key != nullptr && !header.token.empty())
  {
    // This Initial is the answer to a Retry this endpoint sent and kept no
    // record of. The connection ID it is addressed to is the one that Retry
    // named, and section 7.3 has the handshake echo that exact value back, so
    // the connection has to adopt it rather than invent its own.
    config.local_connection_id_override = header.destination_id;
  }
  config.retry_key = impl.config.retry_key;
  config.stateless_reset_key = impl.config.stateless_reset_key;
  config.peer_address = address_bytes(address);
  config.peer_host_address = host_address_bytes(address);
  config.ecn = impl.config.ecn ? ecn_codepoint_t::ect0 : ecn_codepoint_t::not_ect;

  auto created = connection_t::create(*impl.server_context, config);
  if (!created.has_value())
  {
    return nullptr;
  }

  auto entry = std::make_unique<connection_entry_t>();
  entry->id = impl.next_connection_id++;
  entry->connection = std::make_unique<connection_t>(std::move(*created));
  attach_qlog(impl, *entry->connection, header.destination_id, true, now);
  entry->peer_bytes = config.peer_address;
  std::memcpy(&entry->peer, address, address->sa_family == AF_INET6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in));

  auto *raw = entry.get();
  impl.connections.push_back(std::move(entry));
  impl.by_handle[raw->id] = raw;
  impl.by_connection[raw->connection.get()] = raw;
  index_connection(impl, *raw);
  return raw;
}

// Hands the batch to the kernel as one send when there is more than one
// datagram in it, and as an ordinary send otherwise.
void flush_batch(endpoint_impl_t &impl, connection_entry_t &entry, std::size_t used, std::size_t segment, std::size_t count)
{
  if (used == 0 || count == 0)
  {
    return;
  }
  const auto *address = reinterpret_cast<const sockaddr *>(&entry.peer);
  send_or_hold(impl, std::span<const std::uint8_t>(impl.batch.data(), used), segment, address, entry.connection->ecn_sending());
}

void flush_entry(endpoint_impl_t &impl, connection_entry_t &entry, tick_t now)
{
  // Datagrams are polled straight into one buffer so that a run of them can
  // leave in a single call. Segmentation has one rule -- every piece the same
  // size except the last -- so a batch ends as soon as a datagram breaks it.
  // QUIC obliges more often than it looks: a sender with data to send fills
  // packets to the datagram size, and the short one is the tail of the burst.
  std::size_t used = 0;
  std::size_t segment = 0;
  std::size_t count = 0;

  for (int guard = 0; guard < max_batch_datagrams; ++guard)
  {
    // Stop short of what a segmented send can carry, rather than finding out
    // from the kernel.
    if (used != 0 && used + max_datagram > max_batch_bytes)
    {
      flush_batch(impl, entry, used, segment, count);
      used = 0;
      segment = 0;
      count = 0;
    }
    if (impl.blocked)
    {
      break;
    }
    if (impl.batch.size() < used + max_datagram)
    {
      impl.batch.resize(used + max_datagram);
    }
    std::vector<std::uint8_t> destination;
    auto size = entry.connection->poll_send(std::span<std::uint8_t>(impl.batch).subspan(used, max_datagram), now, &destination);
    if (!size.has_value() || *size == 0)
    {
      break;
    }

    if (!destination.empty())
    {
      // Section 8.2.2: an echo owed to a path this connection is not on. It
      // cannot join the batch, which is addressed to the peer, so whatever is
      // held goes first and this leaves on its own.
      //
      // Not ECN-marked and not counted against the path's congestion state: it
      // is an obligation to an address that has proven nothing yet, and it is
      // the one datagram here that is not part of the connection's own flow.
      // Where poll_send actually wrote it, which is past whatever the batch is
      // still holding -- and flush_batch below does not move those bytes.
      const std::size_t at = used;
      flush_batch(impl, entry, used, segment, count);
      used = 0;
      segment = 0;
      count = 0;
      sockaddr_storage probe = {};
      if (address_from_bytes(destination, probe))
      {
        send_or_hold(impl, std::span<const std::uint8_t>(impl.batch).subspan(at, *size), *size, reinterpret_cast<const sockaddr *>(&probe), ecn_codepoint_t::not_ect);
      }
      continue;
    }

    if (count == 0)
    {
      segment = *size;
    }
    else if (*size > segment)
    {
      // Longer than the batch's segment size cannot ride in it at all: send
      // what is held and start again from this one.
      flush_batch(impl, entry, used, segment, count);
      std::copy(impl.batch.begin() + static_cast<std::ptrdiff_t>(used), impl.batch.begin() + static_cast<std::ptrdiff_t>(used + *size), impl.batch.begin());
      used = 0;
      segment = *size;
      count = 0;
    }

    const bool closes_batch = *size < segment;
    used += *size;
    ++count;
    if (closes_batch)
    {
      // A short datagram is only ever the last piece.
      flush_batch(impl, entry, used, segment, count);
      used = 0;
      segment = 0;
      count = 0;
    }
  }
  flush_batch(impl, entry, used, segment, count);

  // Connection IDs are issued as the connection runs, and each one is another
  // way for a datagram to reach it.
  index_connection(impl, entry);

  if (!entry.announced && entry.connection->handshake_complete() && impl.on_connection)
  {
    entry.announced = true;
    impl.on_connection(*entry.connection);
  }

  if (!entry.draining && entry.connection->state() == connection_state_t::closed)
  {
    // Section 10.2: the connection is over but its connection IDs stay live
    // for a while, so a packet still in flight meets silence rather than a
    // stateless reset for a connection that closed politely.
    entry.draining = true;
    entry.draining_since = now;
    // Told here rather than at reap, which runs a whole draining period later
    // -- three seconds by default. Reporting an ending three seconds after it
    // happened is not reporting it. The connection is still alive at this
    // point, so close_reason(), reset_by_peer() and
    // version_negotiation_failed() are all still readable from the handler.
    if (impl.on_connection_gone)
    {
      impl.on_connection_gone(*entry.connection);
    }
  }
}

void reap(endpoint_impl_t &impl, tick_t now)
{
  if (impl.walking > 0)
  {
    // A nested call, from an application callback inside a walk. Erasing now
    // would dangle the walk's cursor; the walk reaps as soon as it unwinds, so
    // nothing is lost by declining here.
    return;
  }
  for (auto it = impl.connections.begin(); it != impl.connections.end();)
  {
    auto &entry = **it;
    if (!entry.draining || now - entry.draining_since < impl.config.draining_period)
    {
      ++it;
      continue;
    }
    for (const auto &id : entry.routed)
    {
      impl.by_id.erase(id);
    }
    impl.by_handle.erase(entry.id);
    impl.by_connection.erase(entry.connection.get());
    it = impl.connections.erase(it);
  }
}

void flush_all(endpoint_impl_t &impl)
{
  const auto now = loop_now(impl.loop);
  ++impl.walking;
  for (std::size_t index = 0; index < impl.connections.size(); ++index)
  {
    flush_entry(impl, *impl.connections[index], now);
  }
  --impl.walking;
  reap(impl, now);
}

void arm_ticker(endpoint_impl_t &impl)
{
  const auto delay = std::chrono::duration_cast<std::chrono::nanoseconds>(timer_granularity).count();
  ::vio::detail::core(impl.loop).add_timer(impl.ticker, ::vio::detail::loop_core_t::now() + delay);
}

void disarm_ticker(endpoint_impl_t &impl)
{
  ::vio::detail::core(impl.loop).remove_timer(impl.ticker);
}
} // namespace

namespace detail
{
void endpoint_tick(::vio::detail::timer_node_t *node)
{
  auto &impl = *static_cast<endpoint_impl_t *>(node->owner);
  if (!impl.running)
  {
    return;
  }
  (void)release_held(impl);
  flush_all(impl);
  if (impl.running)
  {
    arm_ticker(impl);
  }
}

void endpoint_writable(::vio::detail::io_op_t *op)
{
  auto &impl = *static_cast<endpoint_impl_t *>(op->owner);
  if (release_held(impl))
  {
    flush_all(impl);
  }
}
} // namespace detail

endpoint_t::~endpoint_t() = default;
endpoint_t::endpoint_t(endpoint_t &&) noexcept = default;
endpoint_t &endpoint_t::operator=(endpoint_t &&) noexcept = default;

std::expected<endpoint_t, error_t> endpoint_t::create(event_loop_t &loop, const tls_context_t &context, const endpoint_config_t &config)
{
  // The context already knows what it was built for, so an endpoint given one
  // of them can answer or dial but not both -- and which it is needs saying
  // once here rather than being stated again on connection_config_t::role and
  // trusted to agree.
  const auto answering = context.role() == tls_role_t::server;
  return create(loop, answering ? &context : nullptr, answering ? nullptr : &context, config);
}

std::expected<endpoint_t, error_t> endpoint_t::create(event_loop_t &loop, const tls_context_t *server_context, const tls_context_t *client_context, const endpoint_config_t &config)
{
  if (server_context == nullptr && client_context == nullptr)
  {
    return std::unexpected(error_t{.code = -1, .msg = "a QUIC endpoint needs a TLS context to answer with, to dial with, or both"});
  }
  if (server_context != nullptr && server_context->role() != tls_role_t::server)
  {
    return std::unexpected(error_t{.code = -1, .msg = "the answering context was built for a client"});
  }
  if (client_context != nullptr && client_context->role() != tls_role_t::client)
  {
    return std::unexpected(error_t{.code = -1, .msg = "the dialling context was built for a server"});
  }

  auto socket = udp_create(loop);
  if (!socket.has_value())
  {
    return std::unexpected(socket.error());
  }
  endpoint_t endpoint;
  endpoint._impl = std::make_unique<endpoint_impl_t>(loop, server_context, client_context, config, std::move(*socket));
  return endpoint;
}

std::expected<void, error_t> endpoint_t::bind(const sockaddr *address)
{
  return udp_bind(_impl->udp, address);
}

std::expected<std::uint16_t, error_t> endpoint_t::local_port() const
{
  auto name = udp_sockname(_impl->udp);
  if (!name.has_value())
  {
    return std::unexpected(name.error());
  }
  if (name->ss_family == AF_INET6)
  {
    return ntohs(reinterpret_cast<const sockaddr_in6 *>(&*name)->sin6_port);
  }
  return ntohs(reinterpret_cast<const sockaddr_in *>(&*name)->sin_port);
}

void endpoint_t::on_connection(connection_ready_t handler)
{
  _impl->on_connection = std::move(handler);
}

void endpoint_t::on_activity(connection_active_t handler)
{
  _impl->on_activity = std::move(handler);
}

void endpoint_t::on_connection_gone(connection_ready_t handler)
{
  _impl->on_connection_gone = std::move(handler);
}

std::expected<connection_handle_t, error_t> endpoint_t::connect(const sockaddr *address, std::string_view server_name, std::span<const std::uint8_t> resumption_ticket)
{
  auto &impl = *_impl;
  // Before ensure_socket, which binds. An endpoint with nothing to dial with
  // must not acquire a socket -- and on an unbound one that call would pin the
  // address family as well, so a refused dial would decide what a later bind
  // could be.
  if (impl.client_context == nullptr)
  {
    return std::unexpected(error_t{.code = -1, .msg = "this endpoint has no TLS context to dial with"});
  }
  // Before ensure_socket for the same reason the check above is: a dial that
  // cannot happen must not decide the socket's address family.
  //
  // The family is checked and not just the pointer, because everything below
  // reads through this address on the strength of it -- address_bytes switches
  // on the family, and the memcpy into the entry copies sizeof(sockaddr_in6) or
  // sizeof(sockaddr_in) accordingly. A null address dereferenced here, and
  // anything that was neither family read the wrong number of bytes.
  if (address == nullptr || (address->sa_family != AF_INET && address->sa_family != AF_INET6))
  {
    return std::unexpected(error_t{.code = -1, .msg = "connect needs an IPv4 or IPv6 address"});
  }
  ensure_socket(impl, address->sa_family);
  sockaddr_in unmapped = {};
  const auto *peer = unmap_ipv4(address, unmapped);
  auto config = impl.config.connection;
  config.role = tls_role_t::client;
  config.stateless_reset_key = impl.config.stateless_reset_key;
  config.peer_address = address_bytes(peer);
  config.peer_host_address = host_address_bytes(peer);
  config.ecn = impl.config.ecn ? ecn_codepoint_t::ect0 : ecn_codepoint_t::not_ect;
  if (!resumption_ticket.empty())
  {
    config.resumption_ticket.assign(resumption_ticket.begin(), resumption_ticket.end());
  }

  auto created = connection_t::create(*impl.client_context, config, server_name);
  if (!created.has_value())
  {
    return std::unexpected(created.error());
  }

  auto entry = std::make_unique<connection_entry_t>();
  entry->id = impl.next_connection_id++;
  entry->connection = std::make_unique<connection_t>(std::move(*created));
  attach_qlog(impl, *entry->connection, entry->connection->original_destination_id(), false, loop_now(impl.loop));
  entry->peer_bytes = config.peer_address;
  std::memcpy(&entry->peer, peer, address_size(peer));

  auto *raw = entry.get();
  impl.connections.push_back(std::move(entry));
  impl.by_handle[raw->id] = raw;
  impl.by_connection[raw->connection.get()] = raw;
  index_connection(impl, *raw);
  flush_entry(impl, *raw, loop_now(impl.loop));
  return connection_handle_t(raw->id);
}

connection_t *endpoint_t::connection(connection_handle_t handle)
{
  const auto found = _impl->by_handle.find(handle._id);
  return found == _impl->by_handle.end() ? nullptr : found->second->connection.get();
}

std::expected<void, error_t> endpoint_t::flush()
{
  flush_all(*_impl);
  return {};
}

std::expected<void, error_t> endpoint_t::flush(connection_t &connection)
{
  auto &impl = *_impl;
  const auto found = impl.by_connection.find(&connection);
  if (found == impl.by_connection.end())
  {
    return std::unexpected(error_t{.code = -1, .msg = "that connection does not belong to this endpoint"});
  }
  const auto now = loop_now(impl.loop);
  ++impl.walking;
  flush_entry(impl, *found->second, now);
  --impl.walking;
  reap(impl, now);
  return {};
}

std::size_t endpoint_t::connection_count() const
{
  return _impl->connections.size();
}

endpoint_stats_t endpoint_t::stats() const
{
  return _impl->stats;
}

task_t<void> endpoint_t::run(cancellation_t *cancel)
{
  auto &impl = *_impl;
  ensure_socket(impl);
  auto reader = datagram_reader_t::create(impl.loop, impl.udp);
  if (!reader.has_value())
  {
    co_return;
  }
  if (impl.config.ecn)
  {
    (void)reader->receive_ecn(true);
  }
  if (impl.config.offload)
  {
    // Both directions are attempts. Either may be refused, and neither refusal
    // is worth reporting: the endpoint just does one datagram per call.
    (void)reader->receive_coalesced(coalesced_receive_size);
    impl.segmenting = true;
  }
  impl.running = true;

  // QUIC's deadlines have to fire whether or not a datagram ever arrives --
  // loss detection and the idle timeout are both about the absence of traffic.
  //
  // A fixed 2 ms tick rather than the earliest deadline the connections
  // report, which was tried and reverted. next_timeout is not complete enough
  // to drive this: a closed connection keeps reporting the past deadline that
  // closed it, because poll_send returns early and never clears it, and a
  // connection that simply has something to send reports no deadline at all.
  // Arming on the first spins the loop; arming on the second stalls it. The
  // tick papers over both by flushing unconditionally, and making it
  // deadline-driven means fixing what next_timeout reports first.
  arm_ticker(impl);

  // Cancelling has to reach the read as well, or run() stays parked on a
  // socket that will never speak again.
  registration_t stop_reading;
  if (cancel != nullptr)
  {
    stop_reading = cancel->register_callback([reader = &*reader]() { reader->cancel(); });
    if (cancel->is_cancelled())
    {
      reader->cancel();
    }
  }

  // Datagrams that arrived together are answered together. One wakeup usually
  // pulls a run of them off the socket, and replying to each in turn would
  // leave every reply its own system call -- which is exactly the cost the
  // send-side offload exists to remove, given something to batch.
  std::vector<connection_entry_t *> touched;
  for (;;)
  {
    auto received = co_await reader->receive();
    if (!received.has_value())
    {
      break;
    }
    if (cancel != nullptr && cancel->is_cancelled())
    {
      break;
    }
    impl.stats.reads = reader->reads();
    impl.stats.datagrams_received = reader->datagrams();
    touched.clear();

    for (const datagram_t &datagram : *received)
    {
    if (datagram.truncated || datagram.sender() == nullptr)
    {
      continue;
    }
    sockaddr_in unmapped = {};
    const auto *sender = unmap_ipv4(datagram.sender(), unmapped);
    std::span<std::uint8_t> bytes(datagram.data);
    const auto arriving_ecn = static_cast<ecn_codepoint_t>(datagram.ecn);
    const auto now = loop_now(impl.loop);

    auto *entry = find_connection(impl, bytes);
    if (entry == nullptr)
    {
      const auto invariant = parse_invariant_header(bytes);
      if (invariant.has_value() && invariant->long_header && !version_supported(impl, invariant->version))
      {
        // Section 6.1, and only for a long header: a short header carries no
        // version, so there is nothing to negotiate about.
        //
        // Two things this must not do. A Version Negotiation packet carries
        // version zero, which is a version no endpoint supports, so answering
        // one produces a reply that is itself a trigger -- section 6.1 forbids
        // it outright, and without the test two endpoints pointed at each other
        // never stop. And a datagram too small to have been a real connection
        // attempt gets no answer at all, for the reason section 14.1 gives
        // about Initials: a reply larger than what arrived is an amplifier
        // pointed at whoever the source address really belongs to.
        // And only from an endpoint that answers at all. Version Negotiation is
        // a server's reply to a client proposing a version it does not speak;
        // one that only dials has no connection to offer and should be silent
        // rather than answer for a service it does not run.
        if (impl.server_context != nullptr && invariant->version != quic_version_negotiation && bytes.size() >= smallest_maximum_datagram_size)
        {
          send_version_negotiation(impl, *invariant, sender);
        }
        continue;
      }
      // Only an Initial starts a connection. Anything else addressed to a
      // connection ID this endpoint does not know is late, misrouted, or an
      // attempt to make it allocate for a handshake that will never happen.
      const auto initial = peek_initial(impl, bytes);
      if (!initial.has_value())
      {
        send_stateless_reset(impl, bytes, sender, now);
        continue;
      }

      if (impl.server_context != nullptr && impl.config.retry_key != nullptr && !token_proves_address(impl, *initial, sender, now))
      {
        // Section 8.1.2: nothing has proved this address is real, so it is
        // answered without building anything. Whatever comes back carries the
        // token, and only then is a connection worth the memory.
        send_retry(impl, *initial, sender, now);
        continue;
      }

      entry = accept_connection(impl, bytes, sender, *initial, now);
      if (entry == nullptr)
      {
        send_stateless_reset(impl, bytes, sender, now);
        continue;
      }
    }

    const auto peer_key = address_key(sender);
    const auto peer = peer_key.view();
    const bool fresh = entry->routed.empty() || entry->connection->original_destination_id().empty();
    // Only a rise across this one datagram means the connection accepted a
    // move. The running total does not: it stays above zero for the rest of
    // the connection, so testing it would redirect on any later datagram from
    // any address -- including one the connection itself refused, such as a
    // replay it had already seen or a packet carrying nothing but probing
    // frames. That is a way to steer a server away from the real peer.
    const auto migrations_before = entry->connection->migration_count();
    if (!entry->connection->receive(bytes, now, peer, arriving_ecn).has_value())
    {
      // The connection has decided it cannot continue. It still gets to send
      // whatever it wanted to say about that, with the rest of this batch.
      if (std::find(touched.begin(), touched.end(), entry) == touched.end())
      {
        touched.push_back(entry);
      }
      continue;
    }
    if (entry->connection->migration_count() != migrations_before)
    {
      // Section 9.3: the connection accepted the move, so replies go to the
      // new address from here on.
      entry->peer_bytes.assign(peer.begin(), peer.end());
      std::memcpy(&entry->peer, sender, address_size(sender));
    }
    if (fresh)
    {
      index_connection(impl, *entry);
    }
    if (std::find(touched.begin(), touched.end(), entry) == touched.end())
    {
      touched.push_back(entry);
    }
    }

    // Both walks below hold raw pointers into entries the connection vector
    // owns, and the handler is invited to call back in -- flush() reaps, and
    // reaping erases. Marking the walk is what defers that until the pointers
    // are no longer needed; without it a handler that flushes frees the
    // entries this loop is about to write through.
    ++impl.walking;

    // Before the flush, so anything the application writes in response goes
    // out with the reply rather than waiting for the next wakeup.
    if (impl.on_activity)
    {
      for (auto *entry : touched)
      {
        impl.on_activity(*entry->connection);
      }
    }

    const auto now = loop_now(impl.loop);
    for (auto *entry : touched)
    {
      flush_entry(impl, *entry, now);
    }
    --impl.walking;
    reap(impl, now);
  }

  impl.running = false;
  disarm_ticker(impl);
  co_return;
}
} // namespace vio::quic

#if defined(VIO_INTERNAL_TESTS)
#include <doctest/doctest.h>

#include <chrono>
#include <optional>
#include <thread>

#include "vio/operation/sleep.h"
#include "vio/ssl_backend.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace vio::quic
{
namespace
{
struct send_plan_t
{
  int code = 0;
  int failures = 0;
  int pass_first = 0;
  int every = 0;
  bool simulate = true;
  int calls = 0;
};

send_plan_t send_plan;

int planned_send(std::size_t)
{
  ++send_plan.calls;
  const int pass = send_plan.simulate ? 1 : 0;
  if (send_plan.every > 0)
  {
    return send_plan.calls % send_plan.every == 0 ? send_plan.code : pass;
  }
  if (send_plan.pass_first > 0)
  {
    --send_plan.pass_first;
    return pass;
  }
  if (send_plan.failures > 0)
  {
    --send_plan.failures;
    return send_plan.code;
  }
  return pass;
}

class planned_sends_t
{
public:
  explicit planned_sends_t(send_plan_t plan)
  {
    send_plan = plan;
    send_fault = &planned_send;
  }
  ~planned_sends_t()
  {
    send_fault = nullptr;
    send_plan = {};
  }
  planned_sends_t(const planned_sends_t &) = delete;
  planned_sends_t &operator=(const planned_sends_t &) = delete;
};

sockaddr_in loopback_address(std::uint16_t port = 0)
{
  sockaddr_in address = {};
  address.sin_family = AF_INET;
  address.sin_port = htons(port);
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  return address;
}

std::vector<std::uint8_t> numbered_datagrams(std::size_t count, std::size_t size)
{
  std::vector<std::uint8_t> out(count * size);
  for (std::size_t i = 0; i < count; ++i)
  {
    std::fill_n(out.begin() + static_cast<std::ptrdiff_t>(i * size), size, static_cast<std::uint8_t>(i + 1));
  }
  return out;
}

class send_fixture_t
{
public:
  explicit send_fixture_t(event_loop_t &loop)
    : impl(loop, nullptr, nullptr, endpoint_config_t{}, std::move(*udp_create(loop)))
    , receiver(std::move(*udp_create(loop)))
  {
    const auto any = loopback_address();
    REQUIRE(udp_bind(impl.udp, reinterpret_cast<const sockaddr *>(&any)).has_value());
    REQUIRE(udp_bind(receiver, reinterpret_cast<const sockaddr *>(&any)).has_value());
    const auto name = udp_sockname(receiver);
    REQUIRE(name.has_value());
    std::memcpy(&target, &*name, sizeof(target));
    impl.segmenting = true;
  }

  [[nodiscard]] const sockaddr *to() const
  {
    return reinterpret_cast<const sockaddr *>(&target);
  }

  std::vector<std::uint8_t> receive(std::size_t expected)
  {
    std::vector<std::uint8_t> out;
    const auto native = udp_fileno(receiver);
    REQUIRE(native.has_value());
    std::vector<std::byte> buffer(4096);
    std::size_t datagrams = 0;
    for (int attempt = 0; attempt < 2000 && datagrams < expected; ++attempt)
    {
      sockaddr_storage from = {};
      int length = sizeof(from);
      const auto got = ::vio::detail::socket_recvfrom(*native, buffer, &from, &length);
      if (got < 0)
      {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        continue;
      }
      ++datagrams;
      const auto *first = reinterpret_cast<const std::uint8_t *>(buffer.data());
      out.insert(out.end(), first, first + got);
    }
    return out;
  }

  endpoint_impl_t impl;
  udp_t receiver;
  sockaddr_in target = {};
};

struct identity_t
{
  std::vector<std::uint8_t> certificate_pem;
  std::vector<std::uint8_t> private_key_pem;
};

std::vector<std::uint8_t> drain_bio(BIO *bio)
{
  std::vector<std::uint8_t> out(static_cast<std::size_t>(BIO_pending(bio)));
  if (!out.empty())
  {
    BIO_read(bio, out.data(), static_cast<int>(out.size()));
  }
  return out;
}

identity_t make_identity()
{
  EVP_PKEY *key = nullptr;
  EVP_PKEY_CTX *key_context = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
  EVP_PKEY_keygen_init(key_context);
  EVP_PKEY_CTX_set_ec_paramgen_curve_nid(key_context, NID_X9_62_prime256v1);
  EVP_PKEY_keygen(key_context, &key);
  EVP_PKEY_CTX_free(key_context);

  X509 *certificate = X509_new();
  X509_set_version(certificate, 2);
  ASN1_INTEGER_set(X509_get_serialNumber(certificate), 1);
  X509_gmtime_adj(X509_getm_notBefore(certificate), 0);
  X509_gmtime_adj(X509_getm_notAfter(certificate), 31536000L);
  X509_set_pubkey(certificate, key);
  X509_NAME *name = X509_get_subject_name(certificate);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char *>("localhost"), -1, -1, 0);
  X509_set_issuer_name(certificate, name);
  X509_EXTENSION *basic = X509V3_EXT_nconf_nid(nullptr, nullptr, NID_basic_constraints, "critical,CA:TRUE");
  X509_add_ext(certificate, basic, -1);
  X509_EXTENSION_free(basic);
  X509_EXTENSION *san = X509V3_EXT_nconf_nid(nullptr, nullptr, NID_subject_alt_name, "DNS:localhost");
  X509_add_ext(certificate, san, -1);
  X509_EXTENSION_free(san);
  X509_sign(certificate, key, EVP_sha256());

  BIO *certificate_bio = BIO_new(BIO_s_mem());
  BIO *key_bio = BIO_new(BIO_s_mem());
  PEM_write_bio_X509(certificate_bio, certificate);
  PEM_write_bio_PrivateKey(key_bio, key, nullptr, nullptr, 0, nullptr, nullptr);
  identity_t out{.certificate_pem = drain_bio(certificate_bio), .private_key_pem = drain_bio(key_bio)};
  BIO_free(certificate_bio);
  BIO_free(key_bio);
  X509_free(certificate);
  EVP_PKEY_free(key);
  return out;
}
} // namespace

TEST_SUITE("quic endpoint send path")
{
TEST_CASE("a full socket buffer holds a segmented batch and leaves segmentation on")
{
  for (const int code : {errc::again, errc::no_buffer_space})
  {
    CAPTURE(code);
    event_loop_t loop;
    {
      send_fixture_t fixture(loop);
      const auto payload = numbered_datagrams(4, 1200);
      {
        planned_sends_t plan(send_plan_t{.code = code, .failures = 1});
        send_or_hold(fixture.impl, payload, 1200, fixture.to(), ecn_codepoint_t::not_ect);
        CHECK(send_plan.calls == 1);
      }
      CHECK(fixture.impl.blocked);
      CHECK(fixture.impl.segmenting);
      CHECK(fixture.impl.held.size() == payload.size());
      CHECK(fixture.impl.held_runs.size() == 1);
      CHECK(fixture.impl.writable.parked);
      CHECK(fixture.impl.stats.sends == 0);

      {
        planned_sends_t plan(send_plan_t{});
        CHECK(release_held(fixture.impl));
        CHECK(send_plan.calls == 1);
      }
      CHECK_FALSE(fixture.impl.blocked);
      CHECK_FALSE(fixture.impl.writable.parked);
      CHECK(fixture.impl.held.empty());
      CHECK(fixture.impl.held_runs.empty());
      CHECK(fixture.impl.segmenting);
      CHECK(fixture.impl.stats.sends == 1);
      CHECK(fixture.impl.stats.datagrams_sent == 4);
    }
    loop.stop();
    loop.run();
  }
}

TEST_CASE("a batch too large for one message goes out one datagram at a time and keeps segmentation")
{
  event_loop_t loop;
  {
    send_fixture_t fixture(loop);
    const auto payload = numbered_datagrams(4, 1200);
    planned_sends_t plan(send_plan_t{.code = errc::message_too_long, .failures = 1});
    send_or_hold(fixture.impl, payload, 1200, fixture.to(), ecn_codepoint_t::not_ect);
    CHECK(send_plan.calls == 5);
    CHECK_FALSE(fixture.impl.blocked);
    CHECK(fixture.impl.segmenting);
    CHECK(fixture.impl.stats.sends == 4);
    CHECK(fixture.impl.stats.datagrams_sent == 4);
  }
  loop.stop();
  loop.run();
}

TEST_CASE("an offload the kernel refuses is turned off for good")
{
  for (const int code : {errc::not_supported, errc::io_error, errc::invalid_argument})
  {
    CAPTURE(code);
    event_loop_t loop;
    {
      send_fixture_t fixture(loop);
      const auto payload = numbered_datagrams(3, 1000);
      planned_sends_t plan(send_plan_t{.code = code, .failures = 1});
      send_or_hold(fixture.impl, payload, 1000, fixture.to(), ecn_codepoint_t::not_ect);
      CHECK_FALSE(fixture.impl.segmenting);
      CHECK_FALSE(fixture.impl.blocked);
      CHECK(fixture.impl.stats.sends == 3);

      send_plan.calls = 0;
      send_or_hold(fixture.impl, payload, 1000, fixture.to(), ecn_codepoint_t::not_ect);
      CHECK(send_plan.calls == 3);
      CHECK(fixture.impl.stats.sends == 6);
    }
    loop.stop();
    loop.run();
  }
}

TEST_CASE("a route error drops the datagram without touching segmentation")
{
  event_loop_t loop;
  {
    send_fixture_t fixture(loop);
    const auto payload = numbered_datagrams(2, 1000);
    planned_sends_t plan(send_plan_t{.code = errc::network_unreachable, .failures = 3});
    send_or_hold(fixture.impl, payload, 1000, fixture.to(), ecn_codepoint_t::not_ect);
    CHECK(fixture.impl.segmenting);
    CHECK_FALSE(fixture.impl.blocked);
    CHECK(fixture.impl.held.empty());
  }
  loop.stop();
  loop.run();
}

TEST_CASE("a full buffer part way through single sends holds the rest, in order")
{
  event_loop_t loop;
  {
    send_fixture_t fixture(loop);
    fixture.impl.segmenting = false;
    const auto payload = numbered_datagrams(4, 1100);
    {
      planned_sends_t plan(send_plan_t{.code = errc::again, .failures = 1, .pass_first = 1, .simulate = false});
      send_or_hold(fixture.impl, payload, 1100, fixture.to(), ecn_codepoint_t::not_ect);
    }
    CHECK(fixture.impl.blocked);
    CHECK(fixture.impl.held.size() == 3 * 1100);
    const auto first = fixture.receive(1);
    CHECK(first == std::vector<std::uint8_t>(payload.begin(), payload.begin() + 1100));

    CHECK(release_held(fixture.impl));
    const auto rest = fixture.receive(3);
    CHECK(rest == std::vector<std::uint8_t>(payload.begin() + 1100, payload.end()));
    CHECK(fixture.impl.stats.datagrams_sent == 4);
  }
  loop.stop();
  loop.run();
}

TEST_CASE("datagrams held behind a full buffer queue up and leave in order")
{
  event_loop_t loop;
  {
    send_fixture_t fixture(loop);
    const auto first = numbered_datagrams(3, 1200);
    const auto second = numbered_datagrams(2, 900);
    {
      planned_sends_t plan(send_plan_t{.code = errc::again, .failures = 1, .simulate = false});
      send_or_hold(fixture.impl, first, 1200, fixture.to(), ecn_codepoint_t::not_ect);
      send_or_hold(fixture.impl, second, 900, fixture.to(), ecn_codepoint_t::ect0);
      CHECK(send_plan.calls == 1);
    }
    CHECK(fixture.impl.held_runs.size() == 2);
    CHECK(fixture.impl.held.size() == first.size() + second.size());

    {
      planned_sends_t plan(send_plan_t{.code = errc::again, .failures = 1, .pass_first = 1, .simulate = false});
      CHECK_FALSE(release_held(fixture.impl));
    }
    CHECK(fixture.impl.blocked);
    CHECK(fixture.impl.held_runs.size() == 1);
    CHECK(fixture.impl.held_runs.front().segment == 900);
    CHECK(fixture.impl.held_runs.front().ecn == ecn_codepoint_t::ect0);
    CHECK(fixture.impl.held == second);

    CHECK(release_held(fixture.impl));
    auto expected = first;
    expected.insert(expected.end(), second.begin(), second.end());
    CHECK(fixture.receive(5) == expected);
  }
  loop.stop();
  loop.run();
}

TEST_CASE("a held batch goes out when the socket says it can take more")
{
  event_loop_t loop;
  bool released = false;
  std::vector<std::uint8_t> arrived;
  std::vector<std::uint8_t> sent;
  std::optional<task_t<void>> task;
  loop.run_in_loop(
    [&]
    {
      task.emplace(
        [](event_loop_t &loop, bool &released, std::vector<std::uint8_t> &arrived, std::vector<std::uint8_t> &sent) -> task_t<void>
        {
          {
            send_fixture_t fixture(loop);
            sent = numbered_datagrams(3, 1000);
            {
              planned_sends_t plan(send_plan_t{.code = errc::again, .failures = 1, .simulate = false});
              send_or_hold(fixture.impl, sent, 1000, fixture.to(), ecn_codepoint_t::not_ect);
            }
            CHECK(fixture.impl.writable.parked);
            for (int turn = 0; turn < 100 && fixture.impl.blocked; ++turn)
            {
              (void)co_await sleep(loop, std::chrono::milliseconds(1));
            }
            released = !fixture.impl.blocked;
            arrived = fixture.receive(3);
          }
          (void)co_await sleep(loop, std::chrono::milliseconds(1));
          loop.stop();
        }(loop, released, arrived, sent));
    });
  loop.run();
  CHECK(released);
  CHECK(arrived == sent);
}

TEST_CASE("the ticker retries a held batch when no write edge comes")
{
  event_loop_t loop;
  bool released = false;
  std::vector<std::uint8_t> arrived;
  std::vector<std::uint8_t> sent;
  std::optional<task_t<void>> task;
  loop.run_in_loop(
    [&]
    {
      task.emplace(
        [](event_loop_t &loop, bool &released, std::vector<std::uint8_t> &arrived, std::vector<std::uint8_t> &sent) -> task_t<void>
        {
          {
            send_fixture_t fixture(loop);
            sent = numbered_datagrams(2, 1000);
            {
              planned_sends_t plan(send_plan_t{.code = errc::no_buffer_space, .failures = 1, .simulate = false});
              send_or_hold(fixture.impl, sent, 1000, fixture.to(), ecn_codepoint_t::not_ect);
            }
            CHECK(fixture.impl.blocked);
            fixture.impl.udp.handle->socket.cancel(fixture.impl.writable);
            fixture.impl.running = true;
            arm_ticker(fixture.impl);
            (void)co_await sleep(loop, std::chrono::milliseconds(20));
            released = !fixture.impl.blocked;
            arrived = fixture.receive(2);
            fixture.impl.running = false;
            disarm_ticker(fixture.impl);
          }
          (void)co_await sleep(loop, std::chrono::milliseconds(1));
          loop.stop();
        }(loop, released, arrived, sent));
    });
  loop.run();
  CHECK(released);
  CHECK(arrived == sent);
}

TEST_CASE("the ticker never keeps the loop alive")
{
  event_loop_t loop;
  {
    send_fixture_t fixture(loop);
    const auto before = ::vio::detail::core(loop).in_flight();
    fixture.impl.running = true;
    arm_ticker(fixture.impl);
    CHECK(fixture.impl.ticker.armed());
    CHECK(::vio::detail::core(loop).in_flight() == before);
    loop.stop();
    loop.run();
    CHECK(fixture.impl.ticker.armed());
    fixture.impl.running = false;
  }
  loop.run();
}

TEST_CASE("an IPv4-mapped address is read as the IPv4 address it names")
{
  sockaddr_in6 mapped = {};
  mapped.sin6_family = AF_INET6;
  mapped.sin6_port = htons(4433);
  auto *bytes = reinterpret_cast<std::uint8_t *>(&mapped.sin6_addr);
  bytes[10] = 0xff;
  bytes[11] = 0xff;
  bytes[12] = 127;
  bytes[15] = 1;

  sockaddr_in storage = {};
  const auto *plain = unmap_ipv4(reinterpret_cast<const sockaddr *>(&mapped), storage);
  REQUIRE(plain->sa_family == AF_INET);
  const auto expected = loopback_address(4433);
  CHECK(address_key(plain).view().size() == 7);
  CHECK(std::ranges::equal(address_key(plain).view(), address_key(reinterpret_cast<const sockaddr *>(&expected)).view()));

  sockaddr_in6 real = {};
  real.sin6_family = AF_INET6;
  real.sin6_port = htons(4433);
  reinterpret_cast<std::uint8_t *>(&real.sin6_addr)[15] = 1;
  CHECK(unmap_ipv4(reinterpret_cast<const sockaddr *>(&real), storage) == reinterpret_cast<const sockaddr *>(&real));
  CHECK(unmap_ipv4(reinterpret_cast<const sockaddr *>(&expected), storage) == reinterpret_cast<const sockaddr *>(&expected));
}

TEST_CASE("a connection whose sends keep meeting a full buffer still delivers every byte")
{
  const auto identity = make_identity();
  tls_config_t server_tls;
  server_tls.role = tls_role_t::server;
  server_tls.certificate_chain_pem = identity.certificate_pem;
  server_tls.private_key_pem = identity.private_key_pem;
  server_tls.alpn = {"test"};
  tls_config_t client_tls;
  client_tls.role = tls_role_t::client;
  client_tls.ca_certificates_pem = identity.certificate_pem;
  client_tls.alpn = {"test"};
  auto server_context = tls_context_t::create(server_tls);
  auto client_context = tls_context_t::create(client_tls);
  REQUIRE(server_context.has_value());
  REQUIRE(client_context.has_value());

  constexpr std::size_t total = 512 * 1024;
  event_loop_t loop;
  std::size_t received = 0;
  bool finished = false;
  endpoint_stats_t client_stats;
  std::optional<task_t<void>> task;
  loop.run_in_loop(
    [&]
    {
      task.emplace(
        [](event_loop_t &loop, const tls_context_t &server_tls, const tls_context_t &client_tls, std::size_t &received, bool &finished, endpoint_stats_t &client_stats) -> task_t<void>
        {
          planned_sends_t plan(send_plan_t{.code = errc::again, .every = 4, .simulate = false});
          {
            auto server = endpoint_t::create(loop, server_tls, endpoint_config_t{});
            auto client = endpoint_t::create(loop, client_tls, endpoint_config_t{});
            REQUIRE(server.has_value());
            REQUIRE(client.has_value());
            const auto any = loopback_address();
            REQUIRE(server->bind(reinterpret_cast<const sockaddr *>(&any)).has_value());
            const auto port = server->local_port();
            REQUIRE(port.has_value());
            connection_t *accepted = nullptr;
            server->on_connection([&accepted](connection_t &connection) { accepted = &connection; });

            cancellation_t stop;
            auto server_run = [](endpoint_t &endpoint, cancellation_t &cancel) -> detached_task_t { co_await endpoint.run(&cancel); }(*server, stop);
            auto client_run = [](endpoint_t &endpoint, cancellation_t &cancel) -> detached_task_t { co_await endpoint.run(&cancel); }(*client, stop);
            (void)server_run;
            (void)client_run;

            const auto target = loopback_address(*port);
            auto dialled = client->connect(reinterpret_cast<const sockaddr *>(&target), "localhost");
            REQUIRE(dialled.has_value());
            for (int i = 0; i < 400; ++i)
            {
              auto *connection = client->connection(*dialled);
              if (connection == nullptr || connection->handshake_complete())
              {
                break;
              }
              (void)co_await sleep(loop, std::chrono::milliseconds(5));
            }
            auto *connection = client->connection(*dialled);
            REQUIRE(connection != nullptr);
            REQUIRE(connection->handshake_complete());
            const auto stream = connection->open_stream(stream_direction_t::bidirectional);
            REQUIRE(stream.has_value());
            const std::vector<std::uint8_t> payload(total, 0x5a);
            CHECK(connection->write_stream(*stream, payload, true) == payload.size());
            (void)client->flush();

            for (int i = 0; i < 2000 && !finished; ++i)
            {
              if (accepted != nullptr)
              {
                const auto readable = accepted->readable_stream(*stream);
                received += readable.size();
                accepted->consume_stream(*stream, readable.size());
                finished = accepted->stream_receive_finished(*stream);
              }
              if (!finished)
              {
                (void)co_await sleep(loop, std::chrono::milliseconds(2));
              }
            }
            client_stats = client->stats();
            stop.cancel();
            (void)co_await sleep(loop, std::chrono::milliseconds(5));
          }
          (void)co_await sleep(loop, std::chrono::milliseconds(5));
          loop.stop();
        }(loop, *server_context, *client_context, received, finished, client_stats));
    });
  loop.run();
  CHECK(finished);
  CHECK(received == total);
#if defined(__linux__)
  CHECK(client_stats.datagrams_sent > client_stats.sends);
#endif
}
}
} // namespace vio::quic
#endif
