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

#include "vio/operation/sleep.h"
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

// The address as bytes, for the two places that need to compare or authenticate
// one: section 9.3 asks whether the peer has moved, and section 8.1.4 binds a
// Retry token to the address it was issued to. Only equality and opacity are
// required of the encoding, so this is the smallest thing that carries the
// whole address.
[[nodiscard]] std::vector<std::uint8_t> address_bytes(const sockaddr *address)
{
  std::vector<std::uint8_t> out;
  if (address == nullptr)
  {
    return out;
  }
  if (address->sa_family == AF_INET)
  {
    const auto *in4 = reinterpret_cast<const sockaddr_in *>(address);
    out.resize(1 + 4 + 2);
    out[0] = 4;
    std::memcpy(out.data() + 1, &in4->sin_addr, 4);
    std::memcpy(out.data() + 5, &in4->sin_port, 2);
    return out;
  }
  if (address->sa_family == AF_INET6)
  {
    const auto *in6 = reinterpret_cast<const sockaddr_in6 *>(address);
    out.resize(1 + 16 + 2);
    out[0] = 6;
    std::memcpy(out.data() + 1, &in6->sin6_addr, 16);
    std::memcpy(out.data() + 17, &in6->sin6_port, 2);
    return out;
  }
  return out;
}
} // namespace

namespace detail
{
struct connection_entry_t
{
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

struct endpoint_impl_t
{
  endpoint_impl_t(event_loop_t &event_loop, const tls_context_t &tls_context, endpoint_config_t configuration, udp_t socket)
    : loop(event_loop)
    , context(tls_context)
    , config(std::move(configuration))
    , udp(std::move(socket))
  {
  }

  event_loop_t &loop;
  const tls_context_t &context;
  endpoint_config_t config;
  udp_t udp;
  std::vector<std::unique_ptr<connection_entry_t>> connections;
  std::unordered_map<connection_id_t, connection_entry_t *> by_id;
  connection_ready_t on_connection;
  bool running = false;
};
} // namespace detail

using detail::connection_entry_t;
using detail::endpoint_impl_t;

namespace
{
void route_by(endpoint_impl_t &impl, connection_entry_t &entry, const connection_id_t &id)
{
  if (id.empty() || std::find(entry.routed.begin(), entry.routed.end(), id) != entry.routed.end())
  {
    return;
  }
  entry.routed.push_back(id);
  impl.by_id[id] = &entry;
}

void index_connection(endpoint_impl_t &impl, connection_entry_t &entry)
{
  for (const auto &id : entry.connection->issued_connection_ids())
  {
    route_by(impl, entry, id);
  }

  // Section 7.2: a client goes on addressing the connection ID it invented
  // until it has seen the server's choice and switched. Routing only on what
  // this endpoint issued would leave every retransmit of that first Initial
  // unmatched, and each one would be read as a new connection. The value is
  // not known until the first Initial has been processed, so this runs on
  // every flush rather than once at accept.
  route_by(impl, entry, entry.connection->original_destination_id());
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

void send_to(endpoint_impl_t &impl, std::span<const std::uint8_t> bytes, const sockaddr *address)
{
  // A datagram that cannot be handed to the socket is dropped rather than
  // retried: QUIC treats loss as ordinary, and every path here has a
  // retransmission behind it.
  (void)udp_try_send(impl.udp, bytes, address);
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
void send_stateless_reset(endpoint_impl_t &impl, std::span<const std::uint8_t> datagram, const sockaddr *address)
{
  if (impl.config.stateless_reset_key == nullptr)
  {
    return;
  }
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

  const auto token = impl.config.stateless_reset_key->token_for(*id);
  std::array<std::uint8_t, max_datagram> out = {};
  auto size = build_stateless_reset(out, token, datagram.size());
  if (!size.has_value() || *size == 0)
  {
    return;
  }
  send_to(impl, std::span<const std::uint8_t>(out).first(*size), address);
}

[[nodiscard]] connection_entry_t *accept_connection(endpoint_impl_t &impl, std::span<const std::uint8_t> datagram, const sockaddr *address)
{
  if (impl.config.connection.role != tls_role_t::server)
  {
    return nullptr;
  }
  if (impl.config.max_connections != 0 && impl.connections.size() >= impl.config.max_connections)
  {
    return nullptr;
  }

  // Only an Initial starts a connection. Anything else with an unknown
  // connection ID is either late, misrouted, or an attempt to make this
  // endpoint allocate for a handshake that will never happen.
  const auto invariant = parse_invariant_header(datagram);
  if (!invariant.has_value() || !invariant->long_header)
  {
    return nullptr;
  }
  if ((datagram[0] & long_packet_type_mask) != 0x00)
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
  config.retry_key = impl.config.retry_key;
  config.stateless_reset_key = impl.config.stateless_reset_key;
  config.peer_address = address_bytes(address);

  auto created = connection_t::create(impl.context, config);
  if (!created.has_value())
  {
    return nullptr;
  }

  auto entry = std::make_unique<connection_entry_t>();
  entry->connection = std::make_unique<connection_t>(std::move(*created));
  entry->peer_bytes = config.peer_address;
  std::memcpy(&entry->peer, address, address->sa_family == AF_INET6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in));

  auto *raw = entry.get();
  impl.connections.push_back(std::move(entry));
  index_connection(impl, *raw);
  return raw;
}

void flush_entry(endpoint_impl_t &impl, connection_entry_t &entry, tick_t now)
{
  std::array<std::uint8_t, max_datagram> out = {};
  for (int guard = 0; guard < 64; ++guard)
  {
    auto size = entry.connection->poll_send(out, now);
    if (!size.has_value() || *size == 0)
    {
      break;
    }
    send_to(impl, std::span<const std::uint8_t>(out).first(*size), reinterpret_cast<const sockaddr *>(&entry.peer));
  }

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
  }
}

void reap(endpoint_impl_t &impl, tick_t now)
{
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
    it = impl.connections.erase(it);
  }
}
} // namespace

endpoint_t::~endpoint_t() = default;
endpoint_t::endpoint_t(endpoint_t &&) noexcept = default;
endpoint_t &endpoint_t::operator=(endpoint_t &&) noexcept = default;

std::expected<endpoint_t, error_t> endpoint_t::create(event_loop_t &loop, const tls_context_t &context, const endpoint_config_t &config)
{
  auto socket = udp_create(loop);
  if (!socket.has_value())
  {
    return std::unexpected(socket.error());
  }
  endpoint_t endpoint;
  endpoint._impl = std::make_unique<endpoint_impl_t>(loop, context, config, std::move(*socket));
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

std::expected<connection_t *, error_t> endpoint_t::connect(const sockaddr *address, std::string_view server_name)
{
  auto &impl = *_impl;
  auto config = impl.config.connection;
  config.role = tls_role_t::client;
  config.stateless_reset_key = impl.config.stateless_reset_key;
  config.peer_address = address_bytes(address);

  auto created = connection_t::create(impl.context, config, server_name);
  if (!created.has_value())
  {
    return std::unexpected(created.error());
  }

  auto entry = std::make_unique<connection_entry_t>();
  entry->connection = std::make_unique<connection_t>(std::move(*created));
  entry->peer_bytes = config.peer_address;
  std::memcpy(&entry->peer, address, address->sa_family == AF_INET6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in));

  auto *raw = entry.get();
  impl.connections.push_back(std::move(entry));
  index_connection(impl, *raw);
  flush_entry(impl, *raw, loop_now(impl.loop));
  return raw->connection.get();
}

std::expected<void, error_t> endpoint_t::flush()
{
  auto &impl = *_impl;
  const auto now = loop_now(impl.loop);
  for (auto &entry : impl.connections)
  {
    flush_entry(impl, *entry, now);
  }
  reap(impl, now);
  return {};
}

std::size_t endpoint_t::connection_count() const
{
  return _impl->connections.size();
}

task_t<void> endpoint_t::run(cancellation_t *cancel)
{
  auto &impl = *_impl;
  auto reader = udp_create_reader(impl.udp);
  if (!reader.has_value())
  {
    co_return;
  }
  impl.running = true;

  // Timers live in their own coroutine because the read is what the endpoint
  // is normally parked on, and QUIC's deadlines have to fire whether or not a
  // datagram ever arrives -- loss detection and the idle timeout are both
  // about the absence of traffic.
  auto ticker = [](endpoint_impl_t &state, cancellation_t *token) -> detached_task_t
  {
    while (state.running)
    {
      // A cancelled sleep returns at once, so the token has to be tested as
      // well as passed -- otherwise cancelling turns this into a hot loop that
      // starves everything else on the event loop.
      auto slept = co_await sleep(state.loop, timer_granularity, token);
      if (!state.running || !slept.has_value() || (token != nullptr && token->is_cancelled()))
      {
        break;
      }
      const auto now = loop_now(state.loop);
      for (auto &entry : state.connections)
      {
        flush_entry(state, *entry, now);
      }
      reap(state, now);
    }
    state.running = false;
  }(impl, cancel);
  (void)ticker;

  // Cancelling has to reach the read as well, or run() stays parked on a
  // socket that will never speak again.
  registration_t stop_reading;
  if (cancel != nullptr)
  {
    stop_reading = cancel->register_callback([reader = &*reader]() { reader->cancel(); });
  }

  for (;;)
  {
    auto received = co_await *reader;
    if (!received.has_value())
    {
      break;
    }
    if (cancel != nullptr && cancel->is_cancelled())
    {
      break;
    }
    auto &datagram = received.value();
    std::span<std::uint8_t> bytes(reinterpret_cast<std::uint8_t *>(datagram.data->base), datagram.data->len);
    const auto now = loop_now(impl.loop);
    const auto *sender = datagram.get_sender();

    auto *entry = find_connection(impl, bytes);
    if (entry == nullptr)
    {
      const auto invariant = parse_invariant_header(bytes);
      if (invariant.has_value() && invariant->long_header && !version_supported(impl, invariant->version))
      {
        // Section 6.1, and only for a long header: a short header carries no
        // version, so there is nothing to negotiate about.
        send_version_negotiation(impl, *invariant, sender);
        continue;
      }
      entry = accept_connection(impl, bytes, sender);
      if (entry == nullptr)
      {
        send_stateless_reset(impl, bytes, sender);
        continue;
      }
    }

    const auto peer = address_bytes(sender);
    const bool fresh = entry->routed.empty() || entry->connection->original_destination_id().empty();
    if (!entry->connection->receive(bytes, now, peer).has_value())
    {
      // The connection has decided it cannot continue. It still gets to send
      // whatever it wanted to say about that.
      flush_entry(impl, *entry, now);
      continue;
    }
    if (!entry->peer_bytes.empty() && peer != entry->peer_bytes && entry->connection->migration_count() > 0)
    {
      // Section 9.3: the connection accepted the move, so replies go to the
      // new address from here on.
      entry->peer_bytes = peer;
      std::memcpy(&entry->peer, sender, sender->sa_family == AF_INET6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in));
    }
    if (fresh)
    {
      index_connection(impl, *entry);
    }
    flush_entry(impl, *entry, now);
    reap(impl, now);
  }

  impl.running = false;
  co_return;
}
} // namespace vio::quic
