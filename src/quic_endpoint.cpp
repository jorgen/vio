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
#include "vio/crypto.h"
#include "vio/operation/udp_datagram.h"
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

// What one coalesced read may hold. Large enough that a burst arrives in a
// single call, small enough to stay a sensible allocation per endpoint.
constexpr std::size_t coalesced_receive_size = 64 * 1024;

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
  connection_active_t on_activity;
  bool running = false;
  // One buffer for the whole endpoint, grown once and reused: a batch is built
  // by polling datagrams straight into it rather than copying them in.
  std::vector<std::uint8_t> batch;
  // Whether the send-side offload is worth attempting. Cleared the first time
  // a route refuses it, because it will keep refusing.
  bool segmenting = false;
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
  const auto &original = entry.connection->original_destination_id();
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

// libuv creates the UDP socket lazily: a handle that has neither bound nor
// sent has no descriptor at all. Its own recv_start binds implicitly when that
// happens, and anything reading or marking the socket directly needs the same,
// because both start from a descriptor.
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
    if (uv_ip6_addr("::", 0, &any) == 0 && udp_bind(impl.udp, reinterpret_cast<const sockaddr *>(&any)).has_value())
    {
      return;
    }
  }
  // IPv4 otherwise, matching what libuv's own deferred bind would have chosen.
  sockaddr_in any = {};
  if (uv_ip4_addr("0.0.0.0", 0, &any) == 0)
  {
    (void)udp_bind(impl.udp, reinterpret_cast<const sockaddr *>(&any));
  }
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

// The codepoint travels with the datagram rather than sitting on the socket,
// so two connections on one port can disagree about ECN -- one still marking,
// one that has given up on its path -- without either affecting the other.
void send_to(endpoint_impl_t &impl, std::span<const std::uint8_t> bytes, const sockaddr *address, ecn_codepoint_t ecn = ecn_codepoint_t::not_ect)
{
  // A datagram that cannot be handed to the socket is dropped rather than
  // retried: QUIC treats loss as ordinary, and every path here has a
  // retransmission behind it.
  if (ecn == ecn_codepoint_t::not_ect)
  {
    (void)udp_try_send(impl.udp, bytes, address);
    return;
  }
  (void)send_datagram(impl.udp, bytes, address, static_cast<udp_ecn_t>(ecn));
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
  if (impl.config.stateless_reset_key == nullptr || !allow_stateless_reset(impl, now))
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
  const std::size_t head = serialize_retry(out, quic_version_1, header.source_id, *source, *token);
  if (head == 0 || out.size() < head + retry_integrity_tag_size)
  {
    return;
  }
  // Section 5.8 of RFC 9001: the tag is what proves this came from someone who
  // saw the client's Initial, rather than anyone who can write a packet.
  auto tag = retry_integrity_tag(header.destination_id.bytes(), std::span<const std::uint8_t>(out).first(head));
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
  if (impl.config.connection.role != tls_role_t::server)
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

  auto created = connection_t::create(impl.context, config);
  if (!created.has_value())
  {
    return nullptr;
  }

  auto entry = std::make_unique<connection_entry_t>();
  entry->connection = std::make_unique<connection_t>(std::move(*created));
  attach_qlog(impl, *entry->connection, header.destination_id, true, now);
  entry->peer_bytes = config.peer_address;
  std::memcpy(&entry->peer, address, address->sa_family == AF_INET6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in));

  auto *raw = entry.get();
  impl.connections.push_back(std::move(entry));
  index_connection(impl, *raw);
  return raw;
}

// Hands the batch to the kernel as one send when there is more than one
// datagram in it, and as an ordinary send otherwise.
void flush_batch(endpoint_impl_t &impl, connection_entry_t &entry, std::size_t used, std::size_t segment, std::size_t count)
{
  if (used == 0)
  {
    return;
  }
  const auto *address = reinterpret_cast<const sockaddr *>(&entry.peer);
  const auto ecn = entry.connection->ecn_sending();
  const std::span<const std::uint8_t> bytes(impl.batch.data(), used);

  if (count > 1 && impl.segmenting)
  {
    if (send_segments(impl.udp, bytes, segment, address, static_cast<udp_ecn_t>(ecn)).has_value())
    {
      ++impl.stats.sends;
      impl.stats.datagrams_sent += count;
      return;
    }
    // The offload was refused after all -- a route or interface that will not
    // do it. Stop asking, and fall through to sending the batch one datagram
    // at a time so nothing is lost this time either.
    impl.segmenting = false;
  }

  for (std::size_t offset = 0; offset < used; offset += segment)
  {
    const std::size_t piece = (std::min)(segment, used - offset);
    send_to(impl, bytes.subspan(offset, piece), address, ecn);
    ++impl.stats.sends;
    ++impl.stats.datagrams_sent;
  }
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
    if (impl.batch.size() < used + max_datagram)
    {
      impl.batch.resize(used + max_datagram);
    }
    auto size = entry.connection->poll_send(std::span<std::uint8_t>(impl.batch).subspan(used, max_datagram), now);
    if (!size.has_value() || *size == 0)
    {
      break;
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

void endpoint_t::on_activity(connection_active_t handler)
{
  _impl->on_activity = std::move(handler);
}

std::expected<connection_t *, error_t> endpoint_t::connect(const sockaddr *address, std::string_view server_name)
{
  auto &impl = *_impl;
  ensure_socket(impl, address != nullptr ? address->sa_family : AF_INET);
  auto config = impl.config.connection;
  config.role = tls_role_t::client;
  config.stateless_reset_key = impl.config.stateless_reset_key;
  config.peer_address = address_bytes(address);
  config.peer_host_address = host_address_bytes(address);
  config.ecn = impl.config.ecn ? ecn_codepoint_t::ect0 : ecn_codepoint_t::not_ect;

  auto created = connection_t::create(impl.context, config, server_name);
  if (!created.has_value())
  {
    return std::unexpected(created.error());
  }

  auto entry = std::make_unique<connection_entry_t>();
  entry->connection = std::make_unique<connection_t>(std::move(*created));
  attach_qlog(impl, *entry->connection, entry->connection->original_destination_id(), false, loop_now(impl.loop));
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

endpoint_stats_t endpoint_t::stats() const
{
  return _impl->stats;
}

task_t<void> endpoint_t::run(cancellation_t *cancel)
{
  auto &impl = *_impl;
  ensure_socket(impl);
  // Our own read rather than libuv's, so the ECN codepoint the kernel reports
  // alongside each datagram survives to the connection that needs it.
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

  // Datagrams that arrived together are answered together. One wakeup usually
  // pulls a run of them off the socket, and replying to each in turn would
  // leave every reply its own system call -- which is exactly the cost the
  // send-side offload exists to remove, given something to batch.
  std::vector<connection_entry_t *> touched;
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
    impl.stats.reads = reader->reads();
    impl.stats.datagrams_received = reader->datagrams();
    touched.clear();

    std::optional<std::expected<datagram_t, error_t>> next = std::move(received);
    for (; next.has_value(); next = reader->try_next())
    {
    if (!next->has_value())
    {
      break;
    }
    auto &datagram = next->value();
    std::span<std::uint8_t> bytes(datagram.data);
    const auto arriving_ecn = static_cast<ecn_codepoint_t>(datagram.ecn);
    const auto now = loop_now(impl.loop);
    const auto *sender = datagram.sender();

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
      // Only an Initial starts a connection. Anything else addressed to a
      // connection ID this endpoint does not know is late, misrouted, or an
      // attempt to make it allocate for a handshake that will never happen.
      const auto initial = peek_initial(impl, bytes);
      if (!initial.has_value())
      {
        send_stateless_reset(impl, bytes, sender, now);
        continue;
      }

      if (impl.config.retry_key != nullptr && initial->token.empty())
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

    const auto peer = address_bytes(sender);
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
      entry->peer_bytes = peer;
      std::memcpy(&entry->peer, sender, sender->sa_family == AF_INET6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in));
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
    reap(impl, now);
  }

  impl.running = false;
  co_return;
}
} // namespace vio::quic
