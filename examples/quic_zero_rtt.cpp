// Session resumption and 0-RTT: a second connection to a server this client has
// met before, carrying application data in its very first flight.
//
// This is QUIC's headline latency feature and the one place where the transport
// hands the application data it cannot promise is fresh. An attacker who
// captured a 0-RTT flight can send it again, so a server must be given an
// anti_replay_t before it will grant early data at all -- and the request itself
// should be one that is safe to perform twice.
//
// The program makes two connections. The first is an ordinary handshake whose
// only purpose is to be issued a session ticket. The second spends that ticket
// and writes before the server has said anything.
//
// This is the one example that dials with quic_endpoint_connect_early rather
// than quic_endpoint_connect, and the reason is the whole feature: an ordinary
// dial resolves when the handshake completes, which is exactly too late. The
// early form hands back the connection at once so the first flight can carry
// something, and the handshake is awaited afterwards.
//
// One limit of this layer worth knowing before designing around 0-RTT.
// quic_endpoint_accept resolves only once a handshake has *completed*, because
// that is when the transport reports a connection at all -- so a server written
// against this API cannot act on 0-RTT data during the round trip it saves. The
// latency is still saved: the client's first flight carries the request, the
// server has it before its own handshake finishes, and the answer goes out a
// round trip earlier than it otherwise could. What a server cannot do here is
// *observe* that window. A server that must react inside it has to reach for
// quic_endpoint_native and the transport's on_activity, and then it owns the
// rule that no user code may run inside the transport's walk.

#include <chrono>
#include <cstdint>
#include <print>
#include <string>
#include <vector>

#include <vio/quic/anti_replay.h>

#include "quic_common.h"

namespace
{
using namespace std::chrono_literals;
using namespace vio_example;

// Echoes one stream back.
//
// The 0-RTT data is already here when this runs -- it arrived in the client's
// first flight, which is the point -- but the handshake has completed by the
// time an accept hands the connection over, so this cannot watch it happen. The
// client side reports the verdict instead.
vio::task_t<void> serve(vio::quic_connection_t connection)
{
  using namespace vio;
  auto stream = co_await quic_accept_stream(connection);
  if (!stream)
  {
    co_return;
  }
  auto reader = quic_stream_create_reader(*stream);
  if (!reader)
  {
    co_return;
  }
  std::string request;
  while (auto chunk = co_await *reader)
  {
    request += text_of(*chunk);
  }
  std::println("server: \"{}\"", request);
  (void)co_await quic_stream_write_final(*stream, bytes_of(request));
}

// One connection's worth of answering. Two of these run over the program's
// life, one per connection the client makes.
vio::task_t<void> answer_one(vio::quic_endpoint_t &endpoint)
{
  auto connection = co_await vio::quic_endpoint_accept(endpoint);
  if (!connection)
  {
    co_return;
  }
  co_await serve(*connection);
}
} // namespace

int main()
{
  return vio::run(
    [](vio::event_loop_t &loop) -> vio::task_t<int>
    {
      using namespace vio;
      using namespace vio::quic;

      const auto identity = make_self_signed("localhost");

      // One register per endpoint, not per connection: a replay is by
      // definition a second connection. It must outlive the context, which
      // holds it as a bare pointer. A server that sets early_data without one
      // fails to build its context at all, which is the right way round --
      // refusing beats silently never granting 0-RTT.
      anti_replay_t anti_replay;

      tls_config_t server_tls;
      server_tls.role = tls_role_t::server;
      server_tls.certificate_chain_pem = identity.certificate_pem;
      server_tls.private_key_pem = identity.private_key_pem;
      server_tls.alpn = {"vio-0rtt"};
      // Two knobs because they are two features: session_resumption issues and
      // offers tickets, which shortens a handshake and carries no replay
      // exposure; early_data additionally permits 0-RTT, and implies the first.
      server_tls.session_resumption = true;
      server_tls.early_data = true;
      server_tls.anti_replay = &anti_replay;
      auto server_context = tls_context_t::create(server_tls);

      tls_config_t client_tls;
      client_tls.role = tls_role_t::client;
      client_tls.ca_certificates_pem = identity.certificate_pem;
      client_tls.alpn = {"vio-0rtt"};
      client_tls.session_resumption = true;
      client_tls.early_data = true;
      auto client_context = tls_context_t::create(client_tls);
      if (!server_context || !client_context)
      {
        std::println(stderr, "tls_context_t::create failed");
        co_return 1;
      }

      auto server = quic_endpoint_create(loop, *server_context);
      auto client = quic_endpoint_create(loop, nullptr, &*client_context);
      if (!server || !client)
      {
        std::println(stderr, "quic_endpoint_create failed");
        co_return 1;
      }
      if (auto bound = quic_endpoint_bind(*server, std::uint16_t{0}); !bound)
      {
        std::println(stderr, "quic_endpoint_bind: {}", bound.error().msg);
        co_return 1;
      }
      const auto port = quic_endpoint_local_port(*server).value_or(0);
      std::println("server listening on port {}", port);

      const auto target = ip4_addr("127.0.0.1", port);
      if (!target)
      {
        std::println(stderr, "could not build the target address");
        co_return 1;
      }

      // ---- first connection: an ordinary handshake, for the ticket ----
      std::vector<std::uint8_t> ticket;
      {
        auto answering = answer_one(*server);
        auto connection = co_await quic_endpoint_connect(*client, reinterpret_cast<const sockaddr *>(&*target), "localhost");
        if (!connection)
        {
          std::println(stderr, "quic_endpoint_connect: {}", connection.error().msg);
          co_return 1;
        }
        std::println("first connection: a full handshake");

        auto stream = co_await quic_open_stream(*connection);
        if (!stream)
        {
          co_return 1;
        }
        (void)co_await quic_stream_write_final(*stream, bytes_of("hello"));
        auto reader = quic_stream_create_reader(*stream);
        if (reader)
        {
          while ((co_await *reader).has_value())
          {
          }
        }
        co_await std::move(answering);

        // TLS 1.3 sends the ticket AFTER the handshake, often after the
        // exchange the connection existed for, and there is no event for its
        // arrival. So this waits for it, which is the one poll left in this
        // directory and an honest one: nothing in the protocol says when.
        for (int attempt = 0; attempt < 200 && ticket.empty(); ++attempt)
        {
          ticket = quic_connection_resumption_ticket(*connection);
          if (!ticket.empty())
          {
            break;
          }
          (void)co_await sleep(loop, 5ms);
        }
        quic_connection_close(*connection, 0, "have the ticket");
      }

      if (ticket.empty())
      {
        std::println(stderr, "no session ticket ever arrived");
        co_return 1;
      }
      // One opaque blob carrying the TLS session and the server's transport
      // parameters together, because a resuming client has to stay inside the
      // limits it was given last time and there is nothing else to go on before
      // the server has spoken.
      std::println("kept a {} byte session ticket", ticket.size());

      // ---- second connection: spends the ticket, writes immediately ----
      auto answering = answer_one(*server);

      auto resumed = quic_endpoint_connect_early(*client, reinterpret_cast<const sockaddr *>(&*target), "localhost", ticket);
      if (!resumed)
      {
        std::println(stderr, "quic_endpoint_connect_early: {}", resumed.error().msg);
        co_return 1;
      }

      // On this stack, before the next trip through the event loop. There is
      // stream credit to spend already because the ticket carried the server's
      // transport parameters from last time.
      auto stream = quic_try_open_stream(*resumed);
      if (!stream)
      {
        std::println(stderr, "no stream credit for 0-RTT: {}", stream.error().msg);
        co_return 1;
      }
      const std::string message = "sent at 0-RTT";
      if (auto written = co_await quic_stream_write_final(*stream, bytes_of(message)); !written)
      {
        std::println(stderr, "0-RTT write: {}", written.error().msg);
        co_return 1;
      }
      std::println("client: wrote \"{}\" before the handshake began", message);

      auto reader = quic_stream_create_reader(*stream);
      if (!reader)
      {
        co_return 1;
      }
      std::string reply;
      while (auto chunk = co_await *reader)
      {
        reply += text_of(*chunk);
      }
      co_await std::move(answering);

      // Resuming and having early data accepted are different things: a server
      // may take the ticket and still refuse the data on it, in which case the
      // connection rewinds and sends it again under 1-RTT keys. The application
      // does not have to do anything about it -- this only reports it.
      const bool accepted = quic_connection_early_data_accepted(*resumed);
      std::println("client: early data {}", accepted ? "accepted" : "refused");
      std::println("client: received \"{}\"", reply);

      quic_connection_close(*resumed, 0, "done");
      co_return accepted && reply == message ? 0 : 1;
    });
}
