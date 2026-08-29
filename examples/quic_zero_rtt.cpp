// Session resumption and 0-RTT: a second connection to a server this client
// has met before, carrying application data in its very first flight.
//
// This is QUIC's headline latency feature and the one place where the
// transport hands the application data it cannot promise is fresh. An attacker
// who captured a 0-RTT flight can send it again, so a server must be given an
// anti_replay_t before it will grant early data at all -- and the request
// itself should be one that is safe to perform twice.
//
// The program makes two connections. The first is an ordinary handshake whose
// only purpose is to be issued a session ticket. The second spends that ticket
// and writes before the server has said anything; watch the server report that
// its handshake is still running as it answers.

#include <chrono>
#include <cstdint>
#include <optional>
#include <print>
#include <string>
#include <vector>

#include <vio/quic/anti_replay.h>

#include "quic_common.h"

namespace
{
using namespace std::chrono_literals;
using namespace vio_example;
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
      server_tls.alpn = {"vio-zero-rtt"};
      // Two separate decisions. Resumption alone shortens the handshake and
      // carries no replay exposure; early_data additionally permits 0-RTT and
      // implies the first.
      server_tls.session_resumption = true;
      server_tls.early_data = true;
      server_tls.anti_replay = &anti_replay;
      auto server_context = tls_context_t::create(server_tls);
      if (!server_context)
      {
        std::println(stderr, "server tls_context_t::create failed: {}", server_context.error().msg);
        co_return 1;
      }

      tls_config_t client_tls;
      client_tls.role = tls_role_t::client;
      client_tls.ca_certificates_pem = identity.certificate_pem;
      client_tls.alpn = {"vio-zero-rtt"};
      client_tls.session_resumption = true;
      client_tls.early_data = true;
      auto client_context = tls_context_t::create(client_tls);
      if (!client_context)
      {
        std::println(stderr, "client tls_context_t::create failed: {}", client_context.error().msg);
        co_return 1;
      }

      endpoint_config_t server_config;
      server_config.connection.role = tls_role_t::server;
      auto server_created = endpoint_t::create(loop, *server_context, server_config);
      if (!server_created)
      {
        std::println(stderr, "server endpoint_t::create failed: {}", server_created.error().msg);
        co_return 1;
      }
      std::optional<endpoint_t> server(std::move(*server_created));

      auto bind_address = ip4_addr("127.0.0.1", 0);
      if (!bind_address || !server->bind(reinterpret_cast<const sockaddr *>(&*bind_address)))
      {
        std::println(stderr, "could not bind the server socket");
        co_return 1;
      }
      const auto port = server->local_port();
      if (!port)
      {
        std::println(stderr, "could not read the server port");
        co_return 1;
      }
      std::println("server listening on 127.0.0.1:{}", *port);

      server->on_activity(
        [](connection_t &connection)
        {
          for (const auto id : connection.readable_streams())
          {
            auto readable = connection.readable_stream(id);
            // On the resumed connection this prints while the handshake is
            // still running: that is what 0-RTT means, and it is exactly why
            // the anti-replay register has to exist.
            //
            // It is also a trap for a server that keeps per-connection state.
            // on_connection fires only once the handshake is complete, so
            // 0-RTT data reaches on_activity BEFORE on_connection ever fires
            // for that connection -- a server that allocates its state in
            // on_connection will look it up here and not find it. This one
            // holds no per-connection state, which is why it does not care.
            std::println("server: \"{}\" -- handshake {}", text_of(readable), connection.handshake_complete() ? "complete" : "still running");
            (void)connection.write_stream(id, readable, connection.stream_receive_finished(id));
            connection.consume_stream(id, readable.size());
          }
        });

      endpoint_config_t client_config;
      client_config.connection.role = tls_role_t::client;
      auto client_created = endpoint_t::create(loop, *client_context, client_config);
      if (!client_created)
      {
        std::println(stderr, "client endpoint_t::create failed: {}", client_created.error().msg);
        co_return 1;
      }
      std::optional<endpoint_t> client(std::move(*client_created));

      std::string reply;
      bool reply_finished = false;
      client->on_activity(
        [&reply, &reply_finished](connection_t &connection)
        {
          for (const auto id : connection.readable_streams())
          {
            auto readable = connection.readable_stream(id);
            reply += text_of(readable);
            connection.consume_stream(id, readable.size());
            if (connection.stream_receive_finished(id))
            {
              reply_finished = true;
            }
          }
        });

      cancellation_t server_cancel;
      cancellation_t client_cancel;
      auto server_run = [](endpoint_t &endpoint, cancellation_t &cancel) -> detached_task_t { co_await endpoint.run(&cancel); }(*server, server_cancel);
      auto client_run = [](endpoint_t &endpoint, cancellation_t &cancel) -> detached_task_t { co_await endpoint.run(&cancel); }(*client, client_cancel);
      (void)server_run;
      (void)client_run;

      const auto target = ip4_addr("127.0.0.1", *port);

      // ---- first connection: an ordinary handshake, to be issued a ticket ----
      std::vector<std::uint8_t> ticket;
      {
        auto dialled = client->connect(reinterpret_cast<const sockaddr *>(&*target), "localhost");
        if (!dialled)
        {
          std::println(stderr, "connect failed: {}", dialled.error().msg);
          co_return 1;
        }
        for (int attempt = 0; attempt < 400; ++attempt)
        {
          auto *live = client->connection(*dialled);
          if (live == nullptr || live->handshake_complete())
          {
            break;
          }
          co_await sleep(loop, 5ms);
        }
        std::println("first connection: a full handshake");

        // TLS 1.3 sends the ticket AFTER the handshake, often after the
        // exchange the connection existed for. So polling resumption_ticket()
        // the moment handshake_complete() turns true yields nothing, and
        // nothing distinguishes "not yet" from "never".
        for (int attempt = 0; attempt < 400 && ticket.empty(); ++attempt)
        {
          auto *live = client->connection(*dialled);
          if (live == nullptr)
          {
            break;
          }
          ticket = live->resumption_ticket();
          if (!ticket.empty())
          {
            break;
          }
          co_await sleep(loop, 5ms);
        }
        if (auto *live = client->connection(*dialled); live != nullptr)
        {
          live->close(0, "have the ticket", true);
        }
        co_await sleep(loop, 50ms);
      }

      if (ticket.empty())
      {
        std::println(stderr, "no session ticket ever arrived");
        co_return 1;
      }
      // One opaque blob carrying the TLS session and the server's transport
      // parameters together, because a resuming client has to stay inside the
      // limits it was given last time and there is nothing else to go on
      // before the server has spoken. Where it is kept is the application's
      // business, which is why it comes out as bytes.
      std::println("kept a {} byte session ticket", ticket.size());

      // ---- second connection: spends the ticket, writes immediately ----
      reply.clear();
      reply_finished = false;
      auto resumed = client->connect(reinterpret_cast<const sockaddr *>(&*target), "localhost", ticket);
      if (!resumed)
      {
        std::println(stderr, "resumed connect failed: {}", resumed.error().msg);
        co_return 1;
      }
      auto *connection = client->connection(*resumed);
      if (connection == nullptr)
      {
        std::println(stderr, "the resumed connection went away");
        co_return 1;
      }

      // The write has to happen here, between connect() returning and the next
      // trip through the event loop. Waiting until the handshake completes --
      // the natural thing to write -- produces a perfectly good connection
      // that simply never used 0-RTT, with nothing anywhere to say so.
      //
      // There is stream credit to spend already because the ticket carried the
      // server's transport parameters from last time.
      auto stream = connection->open_stream(stream_direction_t::bidirectional);
      if (!stream)
      {
        std::println(stderr, "no stream credit for 0-RTT");
        co_return 1;
      }
      const std::string message = "sent at 0-RTT";
      (void)connection->write_stream(*stream, bytes_of(message), true);
      (void)client->flush();
      std::println("client: wrote \"{}\" before the handshake began", message);

      for (int attempt = 0; attempt < 400 && !reply_finished; ++attempt)
      {
        co_await sleep(loop, 5ms);
      }

      bool accepted = false;
      if (auto *live = client->connection(*resumed); live != nullptr)
      {
        // Resuming and having early data accepted are different things: a
        // server may take the ticket and still refuse the data on it, in which
        // case the connection rewinds and sends it again under 1-RTT keys.
        // early_data_rejected() reports that; the application does not have to
        // do anything about it.
        accepted = live->early_data_accepted();
        std::println("client: early data {}", accepted ? "accepted" : "refused");
        std::println("client: received \"{}\"", reply);
        live->close(0, "done", true);
      }

      co_await sleep(loop, 50ms);
      client_cancel.cancel();
      server_cancel.cancel();
      co_await sleep(loop, 50ms);
      client.reset();
      server.reset();
      co_await sleep(loop, 50ms);

      co_return accepted &&reply == message ? 0 : 1;
    });
}
