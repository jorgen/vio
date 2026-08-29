// How a QUIC connection ends, and how an application finds out.
//
// This is the example to read before putting anything on a real network,
// because the answer to "how do I find out" is the same for every ending:
// there is no callback. on_connection fires only for a handshake that
// succeeded and never fires again; on_activity fires only when a datagram
// arrives. Nothing tells an application that a dial failed, that a peer went
// away, or that a connection it was using has been collected. Every ending
// below is discovered by asking.
//
// Three endings, in order:
//
//   1. The peer closed, and said why. A CONNECTION_CLOSE carries a code and a
//      reason, and close_reason() hands both back with from_peer set.
//   2. Nobody answered. A dial that gets no reply is reaped by
//      connection_config_t::handshake_timeout, which exists because the idle
//      timeout is negotiated and so does not exist yet.
//   3. The peer went quiet. Once transport parameters have been exchanged the
//      negotiated idle timeout applies, and it closes the connection silently
//      -- no frame is sent, so the other end learns nothing from it.

#include <chrono>
#include <cstdint>
#include <optional>
#include <print>
#include <string>

#include <vio/operation/udp.h>

#include "quic_common.h"

namespace
{
using namespace std::chrono_literals;
using namespace vio_example;

// The defaults would keep an idle connection for thirty seconds, which is the
// right answer for a program that is not about timeouts and the wrong one for
// this example. Both endpoints offer the same value and each side uses the
// smaller of its own and the peer's.
vio::quic::transport_parameters_t parameters()
{
  auto out = vio::quic::default_transport_parameters();
  out.max_idle_timeout = 1000;
  return out;
}

std::string describe(const vio::quic::connection_t &connection)
{
  const auto reason = connection.close_reason();
  if (!reason)
  {
    return "closed with nothing recorded";
  }
  return std::format("{} error {}{}", reason->from_peer ? "peer sent" : "we sent", reason->error_code, reason->reason.empty() ? std::string{} : std::format(" (\"{}\")", reason->reason));
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

      tls_config_t server_tls;
      server_tls.role = tls_role_t::server;
      server_tls.certificate_chain_pem = identity.certificate_pem;
      server_tls.private_key_pem = identity.private_key_pem;
      server_tls.alpn = {"vio-close"};
      auto server_context = tls_context_t::create(server_tls);
      if (!server_context)
      {
        std::println(stderr, "server tls_context_t::create failed: {}", server_context.error().msg);
        co_return 1;
      }

      tls_config_t client_tls;
      client_tls.role = tls_role_t::client;
      client_tls.ca_certificates_pem = identity.certificate_pem;
      client_tls.alpn = {"vio-close"};
      auto client_context = tls_context_t::create(client_tls);
      if (!client_context)
      {
        std::println(stderr, "client tls_context_t::create failed: {}", client_context.error().msg);
        co_return 1;
      }

      endpoint_config_t server_config;
      server_config.connection.role = tls_role_t::server;
      server_config.connection.transport_parameters = parameters();
      // How long a closed connection is kept, so a packet still in flight meets
      // silence rather than a stateless reset. Shortened here only so the
      // example can watch a connection actually disappear.
      server_config.draining_period = 250ms;
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

      // A server can only reach its connections from inside a callback:
      // on_connection and on_activity hand out a reference, connection_handle_t
      // can only be minted by connect(), and there is no enumeration. So this
      // is the only place the server side can observe an ending at all.
      std::string server_saw;
      server->on_activity(
        [&server_saw](connection_t &connection)
        {
          for (const auto id : connection.readable_streams())
          {
            auto readable = connection.readable_stream(id);
            connection.consume_stream(id, readable.size());
          }
          if (connection.state() == connection_state_t::closing || connection.state() == connection_state_t::closed)
          {
            if (server_saw.empty())
            {
              server_saw = describe(connection);
            }
          }
        });

      endpoint_config_t client_config;
      client_config.connection.role = tls_role_t::client;
      client_config.connection.transport_parameters = parameters();
      // The one timeout that covers a handshake. The negotiated idle timeout
      // cannot: it does not exist until the peer's transport parameters have
      // arrived, so without this a dial that is never answered is held for the
      // life of the process.
      client_config.connection.handshake_timeout = 1s;
      client_config.draining_period = 250ms;
      auto client_created = endpoint_t::create(loop, *client_context, client_config);
      if (!client_created)
      {
        std::println(stderr, "client endpoint_t::create failed: {}", client_created.error().msg);
        co_return 1;
      }
      std::optional<endpoint_t> client(std::move(*client_created));

      cancellation_t server_cancel;
      cancellation_t client_cancel;
      auto server_run = [](endpoint_t &endpoint, cancellation_t &cancel) -> detached_task_t { co_await endpoint.run(&cancel); }(*server, server_cancel);
      auto client_run = [](endpoint_t &endpoint, cancellation_t &cancel) -> detached_task_t { co_await endpoint.run(&cancel); }(*client, client_cancel);
      (void)server_run;
      (void)client_run;

      const auto target = ip4_addr("127.0.0.1", *port);

      // ---- 1. the peer closed, and said why ----
      {
        std::println("1. an application close, with a code and a reason");
        auto dialled = client->connect(reinterpret_cast<const sockaddr *>(&*target), "localhost");
        if (!dialled)
        {
          std::println(stderr, "   connect failed: {}", dialled.error().msg);
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
        if (auto *live = client->connection(*dialled); live != nullptr)
        {
          // application == true puts the code in the application's numbering
          // rather than the transport's; 42 means whatever this protocol says.
          live->close(42, "that is all", true);
        }
        // The frame is only queued by close(); it goes out on the next pass of
        // the run loop.
        for (int attempt = 0; attempt < 200 && server_saw.empty(); ++attempt)
        {
          co_await sleep(loop, 5ms);
        }
        std::println("   server: {}", server_saw.empty() ? "never saw the close" : server_saw);

        // And on the closing side the same question has a different answer,
        // because this end is the one that sent it.
        if (auto *live = client->connection(*dialled); live != nullptr)
        {
          std::println("   client: {}", describe(*live));
        }
        else
        {
          std::println("   client: the endpoint has already collected it");
        }
      }

      // ---- 2. nobody answered ----
      //
      // A UDP socket that is bound and never read, so the Initials reach a real
      // port and are simply swallowed. Dialling a CLOSED port would be a
      // weaker demonstration: the ICMP port-unreachable that comes back could
      // end the attempt early, and what is being shown here is the timeout.
      std::optional<udp_t> black_hole;
      {
        std::println("2. a dial to somewhere that never answers");
        auto socket = udp_create(loop);
        auto any = ip4_addr("127.0.0.1", 0);
        if (!socket || !any || !udp_bind(*socket, reinterpret_cast<const sockaddr *>(&*any)))
        {
          std::println(stderr, "   could not open the silent socket");
          co_return 1;
        }
        black_hole.emplace(std::move(*socket));
        auto name = udp_sockname(*black_hole);
        if (!name)
        {
          std::println(stderr, "   could not read the silent socket's port");
          co_return 1;
        }
        const auto silent_port = ntohs(reinterpret_cast<const sockaddr_in *>(&*name)->sin_port);
        const auto nowhere = ip4_addr("127.0.0.1", silent_port);
        auto dialled = client->connect(reinterpret_cast<const sockaddr *>(&*nowhere), "localhost");
        if (!dialled)
        {
          std::println(stderr, "   connect failed: {}", dialled.error().msg);
          co_return 1;
        }
        // Nothing reports this. The only way to learn that a dial failed is to
        // keep asking the endpoint whether the connection is still there, and
        // to give up when it is not -- which is also what a collected
        // connection looks like, so the two are the same observation.
        bool gone = false;
        connection_state_t last = connection_state_t::handshaking;
        for (int attempt = 0; attempt < 600; ++attempt)
        {
          auto *live = client->connection(*dialled);
          if (live == nullptr)
          {
            gone = true;
            break;
          }
          last = live->state();
          co_await sleep(loop, 5ms);
        }
        std::println("   client: {}", gone ? "the endpoint reaped it after handshake_timeout" : std::format("still in state {}", static_cast<int>(last)));
      }

      // ---- 3. the peer went quiet ----
      {
        std::println("3. an idle timeout, which closes silently");
        server_saw.clear();
        auto dialled = client->connect(reinterpret_cast<const sockaddr *>(&*target), "localhost");
        if (!dialled)
        {
          std::println(stderr, "   connect failed: {}", dialled.error().msg);
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
        std::println("   connected; now neither side says anything for a second");

        bool gone = false;
        for (int attempt = 0; attempt < 800; ++attempt)
        {
          if (client->connection(*dialled) == nullptr)
          {
            gone = true;
            break;
          }
          co_await sleep(loop, 5ms);
        }
        // No CONNECTION_CLOSE is sent for an idle timeout -- section 10.1 says
        // the connection is simply discarded -- so the server learns nothing
        // and its own idle timeout has to reap its side independently.
        std::println("   client: {}", gone ? "reaped by the idle timeout, with no frame sent" : "still here");
        std::println("   server: {}", server_saw.empty() ? "was told nothing, as expected" : server_saw);
      }

      co_await sleep(loop, 50ms);
      client_cancel.cancel();
      server_cancel.cancel();
      co_await sleep(loop, 50ms);
      // The silent socket is a vio handle like any other: dropping it only
      // requests uv_close, and the close callback needs a live event loop to
      // run on. It has to go here, with the endpoints, and not be left to the
      // end of the coroutine.
      black_hole.reset();
      client.reset();
      server.reset();
      co_await sleep(loop, 50ms);

      co_return 0;
    });
}
