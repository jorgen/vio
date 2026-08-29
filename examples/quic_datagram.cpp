// Unreliable datagrams over QUIC (RFC 9221): the shape a game or a voice
// stream wants, where a late packet is worse than a lost one.
//
// A DATAGRAM frame rides inside the same encrypted, congestion-controlled
// connection as the streams, so it gets QUIC's handshake, its keys and its
// path -- but a lost one is never retransmitted, and nothing is held back
// waiting for it.
//
// The negotiation is the part that catches people out. It is two-sided and
// asymmetric: the max_datagram_frame_size you put in your own transport
// parameters says what you are willing to RECEIVE, and what you may SEND is
// read back out of the peer's, through max_datagram_payload(). Set it on only
// one side and datagrams flow only one way, with nothing to say why.

#include <chrono>
#include <cstdint>
#include <optional>
#include <print>
#include <string>

#include "quic_common.h"

namespace
{
using namespace std::chrono_literals;
using namespace vio_example;

constexpr int datagram_count = 5;

// The defaults cover everything this example needs except the one line that
// turns the DATAGRAM extension on, so it starts from them rather than
// restating them. A nonzero max_datagram_frame_size is the whole of the
// opt-in, and it stays out of the defaults because it commits an endpoint to a
// receive queue QUIC's flow control does not bound -- read_datagram() is the
// only thing that drains it. The value is a whole-frame limit, not a payload
// limit, which is why max_datagram_payload() comes back smaller.
vio::quic::transport_parameters_t parameters()
{
  auto out = vio::quic::default_transport_parameters();
  out.max_datagram_frame_size = 1200;
  return out;
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
      server_tls.alpn = {"vio-datagram"};
      auto server_context = tls_context_t::create(server_tls);
      if (!server_context)
      {
        std::println(stderr, "server tls_context_t::create failed: {}", server_context.error().msg);
        co_return 1;
      }

      tls_config_t client_tls;
      client_tls.role = tls_role_t::client;
      client_tls.ca_certificates_pem = identity.certificate_pem;
      client_tls.alpn = {"vio-datagram"};
      auto client_context = tls_context_t::create(client_tls);
      if (!client_context)
      {
        std::println(stderr, "client tls_context_t::create failed: {}", client_context.error().msg);
        co_return 1;
      }

      endpoint_config_t server_config;
      server_config.connection.role = tls_role_t::server;
      server_config.connection.transport_parameters = parameters();
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

      // Received datagrams queue in the order they arrived and come out one at
      // a time. Draining the queue to empty on every activity matters: it is
      // the only thing that bounds it, since a DATAGRAM frame is deliberately
      // outside QUIC's flow control.
      std::size_t received = 0;
      server->on_activity(
        [&received](connection_t &connection)
        {
          while (auto datagram = connection.read_datagram())
          {
            const auto text = text_of(*datagram);
            std::println("server: {}", text);
            ++received;
            (void)connection.write_datagram(bytes_of("echo of " + text));
          }
        });

      endpoint_config_t client_config;
      client_config.connection.role = tls_role_t::client;
      client_config.connection.transport_parameters = parameters();
      auto client_created = endpoint_t::create(loop, *client_context, client_config);
      if (!client_created)
      {
        std::println(stderr, "client endpoint_t::create failed: {}", client_created.error().msg);
        co_return 1;
      }
      std::optional<endpoint_t> client(std::move(*client_created));

      std::size_t echoed = 0;
      client->on_activity(
        [&echoed](connection_t &connection)
        {
          while (auto datagram = connection.read_datagram())
          {
            std::println("client: {}", text_of(*datagram));
            ++echoed;
          }
        });

      cancellation_t server_cancel;
      cancellation_t client_cancel;
      auto server_run = [](endpoint_t &endpoint, cancellation_t &cancel) -> detached_task_t { co_await endpoint.run(&cancel); }(*server, server_cancel);
      auto client_run = [](endpoint_t &endpoint, cancellation_t &cancel) -> detached_task_t { co_await endpoint.run(&cancel); }(*client, client_cancel);
      (void)server_run;
      (void)client_run;

      const auto target = ip4_addr("127.0.0.1", *port);
      auto dialled = client->connect(reinterpret_cast<const sockaddr *>(&*target), "localhost");
      if (!dialled)
      {
        std::println(stderr, "connect failed: {}", dialled.error().msg);
        co_return 1;
      }

      connection_t *connection = nullptr;
      for (int attempt = 0; attempt < 400; ++attempt)
      {
        connection = client->connection(*dialled);
        if (connection == nullptr || connection->handshake_complete())
        {
          break;
        }
        co_await sleep(loop, 5ms);
      }
      if (connection == nullptr || !connection->handshake_complete())
      {
        std::println(stderr, "the handshake did not complete");
        co_return 1;
      }

      // Not knowable before the handshake: it is the peer's parameter. Zero
      // would mean the peer does not accept datagrams at all, and every
      // write_datagram would be refused.
      std::println("client: the peer will take datagrams of up to {} bytes", connection->max_datagram_payload());

      for (int index = 0; index < datagram_count; ++index)
      {
        connection = client->connection(*dialled);
        if (connection == nullptr)
        {
          break;
        }
        const std::string tick = "tick " + std::to_string(index);
        // Refused rather than truncated when it will not fit, which is the
        // right call for a frame whose whole point is that it arrives intact
        // or not at all.
        if (!connection->write_datagram(bytes_of(tick)))
        {
          std::println(stderr, "write_datagram refused \"{}\"", tick);
          co_return 1;
        }
        (void)client->flush();
        co_await sleep(loop, 20ms);
      }

      for (int attempt = 0; attempt < 200 && echoed < datagram_count; ++attempt)
      {
        co_await sleep(loop, 5ms);
      }

      // On loopback nothing is lost, so all five arrive. Over a real path some
      // would not, and that is the contract rather than a failure: a datagram
      // the connection loses is gone, and no retransmission will bring it.
      std::println("sent {}, the server saw {}, {} came back", datagram_count, received, echoed);

      if (auto *live = client->connection(*dialled); live != nullptr)
      {
        live->close(0, "done", true);
      }
      co_await sleep(loop, 50ms);
      client_cancel.cancel();
      server_cancel.cancel();
      co_await sleep(loop, 50ms);
      client.reset();
      server.reset();
      co_await sleep(loop, 50ms);

      co_return echoed == datagram_count ? 0 : 1;
    });
}
