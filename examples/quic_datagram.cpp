// Unreliable datagrams over QUIC (RFC 9221): the shape a game or a voice
// stream wants, where a late packet is worse than a lost one.
//
// A DATAGRAM frame rides inside the same encrypted, congestion-controlled
// connection as the streams, so it gets QUIC's handshake, its keys and its path
// -- but a lost one is never retransmitted, and nothing is held back waiting for
// it.
//
// The negotiation is the part that catches people out. It is two-sided and
// asymmetric: the max_datagram_frame_size you put in your own transport
// parameters says what you are willing to RECEIVE, and what you may SEND is
// read back out of the peer's, through max_datagram_payload(). Set it on only
// one side and datagrams flow only one way, with nothing to say why.
//
// This is also the one example still reaching through quic_connection_native(),
// and it is worth being clear about why rather than leaving it to be noticed.
// The coroutine layer wraps endpoints, connections and streams; datagrams are
// the next piece of it. Everything about *this* connection -- creating it,
// dialling, accepting, closing -- is coroutine, and the three datagram calls
// below are the transport's own, taken through the accessor that exists for
// exactly this. What that costs is visible: there is no datagram to await, so
// the receive loops here poll, which is the one thing every other example in
// this directory no longer does.

#include <chrono>
#include <cstdint>
#include <print>
#include <string>

#include "quic_common.h"

namespace
{
using namespace std::chrono_literals;
using namespace vio_example;

constexpr int datagram_count = 5;

// The defaults cover everything this example needs except the one line that
// turns the DATAGRAM extension on, so it starts from them rather than restating
// them. A nonzero max_datagram_frame_size is the whole of the opt-in, and it
// stays out of the defaults because it commits an endpoint to a receive queue
// QUIC's flow control does not bound -- read_datagram() is the only thing that
// drains it. The value is a whole-frame limit, not a payload limit, which is
// why max_datagram_payload() comes back smaller.
vio::quic::transport_parameters_t parameters()
{
  auto out = vio::quic::default_transport_parameters();
  out.max_datagram_frame_size = 1200;
  return out;
}

// Reads whatever has arrived and echoes each one back with a prefix. Received
// datagrams queue in the order they arrived and come out one at a time, so this
// drains rather than taking one.
int drain_and_echo(vio::quic_connection_t &connection, const char *who, bool echo)
{
  auto *native = vio::quic_connection_native(connection);
  if (native == nullptr)
  {
    return 0;
  }
  int seen = 0;
  while (auto datagram = native->read_datagram())
  {
    const auto text = text_of(*datagram);
    std::println("{}: {}", who, text);
    ++seen;
    if (echo)
    {
      (void)native->write_datagram(bytes_of("echo of " + text));
    }
  }
  return seen;
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

      tls_config_t client_tls;
      client_tls.role = tls_role_t::client;
      client_tls.ca_certificates_pem = identity.certificate_pem;
      client_tls.alpn = {"vio-datagram"};
      auto client_context = tls_context_t::create(client_tls);
      if (!server_context || !client_context)
      {
        std::println(stderr, "tls_context_t::create failed");
        co_return 1;
      }

      quic_config_t config;
      config.transport.connection.transport_parameters = parameters();

      auto server = quic_endpoint_create(loop, *server_context, config);
      auto client = quic_endpoint_create(loop, nullptr, &*client_context, config);
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

      int received = 0;
      auto serving = [](quic_endpoint_t &endpoint, event_loop_t &loop, int &received) -> task_t<void>
      {
        auto connection = co_await quic_endpoint_accept(endpoint);
        if (!connection)
        {
          co_return;
        }
        // Polled, because there is nothing here to await yet.
        while (received < datagram_count && quic_connection_is_open(*connection))
        {
          received += drain_and_echo(*connection, "server", true);
          (void)co_await sleep(loop, 5ms);
        }
        received += drain_and_echo(*connection, "server", true);
      }(*server, loop, received);

      const auto target = ip4_addr("127.0.0.1", port);
      if (!target)
      {
        std::println(stderr, "could not build the target address");
        co_return 1;
      }
      auto connection = co_await quic_endpoint_connect(*client, reinterpret_cast<const sockaddr *>(&*target), "localhost");
      if (!connection)
      {
        std::println(stderr, "quic_endpoint_connect: {}", connection.error().msg);
        co_return 1;
      }

      auto *native = quic_connection_native(*connection);
      // What the peer offered, minus the frame's own header. Zero would mean
      // the peer does not accept datagrams at all, and every write_datagram
      // would be refused.
      std::println("client: the peer will take datagrams of up to {} bytes", native->max_datagram_payload());

      for (int index = 0; index < datagram_count; ++index)
      {
        const std::string tick = std::format("tick {}", index);
        // Refused rather than truncated when the peer offered no room or too
        // little, which is the only honest answer: a datagram is a message, and
        // half of one is not a shorter message.
        if (!native->write_datagram(bytes_of(tick)))
        {
          std::println(stderr, "write_datagram refused \"{}\"", tick);
          co_return 1;
        }
        (void)co_await sleep(loop, 20ms);
      }

      int echoed = 0;
      for (int attempt = 0; attempt < 200 && echoed < datagram_count; ++attempt)
      {
        echoed += drain_and_echo(*connection, "client", false);
        (void)co_await sleep(loop, 5ms);
      }

      co_await std::move(serving);

      // On a real path some of these would not arrive, and that is the contract
      // rather than a failure: a datagram that is lost is simply gone, and
      // nothing waits for it.
      std::println("sent {}, the server saw {}, {} came back", datagram_count, received, echoed);
      quic_connection_close(*connection, 0, "done");
      co_return echoed == datagram_count ? 0 : 1;
    });
}
