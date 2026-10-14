// The smallest complete QUIC program: a server and a client in one process,
// talking over a real UDP socket on loopback, exchanging one message on one
// stream.
//
// Read this one first. The other QUIC examples assume the three things it
// establishes: that a QUIC endpoint owns a socket and many connections, that
// every step of using one is something you await, and that a stream's ending
// arrives as an ordinary result rather than a flag to test on the side.
//
// Nothing here polls, spawns a run loop, or flushes anything by hand. The
// endpoint drives itself; a coroutine that has something to wait for says
// co_await and is resumed when it has arrived.

#include <print>
#include <string>

#include "quic_common.h"

namespace
{
using namespace vio_example;
} // namespace

int main()
{
  return vio::run(
    [](vio::event_loop_t &loop) -> vio::task_t<int>
    {
      using namespace vio;
      using namespace vio::quic;

      // QUIC has no unencrypted mode, so the certificate comes before anything
      // else. Both sides are given the same PEM: the server as its identity,
      // the client as the one certificate it trusts.
      const auto identity = make_self_signed("localhost");

      tls_config_t server_tls;
      server_tls.role = tls_role_t::server;
      server_tls.certificate_chain_pem = identity.certificate_pem;
      server_tls.private_key_pem = identity.private_key_pem;
      // ALPN is not optional in QUIC the way it is in TLS over TCP: a handshake
      // with no protocol in common is refused.
      server_tls.alpn = {"vio-echo"};
      auto server_context = tls_context_t::create(server_tls);
      if (!server_context)
      {
        std::println(stderr, "server tls_context_t::create: {}", server_context.error().msg);
        co_return 1;
      }

      tls_config_t client_tls;
      client_tls.role = tls_role_t::client;
      client_tls.ca_certificates_pem = identity.certificate_pem;
      client_tls.alpn = {"vio-echo"};
      auto client_context = tls_context_t::create(client_tls);
      if (!client_context)
      {
        std::println(stderr, "client tls_context_t::create: {}", client_context.error().msg);
        co_return 1;
      }

      // Nothing configures flow control here, and that is the point:
      // connection_config_t starts from default_transport_parameters(), so an
      // endpoint told nothing already grants 8 MiB across the connection and
      // 2 MiB per stream.
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

      // The server, as its own coroutine. It is started here and awaited at the
      // bottom; between those two points it runs whenever it has something to
      // do, driven by the endpoint rather than by this function.
      auto serving = [](quic_endpoint_t &endpoint) -> vio::task_t<void>
      {
        auto connection = co_await quic_endpoint_accept(endpoint);
        if (!connection)
        {
          std::println(stderr, "accept: {}", connection.error().msg);
          co_return;
        }
        std::println("server: accepted a connection, protocol \"{}\"", quic_connection_alpn(*connection));

        auto stream = co_await quic_accept_stream(*connection);
        if (!stream)
        {
          std::println(stderr, "accept_stream: {}", stream.error().msg);
          co_return;
        }

        auto reader = quic_stream_create_reader(*stream);
        if (!reader)
        {
          std::println(stderr, "create_reader: {}", reader.error().msg);
          co_return;
        }

        // A stream is a byte stream, so what the client sent may arrive in
        // pieces. The loop ends when the read fails, and the failure says which
        // ending it was -- a clean FIN or a peer that gave up.
        std::string request;
        while (true)
        {
          auto chunk = co_await *reader;
          if (!chunk)
          {
            if (chunk.error().code != vio_quic_stream_finished)
            {
              std::println(stderr, "server: the client abandoned the stream: {}", chunk.error().msg);
              co_return;
            }
            break;
          }
          request += text_of(*chunk);
        }
        std::println("server: read \"{}\"", request);

        // The FIN rides with the bytes it terminates, which costs no packet and
        // leaves no window in which the client has the last chunk without
        // knowing it was the last.
        if (auto written = co_await quic_stream_write_final(*stream, bytes_of(request)); !written)
        {
          std::println(stderr, "server: write: {}", written.error().msg);
        }
      }(*server);

      const auto target = ip4_addr("127.0.0.1", port);
      if (!target)
      {
        std::println(stderr, "could not build the target address");
        co_return 1;
      }

      // Connected means what it means for ssl_client_connect: the certificate
      // has verified, an ALPN has been agreed and the peer's transport
      // parameters have arrived. There is nothing to poll for.
      auto connection = co_await quic_endpoint_connect(*client, reinterpret_cast<const sockaddr *>(&*target), "localhost");
      if (!connection)
      {
        std::println(stderr, "quic_endpoint_connect: {}", connection.error().msg);
        co_return 1;
      }
      std::println("client: connected");

      // This suspends only if the server has granted no stream credit, which it
      // has: section 4.6 forbids exceeding the limit, so waiting is the only
      // correct thing to do and the API does it rather than handing back
      // nothing and leaving a retry loop to write.
      auto stream = co_await quic_open_stream(*connection);
      if (!stream)
      {
        std::println(stderr, "quic_open_stream: {}", stream.error().msg);
        co_return 1;
      }

      const std::string message = "hello over quic";
      if (auto written = co_await quic_stream_write_final(*stream, bytes_of(message)); !written)
      {
        std::println(stderr, "quic_stream_write_final: {}", written.error().msg);
        co_return 1;
      }
      std::println("client: sent \"{}\" on stream {}", message, quic_stream_id(*stream));

      auto reader = quic_stream_create_reader(*stream);
      if (!reader)
      {
        std::println(stderr, "quic_stream_create_reader: {}", reader.error().msg);
        co_return 1;
      }

      std::string echoed;
      while (true)
      {
        auto chunk = co_await *reader;
        if (!chunk)
        {
          break;
        }
        echoed += text_of(*chunk);
      }
      std::println("client: received \"{}\"", echoed);

      co_await std::move(serving);

      // Telling the peer why, rather than letting it discover the silence when
      // its idle timeout expires. The CONNECTION_CLOSE leaves on this turn, so
      // dropping the handle immediately afterwards is safe.
      quic_connection_close(*connection, 0, "done");
      co_return echoed == message ? 0 : 1;
    });
}
