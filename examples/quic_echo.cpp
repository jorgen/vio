// The smallest complete QUIC program: a server and a client in one process,
// talking over a real UDP socket on loopback, exchanging one message on one
// stream.
//
// Read this one first. The other QUIC examples assume the four things it
// establishes: that a QUIC endpoint owns a socket and many connections, that
// it is driven by a coroutine you spawn and never await, that an application
// hears about arriving data through on_activity rather than by reading, and
// that shutting down has an order to it.

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
} // namespace

int main()
{
  return vio::run(
    [](vio::event_loop_t &loop) -> vio::task_t<int>
    {
      using namespace vio;
      using namespace vio::quic;

      // QUIC has no unencrypted mode, so the certificate comes before
      // anything else. Both sides are given the same PEM: the server as its
      // identity, the client as the one certificate it trusts.
      const auto identity = make_self_signed("localhost");

      tls_config_t server_tls;
      server_tls.role = tls_role_t::server;
      server_tls.certificate_chain_pem = identity.certificate_pem;
      server_tls.private_key_pem = identity.private_key_pem;
      // ALPN is not optional in QUIC the way it is in TLS over TCP: a
      // handshake with no protocol in common is refused.
      server_tls.alpn = {"vio-echo"};
      auto server_context = tls_context_t::create(server_tls);
      if (!server_context)
      {
        std::println(stderr, "server tls_context_t::create failed: {}", server_context.error().msg);
        co_return 1;
      }

      tls_config_t client_tls;
      client_tls.role = tls_role_t::client;
      client_tls.ca_certificates_pem = identity.certificate_pem;
      client_tls.alpn = {"vio-echo"};
      auto client_context = tls_context_t::create(client_tls);
      if (!client_context)
      {
        std::println(stderr, "client tls_context_t::create failed: {}", client_context.error().msg);
        co_return 1;
      }

      endpoint_config_t server_config;
      // The role is set twice -- once on the TLS context above, once here --
      // and nothing checks that the two agree.
      server_config.connection.role = tls_role_t::server;

      auto server_created = endpoint_t::create(loop, *server_context, server_config);
      if (!server_created)
      {
        std::println(stderr, "server endpoint_t::create failed: {}", server_created.error().msg);
        co_return 1;
      }
      // Held in an optional so the socket can be closed at a moment of this
      // program's choosing. See the teardown at the bottom for why that
      // matters.
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

      // Called after a batch of arriving datagrams has been processed and
      // before anything is sent, so whatever is written here rides out with
      // the acknowledgement that was going to be sent anyway.
      //
      // readable_streams() is the only way to find a stream the peer opened.
      // It lists streams that have bytes waiting right now -- which is why an
      // echo server can be written this way and a request/response server
      // cannot; quic_file_server.cpp shows the difference.
      server->on_activity(
        [](connection_t &connection)
        {
          for (const auto id : connection.readable_streams())
          {
            auto readable = connection.readable_stream(id);
            std::println("server: stream {} carried \"{}\"", id, text_of(readable));
            // A stream is a byte stream, so this may be only part of what the
            // client sent. The echo carries a FIN only once the client has
            // finished sending -- setting it on the first chunk would close
            // the sending half and silently drop everything after it.
            const bool last = connection.stream_receive_finished(id);
            // write_stream copies, so the span is still good to send back even
            // though consume_stream below invalidates it.
            (void)connection.write_stream(id, readable, last);
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

      std::string echoed;
      bool echo_finished = false;
      client->on_activity(
        [&echoed, &echo_finished](connection_t &connection)
        {
          for (const auto id : connection.readable_streams())
          {
            auto readable = connection.readable_stream(id);
            echoed += text_of(readable);
            connection.consume_stream(id, readable.size());
            // True for a clean end of stream and for a peer that reset it;
            // the two are not distinguishable through this API.
            if (connection.stream_receive_finished(id))
            {
              echo_finished = true;
            }
          }
        });

      // run() is the whole endpoint: it reads the socket, demultiplexes by
      // connection ID, runs QUIC's timers and sends what is owed. It never
      // returns until cancelled, so it cannot be awaited here -- and its
      // task_t must be kept alive, because a task_t destroyed while suspended
      // leaks its frame. detached_task_t is the wrapper that does both.
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

      // connect() returns as soon as the first Initial is queued; the
      // handshake is several round trips after that. There is nothing to
      // await, so the only way to wait for it is to poll.
      //
      // The connection is looked up each time round rather than kept: the
      // endpoint owns it and may collect it -- an idle timeout, a peer that
      // stopped answering, a handshake that never finished -- at any point
      // this coroutine is suspended.
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
      std::println("client: handshake complete, negotiated \"{}\"", connection->selected_alpn());

      // Nothing here fails when the peer's stream limit is reached: it simply
      // yields nothing, and the caller is expected to try again later.
      auto stream = connection->open_stream(stream_direction_t::bidirectional);
      if (!stream)
      {
        std::println(stderr, "the peer granted no stream credit");
        co_return 1;
      }

      const std::string message = "hello over quic";
      // The FIN goes with the data: this is the whole of what the client has
      // to say on this stream.
      (void)connection->write_stream(*stream, bytes_of(message), true);
      // Written outside the run loop, so it has to be pushed onto the socket
      // by hand rather than waiting for the next thing that happens.
      (void)client->flush();
      std::println("client: sent \"{}\" on stream {}", message, *stream);

      for (int attempt = 0; attempt < 400 && !echo_finished; ++attempt)
      {
        co_await sleep(loop, 5ms);
      }
      std::println("client: received \"{}\"", echoed);

      // Telling the peer why, rather than letting it discover the silence
      // when its idle timeout expires.
      if (auto *live = client->connection(*dialled); live != nullptr)
      {
        live->close(0, "done", true);
      }
      // The CONNECTION_CLOSE is only queued; it goes out on the next pass of
      // the run loop, which is why this waits before cancelling it.
      co_await sleep(loop, 50ms);

      // The order below is the one thing about this program that is not
      // obvious and cannot be got wrong quietly.
      //
      // Cancelling stops each run() loop. Destroying the endpoints closes
      // their sockets -- and both must happen before vio::run() stops the
      // event loop, because stop() runs the loop until nothing is open, so a
      // socket still live at that point is a loop that never returns. The
      // endpoints must also outlive their run() coroutines, which hold
      // references to them, which is what the waits are for.
      client_cancel.cancel();
      server_cancel.cancel();
      co_await sleep(loop, 50ms);
      client.reset();
      server.reset();
      co_await sleep(loop, 50ms);

      co_return echoed == message ? 0 : 1;
    });
}
