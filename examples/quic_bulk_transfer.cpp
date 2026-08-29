// Sending more than fits in memory, and the backpressure you have to build
// yourself to do it.
//
// This is the most important example here for real work, because it is about
// something the API does not give you. write_stream() copies the whole span
// onto an in-memory queue and returns data.size() whatever the size is: the
// peer's flow control limit and the congestion window are consulted much
// later, when a packet is built. So an application that feeds a stream faster
// than the path drains it grows the process without bound, and connection_t
// offers no query to stop it -- there is no "how much is still queued", no
// "how much has been acknowledged", no high-water mark. vio's own TCP and TLS
// paths have all of that; QUIC has none of it.
//
// So the sender below meters itself, and the only material it has to do that
// with is an acknowledgement the receiver sends back up the other half of the
// same bidirectional stream. That is the workaround: reimplement, at the
// application layer, the acknowledgement the transport underneath is already
// doing. It works -- this moves 8 MiB and never holds more than the window
// unacknowledged -- but nothing about it should have been necessary.

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <optional>
#include <print>
#include <string>
#include <vector>

#include "quic_common.h"

namespace
{
using namespace std::chrono_literals;
using namespace vio_example;

constexpr std::uint64_t total_bytes = 8ULL * 1024 * 1024;
constexpr std::uint64_t window_bytes = 256ULL * 1024;
constexpr std::size_t chunk_bytes = 32 * 1024;

// The receiver's acknowledgement: how many bytes it has taken so far, as
// decimal digits and a newline, sent back up its own half of the stream.
std::string progress_line(std::uint64_t received)
{
  return std::to_string(received) + "\n";
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
      server_tls.alpn = {"vio-bulk"};
      auto server_context = tls_context_t::create(server_tls);
      if (!server_context)
      {
        std::println(stderr, "server tls_context_t::create failed: {}", server_context.error().msg);
        co_return 1;
      }

      tls_config_t client_tls;
      client_tls.role = tls_role_t::client;
      client_tls.ca_certificates_pem = identity.certificate_pem;
      client_tls.alpn = {"vio-bulk"};
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

      // The receiver. It consumes everything offered and reports its running
      // total back up the other half of the same stream -- which is the
      // sender's only source of backpressure.
      std::uint64_t received = 0;
      server->on_activity(
        [&received](connection_t &connection)
        {
          for (const auto id : connection.readable_streams())
          {
            auto readable = connection.readable_stream(id);
            if (readable.empty())
            {
              continue;
            }
            received += readable.size();
            // Consuming is what returns flow control credit to the peer: the
            // window is extended once it has been half used, so a receiver
            // that reads promptly never stalls the sender.
            connection.consume_stream(id, readable.size());
            (void)connection.write_stream(id, bytes_of(progress_line(received)), false);
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

      const std::vector<std::uint8_t> body(chunk_bytes, std::uint8_t{0xab});
      std::uint64_t offered = 0;
      std::uint64_t acknowledged = 0;
      std::uint64_t peak_outstanding = 0;
      std::string acknowledgements;
      std::optional<std::uint64_t> transfer;

      // The sender, run from the receive callback so that every acknowledgement
      // immediately releases more. Nothing here can ask the transport how much
      // it is holding, so `offered - acknowledged` -- a number this program
      // maintains itself -- is the only bound available.
      client->on_activity(
        [&](connection_t &connection)
        {
          if (!transfer)
          {
            return;
          }
          for (const auto id : connection.readable_streams())
          {
            auto readable = connection.readable_stream(id);
            acknowledgements += text_of(readable);
            connection.consume_stream(id, readable.size());
          }
          // Only the most recent complete line matters; it is a running total,
          // not an increment, so an earlier one carries no information.
          const auto last = acknowledgements.find_last_of('\n');
          if (last != std::string::npos)
          {
            const auto start = acknowledgements.find_last_of('\n', last - 1);
            const auto from = start == std::string::npos ? 0 : start + 1;
            acknowledged = std::strtoull(acknowledgements.substr(from, last - from).c_str(), nullptr, 10);
            acknowledgements.erase(0, last + 1);
          }

          while (offered < total_bytes && offered - acknowledged < window_bytes)
          {
            const auto take = static_cast<std::size_t>((std::min)(static_cast<std::uint64_t>(chunk_bytes), total_bytes - offered));
            const bool last_chunk = offered + take == total_bytes;
            // The return value is all-or-nothing, never a partial count, and
            // zero would mean the stream was already finished or reset rather
            // than "try again later" -- so there is nothing here to retry on.
            if (connection.write_stream(*transfer, std::span(body.data(), take), last_chunk) != take)
            {
              return;
            }
            offered += take;
          }
          peak_outstanding = (std::max)(peak_outstanding, offered - acknowledged);
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

      auto stream = connection->open_stream(stream_direction_t::bidirectional);
      if (!stream)
      {
        std::println(stderr, "the peer granted no stream credit");
        co_return 1;
      }
      transfer = *stream;

      // The first window, written here to start things off; from now on the
      // activity callback above does it, one window at a time.
      while (offered < total_bytes && offered - acknowledged < window_bytes)
      {
        const auto take = static_cast<std::size_t>((std::min)(static_cast<std::uint64_t>(chunk_bytes), total_bytes - offered));
        (void)connection->write_stream(*transfer, std::span(body.data(), take), offered + take == total_bytes);
        offered += take;
      }
      (void)client->flush();
      std::println("client: sending {} bytes, never more than {} unacknowledged", total_bytes, window_bytes);

      for (int attempt = 0; attempt < 6000 && received < total_bytes; ++attempt)
      {
        co_await sleep(loop, 5ms);
      }

      const bool ok = received == total_bytes;
      std::println("server: received {} of {} bytes", received, total_bytes);
      // The number that matters. Without the credit loop this would be the
      // whole 8 MiB, sitting in the transport's send queue at once. It
      // overshoots the window by up to one chunk, because the loop checks the
      // bound before writing rather than splitting a chunk across it.
      std::println("client: peak unacknowledged {} bytes against a {} byte window", peak_outstanding, window_bytes);

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

      co_return ok ? 0 : 1;
    });
}
