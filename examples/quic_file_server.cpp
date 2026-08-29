// Request/response over QUIC: three files fetched at once, each on its own
// stream, over one connection.
//
// This is the shape most applications actually want, and it is where QUIC
// earns its keep -- the three transfers are independent, so the 900 KB one
// cannot delay the 4 KB one the way it would over a single TCP connection.
//
// Two things worth watching here that quic_echo.cpp does not show. Nothing in
// this program paces the sender: the whole body goes into write_stream in one
// call and the transport puts it on the wire as the peer's flow control opens.
// And the server keeps its own map from stream id to per-request state,
// because the API has no per-stream object and no way to enumerate the streams
// a peer has opened.

#include <chrono>
#include <cstdint>
#include <map>
#include <optional>
#include <print>
#include <string>
#include <vector>

#include "quic_common.h"

namespace
{
using namespace std::chrono_literals;
using namespace vio_example;

// Three "files", made up rather than read from disk so the example has no
// dependency on anything outside itself. The largest is a good fraction of the
// per-stream window the defaults open with, so the transfer is paced by
// MAX_STREAM_DATA arriving rather than by anything this program does.
std::string body_for(const std::string &name)
{
  const std::size_t size = name == "small.txt" ? 4 * 1024 : name == "medium.bin" ? 300 * 1024 : 900 * 1024;
  std::string out;
  out.reserve(size);
  while (out.size() < size)
  {
    out += name;
    out += ' ';
  }
  out.resize(size);
  return out;
}

struct download_t
{
  std::string name;
  std::size_t received = 0;
  bool complete = false;
};
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
      server_tls.alpn = {"vio-files"};
      auto server_context = tls_context_t::create(server_tls);
      if (!server_context)
      {
        std::println(stderr, "server tls_context_t::create failed: {}", server_context.error().msg);
        co_return 1;
      }

      tls_config_t client_tls;
      client_tls.role = tls_role_t::client;
      client_tls.ca_certificates_pem = identity.certificate_pem;
      client_tls.alpn = {"vio-files"};
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

      // A request is a name and a newline. Nothing guarantees it arrives in
      // one piece -- a stream is a byte stream, not a message queue -- so what
      // has been taken so far is held per stream until a newline turns up in
      // it. Consuming the bytes and then looking for the newline among only
      // what this call happened to see would lose split requests.
      std::map<std::uint64_t, std::string> partial_requests;
      server->on_activity(
        [&partial_requests](connection_t &connection)
        {
          // The only way to find a stream the peer opened. Note what it is:
          // a list of streams with unread bytes waiting right now, not a list
          // of open streams. A stream whose bytes have all been consumed drops
          // off it, so anything the application still cares about after that
          // has to be remembered here rather than asked for later.
          for (const auto id : connection.readable_streams())
          {
            auto readable = connection.readable_stream(id);
            auto &pending = partial_requests[id];
            pending += text_of(readable);
            connection.consume_stream(id, readable.size());

            const auto newline = pending.find('\n');
            if (newline == std::string::npos)
            {
              continue;
            }
            const std::string name = pending.substr(0, newline);
            partial_requests.erase(id);

            const std::string body = body_for(name);
            // Accepted in full whatever the peer's window is: write_stream
            // queues, and the transport releases it as credit arrives. There
            // is no partial write to handle here and, equally, no way to ask
            // how much is still queued -- so a server sending something it
            // cannot afford to buffer has to bound it some other way.
            (void)connection.write_stream(id, bytes_of(body), true);
            std::println("server: stream {} wants {}, queued {} bytes", id, name, body.size());
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

      std::map<std::uint64_t, download_t> downloads;
      client->on_activity(
        [&downloads](connection_t &connection)
        {
          for (const auto id : connection.readable_streams())
          {
            const auto entry = downloads.find(id);
            if (entry == downloads.end())
            {
              continue;
            }
            auto readable = connection.readable_stream(id);
            entry->second.received += readable.size();
            connection.consume_stream(id, readable.size());
            if (!entry->second.complete && connection.stream_receive_finished(id))
            {
              entry->second.complete = true;
              std::println("client: {} complete, {} bytes", entry->second.name, entry->second.received);
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

      // All three requests are issued before any answer arrives. That is the
      // point: they are three streams on one connection, and the server may
      // answer them in any order.
      const std::vector<std::string> wanted = {"small.txt", "medium.bin", "large.bin"};
      for (const auto &name : wanted)
      {
        auto stream = connection->open_stream(stream_direction_t::bidirectional);
        if (!stream)
        {
          std::println(stderr, "the peer granted no more stream credit");
          co_return 1;
        }
        downloads[*stream] = download_t{.name = name};
        // The request and its FIN go out together. It has to be this way: a
        // FIN carrying no bytes would leave the stream off readable_streams()
        // on the far side, and the server would never see the request end.
        (void)connection->write_stream(*stream, bytes_of(name + "\n"), true);
      }
      (void)client->flush();
      std::println("client: requested {} files on {} streams", wanted.size(), wanted.size());

      const auto everything_arrived = [&downloads, &wanted]
      {
        std::size_t complete = 0;
        for (const auto &entry : downloads)
        {
          complete += entry.second.complete ? 1 : 0;
        }
        return complete == wanted.size();
      };

      for (int attempt = 0; attempt < 2000 && !everything_arrived(); ++attempt)
      {
        co_await sleep(loop, 5ms);
      }

      const bool ok = everything_arrived();
      if (auto *live = client->connection(*dialled); live != nullptr)
      {
        // What the path was measured delivering. On loopback over a transfer
        // this short the estimator has barely sampled anything, so treat it as
        // a demonstration of where the number lives rather than a benchmark.
        std::println("client: {} ({} bytes/s measured)", ok ? "all three arrived" : "gave up waiting", live->delivery_rate());
        live->close(0, "done", true);
      }

      // As in quic_echo.cpp: let the CONNECTION_CLOSE go out, stop the run
      // loops, then close the sockets -- all before vio::run() stops the event
      // loop underneath them.
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
