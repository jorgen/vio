// Request/response over QUIC: three files fetched at once, each on its own
// stream, over one connection.
//
// This is the shape most applications actually want, and it is where QUIC earns
// its keep -- the three transfers are independent, so the 900 KB one cannot
// delay the 4 KB one the way it would over a single TCP connection.
//
// It is also the example that changed most when the coroutine API arrived, and
// the diff is the argument for it. Both sides used to keep a std::map from
// stream id to per-request state, because the old surface reported *levels*
// (which streams have unread bytes right now) rather than *events*, and a
// stream whose bytes had all been consumed simply dropped off the list. A
// request split across two packets had to be reassembled by hand into a map
// entry keyed by id.
//
// Now a stream is an object with a lifetime, and each request is a coroutine
// that owns its own partial buffer as a local. There is no map on either side.

#include <cstddef>
#include <utility>
#include <cstdint>
#include <print>
#include <string>
#include <vector>

#include "quic_common.h"

namespace
{
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

// One request, from the first byte of its name to the last byte of its body.
//
// The partial buffer is a local, which is the whole point: a request is a name
// and a newline, and nothing guarantees it arrives in one piece -- a stream is a
// byte stream, not a message queue.
vio::task_t<void> handle_request(vio::quic_stream_t stream)
{
  using namespace vio;
  auto reader = quic_stream_create_reader(stream);
  if (!reader)
  {
    co_return;
  }

  std::string pending;
  std::string name;
  while (name.empty())
  {
    auto chunk = co_await *reader;
    if (!chunk)
    {
      co_return; // the client gave up before it finished asking
    }
    pending += text_of(*chunk);
    if (const auto newline = pending.find('\n'); newline != std::string::npos)
    {
      name = pending.substr(0, newline);
    }
  }

  const std::string body = body_for(name);
  std::println("server: stream {} wants {}, sending {} bytes", quic_stream_id(stream), name, body.size());
  // Accepted in full whatever the peer's window is: the transport queues it and
  // releases it as credit arrives. Writes are not yet bounded by a high-water
  // mark, so a server sending something it cannot afford to buffer still has to
  // bound it some other way -- see quic_bulk_transfer.cpp.
  if (auto written = co_await quic_stream_write_final(stream, bytes_of(body)); !written)
  {
    std::println(stderr, "server: stream {}: {}", quic_stream_id(stream), written.error().msg);
  }
}

// Accepts streams for the life of one connection, and runs each request beside
// the others rather than one after another. That concurrency is the feature: a
// server that awaited each request in turn would serialise exactly what QUIC
// exists to keep independent.
vio::task_t<void> serve(vio::quic_connection_t connection, std::size_t expected)
{
  using namespace vio;
  std::vector<task_t<void>> requests;
  requests.reserve(expected);
  for (std::size_t taken = 0; taken < expected; ++taken)
  {
    auto stream = co_await quic_accept_stream(connection);
    if (!stream)
    {
      break;
    }
    requests.push_back(handle_request(*stream));
  }
  for (auto &request : requests)
  {
    co_await std::move(request);
  }
}

// One download, counted rather than kept, since the bytes themselves are not
// the point.
vio::task_t<std::size_t> fetch(vio::quic_connection_t connection, std::string name)
{
  using namespace vio;
  auto stream = co_await quic_open_stream(connection);
  if (!stream)
  {
    std::println(stderr, "client: {}: {}", name, stream.error().msg);
    co_return 0;
  }
  if (auto written = co_await quic_stream_write_final(*stream, bytes_of(name + "\n")); !written)
  {
    std::println(stderr, "client: {}: {}", name, written.error().msg);
    co_return 0;
  }

  auto reader = quic_stream_create_reader(*stream);
  if (!reader)
  {
    co_return 0;
  }
  // read_into rather than the owning read: the bytes are counted and thrown
  // away, so there is no reason to allocate a buffer per chunk. Zero is the
  // clean end of the stream, the same convention tcp_reader_t::read_into uses;
  // a reset would come back as an error instead.
  std::vector<std::uint8_t> scratch(64 * 1024);
  std::size_t received = 0;
  while (true)
  {
    auto taken = co_await reader->read_into(scratch);
    if (!taken)
    {
      std::println(stderr, "client: {} ended early: {}", name, taken.error().msg);
      break;
    }
    if (*taken == 0)
    {
      break;
    }
    received += *taken;
  }
  std::println("client: {} complete, {} bytes", name, received);
  co_return std::move(received);
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
      server_tls.alpn = {"vio-files"};
      auto server_context = tls_context_t::create(server_tls);

      tls_config_t client_tls;
      client_tls.role = tls_role_t::client;
      client_tls.ca_certificates_pem = identity.certificate_pem;
      client_tls.alpn = {"vio-files"};
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

      const std::vector<std::string> names = {"small.txt", "medium.bin", "large.dat"};

      auto serving = [](quic_endpoint_t &endpoint, std::size_t expected) -> task_t<void>
      {
        auto connection = co_await quic_endpoint_accept(endpoint);
        if (!connection)
        {
          co_return;
        }
        co_await serve(*connection, expected);
      }(*server, names.size());

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

      // All three at once, on one connection. Started here and awaited below,
      // so they are genuinely concurrent -- which is the property being shown,
      // and the reason the small file finishes first despite being asked for
      // first alongside a file two hundred times its size.
      std::vector<task_t<std::size_t>> downloads;
      downloads.reserve(names.size());
      for (const auto &name : names)
      {
        downloads.push_back(fetch(*connection, name));
      }

      std::size_t total = 0;
      for (auto &download : downloads)
      {
        total += co_await std::move(download);
      }
      co_await std::move(serving);

      const std::size_t expected = body_for("small.txt").size() + body_for("medium.bin").size() + body_for("large.dat").size();
      std::println("client: {} bytes over {} streams", total, names.size());
      quic_connection_close(*connection, 0, "done");
      co_return total == expected ? 0 : 1;
    });
}
