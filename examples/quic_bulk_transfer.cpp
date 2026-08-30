// Sending more than fits in memory, and the backpressure you still have to
// build yourself to do it.
//
// This is the most important example here for real work, because it is about
// something the API does not yet do for you. quic_stream_write hands the whole
// span to the transport and resolves at once, whatever the size: the peer's
// flow control limit and the congestion window are consulted much later, when a
// packet is built. So an application that feeds a stream faster than the path
// drains it grows the process without bound.
//
// What has changed, and what has not.
//
// The transport's own accounting is now readable -- quic_stream_stats reports
// bytes_queued, bytes_sent and bytes_acknowledged, and the gap between the
// first and the last is exactly how far ahead of the peer this sender has run.
// That is the number a sender wants to bound, and until recently there was no
// way to see it at all.
//
// What is still missing is the *waiting*. Reading the depth tells you to stop;
// nothing here tells you when to start again, so a sender that metered on the
// statistic alone would have to poll it. So this example does what an
// application has to do today: the receiver acknowledges on the other half of
// the same bidirectional stream, and the sender awaits that. It works -- this
// moves 8 MiB and never holds more than the window unacknowledged -- and the
// write layer that makes quic_stream_write suspend over a high-water mark will
// delete every line of it without moving a call site.

#include <algorithm>
#include <cstdint>
#include <print>
#include <string>
#include <vector>

#include "quic_common.h"

namespace
{
using namespace vio_example;

constexpr std::uint64_t total_bytes = 8ULL * 1024 * 1024;
constexpr std::uint64_t window_bytes = 256ULL * 1024;
constexpr std::size_t chunk_bytes = 32 * 1024;

// The receiver's acknowledgement: how many bytes it has taken so far, as
// decimal digits and a newline, sent back up its own half of the stream. A
// running total rather than an increment, so a line that is lost costs nothing
// -- the next one carries everything the sender needs.
std::string progress_line(std::uint64_t received)
{
  return std::to_string(received) + "\n";
}

// Reads the transfer and acknowledges it. Consuming is what returns
// MAX_STREAM_DATA credit to the peer, and it happens here because it happens
// nowhere else: bytes stay in the transport's reassembly until a read takes
// them, so a receiver that stops reading stops the sender through the mechanism
// the protocol already has.
vio::task_t<std::uint64_t> receive(vio::quic_endpoint_t &endpoint)
{
  using namespace vio;
  auto connection = co_await quic_endpoint_accept(endpoint);
  if (!connection)
  {
    co_return 0;
  }
  auto stream = co_await quic_accept_stream(*connection);
  if (!stream)
  {
    co_return 0;
  }
  auto reader = quic_stream_create_reader(*stream);
  if (!reader)
  {
    co_return 0;
  }

  std::vector<std::uint8_t> scratch(64 * 1024);
  std::uint64_t received = 0;
  while (true)
  {
    auto taken = co_await reader->read_into(scratch);
    if (!taken || *taken == 0)
    {
      break;
    }
    received += *taken;
    if (auto acknowledged = co_await quic_stream_write(*stream, bytes_of(progress_line(received))); !acknowledged)
    {
      break;
    }
  }
  (void)co_await quic_stream_finish(*stream);
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
      server_tls.alpn = {"vio-bulk"};
      auto server_context = tls_context_t::create(server_tls);

      tls_config_t client_tls;
      client_tls.role = tls_role_t::client;
      client_tls.ca_certificates_pem = identity.certificate_pem;
      client_tls.alpn = {"vio-bulk"};
      auto client_context = tls_context_t::create(client_tls);
      if (!server_context || !client_context)
      {
        std::println(stderr, "tls_context_t::create failed");
        co_return 1;
      }

      // The one place an example departs from the defaults, and it is about
      // this example's subject: 8 MiB across the connection is the default and
      // right for bulk, but the per-stream window has to be big enough that the
      // application's own 256 KiB bound is what limits the sender rather than
      // the transport's.
      quic_config_t config;
      config.transport.connection.transport_parameters.initial_max_stream_data_bidi_local = 4ULL * 1024 * 1024;
      config.transport.connection.transport_parameters.initial_max_stream_data_bidi_remote = 4ULL * 1024 * 1024;

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

      auto receiving = receive(*server);

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

      auto stream = co_await quic_open_stream(*connection);
      if (!stream)
      {
        std::println(stderr, "quic_open_stream: {}", stream.error().msg);
        co_return 1;
      }
      auto reader = quic_stream_create_reader(*stream);
      if (!reader)
      {
        std::println(stderr, "quic_stream_create_reader: {}", reader.error().msg);
        co_return 1;
      }

      std::println("client: sending {} bytes, never more than {} unacknowledged", total_bytes, window_bytes);

      const std::vector<std::uint8_t> body(chunk_bytes, std::uint8_t{0xab});
      std::string acknowledgements;
      std::uint64_t offered = 0;
      std::uint64_t acknowledged = 0;
      std::uint64_t peak_outstanding = 0;
      std::uint64_t peak_in_transport = 0;

      while (offered < total_bytes)
      {
        // Write until the bound is reached. It overshoots by up to one chunk,
        // because the loop checks before writing rather than splitting a chunk
        // across the bound.
        while (offered < total_bytes && offered - acknowledged < window_bytes)
        {
          const auto take = static_cast<std::size_t>((std::min)(static_cast<std::uint64_t>(chunk_bytes), total_bytes - offered));
          const bool last = offered + take == total_bytes;
          auto written = last ? co_await quic_stream_write_final(*stream, std::span(body.data(), take)) : co_await quic_stream_write(*stream, std::span(body.data(), take));
          if (!written)
          {
            std::println(stderr, "client: write: {}", written.error().msg);
            co_return 1;
          }
          offered += take;
        }
        peak_outstanding = (std::max)(peak_outstanding, offered - acknowledged);

        // What the transport itself is carrying, which is the number the old
        // API could not report at all. It tracks the application's own bound
        // rather than the total, which is the whole point of having one.
        const auto stats = quic_stream_stats(*stream);
        peak_in_transport = (std::max)(peak_in_transport, stats.bytes_queued - stats.bytes_acknowledged);

        if (offered >= total_bytes)
        {
          break;
        }

        // And now the wait. This is the line the write layer will make
        // unnecessary.
        auto chunk = co_await *reader;
        if (!chunk)
        {
          std::println(stderr, "client: the receiver stopped acknowledging: {}", chunk.error().msg);
          co_return 1;
        }
        acknowledgements += text_of(*chunk);
        if (const auto last = acknowledgements.find_last_of('\n'); last != std::string::npos)
        {
          const auto previous = last == 0 ? std::string::npos : acknowledgements.find_last_of('\n', last - 1);
          const auto from = previous == std::string::npos ? 0 : previous + 1;
          acknowledged = std::strtoull(acknowledgements.substr(from, last - from).c_str(), nullptr, 10);
          acknowledgements.erase(0, last + 1);
        }
      }

      const auto received = co_await std::move(receiving);
      std::println("server: received {} of {} bytes", received, total_bytes);
      // The two numbers that matter. Without the loop above, the first would be
      // the whole 8 MiB sitting in the transport's send queue at once.
      std::println("client: peak unacknowledged {} bytes against a {} byte window", peak_outstanding, window_bytes);
      std::println("client: peak held by the transport {} bytes", peak_in_transport);

      quic_connection_close(*connection, 0, "done");
      co_return received == total_bytes ? 0 : 1;
    });
}
