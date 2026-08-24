// A benchmark for the QUIC hot paths, not a test.
//
// Everything here is sans-I/O, so a bulk transfer between two connections
// measures exactly the code that would run per packet on a real socket, with
// no kernel or scheduler noise in the way. That makes it a fair measure of
// per-packet cost and a completely unfair measure of achievable throughput --
// the numbers below are what the protocol machinery costs, not what a link
// would do.

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include <vio/quic/connection.h>
#include <vio/quic/frame_codec.h>
#include <vio/quic/packet.h>
#include <vio/quic/protection.h>
#include <vio/event_loop.h>
#include <vio/operation/tcp.h>
#include <vio/operation/sleep.h>
#include <vio/quic/endpoint.h>
#include <vio/task.h>

#include <vio/ssl_backend.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace
{
using namespace vio::quic;
using namespace std::chrono_literals;

std::size_t g_allocations = 0;
std::size_t g_bytes_allocated = 0;
bool g_counting = false;

struct certificate_t
{
  std::vector<std::uint8_t> certificate_pem;
  std::vector<std::uint8_t> private_key_pem;
};

std::vector<std::uint8_t> read_bio(BIO *bio)
{
  std::vector<std::uint8_t> out(static_cast<std::size_t>(BIO_pending(bio)));
  if (!out.empty())
  {
    BIO_read(bio, out.data(), static_cast<int>(out.size()));
  }
  return out;
}

certificate_t make_self_signed(const char *common_name)
{
  EVP_PKEY *key = nullptr;
  EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
  EVP_PKEY_keygen_init(context);
  EVP_PKEY_CTX_set_ec_paramgen_curve_nid(context, NID_X9_62_prime256v1);
  EVP_PKEY_keygen(context, &key);
  EVP_PKEY_CTX_free(context);

  X509 *certificate = X509_new();
  X509_set_version(certificate, 2);
  ASN1_INTEGER_set(X509_get_serialNumber(certificate), 1);
  X509_gmtime_adj(X509_getm_notBefore(certificate), 0);
  X509_gmtime_adj(X509_getm_notAfter(certificate), 31536000L);
  X509_set_pubkey(certificate, key);
  X509_NAME *name = X509_get_subject_name(certificate);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char *>(common_name), -1, -1, 0);
  X509_set_issuer_name(certificate, name);
  const std::string alt_name = std::string("DNS:") + common_name;
  X509_EXTENSION *basic = X509V3_EXT_nconf_nid(nullptr, nullptr, NID_basic_constraints, "critical,CA:TRUE");
  X509_add_ext(certificate, basic, -1);
  X509_EXTENSION_free(basic);
  X509_EXTENSION *san = X509V3_EXT_nconf_nid(nullptr, nullptr, NID_subject_alt_name, alt_name.c_str());
  X509_add_ext(certificate, san, -1);
  X509_EXTENSION_free(san);
  X509_sign(certificate, key, EVP_sha256());

  BIO *certificate_bio = BIO_new(BIO_s_mem());
  BIO *key_bio = BIO_new(BIO_s_mem());
  PEM_write_bio_X509(certificate_bio, certificate);
  PEM_write_bio_PrivateKey(key_bio, key, nullptr, nullptr, 0, nullptr, nullptr);
  certificate_t out{.certificate_pem = read_bio(certificate_bio), .private_key_pem = read_bio(key_bio)};
  BIO_free(certificate_bio);
  BIO_free(key_bio);
  X509_free(certificate);
  EVP_PKEY_free(key);
  return out;
}

vio::tick_t at(std::chrono::nanoseconds offset)
{
  return vio::tick_t::from_nanoseconds(offset);
}

transport_parameters_t generous()
{
  transport_parameters_t parameters;
  parameters.max_idle_timeout = 30000;
  parameters.initial_max_data = 1ull << 32;
  parameters.initial_max_stream_data_bidi_local = 1ull << 32;
  parameters.initial_max_stream_data_bidi_remote = 1ull << 32;
  parameters.initial_max_stream_data_uni = 1ull << 32;
  parameters.initial_max_streams_bidi = 100000;
  parameters.initial_max_streams_uni = 100000;
  return parameters;
}

struct report_t
{
  double seconds = 0;
  std::size_t bytes = 0;
  std::size_t datagrams = 0;
  std::size_t allocations = 0;
  std::size_t allocated_bytes = 0;
};

void print(const char *name, const report_t &report)
{
  const double megabytes = static_cast<double>(report.bytes) / (1024.0 * 1024.0);
  std::printf("%-34s %8.1f MB/s  %10zu datagrams  %8.2f us/datagram  %7.1f allocs/datagram  %6.0f B/datagram\n", name, megabytes / report.seconds, report.datagrams, report.seconds * 1e6 / static_cast<double>(report.datagrams),
              static_cast<double>(report.allocations) / static_cast<double>(report.datagrams), static_cast<double>(report.allocated_bytes) / static_cast<double>(report.datagrams));
}
} // namespace

// Counting every allocation on the hot path is the point of the exercise: a
// transport that allocates per packet cannot be made fast by tuning, only by
// not doing it.
void *operator new(std::size_t size)
{
  if (g_counting)
  {
    ++g_allocations;
    g_bytes_allocated += size;
  }
  void *p = std::malloc(size);
  if (p == nullptr)
  {
    throw std::bad_alloc();
  }
  return p;
}

void operator delete(void *p) noexcept
{
  std::free(p);
}

void operator delete(void *p, std::size_t) noexcept
{
  std::free(p);
}

// The same transfer over a real socket, which is the only place the
// segmentation offloads can show. Everything above the socket is identical
// with them on or off; what changes is how many system calls a megabyte costs.
double socket_transfer(const certificate_t &identity, bool offload, std::size_t megabytes)
{
  using namespace vio;
  using namespace vio::quic;

  event_loop_t loop;
  double seconds = 0;

  loop.run_in_loop(
    [&]
    {
      return [](event_loop_t &event_loop, const certificate_t &pem, bool use_offload, std::size_t total_mb, double &elapsed) -> task_t<void>
      {
        tls_config_t server_tls;
        server_tls.role = tls_role_t::server;
        server_tls.certificate_chain_pem = pem.certificate_pem;
        server_tls.private_key_pem = pem.private_key_pem;
        server_tls.alpn = {"bench"};
        tls_config_t client_tls;
        client_tls.role = tls_role_t::client;
        client_tls.ca_certificates_pem = pem.certificate_pem;
        client_tls.alpn = {"bench"};

        auto server_context = tls_context_t::create(server_tls);
        auto client_context = tls_context_t::create(client_tls);

        endpoint_config_t server_config;
        server_config.connection.role = tls_role_t::server;
        server_config.connection.transport_parameters = generous();
        server_config.connection.pacing = false;
        server_config.offload = use_offload;
        auto server_made = endpoint_t::create(event_loop, *server_context, server_config);
        std::optional<endpoint_t> server(std::move(*server_made));

        auto bind_address = ip4_addr("127.0.0.1", 0);
        (void)server->bind(reinterpret_cast<const sockaddr *>(&*bind_address));
        auto port = server->local_port();

        connection_t *accepted = nullptr;
        const std::size_t total = total_mb * 1024 * 1024;
        std::size_t offered = 0;
        std::size_t drained = 0;
        std::uint64_t sender_stream = 0;
        bool have_stream = false;
        const std::vector<std::uint8_t> chunk(64 * 1024, 0x5a);

        // Draining happens where the data arrives, not on a timer. Anything
        // this writes back joins the flush the endpoint is about to make.
        server->on_connection([&accepted](connection_t &connection) { accepted = &connection; });
        server->on_activity(
          [&drained, &sender_stream, &have_stream](connection_t &connection)
          {
            if (!have_stream)
            {
              return;
            }
            auto readable = connection.readable_stream(sender_stream);
            if (!readable.empty())
            {
              drained += readable.size();
              connection.consume_stream(sender_stream, readable.size());
            }
          });

        endpoint_config_t client_config;
        client_config.connection.role = tls_role_t::client;
        client_config.connection.transport_parameters = generous();
        client_config.connection.pacing = false;
        client_config.offload = use_offload;
        auto client_made = endpoint_t::create(event_loop, *client_context, client_config);
        std::optional<endpoint_t> client(std::move(*client_made));

        // Keeping the send buffer full is the whole point: a sender that runs
        // dry between wakeups never builds a congestion window, and a sender
        // without a window has nothing to batch.
        auto keep_writing = [&offered, total, &chunk, &sender_stream, &have_stream](connection_t &connection)
        {
          if (!have_stream)
          {
            return;
          }
          while (offered < total)
          {
            const std::size_t want = (std::min)(chunk.size(), total - offered);
            const auto wrote = connection.write_stream(sender_stream, std::span<const std::uint8_t>(chunk).first(want), false);
            if (wrote == 0)
            {
              return;
            }
            offered += wrote;
          }
        };
        client->on_activity(keep_writing);

        cancellation_t server_cancel;
        cancellation_t client_cancel;
        auto run_one = [](endpoint_t &endpoint, cancellation_t &cancel) -> detached_task_t { co_await endpoint.run(&cancel); };
        auto server_run = run_one(*server, server_cancel);
        auto client_run = run_one(*client, client_cancel);
        (void)server_run;
        (void)client_run;

        auto target = ip4_addr("127.0.0.1", *port);
        auto dialled = client->connect(reinterpret_cast<const sockaddr *>(&*target), "localhost");
        connection_t *connection = client->connection(*dialled);

        for (int i = 0; i < 600 && !connection->handshake_complete(); ++i)
        {
          co_await sleep(event_loop, 5ms);
        }

        auto stream = connection->open_stream(stream_direction_t::bidirectional);
        sender_stream = *stream;
        have_stream = true;

        const auto started = std::chrono::steady_clock::now();
        keep_writing(*connection);
        (void)client->flush();

        // Only a completion check. The transfer is driven by the callbacks.
        for (int i = 0; i < 4000 && drained < total; ++i)
        {
          co_await sleep(event_loop, 2ms);
        }
        const auto finished = std::chrono::steady_clock::now();
        elapsed = std::chrono::duration<double>(finished - started).count();

        const auto out = client->stats();
        const auto in = server->stats();
        std::printf("%-12s %6.1f MB/s  %5.2f datagrams/send  %5.2f datagrams/read  (%llu sends, %llu reads)\n", use_offload ? "offload on" : "offload off", static_cast<double>(drained) / (1024.0 * 1024.0) / elapsed,
                    out.sends > 0 ? static_cast<double>(out.datagrams_sent) / static_cast<double>(out.sends) : 0.0, in.reads > 0 ? static_cast<double>(in.datagrams_received) / static_cast<double>(in.reads) : 0.0,
                    static_cast<unsigned long long>(out.sends), static_cast<unsigned long long>(in.reads));

        server_cancel.cancel();
        client_cancel.cancel();
        co_await sleep(event_loop, 50ms);
        server.reset();
        client.reset();
        co_await sleep(event_loop, 50ms);
        event_loop.stop();
      }(loop, identity, offload, megabytes, seconds);
    });

  loop.run();
  return seconds;
}

int main(int argc, char **argv)
{
  const std::size_t stream_count = argc > 1 ? static_cast<std::size_t>(std::atoi(argv[1])) : 512;
  const auto identity = make_self_signed("localhost");

  tls_config_t server_tls;
  server_tls.role = tls_role_t::server;
  server_tls.certificate_chain_pem = identity.certificate_pem;
  server_tls.private_key_pem = identity.private_key_pem;
  server_tls.alpn = {"h3"};
  tls_config_t client_tls;
  client_tls.role = tls_role_t::client;
  client_tls.ca_certificates_pem = identity.certificate_pem;
  client_tls.alpn = {"h3"};

  auto server_context = tls_context_t::create(server_tls);
  auto client_context = tls_context_t::create(client_tls);
  if (!server_context.has_value() || !client_context.has_value())
  {
    std::printf("context setup failed\n");
    return 1;
  }

  connection_config_t server_config;
  server_config.role = tls_role_t::server;
  server_config.transport_parameters = generous();
  connection_config_t client_config;
  client_config.role = tls_role_t::client;
  client_config.transport_parameters = generous();
  // This measures what the protocol machinery costs per datagram. Pacing is a
  // rate limiter measured against a round trip, and the clock here barely
  // moves, so leaving it on would measure the pacer and nothing else.
  client_config.pacing = false;
  server_config.pacing = false;

  auto server = connection_t::create(*server_context, server_config);
  auto client = connection_t::create(*client_context, client_config, "localhost");
  if (!server.has_value() || !client.has_value())
  {
    std::printf("connection setup failed\n");
    return 1;
  }

  auto now = at(0ns);
  std::vector<std::uint8_t> datagram(1500);

  // Handshake first, untimed.
  for (int round = 0; round < 16; ++round)
  {
    bool moved = false;
    for (;;)
    {
      auto size = client->poll_send(datagram, now);
      if (!size.has_value() || *size == 0)
      {
        break;
      }
      std::vector<std::uint8_t> copy(datagram.begin(), datagram.begin() + static_cast<std::ptrdiff_t>(*size));
      (void)server->receive(copy, now);
      moved = true;
    }
    for (;;)
    {
      auto size = server->poll_send(datagram, now);
      if (!size.has_value() || *size == 0)
      {
        break;
      }
      std::vector<std::uint8_t> copy(datagram.begin(), datagram.begin() + static_cast<std::ptrdiff_t>(*size));
      (void)client->receive(copy, now);
      moved = true;
    }
    if (!moved)
    {
      break;
    }
  }
  if (!client->handshake_complete() || !server->handshake_complete())
  {
    std::printf("handshake did not complete\n");
    return 1;
  }

  auto id = client->open_stream(stream_direction_t::bidirectional);
  if (!id.has_value())
  {
    std::printf("could not open a stream\n");
    return 1;
  }

  // A bulk transfer, one direction, consumed as it arrives.
  constexpr std::size_t chunk = 256 * 1024;
  constexpr int chunks = 64;
  std::vector<std::uint8_t> payload(chunk, 0x5a);

  report_t report;
  std::vector<std::uint8_t> scratch(1500);
  g_allocations = 0;
  g_bytes_allocated = 0;
  g_counting = true;
  const auto started = std::chrono::steady_clock::now();

  for (int i = 0; i < chunks; ++i)
  {
    (void)client->write_stream(*id, payload, i + 1 == chunks);
    for (;;)
    {
      auto size = client->poll_send(scratch, now);
      if (!size.has_value() || *size == 0)
      {
        break;
      }
      ++report.datagrams;
      (void)server->receive(std::span<std::uint8_t>(scratch).first(*size), now);

      auto readable = server->readable_stream(*id);
      if (!readable.empty())
      {
        report.bytes += readable.size();
        server->consume_stream(*id, readable.size());
      }

      for (;;)
      {
        auto reply = server->poll_send(scratch, now);
        if (!reply.has_value() || *reply == 0)
        {
          break;
        }
        (void)client->receive(std::span<std::uint8_t>(scratch).first(*reply), now);
      }
    }
    now = now + std::chrono::nanoseconds(1ms);
  }

  const auto finished = std::chrono::steady_clock::now();
  g_counting = false;
  report.seconds = std::chrono::duration<double>(finished - started).count();
  report.allocations = g_allocations;
  report.allocated_bytes = g_bytes_allocated;

  print("bulk stream transfer", report);
  std::printf("%-34s %zu bytes delivered\n", "", report.bytes);
  // A second shape entirely: many streams open at once with a little traffic
  // on each. The bulk case above touches the stream container barely once per
  // packet, so it cannot see what holding a thousand streams costs. Here every
  // poll_send asks whether any stream has something to send, and every frame
  // that arrives is a lookup by stream id.
  std::vector<std::uint64_t> ids;
  ids.reserve(stream_count);
  for (std::size_t i = 0; i < stream_count; ++i)
  {
    auto opened = client->open_stream(stream_direction_t::bidirectional);
    if (!opened.has_value())
    {
      std::printf("could not open stream %zu\n", i);
      return 1;
    }
    ids.push_back(*opened);
  }

  const std::vector<std::uint8_t> small(256, 0x33);
  report_t many;
  g_allocations = 0;
  g_bytes_allocated = 0;
  g_counting = true;
  const auto many_started = std::chrono::steady_clock::now();

  for (int round = 0; round < 32; ++round)
  {
    for (auto stream : ids)
    {
      (void)client->write_stream(stream, small, false);
    }
    for (;;)
    {
      auto size = client->poll_send(scratch, now);
      if (!size.has_value() || *size == 0)
      {
        break;
      }
      ++many.datagrams;
      (void)server->receive(std::span<std::uint8_t>(scratch).first(*size), now);
      for (;;)
      {
        auto reply = server->poll_send(scratch, now);
        if (!reply.has_value() || *reply == 0)
        {
          break;
        }
        (void)client->receive(std::span<std::uint8_t>(scratch).first(*reply), now);
      }
    }
    for (auto stream : ids)
    {
      auto readable = server->readable_stream(stream);
      if (!readable.empty())
      {
        many.bytes += readable.size();
        server->consume_stream(stream, readable.size());
      }
    }
    now = now + std::chrono::nanoseconds(1ms);
  }

  const auto many_finished = std::chrono::steady_clock::now();
  g_counting = false;
  many.seconds = std::chrono::duration<double>(many_finished - many_started).count();
  many.allocations = g_allocations;
  many.allocated_bytes = g_bytes_allocated;

  char label[64];
  std::snprintf(label, sizeof(label), "%zu concurrent streams", stream_count);
  print(label, many);

  // Over a real socket, with and without the segmentation offloads. This is
  // the only measurement where they can show at all.
  std::printf("\n");
  (void)socket_transfer(identity, false, 8);
  (void)socket_transfer(identity, true, 8);
  return 0;
}
