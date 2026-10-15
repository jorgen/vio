// A benchmark for the QUIC hot paths, not a test.
//
// The first configurations are sans-I/O, so a bulk transfer between two
// connections measures exactly the code that would run per packet on a real
// socket, with no kernel or scheduler noise in the way. That makes it a fair
// measure of per-packet cost and a completely unfair measure of achievable
// throughput -- those numbers are what the protocol machinery costs, not what a
// link would do.
//
// The configurations at the bottom are the opposite by necessity: they price
// the coroutine API, which *is* I/O, so each shape runs twice over the same
// real socket -- once through the callback API and once through the coroutine
// one -- and only the difference between the pair means anything.

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include <vio/quic/connection.h>
#include <vio/quic/frame_codec.h>
#include <vio/quic/packet.h>
#include <vio/quic/protection.h>
#include <vio/event_loop.h>
#include <vio/operation/quic_stream.h>
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
      return [](event_loop_t &event_loop, const certificate_t &pem, bool use_offload, std::size_t total_mb, double &elapsed) -> vio::task_t<void>
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


// -----------------------------------------------------------------------------
// What the coroutine layer costs
// -----------------------------------------------------------------------------
//
// The sans-I/O configurations above are the floor: they measure the protocol
// machinery with no kernel in the way. They cannot answer this question,
// because the coroutine layer is I/O -- it exists to turn a socket and an event
// loop into something you can await, and subtracting the socket would subtract
// the thing being measured.
//
// So each shape below is run twice over the *same* real socket, once through
// the callback API and once through the coroutine API. The absolute numbers
// include the event loop, the kernel and the loopback path and are not
// interesting on their own; the difference between the two rows is, because
// everything except the API is identical.
//
// Two shapes, because they answer different questions.
//
//   Bulk is dominated by AES-GCM -- 80% of the profile, which is where an
//   encrypted transport's time belongs. Anything the API layer adds is
//   amortised over megabytes, so this shape mostly says whether the coroutine
//   layer is free at scale. It should be, and if it ever stops being, this is
//   where a regression shows.
//
//   Pipelined request/response is the opposite: hundreds of small streams, each
//   costing a stream state, an accept, a reader and two writes. Per-operation
//   cost is what the coroutine layer actually adds -- an operation allocation, a
//   ref-counted state, a registry entry -- and this is the shape that can see
//   it. It is pipelined rather than sequential on purpose: a sequential driver
//   on the callback API has nothing to await and would have to poll, and
//   measuring a 1 ms sleep against a resumption would be measuring the polling
//   rather than the API.
//
// What it measured, on loopback, three runs, MSVC release:
//
//   bulk, callback api                58.9 - 66.1 MB/s   13.4 allocs/datagram
//   bulk, coroutine (read_into)       62.0 - 65.0 MB/s   13.6 allocs/datagram
//   bulk, coroutine (owning read)     63.0 - 64.0 MB/s   13.6 allocs/datagram
//   requests, callback api           22.4k - 25.1k req/s 31.9 allocs/request
//   requests, coroutine api          34.5k - 38.3k req/s 40.5 allocs/request
//
// Two conclusions, and the second is the interesting one.
//
// **Bulk is free.** The three rows are inside each other's noise, and the
// coroutine layer adds 0.2 allocations per datagram. That is what you would
// hope for from a shape where 80% of the profile is AES-GCM: nothing this layer
// does is on the per-byte path. The owning read costs about 1.3 KB per datagram
// more than read_into and no extra allocation count, because a chunk is large;
// on a shape with small reads it would cost one allocation each.
//
// **Request/response is faster through the coroutine API, by about 1.5x**, at
// the price of 8.6 more allocations and twice the bytes per request. Coroutines
// did not make anything faster -- being edge-driven did. `readable_streams()` is
// a *level*: it walks every stream on the connection, filters, sorts and
// allocates a vector, on every call, and a callback server calls it once per
// arriving datagram. With two thousand streams open that is the dominant cost
// and it grows with the number of streams. The coroutine layer reads the
// transport's edge lists instead, which name only what changed. So the honest
// summary is that this layer buys a per-operation allocation and sells an
// O(n log n) sweep per datagram, and on any shape with many concurrent streams
// that is a good trade.
//
// What is not measured here: writes are still submit-and-resolve, so this says
// nothing about what bounded writes will cost. Re-run this table when they land.

namespace
{
// Both sides of a benchmark's TLS, built once per run.
struct contexts_t
{
  std::optional<tls_context_t> server;
  std::optional<tls_context_t> client;
};

contexts_t make_contexts(const certificate_t &identity)
{
  tls_config_t server_tls;
  server_tls.role = tls_role_t::server;
  server_tls.certificate_chain_pem = identity.certificate_pem;
  server_tls.private_key_pem = identity.private_key_pem;
  server_tls.alpn = {"bench"};
  tls_config_t client_tls;
  client_tls.role = tls_role_t::client;
  client_tls.ca_certificates_pem = identity.certificate_pem;
  client_tls.alpn = {"bench"};

  contexts_t out;
  auto server = tls_context_t::create(server_tls);
  auto client = tls_context_t::create(client_tls);
  if (server.has_value() && client.has_value())
  {
    out.server.emplace(std::move(*server));
    out.client.emplace(std::move(*client));
  }
  return out;
}

vio::quic::endpoint_config_t bench_endpoint_config(tls_role_t role)
{
  vio::quic::endpoint_config_t config;
  config.connection.role = role;
  config.connection.transport_parameters = generous();
  // Pacing is a rate limiter measured against a round trip. On loopback it
  // would decide the answer, and the answer would be about the pacer.
  config.connection.pacing = false;
  return config;
}

// Everything a measured phase records, and the reason g_counting is switched on
// around the phase rather than the program: the handshake allocates a TLS
// session, and counting it would swamp what is being compared.
struct phase_t
{
  std::chrono::steady_clock::time_point started;
  void begin()
  {
    g_allocations = 0;
    g_bytes_allocated = 0;
    g_counting = true;
    started = std::chrono::steady_clock::now();
  }
  void end(report_t &into)
  {
    const auto finished = std::chrono::steady_clock::now();
    g_counting = false;
    into.seconds = std::chrono::duration<double>(finished - started).count();
    into.allocations = g_allocations;
    into.allocated_bytes = g_bytes_allocated;
  }
};

void print_per_request(const char *name, const report_t &report, std::size_t requests)
{
  const auto count = static_cast<double>(requests);
  std::printf("%-34s %8.0f req/s  %10zu requests  %8.2f us/request  %7.1f allocs/request  %6.0f B/request\n", name, count / report.seconds, requests, report.seconds * 1e6 / count, static_cast<double>(report.allocations) / count,
              static_cast<double>(report.allocated_bytes) / count);
}

// ---- bulk, through the callback API ----
report_t bulk_callback(const certificate_t &identity, std::size_t megabytes)
{
  using namespace vio;
  event_loop_t loop;
  report_t report;

  loop.run_in_loop(
    [&]
    {
      return [](event_loop_t &event_loop, const certificate_t &pem, std::size_t total_mb, report_t &out) -> vio::task_t<void>
      {
        auto contexts = make_contexts(pem);
        auto server_made = endpoint_t::create(event_loop, *contexts.server, bench_endpoint_config(tls_role_t::server));
        std::optional<endpoint_t> server(std::move(*server_made));
        auto bind_address = ip4_addr("127.0.0.1", 0);
        (void)server->bind(reinterpret_cast<const sockaddr *>(&*bind_address));
        const auto port = server->local_port();

        const std::size_t total = total_mb * 1024 * 1024;
        std::size_t offered = 0;
        std::size_t drained = 0;
        std::uint64_t sender_stream = 0;
        bool have_stream = false;
        const std::vector<std::uint8_t> chunk(64 * 1024, 0x5a);

        server->on_activity(
          [&](connection_t &connection)
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

        auto client_made = endpoint_t::create(event_loop, *contexts.client, bench_endpoint_config(tls_role_t::client));
        std::optional<endpoint_t> client(std::move(*client_made));

        auto keep_writing = [&](connection_t &connection)
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

        phase_t phase;
        phase.begin();
        keep_writing(*connection);
        (void)client->flush();
        for (int i = 0; i < 4000 && drained < total; ++i)
        {
          co_await sleep(event_loop, 2ms);
        }
        phase.end(out);
        out.bytes = drained;
        out.datagrams = client->stats().datagrams_sent;

        server_cancel.cancel();
        client_cancel.cancel();
        co_await sleep(event_loop, 50ms);
        server.reset();
        client.reset();
        co_await sleep(event_loop, 50ms);
        event_loop.stop();
      }(loop, identity, megabytes, report);
    });

  loop.run();
  return report;
}

// ---- bulk, through the coroutine API ----
//
// owning_read chooses between the two ways to read. read_into copies into the
// caller's buffer and allocates nothing per chunk; co_await on the reader hands
// back an owned buffer and therefore allocates one. Measuring both is the point
// -- it is the one place in this layer where the convenient call has a cost the
// other does not, and the per-datagram allocation column is where it shows.
report_t bulk_coroutine(const certificate_t &identity, std::size_t megabytes, bool owning_read)
{
  using namespace vio;
  event_loop_t loop;
  report_t report;

  loop.run_in_loop(
    [&]
    {
      return [](event_loop_t &event_loop, const certificate_t &pem, std::size_t total_mb, bool owning, report_t &out) -> vio::task_t<void>
      {
        auto contexts = make_contexts(pem);
        quic_config_t server_config;
        server_config.transport = bench_endpoint_config(tls_role_t::server);
        quic_config_t client_config;
        client_config.transport = bench_endpoint_config(tls_role_t::client);

        auto server = quic_endpoint_create(event_loop, *contexts.server, server_config);
        auto client = quic_endpoint_create(event_loop, nullptr, &*contexts.client, client_config);
        auto bind_address = ip4_addr("127.0.0.1", 0);
        (void)quic_endpoint_bind(*server, reinterpret_cast<const sockaddr *>(&*bind_address));
        const auto port = quic_endpoint_local_port(*server).value_or(0);
        const auto target_port = static_cast<int>(port);

        const std::size_t total = total_mb * 1024 * 1024;
        std::size_t drained = 0;

        auto receiving = [](quic_endpoint_t &endpoint, std::size_t expected, bool owning, std::size_t &drained) -> vio::task_t<void>
        {
          auto connection = co_await quic_endpoint_accept(endpoint);
          auto stream = co_await quic_accept_stream(*connection);
          auto reader = quic_stream_create_reader(*stream);
          std::vector<std::uint8_t> scratch(64 * 1024);
          while (drained < expected)
          {
            if (owning)
            {
              auto chunk = co_await *reader;
              if (!chunk)
              {
                break;
              }
              drained += chunk->size();
            }
            else
            {
              auto taken = co_await reader->read_into(scratch);
              if (!taken || *taken == 0)
              {
                break;
              }
              drained += *taken;
            }
          }
        }(*server, total, owning, drained);

        auto target = ip4_addr("127.0.0.1", target_port);
        auto connection = co_await quic_endpoint_connect(*client, reinterpret_cast<const sockaddr *>(&*target), "localhost");
        auto stream = co_await quic_open_stream(*connection);

        const std::vector<std::uint8_t> chunk(64 * 1024, 0x5a);
        phase_t phase;
        phase.begin();
        // Written in the same 64 KiB pieces the callback control uses, and for
        // the same reason: at this step a write is submit-and-resolve, so both
        // sides simply queue the whole transfer.
        for (std::size_t offered = 0; offered < total; offered += chunk.size())
        {
          const std::size_t want = (std::min)(chunk.size(), total - offered);
          if (auto written = co_await quic_stream_write(*stream, std::span<const std::uint8_t>(chunk).first(want)); !written)
          {
            break;
          }
        }
        co_await std::move(receiving);
        phase.end(out);
        out.bytes = drained;
        out.datagrams = quic_endpoint_native(*client)->stats().datagrams_sent;

        quic_connection_close(*connection, 0, "done");
        // Released before the loop is asked to stop, and that order is not
        // stylistic: stop() runs the loop until nothing is in flight, so a
        // socket still reading here is a run() that never returns.
        {
          auto releasing_server = std::move(*server);
          auto releasing_client = std::move(*client);
        }
        (void)co_await sleep(event_loop, 1ms);
        event_loop.stop();
      }(loop, identity, megabytes, owning_read, report);
    });

  loop.run();
  return report;
}

// ---- pipelined request/response, through the callback API ----
//
// This is what the old surface makes an application write, and the map is not
// an accident of this benchmark: readable_streams() reports which streams have
// unread bytes *right now*, so a request split across two packets has to be
// reassembled into state keyed by id, and a stream that has been fully consumed
// simply drops off the list.
report_t requests_callback(const certificate_t &identity, std::size_t count, std::size_t body_size)
{
  using namespace vio;
  event_loop_t loop;
  report_t report;

  loop.run_in_loop(
    [&]
    {
      return [](event_loop_t &event_loop, const certificate_t &pem, std::size_t requests, std::size_t body_size, report_t &out) -> vio::task_t<void>
      {
        auto contexts = make_contexts(pem);
        auto server_made = endpoint_t::create(event_loop, *contexts.server, bench_endpoint_config(tls_role_t::server));
        std::optional<endpoint_t> server(std::move(*server_made));
        auto bind_address = ip4_addr("127.0.0.1", 0);
        (void)server->bind(reinterpret_cast<const sockaddr *>(&*bind_address));
        const auto port = server->local_port();

        const std::vector<std::uint8_t> body(body_size, 0x27);
        std::map<std::uint64_t, std::string> pending;
        server->on_activity(
          [&](connection_t &connection)
          {
            for (const auto id : connection.readable_streams())
            {
              auto readable = connection.readable_stream(id);
              auto &partial = pending[id];
              partial.append(reinterpret_cast<const char *>(readable.data()), readable.size());
              connection.consume_stream(id, readable.size());
              if (partial.find('\n') == std::string::npos)
              {
                continue;
              }
              pending.erase(id);
              (void)connection.write_stream(id, body, true);
            }
          });

        auto client_made = endpoint_t::create(event_loop, *contexts.client, bench_endpoint_config(tls_role_t::client));
        std::optional<endpoint_t> client(std::move(*client_made));

        std::size_t completed = 0;
        std::size_t received = 0;
        client->on_activity(
          [&](connection_t &connection)
          {
            for (const auto id : connection.readable_streams())
            {
              auto readable = connection.readable_stream(id);
              received += readable.size();
              connection.consume_stream(id, readable.size());
              if (connection.stream_receive_finished(id))
              {
                ++completed;
              }
            }
          });

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

        phase_t phase;
        phase.begin();
        const std::string request = "get\n";
        for (std::size_t i = 0; i < requests; ++i)
        {
          auto stream = connection->open_stream(stream_direction_t::bidirectional);
          if (!stream)
          {
            break;
          }
          (void)connection->write_stream(*stream, std::span(reinterpret_cast<const std::uint8_t *>(request.data()), request.size()), true);
        }
        (void)client->flush();
        for (int i = 0; i < 8000 && completed < requests; ++i)
        {
          co_await sleep(event_loop, 1ms);
        }
        phase.end(out);
        out.bytes = received;
        out.datagrams = client->stats().datagrams_sent;

        server_cancel.cancel();
        client_cancel.cancel();
        co_await sleep(event_loop, 50ms);
        server.reset();
        client.reset();
        co_await sleep(event_loop, 50ms);
        event_loop.stop();
      }(loop, identity, count, body_size, report);
    });

  loop.run();
  return report;
}

// ---- pipelined request/response, through the coroutine API ----
//
// The same work, with the state that was a map entry now a coroutine frame.
// That is the trade this measurement exists to price: a frame and a stream
// state per request against a map node and a hand-rolled reassembly buffer.
report_t requests_coroutine(const certificate_t &identity, std::size_t count, std::size_t body_size)
{
  using namespace vio;
  event_loop_t loop;
  report_t report;

  loop.run_in_loop(
    [&]
    {
      return [](event_loop_t &event_loop, const certificate_t &pem, std::size_t requests, std::size_t body_size, report_t &out) -> vio::task_t<void>
      {
        auto contexts = make_contexts(pem);
        quic_config_t server_config;
        server_config.transport = bench_endpoint_config(tls_role_t::server);
        quic_config_t client_config;
        client_config.transport = bench_endpoint_config(tls_role_t::client);

        auto server = quic_endpoint_create(event_loop, *contexts.server, server_config);
        auto client = quic_endpoint_create(event_loop, nullptr, &*contexts.client, client_config);
        auto bind_address = ip4_addr("127.0.0.1", 0);
        (void)quic_endpoint_bind(*server, reinterpret_cast<const sockaddr *>(&*bind_address));
        const auto port = quic_endpoint_local_port(*server).value_or(0);
        const auto target_port = static_cast<int>(port);

        const std::vector<std::uint8_t> body(body_size, 0x27);
        std::size_t received = 0;

        auto serving = [](quic_endpoint_t &endpoint, std::size_t requests, const std::vector<std::uint8_t> &body) -> vio::task_t<void>
        {
          auto connection = co_await quic_endpoint_accept(endpoint);
          std::vector<vio::task_t<void>> handlers;
          handlers.reserve(requests);
          for (std::size_t taken = 0; taken < requests; ++taken)
          {
            auto stream = co_await quic_accept_stream(*connection);
            if (!stream)
            {
              break;
            }
            handlers.push_back(
              [](quic_stream_t stream, const std::vector<std::uint8_t> &body) -> vio::task_t<void>
              {
                auto reader = quic_stream_create_reader(stream);
                std::uint8_t scratch[64];
                while (true)
                {
                  auto taken = co_await reader->read_into(scratch);
                  if (!taken || *taken == 0)
                  {
                    break;
                  }
                }
                (void)co_await quic_stream_write_final(stream, body);
              }(*stream, body));
          }
          for (auto &handler : handlers)
          {
            co_await std::move(handler);
          }
        }(*server, requests, body);

        auto target = ip4_addr("127.0.0.1", target_port);
        auto connection = co_await quic_endpoint_connect(*client, reinterpret_cast<const sockaddr *>(&*target), "localhost");

        phase_t phase;
        phase.begin();
        const std::string request = "get\n";
        std::vector<vio::task_t<std::size_t>> asks;
        asks.reserve(requests);
        for (std::size_t i = 0; i < requests; ++i)
        {
          asks.push_back(
            [](quic_connection_t connection, const std::string &request) -> vio::task_t<std::size_t>
            {
              auto stream = co_await quic_open_stream(connection);
              if (!stream)
              {
                co_return std::size_t{0};
              }
              (void)co_await quic_stream_write_final(*stream, std::span(reinterpret_cast<const std::uint8_t *>(request.data()), request.size()));
              auto reader = quic_stream_create_reader(*stream);
              std::uint8_t scratch[4096];
              std::size_t got = 0;
              while (true)
              {
                auto taken = co_await reader->read_into(scratch);
                if (!taken || *taken == 0)
                {
                  break;
                }
                got += *taken;
              }
              co_return std::move(got);
            }(*connection, request));
        }
        for (auto &ask : asks)
        {
          received += co_await std::move(ask);
        }
        co_await std::move(serving);
        phase.end(out);
        out.bytes = received;
        out.datagrams = quic_endpoint_native(*client)->stats().datagrams_sent;

        quic_connection_close(*connection, 0, "done");
        {
          auto releasing_server = std::move(*server);
          auto releasing_client = std::move(*client);
        }
        (void)co_await sleep(event_loop, 1ms);
        event_loop.stop();
      }(loop, identity, count, body_size, report);
    });

  loop.run();
  return report;
}
} // namespace

int main(int argc, char **argv)
{
  // Unbuffered, because this runs for minutes and a reader watching it wants to
  // see each line as it lands rather than the lot at exit -- and because a
  // configuration that hangs should say which one it was.
  std::setvbuf(stdout, nullptr, _IONBF, 0);
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

  const std::vector<std::uint8_t> small_payload(256, 0x33);
  report_t many;
  g_allocations = 0;
  g_bytes_allocated = 0;
  g_counting = true;
  const auto many_started = std::chrono::steady_clock::now();

  for (int round = 0; round < 32; ++round)
  {
    for (auto stream : ids)
    {
      (void)client->write_stream(stream, small_payload, false);
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

  // And the pair of pairs that price the coroutine layer. Read them across, not
  // down: the absolute numbers carry loopback and the kernel with them, and only
  // the gap between a row and the one above it is about the API.
  std::printf("\n");
  print("bulk, callback api", bulk_callback(identity, 8));
  print("bulk, coroutine api (read_into)", bulk_coroutine(identity, 8, false));
  print("bulk, coroutine api (owning read)", bulk_coroutine(identity, 8, true));

  std::printf("\n");
  const std::size_t request_count = argc > 2 ? static_cast<std::size_t>(std::atoi(argv[2])) : 2000;
  constexpr std::size_t response_size = 1024;
  print_per_request("requests, callback api", requests_callback(identity, request_count, response_size), request_count);
  print_per_request("requests, coroutine api", requests_coroutine(identity, request_count, response_size), request_count);
  return 0;
}
