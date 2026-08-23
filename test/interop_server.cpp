// A QUIC server for another implementation to talk to.
//
// Everything else in this tree tests vio against vio. That catches a great
// deal, but not a shared misreading of the specification: if both ends agree on
// the same wrong thing, every test passes. The only cure is a peer that was
// written from the RFC by someone else, which is what this exists for.
//
// Not part of the test suite -- it needs a second process. Build it with
// `cmake --build <dir> --target vio_interop_server` and point a foreign client
// at the port it prints.

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

#include <vio/event_loop.h>
#include <vio/operation/sleep.h>
#include <vio/operation/tcp.h>
#include <vio/quic/endpoint.h>
#include <vio/quic/retry_token.h>
#include <vio/task.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace
{
using namespace std::chrono_literals;

struct identity_t
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

// A certificate the foreign client can be told to trust, with the name it will
// ask for in the subject alternative name -- modern verification ignores the
// common name entirely.
identity_t make_self_signed(const char *common_name)
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
  X509_EXTENSION *basic = X509V3_EXT_conf_nid(nullptr, nullptr, NID_basic_constraints, "critical,CA:TRUE");
  X509_add_ext(certificate, basic, -1);
  X509_EXTENSION_free(basic);
  X509_EXTENSION *san = X509V3_EXT_conf_nid(nullptr, nullptr, NID_subject_alt_name, alt_name.c_str());
  X509_add_ext(certificate, san, -1);
  X509_EXTENSION_free(san);
  X509_sign(certificate, key, EVP_sha256());

  BIO *certificate_bio = BIO_new(BIO_s_mem());
  BIO *key_bio = BIO_new(BIO_s_mem());
  PEM_write_bio_X509(certificate_bio, certificate);
  PEM_write_bio_PrivateKey(key_bio, key, nullptr, nullptr, 0, nullptr, nullptr);
  identity_t out{.certificate_pem = read_bio(certificate_bio), .private_key_pem = read_bio(key_bio)};
  BIO_free(certificate_bio);
  BIO_free(key_bio);
  X509_free(certificate);
  EVP_PKEY_free(key);
  return out;
}

void write_file(const char *path, const std::vector<std::uint8_t> &bytes)
{
  std::FILE *file = std::fopen(path, "wb");
  if (file == nullptr)
  {
    return;
  }
  std::fwrite(bytes.data(), 1, bytes.size(), file);
  std::fclose(file);
}

vio::quic::transport_parameters_t parameters()
{
  vio::quic::transport_parameters_t out;
  out.max_idle_timeout = 30000;
  out.initial_max_data = 16 * 1024 * 1024;
  out.initial_max_stream_data_bidi_local = 1024 * 1024;
  out.initial_max_stream_data_bidi_remote = 1024 * 1024;
  out.initial_max_stream_data_uni = 1024 * 1024;
  out.initial_max_streams_bidi = 100;
  out.initial_max_streams_uni = 100;
  out.active_connection_id_limit = 4;
  return out;
}
} // namespace

int main(int argc, char **argv)
{
  using namespace vio;
  using namespace vio::quic;

  const int port = argc > 1 ? std::atoi(argv[1]) : 4433;
  const char *alpn = argc > 2 ? argv[2] : "hq-interop";
  const char *cert_path = argc > 3 ? argv[3] : "/tmp/vio-interop-cert.pem";
  const char *name = argc > 4 ? argv[4] : "test.example.com";
  const int seconds = argc > 5 ? std::atoi(argv[5]) : 15;
  const bool use_retry = argc > 6 && std::strcmp(argv[6], "retry") == 0;

  const auto identity = make_self_signed(name);
  write_file(cert_path, identity.certificate_pem);

  event_loop_t loop;
  int handshakes = 0;
  std::size_t bytes_read = 0;
  std::size_t answered = 0;

  loop.run_in_loop(
    [&]
    {
      return [](event_loop_t &event_loop, const identity_t &pem, int listen_port, const char *protocol, int lifetime, bool retry, int &handshakes, std::size_t &bytes_read, std::size_t &answered) -> task_t<void>
      {
        tls_config_t tls;
        tls.role = tls_role_t::server;
        tls.certificate_chain_pem = pem.certificate_pem;
        tls.private_key_pem = pem.private_key_pem;
        tls.alpn = {protocol};

        auto context = tls_context_t::create(tls);
        if (!context.has_value())
        {
          std::printf("could not build a TLS context\n");
          event_loop.stop();
          co_return;
        }

        endpoint_config_t config;
        config.connection.role = tls_role_t::server;
        config.connection.transport_parameters = parameters();
        config.ecn = true;

        // A Retry forces the client to prove it can receive at the address it
        // claims, which is the address-validation half of the anti-amplification
        // rules. The token it hands back is authenticated with this key.
        retry_token_key_t retry_key;
        if (retry)
        {
          if (!retry_key.generate().has_value())
          {
            std::printf("could not generate a retry key\n");
            event_loop.stop();
            co_return;
          }
          config.retry_key = &retry_key;
        }
        auto made = endpoint_t::create(event_loop, *context, config);
        if (!made.has_value())
        {
          std::printf("could not build an endpoint\n");
          event_loop.stop();
          co_return;
        }
        std::optional<endpoint_t> server(std::move(*made));

        auto address = ip4_addr("127.0.0.1", listen_port);
        if (!address.has_value() || !server->bind(reinterpret_cast<const sockaddr *>(&*address)).has_value())
        {
          std::printf("could not bind port %d\n", listen_port);
          event_loop.stop();
          co_return;
        }

        server->on_connection(
          [&handshakes](connection_t &connection)
          {
            ++handshakes;
            std::printf("handshake complete: alpn=%.*s migrations=%llu\n", static_cast<int>(connection.selected_alpn().size()), connection.selected_alpn().data(), static_cast<unsigned long long>(connection.migration_count()));
            std::fflush(stdout);
          });

        // HTTP/0.9, which is what the hq-interop ALPN carries: the client
        // sends "GET /<size>" and a newline, and the answer is that many bytes
        // followed by the end of the stream. It is barely a protocol, which is
        // the point -- it exercises the transport and nothing else.
        server->on_activity(
          [&bytes_read, &answered](connection_t &connection)
          {
            for (const auto id : connection.readable_streams())
            {
              auto readable = connection.readable_stream(id);
              if (readable.empty())
              {
                continue;
              }
              const std::string request(reinterpret_cast<const char *>(readable.data()), readable.size());
              bytes_read += readable.size();
              connection.consume_stream(id, readable.size());

              const auto newline = request.find('\n');
              if (newline == std::string::npos)
              {
                continue;
              }
              std::size_t wanted = 1000;
              const auto slash = request.find('/');
              if (slash != std::string::npos)
              {
                const auto digits = request.substr(slash + 1, newline - slash - 1);
                const auto parsed = std::strtoul(digits.c_str(), nullptr, 10);
                if (parsed > 0 && parsed <= 64 * 1024 * 1024)
                {
                  wanted = static_cast<std::size_t>(parsed);
                }
              }
              const std::vector<std::uint8_t> body(wanted, 0x61);
              (void)connection.write_stream(id, body, true);
              answered += wanted;
            }
          });

        cancellation_t cancel;
        auto serving = [](endpoint_t &endpoint, cancellation_t &token) -> detached_task_t { co_await endpoint.run(&token); }(*server, cancel);
        (void)serving;

        std::printf("listening on 127.0.0.1:%d alpn=%s retry=%s\n", listen_port, protocol, retry ? "on" : "off");
        std::fflush(stdout);

        for (int i = 0; i < lifetime * 10; ++i)
        {
          co_await sleep(event_loop, 100ms);
        }

        const auto counters = server->stats();
        std::printf("done: handshakes=%d request_bytes=%zu answered_bytes=%zu connections=%zu sends=%llu reads=%llu\n", handshakes, bytes_read, answered, server->connection_count(),
                    static_cast<unsigned long long>(counters.sends), static_cast<unsigned long long>(counters.reads));
        std::fflush(stdout);

        cancel.cancel();
        co_await sleep(event_loop, 50ms);
        server.reset();
        co_await sleep(event_loop, 50ms);
        event_loop.stop();
      }(loop, identity, port, alpn, seconds, use_retry, handshakes, bytes_read, answered);
    });

  loop.run();
  return handshakes > 0 ? 0 : 1;
}
