// What a megabyte costs the protocol, with the network taken out of it.
//
// connection_t is sans-I/O, so a transfer can be driven entirely in memory:
// poll_send on one side, receive on the other, a clock this program advances
// itself. No sockets, no scheduler, no other process -- which makes it the one
// measurement here that is repeatable, and the one a profiler can be pointed at
// without the timings it distorts changing what is being measured.
//
// Build with `cmake --build <dir> --target vio_profile_quic`. Run it directly
// for a wall-clock number, or under callgrind for where the instructions go.

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include <vio/quic/connection.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace
{
using namespace vio;
using namespace vio::quic;
using namespace std::chrono_literals;

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
  const std::string alt = std::string("DNS:") + common_name;
  X509_EXTENSION *basic = X509V3_EXT_conf_nid(nullptr, nullptr, NID_basic_constraints, "critical,CA:TRUE");
  X509_add_ext(certificate, basic, -1);
  X509_EXTENSION_free(basic);
  X509_EXTENSION *san = X509V3_EXT_conf_nid(nullptr, nullptr, NID_subject_alt_name, alt.c_str());
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

transport_parameters_t parameters()
{
  transport_parameters_t out;
  out.max_idle_timeout = 120000;
  out.initial_max_data = 1024ull * 1024 * 1024;
  out.initial_max_stream_data_bidi_local = 1024ull * 1024 * 1024;
  out.initial_max_stream_data_bidi_remote = 1024ull * 1024 * 1024;
  out.initial_max_stream_data_uni = 1024ull * 1024 * 1024;
  out.initial_max_streams_bidi = 64;
  out.initial_max_streams_uni = 64;
  out.active_connection_id_limit = 4;
  return out;
}
} // namespace

int main(int argc, char **argv)
{
  const std::size_t megabytes = argc > 1 ? static_cast<std::size_t>(std::atoi(argv[1])) : 20;
  const std::size_t total = megabytes * 1024 * 1024;

  const auto identity = make_self_signed("localhost");

  tls_config_t server_tls;
  server_tls.role = tls_role_t::server;
  server_tls.certificate_chain_pem = identity.certificate_pem;
  server_tls.private_key_pem = identity.private_key_pem;
  server_tls.alpn = {"perf"};
  tls_config_t client_tls;
  client_tls.role = tls_role_t::client;
  client_tls.ca_certificates_pem = identity.certificate_pem;
  client_tls.alpn = {"perf"};

  auto server_context = tls_context_t::create(server_tls);
  auto client_context = tls_context_t::create(client_tls);
  if (!server_context.has_value() || !client_context.has_value())
  {
    std::printf("could not build TLS contexts\n");
    return 1;
  }

  connection_config_t server_config;
  server_config.role = tls_role_t::server;
  server_config.transport_parameters = parameters();
  // The point is what the protocol costs per packet, not how it is spaced.
  server_config.pacing = false;
  connection_config_t client_config;
  client_config.role = tls_role_t::client;
  client_config.transport_parameters = parameters();
  client_config.pacing = false;

  auto server = connection_t::create(*server_context, server_config);
  auto client = connection_t::create(*client_context, client_config, "localhost");
  if (!server.has_value() || !client.has_value())
  {
    std::printf("could not build connections\n");
    return 1;
  }

  // A clock this program owns. Advancing it a little each round keeps loss
  // detection and acknowledgement timers in a sane place without letting a
  // real one decide what the measurement says.
  std::chrono::nanoseconds clock{0};
  auto now = [&clock] { return tick_t::from_nanoseconds(clock); };

  std::vector<std::uint8_t> datagram(1500);
  auto pump = [&](connection_t &from, connection_t &to) -> std::size_t
  {
    std::size_t moved = 0;
    for (;;)
    {
      auto size = from.poll_send(datagram, now());
      if (!size.has_value() || *size == 0)
      {
        return moved;
      }
      if (!to.receive(std::span<std::uint8_t>(datagram).first(*size), now()).has_value())
      {
        return moved;
      }
      moved += *size;
    }
  };

  for (int round = 0; round < 64 && !(client->handshake_complete() && server->handshake_complete()); ++round)
  {
    clock += 1ms;
    (void)pump(*client, *server);
    (void)pump(*server, *client);
  }
  if (!client->handshake_complete() || !server->handshake_complete())
  {
    std::printf("handshake did not complete\n");
    return 1;
  }

  auto stream = server->open_stream(stream_direction_t::unidirectional);
  if (!stream.has_value())
  {
    std::printf("no stream\n");
    return 1;
  }

  // Written in pieces rather than one buffer, which is how an application that
  // is not holding the whole body in memory would do it.
  constexpr std::size_t chunk = 64 * 1024;
  const std::vector<std::uint8_t> body(chunk, 0x61);
  std::size_t queued = 0;
  std::size_t received = 0;

  const auto started = std::chrono::steady_clock::now();
  std::size_t rounds = 0;
  while (received < total && rounds < 2000000)
  {
    ++rounds;
    clock += 100us;
    while (queued < total && server->write_stream(*stream, std::span<const std::uint8_t>(body).first((std::min)(chunk, total - queued)), false) != 0)
    {
      queued += (std::min)(chunk, total - queued);
      if (queued - received > 8 * 1024 * 1024)
      {
        break;
      }
    }
    (void)pump(*server, *client);
    for (const auto id : client->readable_streams())
    {
      const auto readable = client->readable_stream(id);
      received += readable.size();
      client->consume_stream(id, readable.size());
    }
    (void)pump(*client, *server);
  }
  const auto finished = std::chrono::steady_clock::now();

  const auto seconds = std::chrono::duration<double>(finished - started).count();
  std::printf("%zu MB in %.3f s, %.1f MB/s, %zu rounds\n", megabytes, seconds, static_cast<double>(received) / seconds / 1e6, rounds);
  return received >= total ? 0 : 1;
}
