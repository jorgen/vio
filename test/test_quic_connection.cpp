#include <chrono>
#include <cstdint>
#include <optional>
#include <ostream>
#include <span>
#include <string>
#include <vector>
#include <doctest/doctest.h>
#include <vio/quic/connection.h>
#include <vio/quic/packet.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

// Two connections, no sockets, no clock: a complete QUIC handshake driven by
// handing each side the other's byte arrays. This is the first test in which
// every layer runs at once -- packet headers, protection, frames, CRYPTO
// reassembly, ACK tracking, transport parameters and TLS -- against a peer
// that is not the same code path.

namespace
{
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
  REQUIRE(context != nullptr);
  REQUIRE(EVP_PKEY_keygen_init(context) == 1);
  REQUIRE(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(context, NID_X9_62_prime256v1) == 1);
  REQUIRE(EVP_PKEY_keygen(context, &key) == 1);
  EVP_PKEY_CTX_free(context);

  X509 *certificate = X509_new();
  REQUIRE(certificate != nullptr);
  X509_set_version(certificate, 2);
  ASN1_INTEGER_set(X509_get_serialNumber(certificate), 1);
  X509_gmtime_adj(X509_getm_notBefore(certificate), 0);
  X509_gmtime_adj(X509_getm_notAfter(certificate), 31536000L);
  REQUIRE(X509_set_pubkey(certificate, key) == 1);

  X509_NAME *name = X509_get_subject_name(certificate);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char *>(common_name), -1, -1, 0);
  REQUIRE(X509_set_issuer_name(certificate, name) == 1);

  const std::string alt_name = std::string("DNS:") + common_name;
  X509_EXTENSION *basic = X509V3_EXT_conf_nid(nullptr, nullptr, NID_basic_constraints, "critical,CA:TRUE");
  X509_add_ext(certificate, basic, -1);
  X509_EXTENSION_free(basic);
  X509_EXTENSION *san = X509V3_EXT_conf_nid(nullptr, nullptr, NID_subject_alt_name, alt_name.c_str());
  X509_add_ext(certificate, san, -1);
  X509_EXTENSION_free(san);

  REQUIRE(X509_sign(certificate, key, EVP_sha256()) > 0);

  BIO *certificate_bio = BIO_new(BIO_s_mem());
  BIO *key_bio = BIO_new(BIO_s_mem());
  REQUIRE(PEM_write_bio_X509(certificate_bio, certificate) == 1);
  REQUIRE(PEM_write_bio_PrivateKey(key_bio, key, nullptr, nullptr, 0, nullptr, nullptr) == 1);
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

transport_parameters_t sane_parameters()
{
  transport_parameters_t parameters;
  parameters.max_idle_timeout = 30000;
  parameters.initial_max_data = 1048576;
  parameters.initial_max_stream_data_bidi_local = 262144;
  parameters.initial_max_stream_data_bidi_remote = 262144;
  parameters.initial_max_streams_bidi = 100;
  parameters.active_connection_id_limit = 4;
  return parameters;
}

struct endpoints_t
{
  tls_context_t server_context;
  tls_context_t client_context;
};

endpoints_t make_contexts(const certificate_t &identity, const std::vector<std::string> &server_alpn = {"h3"}, const std::vector<std::string> &client_alpn = {"h3"})
{
  tls_config_t server_config;
  server_config.role = tls_role_t::server;
  server_config.certificate_chain_pem = identity.certificate_pem;
  server_config.private_key_pem = identity.private_key_pem;
  server_config.alpn = server_alpn;

  tls_config_t client_config;
  client_config.role = tls_role_t::client;
  client_config.ca_certificates_pem = identity.certificate_pem;
  client_config.alpn = client_alpn;

  auto server = tls_context_t::create(server_config);
  REQUIRE(server.has_value());
  auto client = tls_context_t::create(client_config);
  REQUIRE(client.has_value());
  return endpoints_t{.server_context = std::move(*server), .client_context = std::move(*client)};
}

// Everything one side put on the wire during a run, so a test can assert
// about the datagrams themselves rather than only the end state.
struct exchange_t
{
  std::vector<std::vector<std::uint8_t>> client_to_server;
  std::vector<std::vector<std::uint8_t>> server_to_client;
  int rounds = 0;
};

// Drives both sides until neither has anything left to send. Datagrams are
// copied rather than aliased, because receive decrypts in place.
exchange_t run_handshake(connection_t &client, connection_t &server, vio::tick_t now, int max_rounds = 12)
{
  exchange_t exchange;
  for (; exchange.rounds < max_rounds; ++exchange.rounds)
  {
    bool moved = false;

    for (;;)
    {
      std::vector<std::uint8_t> datagram(1500);
      auto size = client.poll_send(datagram, now);
      REQUIRE(size.has_value());
      if (*size == 0)
      {
        break;
      }
      datagram.resize(*size);
      exchange.client_to_server.push_back(datagram);
      REQUIRE(server.receive(datagram, now).has_value());
      moved = true;
    }

    for (;;)
    {
      std::vector<std::uint8_t> datagram(1500);
      auto size = server.poll_send(datagram, now);
      REQUIRE(size.has_value());
      if (*size == 0)
      {
        break;
      }
      datagram.resize(*size);
      exchange.server_to_client.push_back(datagram);
      REQUIRE(client.receive(datagram, now).has_value());
      moved = true;
    }

    if (!moved)
    {
      break;
    }
  }
  return exchange;
}

std::size_t total_bytes(const std::vector<std::vector<std::uint8_t>> &datagrams)
{
  std::size_t sum = 0;
  for (const auto &datagram : datagrams)
  {
    sum += datagram.size();
  }
  return sum;
}
} // namespace

TEST_SUITE("quic connection")
{
TEST_CASE("a client and a server complete a handshake over byte arrays")
{
  const auto identity = make_self_signed("localhost");
  auto contexts = make_contexts(identity);

  connection_config_t server_config;
  server_config.role = tls_role_t::server;
  server_config.transport_parameters = sane_parameters();

  connection_config_t client_config;
  client_config.role = tls_role_t::client;
  client_config.transport_parameters = sane_parameters();

  auto server = connection_t::create(contexts.server_context, server_config);
  REQUIRE(server.has_value());
  auto client = connection_t::create(contexts.client_context, client_config, "localhost");
  REQUIRE(client.has_value());

  const auto exchange = run_handshake(*client, *server, at(0ns));
  CAPTURE(exchange.rounds);

  REQUIRE(client->handshake_complete());
  REQUIRE(server->handshake_complete());
  CHECK(client->state() == connection_state_t::connected);
  CHECK(server->state() == connection_state_t::connected);
  CHECK_FALSE(client->close_reason().has_value());
  CHECK_FALSE(server->close_reason().has_value());

  SUBCASE("the server confirms the handshake and the client learns of it")
  {
    CHECK(server->handshake_confirmed());
    CHECK(client->handshake_confirmed());
  }

  SUBCASE("ALPN was negotiated through the connection")
  {
    CHECK(client->selected_alpn() == "h3");
    CHECK(server->selected_alpn() == "h3");
  }

  SUBCASE("transport parameters crossed and were validated")
  {
    auto seen_by_client = client->peer_transport_parameters();
    auto seen_by_server = server->peer_transport_parameters();
    REQUIRE(seen_by_client.has_value());
    REQUIRE(seen_by_server.has_value());
    CHECK(seen_by_client->initial_max_data == 1048576);
    CHECK(seen_by_server->initial_max_streams_bidi == 100);
    CHECK(seen_by_client->active_connection_id_limit == 4);

    // Section 7.3: each side authenticates the connection IDs it saw.
    REQUIRE(seen_by_client->initial_source_connection_id.has_value());
    CHECK(*seen_by_client->initial_source_connection_id == server->local_connection_id());
    REQUIRE(seen_by_server->initial_source_connection_id.has_value());
    CHECK(*seen_by_server->initial_source_connection_id == client->local_connection_id());
    CHECK(seen_by_client->original_destination_connection_id.has_value());
  }

  SUBCASE("each side ended up addressing the other by its chosen connection id")
  {
    CHECK(client->peer_connection_id() == server->local_connection_id());
    CHECK(server->peer_connection_id() == client->local_connection_id());
  }

  SUBCASE("it settles rather than sending forever")
  {
    CHECK(exchange.rounds < 12);
    std::vector<std::uint8_t> datagram(1500);
    // Section 13.2.1: a 1-RTT acknowledgement may wait out max_ack_delay, so
    // each side can still owe one when the handshake finishes. It leaves on
    // the first poll after that delay. What "settles" means is that nothing
    // follows it -- an acknowledgement must not draw another.
    (void)client->poll_send(datagram, at(1s));
    (void)server->poll_send(datagram, at(1s));

    auto client_idle = client->poll_send(datagram, at(1s));
    REQUIRE(client_idle.has_value());
    CHECK(*client_idle == 0);
    auto server_idle = server->poll_send(datagram, at(1s));
    REQUIRE(server_idle.has_value());
    CHECK(*server_idle == 0);
  }
}

TEST_CASE("the client's first datagram obeys section 14.1")
{
  const auto identity = make_self_signed("localhost");
  auto contexts = make_contexts(identity);

  connection_config_t client_config;
  client_config.role = tls_role_t::client;
  client_config.transport_parameters = sane_parameters();
  auto client = connection_t::create(contexts.client_context, client_config, "localhost");
  REQUIRE(client.has_value());

  std::vector<std::uint8_t> datagram(1500);
  auto size = client->poll_send(datagram, at(0ns));
  REQUIRE(size.has_value());
  REQUIRE(*size >= 1200);
  datagram.resize(*size);

  SUBCASE("and it is a version 1 Initial packet")
  {
    packet_reader_t reader(datagram, 0);
    auto header = reader.next();
    REQUIRE(header.has_value());
    REQUIRE(header->has_value());
    CHECK(header->value().kind == packet_kind_t::initial);
    CHECK(header->value().version == quic_version_1);
    CHECK(header->value().token.empty());
    CHECK(header->value().source_id == client->local_connection_id());
  }
}

TEST_CASE("a server will not amplify before the address is validated")
{
  const auto identity = make_self_signed("localhost");
  auto contexts = make_contexts(identity);

  connection_config_t server_config;
  server_config.role = tls_role_t::server;
  server_config.transport_parameters = sane_parameters();
  connection_config_t client_config;
  client_config.role = tls_role_t::client;
  client_config.transport_parameters = sane_parameters();

  auto server = connection_t::create(contexts.server_context, server_config);
  REQUIRE(server.has_value());
  auto client = connection_t::create(contexts.client_context, client_config, "localhost");
  REQUIRE(client.has_value());

  // One client Initial in, then let the server say everything it wants to.
  std::vector<std::uint8_t> first(1500);
  auto size = client->poll_send(first, at(0ns));
  REQUIRE(size.has_value());
  first.resize(*size);
  REQUIRE(server->receive(first, at(0ns)).has_value());

  std::size_t sent = 0;
  for (int i = 0; i < 16; ++i)
  {
    std::vector<std::uint8_t> datagram(1500);
    auto out = server->poll_send(datagram, at(0ns));
    REQUIRE(out.has_value());
    if (*out == 0)
    {
      break;
    }
    sent += *out;
  }

  // Section 8.1: no more than three times what arrived, and the client's
  // Initial is the only thing that has.
  CHECK(sent <= first.size() * 3);
  CHECK(sent > 0);
}

TEST_CASE("a migrated server stops rationing once the new path is validated")
{
  // Section 9.3 puts a server back under the section 8 amplification limit when
  // the peer's address changes, and section 8.2 makes a matching PATH_RESPONSE
  // the validation that lifts it. A server that never lifts it still works --
  // it just spends the rest of the connection sending three bytes per byte that
  // arrives, which is a crawl rather than an outage, and so goes unnoticed.
  // picoquic's NAT rebinding test took 19.9s for 2 MB against this bug.
  const auto identity = make_self_signed("localhost");
  auto contexts = make_contexts(identity);

  connection_config_t server_config;
  server_config.role = tls_role_t::server;
  server_config.transport_parameters = sane_parameters();
  connection_config_t client_config;
  client_config.role = tls_role_t::client;
  client_config.transport_parameters = sane_parameters();

  auto server = connection_t::create(contexts.server_context, server_config);
  REQUIRE(server.has_value());
  auto client = connection_t::create(contexts.client_context, client_config, "localhost");
  REQUIRE(client.has_value());
  REQUIRE(run_handshake(*client, *server, at(0ns)).rounds > 0);
  REQUIRE(client->handshake_complete());

  const std::vector<std::uint8_t> first_address = {10, 0, 0, 1, 0, 80};
  const std::vector<std::uint8_t> second_address = {10, 0, 0, 1, 0, 81};

  auto client_to_server = [&](vio::tick_t now, std::span<const std::uint8_t> address)
  {
    for (;;)
    {
      std::vector<std::uint8_t> datagram(1500);
      auto size = client->poll_send(datagram, now);
      REQUIRE(size.has_value());
      if (*size == 0)
      {
        return;
      }
      datagram.resize(*size);
      REQUIRE(server->receive(datagram, now, address).has_value());
    }
  };

  auto server_to_client = [&](vio::tick_t now)
  {
    std::size_t total = 0;
    for (;;)
    {
      std::vector<std::uint8_t> datagram(1500);
      auto size = server->poll_send(datagram, now);
      REQUIRE(size.has_value());
      if (*size == 0)
      {
        return total;
      }
      total += *size;
      datagram.resize(*size);
      REQUIRE(client->receive(datagram, now).has_value());
    }
  };

  // A request, so the server has a stream to answer on, and an answer far
  // larger than any amplification budget the migration will allow.
  auto id = client->open_stream(stream_direction_t::bidirectional);
  REQUIRE(id.has_value());
  const std::vector<std::uint8_t> request(16, 0x21);
  REQUIRE(client->write_stream(*id, request, true) == request.size());
  client_to_server(at(1ms), first_address);
  (void)server_to_client(at(1ms));

  const std::vector<std::uint8_t> answer(256 * 1024, 0x61);
  REQUIRE(server->write_stream(*id, answer, true) == answer.size());
  (void)server_to_client(at(2ms));

  // The address changes underneath the connection. Only the datagram that
  // arrived here counts towards what the server may send back.
  const auto migrations_before = server->migration_count();
  client_to_server(at(3ms), second_address);
  REQUIRE(server->migration_count() > migrations_before);

  const auto rationed = server_to_client(at(3ms));
  CHECK(rationed > 0);

  // Section 8.2: the client answers the challenge, and the budget goes away.
  client_to_server(at(4ms), second_address);
  const auto after_validation = server_to_client(at(4ms));
  CHECK(after_validation > rationed * 3);
}

TEST_CASE("stream credit comes back for a stream that finished on an acknowledgement")
{
  // Section 4.6: the peer may open another stream once this endpoint is done
  // with one, and MAX_STREAMS is how it is told. A stream is done when both
  // directions are, and the second direction usually finishes on the
  // acknowledgement of what was sent back -- which arrives long after the
  // application's last read.
  //
  // Scanning for finished streams only when the application reads deadlocks
  // exactly there: a peer that has spent its allowance sends no more requests,
  // so nothing reads, so nothing is reaped, so no credit is returned, so it
  // sends no more requests. The interop runner's multiplexing case stalled at
  // 198 of 2000 files against this.
  const auto identity = make_self_signed("localhost");
  auto contexts = make_contexts(identity);

  auto parameters = sane_parameters();
  parameters.initial_max_streams_bidi = 2;

  connection_config_t server_config;
  server_config.role = tls_role_t::server;
  server_config.transport_parameters = parameters;
  connection_config_t client_config;
  client_config.role = tls_role_t::client;
  client_config.transport_parameters = parameters;

  auto server = connection_t::create(contexts.server_context, server_config);
  REQUIRE(server.has_value());
  auto client = connection_t::create(contexts.client_context, client_config, "localhost");
  REQUIRE(client.has_value());
  REQUIRE(run_handshake(*client, *server, at(0ns)).rounds > 0);
  REQUIRE(client->handshake_complete());

  auto pump = [&](vio::tick_t now)
  {
    for (int round = 0; round < 8; ++round)
    {
      bool moved = false;
      for (;;)
      {
        std::vector<std::uint8_t> datagram(1500);
        auto size = client->poll_send(datagram, now);
        REQUIRE(size.has_value());
        if (*size == 0)
        {
          break;
        }
        datagram.resize(*size);
        REQUIRE(server->receive(datagram, now).has_value());
        moved = true;
      }
      for (;;)
      {
        std::vector<std::uint8_t> datagram(1500);
        auto size = server->poll_send(datagram, now);
        REQUIRE(size.has_value());
        if (*size == 0)
        {
          break;
        }
        datagram.resize(*size);
        REQUIRE(client->receive(datagram, now).has_value());
        moved = true;
      }
      if (!moved)
      {
        return;
      }
    }
  };

  // The allowance is two, and spending it must leave nothing.
  std::vector<std::uint64_t> opened;
  for (int i = 0; i < 2; ++i)
  {
    auto id = client->open_stream(stream_direction_t::bidirectional);
    REQUIRE(id.has_value());
    opened.push_back(*id);
    const std::vector<std::uint8_t> request(8, 0x3f);
    REQUIRE(client->write_stream(*id, request, true) == request.size());
  }
  CHECK_FALSE(client->open_stream(stream_direction_t::bidirectional).has_value());

  pump(at(1ms));

  // The server reads each request to its end and answers it. After this the
  // application has nothing left to do, and every remaining transition on
  // these streams happens because of an acknowledgement.
  for (const auto id : server->readable_streams())
  {
    auto readable = server->readable_stream(id);
    server->consume_stream(id, readable.size());
    const std::vector<std::uint8_t> answer(4, 0x5a);
    REQUIRE(server->write_stream(id, answer, true) == answer.size());
  }

  pump(at(2ms));
  // The client reads what came back, which is the last thing it does.
  for (const auto id : client->readable_streams())
  {
    client->consume_stream(id, client->readable_stream(id).size());
  }
  // Past max_ack_delay: two response packets do not meet the two-packet
  // threshold of section 13.2.2, so the acknowledgement that finishes these
  // streams is a delayed one and only leaves on the timer.
  pump(at(60ms));
  pump(at(120ms));

  CHECK(client->open_stream(stream_direction_t::bidirectional).has_value());
}

TEST_CASE("a datagram that is not for this connection is dropped, not fatal")
{
  const auto identity = make_self_signed("localhost");
  auto contexts = make_contexts(identity);

  connection_config_t server_config;
  server_config.role = tls_role_t::server;
  server_config.transport_parameters = sane_parameters();
  auto server = connection_t::create(contexts.server_context, server_config);
  REQUIRE(server.has_value());

  SUBCASE("random bytes")
  {
    std::vector<std::uint8_t> noise(1200, 0xab);
    CHECK(server->receive(noise, at(0ns)).has_value());
    CHECK(server->state() == connection_state_t::handshaking);
    CHECK_FALSE(server->close_reason().has_value());
  }

  SUBCASE("an empty datagram")
  {
    std::vector<std::uint8_t> empty;
    CHECK(server->receive(empty, at(0ns)).has_value());
    CHECK(server->state() == connection_state_t::handshaking);
  }

  SUBCASE("a well formed Initial protected with the wrong keys")
  {
    connection_config_t client_config;
    client_config.role = tls_role_t::client;
    client_config.transport_parameters = sane_parameters();
    auto client = connection_t::create(contexts.client_context, client_config, "localhost");
    REQUIRE(client.has_value());

    std::vector<std::uint8_t> datagram(1500);
    auto size = client->poll_send(datagram, at(0ns));
    REQUIRE(size.has_value());
    datagram.resize(*size);
    // Corrupting the payload leaves the header parseable and the AEAD
    // failing, which is the shape of an injected packet.
    datagram[datagram.size() - 32] ^= 0xff;
    CHECK(server->receive(datagram, at(0ns)).has_value());
    CHECK_FALSE(server->close_reason().has_value());
    CHECK_FALSE(server->handshake_complete());
  }
}

TEST_CASE("every truncation of a real handshake datagram is survivable")
{
  const auto identity = make_self_signed("localhost");
  auto contexts = make_contexts(identity);

  connection_config_t client_config;
  client_config.role = tls_role_t::client;
  client_config.transport_parameters = sane_parameters();
  auto client = connection_t::create(contexts.client_context, client_config, "localhost");
  REQUIRE(client.has_value());

  std::vector<std::uint8_t> full(1500);
  auto size = client->poll_send(full, at(0ns));
  REQUIRE(size.has_value());
  full.resize(*size);

  connection_config_t server_config;
  server_config.role = tls_role_t::server;
  server_config.transport_parameters = sane_parameters();

  for (std::size_t length = 0; length <= full.size(); length += 37)
  {
    CAPTURE(length);
    auto server = connection_t::create(contexts.server_context, server_config);
    REQUIRE(server.has_value());
    std::vector<std::uint8_t> prefix(full.begin(), full.begin() + static_cast<std::ptrdiff_t>(length));
    // Never a fatal error: an unauthenticated fragment is something to drop.
    CHECK(server->receive(prefix, at(0ns)).has_value());
  }
}

TEST_CASE("no shared ALPN closes the connection with a crypto error")
{
  const auto identity = make_self_signed("localhost");
  auto contexts = make_contexts(identity, {"h3"}, {"hq-interop"});

  connection_config_t server_config;
  server_config.role = tls_role_t::server;
  server_config.transport_parameters = sane_parameters();
  connection_config_t client_config;
  client_config.role = tls_role_t::client;
  client_config.transport_parameters = sane_parameters();

  auto server = connection_t::create(contexts.server_context, server_config);
  REQUIRE(server.has_value());
  auto client = connection_t::create(contexts.client_context, client_config, "localhost");
  REQUIRE(client.has_value());

  run_handshake(*client, *server, at(0ns));

  CHECK_FALSE(server->handshake_complete());
  REQUIRE(server->close_reason().has_value());
  // RFC 9000 section 20.1: a TLS alert becomes CRYPTO_ERROR, 0x0100 plus the
  // alert code.
  CHECK(server->close_reason()->error_code >= 0x0100);
  CHECK(server->close_reason()->error_code <= 0x01ff);
  CHECK_FALSE(server->close_reason()->from_peer);
}

TEST_CASE("a close is delivered to the peer and reported on both sides")
{
  const auto identity = make_self_signed("localhost");
  auto contexts = make_contexts(identity);

  connection_config_t server_config;
  server_config.role = tls_role_t::server;
  server_config.transport_parameters = sane_parameters();
  connection_config_t client_config;
  client_config.role = tls_role_t::client;
  client_config.transport_parameters = sane_parameters();

  auto server = connection_t::create(contexts.server_context, server_config);
  REQUIRE(server.has_value());
  auto client = connection_t::create(contexts.client_context, client_config, "localhost");
  REQUIRE(client.has_value());

  run_handshake(*client, *server, at(0ns));
  REQUIRE(client->handshake_complete());

  client->close(0x1234, "going away", true);
  CHECK(client->state() == connection_state_t::closing);

  std::vector<std::uint8_t> datagram(1500);
  auto size = client->poll_send(datagram, at(0ns));
  REQUIRE(size.has_value());
  REQUIRE(*size > 0);
  datagram.resize(*size);
  CHECK(client->state() == connection_state_t::closed);

  REQUIRE(server->receive(datagram, at(0ns)).has_value());
  REQUIRE(server->close_reason().has_value());
  CHECK(server->close_reason()->error_code == 0x1234);
  CHECK(server->close_reason()->application);
  CHECK(server->close_reason()->from_peer);
  CHECK(server->close_reason()->reason == "going away");
  CHECK(server->state() == connection_state_t::closed);
}

TEST_CASE("handshake packets acknowledge what came before them")
{
  const auto identity = make_self_signed("localhost");
  auto contexts = make_contexts(identity);

  connection_config_t server_config;
  server_config.role = tls_role_t::server;
  server_config.transport_parameters = sane_parameters();
  connection_config_t client_config;
  client_config.role = tls_role_t::client;
  client_config.transport_parameters = sane_parameters();

  auto server = connection_t::create(contexts.server_context, server_config);
  REQUIRE(server.has_value());
  auto client = connection_t::create(contexts.client_context, client_config, "localhost");
  REQUIRE(client.has_value());

  const auto exchange = run_handshake(*client, *server, at(0ns));

  REQUIRE(client->handshake_complete());
  CHECK(exchange.client_to_server.size() >= 2);
  CHECK(exchange.server_to_client.size() >= 1);
  // The whole handshake is small; if this grows by an order of magnitude
  // something is retransmitting or padding that should not be.
  CHECK(total_bytes(exchange.client_to_server) < 8192);
  CHECK(total_bytes(exchange.server_to_client) < 8192);

  SUBCASE("the server coalesced Initial and Handshake into one datagram")
  {
    // It has to: processing the Initial is what gives the client the keys for
    // the Handshake packet that follows it.
    bool found = false;
    for (const auto &datagram : exchange.server_to_client)
    {
      packet_reader_t reader(datagram, 0);
      std::vector<packet_kind_t> kinds;
      while (auto next = reader.next())
      {
        if (!next->has_value())
        {
          break;
        }
        kinds.push_back(next->value().kind);
      }
      if (kinds.size() >= 2 && kinds[0] == packet_kind_t::initial && kinds[1] == packet_kind_t::handshake)
      {
        found = true;
      }
    }
    CHECK(found);
  }
}

TEST_CASE("an ACK deadline is reported so a caller can arm a timer")
{
  const auto identity = make_self_signed("localhost");
  auto contexts = make_contexts(identity);

  connection_config_t server_config;
  server_config.role = tls_role_t::server;
  server_config.transport_parameters = sane_parameters();
  connection_config_t client_config;
  client_config.role = tls_role_t::client;
  client_config.transport_parameters = sane_parameters();

  auto server = connection_t::create(contexts.server_context, server_config);
  REQUIRE(server.has_value());
  auto client = connection_t::create(contexts.client_context, client_config, "localhost");
  REQUIRE(client.has_value());

  CHECK_FALSE(server->next_timeout(at(0ns)).has_value());

  std::vector<std::uint8_t> datagram(1500);
  auto size = client->poll_send(datagram, at(0ns));
  REQUIRE(size.has_value());
  datagram.resize(*size);
  REQUIRE(server->receive(datagram, at(0ns)).has_value());

  // Having received an ack-eliciting packet, the server owes an ACK by some
  // deadline even if it had nothing else to say.
  CHECK(server->next_timeout(at(0ns)).has_value());
}

TEST_CASE("a handshake survives losing datagrams")
{
  const auto identity = make_self_signed("localhost");

  // Drives both sides against a lossy link, advancing the clock to whichever
  // timer either endpoint is waiting on. Without retransmission any drop here
  // deadlocks, so this is the test that says loss recovery is wired up.
  struct link_t
  {
    int client_sent = 0;
    int server_sent = 0;
    int dropped = 0;
  };

  const auto run = [&](auto should_drop_client, auto should_drop_server)
  {
    auto contexts = make_contexts(identity);

    connection_config_t server_config;
    server_config.role = tls_role_t::server;
    server_config.transport_parameters = sane_parameters();
    connection_config_t client_config;
    client_config.role = tls_role_t::client;
    client_config.transport_parameters = sane_parameters();

    auto server = connection_t::create(contexts.server_context, server_config);
    REQUIRE(server.has_value());
    auto client = connection_t::create(contexts.client_context, client_config, "localhost");
    REQUIRE(client.has_value());

    link_t link;
    auto now = at(0ns);

    for (int round = 0; round < 60; ++round)
    {
      bool moved = false;

      for (;;)
      {
        std::vector<std::uint8_t> datagram(1500);
        auto size = client->poll_send(datagram, now);
        REQUIRE(size.has_value());
        if (*size == 0)
        {
          break;
        }
        datagram.resize(*size);
        moved = true;
        if (should_drop_client(link.client_sent++))
        {
          ++link.dropped;
          continue;
        }
        REQUIRE(server->receive(datagram, now).has_value());
      }

      for (;;)
      {
        std::vector<std::uint8_t> datagram(1500);
        auto size = server->poll_send(datagram, now);
        REQUIRE(size.has_value());
        if (*size == 0)
        {
          break;
        }
        datagram.resize(*size);
        moved = true;
        if (should_drop_server(link.server_sent++))
        {
          ++link.dropped;
          continue;
        }
        REQUIRE(client->receive(datagram, now).has_value());
      }

      if (client->handshake_confirmed() && server->handshake_confirmed() && !moved)
      {
        break;
      }

      // Nothing more to send right now: wait for whichever timer comes first.
      if (!moved)
      {
        std::optional<vio::tick_t> next;
        for (auto *side : {&*client, &*server})
        {
          auto deadline = side->next_timeout(now);
          if (deadline.has_value() && (!next.has_value() || *deadline < *next))
          {
            next = deadline;
          }
        }
        REQUIRE(next.has_value());
        now = *next > now ? *next : now + std::chrono::nanoseconds(1ms);
      }
    }

    CHECK(link.dropped > 0);
    CHECK(client->handshake_complete());
    CHECK(server->handshake_complete());
    CHECK_FALSE(client->close_reason().has_value());
    CHECK_FALSE(server->close_reason().has_value());
    CHECK(client->selected_alpn() == "h3");
  };

  SUBCASE("the client's first flight is lost")
  {
    run([](int n) { return n == 0; }, [](int) { return false; });
  }

  SUBCASE("the server's first flight is lost")
  {
    run([](int) { return false; }, [](int n) { return n == 0; });
  }

  SUBCASE("the client's second flight is lost")
  {
    run([](int n) { return n == 1; }, [](int) { return false; });
  }

  SUBCASE("every other datagram in both directions is lost")
  {
    run([](int n) { return n % 2 == 0; }, [](int n) { return n % 2 == 0; });
  }

  SUBCASE("the first two datagrams each way are lost")
  {
    run([](int n) { return n < 2; }, [](int n) { return n < 2; });
  }
}

TEST_CASE("a lost CRYPTO frame is resent with the same bytes at the same offset")
{
  const auto identity = make_self_signed("localhost");
  auto contexts = make_contexts(identity);

  connection_config_t client_config;
  client_config.role = tls_role_t::client;
  client_config.transport_parameters = sane_parameters();
  auto client = connection_t::create(contexts.client_context, client_config, "localhost");
  REQUIRE(client.has_value());

  std::vector<std::uint8_t> first(1500);
  auto size = client->poll_send(first, at(0ns));
  REQUIRE(size.has_value());
  first.resize(*size);

  // Nothing acknowledged it, so the PTO eventually fires and the same
  // ClientHello goes out again.
  auto deadline = client->next_timeout(at(0ns));
  REQUIRE(deadline.has_value());

  std::vector<std::uint8_t> second(1500);
  auto retry = client->poll_send(second, *deadline);
  REQUIRE(retry.has_value());
  REQUIRE(*retry > 0);
  second.resize(*retry);

  // Same size and same shape: an Initial padded to the section 14.1 minimum.
  CHECK(second.size() >= 1200);

  packet_reader_t reader(second, 0);
  auto header = reader.next();
  REQUIRE(header.has_value());
  REQUIRE(header->has_value());
  CHECK(header->value().kind == packet_kind_t::initial);

  SUBCASE("and a server that only ever sees the retransmission still completes")
  {
    connection_config_t server_config;
    server_config.role = tls_role_t::server;
    server_config.transport_parameters = sane_parameters();
    auto server = connection_t::create(contexts.server_context, server_config);
    REQUIRE(server.has_value());

    REQUIRE(server->receive(second, *deadline).has_value());
    // The retransmitted ClientHello was enough to drive TLS forward.
    std::vector<std::uint8_t> answer(1500);
    auto out = server->poll_send(answer, *deadline);
    REQUIRE(out.has_value());
    CHECK(*out > 0);
  }
}

TEST_CASE("a PTO backs off rather than retrying at a fixed rate")
{
  const auto identity = make_self_signed("localhost");
  auto contexts = make_contexts(identity);

  connection_config_t client_config;
  client_config.role = tls_role_t::client;
  client_config.transport_parameters = sane_parameters();
  auto client = connection_t::create(contexts.client_context, client_config, "localhost");
  REQUIRE(client.has_value());

  std::vector<std::uint8_t> datagram(1500);
  auto size = client->poll_send(datagram, at(0ns));
  REQUIRE(size.has_value());
  REQUIRE(*size > 0);

  auto first = client->next_timeout(at(0ns));
  REQUIRE(first.has_value());

  auto probe = client->poll_send(datagram, *first);
  REQUIRE(probe.has_value());
  CHECK(*probe > 0);

  auto second = client->next_timeout(*first);
  REQUIRE(second.has_value());
  // Section 6.2.1: the period doubles on each consecutive expiry.
  const auto firstwait = *first - at(0ns);
  const auto secondwait = *second - *first;
  CHECK(secondwait > firstwait);
}

TEST_CASE("streams carry data end to end over a real connection")
{
  const auto identity = make_self_signed("localhost");
  auto contexts = make_contexts(identity);

  connection_config_t server_config;
  server_config.role = tls_role_t::server;
  server_config.transport_parameters = sane_parameters();
  connection_config_t client_config;
  client_config.role = tls_role_t::client;
  client_config.transport_parameters = sane_parameters();

  auto server = connection_t::create(contexts.server_context, server_config);
  REQUIRE(server.has_value());
  auto client = connection_t::create(contexts.client_context, client_config, "localhost");
  REQUIRE(client.has_value());

  run_handshake(*client, *server, at(0ns));
  REQUIRE(client->handshake_complete());
  REQUIRE(server->handshake_complete());

  auto id = client->open_stream(stream_direction_t::bidirectional);
  REQUIRE(id.has_value());
  // The first client-initiated bidirectional stream.
  CHECK(*id == 0);

  const std::string message = "the quick brown fox jumps over the lazy dog";
  const std::vector<std::uint8_t> payload(message.begin(), message.end());
  CHECK(client->write_stream(*id, payload, true) == payload.size());

  run_handshake(*client, *server, at(0ns));

  auto readable = server->readable_streams();
  REQUIRE(readable.size() == 1);
  CHECK(readable[0] == *id);
  auto data = server->readable_stream(*id);
  CHECK(std::string(reinterpret_cast<const char *>(data.data()), data.size()) == message);

  SUBCASE("and the FIN arrived with it")
  {
    server->consume_stream(*id, data.size());
    CHECK(server->stream_receive_finished(*id));
  }

  SUBCASE("the server can answer on the same stream")
  {
    server->consume_stream(*id, data.size());
    const std::string reply = "and the dog did not care";
    const std::vector<std::uint8_t> reply_bytes(reply.begin(), reply.end());
    CHECK(server->write_stream(*id, reply_bytes, true) == reply_bytes.size());

    run_handshake(*client, *server, at(0ns));

    auto back = client->readable_stream(*id);
    CHECK(std::string(reinterpret_cast<const char *>(back.data()), back.size()) == reply);
  }
}

TEST_CASE("a stream larger than one packet is reassembled")
{
  const auto identity = make_self_signed("localhost");
  auto contexts = make_contexts(identity);

  connection_config_t server_config;
  server_config.role = tls_role_t::server;
  server_config.transport_parameters = sane_parameters();
  connection_config_t client_config;
  client_config.role = tls_role_t::client;
  client_config.transport_parameters = sane_parameters();
  // This drives a simulated clock by jumping to whatever deadline comes next,
  // which makes every round trip look enormous. Pacing is measured against the
  // round trip, so leaving it on would have the test throttling itself against
  // an RTT that is an artefact of how it advances time. What is under test
  // here is reassembly.
  client_config.pacing = false;
  server_config.pacing = false;

  auto server = connection_t::create(contexts.server_context, server_config);
  REQUIRE(server.has_value());
  auto client = connection_t::create(contexts.client_context, client_config, "localhost");
  REQUIRE(client.has_value());

  run_handshake(*client, *server, at(0ns));
  auto id = client->open_stream(stream_direction_t::bidirectional);
  REQUIRE(id.has_value());

  // Well over a datagram, so it must be split across several STREAM frames
  // and put back together on the far side.
  std::vector<std::uint8_t> payload(20000);
  for (std::size_t i = 0; i < payload.size(); ++i)
  {
    payload[i] = static_cast<std::uint8_t>(i * 31 + 7);
  }
  CHECK(client->write_stream(*id, payload, true) == payload.size());

  // Drain repeatedly, consuming as it arrives so the window keeps moving.
  std::vector<std::uint8_t> received;
  auto now = at(0ns);
  for (int round = 0; round < 200; ++round)
  {
    bool moved = false;
    for (;;)
    {
      std::vector<std::uint8_t> datagram(1500);
      auto size = client->poll_send(datagram, now);
      REQUIRE(size.has_value());
      if (*size == 0)
      {
        break;
      }
      datagram.resize(*size);
      REQUIRE(server->receive(datagram, now).has_value());
      moved = true;
    }

    auto chunk = server->readable_stream(*id);
    if (!chunk.empty())
    {
      received.insert(received.end(), chunk.begin(), chunk.end());
      server->consume_stream(*id, chunk.size());
      moved = true;
    }

    for (;;)
    {
      std::vector<std::uint8_t> datagram(1500);
      auto size = server->poll_send(datagram, now);
      REQUIRE(size.has_value());
      if (*size == 0)
      {
        break;
      }
      datagram.resize(*size);
      REQUIRE(client->receive(datagram, now).has_value());
      moved = true;
    }

    if (!moved)
    {
      if (received.size() >= payload.size())
      {
        break;
      }
      auto deadline = client->next_timeout(now);
      auto other = server->next_timeout(now);
      if (other.has_value() && (!deadline.has_value() || *other < *deadline))
      {
        deadline = other;
      }
      REQUIRE(deadline.has_value());
      now = *deadline > now ? *deadline : now + std::chrono::nanoseconds(1ms);
    }
  }

  REQUIRE(received.size() == payload.size());
  CHECK(received == payload);
  CHECK_FALSE(client->close_reason().has_value());
  CHECK_FALSE(server->close_reason().has_value());
}

TEST_CASE("a peer that ignores the connection flow control limit is closed on")
{
  const auto identity = make_self_signed("localhost");
  auto contexts = make_contexts(identity);

  // The server advertises a tiny connection-level limit.
  connection_config_t server_config;
  server_config.role = tls_role_t::server;
  server_config.transport_parameters = sane_parameters();
  server_config.transport_parameters.initial_max_data = 16;
  server_config.transport_parameters.initial_max_stream_data_bidi_remote = 1000;

  connection_config_t client_config;
  client_config.role = tls_role_t::client;
  client_config.transport_parameters = sane_parameters();

  auto server = connection_t::create(contexts.server_context, server_config);
  REQUIRE(server.has_value());
  auto client = connection_t::create(contexts.client_context, client_config, "localhost");
  REQUIRE(client.has_value());

  run_handshake(*client, *server, at(0ns));
  REQUIRE(client->handshake_complete());

  auto id = client->open_stream(stream_direction_t::bidirectional);
  REQUIRE(id.has_value());

  // A well-behaved client will not exceed the limit, so this asserts the
  // other half of the contract: it stops rather than overrunning.
  std::vector<std::uint8_t> payload(100, 0xab);
  CHECK(client->write_stream(*id, payload, false) == payload.size());
  run_handshake(*client, *server, at(0ns));

  CHECK_FALSE(server->close_reason().has_value());
  auto data = server->readable_stream(*id);
  // Section 4.1: no more than the advertised sixteen bytes may arrive.
  CHECK(data.size() <= 16);
}

TEST_CASE("a reset stream tells the peer how much credit it consumed")
{
  const auto identity = make_self_signed("localhost");
  auto contexts = make_contexts(identity);

  connection_config_t server_config;
  server_config.role = tls_role_t::server;
  server_config.transport_parameters = sane_parameters();
  connection_config_t client_config;
  client_config.role = tls_role_t::client;
  client_config.transport_parameters = sane_parameters();

  auto server = connection_t::create(contexts.server_context, server_config);
  REQUIRE(server.has_value());
  auto client = connection_t::create(contexts.client_context, client_config, "localhost");
  REQUIRE(client.has_value());

  run_handshake(*client, *server, at(0ns));
  auto id = client->open_stream(stream_direction_t::bidirectional);
  REQUIRE(id.has_value());

  std::vector<std::uint8_t> payload(50, 0x5a);
  CHECK(client->write_stream(*id, payload, false) == payload.size());
  client->reset_stream(*id, 42);

  run_handshake(*client, *server, at(0ns));

  // Section 4.5: the final size arrives whichever way the stream ended, so
  // both endpoints agree what it cost.
  CHECK(server->stream_receive_finished(*id));
  CHECK_FALSE(server->close_reason().has_value());
  CHECK_FALSE(client->close_reason().has_value());
}

TEST_CASE("STOP_SENDING reaches the peer and stops it")
{
  const auto identity = make_self_signed("localhost");
  auto contexts = make_contexts(identity);

  connection_config_t server_config;
  server_config.role = tls_role_t::server;
  server_config.transport_parameters = sane_parameters();
  connection_config_t client_config;
  client_config.role = tls_role_t::client;
  client_config.transport_parameters = sane_parameters();

  auto server = connection_t::create(contexts.server_context, server_config);
  REQUIRE(server.has_value());
  auto client = connection_t::create(contexts.client_context, client_config, "localhost");
  REQUIRE(client.has_value());

  run_handshake(*client, *server, at(0ns));
  auto id = client->open_stream(stream_direction_t::bidirectional);
  REQUIRE(id.has_value());
  std::vector<std::uint8_t> payload(20, 0x11);
  CHECK(client->write_stream(*id, payload, false) == payload.size());
  run_handshake(*client, *server, at(0ns));

  server->stop_sending(*id, 13);
  run_handshake(*client, *server, at(0ns));

  // Section 3.5: the client answers a STOP_SENDING with a RESET_STREAM
  // rather than continuing to send into a void.
  CHECK_FALSE(client->close_reason().has_value());
  CHECK_FALSE(server->close_reason().has_value());
  CHECK(client->stream_send_finished(*id));
}

TEST_CASE("streams survive a lossy link")
{
  const auto identity = make_self_signed("localhost");
  auto contexts = make_contexts(identity);

  connection_config_t server_config;
  server_config.role = tls_role_t::server;
  server_config.transport_parameters = sane_parameters();
  connection_config_t client_config;
  client_config.role = tls_role_t::client;
  client_config.transport_parameters = sane_parameters();

  auto server = connection_t::create(contexts.server_context, server_config);
  REQUIRE(server.has_value());
  auto client = connection_t::create(contexts.client_context, client_config, "localhost");
  REQUIRE(client.has_value());

  run_handshake(*client, *server, at(0ns));
  auto id = client->open_stream(stream_direction_t::bidirectional);
  REQUIRE(id.has_value());

  std::vector<std::uint8_t> payload(5000);
  for (std::size_t i = 0; i < payload.size(); ++i)
  {
    payload[i] = static_cast<std::uint8_t>(i * 17 + 3);
  }
  CHECK(client->write_stream(*id, payload, true) == payload.size());

  std::vector<std::uint8_t> received;
  auto now = at(0ns);
  int sent = 0;
  int dropped = 0;

  for (int round = 0; round < 400 && received.size() < payload.size(); ++round)
  {
    bool moved = false;
    for (;;)
    {
      std::vector<std::uint8_t> datagram(1500);
      auto size = client->poll_send(datagram, now);
      REQUIRE(size.has_value());
      if (*size == 0)
      {
        break;
      }
      datagram.resize(*size);
      moved = true;
      // Every third datagram never arrives.
      if (sent++ % 3 == 1)
      {
        ++dropped;
        continue;
      }
      REQUIRE(server->receive(datagram, now).has_value());
    }

    auto chunk = server->readable_stream(*id);
    if (!chunk.empty())
    {
      received.insert(received.end(), chunk.begin(), chunk.end());
      server->consume_stream(*id, chunk.size());
      moved = true;
    }

    for (;;)
    {
      std::vector<std::uint8_t> datagram(1500);
      auto size = server->poll_send(datagram, now);
      REQUIRE(size.has_value());
      if (*size == 0)
      {
        break;
      }
      datagram.resize(*size);
      REQUIRE(client->receive(datagram, now).has_value());
      moved = true;
    }

    if (!moved)
    {
      auto deadline = client->next_timeout(now);
      auto other = server->next_timeout(now);
      if (other.has_value() && (!deadline.has_value() || *other < *deadline))
      {
        deadline = other;
      }
      if (!deadline.has_value())
      {
        break;
      }
      now = *deadline > now ? *deadline : now + std::chrono::nanoseconds(1ms);
    }
  }

  CHECK(dropped > 0);
  REQUIRE(received.size() == payload.size());
  CHECK(received == payload);
}

TEST_CASE("a Retry validates the client address before any handshake work")
{
  const auto identity = make_self_signed("localhost");
  auto contexts = make_contexts(identity);

  retry_token_key_t retry_key;
  REQUIRE(retry_key.generate().has_value());
  const std::vector<std::uint8_t> address = {192, 0, 2, 1, 0x1f, 0x90};

  connection_config_t server_config;
  server_config.role = tls_role_t::server;
  server_config.transport_parameters = sane_parameters();
  server_config.retry_key = &retry_key;
  server_config.peer_address = address;

  connection_config_t client_config;
  client_config.role = tls_role_t::client;
  client_config.transport_parameters = sane_parameters();

  auto server = connection_t::create(contexts.server_context, server_config);
  REQUIRE(server.has_value());
  auto client = connection_t::create(contexts.client_context, client_config, "localhost");
  REQUIRE(client.has_value());

  // The client's first Initial.
  std::vector<std::uint8_t> first(1500);
  auto size = client->poll_send(first, at(0ns));
  REQUIRE(size.has_value());
  first.resize(*size);
  REQUIRE(server->receive(first, at(0ns)).has_value());

  // The server answers with a Retry rather than doing handshake work.
  CHECK_FALSE(server->handshake_complete());
  std::vector<std::uint8_t> retry(1500);
  auto retry_size = server->poll_send(retry, at(0ns));
  REQUIRE(retry_size.has_value());
  REQUIRE(*retry_size > 0);
  retry.resize(*retry_size);

  packet_reader_t reader(retry, 0);
  auto header = reader.next();
  REQUIRE(header.has_value());
  REQUIRE(header->has_value());
  CHECK(header->value().kind == packet_kind_t::retry);
  CHECK_FALSE(header->value().retry_token.empty());

  REQUIRE(client->receive(retry, at(0ns)).has_value());
  CHECK(client->address_validated_by_retry());
  // Section 17.2.5.3: the client now addresses the server by the ID it chose.
  CHECK(client->peer_connection_id() == server->local_connection_id());

  // The client comes back with the token, and only now does the server do any
  // handshake work.
  const auto exchange = run_handshake(*client, *server, at(0ns));
  CAPTURE(exchange.rounds);
  CHECK(client->handshake_complete());
  CHECK(server->handshake_complete());
  CHECK(server->address_validated_by_retry());
  CHECK_FALSE(client->close_reason().has_value());
  CHECK_FALSE(server->close_reason().has_value());
  CHECK(client->selected_alpn() == "h3");

  SUBCASE("and the server echoed the original connection id back")
  {
    // Section 8.1.4: the client can only tell a genuine Retry from an injected
    // one by seeing the connection ID it first chose come back through the
    // handshake, which the token is what let the server recover.
    auto parameters = client->peer_transport_parameters();
    REQUIRE(parameters.has_value());
    REQUIRE(parameters->original_destination_connection_id.has_value());
    REQUIRE(parameters->retry_source_connection_id.has_value());
    CHECK(*parameters->retry_source_connection_id == server->local_connection_id());
  }
}

TEST_CASE("a Retry that cannot be trusted is discarded")
{
  const auto identity = make_self_signed("localhost");
  auto contexts = make_contexts(identity);

  retry_token_key_t retry_key;
  REQUIRE(retry_key.generate().has_value());
  const std::vector<std::uint8_t> address = {10, 0, 0, 1};

  connection_config_t server_config;
  server_config.role = tls_role_t::server;
  server_config.transport_parameters = sane_parameters();
  server_config.retry_key = &retry_key;
  server_config.peer_address = address;
  connection_config_t client_config;
  client_config.role = tls_role_t::client;
  client_config.transport_parameters = sane_parameters();

  const auto make_retry = [&]()
  {
    auto server = connection_t::create(contexts.server_context, server_config);
    REQUIRE(server.has_value());
    auto client = connection_t::create(contexts.client_context, client_config, "localhost");
    REQUIRE(client.has_value());
    std::vector<std::uint8_t> first(1500);
    auto size = client->poll_send(first, at(0ns));
    REQUIRE(size.has_value());
    first.resize(*size);
    REQUIRE(server->receive(first, at(0ns)).has_value());
    std::vector<std::uint8_t> retry(1500);
    auto retry_size = server->poll_send(retry, at(0ns));
    REQUIRE(retry_size.has_value());
    retry.resize(*retry_size);
    return std::make_pair(std::move(*client), std::move(retry));
  };

  SUBCASE("a corrupted integrity tag")
  {
    auto [client, retry] = make_retry();
    // Section 5.8 of RFC 9001: the tag is what proves the sender saw the
    // client's Initial. Anyone on the path can write a Retry otherwise.
    retry[retry.size() - 1] ^= 0x01;
    REQUIRE(client.receive(retry, at(0ns)).has_value());
    CHECK_FALSE(client.address_validated_by_retry());
  }

  SUBCASE("a corrupted token, which the tag also covers")
  {
    auto [client, retry] = make_retry();
    retry[20] ^= 0xff;
    REQUIRE(client.receive(retry, at(0ns)).has_value());
    CHECK_FALSE(client.address_validated_by_retry());
  }

  SUBCASE("a second Retry after the first")
  {
    auto [client, retry] = make_retry();
    REQUIRE(client.receive(retry, at(0ns)).has_value());
    CHECK(client.address_validated_by_retry());
    const auto adopted = client.peer_connection_id();

    // Section 17.2.5.2: at most one per connection attempt. A second is an
    // injected packet trying to redirect the connection.
    auto [ignored, second] = make_retry();
    REQUIRE(client.receive(second, at(0ns)).has_value());
    CHECK(client.peer_connection_id() == adopted);
  }
}

TEST_CASE("a Retry token is bound to the address it was issued to")
{
  retry_token_key_t key;
  REQUIRE(key.generate().has_value());

  const auto raw = std::vector<std::uint8_t>{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
  auto original = connection_id_t::from_bytes(raw);
  REQUIRE(original.has_value());
  const std::vector<std::uint8_t> address = {198, 51, 100, 7};

  auto token = key.issue(*original, address, at(0ns));
  REQUIRE(token.has_value());

  auto recovered = key.validate(*token, address, at(1s));
  REQUIRE(recovered.has_value());
  CHECK(recovered->kind == address_token_kind_t::retry);
  CHECK(recovered->original_destination_id == *original);

  SUBCASE("a different address does not validate")
  {
    // This is the attack Retry exists to stop: a token captured from one
    // client replayed to make the server work for a spoofed source.
    const std::vector<std::uint8_t> other = {198, 51, 100, 8};
    auto result = key.validate(*token, other, at(1s));
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == retry_token_error_t::not_authentic);
  }

  SUBCASE("a different key does not validate")
  {
    retry_token_key_t stranger;
    REQUIRE(stranger.generate().has_value());
    auto result = stranger.validate(*token, address, at(1s));
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == retry_token_error_t::not_authentic);
  }

  SUBCASE("an expired token does not validate")
  {
    // Without a lifetime one captured token is a permanent bypass.
    auto result = key.validate(*token, address, at(60s));
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == retry_token_error_t::expired);
  }

  SUBCASE("a token from the future does not validate")
  {
    auto result = key.validate(*token, address, at(0ns) - std::chrono::nanoseconds(1s));
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == retry_token_error_t::expired);
  }

  SUBCASE("every single byte corruption fails to authenticate")
  {
    for (std::size_t index = 0; index < token->size(); index += 5)
    {
      CAPTURE(index);
      auto tampered = *token;
      tampered[index] ^= 0x40;
      auto result = key.validate(tampered, address, at(1s));
      REQUIRE_FALSE(result.has_value());
    }
  }

  SUBCASE("a truncated token is malformed rather than merely wrong")
  {
    std::vector<std::uint8_t> short_token(token->begin(), token->end() - 1);
    auto result = key.validate(short_token, address, at(1s));
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == retry_token_error_t::malformed);
    CHECK_FALSE(key.validate({}, address, at(1s)).has_value());
  }

  SUBCASE("a zero length connection id round trips")
  {
    auto empty = key.issue(connection_id_t{}, address, at(0ns));
    REQUIRE(empty.has_value());
    auto back = key.validate(*empty, address, at(1s));
    REQUIRE(back.has_value());
    CHECK(back->original_destination_id.empty());
  }
}

TEST_CASE("a key update carries data across the phase change")
{
  const auto identity = make_self_signed("localhost");
  auto contexts = make_contexts(identity);

  connection_config_t server_config;
  server_config.role = tls_role_t::server;
  server_config.transport_parameters = sane_parameters();
  connection_config_t client_config;
  client_config.role = tls_role_t::client;
  client_config.transport_parameters = sane_parameters();

  auto server = connection_t::create(contexts.server_context, server_config);
  REQUIRE(server.has_value());
  auto client = connection_t::create(contexts.client_context, client_config, "localhost");
  REQUIRE(client.has_value());

  run_handshake(*client, *server, at(0ns));
  REQUIRE(client->handshake_confirmed());
  REQUIRE(server->handshake_confirmed());

  auto id = client->open_stream(stream_direction_t::bidirectional);
  REQUIRE(id.has_value());
  const std::vector<std::uint8_t> before = {'b', 'e', 'f', 'o', 'r', 'e'};
  CHECK(client->write_stream(*id, before, false) == before.size());
  run_handshake(*client, *server, at(0ns));

  auto first = server->readable_stream(*id);
  CHECK(std::string(reinterpret_cast<const char *>(first.data()), first.size()) == "before");
  server->consume_stream(*id, first.size());

  REQUIRE(client->initiate_key_update());
  CHECK(client->key_phase());
  // Section 6.1: nothing from this phase has been acknowledged yet, so
  // updating again would leave the peer without the keys to read on.
  CHECK_FALSE(client->initiate_key_update());

  const std::vector<std::uint8_t> after = {'a', 'f', 't', 'e', 'r'};
  CHECK(client->write_stream(*id, after, true) == after.size());
  run_handshake(*client, *server, at(0ns));

  // Section 6.2: the server detected the phase change, opened the packet with
  // the next generation, and moved its own send keys to match.
  CHECK(server->key_phase());
  auto second = server->readable_stream(*id);
  CHECK(std::string(reinterpret_cast<const char *>(second.data()), second.size()) == "after");
  CHECK_FALSE(client->close_reason().has_value());
  CHECK_FALSE(server->close_reason().has_value());

  SUBCASE("and traffic keeps flowing in both directions afterwards")
  {
    server->consume_stream(*id, second.size());
    // The client finished its half; the server's half of the same stream is
    // still open, and now protected by the new generation.
    const std::vector<std::uint8_t> reply = {'o', 'k'};
    CHECK(server->write_stream(*id, reply, true) == reply.size());
    run_handshake(*client, *server, at(0ns));
    auto back = client->readable_stream(*id);
    CHECK(std::string(reinterpret_cast<const char *>(back.data()), back.size()) == "ok");
    CHECK(client->key_phase());
    CHECK_FALSE(client->close_reason().has_value());
  }

  SUBCASE("and once this phase is acknowledged another update is allowed")
  {
    // The exchange above carried an acknowledgement of a packet sent in the
    // new phase, which is exactly the condition section 6.1 waits for.
    CHECK(client->initiate_key_update());
    CHECK_FALSE(client->key_phase());
  }
}

TEST_CASE("a key update cannot be initiated before the handshake is confirmed")
{
  const auto identity = make_self_signed("localhost");
  auto contexts = make_contexts(identity);

  connection_config_t client_config;
  client_config.role = tls_role_t::client;
  client_config.transport_parameters = sane_parameters();
  auto client = connection_t::create(contexts.client_context, client_config, "localhost");
  REQUIRE(client.has_value());

  // Section 6.1: not before confirmation, because the peer may not yet have
  // the keys the update would move away from.
  CHECK_FALSE(client->initiate_key_update());
  CHECK_FALSE(client->key_phase());
}

TEST_CASE("an idle connection is discarded once both sides stop talking")
{
  const auto identity = make_self_signed("localhost");
  auto contexts = make_contexts(identity);

  connection_config_t server_config;
  server_config.role = tls_role_t::server;
  server_config.transport_parameters = sane_parameters();
  server_config.transport_parameters.max_idle_timeout = 30000;
  connection_config_t client_config;
  client_config.role = tls_role_t::client;
  client_config.transport_parameters = sane_parameters();
  // Section 10.1: the effective value is the smaller of the two.
  client_config.transport_parameters.max_idle_timeout = 5000;

  auto server = connection_t::create(contexts.server_context, server_config);
  REQUIRE(server.has_value());
  auto client = connection_t::create(contexts.client_context, client_config, "localhost");
  REQUIRE(client.has_value());

  run_handshake(*client, *server, at(0ns));
  REQUIRE(client->handshake_complete());

  auto deadline = client->next_timeout(at(0ns));
  REQUIRE(deadline.has_value());

  std::vector<std::uint8_t> datagram(1500);
  auto idle = client->poll_send(datagram, at(1s));
  REQUIRE(idle.has_value());
  CHECK(client->state() != connection_state_t::closed);

  auto expired = client->poll_send(datagram, at(120s));
  REQUIRE(expired.has_value());
  CHECK(*expired == 0);
  // Silently, with no CONNECTION_CLOSE: there is nobody there to read one,
  // which is why the timer fired.
  CHECK(client->state() == connection_state_t::closed);
  CHECK_FALSE(client->close_reason().has_value());

  SUBCASE("and a connection with no advertised timeout never expires")
  {
    connection_config_t forever;
    forever.role = tls_role_t::client;
    forever.transport_parameters = sane_parameters();
    forever.transport_parameters.max_idle_timeout = 0;
    auto other_server = connection_t::create(contexts.server_context, server_config);
    REQUIRE(other_server.has_value());
    auto patient = connection_t::create(contexts.client_context, forever, "localhost");
    REQUIRE(patient.has_value());
    run_handshake(*patient, *other_server, at(0ns));
    // The server still advertises one, so the sole non-zero value applies.
    CHECK(patient->next_timeout(at(0ns)).has_value());
  }
}

TEST_CASE("stream credit comes back as the application finishes with streams")
{
  const auto identity = make_self_signed("localhost");
  auto contexts = make_contexts(identity);

  connection_config_t server_config;
  server_config.role = tls_role_t::server;
  server_config.transport_parameters = sane_parameters();
  // Room for exactly one peer-initiated bidirectional stream at a time.
  server_config.transport_parameters.initial_max_streams_bidi = 1;

  connection_config_t client_config;
  client_config.role = tls_role_t::client;
  client_config.transport_parameters = sane_parameters();

  auto server = connection_t::create(contexts.server_context, server_config);
  REQUIRE(server.has_value());
  auto client = connection_t::create(contexts.client_context, client_config, "localhost");
  REQUIRE(client.has_value());

  run_handshake(*client, *server, at(0ns));
  REQUIRE(client->handshake_complete());

  auto first = client->open_stream(stream_direction_t::bidirectional);
  REQUIRE(first.has_value());
  // Section 4.6: the peer said one, so one it is.
  CHECK_FALSE(client->open_stream(stream_direction_t::bidirectional).has_value());

  const std::vector<std::uint8_t> payload = {'h', 'i'};
  CHECK(client->write_stream(*first, payload, true) == payload.size());
  run_handshake(*client, *server, at(0ns));

  auto data = server->readable_stream(*first);
  REQUIRE(data.size() == payload.size());
  server->consume_stream(*first, data.size());
  // The server's own half is finished too, so the stream is done with.
  server->reset_stream(*first, 0);
  server->consume_stream(*first, 0);
  run_handshake(*client, *server, at(0ns));

  // A MAX_STREAMS came back, so the client may open another.
  auto second = client->open_stream(stream_direction_t::bidirectional);
  CHECK(second.has_value());
  CHECK_FALSE(client->close_reason().has_value());
  CHECK_FALSE(server->close_reason().has_value());
}

TEST_CASE("a Retry arriving after the handshake has started is ignored")
{
  const auto identity = make_self_signed("localhost");
  auto contexts = make_contexts(identity);

  retry_token_key_t retry_key;
  REQUIRE(retry_key.generate().has_value());
  const std::vector<std::uint8_t> address = {10, 1, 1, 1};

  // One pair that does a Retry, purely to obtain a well-formed Retry packet.
  connection_config_t retry_server_config;
  retry_server_config.role = tls_role_t::server;
  retry_server_config.transport_parameters = sane_parameters();
  retry_server_config.retry_key = &retry_key;
  retry_server_config.peer_address = address;
  connection_config_t client_config;
  client_config.role = tls_role_t::client;
  client_config.transport_parameters = sane_parameters();

  auto retry_server = connection_t::create(contexts.server_context, retry_server_config);
  REQUIRE(retry_server.has_value());
  auto bait = connection_t::create(contexts.client_context, client_config, "localhost");
  REQUIRE(bait.has_value());
  std::vector<std::uint8_t> hello(1500);
  auto hello_size = bait->poll_send(hello, at(0ns));
  REQUIRE(hello_size.has_value());
  hello.resize(*hello_size);
  REQUIRE(retry_server->receive(hello, at(0ns)).has_value());
  std::vector<std::uint8_t> retry(1500);
  auto retry_size = retry_server->poll_send(retry, at(0ns));
  REQUIRE(retry_size.has_value());
  retry.resize(*retry_size);

  // A separate, ordinary handshake that gets as far as a server Initial.
  connection_config_t plain_server_config;
  plain_server_config.role = tls_role_t::server;
  plain_server_config.transport_parameters = sane_parameters();
  auto server = connection_t::create(contexts.server_context, plain_server_config);
  REQUIRE(server.has_value());
  auto client = connection_t::create(contexts.client_context, client_config, "localhost");
  REQUIRE(client.has_value());
  run_handshake(*client, *server, at(0ns));
  REQUIRE(client->handshake_complete());

  const auto established = client->peer_connection_id();
  REQUIRE(client->receive(retry, at(0ns)).has_value());
  // Section 17.2.5.2: too late. Acting on it would let anyone on the path
  // redirect an established connection.
  CHECK_FALSE(client->address_validated_by_retry());
  CHECK(client->peer_connection_id() == established);
}

TEST_CASE("a configuration that cannot work is refused up front")
{
  const auto identity = make_self_signed("localhost");
  auto contexts = make_contexts(identity);

  SUBCASE("a connection id longer than twenty bytes")
  {
    connection_config_t config;
    config.role = tls_role_t::server;
    config.local_connection_id_length = 21;
    CHECK_FALSE(connection_t::create(contexts.server_context, config).has_value());
  }

  SUBCASE("a datagram size below what section 14 requires")
  {
    connection_config_t config;
    config.role = tls_role_t::server;
    config.max_datagram_size = 1199;
    CHECK_FALSE(connection_t::create(contexts.server_context, config).has_value());
  }

  SUBCASE("a zero length connection id is allowed")
  {
    connection_config_t config;
    config.role = tls_role_t::client;
    config.local_connection_id_length = 0;
    auto connection = connection_t::create(contexts.client_context, config, "localhost");
    REQUIRE(connection.has_value());
    CHECK(connection->local_connection_id().empty());
  }
}
TEST_CASE("path validation runs between two connections")
{
  const auto identity = make_self_signed("localhost");
  auto contexts = make_contexts(identity);

  connection_config_t server_config;
  server_config.role = tls_role_t::server;
  server_config.transport_parameters = sane_parameters();
  connection_config_t client_config;
  client_config.role = tls_role_t::client;
  client_config.transport_parameters = sane_parameters();

  auto server = connection_t::create(contexts.server_context, server_config);
  REQUIRE(server.has_value());
  auto client = connection_t::create(contexts.client_context, client_config, "localhost");
  REQUIRE(client.has_value());
  REQUIRE(run_handshake(*client, *server, at(0ns)).rounds > 0);
  REQUIRE(client->handshake_complete());

  // Everything either side has to say, until both go quiet. Returns what the
  // client put on the wire so a test can look at the datagrams themselves.
  auto pump = [&](vio::tick_t now)
  {
    std::vector<std::vector<std::uint8_t>> from_client;
    for (int round = 0; round < 8; ++round)
    {
      bool moved = false;
      for (;;)
      {
        std::vector<std::uint8_t> datagram(1500);
        auto size = client->poll_send(datagram, now);
        REQUIRE(size.has_value());
        if (*size == 0)
        {
          break;
        }
        datagram.resize(*size);
        from_client.push_back(datagram);
        REQUIRE(server->receive(datagram, now).has_value());
        moved = true;
      }
      for (;;)
      {
        std::vector<std::uint8_t> datagram(1500);
        auto size = server->poll_send(datagram, now);
        REQUIRE(size.has_value());
        if (*size == 0)
        {
          break;
        }
        datagram.resize(*size);
        REQUIRE(client->receive(datagram, now).has_value());
        moved = true;
      }
      if (!moved)
      {
        break;
      }
    }
    return from_client;
  };

  SUBCASE("a challenge is answered and the path becomes validated")
  {
    CHECK(client->path_state() == path_state_t::unknown);
    client->validate_path(at(1ms));
    CHECK(client->path_state() == path_state_t::validating);

    const auto sent = pump(at(1ms));
    REQUIRE_FALSE(sent.empty());
    CHECK(client->path_state() == path_state_t::validated);
  }

  SUBCASE("the datagram carrying a challenge is expanded to 1200 bytes")
  {
    // Sections 8.2.1 and 8.2.2: a path proven reachable is also proven to
    // carry a full-size datagram, so a validation that fit in 40 bytes would
    // certify an MTU it never tested.
    client->validate_path(at(1ms));
    const auto sent = pump(at(1ms));
    REQUIRE_FALSE(sent.empty());
    CHECK(sent.front().size() == 1200);
  }

  SUBCASE("an attempt whose responses never arrive is abandoned")
  {
    client->validate_path(at(1ms));
    // Send only into the void: the server never sees a challenge, so nothing
    // is ever echoed.
    for (int round = 0; round < 4; ++round)
    {
      std::vector<std::uint8_t> datagram(1500);
      auto size = client->poll_send(datagram, at(1ms));
      REQUIRE(size.has_value());
    }
    CHECK(client->path_state() == path_state_t::validating);

    // The deadline is three times a PTO built from the initial RTT, which is
    // comfortably under ten seconds.
    std::vector<std::uint8_t> datagram(1500);
    REQUIRE(client->poll_send(datagram, at(10s)).has_value());
    CHECK(client->path_state() == path_state_t::failed);
  }

  SUBCASE("the deadline is reported so a caller knows when to come back")
  {
    client->validate_path(at(1ms));
    const auto deadline = client->next_timeout(at(1ms));
    REQUIRE(deadline.has_value());
    CHECK(*deadline > at(1ms));
  }
}
TEST_CASE("connection ids are exchanged up to the advertised limit")
{
  const auto identity = make_self_signed("localhost");
  auto contexts = make_contexts(identity);

  connection_config_t server_config;
  server_config.role = tls_role_t::server;
  server_config.transport_parameters = sane_parameters();
  server_config.transport_parameters.active_connection_id_limit = 4;
  connection_config_t client_config;
  client_config.role = tls_role_t::client;
  client_config.transport_parameters = sane_parameters();
  client_config.transport_parameters.active_connection_id_limit = 4;

  auto server = connection_t::create(contexts.server_context, server_config);
  REQUIRE(server.has_value());
  auto client = connection_t::create(contexts.client_context, client_config, "localhost");
  REQUIRE(client.has_value());
  REQUIRE(run_handshake(*client, *server, at(0ns)).rounds > 0);
  REQUIRE(client->handshake_complete());

  for (int round = 0; round < 6; ++round)
  {
    for (;;)
    {
      std::vector<std::uint8_t> datagram(1500);
      auto size = client->poll_send(datagram, at(1ms));
      REQUIRE(size.has_value());
      if (*size == 0)
      {
        break;
      }
      datagram.resize(*size);
      REQUIRE(server->receive(datagram, at(1ms)).has_value());
    }
    for (;;)
    {
      std::vector<std::uint8_t> datagram(1500);
      auto size = server->poll_send(datagram, at(1ms));
      REQUIRE(size.has_value());
      if (*size == 0)
      {
        break;
      }
      datagram.resize(*size);
      REQUIRE(client->receive(datagram, at(1ms)).has_value());
    }
  }

  // Section 5.1.1: neither side may exceed what the other advertised, and both
  // should fill up to it so the peer can migrate without asking first.
  CHECK(client->issued_connection_id_count() == 4);
  CHECK(server->issued_connection_id_count() == 4);
  CHECK(client->peer_connection_id_count() == 4);
  CHECK(server->peer_connection_id_count() == 4);
  CHECK_FALSE(client->close_reason().has_value());
  CHECK_FALSE(server->close_reason().has_value());
}
TEST_CASE("a peer that moves is followed, cautiously")
{
  const auto identity = make_self_signed("localhost");
  auto contexts = make_contexts(identity);

  connection_config_t server_config;
  server_config.role = tls_role_t::server;
  server_config.transport_parameters = sane_parameters();
  server_config.transport_parameters.active_connection_id_limit = 4;
  connection_config_t client_config;
  client_config.role = tls_role_t::client;
  client_config.transport_parameters = sane_parameters();
  client_config.transport_parameters.active_connection_id_limit = 4;

  auto server = connection_t::create(contexts.server_context, server_config);
  REQUIRE(server.has_value());
  auto client = connection_t::create(contexts.client_context, client_config, "localhost");
  REQUIRE(client.has_value());

  const std::vector<std::uint8_t> home = {10, 0, 0, 1, 0xc0, 0x00};
  const std::vector<std::uint8_t> away = {10, 0, 0, 2, 0xc0, 0x01};

  // The handshake, with every client datagram arriving from the same address.
  auto deliver_to_server = [&](vio::tick_t now, const std::vector<std::uint8_t> &from)
  {
    std::size_t count = 0;
    for (;;)
    {
      std::vector<std::uint8_t> datagram(1500);
      auto size = client->poll_send(datagram, now);
      REQUIRE(size.has_value());
      if (*size == 0)
      {
        break;
      }
      datagram.resize(*size);
      REQUIRE(server->receive(datagram, now, from).has_value());
      ++count;
    }
    return count;
  };
  auto deliver_to_client = [&](vio::tick_t now)
  {
    for (;;)
    {
      std::vector<std::uint8_t> datagram(1500);
      auto size = server->poll_send(datagram, now);
      REQUIRE(size.has_value());
      if (*size == 0)
      {
        break;
      }
      datagram.resize(*size);
      REQUIRE(client->receive(datagram, now).has_value());
    }
  };

  for (int round = 0; round < 8; ++round)
  {
    const auto moved = deliver_to_server(at(0ns), home);
    deliver_to_client(at(0ns));
    if (moved == 0 && client->handshake_complete())
    {
      break;
    }
  }
  REQUIRE(client->handshake_complete());
  REQUIRE(server->handshake_complete());
  CHECK(server->migration_count() == 0);

  // The path has to exist before it can be left. Migration is a 1-RTT concept
  // -- section 9.3 compares against the address the connection is already
  // using -- and the handshake runs entirely in the Initial and Handshake
  // spaces, so until a 1-RTT packet arrives the server has no address to
  // compare against and simply adopts whatever it first sees.
  auto warmup = client->open_stream(stream_direction_t::bidirectional);
  REQUIRE(warmup.has_value());
  const std::vector<std::uint8_t> hello = {'h', 'o', 'm', 'e'};
  REQUIRE(client->write_stream(*warmup, hello, true) == hello.size());
  REQUIRE(deliver_to_server(at(0ns), home) > 0);
  deliver_to_client(at(0ns));
  REQUIRE(server->migration_count() == 0);

  // Something non-probing to carry the news: section 9.1 says a packet of
  // probing frames alone proves nothing about where the peer is.
  auto stream = client->open_stream(stream_direction_t::bidirectional);
  REQUIRE(stream.has_value());
  const std::string message = "moved house";
  const std::vector<std::uint8_t> payload(message.begin(), message.end());
  REQUIRE(client->write_stream(*stream, payload, false) == payload.size());

  SUBCASE("staying put is not a migration")
  {
    REQUIRE(deliver_to_server(at(1ms), home) > 0);
    CHECK(server->migration_count() == 0);
  }

  SUBCASE("arriving from somewhere else moves the connection")
  {
    const auto available_before = server->peer_connection_id_count();
    REQUIRE(available_before > 1);
    REQUIRE(deliver_to_server(at(1ms), away) > 0);
    CHECK(server->migration_count() == 1);

    // Section 9.3: the new address is unproven until it answers a challenge.
    CHECK(server->path_state() == path_state_t::validating);

    // Section 9.5: the connection moves to an id the old path never carried,
    // or an observer of both paths links them on sight. The one left behind is
    // kept rather than retired -- the peer may still have it bound to the path
    // it is using, and section 5.1.2 leaves retirement to whoever owns the id.
    CHECK(server->peer_connection_id_count() == available_before);
    CHECK(server->peer_connection_id_count() > 1);
  }

  SUBCASE("the new address earns its allowance from scratch")
  {
    // Section 8 and 9.3.1: a spoofed source address would otherwise make this
    // server into an amplifier aimed at whoever the attacker named. The limit
    // is three times what has arrived *on this path*, not on the old one.
    REQUIRE(deliver_to_server(at(1ms), away) > 0);
    REQUIRE(server->migration_count() == 1);

    std::size_t sent = 0;
    for (int i = 0; i < 20; ++i)
    {
      std::vector<std::uint8_t> datagram(1500);
      auto size = server->poll_send(datagram, at(1ms));
      REQUIRE(size.has_value());
      if (*size == 0)
      {
        break;
      }
      sent += *size;
    }
    CHECK(sent <= 3 * 1500);
  }

  SUBCASE("a replay from a third address does not move the connection again")
  {
    // What the endpoint keys its send address on. A packet that arrives from
    // somewhere new but tells the connection nothing it has not already heard
    // must not count as a move, or anyone able to replay a captured datagram
    // could steer the server away from the real peer.
    std::vector<std::vector<std::uint8_t>> captured;
    for (;;)
    {
      std::vector<std::uint8_t> datagram(1500);
      auto size = client->poll_send(datagram, at(1ms));
      REQUIRE(size.has_value());
      if (*size == 0)
      {
        break;
      }
      datagram.resize(*size);
      captured.push_back(datagram);
      REQUIRE(server->receive(datagram, at(1ms), away).has_value());
    }
    REQUIRE_FALSE(captured.empty());
    REQUIRE(server->migration_count() == 1);

    const std::vector<std::uint8_t> elsewhere = {10, 0, 0, 3, 0xc0, 0x02};
    for (auto &datagram : captured)
    {
      auto copy = datagram;
      REQUIRE(server->receive(copy, at(2ms), elsewhere).has_value());
    }
    CHECK(server->migration_count() == 1);
  }

  SUBCASE("the peer that moved is answered at the new address")
  {
    REQUIRE(deliver_to_server(at(1ms), away) > 0);
    // The challenge the server now owes reaches the client, which echoes it.
    for (int round = 0; round < 4; ++round)
    {
      deliver_to_client(at(1ms));
      (void)deliver_to_server(at(1ms), away);
    }
    CHECK(server->path_state() == path_state_t::validated);
    CHECK_FALSE(server->close_reason().has_value());
  }
}
TEST_CASE("a stateless reset ends the connection and a lookalike does not")
{
  const auto identity = make_self_signed("localhost");
  auto contexts = make_contexts(identity);

  auto reset_key = stateless_reset_key_t::create();
  REQUIRE(reset_key.has_value());

  connection_config_t server_config;
  server_config.role = tls_role_t::server;
  server_config.transport_parameters = sane_parameters();
  server_config.stateless_reset_key = &*reset_key;
  connection_config_t client_config;
  client_config.role = tls_role_t::client;
  client_config.transport_parameters = sane_parameters();

  auto server = connection_t::create(contexts.server_context, server_config);
  REQUIRE(server.has_value());
  auto client = connection_t::create(contexts.client_context, client_config, "localhost");
  REQUIRE(client.has_value());
  REQUIRE(run_handshake(*client, *server, at(0ns)).rounds > 0);
  REQUIRE(client->handshake_complete());
  REQUIRE_FALSE(client->reset_by_peer());

  SUBCASE("the token the server advertised kills the connection")
  {
    // Section 10.3: the client learned this token through the handshake, so
    // only it and the server know the value.
    const auto token = reset_key->token_for(server->local_connection_id());
    std::vector<std::uint8_t> reset(64);
    auto size = build_stateless_reset(reset, token, 1200);
    REQUIRE(size.has_value());
    reset.resize(*size);

    REQUIRE(client->receive(reset, at(1ms)).has_value());
    CHECK(client->reset_by_peer());
    CHECK(client->state() == connection_state_t::closed);

    // Section 10.3.1: nothing further goes out on the connection.
    std::vector<std::uint8_t> datagram(1500);
    auto sent = client->poll_send(datagram, at(2ms));
    REQUIRE(sent.has_value());
    CHECK(*sent == 0);
  }

  SUBCASE("a datagram of zeroes is not a reset")
  {
    // The connection ids in the pool that never came with a token hold a
    // zero-filled placeholder. Comparing against it would let anyone end the
    // connection with a handful of zero bytes.
    std::vector<std::uint8_t> zeroes(64, 0x00);
    REQUIRE(client->receive(zeroes, at(1ms)).has_value());
    CHECK_FALSE(client->reset_by_peer());
    CHECK(client->state() == connection_state_t::connected);
  }

  SUBCASE("a token for a key the server does not hold is not a reset")
  {
    auto other = stateless_reset_key_t::create();
    REQUIRE(other.has_value());
    const auto token = other->token_for(server->local_connection_id());
    std::vector<std::uint8_t> reset(64);
    auto size = build_stateless_reset(reset, token, 1200);
    REQUIRE(size.has_value());
    reset.resize(*size);

    REQUIRE(client->receive(reset, at(1ms)).has_value());
    CHECK_FALSE(client->reset_by_peer());
  }
}
TEST_CASE("version negotiation ends an attempt, but only when it is believable")
{
  const auto identity = make_self_signed("localhost");
  auto contexts = make_contexts(identity);

  connection_config_t client_config;
  client_config.role = tls_role_t::client;
  client_config.transport_parameters = sane_parameters();
  auto client = connection_t::create(contexts.client_context, client_config, "localhost");
  REQUIRE(client.has_value());
  REQUIRE_FALSE(client->version_negotiation_failed());

  auto build = [&](std::span<const std::uint32_t> versions, const connection_id_t &destination)
  {
    std::vector<std::uint8_t> packet(256);
    const auto size = build_version_negotiation(packet, destination, client->peer_connection_id(), versions);
    REQUIRE(size > 0);
    packet.resize(size);
    return packet;
  };

  SUBCASE("a list with nothing this build speaks abandons the attempt")
  {
    const std::array<std::uint32_t, 2> versions = {0x6b3343cf, 0xff00001d};
    auto packet = build(versions, client->local_connection_id());
    REQUIRE(client->receive(packet, at(1ms)).has_value());
    CHECK(client->version_negotiation_failed());
    CHECK(client->state() == connection_state_t::closed);
  }

  SUBCASE("a list naming the version already in use is discarded")
  {
    // Section 6.2. This is exactly what replaying a captured packet produces,
    // and the packet carries no authentication at all.
    const std::array<std::uint32_t, 2> versions = {0x6b3343cf, quic_version_1};
    auto packet = build(versions, client->local_connection_id());
    REQUIRE(client->receive(packet, at(1ms)).has_value());
    CHECK_FALSE(client->version_negotiation_failed());
  }

  SUBCASE("one addressed to a different connection id is discarded")
  {
    const std::array<std::uint32_t, 1> versions = {0x6b3343cf};
    std::array<std::uint8_t, 8> other_bytes = {9, 9, 9, 9, 9, 9, 9, 9};
    auto other = connection_id_t::from_bytes(other_bytes);
    REQUIRE(other.has_value());
    auto packet = build(versions, *other);
    REQUIRE(client->receive(packet, at(1ms)).has_value());
    CHECK_FALSE(client->version_negotiation_failed());
  }

  SUBCASE("one arriving after the handshake has moved is discarded")
  {
    connection_config_t server_config;
    server_config.role = tls_role_t::server;
    server_config.transport_parameters = sane_parameters();
    auto server = connection_t::create(contexts.server_context, server_config);
    REQUIRE(server.has_value());
    REQUIRE(run_handshake(*client, *server, at(0ns)).rounds > 0);
    REQUIRE(client->handshake_complete());

    const std::array<std::uint32_t, 1> versions = {0x6b3343cf};
    auto packet = build(versions, client->local_connection_id());
    REQUIRE(client->receive(packet, at(1ms)).has_value());
    CHECK_FALSE(client->version_negotiation_failed());
    CHECK(client->state() == connection_state_t::connected);
  }

  SUBCASE("a server ignores one entirely")
  {
    // Section 6.1: only servers send them, so one arriving at a server is a
    // forgery by definition.
    connection_config_t server_config;
    server_config.role = tls_role_t::server;
    server_config.transport_parameters = sane_parameters();
    auto server = connection_t::create(contexts.server_context, server_config);
    REQUIRE(server.has_value());

    const std::array<std::uint32_t, 1> versions = {0x6b3343cf};
    auto packet = build(versions, server->local_connection_id());
    REQUIRE(server->receive(packet, at(1ms)).has_value());
    CHECK_FALSE(server->version_negotiation_failed());
  }
}
TEST_CASE("a sender stopped by the peer's limits says so once and then waits")
{
  const auto identity = make_self_signed("localhost");
  auto contexts = make_contexts(identity);

  connection_config_t server_config;
  server_config.role = tls_role_t::server;
  server_config.transport_parameters = sane_parameters();
  // What the client is allowed to send. Small enough that a modest write runs
  // straight into it.
  server_config.transport_parameters.initial_max_data = 4096;
  server_config.transport_parameters.initial_max_stream_data_bidi_remote = 2048;
  server_config.transport_parameters.initial_max_streams_bidi = 1;

  connection_config_t client_config;
  client_config.role = tls_role_t::client;
  client_config.transport_parameters = sane_parameters();

  auto server = connection_t::create(contexts.server_context, server_config);
  REQUIRE(server.has_value());
  auto client = connection_t::create(contexts.client_context, client_config, "localhost");
  REQUIRE(client.has_value());
  REQUIRE(run_handshake(*client, *server, at(0ns)).rounds > 0);
  REQUIRE(client->handshake_complete());

  auto stream = client->open_stream(stream_direction_t::bidirectional);
  REQUIRE(stream.has_value());
  const std::vector<std::uint8_t> payload(64 * 1024, 0x7e);
  REQUIRE(client->write_stream(*stream, payload, false) == payload.size());

  // Section 4.6: the peer allowed exactly one stream, so a second is refused
  // and the peer is told its number is the reason.
  CHECK_FALSE(client->open_stream(stream_direction_t::bidirectional).has_value());

  std::size_t datagrams = 0;
  for (int round = 0; round < 200; ++round)
  {
    std::vector<std::uint8_t> datagram(1500);
    auto size = client->poll_send(datagram, at(1ms));
    REQUIRE(size.has_value());
    if (*size == 0)
    {
      break;
    }
    datagram.resize(*size);
    REQUIRE(server->receive(datagram, at(1ms)).has_value());
    ++datagrams;
  }
  CAPTURE(datagrams);
  REQUIRE(datagrams > 0);
  CHECK_FALSE(server->close_reason().has_value());

  // The point of the exercise: once the limit has been reported the sender
  // stops. Section 13.3 allows one frame per limit, so a connection that kept
  // producing packets here would be spending the network on saying the same
  // thing over and over. Two datagrams carried the data it was allowed plus
  // the blocked signals, and there is nothing further to say at this instant.
  CHECK(datagrams <= 4);
  std::vector<std::uint8_t> datagram(1500);
  auto again = client->poll_send(datagram, at(1ms));
  REQUIRE(again.has_value());
  CHECK(*again == 0);

  // Raising the limit is what starts it moving, and the block is reported
  // again if the new limit also runs out.
  CHECK(client->state() == connection_state_t::connected);
}
TEST_CASE("a token from one connection saves a round trip on the next")
{
  const auto identity = make_self_signed("localhost");
  auto contexts = make_contexts(identity);

  retry_token_key_t key;
  REQUIRE(key.generate().has_value());

  const std::vector<std::uint8_t> address = {4, 192, 168, 1, 5, 0xc0, 0x11};
  // Section 8.1.3: the same address without the port, since the port will not
  // survive to the next connection.
  const std::vector<std::uint8_t> host = {4, 192, 168, 1, 5};

  auto make_server = [&](std::vector<std::uint8_t> token_for_client)
  {
    connection_config_t config;
    config.role = tls_role_t::server;
    config.transport_parameters = sane_parameters();
    config.retry_key = &key;
    config.peer_address = address;
    config.peer_host_address = host;
    (void)token_for_client;
    return connection_t::create(contexts.server_context, config);
  };
  auto make_client = [&](std::vector<std::uint8_t> token)
  {
    connection_config_t config;
    config.role = tls_role_t::client;
    config.transport_parameters = sane_parameters();
    config.address_token = std::move(token);
    return connection_t::create(contexts.client_context, config, "localhost");
  };

  std::vector<std::uint8_t> issued;
  {
    auto server = make_server({});
    REQUIRE(server.has_value());
    auto client = make_client({});
    REQUIRE(client.has_value());

    // No token to present, so the server spends a Retry proving the address.
    REQUIRE(run_handshake(*client, *server, at(0ns)).rounds > 0);
    REQUIRE(client->handshake_complete());
    CHECK(client->address_validated_by_retry());

    // The token rides out once the handshake is confirmed, so keep pumping.
    for (int round = 0; round < 6 && client->new_token().empty(); ++round)
    {
      std::vector<std::uint8_t> datagram(1500);
      auto size = server->poll_send(datagram, at(1ms));
      REQUIRE(size.has_value());
      if (*size > 0)
      {
        datagram.resize(*size);
        REQUIRE(client->receive(datagram, at(1ms)).has_value());
        continue;
      }
      auto back = client->poll_send(datagram, at(1ms));
      REQUIRE(back.has_value());
      if (*back > 0)
      {
        datagram.resize(*back);
        REQUIRE(server->receive(datagram, at(1ms)).has_value());
      }
    }
    issued.assign(client->new_token().begin(), client->new_token().end());
  }

  REQUIRE_FALSE(issued.empty());

  SUBCASE("presenting it means no Retry is needed")
  {
    auto server = make_server({});
    REQUIRE(server.has_value());
    auto client = make_client(issued);
    REQUIRE(client.has_value());

    REQUIRE(run_handshake(*client, *server, at(0ns)).rounds > 0);
    REQUIRE(client->handshake_complete());
    // Section 8.1.3: the address was proven by the token, so the round trip a
    // Retry would have cost was not spent.
    CHECK_FALSE(client->address_validated_by_retry());
    CHECK_FALSE(server->close_reason().has_value());
  }

  SUBCASE("a token issued for a different host does not validate")
  {
    connection_config_t config;
    config.role = tls_role_t::server;
    config.transport_parameters = sane_parameters();
    config.retry_key = &key;
    config.peer_address = {4, 10, 0, 0, 9, 0xc0, 0x11};
    config.peer_host_address = {4, 10, 0, 0, 9};
    auto server = connection_t::create(contexts.server_context, config);
    REQUIRE(server.has_value());
    auto client = make_client(issued);
    REQUIRE(client.has_value());

    // The token is bound to the host it was issued to, so this one falls back
    // to a Retry rather than being taken at face value.
    REQUIRE(run_handshake(*client, *server, at(0ns)).rounds > 0);
    CHECK(client->address_validated_by_retry());
  }
}
}
