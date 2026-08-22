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
}
