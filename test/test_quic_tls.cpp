#include <cstdint>
#include <optional>
#include <ostream>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include <doctest/doctest.h>
#include <vio/quic/anti_replay.h>
#include <vio/quic/frame_codec.h>
#include <vio/quic/protection.h>
#include <vio/quic/tls.h>

#include <vio/ssl_backend.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

// A whole TLS 1.3 handshake with no socket anywhere: the two sessions are
// wired to each other by hand, which is exactly the shape the connection layer
// will drive them in. The last test here is the one that matters most -- it
// takes the secrets a real handshake produced, runs them through the key
// schedule, and protects and opens a packet with them. That is the first time
// every layer built so far runs together.

namespace
{
using namespace vio::quic;

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

// P-256 rather than RSA: this runs on every test invocation, and key
// generation is the only slow part of the whole suite.
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

  // Self-signed and used as its own trust anchor, so it has to look like a CA
  // and carry the name the client will check.
  const std::string alt_name = std::string("DNS:") + common_name;
  X509_EXTENSION *basic = X509V3_EXT_nconf_nid(nullptr, nullptr, NID_basic_constraints, "critical,CA:TRUE");
  REQUIRE(basic != nullptr);
  X509_add_ext(certificate, basic, -1);
  X509_EXTENSION_free(basic);
  X509_EXTENSION *san = X509V3_EXT_nconf_nid(nullptr, nullptr, NID_subject_alt_name, alt_name.c_str());
  REQUIRE(san != nullptr);
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

constexpr encryption_level_t crypto_levels[] = {encryption_level_t::initial, encryption_level_t::handshake, encryption_level_t::application};

// Moves whatever one side has produced into the other, exactly as a
// connection would move it through CRYPTO frames.
bool pump(tls_session_t &from, tls_session_t &to)
{
  bool moved = false;
  for (auto level : crypto_levels)
  {
    const auto pending = from.pending_handshake_data(level);
    if (pending.empty())
    {
      continue;
    }
    // Copied first: consuming invalidates the span.
    const std::vector<std::uint8_t> flight(pending.begin(), pending.end());
    REQUIRE(to.provide_handshake_data(level, flight).has_value());
    from.consume_handshake_data(level, flight.size());
    moved = true;
  }
  return moved;
}

void collect(tls_session_t &session, std::vector<tls_secret_t> &reads, std::vector<tls_secret_t> &writes)
{
  for (auto &secret : session.take_read_secrets())
  {
    reads.push_back(std::move(secret));
  }
  for (auto &secret : session.take_write_secrets())
  {
    writes.push_back(std::move(secret));
  }
}

const tls_secret_t *find(const std::vector<tls_secret_t> &secrets, encryption_level_t level)
{
  for (const auto &secret : secrets)
  {
    if (secret.level == level)
    {
      return &secret;
    }
  }
  return nullptr;
}

// Runs both sides to completion and then a few rounds further. The extra
// rounds are not slack: TLS 1.3 sends its NewSessionTicket after the handshake
// reports done, so a loop that stops at completion never carries the ticket.
void run_handshake(tls_session_t &client, tls_session_t &server)
{
  bool settled = false;
  for (int rounds = 0; rounds < 24; ++rounds)
  {
    REQUIRE(client.advance().has_value());
    const bool client_moved = pump(client, server);
    REQUIRE(server.advance().has_value());
    const bool server_moved = pump(server, client);

    if (client.handshake_complete() && server.handshake_complete() && !client_moved && !server_moved)
    {
      if (settled)
      {
        return;
      }
      settled = true;
    }
  }
}

std::string hex(std::span<const std::uint8_t> data)
{
  static const char *digits = "0123456789abcdef";
  std::string out;
  out.reserve(data.size() * 2);
  for (std::uint8_t byte : data)
  {
    out.push_back(digits[byte >> 4]);
    out.push_back(digits[byte & 0x0f]);
  }
  return out;
}
} // namespace

TEST_SUITE("quic tls")
{
TEST_CASE("a handshake completes with no transport underneath it")
{
  const auto identity = make_self_signed("localhost");
  const std::vector<std::uint8_t> server_parameters = {0x01, 0x02, 0x03, 0x04};
  const std::vector<std::uint8_t> client_parameters = {0x0a, 0x0b};

  tls_config_t server_config;
  server_config.role = tls_role_t::server;
  server_config.certificate_chain_pem = identity.certificate_pem;
  server_config.private_key_pem = identity.private_key_pem;
  server_config.alpn = {"h3"};
  server_config.transport_parameters = server_parameters;

  tls_config_t client_config;
  client_config.role = tls_role_t::client;
  client_config.ca_certificates_pem = identity.certificate_pem;
  client_config.alpn = {"h3"};
  client_config.transport_parameters = client_parameters;

  auto server_context = tls_context_t::create(server_config);
  REQUIRE(server_context.has_value());
  auto client_context = tls_context_t::create(client_config);
  REQUIRE(client_context.has_value());

  auto server = tls_session_t::create(*server_context);
  REQUIRE(server.has_value());
  auto client = tls_session_t::create(*client_context, "localhost");
  REQUIRE(client.has_value());

  std::vector<tls_secret_t> server_reads;
  std::vector<tls_secret_t> server_writes;
  std::vector<tls_secret_t> client_reads;
  std::vector<tls_secret_t> client_writes;

  int rounds = 0;
  for (; rounds < 16; ++rounds)
  {
    auto client_state = client->advance();
    REQUIRE(client_state.has_value());
    collect(*client, client_reads, client_writes);
    const bool client_moved = pump(*client, *server);

    auto server_state = server->advance();
    REQUIRE(server_state.has_value());
    collect(*server, server_reads, server_writes);
    const bool server_moved = pump(*server, *client);

    if (client->handshake_complete() && server->handshake_complete() && !client_moved && !server_moved)
    {
      break;
    }
  }

  CAPTURE(rounds);
  REQUIRE(client->handshake_complete());
  REQUIRE(server->handshake_complete());
  CHECK_FALSE(client->alert().has_value());
  CHECK_FALSE(server->alert().has_value());

  SUBCASE("ALPN was negotiated on both sides")
  {
    CHECK(client->selected_alpn() == "h3");
    CHECK(server->selected_alpn() == "h3");
  }

  SUBCASE("transport parameters crossed in both directions")
  {
    CHECK(hex(client->peer_transport_parameters()) == hex(server_parameters));
    CHECK(hex(server->peer_transport_parameters()) == hex(client_parameters));
  }

  SUBCASE("each side's write secret is the other's read secret")
  {
    for (auto level : {encryption_level_t::handshake, encryption_level_t::application})
    {
      CAPTURE(encryption_level_name(level));
      const auto *client_write = find(client_writes, level);
      const auto *server_read = find(server_reads, level);
      const auto *server_write = find(server_writes, level);
      const auto *client_read = find(client_reads, level);
      REQUIRE(client_write != nullptr);
      REQUIRE(server_read != nullptr);
      REQUIRE(server_write != nullptr);
      REQUIRE(client_read != nullptr);
      CHECK(hex(client_write->secret) == hex(server_read->secret));
      CHECK(hex(server_write->secret) == hex(client_read->secret));
      // And the two directions are not the same secret.
      CHECK(hex(client_write->secret) != hex(server_write->secret));
    }
  }

  SUBCASE("both sides agreed one cipher suite, and it is one QUIC allows")
  {
    const auto *application = find(client_writes, encryption_level_t::application);
    REQUIRE(application != nullptr);
    const auto suite = application->suite;
    const bool allowed = (suite.aead == vio::crypto::aead_t::aes_128_gcm && suite.hash == vio::crypto::hash_t::sha256) || (suite.aead == vio::crypto::aead_t::aes_256_gcm && suite.hash == vio::crypto::hash_t::sha384) ||
                         (suite.aead == vio::crypto::aead_t::chacha20_poly1305 && suite.hash == vio::crypto::hash_t::sha256);
    CHECK(allowed);
    for (const auto &secret : client_writes)
    {
      CHECK(secret.suite.aead == suite.aead);
      CHECK(secret.suite.hash == suite.hash);
    }
  }

  SUBCASE("nothing was ever produced at the early data level")
  {
    CHECK(find(client_writes, encryption_level_t::early_data) == nullptr);
    CHECK(find(client_reads, encryption_level_t::early_data) == nullptr);
    CHECK(find(server_writes, encryption_level_t::early_data) == nullptr);
    CHECK(find(server_reads, encryption_level_t::early_data) == nullptr);
  }

  SUBCASE("the handshake secrets protect a real packet end to end")
  {
    // The whole stack, composed: TLS produced a secret, protection.h turns it
    // into keys, and a 1-RTT packet built with the server's keys opens with
    // the client's.
    const auto *server_write = find(server_writes, encryption_level_t::application);
    const auto *client_read = find(client_reads, encryption_level_t::application);
    REQUIRE(server_write != nullptr);
    REQUIRE(client_read != nullptr);

    auto sender_material = derive_key_material(server_write->suite, server_write->secret);
    REQUIRE(sender_material.has_value());
    packet_protection_t sender;
    REQUIRE(sender.init(server_write->suite, server_write->secret).has_value());
    header_protection_t sender_header;
    REQUIRE(sender_header.init(server_write->suite, sender_material->header_protection).has_value());

    auto receiver_material = derive_key_material(client_read->suite, client_read->secret);
    REQUIRE(receiver_material.has_value());
    packet_protection_t receiver;
    REQUIRE(receiver.init(client_read->suite, client_read->secret).has_value());
    header_protection_t receiver_header;
    REQUIRE(receiver_header.init(client_read->suite, receiver_material->header_protection).has_value());

    const auto connection_id = connection_id_t::from_bytes(std::span<const std::uint8_t>(server_parameters));
    REQUIRE(connection_id.has_value());

    std::vector<std::uint8_t> datagram(256, 0x00);
    packet_builder_t builder(datagram);
    REQUIRE(builder.begin_short(*connection_id, false, false, 7, std::nullopt));

    // A PING frame and nothing else, padded to what the sampling rule needs.
    frame_t ping;
    ping.kind = frame_kind_t::ping;
    frame_t padding;
    padding.kind = frame_kind_t::padding;
    padding.padding_count = builder.minimum_frame_bytes() > 1 ? builder.minimum_frame_bytes() - 1 : 0;

    auto payload = builder.payload_buffer();
    frame_writer_t frames(payload);
    REQUIRE(frames.write(ping));
    if (padding.padding_count > 0)
    {
      REQUIRE(frames.write(padding));
    }
    auto layout = builder.finish(frames.written());
    REQUIRE(layout.has_value());

    auto protected_length = protect_packet(sender, sender_header, datagram, *layout, 7);
    REQUIRE(protected_length.has_value());
    datagram.resize(*protected_length);

    packet_reader_t reader(datagram, connection_id->size());
    auto header = reader.next();
    REQUIRE(header.has_value());
    REQUIRE(header->has_value());
    CHECK(header->value().kind == packet_kind_t::one_rtt);
    CHECK(header->value().destination_id == *connection_id);

    auto opened = unprotect_packet(receiver, receiver_header, datagram, header->value().packet_number_offset, 6);
    REQUIRE(opened.has_value());
    CHECK(opened->packet_number == 7);

    frame_reader_t decoded(opened->payload, packet_type_t::one_rtt);
    auto first = decoded.next();
    REQUIRE(first.has_value());
    REQUIRE(first->has_value());
    CHECK(first->value().kind == frame_kind_t::ping);
  }
}

TEST_CASE("no shared ALPN is a fatal alert, not a silent fallback")
{
  const auto identity = make_self_signed("localhost");

  tls_config_t server_config;
  server_config.role = tls_role_t::server;
  server_config.certificate_chain_pem = identity.certificate_pem;
  server_config.private_key_pem = identity.private_key_pem;
  server_config.alpn = {"h3"};
  // A QUIC session carries the transport parameters extension whatever else it
  // is testing; without it the handshake is refused before ALPN is reached.
  server_config.transport_parameters = {0x01, 0x02, 0x03, 0x04};

  tls_config_t client_config;
  client_config.role = tls_role_t::client;
  client_config.ca_certificates_pem = identity.certificate_pem;
  client_config.alpn = {"hq-interop"};
  client_config.transport_parameters = {0x0a, 0x0b};

  auto server_context = tls_context_t::create(server_config);
  REQUIRE(server_context.has_value());
  auto client_context = tls_context_t::create(client_config);
  REQUIRE(client_context.has_value());
  auto server = tls_session_t::create(*server_context);
  REQUIRE(server.has_value());
  auto client = tls_session_t::create(*client_context, "localhost");
  REQUIRE(client.has_value());

  bool server_failed = false;
  for (int round = 0; round < 8 && !server_failed; ++round)
  {
    REQUIRE(client->advance().has_value());
    pump(*client, *server);
    if (!server->advance().has_value())
    {
      server_failed = true;
    }
  }

  CHECK(server_failed);
  REQUIRE(server->alert().has_value());
  CHECK_FALSE(server->handshake_complete());
  // RFC 9000 section 20.1: the alert rides out as CRYPTO_ERROR.
  CHECK(crypto_error_code(*server->alert()) >= 0x0100);
  CHECK(crypto_error_code(*server->alert()) <= 0x01ff);
}

TEST_CASE("a client that cannot verify the server refuses the handshake")
{
  const auto identity = make_self_signed("localhost");
  const auto stranger = make_self_signed("localhost");

  tls_config_t server_config;
  server_config.role = tls_role_t::server;
  server_config.certificate_chain_pem = identity.certificate_pem;
  server_config.private_key_pem = identity.private_key_pem;
  server_config.alpn = {"h3"};
  server_config.transport_parameters = {0x01, 0x02, 0x03, 0x04};

  tls_config_t client_config;
  client_config.role = tls_role_t::client;
  // Trusts a different self-signed certificate entirely.
  client_config.ca_certificates_pem = stranger.certificate_pem;
  client_config.alpn = {"h3"};
  client_config.transport_parameters = {0x0a, 0x0b};

  auto server_context = tls_context_t::create(server_config);
  REQUIRE(server_context.has_value());
  auto client_context = tls_context_t::create(client_config);
  REQUIRE(client_context.has_value());
  auto server = tls_session_t::create(*server_context);
  REQUIRE(server.has_value());
  auto client = tls_session_t::create(*client_context, "localhost");
  REQUIRE(client.has_value());

  bool client_failed = false;
  for (int round = 0; round < 8 && !client_failed; ++round)
  {
    if (!client->advance().has_value())
    {
      client_failed = true;
      break;
    }
    pump(*client, *server);
    REQUIRE(server->advance().has_value());
    pump(*server, *client);
  }

  CHECK(client_failed);
  CHECK_FALSE(client->handshake_complete());
  REQUIRE(client->alert().has_value());
}

TEST_CASE("the 0-RTT seam is cut")
{
  const auto identity = make_self_signed("localhost");
  tls_config_t config;
  config.role = tls_role_t::server;
  config.certificate_chain_pem = identity.certificate_pem;
  config.private_key_pem = identity.private_key_pem;

  auto context = tls_context_t::create(config);
  REQUIRE(context.has_value());
  auto session = tls_session_t::create(*context);
  REQUIRE(session.has_value());

  const std::vector<std::uint8_t> data = {0x01, 0x02, 0x03};
  auto provided = session->provide_handshake_data(encryption_level_t::early_data, data);
  CHECK_FALSE(provided.has_value());

  SUBCASE("and there is no packet type to carry it")
  {
    CHECK_FALSE(packet_kind_for(encryption_level_t::early_data).has_value());
    CHECK(packet_kind_for(encryption_level_t::initial) == packet_kind_t::initial);
    CHECK(packet_kind_for(encryption_level_t::handshake) == packet_kind_t::handshake);
    CHECK(packet_kind_for(encryption_level_t::application) == packet_kind_t::one_rtt);
  }
}

TEST_CASE("a context refuses configurations it cannot honour")
{
  SUBCASE("a server with no certificate")
  {
    tls_config_t config;
    config.role = tls_role_t::server;
    CHECK_FALSE(tls_context_t::create(config).has_value());
  }

  SUBCASE("a certificate that is not PEM")
  {
    tls_config_t config;
    config.role = tls_role_t::server;
    config.certificate_chain_pem = {0x00, 0x01, 0x02};
    config.private_key_pem = {0x00, 0x01, 0x02};
    CHECK_FALSE(tls_context_t::create(config).has_value());
  }

  SUBCASE("a key that does not match the certificate")
  {
    const auto one = make_self_signed("localhost");
    const auto other = make_self_signed("localhost");
    tls_config_t config;
    config.role = tls_role_t::server;
    config.certificate_chain_pem = one.certificate_pem;
    config.private_key_pem = other.private_key_pem;
    CHECK_FALSE(tls_context_t::create(config).has_value());
  }

  SUBCASE("an ALPN protocol that cannot be encoded")
  {
    const auto identity = make_self_signed("localhost");
    tls_config_t config;
    config.role = tls_role_t::server;
    config.certificate_chain_pem = identity.certificate_pem;
    config.private_key_pem = identity.private_key_pem;
    config.alpn = {std::string(256, 'x')};
    CHECK_FALSE(tls_context_t::create(config).has_value());
  }
}

// 0-RTT, and the property that makes it safe to have. The two sessions are
// wired to each other by hand as above, which is what makes a replay testable
// at all: the same first flight can be delivered to two servers, which is
// precisely what an attacker who captured it would do.

TEST_CASE("early data")
{
  const auto identity = make_self_signed("localhost");
  const std::vector<std::uint8_t> server_parameters = {0x01, 0x02, 0x03, 0x04};

  anti_replay_t strikes;

  tls_config_t server_config;
  server_config.role = tls_role_t::server;
  server_config.certificate_chain_pem = identity.certificate_pem;
  server_config.private_key_pem = identity.private_key_pem;
  server_config.alpn = {"h3"};
  server_config.transport_parameters = server_parameters;
  server_config.early_data = true;
  server_config.anti_replay = &strikes;

  tls_config_t client_config;
  client_config.role = tls_role_t::client;
  client_config.ca_certificates_pem = identity.certificate_pem;
  client_config.alpn = {"h3"};
  client_config.transport_parameters = {0x0a, 0x0b};
  client_config.early_data = true;

  auto server_context = tls_context_t::create(server_config);
  REQUIRE(server_context.has_value());
  auto first_client_context = tls_context_t::create(client_config);
  REQUIRE(first_client_context.has_value());

  // The first connection cannot resume anything; what it is for is the ticket.
  auto first_server = tls_session_t::create(*server_context);
  REQUIRE(first_server.has_value());
  auto first_client = tls_session_t::create(*first_client_context, "localhost");
  REQUIRE(first_client.has_value());
  run_handshake(*first_client, *first_server);
  REQUIRE(first_client->handshake_complete());
  REQUIRE(first_server->handshake_complete());

  const auto ticket = first_client->resumption_ticket();

  SUBCASE("a completed handshake hands back a ticket")
  {
    CHECK_FALSE(ticket.empty());
    // Only the client gets one: the server issued it.
    CHECK(first_server->resumption_ticket().empty());
    // And the first connection was a full handshake, so nothing was early.
    CHECK_FALSE(first_client->early_data_accepted());
    CHECK_FALSE(first_server->early_data_accepted());
  }

  SUBCASE("a ticket resumes, and early data is accepted")
  {
    REQUIRE_FALSE(ticket.empty());
    client_config.resumption_ticket = ticket;
    auto resuming_context = tls_context_t::create(client_config);
    REQUIRE(resuming_context.has_value());

    auto client = tls_session_t::create(*resuming_context, "localhost");
    REQUIRE(client.has_value());
    auto server = tls_session_t::create(*server_context);
    REQUIRE(server.has_value());

    // The point of 0-RTT: a write key before the peer has said anything.
    REQUIRE(client->advance().has_value());
    const auto early_writes = client->take_write_secrets();
    const auto *early = find(early_writes, encryption_level_t::early_data);
    REQUIRE(early != nullptr);
    CHECK(client->in_early_data());

    run_handshake(*client, *server);
    CHECK(client->handshake_complete());
    CHECK(server->handshake_complete());
    CHECK_FALSE(client->alert().has_value());
    CHECK_FALSE(server->alert().has_value());

    CHECK(client->early_data_accepted());
    CHECK(server->early_data_accepted());
    CHECK_FALSE(client->early_data_rejected());

    // And the key the client wrote early with is the one the server reads with.
    auto server_reads = server->take_read_secrets();
    const auto *server_early = find(server_reads, encryption_level_t::early_data);
    REQUIRE(server_early != nullptr);
    CHECK(hex(server_early->secret) == hex(early->secret));
  }

  SUBCASE("a replayed first flight is refused early data")
  {
    REQUIRE_FALSE(ticket.empty());
    client_config.resumption_ticket = ticket;
    auto resuming_context = tls_context_t::create(client_config);
    REQUIRE(resuming_context.has_value());

    auto client = tls_session_t::create(*resuming_context, "localhost");
    REQUIRE(client.has_value());
    REQUIRE(client->advance().has_value());

    // Exactly what an attacker gets by watching the wire: the bytes, twice.
    const auto pending = client->pending_handshake_data(encryption_level_t::initial);
    const std::vector<std::uint8_t> flight(pending.begin(), pending.end());
    REQUIRE_FALSE(flight.empty());

    const auto deliver = [&](tls_session_t &server)
    {
      REQUIRE(server.provide_handshake_data(encryption_level_t::initial, flight).has_value());
      REQUIRE(server.advance().has_value());
      return server.in_early_data() || server.early_data_accepted();
    };

    auto honest = tls_session_t::create(*server_context);
    REQUIRE(honest.has_value());
    auto replayed = tls_session_t::create(*server_context);
    REQUIRE(replayed.has_value());

    // The register is what separates them; the two ClientHellos are identical.
    CHECK(deliver(*honest));
    CHECK_FALSE(deliver(*replayed));
    // The replay is still a handshake, just not an early one -- refusing early
    // data costs the client a round trip and nothing else.
    CHECK_FALSE(replayed->alert().has_value());
  }

  SUBCASE("early data is refused when the register is full")
  {
    REQUIRE_FALSE(ticket.empty());
    anti_replay_t full(anti_replay_t::default_window, 1);
    const std::uint8_t occupant[] = {0xff, 0xee};
    REQUIRE(full.accept(occupant, vio::tick_t{}));

    tls_config_t crowded = server_config;
    crowded.anti_replay = &full;
    auto crowded_context = tls_context_t::create(crowded);
    REQUIRE(crowded_context.has_value());

    client_config.resumption_ticket = ticket;
    auto resuming_context = tls_context_t::create(client_config);
    REQUIRE(resuming_context.has_value());
    auto client = tls_session_t::create(*resuming_context, "localhost");
    REQUIRE(client.has_value());
    auto server = tls_session_t::create(*crowded_context);
    REQUIRE(server.has_value());

    run_handshake(*client, *server);
    CHECK(client->handshake_complete());
    CHECK(server->handshake_complete());
    // Fails closed: no room to vouch for it, so it does not get early data.
    CHECK_FALSE(server->early_data_accepted());
    CHECK_FALSE(client->early_data_accepted());
    // The client is told, because what it wrote early is now its to write
    // again -- and the connection is otherwise fine.
    CHECK(client->early_data_rejected());
    CHECK_FALSE(client->alert().has_value());
  }

  SUBCASE("a server without a register refuses to enable early data at all")
  {
    tls_config_t unguarded = server_config;
    unguarded.anti_replay = nullptr;
    CHECK_FALSE(tls_context_t::create(unguarded).has_value());
  }

  SUBCASE("a client needs no register to offer early data")
  {
    tls_config_t offering = client_config;
    offering.anti_replay = nullptr;
    CHECK(tls_context_t::create(offering).has_value());
  }
}

}
