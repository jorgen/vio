#include <algorithm>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>
#include <doctest/doctest.h>
#include <vio/event_loop.h>
#include <vio/operation/sleep.h>
#include <vio/operation/tcp.h>
#include <vio/operation/udp_datagram.h>
#include <vio/quic/anti_replay.h>
#include <vio/quic/endpoint.h>
#include <vio/task.h>

#include <vio/ssl_backend.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

// A QUIC handshake over a real UDP socket. Everything below the endpoint has
// been exercised by handing byte arrays between two connections; this is the
// first test where datagrams are demultiplexed by connection ID, timers come
// from the event loop, and nothing hands either side its cue.

namespace
{
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
  REQUIRE(EVP_PKEY_keygen_init(context) == 1);
  REQUIRE(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(context, NID_X9_62_prime256v1) == 1);
  REQUIRE(EVP_PKEY_keygen(context, &key) == 1);
  EVP_PKEY_CTX_free(context);

  X509 *certificate = X509_new();
  X509_set_version(certificate, 2);
  ASN1_INTEGER_set(X509_get_serialNumber(certificate), 1);
  X509_gmtime_adj(X509_getm_notBefore(certificate), 0);
  X509_gmtime_adj(X509_getm_notAfter(certificate), 31536000L);
  REQUIRE(X509_set_pubkey(certificate, key) == 1);
  X509_NAME *name = X509_get_subject_name(certificate);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char *>(common_name), -1, -1, 0);
  REQUIRE(X509_set_issuer_name(certificate, name) == 1);
  const std::string alt_name = std::string("DNS:") + common_name;
  X509_EXTENSION *basic = X509V3_EXT_nconf_nid(nullptr, nullptr, NID_basic_constraints, "critical,CA:TRUE");
  X509_add_ext(certificate, basic, -1);
  X509_EXTENSION_free(basic);
  X509_EXTENSION *san = X509V3_EXT_nconf_nid(nullptr, nullptr, NID_subject_alt_name, alt_name.c_str());
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

vio::quic::transport_parameters_t sane_parameters()
{
  vio::quic::transport_parameters_t parameters;
  parameters.max_idle_timeout = 30000;
  parameters.initial_max_data = 1048576;
  parameters.initial_max_stream_data_bidi_local = 262144;
  parameters.initial_max_stream_data_bidi_remote = 262144;
  parameters.initial_max_streams_bidi = 16;
  parameters.active_connection_id_limit = 4;
  return parameters;
}
} // namespace

TEST_SUITE("quic endpoint")
{
TEST_CASE("a client and a server reach each other over a UDP socket")
{
  using namespace vio;
  using namespace vio::quic;

  const auto identity = make_self_signed("localhost");
  event_loop_t event_loop;
  bool handshaken = false;
  bool ecn_still_on = false;
  std::string received;

  event_loop.run_in_loop(
    [&]
    {
      return [](event_loop_t &loop, const certificate_t &identity_pem, bool &handshaken, bool &ecn_still_on, std::string &received) -> vio::task_t<void>
      {
        tls_config_t server_tls;
        server_tls.role = tls_role_t::server;
        server_tls.certificate_chain_pem = identity_pem.certificate_pem;
        server_tls.private_key_pem = identity_pem.private_key_pem;
        server_tls.alpn = {"test"};
        tls_config_t client_tls;
        client_tls.role = tls_role_t::client;
        client_tls.ca_certificates_pem = identity_pem.certificate_pem;
        client_tls.alpn = {"test"};

        auto server_context = tls_context_t::create(server_tls);
        auto client_context = tls_context_t::create(client_tls);
        REQUIRE(server_context.has_value());
        REQUIRE(client_context.has_value());

        endpoint_config_t server_config;
        server_config.connection.role = tls_role_t::server;
        server_config.connection.transport_parameters = sane_parameters();
        // Section 13.4: datagrams go out marked ECT(0), so a router can report
        // congestion by setting a bit instead of dropping the packet.
        server_config.ecn = true;
        auto server_created = endpoint_t::create(loop, *server_context, server_config);
        REQUIRE(server_created.has_value());
        // Held in an optional so the socket can be closed before the loop is
        // stopped. event_loop_t::stop() runs the loop until nothing is in
        // flight; a socket still reading at that point means it never returns.
        std::optional<endpoint_t> server(std::move(*server_created));

        auto bind_address = ip4_addr("127.0.0.1", 0);
        REQUIRE(bind_address.has_value());
        REQUIRE(server->bind(reinterpret_cast<const sockaddr *>(&*bind_address)).has_value());
        auto port = server->local_port();
        REQUIRE(port.has_value());

        connection_t *accepted = nullptr;
        server->on_connection([&accepted](connection_t &connection) { accepted = &connection; });

        endpoint_config_t client_config;
        client_config.connection.role = tls_role_t::client;
        client_config.connection.transport_parameters = sane_parameters();
        client_config.ecn = true;
        auto client_created = endpoint_t::create(loop, *client_context, client_config);
        REQUIRE(client_created.has_value());
        std::optional<endpoint_t> client(std::move(*client_created));

        cancellation_t server_cancel;
        cancellation_t client_cancel;
        auto server_run = [](endpoint_t &endpoint, cancellation_t &cancel) -> detached_task_t { co_await endpoint.run(&cancel); }(*server, server_cancel);
        auto client_run = [](endpoint_t &endpoint, cancellation_t &cancel) -> detached_task_t { co_await endpoint.run(&cancel); }(*client, client_cancel);
        (void)server_run;
        (void)client_run;

        auto target = ip4_addr("127.0.0.1", *port);
        REQUIRE(target.has_value());
        auto dialled = client->connect(reinterpret_cast<const sockaddr *>(&*target), "localhost");
        REQUIRE(dialled.has_value());
        connection_t *connection = client->connection(*dialled);
        REQUIRE(connection != nullptr);

        // The endpoints drive themselves from here: the handshake is several
        // round trips, and nothing in this test hands either side a packet.
        for (int i = 0; i < 200 && !connection->handshake_complete(); ++i)
        {
          co_await sleep(loop, 5ms);
        }
        handshaken = connection->handshake_complete();

        if (handshaken)
        {
          auto stream = connection->open_stream(stream_direction_t::bidirectional);
          if (stream.has_value())
          {
            const std::string message = "over a real socket";
            const std::vector<std::uint8_t> payload(message.begin(), message.end());
            (void)connection->write_stream(*stream, payload, true);
            (void)client->flush();

            for (int i = 0; i < 200; ++i)
            {
              if (accepted != nullptr)
              {
                auto readable = accepted->readable_stream(*stream);
                if (readable.size() >= message.size())
                {
                  received.assign(reinterpret_cast<const char *>(readable.data()), readable.size());
                  break;
                }
              }
              co_await sleep(loop, 5ms);
            }
          }
        }

        // Section 13.4.2: both sides marked, both reported, and neither
        // validator objected. If either half were broken -- marking without
        // reporting, or reporting counts that did not account for what was
        // sent -- validation would have failed and the codepoint would have
        // dropped to not_ect. That it did not is the end-to-end check.
        ecn_still_on = connection->ecn_sending() == ecn_codepoint_t::ect0 && accepted != nullptr && accepted->ecn_sending() == ecn_codepoint_t::ect0;

        server_cancel.cancel();
        client_cancel.cancel();
        // Cancelling stops the read loops; destroying the endpoints closes
        // their sockets. Both have to happen before the loop is asked to stop,
        // in that order -- run() holds a reference to the endpoint, so the
        // endpoint must outlive it.
        co_await sleep(loop, 50ms);
        server.reset();
        client.reset();
        co_await sleep(loop, 50ms);
        loop.stop();
      }(event_loop, identity, handshaken, ecn_still_on, received);
    });

  event_loop.run();
  CHECK(handshaken);
  CHECK(received == "over a real socket");
  CHECK(ecn_still_on);
}
TEST_CASE("a Retry is answered without building a connection for it")
{
  using namespace vio;
  using namespace vio::quic;

  const auto identity = make_self_signed("localhost");
  event_loop_t event_loop;
  bool handshaken = false;
  bool through_retry = false;
  std::size_t accepted_connections = 0;

  event_loop.run_in_loop(
    [&]
    {
      return [](event_loop_t &loop, const certificate_t &identity_pem, bool &handshaken, bool &through_retry, std::size_t &accepted_connections) -> vio::task_t<void>
      {
        tls_config_t server_tls;
        server_tls.role = tls_role_t::server;
        server_tls.certificate_chain_pem = identity_pem.certificate_pem;
        server_tls.private_key_pem = identity_pem.private_key_pem;
        server_tls.alpn = {"test"};
        tls_config_t client_tls;
        client_tls.role = tls_role_t::client;
        client_tls.ca_certificates_pem = identity_pem.certificate_pem;
        client_tls.alpn = {"test"};

        auto server_context = tls_context_t::create(server_tls);
        auto client_context = tls_context_t::create(client_tls);
        REQUIRE(server_context.has_value());
        REQUIRE(client_context.has_value());

        retry_token_key_t retry_key;
        REQUIRE(retry_key.generate().has_value());

        endpoint_config_t server_config;
        server_config.connection.role = tls_role_t::server;
        server_config.connection.transport_parameters = sane_parameters();
        server_config.retry_key = &retry_key;
        auto server_created = endpoint_t::create(loop, *server_context, server_config);
        REQUIRE(server_created.has_value());
        std::optional<endpoint_t> server(std::move(*server_created));

        auto bind_address = ip4_addr("127.0.0.1", 0);
        REQUIRE(bind_address.has_value());
        REQUIRE(server->bind(reinterpret_cast<const sockaddr *>(&*bind_address)).has_value());
        auto port = server->local_port();
        REQUIRE(port.has_value());

        connection_t *accepted = nullptr;
        server->on_connection([&accepted](connection_t &connection) { accepted = &connection; });

        endpoint_config_t client_config;
        client_config.connection.role = tls_role_t::client;
        client_config.connection.transport_parameters = sane_parameters();
        auto client_created = endpoint_t::create(loop, *client_context, client_config);
        REQUIRE(client_created.has_value());
        std::optional<endpoint_t> client(std::move(*client_created));

        cancellation_t server_cancel;
        cancellation_t client_cancel;
        auto server_run = [](endpoint_t &endpoint, cancellation_t &cancel) -> detached_task_t { co_await endpoint.run(&cancel); }(*server, server_cancel);
        auto client_run = [](endpoint_t &endpoint, cancellation_t &cancel) -> detached_task_t { co_await endpoint.run(&cancel); }(*client, client_cancel);
        (void)server_run;
        (void)client_run;

        auto target = ip4_addr("127.0.0.1", *port);
        REQUIRE(target.has_value());
        auto dialled = client->connect(reinterpret_cast<const sockaddr *>(&*target), "localhost");
        REQUIRE(dialled.has_value());
        connection_t *connection = client->connection(*dialled);
        REQUIRE(connection != nullptr);

        for (int i = 0; i < 300 && !connection->handshake_complete(); ++i)
        {
          co_await sleep(loop, 5ms);
        }
        handshaken = connection->handshake_complete();
        through_retry = connection->address_validated_by_retry();
        // Section 8.1.2: the first Initial carried no token and cost the server
        // nothing. Exactly one connection exists, built when the token came
        // back -- not two, and not one per Initial the client sent.
        accepted_connections = server->connection_count();

        server_cancel.cancel();
        client_cancel.cancel();
        co_await sleep(loop, 50ms);
        server.reset();
        client.reset();
        co_await sleep(loop, 50ms);
        loop.stop();
      }(event_loop, identity, handshaken, through_retry, accepted_connections);
    });

  event_loop.run();
  CHECK(handshaken);
  CHECK(through_retry);
  CHECK(accepted_connections == 1);
}
TEST_CASE("one server port keeps two clients apart")
{
  using namespace vio;
  using namespace vio::quic;

  const auto identity = make_self_signed("localhost");
  event_loop_t event_loop;
  std::size_t accepted = 0;
  std::string first_message;
  std::string second_message;

  event_loop.run_in_loop(
    [&]
    {
      return [](event_loop_t &loop, const certificate_t &identity_pem, std::size_t &accepted, std::string &first_message, std::string &second_message) -> vio::task_t<void>
      {
        tls_config_t server_tls;
        server_tls.role = tls_role_t::server;
        server_tls.certificate_chain_pem = identity_pem.certificate_pem;
        server_tls.private_key_pem = identity_pem.private_key_pem;
        server_tls.alpn = {"test"};
        tls_config_t client_tls;
        client_tls.role = tls_role_t::client;
        client_tls.ca_certificates_pem = identity_pem.certificate_pem;
        client_tls.alpn = {"test"};

        auto server_context = tls_context_t::create(server_tls);
        auto client_context = tls_context_t::create(client_tls);
        REQUIRE(server_context.has_value());
        REQUIRE(client_context.has_value());

        endpoint_config_t server_config;
        server_config.connection.role = tls_role_t::server;
        server_config.connection.transport_parameters = sane_parameters();
        auto server_created = endpoint_t::create(loop, *server_context, server_config);
        REQUIRE(server_created.has_value());
        std::optional<endpoint_t> server(std::move(*server_created));

        auto bind_address = ip4_addr("127.0.0.1", 0);
        REQUIRE(bind_address.has_value());
        REQUIRE(server->bind(reinterpret_cast<const sockaddr *>(&*bind_address)).has_value());
        auto port = server->local_port();
        REQUIRE(port.has_value());

        std::vector<connection_t *> arrivals;
        server->on_connection([&arrivals](connection_t &connection) { arrivals.push_back(&connection); });

        // Two clients on their own sockets, so they reach the server from two
        // different addresses and can only be told apart by connection id.
        endpoint_config_t client_config;
        client_config.connection.role = tls_role_t::client;
        client_config.connection.transport_parameters = sane_parameters();
        auto first_created = endpoint_t::create(loop, *client_context, client_config);
        auto second_created = endpoint_t::create(loop, *client_context, client_config);
        REQUIRE(first_created.has_value());
        REQUIRE(second_created.has_value());
        std::optional<endpoint_t> first(std::move(*first_created));
        std::optional<endpoint_t> second(std::move(*second_created));

        cancellation_t server_cancel;
        cancellation_t first_cancel;
        cancellation_t second_cancel;
        auto run_one = [](endpoint_t &endpoint, cancellation_t &cancel) -> detached_task_t { co_await endpoint.run(&cancel); };
        auto server_run = run_one(*server, server_cancel);
        auto first_run = run_one(*first, first_cancel);
        auto second_run = run_one(*second, second_cancel);
        (void)server_run;
        (void)first_run;
        (void)second_run;

        auto target = ip4_addr("127.0.0.1", *port);
        REQUIRE(target.has_value());
        auto first_dial = first->connect(reinterpret_cast<const sockaddr *>(&*target), "localhost");
        auto second_dial = second->connect(reinterpret_cast<const sockaddr *>(&*target), "localhost");
        REQUIRE(first_dial.has_value());
        REQUIRE(second_dial.has_value());

        auto *first_connection = first->connection(*first_dial);
        auto *second_connection = second->connection(*second_dial);
        REQUIRE(first_connection != nullptr);
        REQUIRE(second_connection != nullptr);

        for (int i = 0; i < 300 && !(first_connection->handshake_complete() && second_connection->handshake_complete()); ++i)
        {
          co_await sleep(loop, 5ms);
        }
        REQUIRE(first_connection->handshake_complete());
        REQUIRE(second_connection->handshake_complete());
        accepted = server->connection_count();

        auto say = [](connection_t &connection, endpoint_t &endpoint, const std::string &text)
        {
          auto stream = connection.open_stream(stream_direction_t::bidirectional);
          REQUIRE(stream.has_value());
          const std::vector<std::uint8_t> payload(text.begin(), text.end());
          (void)connection.write_stream(*stream, payload, true);
          (void)endpoint.flush();
          return *stream;
        };
        const auto first_stream = say(*first_connection, *first, "from the first client");
        const auto second_stream = say(*second_connection, *second, "from the second client");

        for (int i = 0; i < 300; ++i)
        {
          if (arrivals.size() == 2)
          {
            bool done = true;
            for (auto *arrival : arrivals)
            {
              auto a = arrival->readable_stream(first_stream);
              auto b = arrival->readable_stream(second_stream);
              const auto readable = a.empty() ? b : a;
              if (readable.empty())
              {
                done = false;
              }
            }
            if (done)
            {
              break;
            }
          }
          co_await sleep(loop, 5ms);
        }

        if (arrivals.size() == 2)
        {
          // Each server-side connection holds exactly one client's message,
          // which is the whole job of demultiplexing on connection id.
          std::vector<std::string> heard;
          for (auto *arrival : arrivals)
          {
            auto a = arrival->readable_stream(first_stream);
            auto b = arrival->readable_stream(second_stream);
            const auto readable = a.empty() ? b : a;
            heard.emplace_back(reinterpret_cast<const char *>(readable.data()), readable.size());
          }
          std::sort(heard.begin(), heard.end());
          first_message = heard.front();
          second_message = heard.back();
        }

        server_cancel.cancel();
        first_cancel.cancel();
        second_cancel.cancel();
        co_await sleep(loop, 50ms);
        server.reset();
        first.reset();
        second.reset();
        co_await sleep(loop, 50ms);
        loop.stop();
      }(event_loop, identity, accepted, first_message, second_message);
    });

  event_loop.run();
  CHECK(accepted == 2);
  CHECK(first_message == "from the first client");
  CHECK(second_message == "from the second client");
}

TEST_CASE("a handle stops naming a connection the endpoint has collected")
{
  using namespace vio;
  using namespace vio::quic;

  // What dialling returns has to survive the connection going away, because
  // the endpoint decides when that happens and the application is not asked.
  // The point of a handle rather than a pointer is that the answer becomes
  // nothing rather than becoming freed memory.
  const auto identity = make_self_signed("localhost");
  event_loop_t event_loop;
  bool named_before = false;
  bool named_after = true;

  event_loop.run_in_loop(
    [&]
    {
      return [](event_loop_t &loop, const certificate_t &identity_pem, bool &before, bool &after) -> vio::task_t<void>
      {
        tls_config_t client_tls;
        client_tls.role = tls_role_t::client;
        client_tls.ca_certificates_pem = identity_pem.certificate_pem;
        client_tls.alpn = {"test"};
        auto client_context = tls_context_t::create(client_tls);
        REQUIRE(client_context.has_value());

        endpoint_config_t config;
        config.connection.role = tls_role_t::client;
        config.connection.transport_parameters = sane_parameters();
        // Short enough that the test does not wait out the section 10.2
        // default.
        config.draining_period = std::chrono::milliseconds(10);

        auto made = endpoint_t::create(loop, *client_context, config);
        REQUIRE(made.has_value());
        std::optional<endpoint_t> client(std::move(*made));

        // Nothing is listening there, so the handshake will never finish.
        auto target = ip4_addr("127.0.0.1", 1);
        REQUIRE(target.has_value());
        auto dialled = client->connect(reinterpret_cast<const sockaddr *>(&*target), "localhost");
        REQUIRE(dialled.has_value());

        before = client->connection(*dialled) != nullptr;

        auto *connection = client->connection(*dialled);
        REQUIRE(connection != nullptr);
        connection->close(0, "done", true);
        (void)client->flush();
        co_await sleep(loop, 60ms);
        (void)client->flush();

        after = client->connection(*dialled) != nullptr;

        client.reset();
        co_await sleep(loop, 20ms);
        loop.stop();
      }(event_loop, identity, named_before, named_after);
    });

  event_loop.run();
  CHECK(named_before);
  CHECK_FALSE(named_after);
}
}


TEST_CASE("a resumed connection carries a request in its first flight, over a real socket")
{
  using namespace vio;
  using namespace vio::quic;

  const auto identity = make_self_signed("localhost");
  event_loop_t event_loop;
  bool resumed = false;
  bool early_accepted = false;
  std::string received;

  event_loop.run_in_loop(
    [&]
    {
      return [](event_loop_t &loop, const certificate_t &identity_pem, bool &resumed, bool &early_accepted, std::string &received) -> vio::task_t<void>
      {
        anti_replay_t strikes;

        tls_config_t server_tls;
        server_tls.role = tls_role_t::server;
        server_tls.certificate_chain_pem = identity_pem.certificate_pem;
        server_tls.private_key_pem = identity_pem.private_key_pem;
        server_tls.alpn = {"test"};
        server_tls.early_data = true;
        server_tls.anti_replay = &strikes;

        tls_config_t client_tls;
        client_tls.role = tls_role_t::client;
        client_tls.ca_certificates_pem = identity_pem.certificate_pem;
        client_tls.alpn = {"test"};
        client_tls.early_data = true;

        auto server_context = tls_context_t::create(server_tls);
        auto client_context = tls_context_t::create(client_tls);
        REQUIRE(server_context.has_value());
        REQUIRE(client_context.has_value());

        endpoint_config_t server_config;
        server_config.connection.role = tls_role_t::server;
        server_config.connection.transport_parameters = sane_parameters();
        auto server_created = endpoint_t::create(loop, *server_context, server_config);
        REQUIRE(server_created.has_value());
        std::optional<endpoint_t> server(std::move(*server_created));

        auto bind_address = ip4_addr("127.0.0.1", 0);
        REQUIRE(bind_address.has_value());
        REQUIRE(server->bind(reinterpret_cast<const sockaddr *>(&*bind_address)).has_value());
        auto port = server->local_port();
        REQUIRE(port.has_value());

        connection_t *accepted = nullptr;
        server->on_connection([&accepted](connection_t &connection) { accepted = &connection; });

        endpoint_config_t client_config;
        client_config.connection.role = tls_role_t::client;
        client_config.connection.transport_parameters = sane_parameters();
        auto client_created = endpoint_t::create(loop, *client_context, client_config);
        REQUIRE(client_created.has_value());
        std::optional<endpoint_t> client(std::move(*client_created));

        cancellation_t server_cancel;
        cancellation_t client_cancel;
        auto server_run = [](endpoint_t &endpoint, cancellation_t &cancel) -> detached_task_t { co_await endpoint.run(&cancel); }(*server, server_cancel);
        auto client_run = [](endpoint_t &endpoint, cancellation_t &cancel) -> detached_task_t { co_await endpoint.run(&cancel); }(*client, client_cancel);
        (void)server_run;
        (void)client_run;

        auto target = ip4_addr("127.0.0.1", *port);
        REQUIRE(target.has_value());

        // A first connection, purely to be issued a ticket. The ticket arrives
        // after the handshake reports complete, so this waits past that.
        std::vector<std::uint8_t> ticket;
        {
          auto dialled = client->connect(reinterpret_cast<const sockaddr *>(&*target), "localhost");
          REQUIRE(dialled.has_value());
          for (int i = 0; i < 200; ++i)
          {
            auto *connection = client->connection(*dialled);
            if (connection == nullptr)
            {
              break;
            }
            ticket = connection->resumption_ticket();
            if (!ticket.empty())
            {
              connection->close(0, "done");
              break;
            }
            co_await sleep(loop, 5ms);
          }
        }
        REQUIRE_FALSE(ticket.empty());
        (void)client->flush();
        co_await sleep(loop, 20ms);
        accepted = nullptr;

        auto dialled = client->connect(reinterpret_cast<const sockaddr *>(&*target), "localhost", ticket);
        REQUIRE(dialled.has_value());
        connection_t *connection = client->connection(*dialled);
        REQUIRE(connection != nullptr);

        // Written before the handshake has been given any chance to run. On a
        // connection that was not resuming there would be no key for it.
        REQUIRE_FALSE(connection->handshake_complete());
        const std::string message = "0-RTT over a real socket";
        auto stream = connection->open_stream(stream_direction_t::bidirectional);
        REQUIRE(stream.has_value());
        const std::vector<std::uint8_t> payload(message.begin(), message.end());
        REQUIRE(connection->write_stream(*stream, payload, true) == payload.size());
        (void)client->flush();

        for (int i = 0; i < 200; ++i)
        {
          if (accepted != nullptr)
          {
            auto readable = accepted->readable_stream(*stream);
            if (readable.size() >= message.size())
            {
              received.assign(reinterpret_cast<const char *>(readable.data()), readable.size());
              break;
            }
          }
          co_await sleep(loop, 5ms);
        }
        resumed = connection->handshake_complete();
        early_accepted = connection->early_data_accepted() && accepted != nullptr && accepted->early_data_accepted();

        server_cancel.cancel();
        client_cancel.cancel();
        co_await sleep(loop, 50ms);
        server.reset();
        client.reset();
        co_await sleep(loop, 50ms);
        loop.stop();
      }(event_loop, identity, resumed, early_accepted, received);
    });

  event_loop.run();
  CHECK(resumed);
  CHECK(received == "0-RTT over a real socket");
  CHECK(early_accepted);
}

// VIO-01. A Version Negotiation packet carries version zero, which no endpoint
// supports -- so answering one produced a reply that was itself a trigger.
// Section 6.1 forbids it, and two endpoints pointed at each other never stopped.

TEST_CASE("a Version Negotiation packet is never answered with another one")
{
  using namespace vio;
  using namespace vio::quic;

  const auto identity = make_self_signed("localhost");
  event_loop_t event_loop;
  int replies_to_version_negotiation = 0;
  int replies_to_small_datagram = 0;
  int replies_to_real_unknown_version = 0;

  event_loop.run_in_loop(
    [&]
    {
      return [](event_loop_t &loop, const certificate_t &identity_pem, int &to_vn, int &to_small, int &to_real) -> vio::task_t<void>
      {
        tls_config_t server_tls;
        server_tls.role = tls_role_t::server;
        server_tls.certificate_chain_pem = identity_pem.certificate_pem;
        server_tls.private_key_pem = identity_pem.private_key_pem;
        server_tls.alpn = {"test"};
        auto server_context = tls_context_t::create(server_tls);
        REQUIRE(server_context.has_value());

        endpoint_config_t server_config;
        server_config.connection.role = tls_role_t::server;
        server_config.connection.transport_parameters = sane_parameters();
        auto server_created = endpoint_t::create(loop, *server_context, server_config);
        REQUIRE(server_created.has_value());
        std::optional<endpoint_t> server(std::move(*server_created));

        auto bind_address = ip4_addr("127.0.0.1", 0);
        REQUIRE(bind_address.has_value());
        REQUIRE(server->bind(reinterpret_cast<const sockaddr *>(&*bind_address)).has_value());
        auto port = server->local_port();
        REQUIRE(port.has_value());

        cancellation_t server_cancel;
        auto server_run = [](endpoint_t &endpoint, cancellation_t &cancel) -> detached_task_t { co_await endpoint.run(&cancel); }(*server, server_cancel);
        (void)server_run;

        // A plain socket, so the bytes on the wire are exactly what this test
        // says they are rather than whatever a connection would have built.
        auto probe_created = udp_create(loop);
        REQUIRE(probe_created.has_value());
        std::optional<udp_t> probe(std::move(*probe_created));
        auto probe_address = ip4_addr("127.0.0.1", 0);
        REQUIRE(probe_address.has_value());
        REQUIRE(udp_bind(*probe, reinterpret_cast<const sockaddr *>(&*probe_address)).has_value());
        auto reader_created = udp_create_reader(*probe);
        REQUIRE(reader_created.has_value());
        std::optional<udp_reader_t> reader(std::move(*reader_created));

        auto target = ip4_addr("127.0.0.1", *port);
        REQUIRE(target.has_value());

        int received = 0;
        auto pump = [](decltype(*reader) &r, int &count) -> detached_task_t
        {
          for (;;)
          {
            auto datagram = co_await r;
            if (!datagram.has_value())
            {
              break;
            }
            ++count;
          }
        }(*reader, received);
        (void)pump;

        const auto probe_with = [&](std::vector<std::uint8_t> bytes) -> vio::task_t<int>
        {
          received = 0;
          (void)udp_try_send(*probe, bytes, reinterpret_cast<const sockaddr *>(&*target));
          for (int i = 0; i < 20 && received == 0; ++i)
          {
            co_await sleep(loop, 5ms);
          }
          co_return int{received};
        };

        // Long header, version 0x00000000, both connection ids empty: a
        // Version Negotiation packet, and the shape of the whole attack.
        std::vector<std::uint8_t> version_negotiation = {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        to_vn = co_await probe_with(version_negotiation);

        // An unsupported version in a datagram too small to have been a real
        // connection attempt: also unanswered, so it cannot be an amplifier.
        std::vector<std::uint8_t> small_unknown = {0xC0, 0x0A, 0x0A, 0x0A, 0x0A, 0x00, 0x00};
        to_small = co_await probe_with(small_unknown);

        // And the case that must still work: a full-sized datagram naming a
        // version this endpoint does not speak earns a Version Negotiation.
        std::vector<std::uint8_t> real_unknown(1200, 0x00);
        real_unknown[0] = 0xC0;
        real_unknown[1] = 0x0A;
        real_unknown[2] = 0x0A;
        real_unknown[3] = 0x0A;
        real_unknown[4] = 0x0A;
        to_real = co_await probe_with(real_unknown);

        // The pump parks on the reader, so it has to be woken before anything
        // it refers to is destroyed -- reader first, then the socket, and only
        // then the loop.
        reader->cancel();
        co_await sleep(loop, 20ms);
        reader.reset();
        probe.reset();

        server_cancel.cancel();
        co_await sleep(loop, 50ms);
        server.reset();
        co_await sleep(loop, 50ms);
        loop.stop();
      }(event_loop, identity, replies_to_version_negotiation, replies_to_small_datagram, replies_to_real_unknown_version);
    });

  event_loop.run();
  CHECK(replies_to_version_negotiation == 0);
  CHECK(replies_to_small_datagram == 0);
  CHECK(replies_to_real_unknown_version == 1);
}

// VIO-14. flush_entry hands control to the application, and endpoint.h invites
// it to call back in from there. Both connect() and flush() mutate the
// connection vector -- one reallocates it, the other erases from it -- while
// the walk that called the handler was iterating it by reference.

TEST_CASE("an application may dial and flush from inside its connection handler")
{
  using namespace vio;
  using namespace vio::quic;

  const auto identity = make_self_signed("localhost");
  event_loop_t event_loop;
  int announced = 0;
  bool survived = false;

  event_loop.run_in_loop(
    [&]
    {
      return [](event_loop_t &loop, const certificate_t &identity_pem, int &announced, bool &survived) -> vio::task_t<void>
      {
        tls_config_t server_tls;
        server_tls.role = tls_role_t::server;
        server_tls.certificate_chain_pem = identity_pem.certificate_pem;
        server_tls.private_key_pem = identity_pem.private_key_pem;
        server_tls.alpn = {"test"};
        tls_config_t client_tls;
        client_tls.role = tls_role_t::client;
        client_tls.ca_certificates_pem = identity_pem.certificate_pem;
        client_tls.alpn = {"test"};

        auto server_context = tls_context_t::create(server_tls);
        auto client_context = tls_context_t::create(client_tls);
        REQUIRE(server_context.has_value());
        REQUIRE(client_context.has_value());

        endpoint_config_t server_config;
        server_config.connection.role = tls_role_t::server;
        server_config.connection.transport_parameters = sane_parameters();
        auto server_created = endpoint_t::create(loop, *server_context, server_config);
        REQUIRE(server_created.has_value());
        std::optional<endpoint_t> server(std::move(*server_created));

        auto bind_address = ip4_addr("127.0.0.1", 0);
        REQUIRE(bind_address.has_value());
        REQUIRE(server->bind(reinterpret_cast<const sockaddr *>(&*bind_address)).has_value());
        auto port = server->local_port();
        REQUIRE(port.has_value());

        endpoint_config_t client_config;
        client_config.connection.role = tls_role_t::client;
        client_config.connection.transport_parameters = sane_parameters();
        auto client_created = endpoint_t::create(loop, *client_context, client_config);
        REQUIRE(client_created.has_value());
        std::optional<endpoint_t> client(std::move(*client_created));

        auto target = ip4_addr("127.0.0.1", *port);
        REQUIRE(target.has_value());

        // The handler dials again and flushes, from inside the walk that is
        // announcing it. Both are documented uses.
        endpoint_t *client_ptr = &*client;
        const sockaddr *target_ptr = reinterpret_cast<const sockaddr *>(&*target);
        client->on_connection(
          [client_ptr, target_ptr, &announced](connection_t &)
          {
            ++announced;
            if (announced == 1)
            {
              // Enough dials to grow the vector past its capacity while the
              // walk that called this handler is still holding a cursor into
              // it. One is not enough -- the vector may already have room.
              for (int i = 0; i < 16; ++i)
              {
                (void)client_ptr->connect(target_ptr, "localhost");
              }
            }
            (void)client_ptr->flush();
          });

        cancellation_t server_cancel;
        cancellation_t client_cancel;
        auto server_run = [](endpoint_t &e, cancellation_t &c) -> detached_task_t { co_await e.run(&c); }(*server, server_cancel);
        auto client_run = [](endpoint_t &e, cancellation_t &c) -> detached_task_t { co_await e.run(&c); }(*client, client_cancel);
        (void)server_run;
        (void)client_run;

        // Several, so the walk that announces the first still has entries left
        // to step to when the handler reallocates the vector under it.
        for (int i = 0; i < 4; ++i)
        {
          auto dialled = client->connect(target_ptr, "localhost");
          REQUIRE(dialled.has_value());
        }

        for (int i = 0; i < 200 && announced < 4; ++i)
        {
          co_await sleep(loop, 5ms);
        }
        // Reaching here at all is the assertion: before the fix the walk's
        // cursor dangled the moment the handler dialled.
        survived = announced >= 2;

        server_cancel.cancel();
        client_cancel.cancel();
        co_await sleep(loop, 50ms);
        server.reset();
        client.reset();
        co_await sleep(loop, 50ms);
        loop.stop();
      }(event_loop, identity, announced, survived);
    });

  event_loop.run();
  CHECK(survived);
}

// The allowance that rations stateless resets was spent before the check that
// decides whether a reset is possible at all, so every long-header datagram --
// none of which can ever draw one -- still burned an allowance. Sixty-four of
// them, one second's worth, left a genuine short-header packet unanswered.

TEST_CASE("a datagram that cannot draw a stateless reset does not spend one")
{
  using namespace vio;
  using namespace vio::quic;

  const auto identity = make_self_signed("localhost");
  event_loop_t event_loop;
  int replies_to_long_headers = 0;
  int replies_to_short_header = 0;

  event_loop.run_in_loop(
    [&]
    {
      return [](event_loop_t &loop, const certificate_t &identity_pem, int &to_long, int &to_short) -> vio::task_t<void>
      {
        tls_config_t server_tls;
        server_tls.role = tls_role_t::server;
        server_tls.certificate_chain_pem = identity_pem.certificate_pem;
        server_tls.private_key_pem = identity_pem.private_key_pem;
        server_tls.alpn = {"test"};
        auto server_context = tls_context_t::create(server_tls);
        REQUIRE(server_context.has_value());

        auto reset_key = stateless_reset_key_t::create();
        REQUIRE(reset_key.has_value());

        endpoint_config_t server_config;
        server_config.connection.role = tls_role_t::server;
        server_config.stateless_reset_key = &*reset_key;
        auto server_created = endpoint_t::create(loop, *server_context, server_config);
        REQUIRE(server_created.has_value());
        std::optional<endpoint_t> server(std::move(*server_created));

        auto bind_address = ip4_addr("127.0.0.1", 0);
        REQUIRE(bind_address.has_value());
        REQUIRE(server->bind(reinterpret_cast<const sockaddr *>(&*bind_address)).has_value());
        auto port = server->local_port();
        REQUIRE(port.has_value());

        cancellation_t server_cancel;
        auto server_run = [](endpoint_t &endpoint, cancellation_t &cancel) -> detached_task_t { co_await endpoint.run(&cancel); }(*server, server_cancel);
        (void)server_run;

        auto probe_created = udp_create(loop);
        REQUIRE(probe_created.has_value());
        std::optional<udp_t> probe(std::move(*probe_created));
        auto probe_address = ip4_addr("127.0.0.1", 0);
        REQUIRE(probe_address.has_value());
        REQUIRE(udp_bind(*probe, reinterpret_cast<const sockaddr *>(&*probe_address)).has_value());
        auto reader_created = udp_create_reader(*probe);
        REQUIRE(reader_created.has_value());
        std::optional<udp_reader_t> reader(std::move(*reader_created));

        auto target = ip4_addr("127.0.0.1", *port);
        REQUIRE(target.has_value());

        int received = 0;
        auto pump = [](decltype(*reader) &r, int &count) -> detached_task_t
        {
          for (;;)
          {
            auto datagram = co_await r;
            if (!datagram.has_value())
            {
              break;
            }
            ++count;
          }
        }(*reader, received);
        (void)pump;

        // A Handshake packet for a connection ID this endpoint never issued: a
        // long header, a version it does speak, and not an Initial, so it
        // reaches the stateless reset path and is refused there.
        std::vector<std::uint8_t> handshake_shaped = {0xE0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x00};

        // More than the sixty-four allowed per second, sent back to back so
        // they all land inside one refill window.
        constexpr int long_header_count = 70;
        for (int i = 0; i < long_header_count; ++i)
        {
          handshake_shaped[6] = static_cast<std::uint8_t>(i);
          (void)udp_try_send(*probe, handshake_shaped, reinterpret_cast<const sockaddr *>(&*target));
        }
        co_await sleep(loop, 50ms);
        to_long = received;

        // And the packet that should get one: a short header naming a
        // connection this endpoint has never heard of.
        received = 0;
        std::vector<std::uint8_t> short_header(100, 0x00);
        short_header[0] = 0x40;
        for (std::size_t i = 1; i <= 8; ++i)
        {
          short_header[i] = static_cast<std::uint8_t>(0xA0 + i);
        }
        (void)udp_try_send(*probe, short_header, reinterpret_cast<const sockaddr *>(&*target));
        for (int i = 0; i < 20 && received == 0; ++i)
        {
          co_await sleep(loop, 5ms);
        }
        to_short = received;

        reader->cancel();
        co_await sleep(loop, 20ms);
        reader.reset();
        probe.reset();

        server_cancel.cancel();
        co_await sleep(loop, 50ms);
        server.reset();
        co_await sleep(loop, 50ms);
        loop.stop();
      }(event_loop, identity, replies_to_long_headers, replies_to_short_header);
    });

  event_loop.run();
  // None of the long headers is answerable, so none is answered.
  CHECK(replies_to_long_headers == 0);
  // The allowance they used to consume is still there for the one packet that
  // can actually use it.
  CHECK(replies_to_short_header == 1);
}

// VIO-14 again, on the other walk. run() dispatches on_activity and then
// flushes, both over a vector of raw pointers into entries the connection
// vector owns, and endpoint.h invites the handler to call flush() from there.
// flush() reaps and reaping erases, but neither of those two loops was marked
// as a walk -- so a handler that flushed could free the very entries the flush
// loop was about to write through. flush() and the timer were already marked;
// these two were not.

TEST_CASE("a connection is not reaped while the endpoint is walking it")
{
  using namespace vio;
  using namespace vio::quic;

  const auto identity = make_self_signed("localhost");
  event_loop_t event_loop;
  std::size_t count_before = 0;
  std::size_t count_after = 0;
  bool observed = false;

  event_loop.run_in_loop(
    [&]
    {
      return [](event_loop_t &loop, const certificate_t &identity_pem, std::size_t &before, std::size_t &after, bool &seen) -> vio::task_t<void>
      {
        tls_config_t server_tls;
        server_tls.role = tls_role_t::server;
        server_tls.certificate_chain_pem = identity_pem.certificate_pem;
        server_tls.private_key_pem = identity_pem.private_key_pem;
        server_tls.alpn = {"test"};
        tls_config_t client_tls;
        client_tls.role = tls_role_t::client;
        client_tls.ca_certificates_pem = identity_pem.certificate_pem;
        client_tls.alpn = {"test"};

        auto server_context = tls_context_t::create(server_tls);
        auto client_context = tls_context_t::create(client_tls);
        REQUIRE(server_context.has_value());
        REQUIRE(client_context.has_value());

        endpoint_config_t server_config;
        server_config.connection.role = tls_role_t::server;
        // Zero, so an entry that reaches the closed state during this batch is
        // collectable before the batch has finished being walked. That is the
        // race, compressed into one turn of the loop.
        server_config.draining_period = std::chrono::milliseconds{0};
        auto server_created = endpoint_t::create(loop, *server_context, server_config);
        REQUIRE(server_created.has_value());
        std::optional<endpoint_t> server(std::move(*server_created));

        auto bind_address = ip4_addr("127.0.0.1", 0);
        REQUIRE(bind_address.has_value());
        REQUIRE(server->bind(reinterpret_cast<const sockaddr *>(&*bind_address)).has_value());
        auto port = server->local_port();
        REQUIRE(port.has_value());

        endpoint_config_t client_config;
        client_config.connection.role = tls_role_t::client;
        auto client_created = endpoint_t::create(loop, *client_context, client_config);
        REQUIRE(client_created.has_value());
        std::optional<endpoint_t> client(std::move(*client_created));

        // Everything here is what endpoint.h invites an application to do from
        // a handler. The flush sends the close, which puts the connection into
        // the closed state and latches its draining deadline -- and with that
        // deadline at zero, the reap at the end of that same flush is the one
        // that would collect the connection the outer walk is still holding a
        // pointer to.
        server->on_activity(
          [&server, &before, &after, &seen](connection_t &connection)
          {
            // A close queued before there are keys to send it under never
            // reaches the wire, so the connection would never become closed
            // and never become collectable.
            if (seen || !connection.handshake_complete())
            {
              return;
            }
            seen = true;
            before = server->connection_count();
            connection.close(0, "from the handler", true);
            (void)server->flush();
            after = server->connection_count();
          });

        cancellation_t server_cancel;
        cancellation_t client_cancel;
        auto server_run = [](endpoint_t &endpoint, cancellation_t &cancel) -> detached_task_t { co_await endpoint.run(&cancel); }(*server, server_cancel);
        auto client_run = [](endpoint_t &endpoint, cancellation_t &cancel) -> detached_task_t { co_await endpoint.run(&cancel); }(*client, client_cancel);
        (void)server_run;
        (void)client_run;

        auto target = ip4_addr("127.0.0.1", *port);
        REQUIRE(target.has_value());
        auto dialled = client->connect(reinterpret_cast<const sockaddr *>(&*target), "localhost");
        REQUIRE(dialled.has_value());

        for (int i = 0; i < 400 && !seen; ++i)
        {
          co_await sleep(loop, 5ms);
        }

        client_cancel.cancel();
        server_cancel.cancel();
        co_await sleep(loop, 50ms);
        client.reset();
        server.reset();
        co_await sleep(loop, 50ms);
        loop.stop();
      }(event_loop, identity, count_before, count_after, observed);
    });

  event_loop.run();
  REQUIRE(observed);
  CHECK(count_before == 1);
  // Still there. A reap that ran here would have collected it, and the walk
  // outside would then have flushed freed storage.
  CHECK(count_after == 1);
}

// Several connections on one client endpoint, all to the same server. Each
// holds its own routes and none may take another's: the table is keyed on
// connection id, so an overwrite silently redirects every datagram for the
// first connection -- and reap withdraws the ids the losing entry believes it
// owns, which then unroutes the winner as well.
TEST_CASE("concurrent dials on one endpoint each keep their own routes")
{
  using namespace vio;
  using namespace vio::quic;

  const auto identity = make_self_signed("localhost");
  event_loop_t event_loop;
  std::size_t reachable = 0;

  event_loop.run_in_loop(
    [&]
    {
      return [](event_loop_t &loop, const certificate_t &identity_pem, std::size_t &count) -> vio::task_t<void>
      {
        tls_config_t server_tls;
        server_tls.role = tls_role_t::server;
        server_tls.certificate_chain_pem = identity_pem.certificate_pem;
        server_tls.private_key_pem = identity_pem.private_key_pem;
        server_tls.alpn = {"test"};
        auto server_context = tls_context_t::create(server_tls);
        REQUIRE(server_context.has_value());

        tls_config_t client_tls;
        client_tls.role = tls_role_t::client;
        client_tls.ca_certificates_pem = identity_pem.certificate_pem;
        client_tls.alpn = {"test"};
        auto client_context = tls_context_t::create(client_tls);
        REQUIRE(client_context.has_value());

        endpoint_config_t server_config;
        server_config.connection.role = tls_role_t::server;
        auto server_created = endpoint_t::create(loop, *server_context, server_config);
        REQUIRE(server_created.has_value());
        std::optional<endpoint_t> server(std::move(*server_created));

        auto bind_address = ip4_addr("127.0.0.1", 0);
        REQUIRE(bind_address.has_value());
        REQUIRE(server->bind(reinterpret_cast<const sockaddr *>(&*bind_address)).has_value());
        auto port = server->local_port();
        REQUIRE(port.has_value());

        endpoint_config_t client_config;
        client_config.connection.role = tls_role_t::client;
        auto client_created = endpoint_t::create(loop, *client_context, client_config);
        REQUIRE(client_created.has_value());
        std::optional<endpoint_t> client(std::move(*client_created));

        cancellation_t server_cancel;
        cancellation_t client_cancel;
        auto server_run = [](endpoint_t &endpoint, cancellation_t &cancel) -> detached_task_t { co_await endpoint.run(&cancel); }(*server, server_cancel);
        auto client_run = [](endpoint_t &endpoint, cancellation_t &cancel) -> detached_task_t { co_await endpoint.run(&cancel); }(*client, client_cancel);
        (void)server_run;
        (void)client_run;

        auto target = ip4_addr("127.0.0.1", *port);
        REQUIRE(target.has_value());

        std::vector<connection_handle_t> handles;
        for (int i = 0; i < 4; ++i)
        {
          auto handle = client->connect(reinterpret_cast<const sockaddr *>(&*target), "localhost");
          REQUIRE(handle.has_value());
          handles.push_back(*handle);
        }

        for (int i = 0; i < 600; ++i)
        {
          std::size_t done = 0;
          for (const auto handle : handles)
          {
            auto *live = client->connection(handle);
            done += (live != nullptr && live->handshake_complete()) ? 1 : 0;
          }
          if (done == handles.size())
          {
            break;
          }
          co_await sleep(loop, 5ms);
        }

        for (const auto handle : handles)
        {
          auto *live = client->connection(handle);
          if (live != nullptr && live->handshake_complete())
          {
            ++count;
            live->close(0, "done", true);
          }
        }

        co_await sleep(loop, 50ms);
        client_cancel.cancel();
        server_cancel.cancel();
        co_await sleep(loop, 50ms);
        client.reset();
        server.reset();
        co_await sleep(loop, 50ms);
        loop.stop();
      }(event_loop, identity, reachable);
    });

  event_loop.run();
  CHECK(reachable == 4);
}

// The Destination Connection ID a client invents for its first Initial means
// the opposite thing on the two sides, and the demultiplexer routed on it for
// both. On a server it is a value the peer really does address. On a client it
// is the id this endpoint uses to address the PEER, which nothing ever sends
// back here -- and it travels in plaintext in every Initial that goes out, so
// anyone who has seen one can steer a datagram to that connection.
//
// Observable through the stateless reset path: a datagram naming an id this
// endpoint does not answer to earns a reset, and one naming a connection it
// has earns silence. The invented id must fall in the first group.

TEST_CASE("a dialled connection is not routed by the id it invented")
{
  using namespace vio;
  using namespace vio::quic;

  const auto identity = make_self_signed("localhost");
  event_loop_t event_loop;
  bool connected = false;
  int replies_to_invented_id = 0;
  int replies_to_real_id = 0;

  event_loop.run_in_loop(
    [&]
    {
      return [](event_loop_t &loop, const certificate_t &identity_pem, bool &done, int &to_invented, int &to_real) -> vio::task_t<void>
      {
        tls_config_t server_tls;
        server_tls.role = tls_role_t::server;
        server_tls.certificate_chain_pem = identity_pem.certificate_pem;
        server_tls.private_key_pem = identity_pem.private_key_pem;
        server_tls.alpn = {"test"};
        tls_config_t client_tls;
        client_tls.role = tls_role_t::client;
        client_tls.ca_certificates_pem = identity_pem.certificate_pem;
        client_tls.alpn = {"test"};

        auto server_context = tls_context_t::create(server_tls);
        auto client_context = tls_context_t::create(client_tls);
        REQUIRE(server_context.has_value());
        REQUIRE(client_context.has_value());

        endpoint_config_t server_config;
        server_config.connection.role = tls_role_t::server;
        auto server_created = endpoint_t::create(loop, *server_context, server_config);
        REQUIRE(server_created.has_value());
        std::optional<endpoint_t> server(std::move(*server_created));

        auto bind_address = ip4_addr("127.0.0.1", 0);
        REQUIRE(bind_address.has_value());
        REQUIRE(server->bind(reinterpret_cast<const sockaddr *>(&*bind_address)).has_value());
        auto server_port = server->local_port();
        REQUIRE(server_port.has_value());

        // The client is given a reset key and a fixed port, so a probe can ask
        // it what it does and does not answer to.
        auto reset_key = stateless_reset_key_t::create();
        REQUIRE(reset_key.has_value());
        endpoint_config_t client_config;
        client_config.connection.role = tls_role_t::client;
        client_config.stateless_reset_key = &*reset_key;
        auto client_created = endpoint_t::create(loop, *client_context, client_config);
        REQUIRE(client_created.has_value());
        std::optional<endpoint_t> client(std::move(*client_created));
        auto client_bind = ip4_addr("127.0.0.1", 0);
        REQUIRE(client_bind.has_value());
        REQUIRE(client->bind(reinterpret_cast<const sockaddr *>(&*client_bind)).has_value());
        auto client_port = client->local_port();
        REQUIRE(client_port.has_value());

        cancellation_t server_cancel;
        cancellation_t client_cancel;
        auto server_run = [](endpoint_t &endpoint, cancellation_t &cancel) -> detached_task_t { co_await endpoint.run(&cancel); }(*server, server_cancel);
        auto client_run = [](endpoint_t &endpoint, cancellation_t &cancel) -> detached_task_t { co_await endpoint.run(&cancel); }(*client, client_cancel);
        (void)server_run;
        (void)client_run;

        auto target = ip4_addr("127.0.0.1", *server_port);
        REQUIRE(target.has_value());
        auto handle = client->connect(reinterpret_cast<const sockaddr *>(&*target), "localhost");
        REQUIRE(handle.has_value());

        connection_id_t invented;
        connection_id_t real;
        for (int i = 0; i < 400; ++i)
        {
          auto *live = client->connection(*handle);
          if (live == nullptr)
          {
            break;
          }
          if (live->handshake_complete())
          {
            done = true;
            invented = live->original_destination_id();
            const auto issued = live->issued_connection_ids();
            REQUIRE_FALSE(issued.empty());
            real = issued.front();
            break;
          }
          co_await sleep(loop, 5ms);
        }
        REQUIRE(done);
        REQUIRE_FALSE(invented.empty());
        REQUIRE_FALSE(real.empty());

        auto probe_created = udp_create(loop);
        REQUIRE(probe_created.has_value());
        std::optional<udp_t> probe(std::move(*probe_created));
        auto probe_address = ip4_addr("127.0.0.1", 0);
        REQUIRE(probe_address.has_value());
        REQUIRE(udp_bind(*probe, reinterpret_cast<const sockaddr *>(&*probe_address)).has_value());
        auto reader_created = udp_create_reader(*probe);
        REQUIRE(reader_created.has_value());
        std::optional<udp_reader_t> reader(std::move(*reader_created));

        int received = 0;
        auto pump = [](decltype(*reader) &r, int &count) -> detached_task_t
        {
          for (;;)
          {
            auto datagram = co_await r;
            if (!datagram.has_value())
            {
              break;
            }
            ++count;
          }
        }(*reader, received);
        (void)pump;

        auto client_target = ip4_addr("127.0.0.1", *client_port);
        REQUIRE(client_target.has_value());

        // A short header naming the given connection id. A reset comes back
        // only when the endpoint does not recognise it.
        const auto probe_with = [&](const connection_id_t &id) -> vio::task_t<int>
        {
          received = 0;
          std::vector<std::uint8_t> datagram(100, 0x00);
          datagram[0] = 0x40;
          const auto raw = id.bytes();
          std::copy(raw.begin(), raw.end(), datagram.begin() + 1);
          (void)udp_try_send(*probe, datagram, reinterpret_cast<const sockaddr *>(&*client_target));
          for (int i = 0; i < 20 && received == 0; ++i)
          {
            co_await sleep(loop, 5ms);
          }
          co_return int{received};
        };

        to_invented = co_await probe_with(invented);
        to_real = co_await probe_with(real);

        reader->cancel();
        co_await sleep(loop, 20ms);
        reader.reset();
        probe.reset();

        if (auto *live = client->connection(*handle); live != nullptr)
        {
          live->close(0, "done", true);
        }
        co_await sleep(loop, 50ms);
        client_cancel.cancel();
        server_cancel.cancel();
        co_await sleep(loop, 50ms);
        client.reset();
        server.reset();
        co_await sleep(loop, 50ms);
        loop.stop();
      }(event_loop, identity, connected, replies_to_invented_id, replies_to_real_id);
    });

  event_loop.run();
  CHECK(connected);
  // Not an id this endpoint answers to, so the datagram is unknown and draws a
  // reset. Routed to the dialled connection it would instead have failed to
  // authenticate and been dropped in silence.
  CHECK(replies_to_invented_id == 1);
  // And an id it really did issue is recognised, so there is no reset for it.
  CHECK(replies_to_real_id == 0);
}

// One endpoint, one port, both directions. A tls_context_t is built for a
// single role, so an endpoint that answers and dials needs one of each -- and
// which of them it holds is what decides what it can do.

TEST_CASE("one endpoint both answers and dials on the same port")
{
  using namespace vio;
  using namespace vio::quic;

  const auto identity = make_self_signed("localhost");
  event_loop_t event_loop;
  bool left_dial_connected = false;
  bool right_dial_connected = false;
  std::size_t left_accepted = 0;
  std::size_t right_accepted = 0;
  std::size_t left_client_role = 0;
  std::size_t left_server_role = 0;

  event_loop.run_in_loop(
    [&]
    {
      return [](event_loop_t &loop, const certificate_t &identity_pem, bool &left_ok, bool &right_ok, std::size_t &left_in, std::size_t &right_in, std::size_t &clients, std::size_t &servers) -> vio::task_t<void>
      {
        // One description, two contexts. Both peers answer with the same
        // identity and trust it, which is all a two-node demonstration needs.
        tls_config_t server_tls;
        server_tls.role = tls_role_t::server;
        server_tls.certificate_chain_pem = identity_pem.certificate_pem;
        server_tls.private_key_pem = identity_pem.private_key_pem;
        server_tls.alpn = {"test"};
        tls_config_t client_tls;
        client_tls.role = tls_role_t::client;
        client_tls.ca_certificates_pem = identity_pem.certificate_pem;
        client_tls.alpn = {"test"};

        auto answering = tls_context_t::create(server_tls);
        auto dialling = tls_context_t::create(client_tls);
        REQUIRE(answering.has_value());
        REQUIRE(dialling.has_value());

        const auto make_peer = [&](std::optional<endpoint_t> &out) -> bool
        {
          endpoint_config_t config;
          auto created = endpoint_t::create(loop, &*answering, &*dialling, config);
          if (!created.has_value())
          {
            return false;
          }
          out.emplace(std::move(*created));
          auto address = ip4_addr("127.0.0.1", 0);
          return address.has_value() && out.value().bind(reinterpret_cast<const sockaddr *>(&*address)).has_value();
        };

        std::optional<endpoint_t> left;
        std::optional<endpoint_t> right;
        REQUIRE(make_peer(left));
        REQUIRE(make_peer(right));

        auto left_port = left->local_port();
        auto right_port = right->local_port();
        REQUIRE(left_port.has_value());
        REQUIRE(right_port.has_value());

        // on_connection fires for every completed handshake, dialled ones
        // included, so a peer that does both has to sort them by role.
        left->on_connection(
          [&left_in, &clients, &servers](connection_t &connection)
          {
            if (connection.role() == tls_role_t::server)
            {
              ++left_in;
              ++servers;
            }
            else
            {
              ++clients;
            }
          });
        right->on_connection([&right_in](connection_t &connection)
                             {
                               if (connection.role() == tls_role_t::server)
                               {
                                 ++right_in;
                               }
                             });

        cancellation_t left_cancel;
        cancellation_t right_cancel;
        auto left_run = [](endpoint_t &endpoint, cancellation_t &cancel) -> detached_task_t { co_await endpoint.run(&cancel); }(*left, left_cancel);
        auto right_run = [](endpoint_t &endpoint, cancellation_t &cancel) -> detached_task_t { co_await endpoint.run(&cancel); }(*right, right_cancel);
        (void)left_run;
        (void)right_run;

        auto to_right = ip4_addr("127.0.0.1", *right_port);
        auto to_left = ip4_addr("127.0.0.1", *left_port);
        REQUIRE(to_right.has_value());
        REQUIRE(to_left.has_value());

        // Each dials the other at the same time, so both connections on each
        // endpoint are live together.
        auto left_handle = left->connect(reinterpret_cast<const sockaddr *>(&*to_right), "localhost");
        auto right_handle = right->connect(reinterpret_cast<const sockaddr *>(&*to_left), "localhost");
        REQUIRE(left_handle.has_value());
        REQUIRE(right_handle.has_value());

        for (int i = 0; i < 600; ++i)
        {
          auto *l = left->connection(*left_handle);
          auto *r = right->connection(*right_handle);
          const bool l_done = l != nullptr && l->handshake_complete();
          const bool r_done = r != nullptr && r->handshake_complete();
          if (l_done && r_done && left_in > 0 && right_in > 0)
          {
            break;
          }
          co_await sleep(loop, 5ms);
        }

        if (auto *l = left->connection(*left_handle); l != nullptr)
        {
          left_ok = l->handshake_complete();
          l->close(0, "done", true);
        }
        if (auto *r = right->connection(*right_handle); r != nullptr)
        {
          right_ok = r->handshake_complete();
          r->close(0, "done", true);
        }

        co_await sleep(loop, 50ms);
        left_cancel.cancel();
        right_cancel.cancel();
        co_await sleep(loop, 50ms);
        left.reset();
        right.reset();
        co_await sleep(loop, 50ms);
        loop.stop();
      }(event_loop, identity, left_dial_connected, right_dial_connected, left_accepted, right_accepted, left_client_role, left_server_role);
    });

  event_loop.run();
  CHECK(left_dial_connected);
  CHECK(right_dial_connected);
  // Each peer answered the other's dial as well as completing its own.
  CHECK(left_accepted == 1);
  CHECK(right_accepted == 1);
  // And one endpoint really did hold a connection of each role at once.
  CHECK(left_client_role == 1);
  CHECK(left_server_role == 1);
}

// What an endpoint holds decides what it can do, and both refusals are
// immediate rather than a handshake that quietly never completes.
TEST_CASE("a connection survives its peer's address changing under it")
{
  using namespace vio;
  using namespace vio::quic;

  // NAT rebinding, over real sockets, which is the shape migration actually
  // arrives in: nobody tells the client anything, its datagrams simply start
  // reaching the server from a different source address. Section 9.3 says the
  // server follows -- and everything below the endpoint has been tested with
  // byte arrays, so this is the first thing that exercises the demultiplexer
  // rerouting a live connection and the socket sending to the new address.
  //
  // The rebind is faked with a relay: the client talks to one socket, and the
  // relay forwards to the server from `up_a` and then, on command, from `up_b`.
  // To the server that is one connection whose peer moved; to the client
  // nothing happened at all, which is exactly what a NAT does to you.
  const auto identity = make_self_signed("localhost");
  tls_config_t server_tls;
  server_tls.role = tls_role_t::server;
  server_tls.certificate_chain_pem = identity.certificate_pem;
  server_tls.private_key_pem = identity.private_key_pem;
  server_tls.alpn = {"test"};
  tls_config_t client_tls;
  client_tls.role = tls_role_t::client;
  client_tls.ca_certificates_pem = identity.certificate_pem;
  client_tls.alpn = {"test"};
  auto server_context = tls_context_t::create(server_tls);
  auto client_context = tls_context_t::create(client_tls);
  REQUIRE(server_context.has_value());
  REQUIRE(client_context.has_value());

  event_loop_t event_loop;
  std::optional<vio::task_t<void>> task;
  bool handshaken = false;
  std::uint64_t migrations = 0;
  std::string before_move;
  std::string after_move;

  event_loop.run_in_loop(
    [&]
    {
      task.emplace(
        [](event_loop_t &loop, const tls_context_t &server_ctx, const tls_context_t &client_ctx, bool &handshaken, std::uint64_t &migrations, std::string &before_move, std::string &after_move) -> vio::task_t<void>
        {
          {
            endpoint_config_t server_config;
            server_config.connection.role = tls_role_t::server;
            server_config.connection.transport_parameters = sane_parameters();
            auto server_made = endpoint_t::create(loop, server_ctx, server_config);
            REQUIRE(server_made.has_value());
            std::optional<endpoint_t> server(std::move(*server_made));
            auto any = ip4_addr("127.0.0.1", 0);
            REQUIRE(any.has_value());
            REQUIRE(server->bind(reinterpret_cast<const sockaddr *>(&*any)).has_value());
            const auto server_port = server->local_port();
            REQUIRE(server_port.has_value());

            // The server answers whatever arrives on a stream.
            connection_t *accepted = nullptr;
            server->on_connection([&accepted](connection_t &c) { accepted = &c; });
            server->on_activity(
              [](connection_t &c)
              {
                for (const auto id : c.readable_streams())
                {
                  auto readable = c.readable_stream(id);
                  (void)c.write_stream(id, readable, false);
                  c.consume_stream(id, readable.size());
                }
              });

            // The relay's three sockets.
            auto face_made = udp_create(loop);
            auto up_a_made = udp_create(loop);
            auto up_b_made = udp_create(loop);
            REQUIRE(face_made.has_value());
            REQUIRE(up_a_made.has_value());
            REQUIRE(up_b_made.has_value());
            std::optional<udp_t> face(std::move(*face_made));
            std::optional<udp_t> up_a(std::move(*up_a_made));
            std::optional<udp_t> up_b(std::move(*up_b_made));
            for (auto *sock : {&*face, &*up_a, &*up_b})
            {
              REQUIRE(udp_bind(*sock, reinterpret_cast<const sockaddr *>(&*any)).has_value());
            }
            auto face_name = udp_sockname(*face);
            REQUIRE(face_name.has_value());
            const int face_port = ntohs(reinterpret_cast<const sockaddr_in *>(&*face_name)->sin_port);

            const auto to_server = ip4_addr("127.0.0.1", *server_port);
            REQUIRE(to_server.has_value());
            bool use_b = false;
            sockaddr_storage client_addr = {};
            bool have_client = false;

            // The readers live out here so the pumps below can be woken before
            // anything they hold a reference to goes away: cancel, then release
            // the reader, then the socket. A pump parked on a reader that is
            // simply dropped never returns.
            auto face_reader_made = udp_create_reader(*face);
            auto up_a_reader_made = udp_create_reader(*up_a);
            auto up_b_reader_made = udp_create_reader(*up_b);
            REQUIRE(face_reader_made.has_value());
            REQUIRE(up_a_reader_made.has_value());
            REQUIRE(up_b_reader_made.has_value());
            std::optional<udp_reader_t> face_reader(std::move(*face_reader_made));
            std::optional<udp_reader_t> up_a_reader(std::move(*up_a_reader_made));
            std::optional<udp_reader_t> up_b_reader(std::move(*up_b_reader_made));

            // Client -> server, through whichever uplink is current.
            auto forward_up = [](udp_reader_t &r, udp_t &a, udp_t &b, sockaddr_in dest, bool &use_b, sockaddr_storage &client_addr, bool &have_client) -> detached_task_t
            {
              for (;;)
              {
                auto dgram = co_await r;
                if (!dgram.has_value())
                {
                  break;
                }
                client_addr = dgram->sender_addr;
                have_client = true;
                const std::span<const std::uint8_t> bytes(reinterpret_cast<const std::uint8_t *>(dgram->data.data()), dgram->data.size());
                (void)udp_try_send(use_b ? b : a, bytes, reinterpret_cast<const sockaddr *>(&dest));
              }
            }(*face_reader, *up_a, *up_b, *to_server, use_b, client_addr, have_client);

            // Server -> client, from whichever uplink it answered on.
            //
            // `retired` is what makes this a rebind rather than a second path:
            // once the NAT has moved, the old mapping is gone, and a reply the
            // server still addresses to it is dropped on the floor. Without
            // that the test proves nothing -- the server could keep answering
            // the old address for ever and the client would never notice.
            auto forward_down = [](udp_reader_t &r, udp_t &face_sock, sockaddr_storage &client_addr, bool &have_client, const bool &retired) -> detached_task_t
            {
              for (;;)
              {
                auto dgram = co_await r;
                if (!dgram.has_value())
                {
                  break;
                }
                if (!have_client || retired)
                {
                  continue;
                }
                const std::span<const std::uint8_t> bytes(reinterpret_cast<const std::uint8_t *>(dgram->data.data()), dgram->data.size());
                (void)udp_try_send(face_sock, bytes, reinterpret_cast<const sockaddr *>(&client_addr));
              }
            };
            bool never_retired = false;
            auto down_a = forward_down(*up_a_reader, *face, client_addr, have_client, use_b);
            auto down_b = forward_down(*up_b_reader, *face, client_addr, have_client, never_retired);
            (void)forward_up;
            (void)down_a;
            (void)down_b;

            endpoint_config_t client_config;
            client_config.connection.role = tls_role_t::client;
            client_config.connection.transport_parameters = sane_parameters();
            auto client_made = endpoint_t::create(loop, client_ctx, client_config);
            REQUIRE(client_made.has_value());
            std::optional<endpoint_t> client(std::move(*client_made));

            std::string echoed;
            client->on_activity(
              [&echoed](connection_t &c)
              {
                for (const auto id : c.readable_streams())
                {
                  auto readable = c.readable_stream(id);
                  echoed.append(reinterpret_cast<const char *>(readable.data()), readable.size());
                  c.consume_stream(id, readable.size());
                }
              });

            cancellation_t server_stop;
            cancellation_t client_stop;
            auto run_one = [](endpoint_t &e, cancellation_t &c) -> detached_task_t { co_await e.run(&c); };
            auto server_run = run_one(*server, server_stop);
            auto client_run = run_one(*client, client_stop);
            (void)server_run;
            (void)client_run;

            const auto via_relay = ip4_addr("127.0.0.1", face_port);
            REQUIRE(via_relay.has_value());
            auto dialled = client->connect(reinterpret_cast<const sockaddr *>(&*via_relay), "localhost");
            REQUIRE(dialled.has_value());
            for (int i = 0; i < 400 && (client->connection(*dialled) == nullptr || !client->connection(*dialled)->handshake_complete()); ++i)
            {
              (void)co_await sleep(loop, 5ms);
            }
            auto *connection = client->connection(*dialled);
            REQUIRE(connection != nullptr);
            handshaken = connection->handshake_complete();

            auto stream = connection->open_stream(stream_direction_t::bidirectional);
            REQUIRE(stream.has_value());
            const std::string one = "before";
            (void)connection->write_stream(*stream, std::span(reinterpret_cast<const std::uint8_t *>(one.data()), one.size()), false);
            (void)client->flush();
            for (int i = 0; i < 400 && echoed.size() < one.size(); ++i)
            {
              (void)co_await sleep(loop, 5ms);
            }
            before_move = echoed;
            echoed.clear();

            // The NAT rebinds. Nothing else changes.
            use_b = true;

            const std::string two = "after";
            auto *live = client->connection(*dialled);
            REQUIRE(live != nullptr);
            (void)live->write_stream(*stream, std::span(reinterpret_cast<const std::uint8_t *>(two.data()), two.size()), false);
            (void)client->flush();
            for (int i = 0; i < 600 && echoed.size() < two.size(); ++i)
            {
              (void)co_await sleep(loop, 5ms);
            }
            after_move = echoed;
            if (accepted != nullptr)
            {
              migrations = accepted->migration_count();
            }

            server_stop.cancel();
            client_stop.cancel();
            face_reader->cancel();
            up_a_reader->cancel();
            up_b_reader->cancel();
            (void)co_await sleep(loop, 50ms);
            face_reader.reset();
            up_a_reader.reset();
            up_b_reader.reset();
            server.reset();
            client.reset();
            face.reset();
            up_a.reset();
            up_b.reset();
            (void)co_await sleep(loop, 50ms);
          }
          loop.stop();
        }(event_loop, *server_context, *client_context, handshaken, migrations, before_move, after_move));
    });
  event_loop.run();

  CHECK(handshaken);
  CHECK(before_move == "before");
  // The bytes that matter: these crossed a path the connection was not on when
  // it started, and only arrived because the server followed the move.
  CHECK(after_move == "after");
  CHECK(migrations == 1);
}

TEST_CASE("a dial refuses an address it cannot read")
{
  using namespace vio;
  using namespace vio::quic;

  // connect() reads through the sockaddr it is given on the strength of its
  // family: address_bytes switches on it, and the copy into the connection
  // entry takes sizeof(sockaddr_in6) or sizeof(sockaddr_in) accordingly. A null
  // pointer was dereferenced, and a family that was neither read the wrong
  // number of bytes off the caller's stack.
  //
  // The refusal also has to come before the socket is created, or a dial that
  // cannot happen decides the address family a later bind is stuck with.
  const auto identity = make_self_signed("localhost");
  tls_config_t client_tls;
  client_tls.role = tls_role_t::client;
  client_tls.ca_certificates_pem = identity.certificate_pem;
  client_tls.alpn = {"test"};
  auto client_context = tls_context_t::create(client_tls);
  REQUIRE(client_context.has_value());

  event_loop_t event_loop;
  {
    endpoint_config_t config;
    config.connection.role = tls_role_t::client;
    auto endpoint = endpoint_t::create(event_loop, *client_context, config);
    REQUIRE(endpoint.has_value());

    CHECK_FALSE(endpoint->connect(nullptr, "localhost").has_value());

    sockaddr_storage nonsense = {};
    nonsense.ss_family = AF_UNSPEC;
    CHECK_FALSE(endpoint->connect(reinterpret_cast<const sockaddr *>(&nonsense), "localhost").has_value());

    // And the socket still has no family, so a bind can choose one.
    sockaddr_in6 any6 = {};
    any6.sin6_family = AF_INET6;
    CHECK(endpoint->bind(reinterpret_cast<const sockaddr *>(&any6)).has_value());
  }
  event_loop.stop();
  event_loop.run();
}

TEST_CASE("an endpoint refuses the direction it has no context for")
{
  using namespace vio;
  using namespace vio::quic;

  const auto identity = make_self_signed("localhost");
  event_loop_t event_loop;
  bool dial_refused = false;
  bool socket_untouched = false;
  int replies_to_initial = 0;

  event_loop.run_in_loop(
    [&]
    {
      return [](event_loop_t &loop, const certificate_t &identity_pem, bool &refused, bool &unbound, int &answered) -> vio::task_t<void>
      {
        tls_config_t server_tls;
        server_tls.role = tls_role_t::server;
        server_tls.certificate_chain_pem = identity_pem.certificate_pem;
        server_tls.private_key_pem = identity_pem.private_key_pem;
        server_tls.alpn = {"test"};
        tls_config_t client_tls;
        client_tls.role = tls_role_t::client;
        client_tls.ca_certificates_pem = identity_pem.certificate_pem;
        client_tls.alpn = {"test"};

        auto answering = tls_context_t::create(server_tls);
        auto dialling = tls_context_t::create(client_tls);
        REQUIRE(answering.has_value());
        REQUIRE(dialling.has_value());

        // A pair whose roles are swapped is refused at create, where it can
        // still be reported, rather than at the first handshake.
        endpoint_config_t config;
        auto swapped = endpoint_t::create(loop, &*dialling, &*answering, config);
        CHECK_FALSE(swapped.has_value());
        auto empty = endpoint_t::create(loop, nullptr, nullptr, config);
        CHECK_FALSE(empty.has_value());

        // Answer-only: it has nothing to dial with.
        auto answer_only_created = endpoint_t::create(loop, &*answering, nullptr, config);
        REQUIRE(answer_only_created.has_value());
        std::optional<endpoint_t> answer_only(std::move(*answer_only_created));

        auto somewhere = ip4_addr("127.0.0.1", 9);
        REQUIRE(somewhere.has_value());
        auto dialled = answer_only->connect(reinterpret_cast<const sockaddr *>(&*somewhere), "localhost");
        refused = !dialled.has_value();
        // The refusal came before the socket was acquired, which is what lets
        // a later bind still choose the address family.
        unbound = !answer_only->local_port().has_value();

        // Dial-only: it has nothing to answer with, so an Initial addressed to
        // it builds no connection and draws no reply at all.
        auto dial_only_created = endpoint_t::create(loop, nullptr, &*dialling, config);
        REQUIRE(dial_only_created.has_value());
        std::optional<endpoint_t> dial_only(std::move(*dial_only_created));
        auto bind_address = ip4_addr("127.0.0.1", 0);
        REQUIRE(bind_address.has_value());
        REQUIRE(dial_only->bind(reinterpret_cast<const sockaddr *>(&*bind_address)).has_value());
        auto dial_only_port = dial_only->local_port();
        REQUIRE(dial_only_port.has_value());

        cancellation_t dial_only_cancel;
        auto dial_only_run = [](endpoint_t &endpoint, cancellation_t &cancel) -> detached_task_t { co_await endpoint.run(&cancel); }(*dial_only, dial_only_cancel);
        (void)dial_only_run;

        auto probe_created = udp_create(loop);
        REQUIRE(probe_created.has_value());
        std::optional<udp_t> probe(std::move(*probe_created));
        auto probe_address = ip4_addr("127.0.0.1", 0);
        REQUIRE(probe_address.has_value());
        REQUIRE(udp_bind(*probe, reinterpret_cast<const sockaddr *>(&*probe_address)).has_value());
        auto reader_created = udp_create_reader(*probe);
        REQUIRE(reader_created.has_value());
        std::optional<udp_reader_t> reader(std::move(*reader_created));

        int received = 0;
        auto pump = [](decltype(*reader) &r, int &count) -> detached_task_t
        {
          for (;;)
          {
            auto datagram = co_await r;
            if (!datagram.has_value())
            {
              break;
            }
            ++count;
          }
        }(*reader, received);
        (void)pump;

        // A full-sized long header naming a version this build does not speak.
        // An answering endpoint replies with a Version Negotiation; one that
        // only dials has no service to offer and stays silent.
        auto target = ip4_addr("127.0.0.1", *dial_only_port);
        REQUIRE(target.has_value());
        std::vector<std::uint8_t> unknown_version(1200, 0x00);
        unknown_version[0] = 0xC0;
        unknown_version[1] = 0x0A;
        unknown_version[2] = 0x0A;
        unknown_version[3] = 0x0A;
        unknown_version[4] = 0x0A;
        (void)udp_try_send(*probe, unknown_version, reinterpret_cast<const sockaddr *>(&*target));
        for (int i = 0; i < 20 && received == 0; ++i)
        {
          co_await sleep(loop, 5ms);
        }
        answered = received;

        reader->cancel();
        co_await sleep(loop, 20ms);
        reader.reset();
        probe.reset();

        dial_only_cancel.cancel();
        co_await sleep(loop, 50ms);
        dial_only.reset();
        answer_only.reset();
        co_await sleep(loop, 50ms);
        loop.stop();
      }(event_loop, identity, dial_refused, socket_untouched, replies_to_initial);
    });

  event_loop.run();
  CHECK(dial_refused);
  CHECK(socket_untouched);
  CHECK(replies_to_initial == 0);
}

// KNOWN FAILURE, kept because it is the only statement of the bug.
//
// run() creates the socket itself, with ensure_socket's default family of
// AF_INET. It is normally spawned before the first dial and task_t is eager,
// so it gets there first and pins the endpoint to IPv4 -- after which a dial
// to an IPv6 peer has nowhere to go, because a socket's family cannot change.
//
// The obvious fix -- have run() wait for bind() or connect() to make the
// socket, since only they know the family -- was tried and reverted: the wait
// delays the reader by a loop turn, and that was enough to take the ECN
// validation in the test above from 12/12 to 4/12. A real fix has to arm the
// reader the moment the socket appears rather than after a sleep, which is
// endpoint plumbing this change did not want to disturb.

TEST_CASE("an endpoint reaches an IPv6 peer even with run() started first" * doctest::should_fail())
{
  using namespace vio;
  using namespace vio::quic;

  const auto identity = make_self_signed("localhost");
  event_loop_t event_loop;
  bool connected = false;
  bool skipped = false;

  event_loop.run_in_loop(
    [&]
    {
      return [](event_loop_t &loop, const certificate_t &identity_pem, bool &ok, bool &no_ipv6) -> vio::task_t<void>
      {
        tls_config_t server_tls;
        server_tls.role = tls_role_t::server;
        server_tls.certificate_chain_pem = identity_pem.certificate_pem;
        server_tls.private_key_pem = identity_pem.private_key_pem;
        server_tls.alpn = {"test"};
        tls_config_t client_tls;
        client_tls.role = tls_role_t::client;
        client_tls.ca_certificates_pem = identity_pem.certificate_pem;
        client_tls.alpn = {"test"};

        auto server_context = tls_context_t::create(server_tls);
        auto client_context = tls_context_t::create(client_tls);
        REQUIRE(server_context.has_value());
        REQUIRE(client_context.has_value());

        endpoint_config_t server_config;
        server_config.connection.role = tls_role_t::server;
        auto server_created = endpoint_t::create(loop, *server_context, server_config);
        REQUIRE(server_created.has_value());
        std::optional<endpoint_t> server(std::move(*server_created));

        auto bind_address = ip6_addr("::1", 0);
        if (!bind_address.has_value() || !server->bind(reinterpret_cast<const sockaddr *>(&*bind_address)).has_value())
        {
          // A machine with no IPv6 loopback has nothing to say about this.
          no_ipv6 = true;
          server.reset();
          co_await sleep(loop, 20ms);
          loop.stop();
          co_return;
        }
        auto port = server->local_port();
        REQUIRE(port.has_value());

        endpoint_config_t client_config;
        client_config.connection.role = tls_role_t::client;
        auto client_created = endpoint_t::create(loop, *client_context, client_config);
        REQUIRE(client_created.has_value());
        std::optional<endpoint_t> client(std::move(*client_created));

        cancellation_t server_cancel;
        cancellation_t client_cancel;
        // The client is never bound, and its run loop is started before the
        // dial -- exactly the order every program here uses, and the order
        // that used to decide the address family.
        auto server_run = [](endpoint_t &endpoint, cancellation_t &cancel) -> detached_task_t { co_await endpoint.run(&cancel); }(*server, server_cancel);
        auto client_run = [](endpoint_t &endpoint, cancellation_t &cancel) -> detached_task_t { co_await endpoint.run(&cancel); }(*client, client_cancel);
        (void)server_run;
        (void)client_run;

        auto target = ip6_addr("::1", *port);
        REQUIRE(target.has_value());
        auto dialled = client->connect(reinterpret_cast<const sockaddr *>(&*target), "localhost");
        REQUIRE(dialled.has_value());

        for (int attempt = 0; attempt < 600; ++attempt)
        {
          auto *live = client->connection(*dialled);
          if (live == nullptr || live->handshake_complete())
          {
            break;
          }
          co_await sleep(loop, 5ms);
        }
        if (auto *live = client->connection(*dialled); live != nullptr)
        {
          ok = live->handshake_complete();
          live->close(0, "done", true);
        }

        co_await sleep(loop, 50ms);
        client_cancel.cancel();
        server_cancel.cancel();
        co_await sleep(loop, 50ms);
        client.reset();
        server.reset();
        co_await sleep(loop, 50ms);
        loop.stop();
      }(event_loop, identity, connected, skipped);
    });

  event_loop.run();
  if (skipped)
  {
    MESSAGE("no IPv6 loopback on this machine");
    return;
  }
  CHECK(connected);
}
