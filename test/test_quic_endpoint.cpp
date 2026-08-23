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
#include <vio/quic/endpoint.h>
#include <vio/task.h>

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
      return [](event_loop_t &loop, const certificate_t &identity_pem, bool &handshaken, bool &ecn_still_on, std::string &received) -> task_t<void>
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
        // stopped. event_loop_t::stop() closes its own handles and then runs
        // the loop until nothing is left; a socket still open at that point
        // means it never returns.
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
        connection_t *connection = *dialled;

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
      return [](event_loop_t &loop, const certificate_t &identity_pem, bool &handshaken, bool &through_retry, std::size_t &accepted_connections) -> task_t<void>
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
        connection_t *connection = *dialled;

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
      return [](event_loop_t &loop, const certificate_t &identity_pem, std::size_t &accepted, std::string &first_message, std::string &second_message) -> task_t<void>
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

        for (int i = 0; i < 300 && !((*first_dial)->handshake_complete() && (*second_dial)->handshake_complete()); ++i)
        {
          co_await sleep(loop, 5ms);
        }
        REQUIRE((*first_dial)->handshake_complete());
        REQUIRE((*second_dial)->handshake_complete());
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
        const auto first_stream = say(**first_dial, *first, "from the first client");
        const auto second_stream = say(**second_dial, *second, "from the second client");

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
}
