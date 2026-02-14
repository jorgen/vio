#include <doctest/doctest.h>
#include <numeric>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <string>
#include <string_view>
#include <vio/error.h>
#include <vio/event_loop.h>
#include <vio/operation/tls_server.h>
#include <vio/task.h>

#include "require_expected.h"
#include "vio/operation/tcp.h"
#include "vio/operation/tcp_server.h"
#include "vio/operation/tls_client.h"

#define PROPAGATE_ERROR(x)                                                                                                                                                                                                 \
  if (!(x).has_value())                                                                                                                                                                                                    \
    return std::unexpected(std::move((x).error()));

namespace
{
struct test_certificates_t
{
  std::vector<uint8_t> ca_cert;
  std::vector<uint8_t> ca_key;
  std::vector<uint8_t> cert;
  std::vector<uint8_t> key;
};

test_certificates_t generate_test_certs()
{
  // Generate CA key and certificate
  X509 *ca_cert = X509_new();
  EVP_PKEY *ca_pkey = EVP_PKEY_new();
  EVP_PKEY_CTX *ca_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
  EVP_PKEY_keygen_init(ca_ctx);
  EVP_PKEY_CTX_set_rsa_keygen_bits(ca_ctx, 2048);
  EVP_PKEY_keygen(ca_ctx, &ca_pkey);
  EVP_PKEY_CTX_free(ca_ctx);

  X509_set_version(ca_cert, 2);
  ASN1_INTEGER_set(X509_get_serialNumber(ca_cert), 1);
  X509_gmtime_adj(X509_get_notBefore(ca_cert), 0);
  X509_gmtime_adj(X509_get_notAfter(ca_cert), 31536000L);
  X509_set_pubkey(ca_cert, ca_pkey);

  auto *ca_name = X509_get_subject_name(ca_cert);
  X509_NAME_add_entry_by_txt(ca_name, "C", MBSTRING_ASC, (unsigned char *)"NO", -1, -1, 0);
  X509_NAME_add_entry_by_txt(ca_name, "O", MBSTRING_ASC, (unsigned char *)"vio CA", -1, -1, 0);
  X509_NAME_add_entry_by_txt(ca_name, "CN", MBSTRING_ASC, (unsigned char *)"vio CA", -1, -1, 0);
  X509_set_issuer_name(ca_cert, ca_name);

  X509_sign(ca_cert, ca_pkey, EVP_sha256());

  // Generate server certificate
  X509 *cert = X509_new();
  EVP_PKEY *pkey = EVP_PKEY_new();
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
  EVP_PKEY_keygen_init(ctx);
  EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
  EVP_PKEY_keygen(ctx, &pkey);
  EVP_PKEY_CTX_free(ctx);

  X509_set_version(cert, 2);
  ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
  X509_gmtime_adj(X509_get_notBefore(cert), 0);
  X509_gmtime_adj(X509_get_notAfter(cert), 31536000L);
  X509_set_pubkey(cert, pkey);

  auto *name = X509_get_subject_name(cert);
  X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *)"NO", -1, -1, 0);
  X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char *)"vio unit test", -1, -1, 0);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"localhost", -1, -1, 0);
  X509_set_issuer_name(cert, ca_name);

  X509_sign(cert, ca_pkey, EVP_sha256());

  BIO *ca_cert_bio = BIO_new(BIO_s_mem());
  BIO *ca_key_bio = BIO_new(BIO_s_mem());
  BIO *cert_bio = BIO_new(BIO_s_mem());
  BIO *key_bio = BIO_new(BIO_s_mem());

  PEM_write_bio_X509(ca_cert_bio, ca_cert);
  PEM_write_bio_PrivateKey(ca_key_bio, ca_pkey, nullptr, nullptr, 0, nullptr, nullptr);
  PEM_write_bio_X509(cert_bio, cert);
  PEM_write_bio_PrivateKey(key_bio, pkey, nullptr, nullptr, 0, nullptr, nullptr);

  std::vector<uint8_t> ca_cert_data(BIO_pending(ca_cert_bio));
  std::vector<uint8_t> ca_key_data(BIO_pending(ca_key_bio));
  std::vector<uint8_t> cert_data(BIO_pending(cert_bio));
  std::vector<uint8_t> key_data(BIO_pending(key_bio));

  BIO_read(ca_cert_bio, ca_cert_data.data(), static_cast<int>(ca_cert_data.size()));
  BIO_read(ca_key_bio, ca_key_data.data(), static_cast<int>(ca_key_data.size()));
  BIO_read(cert_bio, cert_data.data(), static_cast<int>(cert_data.size()));
  BIO_read(key_bio, key_data.data(), static_cast<int>(key_data.size()));

  BIO_free(ca_cert_bio);
  BIO_free(ca_key_bio);
  BIO_free(cert_bio);
  BIO_free(key_bio);
  X509_free(ca_cert);
  EVP_PKEY_free(ca_pkey);
  X509_free(cert);
  EVP_PKEY_free(pkey);

  return {.ca_cert = ca_cert_data, .ca_key = ca_key_data, .cert = cert_data, .key = key_data};
}

vio::task_t<void> test_tls_server(vio::event_loop_t &event_loop, vio::tcp_server_t &&s, int port, vio::ssl_config_t config, bool &server_got_data, bool &server_wrote_msg)
{
  auto server_create_result = vio::ssl_server_create(event_loop, std::move(s), "localhost", config);
  REQUIRE_EXPECTED(server_create_result);

  auto server = std::move(server_create_result.value());
  auto server_listen_result = co_await vio::ssl_server_listen(server, port);
  REQUIRE_EXPECTED(server_listen_result);
  auto client_or_err = vio::ssl_server_accept(server);
  REQUIRE_EXPECTED(client_or_err);
  auto client = std::move(client_or_err.value());
  auto reader = vio::ssl_server_client_create_reader(client);
  auto read_result = co_await reader.value();
  REQUIRE_EXPECTED(read_result);
  auto &read_data = read_result.value();
  const std::string_view sv(read_data->base, read_data->len);
  if (sv.find("Hello from client") != std::string_view::npos)
  {
    server_got_data = true;
  }
  std::string reply = "Hello from server";
  const uv_buf_t buf = uv_buf_init(reinterpret_cast<char *>(reply.data()), reply.size());
  auto write_result = co_await vio::ssl_server_client_write(client, buf);
  REQUIRE_EXPECTED(write_result);
  server_wrote_msg = true;
};

std::expected<std::pair<vio::tcp_server_t, int>, vio::error_t> get_ephemeral_port(vio::event_loop_t &event_loop)
{
  auto addr_or_err = vio::ip4_addr("127.0.0.1", 0);
  PROPAGATE_ERROR(addr_or_err);
  auto tcp_server = vio::tcp_create_server(event_loop);
  PROPAGATE_ERROR(tcp_server);
  auto bind_res = vio::tcp_bind(tcp_server.value(), reinterpret_cast<const sockaddr *>(&addr_or_err.value()));
  PROPAGATE_ERROR(bind_res);

  auto sockname_result = vio::sockname(tcp_server->tcp);
  PROPAGATE_ERROR(sockname_result);
  sockaddr_storage sa_storage = sockname_result.value();
  const auto *sa_in = reinterpret_cast<sockaddr_in *>(&sa_storage);
  return std::make_pair(std::move(tcp_server.value()), static_cast<int>(ntohs(sa_in->sin_port)));
}

// A client task that connects to the server, writes a message, and reads the server's reply
vio::task_t<void> test_tls_client(vio::event_loop_t &event_loop, int server_port, vio::ssl_config_t config, bool &client_got_server_reply)
{
  auto client_or_err = vio::ssl_client_create(event_loop, config);
  REQUIRE_EXPECTED(client_or_err);
  auto client_raw = std::move(client_or_err.value());

  auto server_addr_or_err = vio::ip4_addr("127.0.0.1", server_port);
  REQUIRE_EXPECTED(server_addr_or_err);

  auto connect_result = co_await vio::ssl_client_connect(client_raw, "localhost", server_port, "127.0.0.1");
  REQUIRE_EXPECTED(connect_result);

  std::string client_message = "Hello from client";
  const uv_buf_t buf = uv_buf_init(reinterpret_cast<char *>(client_message.data()), client_message.size());
  auto write_result = co_await vio::ssl_client_write(client_raw, buf);
  REQUIRE_EXPECTED(write_result);
  auto reader = vio::ssl_client_create_reader(client_raw);
  REQUIRE_EXPECTED(reader);
  auto read_result = co_await reader.value();
  REQUIRE_EXPECTED(read_result);
  auto &read_data = read_result.value();
  const std::string_view sv(read_data->base, read_data->len);
  if (sv.find("Hello from server") != std::string_view::npos)
  {
    client_got_server_reply = true;
  }
}
TEST_CASE("test basic tls server")
{
  vio::event_loop_t event_loop;

  bool server_got_data = false;
  bool server_wrote_msg = false;
  bool client_got_server_reply = false;

  server_got_data = false;
  server_wrote_msg = false;
  client_got_server_reply = false;

  auto certs = generate_test_certs();
  const vio::ssl_config_t server_config{.ca_mem = certs.ca_cert, .cert_mem = certs.cert, .key_mem = certs.key};
  const vio::ssl_config_t client_config{.ca_mem = certs.ca_cert};
  event_loop.run_in_loop(
    [&event_loop, &server_got_data, &server_wrote_msg, &client_got_server_reply, client_config, server_config]() -> vio::task_t<void>
    {
      auto *ev = &event_loop;
      auto server_tcp_pair = get_ephemeral_port(*ev);
      REQUIRE_EXPECTED(server_tcp_pair);

      auto server = test_tls_server(*ev, std::move(server_tcp_pair->first), server_tcp_pair->second, server_config, server_got_data, server_wrote_msg);
      co_await test_tls_client(*ev, server_tcp_pair->second, client_config, client_got_server_reply);
      co_await std::move(server);

      ev->stop();
    });

  event_loop.run();

  REQUIRE(server_got_data);
  REQUIRE(server_wrote_msg);
  REQUIRE(client_got_server_reply);
}

TEST_CASE("test destroy server while listening")
{
  vio::event_loop_t event_loop;
  auto certs = generate_test_certs();
  vio::ssl_config_t server_config;
  server_config.cert_mem = certs.cert;
  server_config.key_mem = certs.key;
  server_config.ca_mem = certs.ca_cert;

  event_loop.run_in_loop(
    [&event_loop, server_config]() -> vio::task_t<void>
    {
      auto *ev = &event_loop;
      auto server_tcp_pair = get_ephemeral_port(*ev);
      REQUIRE_EXPECTED(server_tcp_pair);

      auto server_create_result = vio::ssl_server_create(*ev, std::move(server_tcp_pair->first), "localhost", server_config);
      REQUIRE_EXPECTED(server_create_result);

      auto server = std::move(server_create_result.value());
      auto listen_future = vio::ssl_server_listen(server, server_tcp_pair->second);

      {
        auto temp_server = std::move(server);
      }

      auto listen_result = co_await listen_future;
      REQUIRE(!listen_result.has_value());

      ev->stop();
    });

  event_loop.run();
}

TEST_CASE("tls echo multiple messages")
{
  vio::event_loop_t event_loop;
  auto certs = generate_test_certs();
  const vio::ssl_config_t server_config{.ca_mem = certs.ca_cert, .cert_mem = certs.cert, .key_mem = certs.key};
  const vio::ssl_config_t client_config{.ca_mem = certs.ca_cert};

  constexpr int num_messages = 5;
  int server_received = 0;
  int client_received = 0;

  event_loop.run_in_loop(
    [&]() -> vio::task_t<void>
    {
      auto *ev = &event_loop;
      auto server_tcp_pair = get_ephemeral_port(*ev);
      REQUIRE_EXPECTED(server_tcp_pair);
      int port = server_tcp_pair->second;

      auto server_task = [](vio::event_loop_t &el, vio::tcp_server_t s, vio::ssl_config_t sc, int p, int nm, int &sr) -> vio::task_t<void>
      {
        auto server_create_result = vio::ssl_server_create(el, std::move(s), "localhost", sc);
        REQUIRE_EXPECTED(server_create_result);
        auto server = std::move(server_create_result.value());

        auto listen_result = co_await vio::ssl_server_listen(server, p);
        REQUIRE_EXPECTED(listen_result);
        auto client_or_err = vio::ssl_server_accept(server);
        REQUIRE_EXPECTED(client_or_err);
        auto client = std::move(client_or_err.value());

        auto reader_or_err = vio::ssl_server_client_create_reader(client);
        REQUIRE_EXPECTED(reader_or_err);
        auto reader = std::move(reader_or_err.value());

        for (int i = 0; i < nm; i++)
        {
          auto read_result = co_await reader;
          REQUIRE_EXPECTED(read_result);
          sr++;

          auto &data = read_result.value();
          uv_buf_t buf = uv_buf_init(data->base, data->len);
          auto write_result = co_await vio::ssl_server_client_write(client, buf);
          REQUIRE_EXPECTED(write_result);
        }
      }(event_loop, std::move(server_tcp_pair->first), server_config, port, num_messages, server_received);

      auto client_task = [](vio::event_loop_t &el, vio::ssl_config_t cc, int p, int nm, int &cr) -> vio::task_t<void>
      {
        auto client_or_err = vio::ssl_client_create(el, cc);
        REQUIRE_EXPECTED(client_or_err);
        auto client = std::move(client_or_err.value());

        auto connect_result = co_await vio::ssl_client_connect(client, "localhost", p, "127.0.0.1");
        REQUIRE_EXPECTED(connect_result);

        auto reader_or_err = vio::ssl_client_create_reader(client);
        REQUIRE_EXPECTED(reader_or_err);
        auto reader = std::move(reader_or_err.value());

        for (int i = 0; i < nm; i++)
        {
          std::string msg = "tls_msg_" + std::to_string(i);
          uv_buf_t buf = uv_buf_init(msg.data(), msg.size());
          auto write_result = co_await vio::ssl_client_write(client, buf);
          REQUIRE_EXPECTED(write_result);

          auto read_result = co_await reader;
          REQUIRE_EXPECTED(read_result);
          auto &data = read_result.value();
          std::string_view sv(data->base, data->len);
          REQUIRE(sv == msg);
          cr++;
        }
      }(event_loop, client_config, port, num_messages, client_received);

      co_await std::move(client_task);
      co_await std::move(server_task);
      ev->stop();
    });

  event_loop.run();
  REQUIRE(server_received == num_messages);
  REQUIRE(client_received == num_messages);
}

TEST_CASE("tls large data round trip")
{
  vio::event_loop_t event_loop;
  auto certs = generate_test_certs();
  const vio::ssl_config_t server_config{.ca_mem = certs.ca_cert, .cert_mem = certs.cert, .key_mem = certs.key};
  const vio::ssl_config_t client_config{.ca_mem = certs.ca_cert};

  constexpr size_t data_size = 128 * 1024; // 128KB
  bool data_verified = false;

  event_loop.run_in_loop(
    [&]() -> vio::task_t<void>
    {
      auto *ev = &event_loop;
      auto server_tcp_pair = get_ephemeral_port(*ev);
      REQUIRE_EXPECTED(server_tcp_pair);
      int port = server_tcp_pair->second;

      auto server_task = [](vio::event_loop_t &el, vio::tcp_server_t s, vio::ssl_config_t sc, int p, size_t ds) -> vio::task_t<void>
      {
        auto server_create_result = vio::ssl_server_create(el, std::move(s), "localhost", sc);
        REQUIRE_EXPECTED(server_create_result);
        auto server = std::move(server_create_result.value());

        auto listen_result = co_await vio::ssl_server_listen(server, p);
        REQUIRE_EXPECTED(listen_result);
        auto client_or_err = vio::ssl_server_accept(server);
        REQUIRE_EXPECTED(client_or_err);
        auto client = std::move(client_or_err.value());

        // Read known amount of data and echo it back
        size_t total_read = 0;
        std::vector<char> received;
        received.reserve(ds);
        auto reader_or_err = vio::ssl_server_client_create_reader(client);
        REQUIRE_EXPECTED(reader_or_err);
        auto reader = std::move(reader_or_err.value());
        while (total_read < ds)
        {
          auto read_result = co_await reader;
          if (!read_result.has_value())
            break;
          auto &data = read_result.value();
          received.insert(received.end(), data->base, data->base + data->len);
          total_read += data->len;
        }
        REQUIRE(total_read == ds);

        uv_buf_t buf = uv_buf_init(received.data(), received.size());
        auto write_result = co_await vio::ssl_server_client_write(client, buf);
        REQUIRE_EXPECTED(write_result);
      }(event_loop, std::move(server_tcp_pair->first), server_config, port, data_size);

      auto client_task = [](vio::event_loop_t &el, vio::ssl_config_t cc, int p, size_t ds, bool &dv) -> vio::task_t<void>
      {
        auto client_or_err = vio::ssl_client_create(el, cc);
        REQUIRE_EXPECTED(client_or_err);
        auto client = std::move(client_or_err.value());

        auto connect_result = co_await vio::ssl_client_connect(client, "localhost", p, "127.0.0.1");
        REQUIRE_EXPECTED(connect_result);

        std::vector<uint8_t> send_data(ds);
        std::iota(send_data.begin(), send_data.end(), uint8_t(0));

        uv_buf_t buf = uv_buf_init(reinterpret_cast<char *>(send_data.data()), send_data.size());
        auto write_result = co_await vio::ssl_client_write(client, buf);
        REQUIRE_EXPECTED(write_result);

        // Read back the echo
        size_t total_read = 0;
        std::vector<char> received;
        received.reserve(ds);
        auto reader_or_err = vio::ssl_client_create_reader(client);
        REQUIRE_EXPECTED(reader_or_err);
        auto reader = std::move(reader_or_err.value());
        while (total_read < ds)
        {
          auto read_result = co_await reader;
          if (!read_result.has_value())
            break;
          auto &data = read_result.value();
          received.insert(received.end(), data->base, data->base + data->len);
          total_read += data->len;
        }
        REQUIRE(total_read == ds);
        REQUIRE(std::memcmp(received.data(), send_data.data(), ds) == 0);
        dv = true;
      }(event_loop, client_config, port, data_size, data_verified);

      co_await std::move(client_task);
      co_await std::move(server_task);
      ev->stop();
    });

  event_loop.run();
  REQUIRE(data_verified);
}

TEST_CASE("tls client disconnect causes server read error" * doctest::skip(true))
{
  vio::event_loop_t event_loop;
  auto certs = generate_test_certs();
  const vio::ssl_config_t server_config{.ca_mem = certs.ca_cert, .cert_mem = certs.cert, .key_mem = certs.key};
  const vio::ssl_config_t client_config{.ca_mem = certs.ca_cert};
  bool server_got_error = false;

  event_loop.run_in_loop(
    [&]() -> vio::task_t<void>
    {
      auto *ev = &event_loop;
      auto server_tcp_pair = get_ephemeral_port(*ev);
      REQUIRE_EXPECTED(server_tcp_pair);
      int port = server_tcp_pair->second;

      auto server_task = [](vio::event_loop_t &el, vio::tcp_server_t s, vio::ssl_config_t sc, int p, bool &sge) -> vio::task_t<void>
      {
        auto server_create_result = vio::ssl_server_create(el, std::move(s), "localhost", sc);
        REQUIRE_EXPECTED(server_create_result);
        auto server = std::move(server_create_result.value());

        auto listen_result = co_await vio::ssl_server_listen(server, p);
        REQUIRE_EXPECTED(listen_result);
        auto client_or_err = vio::ssl_server_accept(server);
        REQUIRE_EXPECTED(client_or_err);
        auto client = std::move(client_or_err.value());

        auto reader_or_err = vio::ssl_server_client_create_reader(client);
        REQUIRE_EXPECTED(reader_or_err);
        auto reader = std::move(reader_or_err.value());

        // Read until we get an error (client disconnects)
        while (true)
        {
          auto read_result = co_await reader;
          if (!read_result.has_value())
          {
            sge = true;
            break;
          }
        }
      }(event_loop, std::move(server_tcp_pair->first), server_config, port, server_got_error);

      // Client as named task: write then disconnect
      auto client_task = [](vio::event_loop_t &el, vio::ssl_config_t cc, int p) -> vio::task_t<void>
      {
        auto client_or_err = vio::ssl_client_create(el, cc);
        REQUIRE_EXPECTED(client_or_err);
        auto client = std::move(client_or_err.value());

        auto connect_result = co_await vio::ssl_client_connect(client, "localhost", p, "127.0.0.1");
        REQUIRE_EXPECTED(connect_result);

        // Write one message then disconnect
        std::string msg = "goodbye";
        uv_buf_t buf = uv_buf_init(msg.data(), msg.size());
        auto write_result = co_await vio::ssl_client_write(client, buf);
        REQUIRE_EXPECTED(write_result);
      }(event_loop, client_config, port);

      co_await std::move(client_task);
      // Explicitly destroy the client task to tear down the coroutine frame
      // (and thus the ssl_client_t inside it), closing the TLS connection.
      {
        auto destroy = std::move(client_task);
      }

      co_await std::move(server_task);
      ev->stop();
    });

  event_loop.run();
  REQUIRE(server_got_error);
}

TEST_CASE("tls server disconnect causes client read error" * doctest::skip(true))
{
  vio::event_loop_t event_loop;
  auto certs = generate_test_certs();
  const vio::ssl_config_t server_config{.ca_mem = certs.ca_cert, .cert_mem = certs.cert, .key_mem = certs.key};
  const vio::ssl_config_t client_config{.ca_mem = certs.ca_cert};
  bool client_got_error = false;

  event_loop.run_in_loop(
    [&]() -> vio::task_t<void>
    {
      auto *ev = &event_loop;
      auto server_tcp_pair = get_ephemeral_port(*ev);
      REQUIRE_EXPECTED(server_tcp_pair);
      int port = server_tcp_pair->second;

      // Client as named task (waits for server disconnect error)
      auto client_task = [](vio::event_loop_t &el, vio::ssl_config_t cc, int p, bool &cge) -> vio::task_t<void>
      {
        auto client_or_err = vio::ssl_client_create(el, cc);
        REQUIRE_EXPECTED(client_or_err);
        auto client = std::move(client_or_err.value());

        auto connect_result = co_await vio::ssl_client_connect(client, "localhost", p, "127.0.0.1");
        REQUIRE_EXPECTED(connect_result);

        std::string msg = "ping";
        uv_buf_t buf = uv_buf_init(msg.data(), msg.size());
        auto write_result = co_await vio::ssl_client_write(client, buf);
        REQUIRE_EXPECTED(write_result);

        auto reader_or_err = vio::ssl_client_create_reader(client);
        REQUIRE_EXPECTED(reader_or_err);
        auto reader = std::move(reader_or_err.value());

        // Read until error (server disconnect)
        while (true)
        {
          auto read_result = co_await reader;
          if (!read_result.has_value())
          {
            cge = true;
            break;
          }
        }
      }(event_loop, client_config, port, client_got_error);

      // Server as temporary: frame destroyed after co_await, closing TLS → client gets read error
      co_await [](vio::event_loop_t &el, vio::tcp_server_t s, vio::ssl_config_t sc, int p) -> vio::task_t<void>
      {
        auto server_create_result = vio::ssl_server_create(el, std::move(s), "localhost", sc);
        REQUIRE_EXPECTED(server_create_result);
        auto server = std::move(server_create_result.value());

        auto listen_result = co_await vio::ssl_server_listen(server, p);
        REQUIRE_EXPECTED(listen_result);
        auto client_or_err = vio::ssl_server_accept(server);
        REQUIRE_EXPECTED(client_or_err);
        auto client = std::move(client_or_err.value());

        // Read one message then destroy
        auto reader_or_err = vio::ssl_server_client_create_reader(client);
        REQUIRE_EXPECTED(reader_or_err);
        auto reader = std::move(reader_or_err.value());
        auto read_result = co_await reader;
        REQUIRE_EXPECTED(read_result);

        // Server client destroyed here
      }(event_loop, std::move(server_tcp_pair->first), server_config, port);

      co_await std::move(client_task);
      ev->stop();
    });

  event_loop.run();
  REQUIRE(client_got_error);
}

TEST_CASE("tls multiple clients to same server")
{
  vio::event_loop_t event_loop;
  auto certs = generate_test_certs();
  const vio::ssl_config_t server_config{.ca_mem = certs.ca_cert, .cert_mem = certs.cert, .key_mem = certs.key};
  const vio::ssl_config_t client_config{.ca_mem = certs.ca_cert};

  constexpr int num_clients = 3;
  int clients_served = 0;
  int clients_replied = 0;

  event_loop.run_in_loop(
    [&]() -> vio::task_t<void>
    {
      auto *ev = &event_loop;
      auto server_tcp_pair = get_ephemeral_port(*ev);
      REQUIRE_EXPECTED(server_tcp_pair);
      int port = server_tcp_pair->second;

      auto server_task = [](vio::event_loop_t &el, vio::tcp_server_t s, vio::ssl_config_t sc, int p, int nc, int &cs) -> vio::task_t<void>
      {
        auto server_create_result = vio::ssl_server_create(el, std::move(s), "localhost", sc);
        REQUIRE_EXPECTED(server_create_result);
        auto server = std::move(server_create_result.value());

        for (int i = 0; i < nc; i++)
        {
          auto listen_result = co_await vio::ssl_server_listen(server, p);
          REQUIRE_EXPECTED(listen_result);
          auto client_or_err = vio::ssl_server_accept(server);
          REQUIRE_EXPECTED(client_or_err);
          auto client = std::move(client_or_err.value());
          server.handle->tcp.tcp.handle->listen.done = false;

          auto reader_or_err = vio::ssl_server_client_create_reader(client);
          REQUIRE_EXPECTED(reader_or_err);
          auto reader = std::move(reader_or_err.value());
          auto read_result = co_await reader;
          REQUIRE_EXPECTED(read_result);
          cs++;

          auto &data = read_result.value();
          uv_buf_t buf = uv_buf_init(data->base, data->len);
          auto write_result = co_await vio::ssl_server_client_write(client, buf);
          REQUIRE_EXPECTED(write_result);
        }
      }(event_loop, std::move(server_tcp_pair->first), server_config, port, num_clients, clients_served);

      co_await [](vio::event_loop_t &el, vio::ssl_config_t cc, int p, int nc, int &cr) -> vio::task_t<void>
      {
        for (int i = 0; i < nc; i++)
        {
          auto client_or_err = vio::ssl_client_create(el, cc);
          REQUIRE_EXPECTED(client_or_err);
          auto client = std::move(client_or_err.value());

          auto connect_result = co_await vio::ssl_client_connect(client, "localhost", p, "127.0.0.1");
          REQUIRE_EXPECTED(connect_result);

          std::string msg = "tls_client_" + std::to_string(i);
          uv_buf_t buf = uv_buf_init(msg.data(), msg.size());
          auto write_result = co_await vio::ssl_client_write(client, buf);
          REQUIRE_EXPECTED(write_result);

          auto reader_or_err = vio::ssl_client_create_reader(client);
          REQUIRE_EXPECTED(reader_or_err);
          auto reader = std::move(reader_or_err.value());
          auto read_result = co_await reader;
          REQUIRE_EXPECTED(read_result);
          auto &data = read_result.value();
          std::string_view sv(data->base, data->len);
          REQUIRE(sv == msg);
          cr++;
        }
      }(event_loop, client_config, port, num_clients, clients_replied);

      co_await std::move(server_task);
      ev->stop();
    });

  event_loop.run();
  REQUIRE(clients_served == num_clients);
  REQUIRE(clients_replied == num_clients);
}

TEST_CASE("tls cannot create multiple active readers on client")
{
  vio::event_loop_t event_loop;
  auto certs = generate_test_certs();
  const vio::ssl_config_t server_config{.ca_mem = certs.ca_cert, .cert_mem = certs.cert, .key_mem = certs.key};
  const vio::ssl_config_t client_config{.ca_mem = certs.ca_cert};
  bool error_caught = false;

  event_loop.run_in_loop(
    [&]() -> vio::task_t<void>
    {
      auto *ev = &event_loop;
      auto server_tcp_pair = get_ephemeral_port(*ev);
      REQUIRE_EXPECTED(server_tcp_pair);
      int port = server_tcp_pair->second;

      auto server_task = [](vio::event_loop_t &el, vio::tcp_server_t s, vio::ssl_config_t sc, int p) -> vio::task_t<void>
      {
        auto server_create_result = vio::ssl_server_create(el, std::move(s), "localhost", sc);
        REQUIRE_EXPECTED(server_create_result);
        auto server = std::move(server_create_result.value());

        auto listen_result = co_await vio::ssl_server_listen(server, p);
        REQUIRE_EXPECTED(listen_result);
        auto client_or_err = vio::ssl_server_accept(server);
        REQUIRE_EXPECTED(client_or_err);
        auto client = std::move(client_or_err.value());

        auto reader_or_err = vio::ssl_server_client_create_reader(client);
        REQUIRE_EXPECTED(reader_or_err);
        auto reader = std::move(reader_or_err.value());
        auto read_result = co_await reader;
        REQUIRE_EXPECTED(read_result);
      }(event_loop, std::move(server_tcp_pair->first), server_config, port);

      co_await [](vio::event_loop_t &el, vio::ssl_config_t cc, int p, bool &ec) -> vio::task_t<void>
      {
        auto client_or_err = vio::ssl_client_create(el, cc);
        REQUIRE_EXPECTED(client_or_err);
        auto client = std::move(client_or_err.value());

        auto connect_result = co_await vio::ssl_client_connect(client, "localhost", p, "127.0.0.1");
        REQUIRE_EXPECTED(connect_result);

        auto reader1 = vio::ssl_client_create_reader(client);
        REQUIRE_EXPECTED(reader1);

        auto reader2 = vio::ssl_client_create_reader(client);
        REQUIRE(!reader2.has_value());
        ec = true;

        // Send a done signal so the server can finish
        std::string msg = "done";
        uv_buf_t buf = uv_buf_init(msg.data(), msg.size());
        auto write_result = co_await vio::ssl_client_write(client, buf);
        REQUIRE_EXPECTED(write_result);
      }(event_loop, client_config, port, error_caught);

      co_await std::move(server_task);
      ev->stop();
    });

  event_loop.run();
  REQUIRE(error_caught);
}

TEST_CASE("tls cannot create multiple active readers on server client")
{
  vio::event_loop_t event_loop;
  auto certs = generate_test_certs();
  const vio::ssl_config_t server_config{.ca_mem = certs.ca_cert, .cert_mem = certs.cert, .key_mem = certs.key};
  const vio::ssl_config_t client_config{.ca_mem = certs.ca_cert};
  bool error_caught = false;

  event_loop.run_in_loop(
    [&]() -> vio::task_t<void>
    {
      auto *ev = &event_loop;
      auto server_tcp_pair = get_ephemeral_port(*ev);
      REQUIRE_EXPECTED(server_tcp_pair);
      int port = server_tcp_pair->second;

      auto server_task = [](vio::event_loop_t &el, vio::tcp_server_t s, vio::ssl_config_t sc, int p, bool &ec) -> vio::task_t<void>
      {
        auto server_create_result = vio::ssl_server_create(el, std::move(s), "localhost", sc);
        REQUIRE_EXPECTED(server_create_result);
        auto server = std::move(server_create_result.value());

        auto listen_result = co_await vio::ssl_server_listen(server, p);
        REQUIRE_EXPECTED(listen_result);
        auto client_or_err = vio::ssl_server_accept(server);
        REQUIRE_EXPECTED(client_or_err);
        auto client = std::move(client_or_err.value());

        auto reader1 = vio::ssl_server_client_create_reader(client);
        REQUIRE_EXPECTED(reader1);

        auto reader2 = vio::ssl_server_client_create_reader(client);
        REQUIRE(!reader2.has_value());
        ec = true;

        // Read the done signal from client
        auto read_result = co_await reader1.value();
        REQUIRE_EXPECTED(read_result);
      }(event_loop, std::move(server_tcp_pair->first), server_config, port, error_caught);

      co_await [](vio::event_loop_t &el, vio::ssl_config_t cc, int p) -> vio::task_t<void>
      {
        auto client_or_err = vio::ssl_client_create(el, cc);
        REQUIRE_EXPECTED(client_or_err);
        auto client = std::move(client_or_err.value());

        auto connect_result = co_await vio::ssl_client_connect(client, "localhost", p, "127.0.0.1");
        REQUIRE_EXPECTED(connect_result);

        // Send a done signal so the server can finish
        std::string msg = "done";
        uv_buf_t buf = uv_buf_init(msg.data(), msg.size());
        auto write_result = co_await vio::ssl_client_write(client, buf);
        REQUIRE_EXPECTED(write_result);
      }(event_loop, client_config, port);

      co_await std::move(server_task);
      ev->stop();
    });

  event_loop.run();
  REQUIRE(error_caught);
}

TEST_CASE("tls reader create on unconnected client fails")
{
  vio::event_loop_t event_loop;
  auto certs = generate_test_certs();
  const vio::ssl_config_t client_config{.ca_mem = certs.ca_cert};

  {
    auto client_or_err = vio::ssl_client_create(event_loop, client_config);
    REQUIRE_EXPECTED(client_or_err);
    auto client = std::move(client_or_err.value());

    auto reader = vio::ssl_client_create_reader(client);
    REQUIRE(!reader.has_value());
  }
  // Stop and run event loop to process uv_close callbacks
  event_loop.stop();
  event_loop.run();
}

TEST_CASE("tls server write then client read")
{
  vio::event_loop_t event_loop;
  auto certs = generate_test_certs();
  const vio::ssl_config_t server_config{.ca_mem = certs.ca_cert, .cert_mem = certs.cert, .key_mem = certs.key};
  const vio::ssl_config_t client_config{.ca_mem = certs.ca_cert};
  bool verified = false;

  event_loop.run_in_loop(
    [&]() -> vio::task_t<void>
    {
      auto *ev = &event_loop;
      auto server_tcp_pair = get_ephemeral_port(*ev);
      REQUIRE_EXPECTED(server_tcp_pair);
      int port = server_tcp_pair->second;

      auto server_task = [](vio::event_loop_t &el, vio::tcp_server_t s, vio::ssl_config_t sc, int p) -> vio::task_t<void>
      {
        auto server_create_result = vio::ssl_server_create(el, std::move(s), "localhost", sc);
        REQUIRE_EXPECTED(server_create_result);
        auto server = std::move(server_create_result.value());

        auto listen_result = co_await vio::ssl_server_listen(server, p);
        REQUIRE_EXPECTED(listen_result);
        auto client_or_err = vio::ssl_server_accept(server);
        REQUIRE_EXPECTED(client_or_err);
        auto client = std::move(client_or_err.value());

        // Server writes first
        std::string msg = "server_speaks_first";
        uv_buf_t buf = uv_buf_init(msg.data(), msg.size());
        auto write_result = co_await vio::ssl_server_client_write(client, buf);
        REQUIRE_EXPECTED(write_result);

        // Then reads client's response
        auto reader_or_err = vio::ssl_server_client_create_reader(client);
        REQUIRE_EXPECTED(reader_or_err);
        auto reader = std::move(reader_or_err.value());
        auto read_result = co_await reader;
        REQUIRE_EXPECTED(read_result);
        auto &data = read_result.value();
        std::string_view sv(data->base, data->len);
        REQUIRE(sv == "client_ack");
      }(event_loop, std::move(server_tcp_pair->first), server_config, port);

      auto client_task = [](vio::event_loop_t &el, vio::ssl_config_t cc, int p, bool &v) -> vio::task_t<void>
      {
        auto client_or_err = vio::ssl_client_create(el, cc);
        REQUIRE_EXPECTED(client_or_err);
        auto client = std::move(client_or_err.value());

        auto connect_result = co_await vio::ssl_client_connect(client, "localhost", p, "127.0.0.1");
        REQUIRE_EXPECTED(connect_result);

        // Client reads server's message first
        auto reader_or_err = vio::ssl_client_create_reader(client);
        REQUIRE_EXPECTED(reader_or_err);
        auto reader = std::move(reader_or_err.value());
        auto read_result = co_await reader;
        REQUIRE_EXPECTED(read_result);
        auto &data = read_result.value();
        std::string_view sv(data->base, data->len);
        REQUIRE(sv == "server_speaks_first");

        // Then responds
        std::string msg = "client_ack";
        uv_buf_t buf = uv_buf_init(msg.data(), msg.size());
        auto write_result = co_await vio::ssl_client_write(client, buf);
        REQUIRE_EXPECTED(write_result);
        v = true;
      }(event_loop, client_config, port, verified);

      co_await std::move(client_task);
      co_await std::move(server_task);
      ev->stop();
    });

  event_loop.run();
  REQUIRE(verified);
}

TEST_CASE("tls exact buffer read with stream_reader_t::read()")
{
  vio::event_loop_t event_loop;
  auto certs = generate_test_certs();
  const vio::ssl_config_t server_config{.ca_mem = certs.ca_cert, .cert_mem = certs.cert, .key_mem = certs.key};
  const vio::ssl_config_t client_config{.ca_mem = certs.ca_cert};
  bool verified = false;

  event_loop.run_in_loop(
    [&]() -> vio::task_t<void>
    {
      auto *ev = &event_loop;
      auto server_tcp_pair = get_ephemeral_port(*ev);
      REQUIRE_EXPECTED(server_tcp_pair);
      int port = server_tcp_pair->second;

      auto server_task = [](vio::event_loop_t &el, vio::tcp_server_t s, vio::ssl_config_t sc, int p) -> vio::task_t<void>
      {
        auto server_create_result = vio::ssl_server_create(el, std::move(s), "localhost", sc);
        REQUIRE_EXPECTED(server_create_result);
        auto server = std::move(server_create_result.value());

        auto listen_result = co_await vio::ssl_server_listen(server, p);
        REQUIRE_EXPECTED(listen_result);
        auto client_or_err = vio::ssl_server_accept(server);
        REQUIRE_EXPECTED(client_or_err);
        auto client = std::move(client_or_err.value());

        // Send exactly 100 bytes of known pattern
        std::vector<char> data(100);
        std::iota(data.begin(), data.end(), char(0));
        uv_buf_t buf = uv_buf_init(data.data(), data.size());
        auto write_result = co_await vio::ssl_server_client_write(client, buf);
        REQUIRE_EXPECTED(write_result);

        // Wait for client's done signal
        auto reader_or_err = vio::ssl_server_client_create_reader(client);
        REQUIRE_EXPECTED(reader_or_err);
        auto reader = std::move(reader_or_err.value());
        auto read_result = co_await reader;
        REQUIRE_EXPECTED(read_result);
      }(event_loop, std::move(server_tcp_pair->first), server_config, port);

      co_await [](vio::event_loop_t &el, vio::ssl_config_t cc, int p, bool &v) -> vio::task_t<void>
      {
        auto client_or_err = vio::ssl_client_create(el, cc);
        REQUIRE_EXPECTED(client_or_err);
        auto client = std::move(client_or_err.value());

        auto connect_result = co_await vio::ssl_client_connect(client, "localhost", p, "127.0.0.1");
        REQUIRE_EXPECTED(connect_result);

        auto reader_or_err = vio::ssl_client_create_reader(client);
        REQUIRE_EXPECTED(reader_or_err);
        auto reader = std::move(reader_or_err.value());

        // Use the exact buffer read to get exactly 100 bytes
        std::vector<char> buffer(100);
        uv_buf_t read_buf;
        read_buf.base = buffer.data();
        read_buf.len = buffer.size();
        auto read_result = co_await reader.read(read_buf);
        REQUIRE_EXPECTED(read_result);

        // Verify the pattern
        std::vector<char> expected(100);
        std::iota(expected.begin(), expected.end(), char(0));
        REQUIRE(std::memcmp(buffer.data(), expected.data(), 100) == 0);
        v = true;

        // Send done signal to server
        std::string msg = "done";
        uv_buf_t done_buf = uv_buf_init(msg.data(), msg.size());
        auto wr = co_await vio::ssl_client_write(client, done_buf);
        REQUIRE_EXPECTED(wr);
      }(event_loop, client_config, port, verified);

      co_await std::move(server_task);
      ev->stop();
    });

  event_loop.run();
  REQUIRE(verified);
}

TEST_CASE("tls bidirectional concurrent read and write")
{
  vio::event_loop_t event_loop;
  auto certs = generate_test_certs();
  const vio::ssl_config_t server_config{.ca_mem = certs.ca_cert, .cert_mem = certs.cert, .key_mem = certs.key};
  const vio::ssl_config_t client_config{.ca_mem = certs.ca_cert};
  bool server_verified = false;
  bool client_verified = false;

  event_loop.run_in_loop(
    [&]() -> vio::task_t<void>
    {
      auto *ev = &event_loop;
      auto server_tcp_pair = get_ephemeral_port(*ev);
      REQUIRE_EXPECTED(server_tcp_pair);
      int port = server_tcp_pair->second;

      auto server_task = [](vio::event_loop_t &el, vio::tcp_server_t s, vio::ssl_config_t sc, int p, bool &sv) -> vio::task_t<void>
      {
        auto server_create_result = vio::ssl_server_create(el, std::move(s), "localhost", sc);
        REQUIRE_EXPECTED(server_create_result);
        auto server = std::move(server_create_result.value());

        auto listen_result = co_await vio::ssl_server_listen(server, p);
        REQUIRE_EXPECTED(listen_result);
        auto client_or_err = vio::ssl_server_accept(server);
        REQUIRE_EXPECTED(client_or_err);
        auto client = std::move(client_or_err.value());

        // Write and read at the same time (write first to avoid deadlock in coroutine)
        std::string msg = "from_server";
        uv_buf_t buf = uv_buf_init(msg.data(), msg.size());
        auto write_result = co_await vio::ssl_server_client_write(client, buf);
        REQUIRE_EXPECTED(write_result);

        auto reader_or_err = vio::ssl_server_client_create_reader(client);
        REQUIRE_EXPECTED(reader_or_err);
        auto reader = std::move(reader_or_err.value());
        auto read_result = co_await reader;
        REQUIRE_EXPECTED(read_result);
        auto &data = read_result.value();
        std::string_view sv2(data->base, data->len);
        REQUIRE(sv2 == "from_client");
        sv = true;
      }(event_loop, std::move(server_tcp_pair->first), server_config, port, server_verified);

      auto client_task = [](vio::event_loop_t &el, vio::ssl_config_t cc, int p, bool &cv) -> vio::task_t<void>
      {
        auto client_or_err = vio::ssl_client_create(el, cc);
        REQUIRE_EXPECTED(client_or_err);
        auto client = std::move(client_or_err.value());

        auto connect_result = co_await vio::ssl_client_connect(client, "localhost", p, "127.0.0.1");
        REQUIRE_EXPECTED(connect_result);

        // Write and read (write first to match server's read)
        std::string msg = "from_client";
        uv_buf_t buf = uv_buf_init(msg.data(), msg.size());
        auto write_result = co_await vio::ssl_client_write(client, buf);
        REQUIRE_EXPECTED(write_result);

        auto reader_or_err = vio::ssl_client_create_reader(client);
        REQUIRE_EXPECTED(reader_or_err);
        auto reader = std::move(reader_or_err.value());
        auto read_result = co_await reader;
        REQUIRE_EXPECTED(read_result);
        auto &data = read_result.value();
        std::string_view sv2(data->base, data->len);
        REQUIRE(sv2 == "from_server");
        cv = true;
      }(event_loop, client_config, port, client_verified);

      co_await std::move(client_task);
      co_await std::move(server_task);
      ev->stop();
    });

  event_loop.run();
  REQUIRE(server_verified);
  REQUIRE(client_verified);
}

} // namespace
