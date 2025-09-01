#include <doctest/doctest.h>
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

  BIO_read(ca_cert_bio, ca_cert_data.data(), ca_cert_data.size());
  BIO_read(ca_key_bio, ca_key_data.data(), ca_key_data.size());
  BIO_read(cert_bio, cert_data.data(), cert_data.size());
  BIO_read(key_bio, key_data.data(), key_data.size());

  BIO_free(ca_cert_bio);
  BIO_free(ca_key_bio);
  BIO_free(cert_bio);
  BIO_free(key_bio);
  X509_free(ca_cert);
  EVP_PKEY_free(ca_pkey);
  X509_free(cert);
  EVP_PKEY_free(pkey);

  return {ca_cert_data, ca_key_data, cert_data, key_data};
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
  std::string_view sv(read_data->base, read_data->len);
  if (sv.find("Hello from client") != std::string_view::npos)
  {
    server_got_data = true;
  }
  std::string reply = "Hello from server";
  uv_buf_t buf = uv_buf_init(reinterpret_cast<char *>(reply.data()), reply.size());
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

  std::string client_message = "Hello TCP server";
  uv_buf_t buf = uv_buf_init(reinterpret_cast<char *>(client_message.data()), client_message.size());
  auto write_result = co_await vio::ssl_client_write(client_raw, buf);
  REQUIRE_EXPECTED(write_result);
  auto reader = vio::ssl_client_create_reader(client_raw);
  REQUIRE_EXPECTED(reader);
  auto read_result = co_await reader.value();
  REQUIRE_EXPECTED(read_result);
  auto &read_data = read_result.value();
  std::string_view sv(read_data->base, read_data->len);
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
  vio::ssl_config_t config;
  config.cert_mem = certs.cert;
  config.key_mem = certs.key;
  config.ca_mem = certs.ca_cert;

  event_loop.run_in_loop(
    [&event_loop, &server_got_data, &server_wrote_msg, &client_got_server_reply, config]() -> vio::task_t<void>
    {
      auto ev = &event_loop;
      auto server_tcp_pair = get_ephemeral_port(*ev);
      REQUIRE_EXPECTED(server_tcp_pair);

      auto server = test_tls_server(*ev, std::move(server_tcp_pair->first), server_tcp_pair->second, config, server_got_data, server_wrote_msg);
      co_await test_tls_client(*ev, server_tcp_pair->second, config, client_got_server_reply);
      co_await std::move(server);

      ev->stop();
    });

  event_loop.run();

  REQUIRE(server_got_data);
  REQUIRE(server_wrote_msg);
  REQUIRE(client_got_server_reply);
}
} // namespace
// Created by Jørgen Lind on 30/07/2025.
//
