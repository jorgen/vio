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

namespace
{

std::pair<std::vector<uint8_t>, std::vector<uint8_t>> generate_test_cert_and_key()
{
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

  X509_NAME *name = X509_get_subject_name(cert);
  X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *)"NO", -1, -1, 0);
  X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char *)"vio unit test", -1, -1, 0);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"localhost", -1, -1, 0);
  X509_set_issuer_name(cert, name);

  X509_sign(cert, pkey, EVP_sha256());

  BIO *cert_bio = BIO_new(BIO_s_mem());
  BIO *key_bio = BIO_new(BIO_s_mem());
  PEM_write_bio_X509(cert_bio, cert);
  PEM_write_bio_PrivateKey(key_bio, pkey, nullptr, nullptr, 0, nullptr, nullptr);

  std::vector<uint8_t> cert_data(BIO_pending(cert_bio));
  std::vector<uint8_t> key_data(BIO_pending(key_bio));
  BIO_read(cert_bio, cert_data.data(), cert_data.size());
  BIO_read(key_bio, key_data.data(), key_data.size());

  BIO_free(cert_bio);
  BIO_free(key_bio);
  X509_free(cert);
  EVP_PKEY_free(pkey);

  return {cert_data, key_data};
}

vio::task_t<void> test_tls_server(vio::event_loop_t &event_loop, vio::tls_server &&s, int port, bool &server_got_data, bool &server_wrote_msg)
{
  auto [cert_data, key_data] = generate_test_cert_and_key();
  ssl_config config;
  config.cert_mem = cert_data;
  config.key_mem = key_data;

  auto server = std::move(s);
  co_return;
};

std::expected<std::pair<vio::tcp_t, int>, vio::error_t> get_ephemeral_port(vio::event_loop_t &event_loop)
{
  auto addr_or_err = vio::ip4_addr("127.0.0.1", 0);
  PROPAGATE_ERROR(addr_or_err);
  auto tmp_tcp = vio::tcp_create(event_loop);
  PROPAGATE_ERROR(tmp_tcp);
  auto bind_res = vio::tcp_bind(tmp_tcp.value(), reinterpret_cast<const sockaddr *>(&addr_or_err.value()));
  PROPAGATE_ERROR(bind_res);

  sockaddr_storage sa_storage{};
  int name_len = sizeof(sa_storage);
  uv_tcp_getsockname(tmp_tcp.value().get_tcp(), reinterpret_cast<sockaddr *>(&sa_storage), &name_len);
  const auto *sa_in = reinterpret_cast<sockaddr_in *>(&sa_storage);
  return std::make_pair(std::move(tmp_tcp.value()), static_cast<int>(ntohs(sa_in->sin_port)));
}

TEST_CASE("test basic tcp")
{
  vio::event_loop_t event_loop;

  bool server_got_data = false;
  bool server_wrote_msg = false;
  bool client_got_server_reply = false;

  server_got_data = false;
  server_wrote_msg = false;
  client_got_server_reply = false;

  event_loop.run_in_loop(
    [&event_loop, &server_got_data, &server_wrote_msg, &client_got_server_reply]() -> vio::task_t<void>
    {
      auto ev = &event_loop;
      auto server_tcp_pair = get_ephemeral_port(*ev);
      REQUIRE_EXPECTED(server_tcp_pair);

      auto server = test_tls_server(*ev, std::move(server_tcp_pair->first), server_tcp_pair->second, server_got_data, server_wrote_msg);
      co_await test_tls_client(*ev, server_tcp_pair->second, client_got_server_reply);
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
