#include <doctest/doctest.h>

#include <numeric>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <string>
#include <string_view>
#include <vector>

#include <vio/error.h>
#include <vio/event_loop.h>
#include <vio/operation/tls_client.h>
#include <vio/operation/tls_server.h>
#include <vio/task.h>

#include "require_expected.h"
#include "vio/operation/tcp_server.h"

namespace
{
struct test_certificates_t
{
  std::vector<uint8_t> ca_cert;
  std::vector<uint8_t> cert;
  std::vector<uint8_t> key;
};

test_certificates_t generate_test_certs()
{
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
  X509_NAME_add_entry_by_txt(ca_name, "CN", MBSTRING_ASC, (unsigned char *)"vio CA", -1, -1, 0);
  X509_set_issuer_name(ca_cert, ca_name);
  X509_sign(ca_cert, ca_pkey, EVP_sha256());

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
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"localhost", -1, -1, 0);
  X509_set_issuer_name(cert, ca_name);
  X509_sign(cert, ca_pkey, EVP_sha256());

  auto to_pem_cert = [](X509 *c)
  {
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio, c);
    std::vector<uint8_t> data(BIO_pending(bio));
    BIO_read(bio, data.data(), static_cast<int>(data.size()));
    BIO_free(bio);
    return data;
  };
  auto to_pem_key = [](EVP_PKEY *k)
  {
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio, k, nullptr, nullptr, 0, nullptr, nullptr);
    std::vector<uint8_t> data(BIO_pending(bio));
    BIO_read(bio, data.data(), static_cast<int>(data.size()));
    BIO_free(bio);
    return data;
  };

  test_certificates_t out{.ca_cert = to_pem_cert(ca_cert), .cert = to_pem_cert(cert), .key = to_pem_key(pkey)};
  X509_free(ca_cert);
  EVP_PKEY_free(ca_pkey);
  X509_free(cert);
  EVP_PKEY_free(pkey);
  return out;
}

std::expected<std::pair<vio::tcp_server_t, int>, vio::error_t> get_ephemeral_port(vio::event_loop_t &event_loop)
{
  auto addr = vio::ip4_addr("127.0.0.1", 0);
  if (!addr.has_value())
    return std::unexpected(addr.error());
  auto tcp_server = vio::tcp_create_server(event_loop);
  if (!tcp_server.has_value())
    return std::unexpected(tcp_server.error());
  auto bind_res = vio::tcp_bind(tcp_server.value(), reinterpret_cast<const sockaddr *>(&addr.value()));
  if (!bind_res.has_value())
    return std::unexpected(bind_res.error());
  auto sockname_result = vio::sockname(tcp_server->tcp);
  if (!sockname_result.has_value())
    return std::unexpected(sockname_result.error());
  sockaddr_storage sa_storage = sockname_result.value();
  const auto *sa_in = reinterpret_cast<sockaddr_in *>(&sa_storage);
  return std::make_pair(std::move(tcp_server.value()), static_cast<int>(ntohs(sa_in->sin_port)));
}

TEST_SUITE("TLS ALPN + duplex")
{
TEST_CASE("alpn negotiates h2 and both sides observe it")
{
  vio::event_loop_t event_loop;
  auto certs = generate_test_certs();
  vio::ssl_config_t server_config{.ca_mem = certs.ca_cert, .cert_mem = certs.cert, .key_mem = certs.key};
  server_config.alpn_protocols = {"h2", "http/1.1"};
  vio::ssl_config_t client_config{.ca_mem = certs.ca_cert};
  client_config.alpn_protocols = {"h2", "http/1.1"};

  std::string server_alpn;
  std::string client_alpn;

  event_loop.run_in_loop(
    [&]
    {
      return [](vio::event_loop_t &event_loop, vio::ssl_config_t sc, vio::ssl_config_t cc, std::string &sa, std::string &ca) -> vio::task_t<void>
      {
        auto *ev = &event_loop;
        auto server_tcp_pair = get_ephemeral_port(*ev);
        REQUIRE_EXPECTED(server_tcp_pair);
        int port = server_tcp_pair->second;

        auto server_task = [](vio::event_loop_t &el, vio::tcp_server_t s, vio::ssl_config_t sc, int p, std::string &sa) -> vio::task_t<void>
        {
          auto server = vio::ssl_server_create(el, std::move(s), "localhost", sc);
          REQUIRE_EXPECTED(server);
          auto srv = std::move(server.value());
          auto listen_result = co_await vio::ssl_server_listen(srv, p);
          REQUIRE_EXPECTED(listen_result);
          auto client_or_err = vio::ssl_server_accept(srv);
          REQUIRE_EXPECTED(client_or_err);
          auto client = std::move(client_or_err.value());
          auto hs = co_await vio::ssl_server_client_handshake(client);
          REQUIRE_EXPECTED(hs);
          if (auto a = vio::ssl_server_client_alpn_selected(client))
            sa = *a;
          auto reader = vio::ssl_server_client_create_reader(client);
          REQUIRE_EXPECTED(reader);
          auto rr = co_await reader.value();
          REQUIRE_EXPECTED(rr);
        }(event_loop, std::move(server_tcp_pair->first), sc, port, sa);

        auto client_task = [](vio::event_loop_t &el, vio::ssl_config_t cc, int p, std::string &ca) -> vio::task_t<void>
        {
          auto client = vio::ssl_client_create(el, cc);
          REQUIRE_EXPECTED(client);
          auto c = std::move(client.value());
          auto connect_result = co_await vio::ssl_client_connect(c, "localhost", p, "127.0.0.1");
          REQUIRE_EXPECTED(connect_result);
          if (auto a = vio::ssl_client_alpn_selected(c))
            ca = *a;
          std::string msg = "hi";
          uv_buf_t buf = uv_buf_init(msg.data(), msg.size());
          auto wr = co_await vio::ssl_client_write(c, buf);
          REQUIRE_EXPECTED(wr);
        }(event_loop, cc, port, ca);

        co_await std::move(client_task);
        co_await std::move(server_task);
        ev->stop();
      }(event_loop, server_config, client_config, server_alpn, client_alpn);
    });
  event_loop.run();
  REQUIRE(server_alpn == "h2");
  REQUIRE(client_alpn == "h2");
}

TEST_CASE("alpn with no overlap still connects, no protocol selected")
{
  vio::event_loop_t event_loop;
  auto certs = generate_test_certs();
  vio::ssl_config_t server_config{.ca_mem = certs.ca_cert, .cert_mem = certs.cert, .key_mem = certs.key};
  server_config.alpn_protocols = {"http/1.1"};
  vio::ssl_config_t client_config{.ca_mem = certs.ca_cert};
  client_config.alpn_protocols = {"h2"};

  bool connected = false;
  bool client_has_alpn = true;

  event_loop.run_in_loop(
    [&]
    {
      return [](vio::event_loop_t &event_loop, vio::ssl_config_t sc, vio::ssl_config_t cc, bool &connected, bool &client_has_alpn) -> vio::task_t<void>
      {
        auto *ev = &event_loop;
        auto server_tcp_pair = get_ephemeral_port(*ev);
        REQUIRE_EXPECTED(server_tcp_pair);
        int port = server_tcp_pair->second;

        auto server_task = [](vio::event_loop_t &el, vio::tcp_server_t s, vio::ssl_config_t sc, int p) -> vio::task_t<void>
        {
          auto server = vio::ssl_server_create(el, std::move(s), "localhost", sc);
          REQUIRE_EXPECTED(server);
          auto srv = std::move(server.value());
          auto listen_result = co_await vio::ssl_server_listen(srv, p);
          REQUIRE_EXPECTED(listen_result);
          auto client_or_err = vio::ssl_server_accept(srv);
          REQUIRE_EXPECTED(client_or_err);
          auto client = std::move(client_or_err.value());
          auto hs = co_await vio::ssl_server_client_handshake(client);
          REQUIRE_EXPECTED(hs);
          auto reader = vio::ssl_server_client_create_reader(client);
          REQUIRE_EXPECTED(reader);
          auto rr = co_await reader.value();
          REQUIRE_EXPECTED(rr);
        }(event_loop, std::move(server_tcp_pair->first), sc, port);

        auto client_task = [](vio::event_loop_t &el, vio::ssl_config_t cc, int p, bool &connected, bool &client_has_alpn) -> vio::task_t<void>
        {
          auto client = vio::ssl_client_create(el, cc);
          REQUIRE_EXPECTED(client);
          auto c = std::move(client.value());
          auto connect_result = co_await vio::ssl_client_connect(c, "localhost", p, "127.0.0.1");
          REQUIRE_EXPECTED(connect_result);
          connected = true;
          client_has_alpn = vio::ssl_client_alpn_selected(c).has_value();
          std::string msg = "hi";
          uv_buf_t buf = uv_buf_init(msg.data(), msg.size());
          auto wr = co_await vio::ssl_client_write(c, buf);
          REQUIRE_EXPECTED(wr);
        }(event_loop, cc, port, connected, client_has_alpn);

        co_await std::move(client_task);
        co_await std::move(server_task);
        ev->stop();
      }(event_loop, server_config, client_config, connected, client_has_alpn);
    });
  event_loop.run();
  REQUIRE(connected);
  REQUIRE_FALSE(client_has_alpn);
}

TEST_CASE("two concurrent in-flight writes arrive intact and in order")
{
  vio::event_loop_t event_loop;
  auto certs = generate_test_certs();
  vio::ssl_config_t server_config{.ca_mem = certs.ca_cert, .cert_mem = certs.cert, .key_mem = certs.key};
  vio::ssl_config_t client_config{.ca_mem = certs.ca_cert};
  bool verified = false;

  event_loop.run_in_loop(
    [&]
    {
      return [](vio::event_loop_t &event_loop, vio::ssl_config_t sc, vio::ssl_config_t cc, bool &verified) -> vio::task_t<void>
      {
        auto *ev = &event_loop;
        auto server_tcp_pair = get_ephemeral_port(*ev);
        REQUIRE_EXPECTED(server_tcp_pair);
        int port = server_tcp_pair->second;

        auto server_task = [](vio::event_loop_t &el, vio::tcp_server_t s, vio::ssl_config_t sc, int p, bool &verified) -> vio::task_t<void>
        {
          auto server = vio::ssl_server_create(el, std::move(s), "localhost", sc);
          REQUIRE_EXPECTED(server);
          auto srv = std::move(server.value());
          auto listen_result = co_await vio::ssl_server_listen(srv, p);
          REQUIRE_EXPECTED(listen_result);
          auto client_or_err = vio::ssl_server_accept(srv);
          REQUIRE_EXPECTED(client_or_err);
          auto client = std::move(client_or_err.value());
          auto reader_or_err = vio::ssl_server_client_create_reader(client);
          REQUIRE_EXPECTED(reader_or_err);
          auto reader = std::move(reader_or_err.value());
          std::string received;
          while (received.size() < 6)
          {
            auto rr = co_await reader;
            if (!rr.has_value())
              break;
            received.append(rr.value()->base, rr.value()->len);
          }
          verified = (received == "AAABBB");
        }(event_loop, std::move(server_tcp_pair->first), sc, port, verified);

        auto client_task = [](vio::event_loop_t &el, vio::ssl_config_t cc, int p) -> vio::task_t<void>
        {
          auto client = vio::ssl_client_create(el, cc);
          REQUIRE_EXPECTED(client);
          auto c = std::move(client.value());
          auto connect_result = co_await vio::ssl_client_connect(c, "localhost", p, "127.0.0.1");
          REQUIRE_EXPECTED(connect_result);
          std::string a = "AAA";
          std::string b = "BBB";
          uv_buf_t ba = uv_buf_init(a.data(), a.size());
          uv_buf_t bb = uv_buf_init(b.data(), b.size());
          // Submit both writes before awaiting either -> two uv_writes in flight.
          auto w1 = vio::ssl_client_write(c, ba);
          auto w2 = vio::ssl_client_write(c, bb);
          auto r1 = co_await std::move(w1);
          REQUIRE_EXPECTED(r1);
          auto r2 = co_await std::move(w2);
          REQUIRE_EXPECTED(r2);
        }(event_loop, cc, port);

        co_await std::move(client_task);
        co_await std::move(server_task);
        ev->stop();
      }(event_loop, server_config, client_config, verified);
    });
  event_loop.run();
  REQUIRE(verified);
}

TEST_CASE("vectored write coalesces buffers and round-trips")
{
  vio::event_loop_t event_loop;
  auto certs = generate_test_certs();
  vio::ssl_config_t server_config{.ca_mem = certs.ca_cert, .cert_mem = certs.cert, .key_mem = certs.key};
  vio::ssl_config_t client_config{.ca_mem = certs.ca_cert};
  bool verified = false;

  event_loop.run_in_loop(
    [&]
    {
      return [](vio::event_loop_t &event_loop, vio::ssl_config_t sc, vio::ssl_config_t cc, bool &verified) -> vio::task_t<void>
      {
        auto *ev = &event_loop;
        auto server_tcp_pair = get_ephemeral_port(*ev);
        REQUIRE_EXPECTED(server_tcp_pair);
        int port = server_tcp_pair->second;

        auto server_task = [](vio::event_loop_t &el, vio::tcp_server_t s, vio::ssl_config_t sc, int p, bool &verified) -> vio::task_t<void>
        {
          auto server = vio::ssl_server_create(el, std::move(s), "localhost", sc);
          REQUIRE_EXPECTED(server);
          auto srv = std::move(server.value());
          auto listen_result = co_await vio::ssl_server_listen(srv, p);
          REQUIRE_EXPECTED(listen_result);
          auto client_or_err = vio::ssl_server_accept(srv);
          REQUIRE_EXPECTED(client_or_err);
          auto client = std::move(client_or_err.value());
          auto reader_or_err = vio::ssl_server_client_create_reader(client);
          REQUIRE_EXPECTED(reader_or_err);
          auto reader = std::move(reader_or_err.value());
          std::string received;
          while (received.size() < 9)
          {
            auto rr = co_await reader;
            if (!rr.has_value())
              break;
            received.append(rr.value()->base, rr.value()->len);
          }
          verified = (received == "frame1two");
        }(event_loop, std::move(server_tcp_pair->first), sc, port, verified);

        auto client_task = [](vio::event_loop_t &el, vio::ssl_config_t cc, int p) -> vio::task_t<void>
        {
          auto client = vio::ssl_client_create(el, cc);
          REQUIRE_EXPECTED(client);
          auto c = std::move(client.value());
          auto connect_result = co_await vio::ssl_client_connect(c, "localhost", p, "127.0.0.1");
          REQUIRE_EXPECTED(connect_result);
          std::string f1 = "frame1";
          std::string f2 = "two";
          uv_buf_t bufs[2] = {uv_buf_init(f1.data(), f1.size()), uv_buf_init(f2.data(), f2.size())};
          auto wr = co_await vio::ssl_client_writev(c, std::span<const uv_buf_t>(bufs, 2));
          REQUIRE_EXPECTED(wr);
        }(event_loop, cc, port);

        co_await std::move(client_task);
        co_await std::move(server_task);
        ev->stop();
      }(event_loop, server_config, client_config, verified);
    });
  event_loop.run();
  REQUIRE(verified);
}

TEST_CASE("empty vectored write completes synchronously without hanging")
{
  // Regression: a synchronously-completing write (empty writev) must not
  // deactivate its slot before the returned awaitable observes it.
  vio::event_loop_t event_loop;
  auto certs = generate_test_certs();
  vio::ssl_config_t server_config{.ca_mem = certs.ca_cert, .cert_mem = certs.cert, .key_mem = certs.key};
  vio::ssl_config_t client_config{.ca_mem = certs.ca_cert};
  bool empty_ok = false;

  event_loop.run_in_loop(
    [&]
    {
      return [](vio::event_loop_t &event_loop, vio::ssl_config_t sc, vio::ssl_config_t cc, bool &empty_ok) -> vio::task_t<void>
      {
        auto *ev = &event_loop;
        auto server_tcp_pair = get_ephemeral_port(*ev);
        REQUIRE_EXPECTED(server_tcp_pair);
        int port = server_tcp_pair->second;

        auto server_task = [](vio::event_loop_t &el, vio::tcp_server_t s, vio::ssl_config_t sc, int p) -> vio::task_t<void>
        {
          auto server = vio::ssl_server_create(el, std::move(s), "localhost", sc);
          REQUIRE_EXPECTED(server);
          auto srv = std::move(server.value());
          auto listen_result = co_await vio::ssl_server_listen(srv, p);
          REQUIRE_EXPECTED(listen_result);
          auto client_or_err = vio::ssl_server_accept(srv);
          REQUIRE_EXPECTED(client_or_err);
          auto client = std::move(client_or_err.value());
          auto reader = vio::ssl_server_client_create_reader(client);
          REQUIRE_EXPECTED(reader);
          auto rr = co_await reader.value();
          REQUIRE_EXPECTED(rr);
        }(event_loop, std::move(server_tcp_pair->first), sc, port);

        auto client_task = [](vio::event_loop_t &el, vio::ssl_config_t cc, int p, bool &empty_ok) -> vio::task_t<void>
        {
          auto client = vio::ssl_client_create(el, cc);
          REQUIRE_EXPECTED(client);
          auto c = std::move(client.value());
          auto connect_result = co_await vio::ssl_client_connect(c, "localhost", p, "127.0.0.1");
          REQUIRE_EXPECTED(connect_result);
          // Empty vectored write: must resolve, not hang.
          auto ew = co_await vio::ssl_client_writev(c, std::span<const uv_buf_t>{});
          REQUIRE_EXPECTED(ew);
          empty_ok = true;
          std::string msg = "done";
          uv_buf_t buf = uv_buf_init(msg.data(), msg.size());
          auto wr = co_await vio::ssl_client_write(c, buf);
          REQUIRE_EXPECTED(wr);
        }(event_loop, cc, port, empty_ok);

        co_await std::move(client_task);
        co_await std::move(server_task);
        ev->stop();
      }(event_loop, server_config, client_config, empty_ok);
    });
  event_loop.run();
  REQUIRE(empty_ok);
}

TEST_CASE("server write parked before a failing handshake resolves with an error")
{
  // Regression: a server-speaks-first write parked in pending_handshake_writes
  // must be failed (not hang) when the handshake fails. The client is given the
  // wrong CA so it rejects the server certificate and the handshake fails.
  vio::event_loop_t event_loop;
  auto server_certs = generate_test_certs();
  auto other_certs = generate_test_certs(); // an unrelated CA the client will trust
  vio::ssl_config_t server_config{.ca_mem = server_certs.ca_cert, .cert_mem = server_certs.cert, .key_mem = server_certs.key};
  vio::ssl_config_t client_config{.ca_mem = other_certs.ca_cert};
  bool server_write_failed = false;
  bool client_connect_failed = false;

  event_loop.run_in_loop(
    [&]
    {
      return [](vio::event_loop_t &event_loop, vio::ssl_config_t sc, vio::ssl_config_t cc, bool &swf, bool &ccf) -> vio::task_t<void>
      {
        auto *ev = &event_loop;
        auto server_tcp_pair = get_ephemeral_port(*ev);
        REQUIRE_EXPECTED(server_tcp_pair);
        int port = server_tcp_pair->second;

        auto server_task = [](vio::event_loop_t &el, vio::tcp_server_t s, vio::ssl_config_t sc, int p, bool &swf) -> vio::task_t<void>
        {
          auto server = vio::ssl_server_create(el, std::move(s), "localhost", sc);
          REQUIRE_EXPECTED(server);
          auto srv = std::move(server.value());
          auto listen_result = co_await vio::ssl_server_listen(srv, p);
          REQUIRE_EXPECTED(listen_result);
          auto client_or_err = vio::ssl_server_accept(srv);
          REQUIRE_EXPECTED(client_or_err);
          auto client = std::move(client_or_err.value());
          // Write before the handshake finishes (parked in pending_handshake_writes).
          std::string greeting = "hello";
          uv_buf_t buf = uv_buf_init(greeting.data(), greeting.size());
          auto wr = co_await vio::ssl_server_client_write(client, buf);
          swf = !wr.has_value(); // must resolve with an error, not hang
        }(event_loop, std::move(server_tcp_pair->first), sc, port, swf);

        auto client_task = [](vio::event_loop_t &el, vio::ssl_config_t cc, int p, bool &ccf) -> vio::task_t<void>
        {
          auto client = vio::ssl_client_create(el, cc);
          REQUIRE_EXPECTED(client);
          auto c = std::move(client.value());
          auto connect_result = co_await vio::ssl_client_connect(c, "localhost", p, "127.0.0.1");
          ccf = !connect_result.has_value(); // verification must fail
        }(event_loop, cc, port, ccf);

        co_await std::move(client_task);
        { auto destroy = std::move(client_task); }
        co_await std::move(server_task);
        ev->stop();
      }(event_loop, server_config, client_config, server_write_failed, client_connect_failed);
    });
  event_loop.run();
  REQUIRE(client_connect_failed);
  REQUIRE(server_write_failed);
}

TEST_CASE("half-close: client close_notify surfaces as a clean read error on the server")
{
  vio::event_loop_t event_loop;
  auto certs = generate_test_certs();
  vio::ssl_config_t server_config{.ca_mem = certs.ca_cert, .cert_mem = certs.cert, .key_mem = certs.key};
  vio::ssl_config_t client_config{.ca_mem = certs.ca_cert};
  int close_code = 0;

  event_loop.run_in_loop(
    [&]
    {
      return [](vio::event_loop_t &event_loop, vio::ssl_config_t sc, vio::ssl_config_t cc, int &close_code) -> vio::task_t<void>
      {
        auto *ev = &event_loop;
        auto server_tcp_pair = get_ephemeral_port(*ev);
        REQUIRE_EXPECTED(server_tcp_pair);
        int port = server_tcp_pair->second;

        auto server_task = [](vio::event_loop_t &el, vio::tcp_server_t s, vio::ssl_config_t sc, int p, int &close_code) -> vio::task_t<void>
        {
          auto server = vio::ssl_server_create(el, std::move(s), "localhost", sc);
          REQUIRE_EXPECTED(server);
          auto srv = std::move(server.value());
          auto listen_result = co_await vio::ssl_server_listen(srv, p);
          REQUIRE_EXPECTED(listen_result);
          auto client_or_err = vio::ssl_server_accept(srv);
          REQUIRE_EXPECTED(client_or_err);
          auto client = std::move(client_or_err.value());
          auto reader_or_err = vio::ssl_server_client_create_reader(client);
          REQUIRE_EXPECTED(reader_or_err);
          auto reader = std::move(reader_or_err.value());
          while (true)
          {
            auto rr = co_await reader;
            if (!rr.has_value())
            {
              close_code = rr.error().code;
              break;
            }
          }
        }(event_loop, std::move(server_tcp_pair->first), sc, port, close_code);

        auto client_task = [](vio::event_loop_t &el, vio::ssl_config_t cc, int p) -> vio::task_t<void>
        {
          auto client = vio::ssl_client_create(el, cc);
          REQUIRE_EXPECTED(client);
          auto c = std::move(client.value());
          auto connect_result = co_await vio::ssl_client_connect(c, "localhost", p, "127.0.0.1");
          REQUIRE_EXPECTED(connect_result);
          std::string msg = "hello";
          uv_buf_t buf = uv_buf_init(msg.data(), msg.size());
          auto wr = co_await vio::ssl_client_write(c, buf);
          REQUIRE_EXPECTED(wr);
          auto sh = co_await vio::ssl_client_shutdown(c);
          REQUIRE_EXPECTED(sh);
        }(event_loop, cc, port);

        co_await std::move(client_task);
        { auto destroy = std::move(client_task); }
        co_await std::move(server_task);
        ev->stop();
      }(event_loop, server_config, client_config, close_code);
    });
  event_loop.run();
  REQUIRE(close_code == vio::vio_tls_clean_shutdown);
}
} // TEST_SUITE
} // namespace
