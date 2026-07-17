#include <doctest/doctest.h>

#include <vio/event_loop.h>
#include <vio/operation/http_client.h>
#include <vio/operation/tcp.h>
#include <vio/operation/tcp_server.h>
#include <vio/operation/tls_server.h>
#include <vio/task.h>

#include "require_expected.h"
#include "tls_test_helpers.h"

#include <string>
#include <utility>

#ifndef _WIN32
#include <openssl/x509v3.h> // IP-SAN construction for the ca_mem loopback cases (see below)
#endif

TEST_SUITE("http_client parse_response")
{
  TEST_CASE("status line and identity body")
  {
    std::string raw =
      "HTTP/1.1 200 OK\r\n"
      "Content-Type: application/json\r\n"
      "Content-Length: 11\r\n"
      "\r\n"
      "{\"ok\":true}";
    auto response = vio::http::detail::parse_response(raw);
    REQUIRE(response.has_value());
    CHECK(response->status == 200);
    CHECK(response->body == "{\"ok\":true}");
    CHECK(std::string(response->header("content-type")) == "application/json");
    CHECK(std::string(response->header("Content-Type")) == "application/json");
    CHECK(response->header("missing").empty());
  }

  TEST_CASE("non-200 status")
  {
    std::string raw = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
    auto response = vio::http::detail::parse_response(raw);
    REQUIRE(response.has_value());
    CHECK(response->status == 404);
    CHECK(response->body.empty());
  }

  TEST_CASE("chunked transfer-encoding is de-chunked")
  {
    std::string raw =
      "HTTP/1.1 200 OK\r\n"
      "Transfer-Encoding: chunked\r\n"
      "\r\n"
      "5\r\nHello\r\n6\r\n World\r\n0\r\n\r\n";
    auto response = vio::http::detail::parse_response(raw);
    REQUIRE(response.has_value());
    CHECK(response->status == 200);
    CHECK(response->body == "Hello World");
  }

  TEST_CASE("missing header terminator is an error")
  {
    std::string raw = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n";
    auto response = vio::http::detail::parse_response(raw);
    CHECK_FALSE(response.has_value());
  }
}

namespace
{
std::expected<std::pair<vio::tcp_server_t, int>, vio::error_t> bound_http_server(vio::event_loop_t &event_loop)
{
  auto addr = vio::ip4_addr("127.0.0.1", 0);
  if (!addr)
    return std::unexpected(addr.error());
  auto server = vio::tcp_create_server(event_loop);
  if (!server)
    return std::unexpected(server.error());
  auto bound = vio::tcp_bind(server.value(), reinterpret_cast<const sockaddr *>(&addr.value()));
  if (!bound)
    return std::unexpected(bound.error());
  auto sn = vio::sockname(server->tcp);
  if (!sn)
    return std::unexpected(sn.error());
  sockaddr_storage storage = sn.value();
  const auto *in = reinterpret_cast<const sockaddr_in *>(&storage);
  return std::make_pair(std::move(server.value()), static_cast<int>(ntohs(in->sin_port)));
}

vio::task_t<void> plaintext_scenario(vio::event_loop_t &event_loop, std::string &captured, vio::http::response_t &resp_out, bool &ok)
{
  auto server_and_port = bound_http_server(event_loop);
  REQUIRE_EXPECTED(server_and_port);
  const int port = server_and_port->second;

  auto server_task = [](vio::tcp_server_t s, std::string &captured_request) -> vio::task_t<void>
  {
    auto server = std::move(s);
    auto listen_result = co_await vio::tcp_listen(server, 10);
    REQUIRE_EXPECTED(listen_result);
    auto accepted = vio::tcp_accept(server);
    REQUIRE_EXPECTED(accepted);
    auto conn = std::move(accepted.value());

    auto reader_or_err = vio::tcp_create_reader(conn);
    REQUIRE_EXPECTED(reader_or_err);
    auto reader = std::move(reader_or_err.value());
    while (captured_request.find("\r\n\r\n") == std::string::npos)
    {
      auto chunk = co_await reader;
      if (!chunk)
        break;
      captured_request.append(chunk.value().buf.base, chunk.value().buf.len);
    }

    std::string response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello";
    auto write_result = co_await vio::write_tcp(conn, reinterpret_cast<const uint8_t *>(response.data()), response.size());
    REQUIRE_EXPECTED(write_result);
  }(std::move(server_and_port->first), captured);

  co_await [](vio::event_loop_t &el, int p, vio::http::response_t &out, bool &success) -> vio::task_t<void>
  {
    vio::http::request_t req;
    req.method = "GET";
    req.url = "http://127.0.0.1:" + std::to_string(p) + "/x?y=1";
    req.allow_plaintext = true;
    req.headers.push_back(vio::http::header_t{"X-Test", "abc"});
    auto resp = co_await vio::http::fetch_once(el, req);
    REQUIRE_EXPECTED(resp);
    out = std::move(resp.value());
    success = true;
  }(event_loop, port, resp_out, ok);

  co_await std::move(server_task);
}
} // namespace

TEST_SUITE("http_client plaintext")
{
  // fetch_once with allow_plaintext drives a plain-TCP HTTP/1.1 request against a loopback backend.
  TEST_CASE("opt-in plaintext round-trips and forwards a single Host + custom header")
  {
    vio::event_loop_t event_loop;
    std::string captured;
    vio::http::response_t resp;
    bool ok = false;

    event_loop.run_in_loop(
      [&]
      {
        return [](vio::event_loop_t &el, std::string &cap, vio::http::response_t &out, bool &success) -> vio::task_t<void>
        {
          co_await plaintext_scenario(el, cap, out, success);
          el.stop();
        }(event_loop, captured, resp, ok);
      });
    event_loop.run();

    REQUIRE(ok);
    CHECK(resp.status == 200);
    CHECK(resp.body == "hello");
    CHECK(captured.find("GET /x?y=1 HTTP/1.1\r\n") != std::string::npos);
    CHECK(captured.find("X-Test: abc\r\n") != std::string::npos);
    const auto first_host = captured.find("Host:");
    REQUIRE(first_host != std::string::npos);
    CHECK(captured.find("Host:", first_host + 1) == std::string::npos);
    // A non-default port must appear in the Host header (RFC 9110); servers that
    // echo Host into absolute URLs (e.g. an ACME directory) otherwise break. The
    // loopback backend listens on an ephemeral (non-80) port, so a "host:port"
    // colon must be present.
    CHECK(captured.find("Host: 127.0.0.1:") != std::string::npos);
  }

  // Safety: without the opt-in flag, http:// is still refused (protects existing callers).
  TEST_CASE("plaintext http is refused without the opt-in flag")
  {
    vio::event_loop_t event_loop;
    bool checked = false;

    event_loop.run_in_loop(
      [&]
      {
        return [](vio::event_loop_t &el, bool &done) -> vio::task_t<void>
        {
          vio::http::request_t req;
          req.method = "GET";
          req.url = "http://127.0.0.1:1/x";
          auto resp = co_await vio::http::fetch_once(el, req);
          CHECK_FALSE(resp.has_value());
          if (!resp.has_value())
            CHECK(resp.error().msg == std::string("http: only https is supported"));
          done = true;
          el.stop();
        }(event_loop, checked);
      });
    event_loop.run();

    CHECK(checked);
  }
}

// The ca_mem end-to-end cases connect fetch_once to a literal 127.0.0.1 (a single
// address, so no IPv4/IPv6 candidate failover) against a loopback TLS server whose
// leaf carries an IP SAN for 127.0.0.1 (verified by IP, so no DNS name is needed).
// The IP SAN needs x509v3.h, which collides with <wincrypt.h> on Windows, so the
// whole section is skipped there (the ACME client ships on Linux).
#ifndef _WIN32
namespace
{
// A CA plus a leaf whose subjectAltName is IP:127.0.0.1 (what fetch_once verifies
// against when the URL host is that literal address).
vio_test::cert_set_t make_ip_cert_set()
{
  EVP_PKEY *ca_key = vio_test::make_key();
  X509 *ca = X509_new();
  X509_set_version(ca, 2);
  ASN1_INTEGER_set(X509_get_serialNumber(ca), 1);
  X509_gmtime_adj(X509_get_notBefore(ca), 0);
  X509_gmtime_adj(X509_get_notAfter(ca), 31536000L);
  X509_set_pubkey(ca, ca_key);
  auto *ca_name = X509_get_subject_name(ca);
  X509_NAME_add_entry_by_txt(ca_name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char *>("vio loopback CA"), -1, -1, 0);
  X509_set_issuer_name(ca, ca_name);
  X509_sign(ca, ca_key, EVP_sha256());

  EVP_PKEY *leaf_key = vio_test::make_key();
  X509 *leaf = X509_new();
  X509_set_version(leaf, 2);
  ASN1_INTEGER_set(X509_get_serialNumber(leaf), 2);
  X509_gmtime_adj(X509_get_notBefore(leaf), 0);
  X509_gmtime_adj(X509_get_notAfter(leaf), 31536000L);
  X509_set_pubkey(leaf, leaf_key);
  auto *leaf_name = X509_get_subject_name(leaf);
  X509_NAME_add_entry_by_txt(leaf_name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char *>("127.0.0.1"), -1, -1, 0);
  X509_set_issuer_name(leaf, ca_name);

  GENERAL_NAMES *sans = sk_GENERAL_NAME_new_null();
  GENERAL_NAME *gn = GENERAL_NAME_new();
  ASN1_OCTET_STRING *ip = a2i_IPADDRESS("127.0.0.1");
  GENERAL_NAME_set0_value(gn, GEN_IPADD, ip);
  sk_GENERAL_NAME_push(sans, gn);
  X509_add1_ext_i2d(leaf, NID_subject_alt_name, sans, 0, 0);
  GENERAL_NAMES_free(sans);

  X509_sign(leaf, ca_key, EVP_sha256());

  vio_test::cert_set_t out{.ca_cert = vio_test::pem_from_cert(ca), .cert = vio_test::pem_from_cert(leaf), .key = vio_test::pem_from_key(leaf_key)};
  X509_free(ca);
  EVP_PKEY_free(ca_key);
  X509_free(leaf);
  EVP_PKEY_free(leaf_key);
  return out;
}

// A loopback TLS/1.1 server presenting `certs`; replies 200 to one request then
// completes (destroying its client, which close_notifies → the client's read loop
// sees EOF). Tolerates a client that aborts the handshake (the untrusted-CA case),
// so both scenarios drive the same server.
vio::task_t<void> https_ca_scenario(vio::event_loop_t &event_loop, vio_test::cert_set_t certs, bool trust_ca, std::expected<vio::http::response_t, vio::error_t> &result_out)
{
  auto ep = vio_test::get_ephemeral_port(event_loop);
  REQUIRE_EXPECTED(ep);
  const int port = ep->second;

  auto server_task = [](vio::event_loop_t &el, vio::tcp_server_t s, std::vector<uint8_t> cert, std::vector<uint8_t> key) -> vio::task_t<void>
  {
    vio::ssl_config_t sc;
    sc.cert_mem = std::move(cert);
    sc.key_mem = std::move(key);
    auto server_or = vio::ssl_server_create(el, std::move(s), "127.0.0.1", sc);
    REQUIRE_EXPECTED(server_or);
    auto server = std::move(server_or.value());
    auto listen_result = co_await vio::ssl_server_listen(server, 10);
    REQUIRE_EXPECTED(listen_result);
    auto accepted = vio::ssl_server_accept(server);
    REQUIRE_EXPECTED(accepted);
    auto client = std::move(accepted.value());

    auto reader_or = vio::ssl_server_client_create_reader(client);
    REQUIRE_EXPECTED(reader_or);
    auto reader = std::move(reader_or.value());
    std::string request;
    bool have_request = false;
    while (request.find("\r\n\r\n") == std::string::npos)
    {
      auto chunk = co_await reader;
      if (!chunk)
        break;
      request.append(chunk.value()->base, chunk.value()->len);
      have_request = true;
    }
    if (!have_request)
      co_return; // client aborted the handshake (untrusted CA) — nothing to reply to
    std::string response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello";
    const uv_buf_t buf = uv_buf_init(response.data(), response.size());
    auto write_result = co_await vio::ssl_server_client_write(client, buf);
    REQUIRE_EXPECTED(write_result);
  }(event_loop, std::move(ep->first), certs.cert, certs.key);

  co_await [](vio::event_loop_t &el, int p, std::vector<uint8_t> ca, bool trust, std::expected<vio::http::response_t, vio::error_t> &out) -> vio::task_t<void>
  {
    vio::http::request_t req;
    req.url = "https://127.0.0.1:" + std::to_string(p) + "/health";
    if (trust)
      req.ca_mem = std::move(ca);
    out = co_await vio::http::fetch_once(el, req);
  }(event_loop, port, certs.ca_cert, trust_ca, result_out);

  co_await std::move(server_task);
}
} // namespace

TEST_SUITE("http_client https ca_mem")
{
  // request_t::ca_mem makes fetch_once verify the peer against a private CA bundle
  // (the mechanism the ACME client uses to trust a Pebble/staging CA).
  TEST_CASE("ca_mem trust anchor lets fetch_once verify a private CA")
  {
    vio::event_loop_t event_loop;
    auto certs = make_ip_cert_set();
    std::expected<vio::http::response_t, vio::error_t> result = std::unexpected(vio::error_t{});

    event_loop.run_in_loop(
      [&]
      {
        return [](vio::event_loop_t &el, vio_test::cert_set_t c, std::expected<vio::http::response_t, vio::error_t> &out) -> vio::task_t<void>
        {
          co_await https_ca_scenario(el, std::move(c), true, out);
          el.stop();
        }(event_loop, certs, result);
      });
    event_loop.run();

    REQUIRE(result.has_value());
    CHECK(result->status == 200);
    CHECK(result->body == "hello");
  }

  // Without ca_mem the private CA is untrusted, so verification fails (proving the
  // trust really comes from ca_mem and not a disabled check).
  TEST_CASE("without ca_mem the private CA is rejected")
  {
    vio::event_loop_t event_loop;
    auto certs = make_ip_cert_set();
    std::expected<vio::http::response_t, vio::error_t> result = vio::http::response_t{};

    event_loop.run_in_loop(
      [&]
      {
        return [](vio::event_loop_t &el, vio_test::cert_set_t c, std::expected<vio::http::response_t, vio::error_t> &out) -> vio::task_t<void>
        {
          co_await https_ca_scenario(el, std::move(c), false, out);
          el.stop();
        }(event_loop, certs, result);
      });
    event_loop.run();

    CHECK_FALSE(result.has_value());
  }
}
#endif // !_WIN32
