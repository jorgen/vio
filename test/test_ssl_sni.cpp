#include <doctest/doctest.h>

#include <cstdint>
#include <string>
#include <vector>

#include <vio/event_loop.h>
#include <vio/operation/tls_client.h>
#include <vio/operation/tls_common.h>
#include <vio/operation/tls_server.h>
#include <vio/task.h>

#include "require_expected.h"
#include "tls_test_helpers.h"

namespace
{
std::vector<uint8_t> concat_pem(std::initializer_list<const std::vector<uint8_t> *> parts)
{
  std::vector<uint8_t> out;
  for (const auto *p : parts)
  {
    out.insert(out.end(), p->begin(), p->end());
  }
  return out;
}

// Accept `count` connections on one server, driving each handshake to completion
// (or failure) before the next. Mirrors the multi-accept pattern from
// test_tls_server.cpp (reset listen.done, re-listen).
vio::task_t<void> sni_accept_loop(vio::event_loop_t &event_loop, vio::tcp_server_t s, vio::ssl_config_t config, int count)
{
  auto server_or = vio::ssl_server_create(event_loop, std::move(s), "localhost", config);
  REQUIRE_EXPECTED(server_or);
  auto server = std::move(server_or.value());
  for (int i = 0; i < count; ++i)
  {
    auto listen_result = co_await vio::ssl_server_listen(server, 16);
    REQUIRE_EXPECTED(listen_result);
    auto accepted = vio::ssl_server_accept(server);
    REQUIRE_EXPECTED(accepted);
    auto client = std::move(accepted.value());
    server.handle->tcp.tcp.handle->listen.done = false;
    co_await vio::ssl_server_client_handshake(client); // result ignored: an untrusted client fails here
  }
}

// Connect once with SNI=`host` (over 127.0.0.1). expect_ok asserts the handshake
// (and thus the server's cert selection + this client's verification) succeeds;
// when it does and expect_alpn is non-empty, the negotiated ALPN must match.
vio::task_t<void> sni_connect(vio::event_loop_t &event_loop, vio::ssl_config_t config, std::string host, int port, bool expect_ok, std::string expect_alpn, int &ok_count, int &fail_count)
{
  auto client_or = vio::ssl_client_create(event_loop, config);
  REQUIRE_EXPECTED(client_or);
  auto client = std::move(client_or.value());
  auto connect_result = co_await vio::ssl_client_connect(client, host, static_cast<uint16_t>(port), std::string("127.0.0.1"));
  if (expect_ok)
  {
    REQUIRE_EXPECTED(connect_result);
    if (!expect_alpn.empty())
    {
      auto alpn = vio::ssl_client_alpn_selected(client);
      REQUIRE(alpn.has_value());
      CHECK(*alpn == expect_alpn);
    }
    ++ok_count;
  }
  else
  {
    REQUIRE_FALSE(connect_result.has_value());
    ++fail_count;
  }
}
} // namespace

TEST_SUITE("TLS SNI")
{
  // Two registered certs + a fallback: the server must return the cert whose CN
  // matches the SNI name (verified by the client's hostname check against a bundle
  // that trusts all three CAs, so only the CN match — not trust — discriminates),
  // and ALPN must still negotiate after the per-host SSL_CTX switch.
  TEST_CASE("server selects the certificate matching the SNI name")
  {
    vio::event_loop_t event_loop;
    auto a = vio_test::make_cert_set("host-a.test");
    auto b = vio_test::make_cert_set("host-b.test");
    auto fb = vio_test::make_cert_set("fallback.test");
    auto bundle = concat_pem({&a.ca_cert, &b.ca_cert, &fb.ca_cert});

    int ok_count = 0;
    int fail_count = 0;

    event_loop.run_in_loop(
      [&]
      {
        return [](vio::event_loop_t &el, vio_test::cert_set_t a, vio_test::cert_set_t b, vio_test::cert_set_t fb, std::vector<uint8_t> bundle, int &oks, int &fails) -> vio::task_t<void>
        {
          auto ep = vio_test::get_ephemeral_port(el);
          REQUIRE_EXPECTED(ep);
          const int port = ep->second;

          vio::ssl_config_t store_base;
          store_base.alpn_protocols = {"h2", "http/1.1"};
          auto store = vio::make_sni_cert_store(store_base);
          REQUIRE_EXPECTED(store->set_certificate("host-a.test", a.cert, a.key));
          REQUIRE_EXPECTED(store->set_certificate("host-b.test", b.cert, b.key));

          vio::ssl_config_t server_config;
          server_config.alpn_protocols = {"h2", "http/1.1"};
          server_config.cert_mem = fb.cert;
          server_config.key_mem = fb.key;
          server_config.sni_store = store;

          auto server_task = sni_accept_loop(el, std::move(ep->first), server_config, 3);

          vio::ssl_config_t client_config;
          client_config.alpn_protocols = {"h2"};
          client_config.ca_mem = bundle;

          co_await sni_connect(el, client_config, "host-a.test", port, true, "h2", oks, fails);
          co_await sni_connect(el, client_config, "host-b.test", port, true, "h2", oks, fails);
          co_await sni_connect(el, client_config, "fallback.test", port, true, "h2", oks, fails);

          co_await std::move(server_task);
          el.stop();
        }(event_loop, a, b, fb, bundle, ok_count, fail_count);
      });
    event_loop.run();

    CHECK(ok_count == 3);
    CHECK(fail_count == 0);
  }

  // set_certificate adds and replaces a host's cert while the same server keeps
  // running: a name is unserved until added, then served, and a replacement with a
  // cert from a different CA flips which trust anchor a new connection needs — the
  // server never restarts, so live issuance/renewal drops no connections.
  TEST_CASE("set_certificate adds and replaces a host's certificate live")
  {
    vio::event_loop_t event_loop;
    auto a1 = vio_test::make_cert_set("host-a.test"); // CN host-a.test, CA #1
    auto a2 = vio_test::make_cert_set("host-a.test"); // CN host-a.test, independent CA #2
    auto fb = vio_test::make_cert_set("fallback.test");

    int ok_count = 0;
    int fail_count = 0;

    event_loop.run_in_loop(
      [&]
      {
        return [](vio::event_loop_t &el, vio_test::cert_set_t a1, vio_test::cert_set_t a2, vio_test::cert_set_t fb, int &oks, int &fails) -> vio::task_t<void>
        {
          auto ep = vio_test::get_ephemeral_port(el);
          REQUIRE_EXPECTED(ep);
          const int port = ep->second;

          auto store = vio::make_sni_cert_store(vio::ssl_config_t{});

          vio::ssl_config_t server_config;
          server_config.cert_mem = fb.cert;
          server_config.key_mem = fb.key;
          server_config.sni_store = store;

          auto server_task = sni_accept_loop(el, std::move(ep->first), server_config, 4);

          vio::ssl_config_t trust_ca1;
          trust_ca1.ca_mem = a1.ca_cert;
          vio::ssl_config_t trust_ca2;
          trust_ca2.ca_mem = a2.ca_cert;

          co_await sni_connect(el, trust_ca1, "host-a.test", port, false, "", oks, fails); // unserved -> fallback CN != host-a
          REQUIRE_EXPECTED(store->set_certificate("host-a.test", a1.cert, a1.key));
          co_await sni_connect(el, trust_ca1, "host-a.test", port, true, "", oks, fails); // now served, CA #1 trusted
          REQUIRE_EXPECTED(store->set_certificate("host-a.test", a2.cert, a2.key));
          co_await sni_connect(el, trust_ca1, "host-a.test", port, false, "", oks, fails); // replaced -> CA #1 no longer trusts it
          co_await sni_connect(el, trust_ca2, "host-a.test", port, true, "", oks, fails);  // CA #2 trusts the replacement

          co_await std::move(server_task);
          el.stop();
        }(event_loop, a1, a2, fb, ok_count, fail_count);
      });
    event_loop.run();

    CHECK(ok_count == 2);
    CHECK(fail_count == 2);
  }
}
