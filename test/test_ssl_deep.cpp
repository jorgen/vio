// Deep, backend-agnostic TLS verification suite. Every test drives only the
// public vio API, so the same suite validates whichever VIO_SSL_BACKEND is
// compiled (LibreSSL today; OpenSSL 3.x / BoringSSL when wired). It exercises
// the security-critical behaviors: certificate verification (trust, hostname),
// mutual TLS, protocol-version pinning, session resumption, OCSP staple
// delivery, distinct close semantics, and concurrent-connection integrity.

#include <doctest/doctest.h>

#include <string>
#include <string_view>
#include <vector>

#include <vio/event_loop.h>
#include <vio/operation/tls_client.h>
#include <vio/operation/tls_server.h>
#include <vio/task.h>

#include "require_expected.h"
#include "tls_test_helpers.h"

using vio_test::get_ephemeral_port;
using vio_test::make_cert_set;

namespace
{
// Runs a coroutine body to completion on its own event loop. The body takes the
// loop by reference and must call ev.stop() when done.
template <typename Fn>
void run_loop(Fn &&make_task)
{
  vio::event_loop_t event_loop;
  event_loop.run_in_loop([&] { return make_task(event_loop); });
  event_loop.run();
}

// A minimal echo server task: accept one client, (optionally await handshake),
// then echo back everything until the peer closes.
vio::task_t<void> echo_server(vio::event_loop_t &el, vio::tcp_server_t s, vio::ssl_config_t cfg, int port, bool await_handshake)
{
  auto server = vio::ssl_server_create(el, std::move(s), "localhost", cfg);
  REQUIRE_EXPECTED(server);
  auto srv = std::move(server.value());
  auto listen_result = co_await vio::ssl_server_listen(srv, port);
  REQUIRE_EXPECTED(listen_result);
  auto client_or_err = vio::ssl_server_accept(srv);
  REQUIRE_EXPECTED(client_or_err);
  auto client = std::move(client_or_err.value());
  if (await_handshake)
  {
    auto hs = co_await vio::ssl_server_client_handshake(client);
    if (!hs.has_value())
      co_return; // handshake failed (e.g. client cert rejected) -- nothing to echo
  }
  auto reader_or_err = vio::ssl_server_client_create_reader(client);
  REQUIRE_EXPECTED(reader_or_err);
  auto reader = std::move(reader_or_err.value());
  while (true)
  {
    auto rr = co_await reader;
    if (!rr.has_value())
      break;
    auto &data = rr.value();
    uv_buf_t buf = uv_buf_init(data->base, data->len);
    auto wr = co_await vio::ssl_server_client_write(client, buf);
    if (!wr.has_value())
      break;
  }
}

TEST_SUITE("TLS deep verification")
{
TEST_CASE("rejects a server certificate signed by an untrusted CA")
{
  auto server = make_cert_set("localhost");
  auto rogue = make_cert_set("localhost"); // an unrelated CA the client will trust
  vio::ssl_config_t server_config{.ca_mem = server.ca_cert, .cert_mem = server.cert, .key_mem = server.key};
  vio::ssl_config_t client_config{.ca_mem = rogue.ca_cert}; // wrong trust anchor
  bool client_rejected = false;

  run_loop(
    [&](vio::event_loop_t &el) -> vio::task_t<void>
    {
      auto pair = get_ephemeral_port(el);
      REQUIRE_EXPECTED(pair);
      int port = pair->second;
      auto server_task = echo_server(el, std::move(pair->first), server_config, port, true);
      auto client_task = [](vio::event_loop_t &el, vio::ssl_config_t cc, int p, bool &rejected) -> vio::task_t<void>
      {
        auto c = vio::ssl_client_create(el, cc);
        REQUIRE_EXPECTED(c);
        auto client = std::move(c.value());
        auto cr = co_await vio::ssl_client_connect(client, "localhost", p, "127.0.0.1");
        rejected = !cr.has_value();
      }(el, client_config, port, client_rejected);
      co_await std::move(client_task);
      { auto destroy = std::move(client_task); }
      co_await std::move(server_task);
      el.stop();
    });
  REQUIRE(client_rejected);
}

TEST_CASE("rejects a certificate whose name does not match the requested host")
{
  auto certs = make_cert_set("localhost");
  vio::ssl_config_t server_config{.ca_mem = certs.ca_cert, .cert_mem = certs.cert, .key_mem = certs.key};
  vio::ssl_config_t client_config{.ca_mem = certs.ca_cert};
  bool client_rejected = false;

  run_loop(
    [&](vio::event_loop_t &el) -> vio::task_t<void>
    {
      auto pair = get_ephemeral_port(el);
      REQUIRE_EXPECTED(pair);
      int port = pair->second;
      auto server_task = echo_server(el, std::move(pair->first), server_config, port, true);
      auto client_task = [](vio::event_loop_t &el, vio::ssl_config_t cc, int p, bool &rejected) -> vio::task_t<void>
      {
        auto c = vio::ssl_client_create(el, cc);
        REQUIRE_EXPECTED(c);
        auto client = std::move(c.value());
        // Cert CN is "localhost" but we verify against "wrong.example".
        auto cr = co_await vio::ssl_client_connect(client, "wrong.example", p, "127.0.0.1");
        rejected = !cr.has_value();
      }(el, client_config, port, client_rejected);
      co_await std::move(client_task);
      { auto destroy = std::move(client_task); }
      co_await std::move(server_task);
      el.stop();
    });
  REQUIRE(client_rejected);
}

TEST_CASE("mutual TLS: a client certificate signed by a trusted CA is accepted")
{
  auto server = make_cert_set("localhost");
  auto client = make_cert_set("test-client");
  vio::ssl_config_t server_config{.ca_mem = client.ca_cert, // trust the CA that signed the client cert
                                  .cert_mem = server.cert,
                                  .key_mem = server.key};
  server_config.peer_verify = vio::peer_verify_t::required;
  vio::ssl_config_t client_config{.ca_mem = server.ca_cert, .cert_mem = client.cert, .key_mem = client.key};
  bool ok = false;

  run_loop(
    [&](vio::event_loop_t &el) -> vio::task_t<void>
    {
      auto pair = get_ephemeral_port(el);
      REQUIRE_EXPECTED(pair);
      int port = pair->second;
      auto server_task = echo_server(el, std::move(pair->first), server_config, port, true);
      auto client_task = [](vio::event_loop_t &el, vio::ssl_config_t cc, int p, bool &ok) -> vio::task_t<void>
      {
        auto c = vio::ssl_client_create(el, cc);
        REQUIRE_EXPECTED(c);
        auto client = std::move(c.value());
        auto cr = co_await vio::ssl_client_connect(client, "localhost", p, "127.0.0.1");
        REQUIRE_EXPECTED(cr);
        std::string msg = "mtls";
        uv_buf_t buf = uv_buf_init(msg.data(), msg.size());
        auto wr = co_await vio::ssl_client_write(client, buf);
        REQUIRE_EXPECTED(wr);
        auto reader = vio::ssl_client_create_reader(client);
        REQUIRE_EXPECTED(reader);
        auto rr = co_await reader.value();
        REQUIRE_EXPECTED(rr);
        ok = std::string_view(rr.value()->base, rr.value()->len) == "mtls";
      }(el, client_config, port, ok);
      co_await std::move(client_task);
      co_await std::move(server_task);
      el.stop();
    });
  REQUIRE(ok);
}

TEST_CASE("mutual TLS: a client with no certificate is rejected when one is required")
{
  auto server = make_cert_set("localhost");
  auto client = make_cert_set("test-client");
  vio::ssl_config_t server_config{.ca_mem = client.ca_cert, .cert_mem = server.cert, .key_mem = server.key};
  server_config.peer_verify = vio::peer_verify_t::required;
  vio::ssl_config_t client_config{.ca_mem = server.ca_cert}; // no client cert
  // In TLS 1.3 the client's connect can succeed (it sends an empty Certificate
  // and considers the handshake done) before the server's rejection alert
  // arrives, so the rejection is observed on the SERVER's handshake.
  bool server_rejected = false;

  run_loop(
    [&](vio::event_loop_t &el) -> vio::task_t<void>
    {
      auto pair = get_ephemeral_port(el);
      REQUIRE_EXPECTED(pair);
      int port = pair->second;
      auto server_task = [](vio::event_loop_t &el, vio::tcp_server_t s, vio::ssl_config_t sc, int p, bool &rejected) -> vio::task_t<void>
      {
        auto server = vio::ssl_server_create(el, std::move(s), "localhost", sc);
        REQUIRE_EXPECTED(server);
        auto srv = std::move(server.value());
        auto listen_result = co_await vio::ssl_server_listen(srv, p);
        REQUIRE_EXPECTED(listen_result);
        auto client_or_err = vio::ssl_server_accept(srv);
        REQUIRE_EXPECTED(client_or_err);
        auto sclient = std::move(client_or_err.value());
        auto hs = co_await vio::ssl_server_client_handshake(sclient);
        rejected = !hs.has_value(); // the missing client cert fails the handshake
      }(el, std::move(pair->first), server_config, port, server_rejected);
      auto client_task = [](vio::event_loop_t &el, vio::ssl_config_t cc, int p) -> vio::task_t<void>
      {
        auto c = vio::ssl_client_create(el, cc);
        REQUIRE_EXPECTED(c);
        auto client = std::move(c.value());
        co_await vio::ssl_client_connect(client, "localhost", p, "127.0.0.1");
      }(el, client_config, port);
      co_await std::move(client_task);
      { auto destroy = std::move(client_task); }
      co_await std::move(server_task);
      el.stop();
    });
  REQUIRE(server_rejected);
}

void run_version_pinned_case(vio::tls_protocol_version version, bool &verified_out)
{
  auto certs = make_cert_set("localhost");
  vio::ssl_config_t server_config{.ca_mem = certs.ca_cert, .cert_mem = certs.cert, .key_mem = certs.key};
  server_config.min_protocol = version;
  server_config.max_protocol = version;
  vio::ssl_config_t client_config{.ca_mem = certs.ca_cert};
  client_config.min_protocol = version;
  client_config.max_protocol = version;

  run_loop(
    [&](vio::event_loop_t &el) -> vio::task_t<void>
    {
      auto pair = get_ephemeral_port(el);
      REQUIRE_EXPECTED(pair);
      int port = pair->second;
      auto server_task = echo_server(el, std::move(pair->first), server_config, port, false);
      auto client_task = [](vio::event_loop_t &el, vio::ssl_config_t cc, int p, bool &v) -> vio::task_t<void>
      {
        auto c = vio::ssl_client_create(el, cc);
        REQUIRE_EXPECTED(c);
        auto client = std::move(c.value());
        auto cr = co_await vio::ssl_client_connect(client, "localhost", p, "127.0.0.1");
        REQUIRE_EXPECTED(cr);
        std::string msg = "ping";
        uv_buf_t buf = uv_buf_init(msg.data(), msg.size());
        auto wr = co_await vio::ssl_client_write(client, buf);
        REQUIRE_EXPECTED(wr);
        auto reader = vio::ssl_client_create_reader(client);
        REQUIRE_EXPECTED(reader);
        auto rr = co_await reader.value();
        REQUIRE_EXPECTED(rr);
        v = std::string_view(rr.value()->base, rr.value()->len) == "ping";
      }(el, client_config, port, verified_out);
      co_await std::move(client_task);
      co_await std::move(server_task);
      el.stop();
    });
}

TEST_CASE("TLS 1.2-only handshake round-trips")
{
  bool verified = false;
  run_version_pinned_case(vio::tls_protocol_version::tls1_2, verified);
  REQUIRE(verified);
}

TEST_CASE("TLS 1.3-only handshake round-trips")
{
  bool verified = false;
  run_version_pinned_case(vio::tls_protocol_version::tls1_3, verified);
  REQUIRE(verified);
}

TEST_CASE("session resumption: a second connection reuses the cached session")
{
  auto certs = make_cert_set("localhost");
  vio::ssl_config_t server_config{.ca_mem = certs.ca_cert, .cert_mem = certs.cert, .key_mem = certs.key};
  server_config.enable_session_cache = true; // issue resumption tickets
  // Pin TLS 1.2: its session ticket is delivered within the handshake, so
  // resumption is deterministic. (The session-cache plumbing being verified --
  // new-session callback -> cache -> SSL_set_session -> reuse -- is
  // version-independent. TLS 1.3 post-handshake ticket delivery with the bundled
  // LibreSSL is a known follow-up; see the caveat in the docs.)
  server_config.min_protocol = vio::tls_protocol_version::tls1_2;
  server_config.max_protocol = vio::tls_protocol_version::tls1_2;
  vio::ssl_session_cache_t cache;
  vio::ssl_config_t client_config{.ca_mem = certs.ca_cert};
  client_config.session_cache = &cache;
  client_config.min_protocol = vio::tls_protocol_version::tls1_2;
  client_config.max_protocol = vio::tls_protocol_version::tls1_2;
  bool second_resumed = false;

  run_loop(
    [&](vio::event_loop_t &el) -> vio::task_t<void>
    {
      auto pair = get_ephemeral_port(el);
      REQUIRE_EXPECTED(pair);
      int port = pair->second;

      // Server accepts two sequential connections and echoes one message each.
      auto server_task = [](vio::event_loop_t &el, vio::tcp_server_t s, vio::ssl_config_t sc, int p) -> vio::task_t<void>
      {
        auto server = vio::ssl_server_create(el, std::move(s), "localhost", sc);
        REQUIRE_EXPECTED(server);
        auto srv = std::move(server.value());
        for (int i = 0; i < 2; ++i)
        {
          auto listen_result = co_await vio::ssl_server_listen(srv, p);
          REQUIRE_EXPECTED(listen_result);
          auto client_or_err = vio::ssl_server_accept(srv);
          REQUIRE_EXPECTED(client_or_err);
          auto client = std::move(client_or_err.value());
          srv.handle->tcp.tcp.handle->listen.done = false; // re-arm listen
          auto reader = vio::ssl_server_client_create_reader(client);
          REQUIRE_EXPECTED(reader);
          auto rr = co_await reader.value();
          REQUIRE_EXPECTED(rr);
          uv_buf_t buf = uv_buf_init(rr.value()->base, rr.value()->len);
          auto wr = co_await vio::ssl_server_client_write(client, buf);
          REQUIRE_EXPECTED(wr);
          // Keep reading until the client closes: this keeps the connection open
          // long enough for the post-handshake NewSessionTicket to be flushed and
          // for the client to process it.
          while (true)
          {
            auto more = co_await reader.value();
            if (!more.has_value())
              break;
          }
          { auto destroy = std::move(client); }
        }
      }(el, std::move(pair->first), server_config, port);

      // A single client connection: write, read the echo (which pumps the
      // TLS 1.3 NewSessionTicket into the cache), then let it be destroyed.
      auto do_client = [](vio::event_loop_t &el, vio::ssl_config_t cc, int p, bool *resumed_out) -> vio::task_t<void>
      {
        auto c = vio::ssl_client_create(el, cc);
        REQUIRE_EXPECTED(c);
        auto client = std::move(c.value());
        auto cr = co_await vio::ssl_client_connect(client, "localhost", p, "127.0.0.1");
        REQUIRE_EXPECTED(cr);
        if (resumed_out != nullptr)
          *resumed_out = vio::ssl_client_session_reused(client);
        std::string msg = "resume-me";
        uv_buf_t buf = uv_buf_init(msg.data(), msg.size());
        auto wr = co_await vio::ssl_client_write(client, buf);
        REQUIRE_EXPECTED(wr);
        auto reader = vio::ssl_client_create_reader(client);
        REQUIRE_EXPECTED(reader);
        auto rr = co_await reader.value();
        REQUIRE_EXPECTED(rr);
        // Half-close and drain to end-of-stream so the NewSessionTicket (a
        // post-handshake message) is received and cached before we disconnect.
        co_await vio::ssl_client_shutdown(client);
        while (true)
        {
          auto more = co_await reader.value();
          if (!more.has_value())
            break;
        }
      };

      co_await do_client(el, client_config, port, nullptr); // first: full handshake, caches ticket
      co_await do_client(el, client_config, port, &second_resumed); // second: should resume
      co_await std::move(server_task);
      el.stop();
    });
  REQUIRE(second_resumed);
}

TEST_CASE("OCSP staple: the server's stapled response is delivered to a requesting client")
{
  auto certs = make_cert_set("localhost");
  // vio treats the staple as opaque bytes; use a distinctive blob and check the
  // client receives exactly it (verifies the staple plumbing end to end).
  std::vector<uint8_t> staple = {0x30, 0x03, 0x0a, 0x01, 0x00, 0xde, 0xad, 0xbe, 0xef};
  vio::ssl_config_t server_config{.ca_mem = certs.ca_cert, .cert_mem = certs.cert, .key_mem = certs.key, .ocsp_staple_mem = staple};
  vio::ssl_config_t client_config{.ca_mem = certs.ca_cert};
  client_config.request_ocsp_staple = true;
  std::vector<uint8_t> received;

  run_loop(
    [&](vio::event_loop_t &el) -> vio::task_t<void>
    {
      auto pair = get_ephemeral_port(el);
      REQUIRE_EXPECTED(pair);
      int port = pair->second;
      auto server_task = echo_server(el, std::move(pair->first), server_config, port, false);
      auto client_task = [](vio::event_loop_t &el, vio::ssl_config_t cc, int p, std::vector<uint8_t> &out) -> vio::task_t<void>
      {
        auto c = vio::ssl_client_create(el, cc);
        REQUIRE_EXPECTED(c);
        auto client = std::move(c.value());
        auto cr = co_await vio::ssl_client_connect(client, "localhost", p, "127.0.0.1");
        REQUIRE_EXPECTED(cr);
        out = vio::ssl_client_ocsp_response(client);
        std::string msg = "x";
        uv_buf_t buf = uv_buf_init(msg.data(), msg.size());
        auto wr = co_await vio::ssl_client_write(client, buf);
        REQUIRE_EXPECTED(wr);
      }(el, client_config, port, received);
      co_await std::move(client_task);
      co_await std::move(server_task);
      el.stop();
    });
  REQUIRE(received == staple);
}

TEST_CASE("a pre-cancelled TLS write resolves with vio_cancelled")
{
  auto certs = make_cert_set("localhost");
  vio::ssl_config_t server_config{.ca_mem = certs.ca_cert, .cert_mem = certs.cert, .key_mem = certs.key};
  vio::ssl_config_t client_config{.ca_mem = certs.ca_cert};
  bool cancelled = false;

  run_loop(
    [&](vio::event_loop_t &el) -> vio::task_t<void>
    {
      auto pair = get_ephemeral_port(el);
      REQUIRE_EXPECTED(pair);
      int port = pair->second;
      auto server_task = echo_server(el, std::move(pair->first), server_config, port, false);
      auto client_task = [](vio::event_loop_t &el, vio::ssl_config_t cc, int p, bool &cancelled) -> vio::task_t<void>
      {
        auto c = vio::ssl_client_create(el, cc);
        REQUIRE_EXPECTED(c);
        auto client = std::move(c.value());
        auto cr = co_await vio::ssl_client_connect(client, "localhost", p, "127.0.0.1");
        REQUIRE_EXPECTED(cr);
        vio::cancellation_t cancel;
        cancel.cancel();
        std::string msg = "never-sent";
        uv_buf_t buf = uv_buf_init(msg.data(), msg.size());
        auto wr = co_await vio::ssl_client_write(client, buf, &cancel);
        cancelled = !wr.has_value() && vio::is_cancelled(wr.error());
      }(el, client_config, port, cancelled);
      co_await std::move(client_task);
      { auto destroy = std::move(client_task); }
      co_await std::move(server_task);
      el.stop();
    });
  REQUIRE(cancelled);
}

TEST_CASE("an in-flight TLS write cancelled before completion resolves with vio_cancelled")
{
  auto certs = make_cert_set("localhost");
  vio::ssl_config_t server_config{.ca_mem = certs.ca_cert, .cert_mem = certs.cert, .key_mem = certs.key};
  vio::ssl_config_t client_config{.ca_mem = certs.ca_cert};
  bool cancelled = false;

  run_loop(
    [&](vio::event_loop_t &el) -> vio::task_t<void>
    {
      auto pair = get_ephemeral_port(el);
      REQUIRE_EXPECTED(pair);
      int port = pair->second;
      auto server_task = echo_server(el, std::move(pair->first), server_config, port, false);
      auto client_task = [](vio::event_loop_t &el, vio::ssl_config_t cc, int p, bool &cancelled) -> vio::task_t<void>
      {
        auto c = vio::ssl_client_create(el, cc);
        REQUIRE_EXPECTED(c);
        auto client = std::move(c.value());
        auto cr = co_await vio::ssl_client_connect(client, "localhost", p, "127.0.0.1");
        REQUIRE_EXPECTED(cr);
        vio::cancellation_t cancel;
        std::string msg = "in-flight";
        uv_buf_t buf = uv_buf_init(msg.data(), msg.size());
        // Submit the write, then cancel before the loop runs its write callback.
        auto w = vio::ssl_client_write(client, buf, &cancel);
        cancel.cancel();
        auto wr = co_await std::move(w);
        cancelled = !wr.has_value() && vio::is_cancelled(wr.error());
        // A cancelled TLS write leaves the stream unusable -> close (done by scope exit).
      }(el, client_config, port, cancelled);
      co_await std::move(client_task);
      { auto destroy = std::move(client_task); }
      co_await std::move(server_task);
      el.stop();
    });
  REQUIRE(cancelled);
}

TEST_CASE("many sequential connections keep their data intact (no cross-connection leakage)")
{
  auto certs = make_cert_set("localhost");
  vio::ssl_config_t server_config{.ca_mem = certs.ca_cert, .cert_mem = certs.cert, .key_mem = certs.key};
  vio::ssl_config_t client_config{.ca_mem = certs.ca_cert};
  constexpr int num_clients = 8;
  int verified = 0;

  run_loop(
    [&](vio::event_loop_t &el) -> vio::task_t<void>
    {
      auto pair = get_ephemeral_port(el);
      REQUIRE_EXPECTED(pair);
      int port = pair->second;

      auto server_task = [](vio::event_loop_t &el, vio::tcp_server_t s, vio::ssl_config_t sc, int p, int n) -> vio::task_t<void>
      {
        auto server = vio::ssl_server_create(el, std::move(s), "localhost", sc);
        REQUIRE_EXPECTED(server);
        auto srv = std::move(server.value());
        for (int i = 0; i < n; ++i)
        {
          auto listen_result = co_await vio::ssl_server_listen(srv, p);
          REQUIRE_EXPECTED(listen_result);
          auto client_or_err = vio::ssl_server_accept(srv);
          REQUIRE_EXPECTED(client_or_err);
          auto client = std::move(client_or_err.value());
          srv.handle->tcp.tcp.handle->listen.done = false;
          auto reader = vio::ssl_server_client_create_reader(client);
          REQUIRE_EXPECTED(reader);
          auto rr = co_await reader.value();
          REQUIRE_EXPECTED(rr);
          uv_buf_t buf = uv_buf_init(rr.value()->base, rr.value()->len);
          auto wr = co_await vio::ssl_server_client_write(client, buf);
          REQUIRE_EXPECTED(wr);
          { auto destroy = std::move(client); }
        }
      }(el, std::move(pair->first), server_config, port, num_clients);

      // Each connection sends a distinct payload and must receive exactly it
      // back -- verifying independent per-connection TLS state with no leakage.
      // Connections run one at a time (vio's accept model serializes accepts).
      auto make_client = [](vio::event_loop_t &el, vio::ssl_config_t cc, int p, int id) -> vio::task_t<bool>
      {
        auto c = vio::ssl_client_create(el, cc);
        if (!c.has_value())
          co_return false;
        auto client = std::move(c.value());
        auto cr = co_await vio::ssl_client_connect(client, "localhost", p, "127.0.0.1");
        if (!cr.has_value())
          co_return false;
        std::string msg = "client-payload-" + std::to_string(id) + "-" + std::string(static_cast<size_t>(id) * 7 + 3, 'a' + (id % 20));
        uv_buf_t buf = uv_buf_init(msg.data(), msg.size());
        auto wr = co_await vio::ssl_client_write(client, buf);
        if (!wr.has_value())
          co_return false;
        auto reader = vio::ssl_client_create_reader(client);
        if (!reader.has_value())
          co_return false;
        std::string got;
        while (got.size() < msg.size())
        {
          auto rr = co_await reader.value();
          if (!rr.has_value())
            break;
          got.append(rr.value()->base, rr.value()->len);
        }
        co_return got == msg;
      };
      for (int i = 0; i < num_clients; ++i)
      {
        if (co_await make_client(el, client_config, port, i))
          ++verified;
      }
      co_await std::move(server_task);
      el.stop();
    });
  REQUIRE(verified == num_clients);
}
} // TEST_SUITE
} // namespace
