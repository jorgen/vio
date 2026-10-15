/*
Copyright (c) 2025 Jørgen Lind

  Permission is hereby granted, free of charge, to any person obtaining a copy of
  this software and associated documentation files (the "Software"), to deal in
  the Software without restriction, including without limitation the rights to
  use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
  of the Software, and to permit persons to whom the Software is furnished to do
  so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
*/

// Deep, backend-agnostic TLS verification suite. Every test drives only the
// public vio API, so the same suite validates whichever VIO_SSL_BACKEND is
// compiled (LibreSSL today; OpenSSL 3.x / BoringSSL when wired). It exercises
// the security-critical behaviors: certificate verification (trust, hostname),
// mutual TLS, protocol-version pinning, session resumption, OCSP staple
// delivery, distinct close semantics, and concurrent-connection integrity.

#include <doctest/doctest.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <vio/event_loop.h>
#include <vio/operation/sleep.h>
#include <vio/operation/tcp.h>
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
    auto buf = std::span<const std::byte>(data.span());
    auto wr = co_await vio::ssl_server_client_write(client, buf);
    if (!wr.has_value())
      break;
  }
}

struct sink_result_t
{
  std::string data;
  int end_code = 0;
};

vio::task_t<void> sink_server(vio::event_loop_t &el, vio::tcp_server_t s, vio::ssl_config_t cfg, int port, sink_result_t &out)
{
  auto server = vio::ssl_server_create(el, std::move(s), "localhost", cfg);
  REQUIRE_EXPECTED(server);
  auto srv = std::move(server.value());
  auto listen_result = co_await vio::ssl_server_listen(srv, port);
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
      out.end_code = rr.error().code;
      break;
    }
    out.data.append(rr.value().chars(), rr.value().size());
  }
}

std::string make_pattern(std::size_t size, unsigned seed)
{
  std::string out(size, '\0');
  for (std::size_t i = 0; i < size; ++i)
    out[i] = static_cast<char>((i * 131 + seed * 7 + (i >> 12)) & 0xff);
  return out;
}

struct tls_pair_config_t
{
  vio::ssl_config_t server;
  vio::ssl_config_t client;
};

tls_pair_config_t make_pair_config()
{
  auto certs = make_cert_set("localhost");
  tls_pair_config_t out;
  out.server.ca_mem = certs.ca_cert;
  out.server.cert_mem = certs.cert;
  out.server.key_mem = certs.key;
  out.client.ca_mem = certs.ca_cert;
  return out;
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
        auto buf = std::as_bytes(std::span(msg));
        auto wr = co_await vio::ssl_client_write(client, buf);
        REQUIRE_EXPECTED(wr);
        auto reader = vio::ssl_client_create_reader(client);
        REQUIRE_EXPECTED(reader);
        auto rr = co_await reader.value();
        REQUIRE_EXPECTED(rr);
        ok = std::string_view(rr.value().chars(), rr.value().size()) == "mtls";
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
        auto buf = std::as_bytes(std::span(msg));
        auto wr = co_await vio::ssl_client_write(client, buf);
        REQUIRE_EXPECTED(wr);
        auto reader = vio::ssl_client_create_reader(client);
        REQUIRE_EXPECTED(reader);
        auto rr = co_await reader.value();
        REQUIRE_EXPECTED(rr);
        v = std::string_view(rr.value().chars(), rr.value().size()) == "ping";
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

// Both versions deliver a resumption ticket, at different points: 1.2 inside
// the handshake, 1.3 after it. The plumbing under test -- new-session callback
// -> cache -> SSL_set_session -> reuse -- is the same either way, and the loops
// below drain to end of stream so a post-handshake ticket arrives before the
// connection goes away. Separate cases rather than subcases: the body stands up
// a server and an event loop, which wants a clean process state each time.
static void check_session_resumption(vio::tls_protocol_version version)
{
  auto certs = make_cert_set("localhost");
  vio::ssl_config_t server_config{.ca_mem = certs.ca_cert, .cert_mem = certs.cert, .key_mem = certs.key};
  server_config.enable_session_cache = true; // issue resumption tickets
  server_config.min_protocol = version;
  server_config.max_protocol = version;
  vio::ssl_session_cache_t cache;
  vio::ssl_config_t client_config{.ca_mem = certs.ca_cert};
  client_config.session_cache = &cache;
  client_config.min_protocol = version;
  client_config.max_protocol = version;
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
          auto reader = vio::ssl_server_client_create_reader(client);
          REQUIRE_EXPECTED(reader);
          auto rr = co_await reader.value();
          REQUIRE_EXPECTED(rr);
          auto buf = std::span<const std::byte>(rr.value().span());
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
        auto buf = std::as_bytes(std::span(msg));
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

TEST_CASE("session resumption: TLS 1.2 carries the ticket in the handshake")
{
  check_session_resumption(vio::tls_protocol_version::tls1_2);
}

TEST_CASE("session resumption: TLS 1.3 sends the ticket after the handshake")
{
  check_session_resumption(vio::tls_protocol_version::tls1_3);
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
        auto buf = std::as_bytes(std::span(msg));
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
        auto buf = std::as_bytes(std::span(msg));
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
        auto buf = std::as_bytes(std::span(msg));
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
          auto reader = vio::ssl_server_client_create_reader(client);
          REQUIRE_EXPECTED(reader);
          auto rr = co_await reader.value();
          REQUIRE_EXPECTED(rr);
          auto buf = std::span<const std::byte>(rr.value().span());
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
        auto buf = std::as_bytes(std::span(msg));
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
          got.append(rr.value().chars(), rr.value().size());
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
TEST_CASE("a single write larger than the write high-water mark arrives intact")
{
  auto config = make_pair_config();
  const std::string payload = make_pattern(3 * 1024 * 1024 + 123, 7);
  sink_result_t sink;

  run_loop(
    [&](vio::event_loop_t &el) -> vio::task_t<void>
    {
      auto pair = get_ephemeral_port(el);
      REQUIRE_EXPECTED(pair);
      int port = pair->second;
      auto server_task = sink_server(el, std::move(pair->first), config.server, port, sink);
      auto client_task = [](vio::event_loop_t &el, vio::ssl_config_t cc, int p, const std::string &payload) -> vio::task_t<void>
      {
        auto c = vio::ssl_client_create(el, cc);
        REQUIRE_EXPECTED(c);
        auto client = std::move(c.value());
        auto cr = co_await vio::ssl_client_connect(client, "localhost", p, "127.0.0.1");
        REQUIRE_EXPECTED(cr);
        auto wr = co_await vio::ssl_client_write(client, std::as_bytes(std::span(payload)));
        REQUIRE_EXPECTED(wr);
        auto sh = co_await vio::ssl_client_shutdown(client);
        REQUIRE_EXPECTED(sh);
      }(el, config.client, port, payload);
      co_await std::move(client_task);
      { auto destroy = std::move(client_task); }
      co_await std::move(server_task);
      el.stop();
    });
  REQUIRE(sink.data.size() == payload.size());
  REQUIRE((sink.data == payload));
  REQUIRE(sink.end_code == vio::vio_tls_clean_shutdown);
}

TEST_CASE("writes queued behind the high-water mark keep their order")
{
  auto config = make_pair_config();
  const std::string big = make_pattern(4 * 1024 * 1024, 3);
  const std::string tail = "tail-marker";
  sink_result_t sink;

  run_loop(
    [&](vio::event_loop_t &el) -> vio::task_t<void>
    {
      auto pair = get_ephemeral_port(el);
      REQUIRE_EXPECTED(pair);
      int port = pair->second;
      auto server_task = sink_server(el, std::move(pair->first), config.server, port, sink);
      auto client_task = [](vio::event_loop_t &el, vio::ssl_config_t cc, int p, const std::string &big, const std::string &tail) -> vio::task_t<void>
      {
        auto c = vio::ssl_client_create(el, cc);
        REQUIRE_EXPECTED(c);
        auto client = std::move(c.value());
        auto cr = co_await vio::ssl_client_connect(client, "localhost", p, "127.0.0.1");
        REQUIRE_EXPECTED(cr);
        auto first = vio::ssl_client_write(client, std::as_bytes(std::span(big)));
        auto second = vio::ssl_client_write(client, std::as_bytes(std::span(tail)));
        auto r1 = co_await std::move(first);
        REQUIRE_EXPECTED(r1);
        auto r2 = co_await std::move(second);
        REQUIRE_EXPECTED(r2);
        auto sh = co_await vio::ssl_client_shutdown(client);
        REQUIRE_EXPECTED(sh);
      }(el, config.client, port, big, tail);
      co_await std::move(client_task);
      { auto destroy = std::move(client_task); }
      co_await std::move(server_task);
      el.stop();
    });
  REQUIRE(sink.data.size() == big.size() + tail.size());
  REQUIRE((sink.data == big + tail));
}

TEST_CASE("dropping a write before it completes still delivers its bytes from a private copy")
{
  auto config = make_pair_config();
  const std::string expected = make_pattern(6 * 1024 * 1024 + 17, 11);
  const std::string tail = "after-drop";
  sink_result_t sink;

  run_loop(
    [&](vio::event_loop_t &el) -> vio::task_t<void>
    {
      auto pair = get_ephemeral_port(el);
      REQUIRE_EXPECTED(pair);
      int port = pair->second;
      auto server_task = sink_server(el, std::move(pair->first), config.server, port, sink);
      auto client_task = [](vio::event_loop_t &el, vio::ssl_config_t cc, int p, const std::string &expected, const std::string &tail) -> vio::task_t<void>
      {
        auto c = vio::ssl_client_create(el, cc);
        REQUIRE_EXPECTED(c);
        auto client = std::move(c.value());
        auto cr = co_await vio::ssl_client_connect(client, "localhost", p, "127.0.0.1");
        REQUIRE_EXPECTED(cr);
        auto payload = std::make_unique<std::string>(expected);
        {
          auto dropped = vio::ssl_client_write(client, std::as_bytes(std::span(*payload)));
        }
        std::fill(payload->begin(), payload->end(), '\0');
        payload.reset();
        auto wr = co_await vio::ssl_client_write(client, std::as_bytes(std::span(tail)));
        REQUIRE_EXPECTED(wr);
        auto sh = co_await vio::ssl_client_shutdown(client);
        REQUIRE_EXPECTED(sh);
      }(el, config.client, port, expected, tail);
      co_await std::move(client_task);
      { auto destroy = std::move(client_task); }
      co_await std::move(server_task);
      el.stop();
    });
  REQUIRE(sink.data.size() == expected.size() + tail.size());
  REQUIRE((sink.data == expected + tail));
}

TEST_CASE("a client dropped with unflushed writes delivers them, then close_notify")
{
  auto config = make_pair_config();
  const std::string expected = make_pattern(8 * 1024 * 1024 + 5, 19);
  sink_result_t sink;

  run_loop(
    [&](vio::event_loop_t &el) -> vio::task_t<void>
    {
      auto pair = get_ephemeral_port(el);
      REQUIRE_EXPECTED(pair);
      int port = pair->second;
      auto server_task = sink_server(el, std::move(pair->first), config.server, port, sink);
      auto client_task = [](vio::event_loop_t &el, vio::ssl_config_t cc, int p, const std::string &expected) -> vio::task_t<void>
      {
        auto c = vio::ssl_client_create(el, cc);
        REQUIRE_EXPECTED(c);
        auto client = std::move(c.value());
        auto cr = co_await vio::ssl_client_connect(client, "localhost", p, "127.0.0.1");
        REQUIRE_EXPECTED(cr);
        auto dropped = vio::ssl_client_write(client, std::as_bytes(std::span(expected)));
      }(el, config.client, port, expected);
      co_await std::move(client_task);
      { auto destroy = std::move(client_task); }
      co_await std::move(server_task);
      el.stop();
    });
  REQUIRE(sink.data.size() == expected.size());
  REQUIRE((sink.data == expected));
  REQUIRE(sink.end_code == vio::vio_tls_clean_shutdown);
}

TEST_CASE("a client dropped right after a write sends close_notify")
{
  auto config = make_pair_config();
  sink_result_t sink;

  run_loop(
    [&](vio::event_loop_t &el) -> vio::task_t<void>
    {
      auto pair = get_ephemeral_port(el);
      REQUIRE_EXPECTED(pair);
      int port = pair->second;
      auto server_task = sink_server(el, std::move(pair->first), config.server, port, sink);
      auto client_task = [](vio::event_loop_t &el, vio::ssl_config_t cc, int p) -> vio::task_t<void>
      {
        auto c = vio::ssl_client_create(el, cc);
        REQUIRE_EXPECTED(c);
        auto client = std::move(c.value());
        auto cr = co_await vio::ssl_client_connect(client, "localhost", p, "127.0.0.1");
        REQUIRE_EXPECTED(cr);
        std::string msg = "bye";
        auto wr = co_await vio::ssl_client_write(client, std::as_bytes(std::span(msg)));
        REQUIRE_EXPECTED(wr);
      }(el, config.client, port);
      co_await std::move(client_task);
      { auto destroy = std::move(client_task); }
      co_await std::move(server_task);
      el.stop();
    });
  REQUIRE(sink.data == "bye");
  REQUIRE(sink.end_code == vio::vio_tls_clean_shutdown);
}

TEST_CASE("a zero-length write resolves at once")
{
  auto config = make_pair_config();
  sink_result_t sink;
  bool empty_ok = false;

  run_loop(
    [&](vio::event_loop_t &el) -> vio::task_t<void>
    {
      auto pair = get_ephemeral_port(el);
      REQUIRE_EXPECTED(pair);
      int port = pair->second;
      auto server_task = sink_server(el, std::move(pair->first), config.server, port, sink);
      auto client_task = [](vio::event_loop_t &el, vio::ssl_config_t cc, int p, bool &empty_ok) -> vio::task_t<void>
      {
        auto c = vio::ssl_client_create(el, cc);
        REQUIRE_EXPECTED(c);
        auto client = std::move(c.value());
        auto cr = co_await vio::ssl_client_connect(client, "localhost", p, "127.0.0.1");
        REQUIRE_EXPECTED(cr);
        auto empty = vio::ssl_client_write(client, std::span<const std::byte>{});
        empty_ok = empty.await_ready();
        auto er = co_await std::move(empty);
        REQUIRE_EXPECTED(er);
        std::string msg = "x";
        auto wr = co_await vio::ssl_client_write(client, msg.data(), msg.size());
        REQUIRE_EXPECTED(wr);
        auto sh = co_await vio::ssl_client_shutdown(client);
        REQUIRE_EXPECTED(sh);
      }(el, config.client, port, empty_ok);
      co_await std::move(client_task);
      { auto destroy = std::move(client_task); }
      co_await std::move(server_task);
      el.stop();
    });
  REQUIRE(empty_ok);
  REQUIRE(sink.data == "x");
}

TEST_CASE("exact reads take part of a queued chunk and a plain read gets the rest")
{
  auto config = make_pair_config();
  const std::string payload = make_pattern(100, 23);
  std::string received;

  run_loop(
    [&](vio::event_loop_t &el) -> vio::task_t<void>
    {
      auto pair = get_ephemeral_port(el);
      REQUIRE_EXPECTED(pair);
      int port = pair->second;
      auto server_task = [](vio::event_loop_t &el, vio::tcp_server_t s, vio::ssl_config_t sc, int p, const std::string &payload) -> vio::task_t<void>
      {
        auto server = vio::ssl_server_create(el, std::move(s), "localhost", sc);
        REQUIRE_EXPECTED(server);
        auto srv = std::move(server.value());
        auto listen_result = co_await vio::ssl_server_listen(srv, p);
        REQUIRE_EXPECTED(listen_result);
        auto client_or_err = vio::ssl_server_accept(srv);
        REQUIRE_EXPECTED(client_or_err);
        auto client = std::move(client_or_err.value());
        auto wr = co_await vio::ssl_server_client_write(client, std::as_bytes(std::span(payload)));
        REQUIRE_EXPECTED(wr);
        auto reader = vio::ssl_server_client_create_reader(client);
        REQUIRE_EXPECTED(reader);
        while ((co_await reader.value()).has_value())
        {
        }
      }(el, std::move(pair->first), config.server, port, payload);
      auto client_task = [](vio::event_loop_t &el, vio::ssl_config_t cc, int p, std::string &received) -> vio::task_t<void>
      {
        auto c = vio::ssl_client_create(el, cc);
        REQUIRE_EXPECTED(c);
        auto client = std::move(c.value());
        auto cr = co_await vio::ssl_client_connect(client, "localhost", p, "127.0.0.1");
        REQUIRE_EXPECTED(cr);
        auto reader_or_err = vio::ssl_client_create_reader(client);
        REQUIRE_EXPECTED(reader_or_err);
        auto reader = std::move(reader_or_err.value());
        co_await vio::sleep(el, std::chrono::milliseconds(50));
        std::array<char, 10> first{};
        auto r1 = co_await reader.read(std::as_writable_bytes(std::span(first)));
        REQUIRE_EXPECTED(r1);
        REQUIRE(r1->size() == first.size());
        std::array<char, 20> second{};
        auto r2 = co_await reader.read(std::as_writable_bytes(std::span(second)));
        REQUIRE_EXPECTED(r2);
        received.append(first.data(), first.size());
        received.append(second.data(), second.size());
        while (received.size() < 100)
        {
          auto rest = co_await reader;
          REQUIRE_EXPECTED(rest);
          received.append(rest.value().chars(), rest.value().size());
        }
      }(el, config.client, port, received);
      co_await std::move(client_task);
      { auto destroy = std::move(client_task); }
      co_await std::move(server_task);
      el.stop();
    });
  REQUIRE(received == payload);
}

TEST_CASE("an exact read larger than many records completes")
{
  auto config = make_pair_config();
  const std::string payload = make_pattern(2 * 1024 * 1024 + 9, 29);
  std::vector<char> received(payload.size());
  bool done = false;

  run_loop(
    [&](vio::event_loop_t &el) -> vio::task_t<void>
    {
      auto pair = get_ephemeral_port(el);
      REQUIRE_EXPECTED(pair);
      int port = pair->second;
      auto server_task = [](vio::event_loop_t &el, vio::tcp_server_t s, vio::ssl_config_t sc, int p, const std::string &payload) -> vio::task_t<void>
      {
        auto server = vio::ssl_server_create(el, std::move(s), "localhost", sc);
        REQUIRE_EXPECTED(server);
        auto srv = std::move(server.value());
        auto listen_result = co_await vio::ssl_server_listen(srv, p);
        REQUIRE_EXPECTED(listen_result);
        auto client_or_err = vio::ssl_server_accept(srv);
        REQUIRE_EXPECTED(client_or_err);
        auto client = std::move(client_or_err.value());
        auto wr = co_await vio::ssl_server_client_write(client, std::as_bytes(std::span(payload)));
        REQUIRE_EXPECTED(wr);
        auto reader = vio::ssl_server_client_create_reader(client);
        REQUIRE_EXPECTED(reader);
        while ((co_await reader.value()).has_value())
        {
        }
      }(el, std::move(pair->first), config.server, port, payload);
      auto client_task = [](vio::event_loop_t &el, vio::ssl_config_t cc, int p, std::vector<char> &received, bool &done) -> vio::task_t<void>
      {
        auto c = vio::ssl_client_create(el, cc);
        REQUIRE_EXPECTED(c);
        auto client = std::move(c.value());
        auto cr = co_await vio::ssl_client_connect(client, "localhost", p, "127.0.0.1");
        REQUIRE_EXPECTED(cr);
        auto reader_or_err = vio::ssl_client_create_reader(client);
        REQUIRE_EXPECTED(reader_or_err);
        auto reader = std::move(reader_or_err.value());
        auto r = co_await reader.read(std::as_writable_bytes(std::span(received)));
        REQUIRE_EXPECTED(r);
        done = r->size() == received.size();
      }(el, config.client, port, received, done);
      co_await std::move(client_task);
      { auto destroy = std::move(client_task); }
      co_await std::move(server_task);
      el.stop();
    });
  REQUIRE(done);
  REQUIRE((std::string_view(received.data(), received.size()) == payload));
}

TEST_CASE("cancelling the reader resolves a pending exact read")
{
  auto config = make_pair_config();
  sink_result_t sink;
  int code = 0;

  run_loop(
    [&](vio::event_loop_t &el) -> vio::task_t<void>
    {
      auto pair = get_ephemeral_port(el);
      REQUIRE_EXPECTED(pair);
      int port = pair->second;
      auto server_task = sink_server(el, std::move(pair->first), config.server, port, sink);
      auto client_task = [](vio::event_loop_t &el, vio::ssl_config_t cc, int p, int &code) -> vio::task_t<void>
      {
        auto c = vio::ssl_client_create(el, cc);
        REQUIRE_EXPECTED(c);
        auto client = std::move(c.value());
        auto cr = co_await vio::ssl_client_connect(client, "localhost", p, "127.0.0.1");
        REQUIRE_EXPECTED(cr);
        auto reader_or_err = vio::ssl_client_create_reader(client);
        REQUIRE_EXPECTED(reader_or_err);
        auto reader = std::move(reader_or_err.value());
        std::array<std::byte, 64> buffer{};
        auto pending = [](vio::tls_client_reader_t &reader, std::span<std::byte> buffer, int &code) -> vio::task_t<void>
        {
          auto r = co_await reader.read(buffer);
          code = r.has_value() ? 0 : r.error().code;
        }(reader, buffer, code);
        co_await vio::sleep(el, std::chrono::milliseconds(20));
        reader.cancel();
        co_await std::move(pending);
      }(el, config.client, port, code);
      co_await std::move(client_task);
      { auto destroy = std::move(client_task); }
      co_await std::move(server_task);
      el.stop();
    });
  REQUIRE(code == vio::errc::canceled);
}

TEST_CASE("connect resolves a host name on the blocking pool")
{
  auto config = make_pair_config();
  sink_result_t sink;

  run_loop(
    [&](vio::event_loop_t &el) -> vio::task_t<void>
    {
      auto pair = get_ephemeral_port(el);
      REQUIRE_EXPECTED(pair);
      int port = pair->second;
      auto server_task = sink_server(el, std::move(pair->first), config.server, port, sink);
      auto client_task = [](vio::event_loop_t &el, vio::ssl_config_t cc, int p) -> vio::task_t<void>
      {
        auto c = vio::ssl_client_create(el, cc);
        REQUIRE_EXPECTED(c);
        auto client = std::move(c.value());
        auto cr = co_await vio::ssl_client_connect(client, "localhost", static_cast<uint16_t>(p));
        REQUIRE_EXPECTED(cr);
        REQUIRE(vio::ssl_client_peer_ip(client) == "127.0.0.1");
        std::string msg = "named";
        auto wr = co_await vio::ssl_client_write(client, std::as_bytes(std::span(msg)));
        REQUIRE_EXPECTED(wr);
        auto sh = co_await vio::ssl_client_shutdown(client);
        REQUIRE_EXPECTED(sh);
      }(el, config.client, port);
      co_await std::move(client_task);
      { auto destroy = std::move(client_task); }
      co_await std::move(server_task);
      el.stop();
    });
  REQUIRE(sink.data == "named");
}

TEST_CASE("connecting to a closed port fails with connection_refused")
{
  auto config = make_pair_config();
  int code = 0;

  run_loop(
    [&](vio::event_loop_t &el) -> vio::task_t<void>
    {
      int port = 0;
      {
        auto pair = get_ephemeral_port(el);
        REQUIRE_EXPECTED(pair);
        port = pair->second;
      }
      co_await vio::sleep(el, std::chrono::milliseconds(1));
      auto c = vio::ssl_client_create(el, config.client);
      REQUIRE_EXPECTED(c);
      {
        auto client = std::move(c.value());
        auto cr = co_await vio::ssl_client_connect(client, "localhost", static_cast<uint16_t>(port), "127.0.0.1");
        REQUIRE_FALSE(cr.has_value());
        code = cr.error().code;
      }
      el.stop();
    });
  REQUIRE(code == vio::errc::connection_refused);
}

TEST_CASE("upgrading a socket that is not connected fails")
{
  auto config = make_pair_config();
  int code = 0;

  run_loop(
    [&](vio::event_loop_t &el) -> vio::task_t<void>
    {
      {
        auto tcp = vio::tcp_create(el);
        REQUIRE_EXPECTED(tcp);
        auto upgraded = co_await vio::ssl_client_upgrade(std::move(tcp.value()), config.client, "localhost");
        REQUIRE_FALSE(upgraded.has_value());
        code = upgraded.error().code;
      }
      el.stop();
    });
  REQUIRE(code == vio::errc::not_connected);
}
} // TEST_SUITE
} // namespace
