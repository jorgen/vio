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

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <memory>
#include <optional>
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

vio::task_t<void> watchdog(vio::event_loop_t &el, vio::cancellation_t &target, vio::cancellation_t &stop)
{
  auto slept = co_await vio::sleep(el, std::chrono::seconds(3), &stop);
  if (slept.has_value())
    target.cancel();
}

vio::task_t<void> hold_until_closed(vio::tcp_server_t s)
{
  auto server = std::move(s);
  auto listened = co_await vio::tcp_listen(server, 4);
  REQUIRE_EXPECTED(listened);
  auto accepted = vio::tcp_accept(server);
  REQUIRE_EXPECTED(accepted);
  auto connection = std::move(accepted.value());
  auto reader = vio::tcp_create_reader(connection);
  REQUIRE_EXPECTED(reader);
  for (;;)
  {
    auto chunk = co_await reader.value();
    if (!chunk.has_value())
      break;
  }
}

bool pump_handshake(vio::ssl_engine_t &client, vio::ssl_engine_t &server)
{
  for (int round = 0; round < 16; ++round)
  {
    client.do_handshake();
    auto to_server = client.pending_output();
    if (!server.feed_ciphertext(reinterpret_cast<const char *>(to_server.data()), to_server.size()))
      return false;
    client.consume_output(to_server.size());
    server.do_handshake();
    auto to_client = server.pending_output();
    if (!client.feed_ciphertext(reinterpret_cast<const char *>(to_client.data()), to_client.size()))
      return false;
    server.consume_output(to_client.size());
    if (client.is_init_finished() && server.is_init_finished())
      return true;
  }
  return false;
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

namespace
{
void shrink_socket_buffers(vio::detail::socket_resource_t &socket)
{
  int size = 64 * 1024;
  REQUIRE(vio::detail::socket_set_option(socket.native(), SOL_SOCKET, SO_SNDBUF, &size, static_cast<int>(sizeof(size))) == 0);
  REQUIRE(vio::detail::socket_set_option(socket.native(), SOL_SOCKET, SO_RCVBUF, &size, static_cast<int>(sizeof(size))) == 0);
}

vio::task_t<void> lingering_tls_server(vio::event_loop_t &el, vio::tcp_server_t s, vio::ssl_config_t cfg, int port, const std::string &payload)
{
  auto server = vio::ssl_server_create(el, std::move(s), "localhost", cfg);
  REQUIRE_EXPECTED(server);
  auto srv = std::move(server.value());
  auto listened = co_await vio::ssl_server_listen(srv, port);
  REQUIRE_EXPECTED(listened);
  auto accepted = vio::ssl_server_accept(srv);
  REQUIRE_EXPECTED(accepted);
  auto client = std::move(accepted.value());
  auto handshake = co_await vio::ssl_server_client_handshake(client);
  REQUIRE_EXPECTED(handshake);
  shrink_socket_buffers(client.handle->tcp.handle->socket);
  auto dropped = vio::ssl_server_client_write(client, std::as_bytes(std::span(payload)));
}

vio::task_t<void> lingering_tls_client(vio::event_loop_t &el, vio::ssl_config_t cc, int port, const std::string &payload)
{
  auto created = vio::ssl_client_create(el, cc);
  REQUIRE_EXPECTED(created);
  auto client = std::move(created.value());
  auto connected = co_await vio::ssl_client_connect(client, "localhost", port, "127.0.0.1");
  REQUIRE_EXPECTED(connected);
  shrink_socket_buffers(client.state->tcp.handle->socket);
  auto dropped = vio::ssl_client_write(client, std::as_bytes(std::span(payload)));
}
} // namespace

TEST_CASE("two TLS ends dropped with writes queued drain each other instead of waiting out the linger")
{
  auto config = make_pair_config();
  const std::string payload = make_pattern(4 * 1024 * 1024, 23);
  auto started = std::chrono::steady_clock::now();

  run_loop(
    [&](vio::event_loop_t &el) -> vio::task_t<void>
    {
      auto pair = get_ephemeral_port(el);
      REQUIRE_EXPECTED(pair);
      int port = pair->second;
      auto server_task = lingering_tls_server(el, std::move(pair->first), config.server, port, payload);
      auto client_task = lingering_tls_client(el, config.client, port, payload);
      co_await std::move(client_task);
      co_await std::move(server_task);
      el.stop();
    });
  auto elapsed = std::chrono::steady_clock::now() - started;
  CHECK(elapsed < std::chrono::seconds(5));
}

namespace
{
vio::task_t<void> read_to_end_then_send_raw(vio::event_loop_t &el, vio::ssl_config_t cc, int port, std::size_t &received, int &end_code, int &late_writes,
                                            std::chrono::steady_clock::time_point &peer_closed)
{
  {
    auto created = vio::ssl_client_create(el, cc);
    REQUIRE_EXPECTED(created);
    auto client = std::move(created.value());
    auto connected = co_await vio::ssl_client_connect(client, "localhost", port, "127.0.0.1");
    REQUIRE_EXPECTED(connected);
    {
      auto reader = vio::ssl_client_create_reader(client);
      REQUIRE_EXPECTED(reader);
      for (;;)
      {
        auto chunk = co_await reader.value();
        if (!chunk.has_value())
        {
          end_code = chunk.error().code;
          break;
        }
        received += chunk->size();
      }
    }
    auto native = client.state->tcp.handle->socket.native();
    std::array<std::byte, 1024> junk{};
    for (int i = 0; i < 3; ++i)
    {
      late_writes += int(vio::detail::socket_send(native, junk) == static_cast<std::int64_t>(junk.size()));
      [[maybe_unused]] auto slept = co_await vio::sleep(el, std::chrono::milliseconds(20));
    }
  }
  peer_closed = std::chrono::steady_clock::now();
}
} // namespace

TEST_CASE("a lingering TLS end sends its end of stream and stays open until the peer closes")
{
  auto config = make_pair_config();
  const std::string payload = make_pattern(4 * 1024 * 1024, 29);
  std::size_t received = 0;
  int end_code = 0;
  int late_writes = 0;
  std::chrono::steady_clock::time_point peer_closed;

  run_loop(
    [&](vio::event_loop_t &el) -> vio::task_t<void>
    {
      auto pair = get_ephemeral_port(el);
      REQUIRE_EXPECTED(pair);
      int port = pair->second;
      auto server_task = lingering_tls_server(el, std::move(pair->first), config.server, port, payload);
      auto client_task = read_to_end_then_send_raw(el, config.client, port, received, end_code, late_writes, peer_closed);
      co_await std::move(client_task);
      co_await std::move(server_task);
      el.stop();
    });
  auto linger_after_peer = std::chrono::steady_clock::now() - peer_closed;
  CHECK(received == payload.size());
  CHECK(end_code == vio::vio_tls_clean_shutdown);
  CHECK(late_writes == 3);
  CHECK(linger_after_peer < std::chrono::seconds(1));
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

TEST_CASE("a client whose handshake failed refuses to connect again instead of hanging")
{
  auto config = make_pair_config();
  int first_code = 0;
  int retry_code = 0;
  std::chrono::steady_clock::duration retry_time{};

  run_loop(
    [&](vio::event_loop_t &el) -> vio::task_t<void>
    {
      auto pair = get_ephemeral_port(el);
      REQUIRE_EXPECTED(pair);
      int port = pair->second;
      auto server_task = [](vio::tcp_server_t s) -> vio::task_t<void>
      {
        auto server = std::move(s);
        auto listened = co_await vio::tcp_listen(server, 4);
        REQUIRE_EXPECTED(listened);
        auto accepted = vio::tcp_accept(server);
        REQUIRE_EXPECTED(accepted);
      }(std::move(pair->first));
      {
        auto c = vio::ssl_client_create(el, config.client);
        REQUIRE_EXPECTED(c);
        auto client = std::move(c.value());
        auto first = co_await vio::ssl_client_connect(client, "localhost", static_cast<uint16_t>(port), "127.0.0.1");
        REQUIRE_FALSE(first.has_value());
        first_code = first.error().code;
        vio::cancellation_t guard;
        vio::cancellation_t stop;
        auto dog = watchdog(el, guard, stop);
        auto started = std::chrono::steady_clock::now();
        auto retry = co_await vio::ssl_client_connect(client, "localhost", static_cast<uint16_t>(port), "127.0.0.1", &guard);
        retry_time = std::chrono::steady_clock::now() - started;
        stop.cancel();
        co_await std::move(dog);
        REQUIRE_FALSE(retry.has_value());
        retry_code = retry.error().code;
      }
      co_await std::move(server_task);
      el.stop();
    });
  CHECK(first_code != 0);
  CHECK(retry_code == vio::errc::already_connected);
  CHECK(retry_time < std::chrono::seconds(1));
}

TEST_CASE("a client cancelled mid-handshake stops the handshake and refuses to connect again")
{
  auto config = make_pair_config();
  int first_code = 0;
  int pending_code = -1;
  int retry_code = 0;
  int write_code = 0;

  run_loop(
    [&](vio::event_loop_t &el) -> vio::task_t<void>
    {
      auto pair = get_ephemeral_port(el);
      REQUIRE_EXPECTED(pair);
      int port = pair->second;
      auto server_task = hold_until_closed(std::move(pair->first));
      {
        auto c = vio::ssl_client_create(el, config.client);
        REQUIRE_EXPECTED(c);
        auto client = std::move(c.value());
        vio::cancellation_t cancel;
        vio::cancellation_t guard;
        vio::cancellation_t stop;
        auto dog = watchdog(el, guard, stop);
        auto connecting = vio::ssl_client_connect(client, "localhost", static_cast<uint16_t>(port), "127.0.0.1", &cancel);
        auto canceller = [](vio::event_loop_t &el, vio::ssl_client_t &client, vio::cancellation_t &cancel, vio::cancellation_t &guard, int &pending_code) -> vio::task_t<void>
        {
          co_await vio::sleep(el, std::chrono::milliseconds(50));
          const std::string early = "early";
          auto writer = [](vio::tls_client_write_awaitable_t write, int &code) -> vio::task_t<void>
          {
            auto result = co_await std::move(write);
            code = result.has_value() ? 0 : result.error().code;
          }(vio::ssl_client_write(client, std::as_bytes(std::span(early)), &guard), pending_code);
          cancel.cancel();
          co_await std::move(writer);
        }(el, client, cancel, guard, pending_code);
        auto first = co_await std::move(connecting);
        co_await std::move(canceller);
        REQUIRE_FALSE(first.has_value());
        first_code = first.error().code;

        auto retry = co_await vio::ssl_client_connect(client, "localhost", static_cast<uint16_t>(port), "127.0.0.1", &guard);
        REQUIRE_FALSE(retry.has_value());
        retry_code = retry.error().code;
        std::string msg = "x";
        auto written = co_await vio::ssl_client_write(client, std::as_bytes(std::span(msg)), &guard);
        REQUIRE_FALSE(written.has_value());
        write_code = written.error().code;
        stop.cancel();
        co_await std::move(dog);
      }
      co_await std::move(server_task);
      el.stop();
    });
  CHECK(first_code == vio::vio_cancelled);
  CHECK(pending_code == vio::errc::not_connected);
  CHECK(retry_code == vio::errc::already_connected);
  CHECK(write_code == vio::errc::not_connected);
}

TEST_CASE("a write that finished while awaited keeps its result when its token fires before it resumes")
{
  auto config = make_pair_config();
  sink_result_t sink;
  bool first_ok = false;
  int second_code = -1;

  run_loop(
    [&](vio::event_loop_t &el) -> vio::task_t<void>
    {
      auto pair = get_ephemeral_port(el);
      REQUIRE_EXPECTED(pair);
      int port = pair->second;
      auto server_task = sink_server(el, std::move(pair->first), config.server, port, sink);
      {
        auto tcp = vio::tcp_create(el);
        REQUIRE_EXPECTED(tcp);
        auto address = vio::ip4_addr("127.0.0.1", port);
        REQUIRE_EXPECTED(address);
        auto connected_tcp = co_await vio::tcp_connect(tcp.value(), reinterpret_cast<const sockaddr *>(&address.value()));
        REQUIRE_EXPECTED(connected_tcp);
        const std::string first_text = "bbb";
        const std::string second_text = "aaa";
        auto upgrade = vio::ssl_client_upgrade(std::move(tcp.value()), config.client, "localhost");
        auto first = vio::ssl_client_write(upgrade.client, std::as_bytes(std::span(first_text)));
        vio::cancellation_t token;
        auto second = vio::ssl_client_write(upgrade.client, std::as_bytes(std::span(second_text)), &token);
        auto canceller = [](vio::tls_client_write_awaitable_t write, vio::cancellation_t &token, bool &ok) -> vio::task_t<void>
        {
          auto result = co_await std::move(write);
          ok = result.has_value();
          token.cancel();
        }(std::move(first), token, first_ok);
        auto victim = [](vio::tls_client_write_awaitable_t write, int &code) -> vio::task_t<void>
        {
          auto result = co_await std::move(write);
          code = result.has_value() ? 0 : result.error().code;
        }(std::move(second), second_code);
        auto connected = co_await std::move(upgrade);
        REQUIRE_EXPECTED(connected);
        co_await std::move(canceller);
        co_await std::move(victim);
        auto client = std::move(connected.value());
        auto closed = co_await vio::ssl_client_shutdown(client);
        REQUIRE_EXPECTED(closed);
      }
      co_await std::move(server_task);
      el.stop();
    });
  CHECK(first_ok);
  CHECK(second_code == 0);
  CHECK(sink.data == "bbbaaa");
}

TEST_CASE("an emptied inbound buffer is kept for the next read instead of freed")
{
  auto &pool = vio::detail::ssl_inbound_pool();
  while (pool.size() > 0)
  {
    [[maybe_unused]] auto dropped = pool.take();
  }
  vio::ssl_engine_t engine;
  auto space = engine.inbound_space(vio::ssl_engine_t::inbound_capacity);
  REQUIRE(space.size() == vio::ssl_engine_t::inbound_capacity);
  auto *buffer = space.data();
  auto pooled = pool.size();
  engine.release_inbound_if_empty();
  CHECK(pool.size() == pooled + 1);
  vio::ssl_engine_t next;
  auto reused = next.inbound_space(vio::ssl_engine_t::inbound_capacity);
  CHECK(reused.data() == buffer);
}

TEST_CASE("a drained output buffer leaves the idle connection and is reused for the next write slice")
{
  auto &pool = vio::detail::ssl_output_pool();
  while (pool.size() > 0)
  {
    [[maybe_unused]] auto dropped = pool.take();
  }
  auto config = make_pair_config();
  vio::ssl_context_t server_context;
  REQUIRE(server_context.init(true, config.server, std::string{}).code == 0);
  vio::ssl_context_t client_context;
  REQUIRE(client_context.init(false, config.client, std::string{}).code == 0);
  vio::ssl_engine_t server;
  REQUIRE(server.init(server_context, true, std::string{}).code == 0);
  vio::ssl_engine_t client;
  REQUIRE(client.init(client_context, false, "localhost").code == 0);
  REQUIRE(pump_handshake(client, server));
  CHECK(client.output_capacity() == 0);
  CHECK(server.output_capacity() == 0);
  while (pool.size() > 0)
  {
    [[maybe_unused]] auto dropped = pool.take();
  }

  const std::string slice(vio::tls_stream_t::write_slice, 's');
  auto write_slice = [&] {
    client.reserve_output(slice.size() + slice.size() / 16 + 1024);
    int written = 0;
    REQUIRE(client.write_plaintext(slice.data(), static_cast<int>(slice.size()), written) == vio::ssl_status::ok);
    REQUIRE(written == static_cast<int>(slice.size()));
    return client.pending_output().data();
  };
  auto *first = write_slice();
  client.consume_output(client.output_size());
  CHECK(client.output_capacity() == 0);
  CHECK(pool.size() == 1);
  std::vector<std::byte> other(vio::ssl_engine_t::output_retain);
  auto *second = write_slice();
  CHECK(first == second);
  CHECK(pool.size() == 0);
  CHECK(other.size() == vio::ssl_engine_t::output_retain);
  client.consume_output(client.output_size());
  CHECK(pool.size() == 1);

  const std::string brief = "a short response";
  client.reserve_output(brief.size() + brief.size() / 16 + 1024);
  int written = 0;
  REQUIRE(client.write_plaintext(brief.data(), static_cast<int>(brief.size()), written) == vio::ssl_status::ok);
  CHECK(client.pending_output().data() == first);
  client.consume_output(client.output_size());
  CHECK(client.output_capacity() == 0);
  CHECK(pool.size() == 1);
}

namespace
{
std::vector<std::byte> output_sized_buffer()
{
  std::vector<std::byte> buffer;
  buffer.reserve(vio::ssl_engine_t::output_retain);
  return buffer;
}

void seed_output_pool(std::size_t count)
{
  auto &pool = vio::detail::ssl_output_pool();
  while (pool.size() > 0)
  {
    [[maybe_unused]] auto dropped = pool.take();
  }
  for (std::size_t i = 0; i < count; ++i)
  {
    pool.give(output_sized_buffer());
  }
  pool.trim();
}
} // namespace

TEST_CASE("warm writes on more than four connections at once take every output buffer from the pool")
{
  auto &pool = vio::detail::ssl_output_pool();
  while (pool.size() > 0)
  {
    [[maybe_unused]] auto dropped = pool.take();
  }
  auto config = make_pair_config();
  vio::ssl_context_t server_context;
  REQUIRE(server_context.init(true, config.server, std::string{}).code == 0);
  vio::ssl_context_t client_context;
  REQUIRE(client_context.init(false, config.client, std::string{}).code == 0);
  constexpr std::size_t connections = 3 * vio::detail::ssl_output_pool_t::spare_floor;
  std::vector<std::unique_ptr<vio::ssl_engine_t>> clients;
  std::vector<std::unique_ptr<vio::ssl_engine_t>> servers;
  for (std::size_t i = 0; i < connections; ++i)
  {
    clients.push_back(std::make_unique<vio::ssl_engine_t>());
    servers.push_back(std::make_unique<vio::ssl_engine_t>());
    REQUIRE(clients.back()->init(client_context, false, "localhost").code == 0);
    REQUIRE(servers.back()->init(server_context, true, std::string{}).code == 0);
    REQUIRE(pump_handshake(*clients.back(), *servers.back()));
  }
  auto write_all = [&](const std::string &bytes) {
    for (auto &client : clients)
    {
      client->reserve_output(bytes.size() + bytes.size() / 16 + 1024);
      int written = 0;
      REQUIRE(client->write_plaintext(bytes.data(), static_cast<int>(bytes.size()), written) == vio::ssl_status::ok);
    }
  };
  auto drain_all = [&] {
    for (auto &client : clients)
    {
      client->consume_output(client->output_size());
    }
  };

  const std::string slice(vio::tls_stream_t::write_slice, 's');
  write_all(slice);
  drain_all();
  const auto pooled = pool.size();
  REQUIRE(pooled >= connections);

  const std::string brief = "a short response";
  for (int round = 0; round < 3; ++round)
  {
    CAPTURE(round);
    write_all(round == 0 ? brief : slice);
    CHECK(pool.size() == pooled - connections);
    drain_all();
    CHECK(pool.size() == pooled);
    for (auto &client : clients)
    {
      CHECK(client->output_capacity() == 0);
    }
  }
}

TEST_CASE("the output pool frees only buffers untouched for a whole period, never below its floor")
{
  constexpr auto kept = vio::detail::ssl_output_pool_t::spare_floor;
  vio::detail::ssl_output_pool_t pool;
  for (std::size_t i = 0; i < 3 * kept; ++i)
  {
    pool.give(output_sized_buffer());
  }
  pool.trim();
  REQUIRE(pool.size() == 3 * kept);
  CHECK_FALSE(pool.period_elapsed(vio::tls_stream_t::output_trim_ns));
  CHECK(pool.period_elapsed(0));

  std::vector<std::vector<std::byte>> lent;
  for (std::size_t i = 0; i < 3 * kept; ++i)
  {
    lent.push_back(pool.take());
  }
  for (auto &buffer : lent)
  {
    pool.give(std::move(buffer));
  }
  lent.clear();
  pool.trim();
  CHECK(pool.size() == 3 * kept);

  std::vector<const std::byte *> recent;
  for (std::size_t i = 0; i < kept + 2; ++i)
  {
    lent.push_back(pool.take());
    recent.push_back(lent.back().data());
  }
  for (auto &buffer : lent)
  {
    pool.give(std::move(buffer));
  }
  lent.clear();
  pool.trim();
  CHECK(pool.size() == kept + 2);
  std::vector<const std::byte *> survivors;
  for (std::size_t i = 0; i < kept + 2; ++i)
  {
    lent.push_back(pool.take());
    survivors.push_back(lent.back().data());
  }
  std::sort(recent.begin(), recent.end());
  std::sort(survivors.begin(), survivors.end());
  CHECK(survivors == recent);
  for (auto &buffer : lent)
  {
    pool.give(std::move(buffer));
  }
  lent.clear();
  pool.trim();
  CHECK(pool.size() == kept + 2);
  pool.trim();
  CHECK(pool.size() == kept);
  pool.trim();
  CHECK(pool.size() == kept);

  int first = 0;
  int second = 0;
  CHECK_FALSE(pool.claim_trim(&first));
  pool.give(output_sized_buffer());
  CHECK(pool.claim_trim(&first));
  CHECK(pool.trim_claimed());
  CHECK_FALSE(pool.claim_trim(&second));
  CHECK_FALSE(pool.release_trim(&second));
  CHECK(pool.release_trim(&first));
  CHECK_FALSE(pool.trim_claimed());

  pool.attach();
  pool.attach();
  for (std::size_t i = 0; i < kept; ++i)
  {
    pool.give(output_sized_buffer());
  }
  pool.detach();
  CHECK(pool.size() == 2 * kept + 1);
  pool.detach();
  CHECK(pool.size() == kept);
  CHECK_FALSE(pool.period_elapsed(vio::tls_stream_t::output_trim_ns));
}

TEST_CASE("an idle TLS connection holds no output buffer and the pool returns to its floor once writes stop")
{
  constexpr auto kept = vio::detail::ssl_output_pool_t::spare_floor;
  auto config = make_pair_config();
  seed_output_pool(3 * kept);
  REQUIRE_FALSE(vio::detail::ssl_output_pool().trim_claimed());
  bool claimed_after_exchange = false;
  std::size_t client_capacity = 1;
  std::size_t pooled_when_idle = 0;
  bool claimed_when_idle = true;

  run_loop(
    [&](vio::event_loop_t &el) -> vio::task_t<void>
    {
      auto pair = get_ephemeral_port(el);
      REQUIRE_EXPECTED(pair);
      int port = pair->second;
      auto server_task = echo_server(el, std::move(pair->first), config.server, port, true);
      auto client_task = [](vio::event_loop_t &el, vio::ssl_config_t cc, int p, bool &claimed_after_exchange, std::size_t &client_capacity, std::size_t &pooled_when_idle,
                            bool &claimed_when_idle) -> vio::task_t<void>
      {
        auto c = vio::ssl_client_create(el, cc);
        REQUIRE_EXPECTED(c);
        auto client = std::move(c.value());
        auto cr = co_await vio::ssl_client_connect(client, "localhost", static_cast<uint16_t>(p), "127.0.0.1");
        REQUIRE_EXPECTED(cr);
        auto reader = vio::ssl_client_create_reader(client);
        REQUIRE_EXPECTED(reader);
        std::string msg = "ping";
        auto wr = co_await vio::ssl_client_write(client, std::as_bytes(std::span(msg)));
        REQUIRE_EXPECTED(wr);
        auto echoed = co_await reader.value();
        REQUIRE_EXPECTED(echoed);
        auto &pool = vio::detail::ssl_output_pool();
        claimed_after_exchange = pool.trim_claimed();
        client_capacity = client.state->engine.output_capacity();
        for (int i = 0; i < 60 && pool.size() > vio::detail::ssl_output_pool_t::spare_floor; ++i)
        {
          auto tick = vio::sleep(el, std::chrono::milliseconds(50));
          co_await tick;
        }
        pooled_when_idle = pool.size();
        claimed_when_idle = pool.trim_claimed();
        auto sh = co_await vio::ssl_client_shutdown(client);
        REQUIRE_EXPECTED(sh);
      }(el, config.client, port, claimed_after_exchange, client_capacity, pooled_when_idle, claimed_when_idle);
      co_await std::move(client_task);
      { auto destroy = std::move(client_task); }
      co_await std::move(server_task);
      el.stop();
    });
  CHECK(claimed_after_exchange);
  CHECK(client_capacity == 0);
  CHECK(pooled_when_idle == kept);
  CHECK_FALSE(claimed_when_idle);
}

TEST_CASE("closing the connection that holds the output trim a period after the last trim frees what went untouched while another stays open")
{
  constexpr auto kept = vio::detail::ssl_output_pool_t::spare_floor;
  auto config = make_pair_config();
  seed_output_pool(3 * kept);
  REQUIRE_FALSE(vio::detail::ssl_output_pool().trim_claimed());
  bool claimed_by_first = false;
  std::size_t pooled_after_first = 0;
  bool claimed_after_first = true;

  run_loop(
    [&](vio::event_loop_t &el) -> vio::task_t<void>
    {
      auto first_pair = get_ephemeral_port(el);
      REQUIRE_EXPECTED(first_pair);
      const int first_port = first_pair->second;
      auto second_pair = get_ephemeral_port(el);
      REQUIRE_EXPECTED(second_pair);
      const int second_port = second_pair->second;
      auto first_server = echo_server(el, std::move(first_pair->first), config.server, first_port, true);
      auto second_server = echo_server(el, std::move(second_pair->first), config.server, second_port, true);

      auto exchange = [](vio::event_loop_t &el, vio::ssl_config_t cc, int port, vio::ssl_client_t &client) -> vio::task_t<void>
      {
        auto created = vio::ssl_client_create(el, cc);
        REQUIRE_EXPECTED(created);
        client = std::move(created.value());
        auto connected = co_await vio::ssl_client_connect(client, "localhost", static_cast<uint16_t>(port), "127.0.0.1");
        REQUIRE_EXPECTED(connected);
        auto reader = vio::ssl_client_create_reader(client);
        REQUIRE_EXPECTED(reader);
        std::string msg = "ping";
        auto written = co_await vio::ssl_client_write(client, std::as_bytes(std::span(msg)));
        REQUIRE_EXPECTED(written);
        auto echoed = co_await reader.value();
        REQUIRE_EXPECTED(echoed);
      };

      auto period = vio::sleep(el, std::chrono::nanoseconds(vio::tls_stream_t::output_trim_ns + 100'000'000));
      co_await period;
      vio::ssl_client_t second_client{vio::ref_ptr_t<vio::ssl_client_state_t>::null()};
      {
        vio::ssl_client_t first_client{vio::ref_ptr_t<vio::ssl_client_state_t>::null()};
        co_await exchange(el, config.client, first_port, first_client);
        claimed_by_first = vio::detail::ssl_output_pool().trim_claimed();
        co_await exchange(el, config.client, second_port, second_client);
        auto closed = co_await vio::ssl_client_shutdown(first_client);
        REQUIRE_EXPECTED(closed);
      }
      co_await std::move(first_server);
      for (int i = 0; i < 20; ++i)
      {
        auto tick = vio::sleep(el, std::chrono::milliseconds(5));
        co_await tick;
      }
      pooled_after_first = vio::detail::ssl_output_pool().size();
      claimed_after_first = vio::detail::ssl_output_pool().trim_claimed();
      auto closed = co_await vio::ssl_client_shutdown(second_client);
      REQUIRE_EXPECTED(closed);
      { auto drop = std::move(second_client); }
      co_await std::move(second_server);
      el.stop();
    });
  CHECK(claimed_by_first);
  CHECK(pooled_after_first == kept);
  CHECK_FALSE(claimed_after_first);
}

TEST_CASE("closing the connection that holds the output trim within a period frees no spare the next connections need")
{
  constexpr auto kept = vio::detail::ssl_output_pool_t::spare_floor;
  auto config = make_pair_config();
  seed_output_pool(3 * kept);
  REQUIRE_FALSE(vio::detail::ssl_output_pool().trim_claimed());
  bool claimed_by_first = false;
  std::size_t pooled_after_first = 0;

  run_loop(
    [&](vio::event_loop_t &el) -> vio::task_t<void>
    {
      auto first_pair = get_ephemeral_port(el);
      REQUIRE_EXPECTED(first_pair);
      const int first_port = first_pair->second;
      auto second_pair = get_ephemeral_port(el);
      REQUIRE_EXPECTED(second_pair);
      const int second_port = second_pair->second;
      auto first_server = echo_server(el, std::move(first_pair->first), config.server, first_port, true);
      auto second_server = echo_server(el, std::move(second_pair->first), config.server, second_port, true);

      auto exchange = [](vio::event_loop_t &el, vio::ssl_config_t cc, int port, vio::ssl_client_t &client) -> vio::task_t<void>
      {
        auto created = vio::ssl_client_create(el, cc);
        REQUIRE_EXPECTED(created);
        client = std::move(created.value());
        auto connected = co_await vio::ssl_client_connect(client, "localhost", static_cast<uint16_t>(port), "127.0.0.1");
        REQUIRE_EXPECTED(connected);
        auto reader = vio::ssl_client_create_reader(client);
        REQUIRE_EXPECTED(reader);
        std::string msg = "ping";
        auto written = co_await vio::ssl_client_write(client, std::as_bytes(std::span(msg)));
        REQUIRE_EXPECTED(written);
        auto echoed = co_await reader.value();
        REQUIRE_EXPECTED(echoed);
      };

      vio::ssl_client_t second_client{vio::ref_ptr_t<vio::ssl_client_state_t>::null()};
      {
        vio::ssl_client_t first_client{vio::ref_ptr_t<vio::ssl_client_state_t>::null()};
        co_await exchange(el, config.client, first_port, first_client);
        claimed_by_first = vio::detail::ssl_output_pool().trim_claimed();
        co_await exchange(el, config.client, second_port, second_client);
        auto closed = co_await vio::ssl_client_shutdown(first_client);
        REQUIRE_EXPECTED(closed);
      }
      co_await std::move(first_server);
      for (int i = 0; i < 20; ++i)
      {
        auto tick = vio::sleep(el, std::chrono::milliseconds(5));
        co_await tick;
      }
      pooled_after_first = vio::detail::ssl_output_pool().size();
      auto closed = co_await vio::ssl_client_shutdown(second_client);
      REQUIRE_EXPECTED(closed);
      { auto drop = std::move(second_client); }
      co_await std::move(second_server);
      el.stop();
    });
  CHECK(claimed_by_first);
  CHECK(pooled_after_first == 3 * kept);
}

TEST_CASE("an armed output trim does not keep run() going after stop()")
{
  constexpr auto kept = vio::detail::ssl_output_pool_t::spare_floor;
  auto config = make_pair_config();
  seed_output_pool(3 * kept);
  vio::event_loop_t event_loop;
  std::optional<vio::ssl_server_t> server;
  std::optional<vio::ssl_server_client_t> accepted;
  std::optional<vio::ssl_client_t> client;
  bool claimed = false;
  std::chrono::steady_clock::time_point stopped_at;

  event_loop.run_in_loop(
    [&]
    {
      return [](vio::event_loop_t &el, vio::ssl_config_t server_config, vio::ssl_config_t client_config, std::optional<vio::ssl_server_t> &server,
                std::optional<vio::ssl_server_client_t> &accepted, std::optional<vio::ssl_client_t> &client, bool &claimed,
                std::chrono::steady_clock::time_point &stopped_at) -> vio::task_t<void>
      {
        auto pair = get_ephemeral_port(el);
        REQUIRE_EXPECTED(pair);
        const int port = pair->second;
        auto created_server = vio::ssl_server_create(el, std::move(pair->first), "localhost", server_config);
        REQUIRE_EXPECTED(created_server);
        server.emplace(std::move(created_server.value()));
        auto listening = vio::ssl_server_listen(*server, 4);
        auto created_client = vio::ssl_client_create(el, client_config);
        REQUIRE_EXPECTED(created_client);
        client.emplace(std::move(created_client.value()));
        auto connecting = vio::ssl_client_connect(*client, "localhost", static_cast<uint16_t>(port), "127.0.0.1");
        auto listened = co_await listening;
        REQUIRE_EXPECTED(listened);
        auto incoming = vio::ssl_server_accept(*server);
        REQUIRE_EXPECTED(incoming);
        accepted.emplace(std::move(incoming.value()));
        auto handshake = co_await vio::ssl_server_client_handshake(*accepted);
        REQUIRE_EXPECTED(handshake);
        auto connected = co_await connecting;
        REQUIRE_EXPECTED(connected);
        std::string msg = "ping";
        auto wr = co_await vio::ssl_client_write(*client, std::as_bytes(std::span(msg)));
        REQUIRE_EXPECTED(wr);
        claimed = vio::detail::ssl_output_pool().trim_claimed();
        stopped_at = std::chrono::steady_clock::now();
        el.stop();
      }(event_loop, config.server, config.client, server, accepted, client, claimed, stopped_at);
    });
  event_loop.run();
  const auto stopped_for = std::chrono::steady_clock::now() - stopped_at;
  client.reset();
  accepted.reset();
  server.reset();
  event_loop.run();
  CHECK(claimed);
  CHECK(stopped_for < std::chrono::milliseconds(500));
  CHECK(vio::detail::ssl_output_pool().size() == kept);
  CHECK_FALSE(vio::detail::ssl_output_pool().trim_claimed());
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
