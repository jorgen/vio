#include <doctest/doctest.h>

#include <vio/event_loop.h>
#include <vio/operation/http_client.h>
#include <vio/operation/tcp.h>
#include <vio/operation/tcp_server.h>
#include <vio/task.h>

#include "require_expected.h"

#include <string>
#include <utility>

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
