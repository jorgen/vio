#include <doctest/doctest.h>

#include <vio/operation/http_client.h>

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
