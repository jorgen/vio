#include <doctest/doctest.h>
#include <vio/event_loop.h>
#include <vio/event_pipe.h>
#include <vio/operation/ssl_client.h>
#include <vio/task.h>

#include "require_expected.h"
#include "vio/operation/sleep.h"

static vio::task_t<void> test_ssl_client_connect(vio::event_loop_t &event_loop)
{
  auto ssl_client = vio::ssl_client_create(event_loop);
  REQUIRE_EXPECTED(ssl_client);

  auto connect_result = co_await ssl_client_connect(ssl_client.value(), "en.wikipedia.org", 443);
  REQUIRE_EXPECTED(connect_result);

  {
    std::string client_message = "GET /wiki/Susan_B._Anthony HTTP/1.1\r\nHost: en.wikipedia.org\r\nConnection: close\r\n\r\n";
    uv_buf_t buf;
    buf.base = client_message.data();
    buf.len = client_message.size();
    auto write_result = co_await vio::ssl_client_write(ssl_client.value(), buf);
  }

  {
    auto read_create_result = vio::ssl_client_create_reader(ssl_client.value());
    REQUIRE_EXPECTED(read_create_result);

    const std::string header_end = "\r\n\r\n";
    std::vector<char> header_buffer;
    std::vector<char> body_buffer;
    auto reader = std::move(read_create_result.value());

    bool header_end_found = false;
    while (!header_end_found)
    {
      auto read_result = co_await reader;
      REQUIRE_EXPECTED(read_result);
      auto &value = read_result.value();

      header_buffer.insert(header_buffer.end(), value.buf.base, value.buf.base + value.buf.len);

      auto header_str = std::string_view(header_buffer.data(), header_buffer.size());
      if (auto pos = header_str.find(header_end); pos != std::string::npos)
      {
        header_end_found = true;
        size_t body_start = pos + header_end.length();
        size_t leftover_size = header_buffer.size() - body_start;
        if (leftover_size > 0)
        {
          body_buffer.insert(body_buffer.end(), header_buffer.begin() + body_start, header_buffer.end());
        }
        header_buffer.resize(pos + header_end.length());
      }
    }
    auto headers = std::string_view(header_buffer.data(), header_buffer.size());
    size_t content_length = 0;
    std::string_view content_length_header = "content-length: ";
    std::string headers_lower;
    headers_lower.resize(headers.size());
    std::transform(headers.begin(), headers.end(), headers_lower.begin(), ::tolower);

    if (auto cl_pos = headers_lower.find(content_length_header); cl_pos != std::string::npos)
    {
      auto cl_end = headers.find("\r\n", cl_pos);
      auto cl_str = headers.substr(cl_pos + content_length_header.length(), cl_end - (cl_pos + content_length_header.length()));
      content_length = std::stoul(std::string(cl_str));
    }
    auto initial_body_size = body_buffer.size();
    body_buffer.resize(content_length);

    if (initial_body_size < content_length)
    {
      uv_buf_t buf;
      buf.base = body_buffer.data() + initial_body_size;
      buf.len = content_length - initial_body_size;
      auto body_read = co_await reader.read(buf);
      REQUIRE_EXPECTED(body_read);
    }

    MESSAGE("Headers:\n" << headers);
    MESSAGE("Body:\n" << std::string_view(body_buffer.data(), content_length));
  }

  event_loop.stop();
}

TEST_CASE("test ssl toy http client")
{
  vio::event_loop_t event_loop;
  event_loop.run_in_loop([&event_loop] { test_ssl_client_connect(event_loop); });
  event_loop.run();
}
