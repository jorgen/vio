#include <algorithm>
#include <print>
#include <string>
#include <string_view>
#include <vector>

#include <vio/operation/tls_client.h>
#include <vio/run.h>

int main()
{
  return vio::run([](vio::event_loop_t &event_loop) -> vio::task_t<int>
  {
    auto ssl_client = vio::ssl_client_create(event_loop);
    if (!ssl_client)
    {
      std::println(stderr, "ssl_client_create failed: {}", ssl_client.error().msg);
      co_return 1;
    }

    std::println("Connecting to example.com:443...");
    auto connect_result = co_await vio::ssl_client_connect(ssl_client.value(), "example.com", 443);
    if (!connect_result)
    {
      std::println(stderr, "ssl_client_connect failed: {}", connect_result.error().msg);
      co_return 1;
    }
    std::println("TLS connection established");

    std::string request = "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: vio-example\r\nConnection: close\r\n\r\n";
    uv_buf_t write_buf;
    write_buf.base = request.data();
    write_buf.len = request.size();
    auto write_result = co_await vio::ssl_client_write(ssl_client.value(), write_buf);
    if (!write_result)
    {
      std::println(stderr, "ssl_client_write failed: {}", write_result.error().msg);
      co_return 1;
    }
    std::println("Sent HTTP request");

    auto reader_result = vio::ssl_client_create_reader(ssl_client.value());
    if (!reader_result)
    {
      std::println(stderr, "ssl_client_create_reader failed: {}", reader_result.error().msg);
      co_return 1;
    }
    auto reader = std::move(reader_result.value());

    std::vector<char> response;
    while (true)
    {
      auto read_result = co_await reader;
      if (!read_result)
        break;
      auto &data = read_result.value();
      response.insert(response.end(), data.buf.base, data.buf.base + data.buf.len);
    }

    std::println("Received {} bytes", response.size());

    std::string_view body(response.data(), response.size());
    constexpr size_t max_display = 2000;
    if (body.size() > max_display)
    {
      std::println("{}", body.substr(0, max_display));
      std::println("... (truncated, {} bytes total)", body.size());
    }
    else
    {
      std::println("{}", body);
    }

    std::println("Done!");
    co_return 0;
  });
}
