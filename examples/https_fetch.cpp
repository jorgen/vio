#include <expected>
#include <print>
#include <string>
#include <string_view>
#include <vector>

#include <vio/error.h>
#include <vio/operation/tls_client.h>
#include <vio/run.h>

namespace
{

struct http_response
{
  int status_code{};
  std::string status_text;
  std::vector<std::pair<std::string, std::string>> headers;
  std::string body;

  std::string_view header(std::string_view name) const
  {
    for (auto &[k, v] : headers)
    {
      if (k.size() != name.size())
        continue;
      bool match = true;
      for (size_t i = 0; i < k.size(); i++)
      {
        if (std::tolower(static_cast<unsigned char>(k[i])) != std::tolower(static_cast<unsigned char>(name[i])))
        {
          match = false;
          break;
        }
      }
      if (match)
        return v;
    }
    return {};
  }
};

std::unexpected<vio::error_t> make_error(const std::string &msg)
{
  return std::unexpected(vio::error_t{.code = -1, .msg = msg});
}

vio::task_t<std::expected<http_response, vio::error_t>> fetch(vio::event_loop_t &event_loop, const std::string &host, const std::string &path = "/", uint16_t port = 443)
{
  auto client = vio::ssl_client_create(event_loop);
  if (!client)
    co_return std::unexpected(client.error());

  auto connect_result = co_await vio::ssl_client_connect(client.value(), host, port);
  if (!connect_result)
    co_return std::unexpected(connect_result.error());

  std::string request = "GET " + path + " HTTP/1.1\r\n"
                         "Host: " + host + "\r\n"
                         "User-Agent: vio-fetch\r\n"
                         "Connection: close\r\n"
                         "\r\n";
  uv_buf_t buf;
  buf.base = request.data();
  buf.len = request.size();
  auto write_result = co_await vio::ssl_client_write(client.value(), buf);
  if (!write_result)
    co_return std::unexpected(write_result.error());

  auto reader_result = vio::ssl_client_create_reader(client.value());
  if (!reader_result)
    co_return std::unexpected(reader_result.error());
  auto reader = std::move(reader_result.value());

  // Read entire response
  std::string raw;
  while (true)
  {
    auto read_result = co_await reader;
    if (!read_result)
      break;
    auto &data = read_result.value();
    raw.append(data.buf.base, data.buf.len);
  }

  // Split headers from body
  auto header_end = raw.find("\r\n\r\n");
  if (header_end == std::string::npos)
    co_return make_error("Malformed HTTP response: no header terminator");

  std::string_view header_section(raw.data(), header_end);
  std::string raw_body = raw.substr(header_end + 4);

  // Parse status line: "HTTP/1.1 200 OK"
  http_response response;
  auto first_line_end = header_section.find("\r\n");
  std::string_view status_line = header_section.substr(0, first_line_end);

  auto sp1 = status_line.find(' ');
  if (sp1 == std::string_view::npos)
    co_return make_error("Malformed status line");
  auto sp2 = status_line.find(' ', sp1 + 1);
  response.status_code = std::atoi(std::string(status_line.substr(sp1 + 1, sp2 - sp1 - 1)).c_str());
  if (sp2 != std::string_view::npos)
    response.status_text = status_line.substr(sp2 + 1);

  // Parse headers
  std::string_view remaining = header_section.substr(first_line_end + 2);
  while (!remaining.empty())
  {
    auto line_end = remaining.find("\r\n");
    std::string_view line = remaining.substr(0, line_end);
    if (auto colon = line.find(':'); colon != std::string_view::npos)
    {
      std::string key(line.substr(0, colon));
      std::string_view val = line.substr(colon + 1);
      while (!val.empty() && val.front() == ' ')
        val.remove_prefix(1);
      response.headers.emplace_back(std::move(key), std::string(val));
    }
    if (line_end == std::string_view::npos)
      break;
    remaining = remaining.substr(line_end + 2);
  }

  // Dechunk if Transfer-Encoding: chunked
  if (response.header("Transfer-Encoding") == "chunked")
  {
    std::string decoded;
    std::string_view src = raw_body;
    while (!src.empty())
    {
      auto nl = src.find("\r\n");
      if (nl == std::string_view::npos)
        break;
      auto chunk_size = std::strtoul(std::string(src.substr(0, nl)).c_str(), nullptr, 16);
      if (chunk_size == 0)
        break;
      src = src.substr(nl + 2);
      if (src.size() < chunk_size)
        break;
      decoded.append(src.data(), chunk_size);
      src = src.substr(chunk_size);
      if (src.starts_with("\r\n"))
        src = src.substr(2);
    }
    response.body = std::move(decoded);
  }
  else
  {
    response.body = std::move(raw_body);
  }

  co_return response;
}

} // namespace

int main()
{
  return vio::run([](vio::event_loop_t &event_loop) -> vio::task_t<int>
  {
    auto response = co_await fetch(event_loop, "example.com");
    if (!response)
    {
      std::println(stderr, "fetch failed: {}", response.error().msg);
      co_return 1;
    }

    std::println("Status: {} {}", response->status_code, response->status_text);
    std::println("Headers:");
    for (auto &[key, value] : response->headers)
      std::println("  {}: {}", key, value);
    std::println("Body ({} bytes):", response->body.size());
    std::println("{}", response->body);

    co_return 0;
  });
}
