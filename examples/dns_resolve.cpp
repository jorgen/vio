#include <print>
#include <string>

#include <vio/operation/dns.h>
#include <vio/run.h>

int main(int argc, char *argv[])
{
  std::string hostname = argc > 1 ? argv[1] : "google.com";

  return vio::run([hostname](vio::event_loop_t &event_loop) -> vio::task_t<int>
  {
    std::println("Resolving \"{}\"...", hostname);

    vio::address_info_t hints;
    hints.family = AF_UNSPEC;
    hints.socktype = SOCK_STREAM;

    auto result = co_await vio::get_addrinfo(event_loop, hostname, hints);
    if (!result)
    {
      std::println(stderr, "get_addrinfo failed: {}", result.error().msg);
      co_return 1;
    }

    std::println("Found {} address(es):", result->size());

    for (auto &addr_info : *result)
    {
      const char *family = addr_info.family == AF_INET ? "IPv4" : addr_info.family == AF_INET6 ? "IPv6" : "other";

      auto name_info = co_await vio::get_nameinfo(event_loop, addr_info);
      if (!name_info)
      {
        std::println(stderr, "  get_nameinfo failed: {}", name_info.error().msg);
        continue;
      }

      std::println("  [{}] host={} service={}", family, name_info->host, name_info->service);
    }

    std::println("Done!");
    co_return 0;
  });
}
