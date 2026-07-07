#include <array>
#include <cstddef>
#include <cstdint>
#include <print>
#include <span>
#include <string>
#include <utility>

#include <vio/operation/tcp.h>
#include <vio/operation/tcp_server.h>
#include <vio/run.h>

// Demonstrates the zero-copy scatter read: the client reads the whole payload
// through one fixed 16 KiB buffer with reader.read_into(), never allocating a
// buffer per read. Because read_into leaves the reader paused between reads, the
// pull cadence is the backpressure.
int main()
{
  return vio::run(
    [](vio::event_loop_t &loop) -> vio::task_t<int>
    {
      auto addr = vio::ip4_addr("127.0.0.1", 0);
      if (!addr)
        co_return 1;
      auto server = vio::tcp_create_server(loop);
      if (!server)
        co_return 1;
      if (!vio::tcp_bind(server.value(), reinterpret_cast<const sockaddr *>(&addr.value())))
        co_return 1;
      auto sn = vio::sockname(server->tcp);
      if (!sn)
        co_return 1;
      int port = ntohs(reinterpret_cast<const sockaddr_in *>(&sn.value())->sin_port);

      // Server: accept one client and stream a large payload, then close.
      auto server_task = [](vio::tcp_server_t s) -> vio::task_t<void>
      {
        auto server = std::move(s);
        if (!co_await vio::tcp_listen(server, 1))
          co_return;
        auto client = vio::tcp_accept(server);
        if (!client)
          co_return;
        std::string payload(4u * 1024u * 1024u, 'x');
        co_await vio::write_tcp(client.value(), reinterpret_cast<const uint8_t *>(payload.data()), payload.size());
      }(std::move(server.value()));

      // Client: connect and drain the payload into one reused buffer.
      co_await [](vio::event_loop_t &el, int p) -> vio::task_t<void>
      {
        auto client = vio::tcp_create(el);
        if (!client)
          co_return;
        auto a = vio::ip4_addr("127.0.0.1", p);
        if (!a || !co_await vio::tcp_connect(client.value(), reinterpret_cast<const sockaddr *>(&a.value())))
          co_return;
        auto reader = vio::tcp_create_reader(client.value());
        if (!reader)
          co_return;

        std::array<std::byte, 16u * 1024u> buffer{};
        std::uint64_t total = 0;
        for (;;)
        {
          auto n = co_await reader->read_into(std::span<std::byte>(buffer.data(), buffer.size()));
          if (!n)
          {
            std::println(stderr, "read_into failed: {}", n.error().msg);
            co_return;
          }
          if (n.value() == 0)
            break; // EOF
          total += n.value();
        }
        std::println("received {} bytes via read_into (16 KiB buffer)", total);
      }(loop, port);

      co_await std::move(server_task);
      co_return 0;
    });
}
