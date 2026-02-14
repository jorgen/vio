#include <print>
#include <string>
#include <string_view>

#include <vio/operation/tcp.h>
#include <vio/operation/udp.h>
#include <vio/run.h>

int main()
{
  return vio::run([](vio::event_loop_t &event_loop) -> vio::task_t<int>
  {
    // Bind receiver to ephemeral port
    auto addr = vio::ip4_addr("127.0.0.1", 0);
    if (!addr)
    {
      std::println(stderr, "ip4_addr failed: {}", addr.error().msg);
      co_return 1;
    }

    auto receiver = vio::udp_create(event_loop);
    if (!receiver)
    {
      std::println(stderr, "udp_create failed: {}", receiver.error().msg);
      co_return 1;
    }

    auto bind_result = vio::udp_bind(receiver.value(), reinterpret_cast<const sockaddr *>(&addr.value()));
    if (!bind_result)
    {
      std::println(stderr, "udp_bind failed: {}", bind_result.error().msg);
      co_return 1;
    }

    auto sn = vio::udp_sockname(receiver.value());
    if (!sn)
    {
      std::println(stderr, "udp_sockname failed: {}", sn.error().msg);
      co_return 1;
    }
    const auto *sa_in = reinterpret_cast<sockaddr_in *>(&sn.value());
    int port = ntohs(sa_in->sin_port);
    std::println("Receiver listening on 127.0.0.1:{}", port);

    constexpr int num_datagrams = 3;

    // Echo server coroutine: receive datagrams and echo them back
    auto echo_task = [](vio::udp_t echo_sock, int count) -> vio::task_t<void>
    {
      auto reader_result = vio::udp_create_reader(echo_sock);
      if (!reader_result)
      {
        std::println(stderr, "udp_create_reader failed: {}", reader_result.error().msg);
        co_return;
      }
      auto reader = std::move(reader_result.value());

      for (int i = 0; i < count; i++)
      {
        auto recv_result = co_await reader;
        if (!recv_result)
        {
          std::println(stderr, "Receiver read failed: {}", recv_result.error().msg);
          co_return;
        }
        auto &datagram = recv_result.value();
        std::string_view msg(datagram.data->base, datagram.data->len);
        std::println("Receiver: got \"{}\" from port {}", msg, datagram.sender_port());

        auto send_result = co_await vio::send_udp(echo_sock, reinterpret_cast<const uint8_t *>(datagram.data->base), datagram.data->len, datagram.get_sender());
        if (!send_result)
        {
          std::println(stderr, "Receiver echo failed: {}", send_result.error().msg);
          co_return;
        }
        std::println("Receiver: echoed back \"{}\"", msg);
      }
    }(std::move(receiver.value()), num_datagrams);

    // Sender coroutine: send datagrams and read echoes
    co_await [](vio::event_loop_t &el, int p, int count) -> vio::task_t<void>
    {
      auto sender_addr = vio::ip4_addr("127.0.0.1", 0);
      if (!sender_addr)
      {
        std::println(stderr, "ip4_addr failed: {}", sender_addr.error().msg);
        co_return;
      }

      auto sender = vio::udp_create(el);
      if (!sender)
      {
        std::println(stderr, "udp_create failed: {}", sender.error().msg);
        co_return;
      }

      auto bind_result = vio::udp_bind(sender.value(), reinterpret_cast<const sockaddr *>(&sender_addr.value()));
      if (!bind_result)
      {
        std::println(stderr, "udp_bind failed: {}", bind_result.error().msg);
        co_return;
      }

      auto dest_addr = vio::ip4_addr("127.0.0.1", p);
      if (!dest_addr)
      {
        std::println(stderr, "ip4_addr failed: {}", dest_addr.error().msg);
        co_return;
      }

      auto reader_result = vio::udp_create_reader(sender.value());
      if (!reader_result)
      {
        std::println(stderr, "udp_create_reader failed: {}", reader_result.error().msg);
        co_return;
      }
      auto reader = std::move(reader_result.value());

      for (int i = 0; i < count; i++)
      {
        std::string msg = "Hello #" + std::to_string(i + 1);
        auto send_result = co_await vio::send_udp(sender.value(), reinterpret_cast<const uint8_t *>(msg.data()), msg.size(), reinterpret_cast<const sockaddr *>(&dest_addr.value()));
        if (!send_result)
        {
          std::println(stderr, "Sender send failed: {}", send_result.error().msg);
          co_return;
        }
        std::println("Sender: sent \"{}\"", msg);

        auto recv_result = co_await reader;
        if (!recv_result)
        {
          std::println(stderr, "Sender recv failed: {}", recv_result.error().msg);
          co_return;
        }
        auto &datagram = recv_result.value();
        std::string_view echo(datagram.data->base, datagram.data->len);
        std::println("Sender: received echo \"{}\"", echo);
      }
    }(event_loop, port, num_datagrams);

    co_await std::move(echo_task);
    { auto tmp = std::move(echo_task); }
    std::println("Done!");
    co_return 0;
  });
}
