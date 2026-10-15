// What the datagram path costs, per API, in the shape QUIC uses it.
//
// Both directions are measured against a partner running the fastest method
// available, so a number here is the cost of the method under test rather than
// of the slower of a pair. Datagrams are 1200 bytes, which is what a QUIC
// packet is, and the totals are reported per datagram because that is what the
// protocol pays per packet regardless of how much payload rides in it.
//
// Linux only: sendmmsg, recvmmsg and UDP_SEGMENT are what is being compared.

#include <cstdio>

#if !defined(__linux__)
int main()
{
  std::printf("udp_bench measures Linux datagram syscalls; there is nothing to compare here.\n");
  return 0;
}
#else

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

#include <vio/buffer_pool.h>
#include <vio/event_loop.h>
#include <vio/operation/udp.h>
#include <vio/operation/udp_datagram.h>
#include <vio/task.h>

namespace
{
constexpr std::size_t datagram_size = 1200;
// What vio's reader takes per readable event, so the comparison is against the
// batch the code actually uses rather than an arbitrary one.
constexpr std::size_t batch = 32;

using clock_t_ = std::chrono::steady_clock;

[[nodiscard]] double seconds_since(clock_t_::time_point start)
{
  return std::chrono::duration<double>(clock_t_::now() - start).count();
}

// Per-thread, not per-process: the sender and the drain thread run at once and
// charging one with the other's time would make every number meaningless.
[[nodiscard]] double thread_cpu_seconds()
{
  rusage usage = {};
  getrusage(RUSAGE_THREAD, &usage);
  const auto user = static_cast<double>(usage.ru_utime.tv_sec) + static_cast<double>(usage.ru_utime.tv_usec) / 1e6;
  const auto system = static_cast<double>(usage.ru_stime.tv_sec) + static_cast<double>(usage.ru_stime.tv_usec) / 1e6;
  return user + system;
}

struct result_t
{
  double seconds = 0;
  double cpu_seconds = 0;
  std::uint64_t datagrams = 0;
  std::uint64_t syscalls = 0;
};

[[nodiscard]] int open_socket(std::uint16_t port, bool receiving)
{
  const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0)
  {
    return -1;
  }
  int buffer = 16 * 1024 * 1024;
  ::setsockopt(fd, SOL_SOCKET, receiving ? SO_RCVBUF : SO_SNDBUF, &buffer, sizeof(buffer));
  if (receiving)
  {
    sockaddr_in address = {};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
    address.sin_port = ::htons(port);
    if (::bind(fd, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) != 0)
    {
      ::close(fd);
      return -1;
    }
#if defined(UDP_GRO)
    // The receive side offload, matching what vio asks for. Without it the
    // kernel hands over one datagram per recvmsg however they arrived.
    //
    // Worth turning off deliberately (VIO_UDP_BENCH_NO_GRO=1) when reading these
    // numbers: over loopback a GSO run met by GRO is never actually cut up, so
    // the pair measures a large buffer moving rather than many datagrams. With
    // GRO off the kernel has to produce each datagram separately, which is the
    // pessimistic bound and closer to what a real interface does.
    int on = std::getenv("VIO_UDP_BENCH_NO_GRO") == nullptr ? 1 : 0;
    ::setsockopt(fd, IPPROTO_UDP, UDP_GRO, &on, sizeof(on));
#endif
    // A blocking receive with nothing to receive would sit in the kernel past
    // the end of the run and never look at the stop flag again. The timeout is
    // long enough that a loaded socket never reaches it, so it costs nothing
    // while the measurement is actually running.
    timeval timeout = {0, 100 * 1000};
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  }
  return fd;
}

[[nodiscard]] sockaddr_in loopback(std::uint16_t port)
{
  sockaddr_in address = {};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
  address.sin_port = ::htons(port);
  return address;
}

// ---- send methods ---------------------------------------------------------

// One datagram per syscall. The floor every other method is trying to beat.
result_t send_one_per_call(int fd, const sockaddr_in &to, std::uint64_t count)
{
  std::vector<std::uint8_t> payload(datagram_size, 0x61);
  iovec io = {payload.data(), payload.size()};
  msghdr message = {};
  message.msg_name = const_cast<sockaddr_in *>(&to);
  message.msg_namelen = sizeof(to);
  message.msg_iov = &io;
  message.msg_iovlen = 1;

  result_t out;
  const auto cpu = thread_cpu_seconds();
  const auto start = clock_t_::now();
  for (std::uint64_t i = 0; i < count; ++i)
  {
    ++out.syscalls;
    if (::sendmsg(fd, &message, 0) > 0)
    {
      ++out.datagrams;
    }
  }
  out.seconds = seconds_since(start);
  out.cpu_seconds = thread_cpu_seconds() - cpu;
  return out;
}

// One syscall carrying a run of datagrams for the kernel to cut up: what
// send_segments does. The payload is contiguous and UDP_SEGMENT says where the
// cuts go.
result_t send_gso(int fd, const sockaddr_in &to, std::uint64_t count, std::size_t segments)
{
#if !defined(UDP_SEGMENT)
  (void)fd;
  (void)to;
  (void)count;
  (void)segments;
  return {};
#else
  std::vector<std::uint8_t> payload(datagram_size * segments, 0x61);
  alignas(cmsghdr) char control[CMSG_SPACE(sizeof(std::uint16_t))] = {};

  iovec io = {payload.data(), payload.size()};
  msghdr message = {};
  message.msg_name = const_cast<sockaddr_in *>(&to);
  message.msg_namelen = sizeof(to);
  message.msg_iov = &io;
  message.msg_iovlen = 1;
  message.msg_control = control;
  message.msg_controllen = sizeof(control);

  cmsghdr *header = CMSG_FIRSTHDR(&message);
  header->cmsg_level = SOL_UDP;
  header->cmsg_type = UDP_SEGMENT;
  header->cmsg_len = CMSG_LEN(sizeof(std::uint16_t));
  const auto segment_size = static_cast<std::uint16_t>(datagram_size);
  std::memcpy(CMSG_DATA(header), &segment_size, sizeof(segment_size));

  result_t out;
  const auto cpu = thread_cpu_seconds();
  const auto start = clock_t_::now();
  for (std::uint64_t sent = 0; sent < count; sent += segments)
  {
    ++out.syscalls;
    if (::sendmsg(fd, &message, 0) > 0)
    {
      out.datagrams += segments;
    }
  }
  out.seconds = seconds_since(start);
  out.cpu_seconds = thread_cpu_seconds() - cpu;
  return out;
#endif
}

// One syscall carrying an array of separate datagrams. Unlike GSO the kernel
// does no segmenting, so this is the honest comparison for a sender whose
// datagrams are not one contiguous run.
result_t send_many(int fd, const sockaddr_in &to, std::uint64_t count, std::size_t depth)
{
  std::vector<std::uint8_t> payload(datagram_size * depth, 0x61);
  std::vector<iovec> iov(depth);
  std::vector<mmsghdr> messages(depth);
  for (std::size_t i = 0; i < depth; ++i)
  {
    iov[i] = {payload.data() + i * datagram_size, datagram_size};
    messages[i] = {};
    messages[i].msg_hdr.msg_name = const_cast<sockaddr_in *>(&to);
    messages[i].msg_hdr.msg_namelen = sizeof(to);
    messages[i].msg_hdr.msg_iov = &iov[i];
    messages[i].msg_hdr.msg_iovlen = 1;
  }

  result_t out;
  const auto cpu = thread_cpu_seconds();
  const auto start = clock_t_::now();
  for (std::uint64_t sent = 0; sent < count; sent += depth)
  {
    ++out.syscalls;
    const int done = ::sendmmsg(fd, messages.data(), static_cast<unsigned>(depth), 0);
    if (done > 0)
    {
      out.datagrams += static_cast<std::uint64_t>(done);
    }
  }
  out.seconds = seconds_since(start);
  out.cpu_seconds = thread_cpu_seconds() - cpu;
  return out;
}

[[nodiscard]] std::span<const std::uint8_t> bytes_of(const std::vector<std::uint8_t> &payload)
{
  return {payload.data(), payload.size()};
}

result_t send_vio_try(vio::udp_t &udp, const sockaddr_in &to, std::uint64_t count)
{
  std::vector<std::uint8_t> payload(datagram_size, 0x61);
  const auto *address = reinterpret_cast<const sockaddr *>(&to);

  result_t out;
  const auto cpu = thread_cpu_seconds();
  const auto start = clock_t_::now();
  for (std::uint64_t i = 0; i < count; ++i)
  {
    ++out.syscalls;
    if (vio::udp_try_send(udp, bytes_of(payload), address).has_value())
    {
      ++out.datagrams;
    }
  }
  out.seconds = seconds_since(start);
  out.cpu_seconds = thread_cpu_seconds() - cpu;
  return out;
}

result_t send_vio_batch(vio::udp_t &udp, const sockaddr_in &to, std::uint64_t count, std::size_t depth)
{
  std::vector<std::uint8_t> payload(datagram_size, 0x61);
  std::vector<vio::udp_out_datagram_t> datagrams(depth);
  for (auto &datagram : datagrams)
  {
    datagram.bytes = bytes_of(payload);
    datagram.addr = reinterpret_cast<const sockaddr *>(&to);
  }

  result_t out;
  const auto cpu = thread_cpu_seconds();
  const auto start = clock_t_::now();
  for (std::uint64_t sent = 0; sent < count; sent += depth)
  {
    ++out.syscalls;
    if (auto done = vio::udp_try_send_batch(udp, datagrams); done.has_value())
    {
      out.datagrams += *done;
    }
  }
  out.seconds = seconds_since(start);
  out.cpu_seconds = thread_cpu_seconds() - cpu;
  return out;
}

result_t send_vio_datagram(vio::udp_t &udp, const sockaddr_in &to, std::uint64_t count)
{
  std::vector<std::uint8_t> payload(datagram_size, 0x61);
  const auto *address = reinterpret_cast<const sockaddr *>(&to);

  result_t out;
  const auto cpu = thread_cpu_seconds();
  const auto start = clock_t_::now();
  for (std::uint64_t i = 0; i < count; ++i)
  {
    ++out.syscalls;
    if (vio::send_datagram(udp, bytes_of(payload), address, vio::udp_ecn_t::ect0).has_value())
    {
      ++out.datagrams;
    }
  }
  out.seconds = seconds_since(start);
  out.cpu_seconds = thread_cpu_seconds() - cpu;
  return out;
}

result_t send_vio_segments(vio::udp_t &udp, const sockaddr_in &to, std::uint64_t count, std::size_t segments)
{
  std::vector<std::uint8_t> payload(datagram_size * segments, 0x61);
  const auto *address = reinterpret_cast<const sockaddr *>(&to);

  result_t out;
  const auto cpu = thread_cpu_seconds();
  const auto start = clock_t_::now();
  for (std::uint64_t sent = 0; sent < count; sent += segments)
  {
    ++out.syscalls;
    if (vio::send_segments(udp, bytes_of(payload), datagram_size, address, vio::udp_ecn_t::not_ect).has_value())
    {
      out.datagrams += segments;
    }
  }
  out.seconds = seconds_since(start);
  out.cpu_seconds = thread_cpu_seconds() - cpu;
  return out;
}

vio::task_t<void> send_vio_awaited(vio::udp_t &udp, const sockaddr_in &to, std::uint64_t count, result_t &out)
{
  std::vector<std::uint8_t> payload(datagram_size, 0x61);
  const auto *address = reinterpret_cast<const sockaddr *>(&to);

  const auto cpu = thread_cpu_seconds();
  const auto start = clock_t_::now();
  for (std::uint64_t i = 0; i < count; ++i)
  {
    ++out.syscalls;
    if ((co_await vio::send_udp(udp, payload.data(), payload.size(), address)).has_value())
    {
      ++out.datagrams;
    }
  }
  out.seconds = seconds_since(start);
  out.cpu_seconds = thread_cpu_seconds() - cpu;
}

// ---- receive methods ------------------------------------------------------

struct drain_t
{
  std::atomic<std::uint64_t> datagrams{0};
  std::atomic<std::uint64_t> syscalls{0};
  std::atomic<bool> stop{false};
  double cpu_seconds = 0;
};

// One datagram per syscall. GRO can still hand back a coalesced run, so the
// datagram count is derived from the bytes returned rather than assumed to be
// one.
void drain_one_per_call(int fd, drain_t &state)
{
  std::vector<std::uint8_t> buffer(64 * 1024);
  alignas(cmsghdr) char control[256] = {};
  const auto cpu = thread_cpu_seconds();
  while (!state.stop.load(std::memory_order_relaxed))
  {
    iovec io = {buffer.data(), buffer.size()};
    msghdr message = {};
    message.msg_iov = &io;
    message.msg_iovlen = 1;
    message.msg_control = control;
    message.msg_controllen = sizeof(control);
    state.syscalls.fetch_add(1, std::memory_order_relaxed);
    const ssize_t received = ::recvmsg(fd, &message, 0);
    if (received <= 0)
    {
      continue;
    }
    std::size_t segment = static_cast<std::size_t>(received);
#if defined(UDP_GRO)
    for (cmsghdr *header = CMSG_FIRSTHDR(&message); header != nullptr; header = CMSG_NXTHDR(&message, header))
    {
      if (header->cmsg_level == SOL_UDP && header->cmsg_type == UDP_GRO)
      {
        int value = 0;
        std::memcpy(&value, CMSG_DATA(header), sizeof(value));
        if (value > 0)
        {
          segment = static_cast<std::size_t>(value);
        }
      }
    }
#endif
    const auto whole = (static_cast<std::size_t>(received) + segment - 1) / segment;
    state.datagrams.fetch_add(whole, std::memory_order_relaxed);
  }
  state.cpu_seconds = thread_cpu_seconds() - cpu;
}

// One syscall for a batch of datagrams.
void drain_many(int fd, drain_t &state, std::size_t depth)
{
  std::vector<std::uint8_t> storage(depth * 64 * 1024);
  std::vector<iovec> iov(depth);
  std::vector<mmsghdr> messages(depth);
  const auto cpu = thread_cpu_seconds();
  while (!state.stop.load(std::memory_order_relaxed))
  {
    for (std::size_t i = 0; i < depth; ++i)
    {
      iov[i] = {storage.data() + i * 64 * 1024, 64 * 1024};
      messages[i] = {};
      messages[i].msg_hdr.msg_iov = &iov[i];
      messages[i].msg_hdr.msg_iovlen = 1;
    }
    timespec timeout = {0, 20 * 1000 * 1000};
    state.syscalls.fetch_add(1, std::memory_order_relaxed);
    const int received = ::recvmmsg(fd, messages.data(), static_cast<unsigned>(depth), 0, &timeout);
    if (received <= 0)
    {
      continue;
    }
    std::uint64_t whole = 0;
    for (int i = 0; i < received; ++i)
    {
      const auto length = static_cast<std::size_t>(messages[i].msg_len);
      whole += length > datagram_size ? (length + datagram_size - 1) / datagram_size : 1;
    }
    state.datagrams.fetch_add(whole, std::memory_order_relaxed);
  }
  state.cpu_seconds = thread_cpu_seconds() - cpu;
}

enum class vio_drain_kind_t
{
  reader,
  reader_mmsg,
  datagram,
  datagram_batch,
};

struct vio_drain_t
{
  vio::udp_reader_t *reader = nullptr;
  vio::datagram_reader_t *datagram = nullptr;
};

[[nodiscard]] bool use_gro()
{
  return std::getenv("VIO_UDP_BENCH_NO_GRO") == nullptr;
}

vio::task_t<void> drain_vio(vio::event_loop_t &loop, std::uint16_t port, drain_t &state, vio_drain_t &context, vio_drain_kind_t kind, vio::buffer_pool_t &pool)
{
  auto created = vio::udp_create(loop, kind == vio_drain_kind_t::reader_mmsg ? vio::udp_recvmmsg_t::on : vio::udp_recvmmsg_t::off);
  if (!created.has_value())
  {
    co_return;
  }
  auto udp = std::move(*created);
  const auto address = loopback(port);
  if (!vio::udp_bind(udp, reinterpret_cast<const sockaddr *>(&address)).has_value())
  {
    co_return;
  }
  (void)vio::udp_set_recv_buffer_size(udp, 16 * 1024 * 1024);

  const auto cpu = thread_cpu_seconds();
  if (kind == vio_drain_kind_t::reader || kind == vio_drain_kind_t::reader_mmsg)
  {
    (void)vio::udp_use_buffer_pool(udp, pool);
    auto reader = vio::udp_create_reader(udp);
    if (!reader.has_value())
    {
      co_return;
    }
    context.reader = &*reader;
    std::array<std::expected<vio::udp_datagram_t, vio::error_t>, batch> taken;
    for (;;)
    {
      auto datagram = co_await *reader;
      if (!datagram.has_value())
      {
        break;
      }
      const auto more = vio::udp_reader_take_batch(*reader, taken);
      state.datagrams.fetch_add(1 + more, std::memory_order_relaxed);
    }
    context.reader = nullptr;
  }
  else
  {
    auto reader = vio::datagram_reader_t::create(loop, udp);
    if (!reader.has_value())
    {
      co_return;
    }
    if (use_gro())
    {
      (void)reader->receive_coalesced(64 * 1024);
    }
    context.datagram = &*reader;
    for (;;)
    {
      if (kind == vio_drain_kind_t::datagram_batch)
      {
        auto received = co_await reader->receive();
        if (!received.has_value())
        {
          break;
        }
        state.datagrams.fetch_add(received->size(), std::memory_order_relaxed);
      }
      else
      {
        auto first = co_await *reader;
        if (!first.has_value())
        {
          break;
        }
        std::uint64_t taken = 1;
        while (reader->try_next().has_value())
        {
          ++taken;
        }
        state.datagrams.fetch_add(taken, std::memory_order_relaxed);
      }
      state.syscalls.store(reader->reads(), std::memory_order_relaxed);
    }
    context.datagram = nullptr;
  }
  state.cpu_seconds = thread_cpu_seconds() - cpu;
}

// ---- reporting ------------------------------------------------------------

void report(const char *label, const result_t &r)
{
  if (r.datagrams == 0 || r.seconds <= 0)
  {
    std::printf("  %-28s unavailable\n", label);
    return;
  }
  const double pps = static_cast<double>(r.datagrams) / r.seconds;
  const double per_datagram_ns = r.seconds * 1e9 / static_cast<double>(r.datagrams);
  const double gbps = pps * datagram_size * 8 / 1e9;
  if (r.syscalls == 0)
  {
    std::printf("  %-28s %8.0f kpps  %6.2f Gbit/s  %7.0f ns/dgram  %5s dgram/syscall  cpu %.2fs\n", label, pps / 1000.0, gbps, per_datagram_ns, "-", r.cpu_seconds);
    return;
  }
  const double per_syscall = static_cast<double>(r.datagrams) / static_cast<double>(r.syscalls);
  std::printf("  %-28s %8.0f kpps  %6.2f Gbit/s  %7.0f ns/dgram  %5.1f dgram/syscall  cpu %.2fs\n", label, pps / 1000.0, gbps, per_datagram_ns, per_syscall, r.cpu_seconds);
}
} // namespace

int main(int argc, char **argv)
{
  const std::uint64_t count = argc > 1 ? static_cast<std::uint64_t>(std::stoull(argv[1])) : 2000000;
  const std::uint16_t port = 39001;

  std::printf("UDP datagram path, %zu byte datagrams, %llu per run, batch %zu\n\n", datagram_size, static_cast<unsigned long long>(count), batch);

  // Send, against a receiver using the fastest drain available, so what is
  // being timed is the send method rather than the slower half of a pair.
  std::printf("send (drained by recvmmsg):\n");
  {
    const int receive_fd = open_socket(port, true);
    drain_t drain;
    std::thread drainer([&] { drain_many(receive_fd, drain, batch); });

    const int send_fd = open_socket(0, false);
    const auto to = loopback(port);

    report("::sendmsg, one at a time", send_one_per_call(send_fd, to, count));
    report("::sendmsg + UDP_SEGMENT", send_gso(send_fd, to, count, batch));
    report("::sendmmsg", send_many(send_fd, to, count, batch));

    vio::event_loop_t loop;
    std::optional<vio::task_t<void>> task;
    loop.run_in_loop(
      [&]
      {
        task.emplace(
          [](vio::event_loop_t &event_loop, const sockaddr_in &destination, std::uint64_t total) -> vio::task_t<void>
          {
            {
              auto created = vio::udp_create(event_loop);
              if (created.has_value())
              {
                auto udp = std::move(*created);
                const auto any = loopback(0);
                (void)vio::udp_bind(udp, reinterpret_cast<const sockaddr *>(&any));
                (void)vio::udp_set_send_buffer_size(udp, 16 * 1024 * 1024);
                report("vio udp_try_send", send_vio_try(udp, destination, total));
                report("vio udp_try_send_batch", send_vio_batch(udp, destination, total, batch));
                report("vio send_datagram (ECN)", send_vio_datagram(udp, destination, total));
                report("vio send_segments", send_vio_segments(udp, destination, total, batch));
                result_t awaited;
                co_await send_vio_awaited(udp, destination, total, awaited);
                report("vio send_udp (awaited)", awaited);
              }
            }
            event_loop.stop();
          }(loop, to, count));
      });
    loop.run();
    task.reset();

    drain.stop.store(true);
    drainer.join();
    ::close(send_fd);
    ::close(receive_fd);
  }

  // Receive, against a sender using GSO, which is what the QUIC endpoint sends
  // with. Each drain runs for a fixed wall time and reports what it took in.
  std::printf("\nreceive (fed by ::sendmsg + UDP_SEGMENT, 3s each):\n");
  {
    struct case_t
    {
      const char *label;
      int kind;
    };
    const case_t cases[] = {{"::recvmsg, one at a time", 0},
                            {"::recvmmsg", 1},
                            {"vio udp_reader_t, pooled", 2},
                            {"vio udp_reader_t, pooled+mmsg", 3},
                            {"vio datagram_reader_t", 4},
                            {"vio datagram_reader_t batch", 5}};

    for (const auto &item : cases)
    {
      const std::uint16_t case_port = static_cast<std::uint16_t>(port + 1 + item.kind);
      drain_t drain;
      int receive_fd = -1;
      std::thread drainer;
      vio::buffer_pool_t pool(vio::default_pool_block_size, 256);
      std::optional<vio::thread_with_event_loop_t> worker;
      std::optional<vio::task_t<void>> task;
      vio_drain_t context;
      if (item.kind == 0 || item.kind == 1)
      {
        receive_fd = open_socket(case_port, true);
        if (item.kind == 0)
        {
          drainer = std::thread([&] { drain_one_per_call(receive_fd, drain); });
        }
        else
        {
          drainer = std::thread([&] { drain_many(receive_fd, drain, batch); });
        }
      }
      else
      {
        const vio_drain_kind_t kinds[] = {vio_drain_kind_t::reader, vio_drain_kind_t::reader_mmsg, vio_drain_kind_t::datagram, vio_drain_kind_t::datagram_batch};
        const auto kind = kinds[item.kind - 2];
        worker.emplace();
        auto &loop = worker->event_loop();
        loop.run_in_loop([&, kind] { task.emplace(drain_vio(loop, case_port, drain, context, kind, pool)); });
      }

      std::this_thread::sleep_for(std::chrono::milliseconds(200));

      std::atomic<bool> sending{true};
      std::thread sender(
        [&]
        {
          const int fd = open_socket(0, false);
          const auto to = loopback(case_port);
          while (sending.load(std::memory_order_relaxed))
          {
            send_gso(fd, to, batch * 256, batch);
          }
          ::close(fd);
        });

      const auto start = clock_t_::now();
      const auto before = drain.datagrams.load();
      std::this_thread::sleep_for(std::chrono::seconds(3));
      const auto taken = drain.datagrams.load() - before;
      const auto syscalls = drain.syscalls.load();
      const double elapsed = seconds_since(start);

      sending.store(false);
      sender.join();
      drain.stop.store(true);
      if (drainer.joinable())
      {
        drainer.join();
      }
      if (worker.has_value())
      {
        worker->event_loop().run_in_loop(
          [&context]
          {
            if (context.reader != nullptr)
            {
              context.reader->cancel();
            }
            if (context.datagram != nullptr)
            {
              context.datagram->cancel();
            }
          });
        worker->stop_and_join();
        task.reset();
        worker.reset();
      }
      if (receive_fd >= 0)
      {
        ::close(receive_fd);
      }

      result_t r;
      r.seconds = elapsed;
      r.datagrams = taken;
      r.syscalls = syscalls;
      r.cpu_seconds = drain.cpu_seconds;
      report(item.label, r);
    }
  }

  return 0;
}
#endif
