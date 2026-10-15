#include <vio/crypto.h>
#include <vio/event_loop.h>
#include <vio/operation/sleep.h>
#include <vio/operation/tls_client.h>
#include <vio/task.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <optional>

int main()
{
  vio::event_loop_t loop;
  bool slept = false;
  std::optional<vio::task_t<void>> task;
  loop.run_in_loop([&] {
    task.emplace([](vio::event_loop_t &loop, bool &slept) -> vio::task_t<void> {
      auto result = co_await vio::sleep(loop, std::chrono::milliseconds(1));
      slept = result.has_value();
      loop.stop();
    }(loop, slept));
  });
  loop.run();
  const std::array<std::uint8_t, 3> abc = {'a', 'b', 'c'};
  const auto digest = vio::crypto::sha256(abc);
  const bool hashed = digest[0] == 0xba && digest[31] == 0xad;
  std::printf("backend %s, slept %d, hashed %d\n", loop.backend_name(), slept ? 1 : 0, hashed ? 1 : 0);
  return slept && hashed ? 0 : 1;
}
