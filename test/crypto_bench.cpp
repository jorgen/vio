// What the AEAD costs, in the shape QUIC actually uses it: one seal or open
// per packet, over a payload the size of a datagram.
//
// A QUIC implementation's throughput ceiling is partly its record layer, so
// when two of them differ it is worth knowing whether the crypto underneath
// them differs first. Not part of the suite -- build it with
// `cmake --build <dir> --target vio_crypto_bench`.

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string>
#include <vector>

#include <vio/crypto_aead.h>
#include <vio/ssl_backend.h>

namespace
{
using namespace vio;
using namespace std::chrono_literals;

struct result_t
{
  double seal_megabytes_per_second = 0;
  double open_megabytes_per_second = 0;
};

result_t measure(crypto::aead_t algorithm, std::size_t key_size, std::size_t payload, int iterations)
{
  std::vector<std::uint8_t> key(key_size, 0x2b);
  crypto::aead_key_t state;
  if (!state.init(algorithm, key).has_value())
  {
    return {};
  }

  std::array<std::uint8_t, crypto::aead_nonce_size> nonce = {};
  const std::vector<std::uint8_t> aad(20, 0x11);
  const std::vector<std::uint8_t> plaintext(payload, 0x61);
  std::vector<std::uint8_t> sealed(payload + 16);
  std::vector<std::uint8_t> opened(payload + 16);

  // The nonce changes per packet, as it does on the wire.
  auto bump = [&nonce](std::uint64_t counter)
  {
    for (std::size_t i = 0; i < 8; ++i)
    {
      nonce[nonce.size() - 1 - i] = static_cast<std::uint8_t>(counter >> (i * 8));
    }
  };

  bump(0);
  auto first = state.seal(sealed, nonce, plaintext, aad);
  if (!first.has_value())
  {
    return {};
  }
  const auto sealed_size = *first;

  const auto seal_start = std::chrono::steady_clock::now();
  for (int i = 0; i < iterations; ++i)
  {
    bump(static_cast<std::uint64_t>(i));
    (void)state.seal(sealed, nonce, plaintext, aad);
  }
  const auto seal_end = std::chrono::steady_clock::now();

  bump(0);
  (void)state.seal(sealed, nonce, plaintext, aad);
  const auto open_start = std::chrono::steady_clock::now();
  for (int i = 0; i < iterations; ++i)
  {
    bump(0);
    (void)state.open(opened, nonce, std::span<const std::uint8_t>(sealed).first(sealed_size), aad);
  }
  const auto open_end = std::chrono::steady_clock::now();

  const auto bytes = static_cast<double>(payload) * static_cast<double>(iterations);
  const auto seal_seconds = std::chrono::duration<double>(seal_end - seal_start).count();
  const auto open_seconds = std::chrono::duration<double>(open_end - open_start).count();
  return result_t{
    .seal_megabytes_per_second = bytes / seal_seconds / 1e6,
    .open_megabytes_per_second = bytes / open_seconds / 1e6,
  };
}
} // namespace

int main(int argc, char **argv)
{
  const std::size_t payload = argc > 1 ? static_cast<std::size_t>(std::atoi(argv[1])) : 1200;
  const int iterations = argc > 2 ? std::atoi(argv[2]) : 400000;

  std::printf("%s AEAD through vio, %zu byte payloads, %d iterations\n\n", OPENSSL_VERSION_TEXT, payload, iterations);
  std::printf("%-22s %14s %14s\n", "algorithm", "seal MB/s", "open MB/s");

  struct entry_t
  {
    const char *name;
    crypto::aead_t algorithm;
    std::size_t key_size;
  };
  const entry_t entries[] = {
    {"aes-128-gcm", crypto::aead_t::aes_128_gcm, 16},
    {"aes-256-gcm", crypto::aead_t::aes_256_gcm, 32},
    {"chacha20-poly1305", crypto::aead_t::chacha20_poly1305, 32},
  };

  for (const auto &entry : entries)
  {
    const auto measured = measure(entry.algorithm, entry.key_size, payload, iterations);
    std::printf("%-22s %14.1f %14.1f\n", entry.name, measured.seal_megabytes_per_second, measured.open_megabytes_per_second);
  }
  return 0;
}
