#include <doctest/doctest.h>
#include <vio/crypto.h>

#include <cstring>
#include <vector>

static std::vector<uint8_t> to_bytes(const char *str)
{
  return {reinterpret_cast<const uint8_t *>(str), reinterpret_cast<const uint8_t *>(str) + std::strlen(str)};
}

TEST_SUITE("Crypto")
{
TEST_CASE("SHA-1 empty string")
{
  auto data = to_bytes("");
  auto digest = vio::crypto::sha1(data);
  auto hex = vio::crypto::to_hex(digest);
  CHECK(hex == "da39a3ee5e6b4b0d3255bfef95601890afd80709");
}

TEST_CASE("SHA-1 abc")
{
  auto data = to_bytes("abc");
  auto digest = vio::crypto::sha1(data);
  auto hex = vio::crypto::to_hex(digest);
  CHECK(hex == "a9993e364706816aba3e25717850c26c9cd0d89d");
}

TEST_CASE("SHA-256 empty string")
{
  auto data = to_bytes("");
  auto digest = vio::crypto::sha256(data);
  auto hex = vio::crypto::to_hex(digest);
  CHECK(hex == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST_CASE("SHA-256 abc")
{
  auto data = to_bytes("abc");
  auto digest = vio::crypto::sha256(data);
  auto hex = vio::crypto::to_hex(digest);
  CHECK(hex == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST_CASE("SHA-512 empty string")
{
  auto data = to_bytes("");
  auto digest = vio::crypto::sha512(data);
  auto hex = vio::crypto::to_hex(digest);
  CHECK(hex == "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
}

TEST_CASE("SHA-512 abc")
{
  auto data = to_bytes("abc");
  auto digest = vio::crypto::sha512(data);
  auto hex = vio::crypto::to_hex(digest);
  CHECK(hex == "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
}

TEST_CASE("HMAC-SHA-256 RFC 4231 Test Case 2")
{
  // Key = "Jefe", Data = "what do ya want for nothing?"
  auto key = to_bytes("Jefe");
  auto data = to_bytes("what do ya want for nothing?");
  auto digest = vio::crypto::hmac_sha256(key, data);
  auto hex = vio::crypto::to_hex(digest);
  CHECK(hex == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
}

TEST_CASE("HMAC-SHA-512 RFC 4231 Test Case 2")
{
  // Key = "Jefe", Data = "what do ya want for nothing?"
  auto key = to_bytes("Jefe");
  auto data = to_bytes("what do ya want for nothing?");
  auto digest = vio::crypto::hmac_sha512(key, data);
  auto hex = vio::crypto::to_hex(digest);
  CHECK(hex == "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737");
}

TEST_CASE("HMAC-SHA-256 RFC 4231 Test Case 1")
{
  // Key = 20 bytes of 0x0b
  std::vector<uint8_t> key(20, 0x0b);
  auto data = to_bytes("Hi There");
  auto digest = vio::crypto::hmac_sha256(key, data);
  auto hex = vio::crypto::to_hex(digest);
  CHECK(hex == "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
}

TEST_CASE("HMAC-SHA-512 RFC 4231 Test Case 1")
{
  // Key = 20 bytes of 0x0b
  std::vector<uint8_t> key(20, 0x0b);
  auto data = to_bytes("Hi There");
  auto digest = vio::crypto::hmac_sha512(key, data);
  auto hex = vio::crypto::to_hex(digest);
  CHECK(hex == "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854");
}

TEST_CASE("to_hex")
{
  std::vector<uint8_t> data = {0x00, 0x01, 0x0a, 0x0f, 0x10, 0xff};
  auto hex = vio::crypto::to_hex(data);
  CHECK(hex == "00010a0f10ff");
}

TEST_CASE("to_hex empty")
{
  std::vector<uint8_t> data;
  auto hex = vio::crypto::to_hex(data);
  CHECK(hex.empty());
}
} // TEST_SUITE
