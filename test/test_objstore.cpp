#include "require_expected.h"

#include <doctest/doctest.h>

#include <vio/crypto.h>
#include <vio/event_loop.h>
#include <vio/objstore/objstore.h>
#include <vio/task.h>

#include <cstring>
#include <memory>
#include <span>
#include <string>
#include <vector>

static std::span<const uint8_t> bytes(std::string_view s)
{
  return {reinterpret_cast<const uint8_t *>(s.data()), s.size()};
}

static std::vector<uint8_t> pattern(size_t n, uint8_t seed)
{
  std::vector<uint8_t> v(n);
  for (size_t i = 0; i < n; i++)
    v[i] = uint8_t(seed + i * 7u);
  return v;
}

TEST_SUITE("objstore")
{

TEST_CASE("uri_encode follows RFC 3986")
{
  using vio::objstore::uri_encode;
  REQUIRE(uri_encode("blob_00000000_0000000000000000", true) == "blob_00000000_0000000000000000");
  REQUIRE(uri_encode("a/b c", true) == "a/b%20c");
  REQUIRE(uri_encode("a/b c", false) == "a%2Fb%20c");
  REQUIRE(uri_encode("-_.~", true) == "-_.~");
}

TEST_CASE("AWS SigV4 matches the official get-vanilla vector")
{
  std::string empty_sha = vio::crypto::to_hex(vio::crypto::sha256(bytes("")));
  auto authz = vio::objstore::aws_sigv4_authorization("GET", "/", "", {{"host", "example.amazonaws.com"}, {"x-amz-date", "20150830T123600Z"}}, empty_sha, "AKIDEXAMPLE",
                                                      "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "us-east-1", "service", "20150830T123600Z", "20150830");
  REQUIRE(authz == "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, "
                   "SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31");
}

TEST_CASE("Azure Shared Key produces a decodable SharedKey header")
{
  std::string key = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==";
  auto authz = vio::objstore::azure_sharedkey_authorization("GET", "devstoreaccount1", key, "/devstoreaccount1/container/blob", {{"x-ms-date", "Mon, 01 Jan 2024 00:00:00 GMT"}, {"x-ms-version", "2021-08-06"}}, "", "", "");
  REQUIRE(authz.rfind("SharedKey devstoreaccount1:", 0) == 0);
  auto sig = authz.substr(std::string("SharedKey devstoreaccount1:").size());
  REQUIRE(vio::crypto::base64_decode(sig).has_value());
}

static vio::task_t<void> memory_round_trip(vio::event_loop_t &loop)
{
  vio::objstore::memory_io_manager_t io;
  auto data = pattern(200, 3);
  auto p = std::make_shared<uint8_t[]>(data.size());
  memcpy(p.get(), data.data(), data.size());

  auto w = co_await io.write_object("a", p, data.size());
  REQUIRE_EXPECTED(w);

  auto info = co_await io.object_info("a");
  REQUIRE_EXPECTED(info);
  REQUIRE(info->exists);
  REQUIRE(info->size == data.size());

  std::vector<uint8_t> whole(data.size());
  auto r = co_await io.read_object("a", whole.data(), {0, int64_t(data.size())});
  REQUIRE_EXPECTED(r);
  REQUIRE(r.value() == data.size());
  REQUIRE(memcmp(whole.data(), data.data(), data.size()) == 0);

  std::vector<uint8_t> mid(40);
  auto rr = co_await io.read_object("a", mid.data(), {50, 40});
  REQUIRE_EXPECTED(rr);
  REQUIRE(rr.value() == 40);
  REQUIRE(memcmp(mid.data(), data.data() + 50, 40) == 0);

  auto missing = co_await io.object_info("missing");
  REQUIRE_EXPECTED(missing);
  REQUIRE(!missing->exists);
  uint8_t d = 0;
  auto bad = co_await io.read_object("missing", &d, {0, 1});
  REQUIRE(!bad.has_value());

  auto rm = co_await io.remove_object("a");
  REQUIRE_EXPECTED(rm);
  auto gone = co_await io.object_info("a");
  REQUIRE_EXPECTED(gone);
  REQUIRE(!gone->exists);

  loop.stop();
}

TEST_CASE("memory io_manager round trip")
{
  vio::event_loop_t loop;
  loop.run_in_loop([&] { return memory_round_trip(loop); });
  loop.run();
}

static vio::task_t<void> file_round_trip(vio::event_loop_t &loop)
{
  vio::objstore::file_dir_io_manager_t io("vio_objstore_test_dir", loop);
  auto data = pattern(300, 11);
  auto p = std::make_shared<uint8_t[]>(data.size());
  memcpy(p.get(), data.data(), data.size());

  auto w = co_await io.write_object("obj", p, data.size());
  REQUIRE_EXPECTED(w);

  auto info = co_await io.object_info("obj");
  REQUIRE_EXPECTED(info);
  REQUIRE(info->exists);
  REQUIRE(info->size == data.size());

  std::vector<uint8_t> got(data.size());
  auto r = co_await io.read_object("obj", got.data(), {0, int64_t(data.size())});
  REQUIRE_EXPECTED(r);
  REQUIRE(r.value() == data.size());
  REQUIRE(memcmp(got.data(), data.data(), data.size()) == 0);

  std::vector<uint8_t> mid(50);
  auto rr = co_await io.read_object("obj", mid.data(), {100, 50});
  REQUIRE_EXPECTED(rr);
  REQUIRE(memcmp(mid.data(), data.data() + 100, 50) == 0);

  auto rm = co_await io.remove_object("obj");
  REQUIRE_EXPECTED(rm);
  auto gone = co_await io.object_info("obj");
  REQUIRE_EXPECTED(gone);
  REQUIRE(!gone->exists);

  loop.stop();
}

TEST_CASE("file_dir io_manager round trip")
{
  vio::event_loop_t loop;
  loop.run_in_loop([&] { return file_round_trip(loop); });
  loop.run();
}

TEST_CASE("create_io_manager dispatches on scheme")
{
  vio::event_loop_t loop;
  REQUIRE(vio::objstore::create_io_manager("mem://x", loop).has_value());
  REQUIRE(vio::objstore::create_io_manager("dir:///tmp/points_objstore_x", loop).has_value());
  REQUIRE(!vio::objstore::create_io_manager("ftp://nope", loop).has_value());   // unsupported scheme
  REQUIRE(!vio::objstore::create_io_manager("s3://bucket/p", loop).has_value()); // no AWS creds in env
  // Drain the loop once so it tears down cleanly (its internal handles need a run/stop cycle).
  loop.run_in_loop([&]() -> vio::task_t<void> {
    loop.stop();
    co_return;
  });
  loop.run();
}

} // TEST_SUITE
