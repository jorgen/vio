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

namespace
{
// Exposes the protected build_request so a test can inspect the signed + sent headers directly.
struct exposed_s3_io_manager_t : vio::objstore::s3_io_manager_t
{
  using s3_io_manager_t::s3_io_manager_t;
  vio::http::request_t make_request(const std::string &method, const std::string &name) const
  {
    return build_request(method, name, {}, nullptr);
  }
};

const std::string *find_header(const vio::http::request_t &req, std::string_view name)
{
  for (const auto &h : req.headers)
    if (vio::http::detail::header_name_equals(h.name, name))
      return &h.value;
  return nullptr;
}

std::string signed_headers_of(const vio::http::request_t &req)
{
  const std::string *authz = find_header(req, "Authorization");
  if (!authz)
    return {};
  auto a = authz->find("SignedHeaders=");
  if (a == std::string::npos)
    return {};
  a += std::string_view("SignedHeaders=").size();
  auto b = authz->find(',', a);
  return authz->substr(a, b - a);
}
} // namespace

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

TEST_CASE("AWS SigV4 signs x-amz-security-token as an ordinary header (temp credentials)")
{
  // The session token is not special-cased by the signer -- it is lowercased, sorted, and canonicalized
  // like any other header. Adding it must change SignedHeaders (and hence the signature) vs. the vanilla
  // request, and it sorts after x-amz-date.
  std::string empty_sha = vio::crypto::to_hex(vio::crypto::sha256(bytes("")));
  auto without = vio::objstore::aws_sigv4_authorization("GET", "/", "", {{"host", "example.amazonaws.com"}, {"x-amz-date", "20150830T123600Z"}}, empty_sha, "AKIDEXAMPLE",
                                                        "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "us-east-1", "service", "20150830T123600Z", "20150830");
  auto with = vio::objstore::aws_sigv4_authorization("GET", "/", "", {{"host", "example.amazonaws.com"}, {"x-amz-date", "20150830T123600Z"}, {"x-amz-security-token", "AQoDYXdzT0KEN"}}, empty_sha,
                                                     "AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "us-east-1", "service", "20150830T123600Z", "20150830");
  REQUIRE(with != without); // the token changed the signature
  // Known answer cross-checked against an independent SigV4 implementation (validated on the
  // published get-vanilla vector above): the token is folded into the signing like any other header.
  REQUIRE(with == "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, "
                  "SignedHeaders=host;x-amz-date;x-amz-security-token, Signature=978160d7c763b25c77297ea9d237c53b94c828e189d4fbde68b2ddb07c207b83");
}

TEST_CASE("s3 build_request signs and sends x-amz-security-token only for temporary credentials")
{
  vio::event_loop_t loop;
  vio::objstore::s3_io_manager_t::config_t cfg;
  cfg.https = false;
  cfg.host = "127.0.0.1";
  cfg.port = 9000;
  cfg.region = "us-east-1";
  cfg.bucket = "bucket";
  cfg.access_key = "AKIDEXAMPLE";
  cfg.secret_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
  cfg.path_style = true;

  SUBCASE("long-lived credentials: token neither signed nor sent")
  {
    exposed_s3_io_manager_t s3(loop, cfg);
    auto req = s3.make_request("GET", "obj");
    CHECK(find_header(req, "x-amz-security-token") == nullptr);
    CHECK(signed_headers_of(req) == "host;x-amz-content-sha256;x-amz-date");
  }

  SUBCASE("temporary credentials: token sent on the wire and present in SignedHeaders (sorted last)")
  {
    cfg.session_token = "FQoGZXIvYXdzEExampleSecurityToken==";
    exposed_s3_io_manager_t s3(loop, cfg);
    auto req = s3.make_request("GET", "obj");
    const std::string *tok = find_header(req, "x-amz-security-token");
    REQUIRE(tok != nullptr);
    CHECK(*tok == cfg.session_token);
    CHECK(signed_headers_of(req) == "host;x-amz-content-sha256;x-amz-date;x-amz-security-token");
  }

  // event_loop_t needs a run/stop cycle before destruction.
  loop.run_in_loop([&]() -> vio::task_t<void> {
    loop.stop();
    co_return;
  });
  loop.run();
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
