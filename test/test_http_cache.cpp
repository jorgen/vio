#include <doctest/doctest.h>

#include <vio/objstore/http_cache.h>

#include <filesystem>
#include <string>

namespace
{
// A fresh, empty cache directory per test case.
std::string unique_dir(const char *tag)
{
  static int counter = 0;
  auto dir = std::filesystem::temp_directory_path() / (std::string("vio_http_cache_") + tag + "_" + std::to_string(counter++));
  std::error_code ec;
  std::filesystem::remove_all(dir, ec);
  return dir.string();
}

vio::http::response_t make_response(int status, std::string body, std::vector<vio::http::header_t> headers)
{
  vio::http::response_t r;
  r.status = status;
  r.body = std::move(body);
  r.headers = std::move(headers);
  return r;
}
} // namespace

TEST_SUITE("http_cache")
{
  using vio::objstore::http_cache_t;

  TEST_CASE("max-age response is stored and served fresh without a network hit")
  {
    http_cache_t cache({unique_dir("maxage"), 1u << 20});
    auto resp = make_response(200, "hello", {{"Cache-Control", "max-age=3600"}, {"ETag", "\"abc\""}, {"Content-Type", "text/plain"}});
    cache.store("https://host/obj", "", resp, false);

    auto hit = cache.lookup("https://host/obj", "");
    CHECK(hit.state == http_cache_t::state_t::fresh);
    CHECK(hit.response.status == 200);
    CHECK(hit.response.body == "hello");
    CHECK(hit.response.header("Content-Type") == "text/plain");

    // A different URL (and a different byte range of the same URL) must not alias.
    CHECK(cache.lookup("https://host/other", "").state == http_cache_t::state_t::miss);
    CHECK(cache.lookup("https://host/obj", "bytes=0-9").state == http_cache_t::state_t::miss);
  }

  TEST_CASE("a response with no freshness information is stored but reported stale for revalidation")
  {
    http_cache_t cache({unique_dir("stale"), 1u << 20});
    auto resp = make_response(200, "data", {{"ETag", "\"v1\""}}); // no Cache-Control, no Last-Modified
    cache.store("https://host/nofresh", "", resp, false);

    auto hit = cache.lookup("https://host/nofresh", "");
    CHECK(hit.state == http_cache_t::state_t::stale);
    CHECK(hit.etag == "\"v1\"");
  }

  TEST_CASE("the immutable hint keeps a Cache-Control-less response fresh")
  {
    http_cache_t cache({unique_dir("immutable"), 1u << 20});
    auto resp = make_response(200, "blob", {{"ETag", "\"v1\""}}); // no freshness headers
    cache.store("https://host/blob", "", resp, /*request_immutable=*/true);

    CHECK(cache.lookup("https://host/blob", "").state == http_cache_t::state_t::fresh);
  }

  TEST_CASE("a 304 refreshes the stored entry and serves the cached body as 200")
  {
    http_cache_t cache({unique_dir("revalidate"), 1u << 20});
    cache.store("https://host/rev", "", make_response(200, "body-v1", {{"ETag", "\"v1\""}}), false);
    REQUIRE(cache.lookup("https://host/rev", "").state == http_cache_t::state_t::stale);

    auto r304 = make_response(304, "", {{"Cache-Control", "max-age=3600"}});
    auto served = cache.note_not_modified("https://host/rev", "", r304);
    REQUIRE(served.has_value());
    CHECK(served->status == 200);
    CHECK(served->body == "body-v1");

    // Now fresh (the 304 carried max-age=3600), so a subsequent lookup needs no network.
    CHECK(cache.lookup("https://host/rev", "").state == http_cache_t::state_t::fresh);
  }

  TEST_CASE("the byte budget is enforced with LRU eviction")
  {
    http_cache_t cache({unique_dir("lru"), 10}); // room for two 5-byte bodies
    auto five = make_response(200, "aaaaa", {}); // 5-byte body, immutable so freshness never expires
    cache.store("https://host/u1", "", five, true);
    cache.store("https://host/u2", "", five, true);
    cache.store("https://host/u3", "", five, true); // total would be 15 > 10 -> one is evicted

    int present = 0;
    for (const char *u : {"https://host/u1", "https://host/u2", "https://host/u3"})
      if (cache.lookup(u, "").state != http_cache_t::state_t::miss)
        ++present;
    CHECK(present == 2);
    CHECK(cache.total_bytes() <= 10);
  }

  TEST_CASE("the on-disk index survives a restart")
  {
    const std::string dir = unique_dir("persist");
    {
      http_cache_t writer({dir, 1u << 20});
      writer.store("https://host/persisted", "", make_response(200, "kept", {{"Cache-Control", "max-age=3600"}}), false);
    }
    http_cache_t reopened({dir, 1u << 20}); // rebuilds its index from the directory
    auto hit = reopened.lookup("https://host/persisted", "");
    CHECK(hit.state == http_cache_t::state_t::fresh);
    CHECK(hit.response.body == "kept");
  }
}
