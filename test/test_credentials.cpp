#include "require_expected.h"

#include <doctest/doctest.h>

#include <vio/crypto.h>
#include <vio/detail/ini.h>
#include <vio/event_loop.h>
#include <vio/objstore/aws_config.h>
#include <vio/objstore/aws_json.h>
#include <vio/objstore/aws_profile.h>
#include <vio/objstore/aws_sts_client.h>
#include <vio/objstore/create_object_store.h>
#include <vio/objstore/credentials_providers.h>
#include <vio/task.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <span>
#include <string>

using namespace vio::objstore;
namespace fs = std::filesystem;

namespace
{
std::span<const uint8_t> bytes(std::string_view s)
{
  return {reinterpret_cast<const uint8_t *>(s.data()), s.size()};
}

// Drive a provider's credentials() coroutine to completion on a throwaway loop and return the result. The
// coroutine is a free function so its reference parameters live in the coroutine frame (the forwarding
// lambda closure may be destroyed while it is suspended).
vio::task_t<void> drive(credentials_provider_t &p, vio::event_loop_t &loop, std::optional<std::expected<credentials_t, vio::error_t>> &out)
{
  out = co_await p.credentials(loop);
  loop.stop();
  co_return;
}

std::expected<credentials_t, vio::error_t> get_creds(credentials_provider_t &p)
{
  vio::event_loop_t loop;
  std::optional<std::expected<credentials_t, vio::error_t>> out;
  loop.run_in_loop([&] { return drive(p, loop, out); });
  loop.run();
  return std::move(*out);
}

void write_file(const fs::path &path, std::string_view content)
{
  fs::create_directories(path.parent_path());
  std::ofstream f(path, std::ios::binary | std::ios::trunc);
  f.write(content.data(), static_cast<std::streamsize>(content.size()));
}

// The CLI-derived cache filename for a login session: sha256(login_session) hex + ".json".
std::string login_cache_filename(std::string_view login_session)
{
  return vio::crypto::to_hex(vio::crypto::sha256(bytes(login_session))) + ".json";
}
} // namespace

TEST_SUITE("credentials")
{

TEST_CASE("ini parser: sections, comments, case-insensitivity")
{
  const std::string text = "[default]\n"
                           "region = eu-north-1  # inline stays part of value? no, whole line kept\n"
                           "; a comment line\n"
                           "\n"
                           "[profile Dev]\n"
                           "  Aws_Access_Key_Id = AKIA_DEV\n"
                           "aws_secret_access_key=secretval\n"
                           "[sso-session my-sso]\n"
                           "sso_start_url = https://example.awsapps.com/start\n";
  auto ini = vio::detail::parse_ini(text);
  REQUIRE(ini.get("default", "region") != nullptr);
  CHECK(*ini.get("default", "region") == "eu-north-1  # inline stays part of value? no, whole line kept");
  // section + key lookups are case-insensitive; keys are stored lowercased
  REQUIRE(ini.get("profile dev", "aws_access_key_id") != nullptr);
  CHECK(*ini.get("PROFILE DEV", "AWS_ACCESS_KEY_ID") == "AKIA_DEV");
  CHECK(*ini.get("profile dev", "aws_secret_access_key") == "secretval");
  CHECK(ini.has_section("sso-session my-sso"));
  CHECK(ini.get("default", "missing") == nullptr);
}

TEST_CASE("resolve_profile: static keys from the credentials file")
{
  auto config = vio::detail::parse_ini("[default]\nregion = us-west-2\n");
  auto creds = vio::detail::parse_ini("[default]\naws_access_key_id = AKIAEXAMPLE\naws_secret_access_key = shhh\naws_session_token = tok\n");
  auto rp = resolve_profile(config, creds, "default");
  CHECK(rp.source == credential_source_t::static_keys);
  CHECK(rp.access_key_id == "AKIAEXAMPLE");
  CHECK(rp.secret_access_key == "shhh");
  CHECK(rp.session_token == "tok");
  CHECK(rp.region == "us-west-2");
}

TEST_CASE("resolve_profile: login_session (aws login / DPoP)")
{
  auto config = vio::detail::parse_ini("[default]\nlogin_session = arn:aws:iam::123456789012:user/me\nregion = eu-north-1\n");
  vio::detail::ini_file_t creds;
  auto rp = resolve_profile(config, creds, "default");
  CHECK(rp.source == credential_source_t::login_session);
  CHECK(rp.login_session == "arn:aws:iam::123456789012:user/me");
  CHECK(rp.region == "eu-north-1");
}

TEST_CASE("resolve_profile: modern SSO via sso-session, and assume-role")
{
  auto sso_config = vio::detail::parse_ini("[profile work]\nsso_session = corp\nsso_account_id = 111122223333\nsso_role_name = ReadOnly\n"
                                           "[sso-session corp]\nsso_start_url = https://corp.awsapps.com/start\nsso_region = us-east-1\n");
  vio::detail::ini_file_t empty;
  auto sso = resolve_profile(sso_config, empty, "work");
  CHECK(sso.source == credential_source_t::sso);
  CHECK(sso.sso_session == "corp");
  CHECK(sso.sso_start_url == "https://corp.awsapps.com/start");
  CHECK(sso.sso_region == "us-east-1");
  CHECK(sso.sso_account_id == "111122223333");
  CHECK(sso.sso_role_name == "ReadOnly");

  auto ar_config = vio::detail::parse_ini("[profile deploy]\nrole_arn = arn:aws:iam::444455556666:role/Deploy\nsource_profile = default\n");
  auto ar = resolve_profile(ar_config, empty, "deploy");
  CHECK(ar.source == credential_source_t::assume_role);
  CHECK(ar.role_arn == "arn:aws:iam::444455556666:role/Deploy");
  CHECK(ar.source_profile == "default");
}

TEST_CASE("parse_login_cache: extracts credentials and ignores extra fields")
{
  const std::string json = R"({
    "accessToken": {
      "accessKeyId": "ASIAEXAMPLE",
      "secretAccessKey": "sekret",
      "sessionToken": "session-token",
      "accountId": "123456789012",
      "expiresAt": "2099-01-01T00:00:00Z"
    },
    "tokenType": "Bearer",
    "clientId": "unused",
    "refreshToken": "unused",
    "idToken": "unused",
    "dpopKey": { "kty": "EC", "crv": "P-256" }
  })";
  auto r = parse_login_cache(json);
  REQUIRE_EXPECTED(r);
  CHECK(r->access_key_id == "ASIAEXAMPLE");
  CHECK(r->secret_access_key == "sekret");
  CHECK(r->session_token == "session-token");
  REQUIRE(r->expiration.has_value());

  auto missing = parse_login_cache(R"({"accessToken":{"sessionToken":"x"},"tokenType":"Bearer"})");
  CHECK(!missing.has_value()); // no accessKeyId/secretAccessKey

  auto bad = parse_login_cache("not json at all");
  CHECK(!bad.has_value());
}

TEST_CASE("parse_sso_role_credentials: epoch-ms expiration")
{
  const std::string json = R"({"roleCredentials":{"accessKeyId":"ASIA1","secretAccessKey":"s1","sessionToken":"t1","expiration":4102444800000}})";
  auto r = parse_sso_role_credentials(json);
  REQUIRE_EXPECTED(r);
  CHECK(r->access_key_id == "ASIA1");
  REQUIRE(r->expiration.has_value());
  // 4102444800000 ms = 2100-01-01T00:00:00Z, well in the future
  CHECK(*r->expiration > std::chrono::system_clock::now());
}

TEST_CASE("parse_imds_credentials / parse_oidc_create_token / parse_sso_token_cache")
{
  auto imds = parse_imds_credentials(R"({"Code":"Success","AccessKeyId":"ASIA2","SecretAccessKey":"s2","Token":"t2","Expiration":"2099-01-01T00:00:00Z"})");
  REQUIRE_EXPECTED(imds);
  CHECK(imds->access_key_id == "ASIA2");
  CHECK(imds->session_token == "t2");

  auto oidc = parse_oidc_create_token(R"({"accessToken":"aaa","expiresIn":3600,"refreshToken":"rrr","tokenType":"Bearer"})");
  REQUIRE_EXPECTED(oidc);
  CHECK(oidc->access_token == "aaa");
  CHECK(oidc->refresh_token == "rrr");
  CHECK(oidc->expires_in == 3600);

  auto sso = parse_sso_token_cache(R"({"startUrl":"https://x.awsapps.com/start","region":"us-east-1","accessToken":"bearer","expiresAt":"2099-01-01T00:00:00Z","refreshToken":"rt","clientId":"cid","clientSecret":"csec"})");
  REQUIRE_EXPECTED(sso);
  CHECK(sso->access_token == "bearer");
  CHECK(sso->region == "us-east-1");
  CHECK(sso->start_url == "https://x.awsapps.com/start");
}

TEST_CASE("parse_sts_assume_role_xml: extracts credentials from the STS XML response")
{
  const std::string xml = R"(<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    <Credentials>
      <AccessKeyId>ASIASTS</AccessKeyId>
      <SecretAccessKey>stssecret</SecretAccessKey>
      <SessionToken>ststoken</SessionToken>
      <Expiration>2099-01-01T00:00:00Z</Expiration>
    </Credentials>
    <AssumedRoleUser><Arn>arn:aws:sts::123:assumed-role/x/vio-session</Arn></AssumedRoleUser>
  </AssumeRoleResult>
</AssumeRoleResponse>)";
  auto r = parse_sts_assume_role_xml(xml);
  REQUIRE_EXPECTED(r);
  CHECK(r->access_key_id == "ASIASTS");
  CHECK(r->secret_access_key == "stssecret");
  CHECK(r->session_token == "ststoken");
  REQUIRE(r->expiration.has_value());

  auto empty = parse_sts_assume_role_xml("<AssumeRoleResponse></AssumeRoleResponse>");
  CHECK(!empty.has_value());
}

TEST_CASE("resolve_credential_chain: builds a non-null provider for SSO and assume-role profiles")
{
  // Fixture ~/.aws with an SSO profile (construction only -- credentials() would call live AWS).
  fs::path home = fs::temp_directory_path() / "vio_cred_home_sso";
  fs::remove_all(home);
  write_file(home / ".aws" / "config",
             "[profile work]\nsso_session = corp\nsso_account_id = 111122223333\nsso_role_name = RO\nregion = us-east-1\n"
             "[sso-session corp]\nsso_start_url = https://corp.awsapps.com/start\nsso_region = us-east-1\n"
             "[profile deploy]\nrole_arn = arn:aws:iam::444455556666:role/Deploy\nsource_profile = work\n");

  const char *home_env = std::getenv("HOME");
  std::optional<std::string> saved_home = home_env ? std::optional<std::string>(home_env) : std::nullopt;
  ::setenv("HOME", home.string().c_str(), 1);
  ::unsetenv("AWS_CONFIG_FILE");
  ::unsetenv("AWS_SHARED_CREDENTIALS_FILE");

  auto sso = resolve_credential_chain(std::string("work"));
  CHECK(sso.provider != nullptr);
  REQUIRE(sso.region.has_value());
  CHECK(*sso.region == "us-east-1");

  auto ar = resolve_credential_chain(std::string("deploy"));
  CHECK(ar.provider != nullptr);

  if (saved_home)
    ::setenv("HOME", saved_home->c_str(), 1);
  fs::remove_all(home);
}

TEST_CASE("login_cache provider: serves valid credentials, errors on expiry / absence")
{
  const std::string session = "arn:aws:iam::123456789012:user/tester";
  fs::path dir = fs::temp_directory_path() / "vio_cred_test" / "login" / "cache";
  fs::remove_all(fs::temp_directory_path() / "vio_cred_test");

  SUBCASE("valid (future expiry)")
  {
    write_file(dir / login_cache_filename(session), R"({"accessToken":{"accessKeyId":"ASIAOK","secretAccessKey":"sk","sessionToken":"st","expiresAt":"2099-01-01T00:00:00Z"},"dpopKey":{"kty":"EC"}})");
    login_cache_credentials_provider_t p(session, dir.string());
    auto c = get_creds(p);
    REQUIRE_EXPECTED(c);
    CHECK(c->access_key == "ASIAOK");
    CHECK(c->secret_key == "sk");
    CHECK(c->session_token == "st");
  }

  SUBCASE("expired")
  {
    write_file(dir / login_cache_filename(session), R"({"accessToken":{"accessKeyId":"ASIAOLD","secretAccessKey":"sk","sessionToken":"st","expiresAt":"2000-01-01T00:00:00Z"}})");
    login_cache_credentials_provider_t p(session, dir.string());
    auto c = get_creds(p);
    REQUIRE(!c.has_value());
    CHECK(c.error().msg.find("aws login") != std::string::npos);
  }

  SUBCASE("missing file")
  {
    login_cache_credentials_provider_t p(session, dir.string());
    auto c = get_creds(p);
    REQUIRE(!c.has_value());
    CHECK(c.error().msg.find("run `aws login`") != std::string::npos);
  }

  fs::remove_all(fs::temp_directory_path() / "vio_cred_test");
}

TEST_CASE("environment provider + chain: env preferred, falls through when unset")
{
  const std::string session = "arn:aws:iam::123456789012:user/tester";
  fs::path dir = fs::temp_directory_path() / "vio_cred_test_env" / "cache";
  fs::remove_all(fs::temp_directory_path() / "vio_cred_test_env");
  write_file(dir / login_cache_filename(session), R"({"accessToken":{"accessKeyId":"ASIAFILE","secretAccessKey":"fk","sessionToken":"ft","expiresAt":"2099-01-01T00:00:00Z"}})");

  // Save + clear any ambient AWS_* so the test is deterministic.
  auto saved = [](const char *k) -> std::optional<std::string> {
    const char *v = std::getenv(k);
    return v ? std::optional<std::string>(v) : std::nullopt;
  };
  auto ak0 = saved("AWS_ACCESS_KEY_ID");
  auto sk0 = saved("AWS_SECRET_ACCESS_KEY");
  auto tk0 = saved("AWS_SESSION_TOKEN");
  ::unsetenv("AWS_ACCESS_KEY_ID");
  ::unsetenv("AWS_SECRET_ACCESS_KEY");
  ::unsetenv("AWS_SESSION_TOKEN");

  auto chain = std::make_shared<chain_credentials_provider_t>(std::vector<std::shared_ptr<credentials_provider_t>>{
    std::make_shared<environment_credentials_provider_t>(), std::make_shared<login_cache_credentials_provider_t>(session, dir.string())});

  SUBCASE("env unset -> falls through to the login cache")
  {
    auto c = get_creds(*chain);
    REQUIRE_EXPECTED(c);
    CHECK(c->access_key == "ASIAFILE");
  }

  SUBCASE("env set -> wins over the login cache")
  {
    ::setenv("AWS_ACCESS_KEY_ID", "AKIAENV", 1);
    ::setenv("AWS_SECRET_ACCESS_KEY", "envsecret", 1);
    auto c = get_creds(*chain);
    REQUIRE_EXPECTED(c);
    CHECK(c->access_key == "AKIAENV");
    CHECK(c->secret_key == "envsecret");
    ::unsetenv("AWS_ACCESS_KEY_ID");
    ::unsetenv("AWS_SECRET_ACCESS_KEY");
  }

  // Restore ambient env.
  if (ak0)
    ::setenv("AWS_ACCESS_KEY_ID", ak0->c_str(), 1);
  if (sk0)
    ::setenv("AWS_SECRET_ACCESS_KEY", sk0->c_str(), 1);
  if (tk0)
    ::setenv("AWS_SESSION_TOKEN", tk0->c_str(), 1);
  fs::remove_all(fs::temp_directory_path() / "vio_cred_test_env");
}

TEST_CASE("resolve_credential_chain: end-to-end from a fixture ~/.aws (login_session)")
{
  const std::string session = "arn:aws:iam::123456789012:user/e2e";
  fs::path home = fs::temp_directory_path() / "vio_cred_home";
  fs::remove_all(home);
  write_file(home / ".aws" / "config", "[default]\nlogin_session = " + session + "\nregion = eu-north-1\n");
  write_file(home / ".aws" / "login" / "cache" / login_cache_filename(session), R"({"accessToken":{"accessKeyId":"ASIAE2E","secretAccessKey":"e2ekey","sessionToken":"e2etok","expiresAt":"2099-01-01T00:00:00Z"}})");

  const char *home_env = std::getenv("HOME");
  std::optional<std::string> saved_home = home_env ? std::optional<std::string>(home_env) : std::nullopt;
  ::setenv("HOME", home.string().c_str(), 1);
  // Ensure no ambient env/profile overrides interfere.
  ::unsetenv("AWS_PROFILE");
  ::unsetenv("AWS_CONFIG_FILE");
  ::unsetenv("AWS_SHARED_CREDENTIALS_FILE");
  auto ak0 = std::getenv("AWS_ACCESS_KEY_ID") ? std::optional<std::string>(std::getenv("AWS_ACCESS_KEY_ID")) : std::nullopt;
  ::unsetenv("AWS_ACCESS_KEY_ID");

  auto chain = resolve_credential_chain(std::nullopt);
  REQUIRE(chain.provider != nullptr);
  REQUIRE(chain.region.has_value());
  CHECK(*chain.region == "eu-north-1");
  auto c = get_creds(*chain.provider);
  REQUIRE_EXPECTED(c);
  CHECK(c->access_key == "ASIAE2E");
  CHECK(c->session_token == "e2etok");

  if (saved_home)
    ::setenv("HOME", saved_home->c_str(), 1);
  if (ak0)
    ::setenv("AWS_ACCESS_KEY_ID", ak0->c_str(), 1);
  fs::remove_all(home);
}

// Live end-to-end against real AWS S3, exercising the native credential chain (no AWS_* env; credentials
// come from ~/.aws via `aws login`). Off by default -- opt in with VIO_LIVE_AWS_TEST=1 after `aws login`.
// The fixture object is s3://limilind-public/points/synthetic/blob_00000000_0000000000000000 (eu-north-1).
namespace
{
vio::task_t<void> live_read(vio::event_loop_t &loop, bool &exists, uint64_t &size, uint64_t &bytes_read, std::string &err)
{
  auto mgr = vio::objstore::create_io_manager("s3://limilind-public/points/synthetic", loop);
  if (!mgr)
  {
    err = mgr.error().msg;
    loop.stop();
    co_return;
  }
  auto info = co_await (*mgr)->object_info("blob_00000000_0000000000000000");
  if (!info)
  {
    err = info.error().msg;
    loop.stop();
    co_return;
  }
  exists = info->exists;
  size = info->size;

  std::vector<uint8_t> head(16, 0);
  auto r = co_await (*mgr)->read_object("blob_00000000_0000000000000000", head.data(), {0, 16});
  if (!r)
    err = r.error().msg;
  else
    bytes_read = *r;
  loop.stop();
  co_return;
}
} // namespace

TEST_CASE("live AWS: read via the native ~/.aws credential chain" * doctest::skip())
{
  if (!std::getenv("VIO_LIVE_AWS_TEST"))
    return;
  // Force the native chain: no ambient AWS_* credentials.
  ::unsetenv("AWS_ACCESS_KEY_ID");
  ::unsetenv("AWS_SECRET_ACCESS_KEY");
  ::unsetenv("AWS_SESSION_TOKEN");

  vio::event_loop_t loop;
  bool exists = false;
  uint64_t size = 0, bytes_read = 0;
  std::string err;
  loop.run_in_loop([&] { return live_read(loop, exists, size, bytes_read, err); });
  loop.run();

  INFO("error: " << err);
  CHECK(err.empty());
  CHECK(exists);
  CHECK(size == 101069);
  CHECK(bytes_read == 16);
}

} // TEST_SUITE
