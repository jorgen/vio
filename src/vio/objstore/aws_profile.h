/*
  Copyright (c) 2025 Jørgen Lind

  Permission is hereby granted, free of charge, to any person obtaining a copy of
  this software and associated documentation files (the "Software"), to deal in
  the Software without restriction, including without limitation the rights to
  use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
  of the Software, and to permit persons to whom the Software is furnished to do
  so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
*/
#pragma once

// Resolve a named AWS profile from the parsed shared config (`~/.aws/config`) and credentials
// (`~/.aws/credentials`) files into a small description of how to obtain credentials for it. This is a
// pure function over two ini_file_t inputs (no filesystem, no environment) so it is directly unit-testable.
// The section-naming rules mirror the AWS CLI: the credentials file uses `[<profile>]`, while the config
// file uses `[default]` for the default profile and `[profile <name>]` otherwise; SSO-session settings
// live in `[sso-session <name>]`.

#include <vio/detail/ini.h>

#include <string>

namespace vio::objstore
{

enum class credential_source_t
{
  none,          // nothing usable in this profile (fall back to environment / instance metadata)
  static_keys,   // long-lived or pre-exported temporary keys in the credentials/config file
  login_session, // new `aws login` (DPoP) flow: credentials cached under ~/.aws/login/cache
  sso,           // classic IAM Identity Center: token in ~/.aws/sso/cache + GetRoleCredentials
  assume_role,   // source_profile + role_arn via STS AssumeRole
};

struct resolved_profile_t
{
  credential_source_t source = credential_source_t::none;
  std::string region;

  // static_keys
  std::string access_key_id;
  std::string secret_access_key;
  std::string session_token;

  // login_session (the value is the login session id / IAM ARN hashed to locate the cache file)
  std::string login_session;

  // sso
  std::string sso_session;    // name of the [sso-session <name>] block, if the modern form is used
  std::string sso_start_url;
  std::string sso_region;
  std::string sso_account_id;
  std::string sso_role_name;

  // assume_role
  std::string role_arn;
  std::string source_profile;
  std::string external_id;
  std::string mfa_serial;
};

namespace profile_detail
{
inline const std::string *first(const vio::detail::ini_file_t &ini, std::string_view section, std::string_view key)
{
  return ini.get(section, key);
}

// The config-file section name for a profile: "default" stays "default", everything else is "profile <name>".
inline std::string config_section(const std::string &profile)
{
  return profile == "default" ? std::string("default") : ("profile " + profile);
}
} // namespace profile_detail

inline resolved_profile_t resolve_profile(const vio::detail::ini_file_t &config, const vio::detail::ini_file_t &credentials, const std::string &profile_name)
{
  using profile_detail::first;
  const std::string cfg_section = profile_detail::config_section(profile_name);

  resolved_profile_t out;

  // Region: credentials file wins over config (the CLI treats an explicit region in either as equal; we
  // prefer the credentials file only because it is the more specific, credential-scoped file).
  if (const std::string *r = first(credentials, profile_name, "region"))
    out.region = *r;
  else if (const std::string *r2 = first(config, cfg_section, "region"))
    out.region = *r2;

  // Static keys: the credentials file first, then the config file (both are permitted by the CLI).
  auto pick_static = [&](const vio::detail::ini_file_t &ini, std::string_view section) -> bool {
    const std::string *ak = first(ini, section, "aws_access_key_id");
    const std::string *sk = first(ini, section, "aws_secret_access_key");
    if (ak && sk && !ak->empty() && !sk->empty())
    {
      out.access_key_id = *ak;
      out.secret_access_key = *sk;
      if (const std::string *st = first(ini, section, "aws_session_token"))
        out.session_token = *st;
      return true;
    }
    return false;
  };
  if (pick_static(credentials, profile_name) || pick_static(config, cfg_section))
  {
    out.source = credential_source_t::static_keys;
    return out;
  }

  // Modern SSO via an [sso-session <name>] block.
  if (const std::string *sess = first(config, cfg_section, "sso_session"))
  {
    out.source = credential_source_t::sso;
    out.sso_session = *sess;
    const std::string sso_section = "sso-session " + *sess;
    if (const std::string *v = first(config, sso_section, "sso_start_url"))
      out.sso_start_url = *v;
    if (const std::string *v = first(config, sso_section, "sso_region"))
      out.sso_region = *v;
    if (const std::string *v = first(config, cfg_section, "sso_account_id"))
      out.sso_account_id = *v;
    if (const std::string *v = first(config, cfg_section, "sso_role_name"))
      out.sso_role_name = *v;
    return out;
  }

  // Legacy inline SSO (sso_start_url etc. directly on the profile).
  if (const std::string *start = first(config, cfg_section, "sso_start_url"))
  {
    out.source = credential_source_t::sso;
    out.sso_start_url = *start;
    if (const std::string *v = first(config, cfg_section, "sso_region"))
      out.sso_region = *v;
    if (const std::string *v = first(config, cfg_section, "sso_account_id"))
      out.sso_account_id = *v;
    if (const std::string *v = first(config, cfg_section, "sso_role_name"))
      out.sso_role_name = *v;
    return out;
  }

  // New `aws login` (DPoP) flow.
  if (const std::string *ls = first(config, cfg_section, "login_session"))
  {
    out.source = credential_source_t::login_session;
    out.login_session = *ls;
    return out;
  }

  // STS assume-role.
  if (const std::string *arn = first(config, cfg_section, "role_arn"))
  {
    out.source = credential_source_t::assume_role;
    out.role_arn = *arn;
    if (const std::string *v = first(config, cfg_section, "source_profile"))
      out.source_profile = *v;
    if (const std::string *v = first(config, cfg_section, "external_id"))
      out.external_id = *v;
    if (const std::string *v = first(config, cfg_section, "mfa_serial"))
      out.mfa_serial = *v;
    return out;
  }

  return out; // credential_source_t::none
}

} // namespace vio::objstore
