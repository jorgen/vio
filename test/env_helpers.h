#pragma once

// Portable environment-variable helpers for tests.
//
// MSVC has neither setenv nor unsetenv. _putenv_s covers both: assigning an
// empty value removes the variable, which is what unsetenv does.

#include <cstdlib>

namespace vio::test
{
inline void set_env(const char *name, const char *value)
{
#ifdef _WIN32
  _putenv_s(name, value);
#else
  ::setenv(name, value, 1);
#endif
}

inline void unset_env(const char *name)
{
#ifdef _WIN32
  _putenv_s(name, "");
#else
  ::unsetenv(name);
#endif
}

// The variable vio::detail::home_dir() actually consults, so a test that
// redirects the home directory to a fixture redirects the same one.
inline const char *home_env_name()
{
#ifdef _WIN32
  return "USERPROFILE";
#else
  return "HOME";
#endif
}
}
