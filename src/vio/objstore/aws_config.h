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

// The entry point that turns the user's `~/.aws` configuration + environment into a credential provider.
// This is the only credential-chain header included by the public create_object_store.h; the concrete
// providers and parsers stay internal (compiled into vio via aws_config.cpp / aws_json.cpp). Native only:
// the browser build injects credentials as a static config and never calls this.

#ifndef __EMSCRIPTEN__

#include <vio/objstore/credentials.h>
#include <vio/vio_export.h>

#include <memory>
#include <optional>
#include <string>

namespace vio::objstore
{

struct credential_chain_t
{
  std::shared_ptr<credentials_provider_t> provider; // never null
  std::optional<std::string> region;                // the profile's configured region, if any
};

// Build the default AWS credential chain for `profile` (nullopt => $AWS_PROFILE, else "default"). Reads
// `~/.aws/config` + `~/.aws/credentials` (honoring $AWS_CONFIG_FILE / $AWS_SHARED_CREDENTIALS_FILE) and
// the environment, in the standard precedence: environment variables, then the profile's own source
// (static keys / `aws login` cache / SSO / assume-role). Resolution is lazy -- the returned provider
// reads files / calls STS on first use -- so a missing or expired login surfaces at request time with an
// actionable message rather than at construction. The provider is never null.
VIO_EXPORT credential_chain_t resolve_credential_chain(std::optional<std::string> profile);

} // namespace vio::objstore

#endif // __EMSCRIPTEN__
