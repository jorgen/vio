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

// The credentials abstraction that the S3 signer consults per request. A credentials_provider_t resolves
// and (for temporary credentials) auto-refreshes AWS SigV4 credentials -- from the environment, the
// `~/.aws` files (static keys, `aws login` cache, SSO), STS assume-role, or EC2/ECS instance metadata.
// The abstract interface here is available in every build (it is pure std + vio coroutine types); the
// concrete providers and the `~/.aws`-driven resolver live in the native-only credential_providers /
// aws_config headers and are compiled into vio (see aws_credentials.cpp). In the browser build no
// provider is used -- credentials are injected as a static config (see create_object_store.h).

#include <vio/error.h>
#include <vio/event_loop.h>
#include <vio/task.h>
#include <vio/vio_export.h>

#include <chrono>
#include <expected>
#include <optional>
#include <string>

namespace vio::objstore
{

// Resolved SigV4 credential material. `session_token` is empty for long-lived (AKIA...) keys and set for
// temporary (ASIA...) STS/SSO credentials. `expiration` is nullopt when the credentials never expire.
struct credentials_t
{
  std::string access_key;
  std::string secret_key;
  std::string session_token;
  std::optional<std::chrono::system_clock::time_point> expiration;
};

// How long before the stated expiry a provider treats credentials as due for refresh, so a request is
// never signed with credentials about to expire mid-flight.
inline constexpr std::chrono::seconds credentials_refresh_skew{300};

// Async source of credentials. Implementations cache their last result and refresh transparently (an HTTP
// call or a file re-read) when it is near expiry, so credentials() is a cheap cache hit on the common
// path. A single provider is owned by each s3_io_manager_t and only ever touched on that manager's loop
// thread, so implementations need no internal locking.
class VIO_EXPORT credentials_provider_t
{
public:
  virtual ~credentials_provider_t() = default;

  // Current valid credentials, refreshing first if the cached set is missing or near expiry. On failure
  // (e.g. an expired `aws login` session, or no credentials configured) returns an error whose message is
  // suitable to show the user.
  virtual task_t<std::expected<credentials_t, error_t>> credentials(event_loop_t &loop) = 0;
};

} // namespace vio::objstore
