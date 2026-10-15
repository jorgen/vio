// How a QUIC connection ends, and how an application finds out.
//
// Read this one before putting anything on a real network. Every ending below
// is discovered the same way -- by awaiting quic_connection_closed -- and the
// result says which of them it was. There is no callback to install and nothing
// to poll: a connection that ends resumes whoever was waiting for it, and one
// that has already ended answers immediately rather than blocking for ever.
//
// Three endings, in order:
//
//   1. The peer closed, and said why. A CONNECTION_CLOSE carries a code and a
//      reason, and quic_connection_close_reason hands both back with from_peer
//      set. A zero code is a clean ending and arrives as success.
//   2. Nobody answered. A dial that gets no reply is ended by
//      connection_config_t::handshake_timeout, which exists because the idle
//      timeout is negotiated and so does not exist yet.
//   3. The peer went quiet. Once transport parameters have been exchanged the
//      negotiated idle timeout applies, and it closes the connection silently
//      -- no frame is sent, so the other end learns nothing from it.

#include <chrono>
#include <cstdint>
#include <optional>
#include <print>
#include <string>

#include <vio/operation/udp.h>

#include "quic_common.h"

namespace
{
using namespace std::chrono_literals;
using namespace vio_example;

// The defaults would keep an idle connection for thirty seconds, which is the
// right answer for a program that is not about timeouts and the wrong one for
// this example. Both endpoints offer the same value and each side uses the
// smaller of its own and the peer's.
vio::quic::transport_parameters_t parameters()
{
  auto out = vio::quic::default_transport_parameters();
  out.max_idle_timeout = 1000;
  return out;
}

std::string describe(const vio::quic_connection_t &connection)
{
  const auto reason = vio::quic_connection_close_reason(connection);
  if (!reason)
  {
    return "closed with nothing recorded";
  }
  return std::format("{} error {}{}", reason->from_peer ? "peer sent" : "we sent", reason->error_code, reason->reason.empty() ? std::string{} : std::format(" (\"{}\")", reason->reason));
}

// What an ending means, in the codes this layer publishes. Every one of them is
// a distinct thing that can happen to a connection, and the whole reason they
// are separate numbers is that an application does different things about them.
std::string classify(const std::expected<void, vio::error_t> &ending)
{
  using namespace vio;
  if (ending)
  {
    return "ended cleanly";
  }
  switch (ending.error().code)
  {
  case vio_quic_connection_closed:
    return "closed with an error";
  case vio_quic_idle_timeout:
    return "idle timeout";
  case vio_quic_handshake_failed:
    return "the handshake never completed";
  case vio_quic_stateless_reset:
    return "the peer no longer remembers it";
  case vio_quic_endpoint_closed:
    return "the endpoint went away";
  default:
    return ending.error().msg;
  }
}
} // namespace

int main()
{
  return vio::run(
    [](vio::event_loop_t &loop) -> vio::task_t<int>
    {
      using namespace vio;
      using namespace vio::quic;

      const auto identity = make_self_signed("localhost");

      tls_config_t server_tls;
      server_tls.role = tls_role_t::server;
      server_tls.certificate_chain_pem = identity.certificate_pem;
      server_tls.private_key_pem = identity.private_key_pem;
      server_tls.alpn = {"vio-close"};
      auto server_context = tls_context_t::create(server_tls);
      if (!server_context)
      {
        std::println(stderr, "server tls_context_t::create: {}", server_context.error().msg);
        co_return 1;
      }

      tls_config_t client_tls;
      client_tls.role = tls_role_t::client;
      client_tls.ca_certificates_pem = identity.certificate_pem;
      client_tls.alpn = {"vio-close"};
      auto client_context = tls_context_t::create(client_tls);
      if (!client_context)
      {
        std::println(stderr, "client tls_context_t::create: {}", client_context.error().msg);
        co_return 1;
      }

      quic_config_t server_config;
      server_config.transport.connection.transport_parameters = parameters();
      // How long a closed connection is kept, so a packet still in flight meets
      // silence rather than a stateless reset. Shortened here only so the
      // example can watch a connection actually disappear.
      server_config.transport.draining_period = 250ms;

      quic_config_t client_config;
      client_config.transport.connection.transport_parameters = parameters();
      // The one timeout that covers a handshake. The negotiated idle timeout
      // cannot: it does not exist until the peer's transport parameters have
      // arrived, so without this a dial that is never answered is held for the
      // life of the process.
      client_config.transport.connection.handshake_timeout = 1s;
      client_config.transport.draining_period = 250ms;

      auto server = quic_endpoint_create(loop, *server_context, server_config);
      auto client = quic_endpoint_create(loop, nullptr, &*client_context, client_config);
      if (!server || !client)
      {
        std::println(stderr, "quic_endpoint_create failed");
        co_return 1;
      }
      if (auto bound = quic_endpoint_bind(*server, std::uint16_t{0}); !bound)
      {
        std::println(stderr, "quic_endpoint_bind: {}", bound.error().msg);
        co_return 1;
      }
      const auto port = quic_endpoint_local_port(*server).value_or(0);
      std::println("server listening on port {}", port);

      const auto target = ip4_addr("127.0.0.1", port);
      if (!target)
      {
        std::println(stderr, "could not build the target address");
        co_return 1;
      }

      // ---- 1. the peer closed, and said why ----
      //
      // The server accepts, closes with a code and a reason, and the client
      // learns all of it by awaiting the ending. Note which side each fact
      // comes from: the *code* is the server's, and from_peer is what tells the
      // client it did not close this connection itself.
      {
        auto serving = [](quic_endpoint_t &endpoint) -> vio::task_t<void>
        {
          auto connection = co_await quic_endpoint_accept(endpoint);
          if (!connection)
          {
            co_return;
          }
          quic_connection_close(*connection, 42, "go away");
          const auto ending = co_await quic_connection_closed(*connection);
          std::println("server: its own connection {}", classify(ending));
        }(*server);

        auto connection = co_await quic_endpoint_connect(*client, reinterpret_cast<const sockaddr *>(&*target), "localhost");
        if (!connection)
        {
          std::println(stderr, "connect: {}", connection.error().msg);
          co_return 1;
        }

        const auto ending = co_await quic_connection_closed(*connection);
        std::println("client: {} -- {}", classify(ending), describe(*connection));
        // And the handle keeps answering afterwards, which is what makes it
        // safe to hold one past the ending: the endpoint frees the connection
        // on its own schedule and says nothing about it.
        std::println("client: still open? {}", quic_connection_is_open(*connection));
        co_await std::move(serving);
      }

      // ---- 2. nobody answered ----
      //
      // A UDP socket that is bound and never read, so the Initials reach a real
      // port and are simply swallowed. Dialling a CLOSED port would be a weaker
      // demonstration: the ICMP port-unreachable that comes back could end the
      // attempt early, and what is being shown here is the timeout.
      {
        auto silence = udp_create(loop);
        if (!silence)
        {
          std::println(stderr, "udp_create: {}", silence.error().msg);
          co_return 1;
        }
        const auto nowhere = ip4_addr("127.0.0.1", 0);
        if (!nowhere || !udp_bind(*silence, reinterpret_cast<const sockaddr *>(&*nowhere)))
        {
          std::println(stderr, "could not bind the silent socket");
          co_return 1;
        }
        const auto bound = udp_sockname(*silence);
        if (!bound)
        {
          std::println(stderr, "could not read the silent socket's port");
          co_return 1;
        }
        const auto silent_port = ntohs(reinterpret_cast<const sockaddr_in *>(&*bound)->sin_port);
        const auto silent = ip4_addr("127.0.0.1", silent_port);

        // The dial itself resolves with the failure. There is no separate
        // ending to wait for, because there was never a connection to have one.
        const auto attempt = co_await quic_endpoint_connect(*client, reinterpret_cast<const sockaddr *>(&*silent), "localhost");
        std::println("client: dialling silence -- {}", attempt ? std::string("connected?!") : classify(std::unexpected(attempt.error())));
      }

      // ---- 3. the peer went quiet ----
      //
      // Section 10.1 closes silently: no frame is sent, so the peer learns
      // nothing from it and must have its own timer. That is exactly why the
      // ending has its own code -- the transport records it with the same error
      // code, the same application flag and the same from_peer as a clean local
      // close, and nothing else separates them.
      {
        auto serving = [](quic_endpoint_t &endpoint) -> vio::task_t<void>
        {
          auto connection = co_await quic_endpoint_accept(endpoint);
          if (!connection)
          {
            co_return;
          }
          // Accepted and then ignored, which is all it takes.
          const auto ending = co_await quic_connection_closed(*connection);
          std::println("server: the quiet connection {}", classify(ending));
        }(*server);

        auto connection = co_await quic_endpoint_connect(*client, reinterpret_cast<const sockaddr *>(&*target), "localhost");
        if (!connection)
        {
          std::println(stderr, "connect: {}", connection.error().msg);
          co_return 1;
        }
        const auto ending = co_await quic_connection_closed(*connection);
        std::println("client: the quiet connection {}", classify(ending));
        co_await std::move(serving);
      }

      // Nothing is torn down by hand. Both endpoints go out of scope when this
      // coroutine returns, each closing its socket, and vio::run stops the loop
      // afterwards. The order that used to matter -- cancel, wait, release,
      // wait -- was a consequence of driving run() by hand, and there is no
      // run() to drive any more.
      co_return 0;
    });
}
