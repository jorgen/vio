// Peer-to-peer QUIC: two nodes, each one both answering and dialling on its
// own port, and each one knowing who the other is.
//
// Two things make this different from the client/server examples.
//
// An endpoint holds two TLS contexts rather than one. A tls_context_t is built
// for a single role -- it picks TLS_server_method or TLS_client_method and
// gates tickets and early data on that choice -- so a node that does both
// needs one of each, and endpoint_t::create takes them as a pair. Which of the
// two it holds is what decides what it can do: with only an answering context
// it cannot dial, and with only a dialling one an arriving Initial is dropped.
//
// And both ends authenticate. An ordinary server accepts a connection from
// anyone and lets the application sort out authorisation afterwards, which is
// the right arrangement for the web and the wrong one for a mesh: a node that
// cannot say which peer it is talking to has nothing to make a decision on.
// So each node here asks for a certificate and refuses a peer that cannot
// produce one signed by the mesh's authority.
//
// The certificate arrangement is the part worth copying. Each node has its own
// identity, and both trust one CA that signed both -- so adding a third node
// means signing a third certificate, and nothing about the existing two
// changes. Hardcoding each peer's certificate as the other's trust anchor also
// works for exactly two nodes and then stops.

#include <chrono>
#include <cstdint>
#include <optional>
#include <print>
#include <string>
#include <vector>

#include "quic_common.h"

namespace
{
using namespace std::chrono_literals;
using namespace vio_example;

// What one node is: an identity, a socket, and the two contexts that let it
// speak in both directions.
struct peer_t
{
  std::string name;
  std::optional<vio::quic::tls_context_t> answering;
  std::optional<vio::quic::tls_context_t> dialling;
  std::optional<vio::quic::endpoint_t> endpoint;
  vio::cancellation_t cancel;
  std::uint16_t port = 0;
};

// Both halves are built from the same identity and the same trust anchor,
// because a peer is one thing however the connection happened to start. Only
// the role differs, and it has to, since a context is bound to one.
bool build_peer(vio::event_loop_t &loop, peer_t &peer, const identity_t &mesh_ca, const identity_t &self)
{
  using namespace vio::quic;

  tls_config_t answering_tls;
  answering_tls.role = tls_role_t::server;
  answering_tls.certificate_chain_pem = self.certificate_pem;
  answering_tls.private_key_pem = self.private_key_pem;
  answering_tls.ca_certificates_pem = mesh_ca.certificate_pem;
  // The line that makes this a mesh rather than a public service: a peer that
  // presents no certificate, or one the mesh CA did not sign, is refused
  // during the handshake rather than let in to be sorted out later.
  answering_tls.peer_verify = vio::peer_verify_t::required;
  answering_tls.alpn = {"vio-peer"};

  tls_config_t dialling_tls;
  dialling_tls.role = tls_role_t::client;
  dialling_tls.certificate_chain_pem = self.certificate_pem;
  dialling_tls.private_key_pem = self.private_key_pem;
  dialling_tls.ca_certificates_pem = mesh_ca.certificate_pem;
  dialling_tls.alpn = {"vio-peer"};

  auto answering = tls_context_t::create(answering_tls);
  auto dialling = tls_context_t::create(dialling_tls);
  if (!answering || !dialling)
  {
    std::println(stderr, "{}: could not build its TLS contexts", peer.name);
    return false;
  }
  peer.answering.emplace(std::move(*answering));
  peer.dialling.emplace(std::move(*dialling));

  endpoint_config_t config;
  auto created = endpoint_t::create(loop, &*peer.answering, &*peer.dialling, config);
  if (!created)
  {
    std::println(stderr, "{}: endpoint_t::create failed: {}", peer.name, created.error().msg);
    return false;
  }
  peer.endpoint.emplace(std::move(*created));

  auto address = vio::ip4_addr("127.0.0.1", 0);
  if (!address || !peer.endpoint->bind(reinterpret_cast<const sockaddr *>(&*address)))
  {
    std::println(stderr, "{}: could not bind", peer.name);
    return false;
  }
  auto port = peer.endpoint->local_port();
  if (!port)
  {
    std::println(stderr, "{}: could not read its port", peer.name);
    return false;
  }
  peer.port = *port;
  return true;
}
} // namespace

int main()
{
  return vio::run(
    [](vio::event_loop_t &loop) -> vio::task_t<int>
    {
      using namespace vio;
      using namespace vio::quic;

      // One authority for the mesh, and an identity per node signed by it.
      const auto mesh_ca = make_certificate_authority("vio mesh");
      const auto alice_identity = make_signed_by(mesh_ca, "alice");
      const auto bob_identity = make_signed_by(mesh_ca, "bob");

      peer_t alice{.name = "alice"};
      peer_t bob{.name = "bob"};
      if (!build_peer(loop, alice, mesh_ca, alice_identity) || !build_peer(loop, bob, mesh_ca, bob_identity))
      {
        co_return 1;
      }
      std::println("alice on 127.0.0.1:{}, bob on 127.0.0.1:{}", alice.port, bob.port);

      // on_connection fires for every completed handshake, dialled ones
      // included, so a node that does both sorts them by role. Only the ones
      // it answered are arrivals.
      const auto announce = [](const char *who)
      {
        return [who](connection_t &connection)
        {
          if (connection.role() != tls_role_t::server)
          {
            return;
          }
          // Non-empty only because the certificate behind it verified, which
          // is what makes it safe to act on.
          std::println("{}: accepted a connection from \"{}\"", who, connection.peer_certificate_subject());
        };
      };
      alice.endpoint->on_connection(announce("alice"));
      bob.endpoint->on_connection(announce("bob"));

      // Each answers whatever arrives on a stream and echoes it back, so the
      // exchange below can be driven from either side.
      const auto serve = [](connection_t &connection)
      {
        // Only what this node answered. A connection it dialled carries its
        // own request, and whatever comes back on it belongs to whoever made
        // that request -- a handler that echoed there would consume the reply
        // before the caller ever saw it.
        if (connection.role() != tls_role_t::server)
        {
          return;
        }
        for (const auto id : connection.readable_streams())
        {
          auto readable = connection.readable_stream(id);
          (void)connection.write_stream(id, readable, connection.stream_receive_finished(id));
          connection.consume_stream(id, readable.size());
        }
      };
      alice.endpoint->on_activity(serve);
      bob.endpoint->on_activity(serve);

      auto alice_run = [](endpoint_t &endpoint, cancellation_t &cancel) -> detached_task_t { co_await endpoint.run(&cancel); }(*alice.endpoint, alice.cancel);
      auto bob_run = [](endpoint_t &endpoint, cancellation_t &cancel) -> detached_task_t { co_await endpoint.run(&cancel); }(*bob.endpoint, bob.cancel);
      (void)alice_run;
      (void)bob_run;

      // Each dials the other at once. QUIC does not collapse a simultaneous
      // open the way TCP can, so this really is two connections per pair --
      // one dialled and one accepted at each node. A mesh that wants a single
      // link between two nodes has to pick one itself, and that rule belongs
      // to the application rather than to the transport.
      const auto to_bob = ip4_addr("127.0.0.1", bob.port);
      const auto to_alice = ip4_addr("127.0.0.1", alice.port);
      auto alice_dial = alice.endpoint->connect(reinterpret_cast<const sockaddr *>(&*to_bob), "bob");
      auto bob_dial = bob.endpoint->connect(reinterpret_cast<const sockaddr *>(&*to_alice), "alice");
      if (!alice_dial || !bob_dial)
      {
        std::println(stderr, "a dial was refused");
        co_return 1;
      }

      for (int attempt = 0; attempt < 600; ++attempt)
      {
        auto *a = alice.endpoint->connection(*alice_dial);
        auto *b = bob.endpoint->connection(*bob_dial);
        if (a != nullptr && a->handshake_complete() && b != nullptr && b->handshake_complete())
        {
          break;
        }
        co_await sleep(loop, 5ms);
      }

      auto *alice_to_bob = alice.endpoint->connection(*alice_dial);
      auto *bob_to_alice = bob.endpoint->connection(*bob_dial);
      if (alice_to_bob == nullptr || !alice_to_bob->handshake_complete() || bob_to_alice == nullptr || !bob_to_alice->handshake_complete())
      {
        std::println(stderr, "the peers did not reach each other");
        co_return 1;
      }

      // Each dialling side knows who it reached, for the same reason each
      // answering side did.
      std::println("alice dialled \"{}\"", alice_to_bob->peer_certificate_subject());
      std::println("bob dialled \"{}\"", bob_to_alice->peer_certificate_subject());

      auto stream = alice_to_bob->open_stream(stream_direction_t::bidirectional);
      if (!stream)
      {
        std::println(stderr, "no stream credit");
        co_return 1;
      }
      const std::string message = "hello from alice";
      (void)alice_to_bob->write_stream(*stream, bytes_of(message), true);
      (void)alice.endpoint->flush();

      std::string echoed;
      for (int attempt = 0; attempt < 400 && echoed.empty(); ++attempt)
      {
        co_await sleep(loop, 5ms);
        if (auto *live = alice.endpoint->connection(*alice_dial); live != nullptr)
        {
          auto readable = live->readable_stream(*stream);
          if (!readable.empty())
          {
            echoed = text_of(readable);
            live->consume_stream(*stream, readable.size());
          }
        }
      }
      std::println("alice sent \"{}\" and bob returned \"{}\"", message, echoed);

      if (auto *live = alice.endpoint->connection(*alice_dial); live != nullptr)
      {
        live->close(0, "done", true);
      }
      if (auto *live = bob.endpoint->connection(*bob_dial); live != nullptr)
      {
        live->close(0, "done", true);
      }

      co_await sleep(loop, 50ms);
      alice.cancel.cancel();
      bob.cancel.cancel();
      co_await sleep(loop, 50ms);
      alice.endpoint.reset();
      bob.endpoint.reset();
      co_await sleep(loop, 50ms);

      co_return echoed == message ? 0 : 1;
    });
}
