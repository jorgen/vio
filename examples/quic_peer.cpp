// Peer-to-peer QUIC: two nodes, each one both answering and dialling on its
// own port, and each one knowing who the other is.
//
// Two things make this different from the client/server examples.
//
// An endpoint holds two TLS contexts rather than one. A tls_context_t is built
// for a single role -- it picks TLS_server_method or TLS_client_method and
// gates tickets and early data on that choice -- so a node that does both needs
// one of each, and quic_endpoint_create takes them as a pair. Which of the two
// it holds is what decides what it can do: with only an answering context a
// dial is refused with a sentence, and with only a dialling one an accept is.
//
// And both ends authenticate. An ordinary server accepts a connection from
// anyone and lets the application sort out authorisation afterwards, which is
// the right arrangement for the web and the wrong one for a mesh: a node that
// cannot say which peer it is talking to has nothing to make a decision on. So
// each node here asks for a certificate and refuses a peer that cannot produce
// one signed by the mesh's authority.
//
// The certificate arrangement is the part worth copying. Each node has its own
// identity, and both trust one CA that signed both -- so adding a third node
// means signing a third certificate, and nothing about the existing two
// changes. Hardcoding each peer's certificate as the other's trust anchor also
// works for exactly two nodes and then stops.

#include <cstdint>
#include <optional>
#include <print>
#include <string>

#include "quic_common.h"

namespace
{
using namespace vio_example;

// What one node is: an identity, a socket, and the two contexts that let it
// speak in both directions.
struct peer_t
{
  std::string name;
  std::optional<vio::quic::tls_context_t> answering;
  std::optional<vio::quic::tls_context_t> dialling;
  std::optional<vio::quic_endpoint_t> endpoint;
  std::uint16_t port = 0;
};

// Both halves are built from the same identity and the same trust anchor,
// because a peer is one thing however the connection happened to start. Only
// the role differs, and it has to, since a context is bound to one.
bool build_peer(vio::event_loop_t &loop, peer_t &peer, const identity_t &mesh_ca, const identity_t &self)
{
  using namespace vio;
  using namespace vio::quic;

  tls_config_t answering_tls;
  answering_tls.role = tls_role_t::server;
  answering_tls.certificate_chain_pem = self.certificate_pem;
  answering_tls.private_key_pem = self.private_key_pem;
  answering_tls.ca_certificates_pem = mesh_ca.certificate_pem;
  // The line that makes this a mesh rather than a public service: a peer that
  // presents no certificate, or one the mesh CA did not sign, is refused during
  // the handshake rather than let in to be sorted out later.
  answering_tls.peer_verify = peer_verify_t::required;
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

  auto created = quic_endpoint_create(loop, &*peer.answering, &*peer.dialling);
  if (!created)
  {
    std::println(stderr, "{}: quic_endpoint_create: {}", peer.name, created.error().msg);
    return false;
  }
  peer.endpoint.emplace(std::move(*created));

  // Bound with an explicit IPv4 address rather than by port, because these
  // nodes dial each other at IPv4 literals: the port-only bind prefers
  // dual-stack IPv6, and a socket that has a family cannot send to another.
  const auto address = ip4_addr("127.0.0.1", 0);
  if (!address || !quic_endpoint_bind(*peer.endpoint, reinterpret_cast<const sockaddr *>(&*address)))
  {
    std::println(stderr, "{}: could not bind", peer.name);
    return false;
  }
  peer.port = quic_endpoint_local_port(*peer.endpoint).value_or(0);
  return peer.port != 0;
}

// Answers one stream and echoes it back. A node runs one of these per
// connection it accepted -- and only per connection it accepted, because a
// connection it dialled carries its own request and whatever comes back on it
// belongs to whoever made that request.
vio::task_t<void> serve(vio::quic_connection_t connection, const char *who)
{
  using namespace vio;
  // Non-empty only because the certificate behind it verified, which is what
  // makes it safe to act on.
  std::println("{}: accepted a connection from \"{}\"", who, quic_connection_peer_certificate_subject(connection));

  auto stream = co_await quic_accept_stream(connection);
  if (!stream)
  {
    co_return;
  }
  auto reader = quic_stream_create_reader(*stream);
  if (!reader)
  {
    co_return;
  }
  std::string request;
  while (auto chunk = co_await *reader)
  {
    request += text_of(*chunk);
  }
  (void)co_await quic_stream_write_final(*stream, bytes_of(request));
}

// Waits for one connection to arrive and serves it. On a real mesh this would
// be a loop; one is enough to show the sort.
vio::task_t<void> answer_one(vio::quic_endpoint_t &endpoint, const char *who)
{
  auto connection = co_await vio::quic_endpoint_accept(endpoint);
  if (!connection)
  {
    co_return;
  }
  co_await serve(*connection, who);
}

// The other half: opens a stream on a connection this node dialled, says one
// thing on it, and reads the answer back.
vio::task_t<std::string> ask(vio::quic_connection_t connection, std::string message)
{
  using namespace vio;
  auto stream = co_await quic_open_stream(connection);
  if (!stream)
  {
    std::println(stderr, "quic_open_stream: {}", stream.error().msg);
    co_return std::string{};
  }
  if (auto written = co_await quic_stream_write_final(*stream, bytes_of(message)); !written)
  {
    std::println(stderr, "quic_stream_write_final: {}", written.error().msg);
    co_return std::string{};
  }
  auto reader = quic_stream_create_reader(*stream);
  if (!reader)
  {
    std::println(stderr, "quic_stream_create_reader: {}", reader.error().msg);
    co_return std::string{};
  }
  std::string echoed;
  while (auto chunk = co_await *reader)
  {
    echoed += text_of(*chunk);
  }
  co_return echoed;
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

      // Each node stands ready to answer. This is where the role sort lives
      // now, and it is structural rather than a test inside a callback: an
      // accept resolves only for connections that arrived, so a node's own
      // outbound connection can never be mistaken for one.
      auto alice_answering = answer_one(*alice.endpoint, "alice");
      auto bob_answering = answer_one(*bob.endpoint, "bob");

      // Each dials the other at once. QUIC does not collapse a simultaneous
      // open the way TCP can, so this really is two connections per pair -- one
      // dialled and one accepted at each node. A mesh that wants a single link
      // between two nodes has to pick one itself, and that rule belongs to the
      // application rather than to the transport.
      const auto to_bob = ip4_addr("127.0.0.1", bob.port);
      const auto to_alice = ip4_addr("127.0.0.1", alice.port);
      if (!to_bob || !to_alice)
      {
        std::println(stderr, "could not build the peer addresses");
        co_return 1;
      }

      auto alice_to_bob = co_await quic_endpoint_connect(*alice.endpoint, reinterpret_cast<const sockaddr *>(&*to_bob), "bob");
      auto bob_to_alice = co_await quic_endpoint_connect(*bob.endpoint, reinterpret_cast<const sockaddr *>(&*to_alice), "alice");
      if (!alice_to_bob || !bob_to_alice)
      {
        std::println(stderr, "the peers did not reach each other");
        co_return 1;
      }

      // Each dialling side knows who it reached, for the same reason each
      // answering side did. And each says which end of the handshake it ran,
      // which a peer-to-peer application needs and a client never has to ask.
      std::println("alice dialled \"{}\" as a {}", quic_connection_peer_certificate_subject(*alice_to_bob), quic_connection_role(*alice_to_bob) == tls_role_t::client ? "client" : "server");
      std::println("bob dialled \"{}\" as a {}", quic_connection_peer_certificate_subject(*bob_to_alice), quic_connection_role(*bob_to_alice) == tls_role_t::client ? "client" : "server");

      // Both directions at once, which is the shape a mesh actually has and the
      // reason the two coroutines above had to be started before either dial:
      // each node is answering the other while it waits for its own answer, and
      // a program that did one and then the other would deadlock the moment
      // both nodes chose the same order.
      const std::string from_alice = "hello from alice";
      const std::string from_bob = "hello from bob";
      auto alice_asking = ask(*alice_to_bob, from_alice);
      auto bob_asking = ask(*bob_to_alice, from_bob);

      const auto alice_heard = co_await std::move(alice_asking);
      const auto bob_heard = co_await std::move(bob_asking);
      std::println("alice sent \"{}\" and bob returned \"{}\"", from_alice, alice_heard);
      std::println("bob sent \"{}\" and alice returned \"{}\"", from_bob, bob_heard);

      co_await std::move(alice_answering);
      co_await std::move(bob_answering);

      quic_connection_close(*alice_to_bob, 0, "done");
      quic_connection_close(*bob_to_alice, 0, "done");
      co_return (alice_heard == from_alice && bob_heard == from_bob) ? 0 : 1;
    });
}
