#include <array>
#include <cstdint>
#include <vector>
#include <doctest/doctest.h>
#include <vio/quic/connection_id_manager.h>

// RFC 9000 sections 5.1, 19.15 and 19.16. Most of these rules exist to keep two
// endpoints from disagreeing about which connection IDs are live, and the
// failure they guard against is silent: an endpoint that quietly drops an ID
// the peer still believes in cannot be reached on it.

namespace
{
using namespace vio::quic;

connection_id_t make_id(std::uint8_t seed, std::size_t length = 8)
{
  std::array<std::uint8_t, max_connection_id_size> bytes = {};
  for (std::size_t i = 0; i < length; ++i)
  {
    bytes[i] = static_cast<std::uint8_t>(seed + i);
  }
  auto id = connection_id_t::from_bytes(std::span<const std::uint8_t>(bytes).first(length));
  REQUIRE(id.has_value());
  return *id;
}

stateless_reset_token_t make_token(std::uint8_t seed)
{
  stateless_reset_token_t token = {};
  for (std::size_t i = 0; i < token.size(); ++i)
  {
    token[i] = static_cast<std::uint8_t>(seed ^ i);
  }
  return token;
}

constexpr std::uint64_t generous_limit = 8;
} // namespace

TEST_SUITE("quic connection ids")
{
TEST_CASE("issued ids are numbered from the handshake one")
{
  local_connection_ids_t local;
  local.install_initial(make_id(1), make_token(1));
  CHECK(local.active().size() == 1);
  CHECK(local.next_sequence() == 1);

  const auto &second = local.add(make_id(2), make_token(2));
  CHECK(second.sequence == 1);
  CHECK(local.active().size() == 2);
}

TEST_CASE("issuing stops at the peer's advertised limit")
{
  // Section 5.1.1: an endpoint MUST NOT provide more connection IDs than the
  // peer said it would keep, or the peer must close the connection.
  local_connection_ids_t local;
  local.install_initial(make_id(1), make_token(1));

  std::uint64_t issued = 1;
  while (local.can_issue(4))
  {
    (void)local.add(make_id(static_cast<std::uint8_t>(10 + issued)), make_token(0));
    ++issued;
  }
  CHECK(issued == 4);
}

TEST_CASE("a zero length connection id cannot be supplemented")
{
  // Section 5.1.1: packets toward such an endpoint carry no connection ID at
  // all, so there is nothing an additional one could change.
  local_connection_ids_t local;
  local.install_initial(connection_id_t{}, make_token(1));
  CHECK_FALSE(local.can_issue(generous_limit));
}

TEST_CASE("retiring an id this endpoint never issued is a protocol violation")
{
  local_connection_ids_t local;
  local.install_initial(make_id(1), make_token(1));
  CHECK(local.on_retire(7, make_id(9)) == cid_error_t::protocol_violation);
}

TEST_CASE("retiring the id the packet was addressed to is a protocol violation")
{
  // Section 19.16. The peer would be disowning the only connection ID it had
  // just demonstrated it was using.
  local_connection_ids_t local;
  const auto initial = make_id(1);
  local.install_initial(initial, make_token(1));
  (void)local.add(make_id(2), make_token(2));
  CHECK(local.on_retire(0, initial) == cid_error_t::protocol_violation);
  CHECK(local.active().size() == 2);
}

TEST_CASE("a repeated retire is not an error")
{
  // Section 19.15: retransmission makes duplicates ordinary, so treating the
  // second one as an error would close healthy connections on packet loss.
  local_connection_ids_t local;
  local.install_initial(make_id(1), make_token(1));
  (void)local.add(make_id(2), make_token(2));
  CHECK(local.on_retire(0, make_id(2)) == cid_error_t::none);
  CHECK(local.on_retire(0, make_id(2)) == cid_error_t::none);
  CHECK(local.active().size() == 1);
  CHECK_FALSE(local.accepts(make_id(1)));
}

TEST_CASE("a peer issued id is taken once and repeats are ignored")
{
  remote_connection_ids_t remote;
  remote.install_initial(make_id(1));
  const auto token = make_token(5);

  CHECK(remote.on_new(1, 0, make_id(2), token, generous_limit) == cid_error_t::none);
  CHECK(remote.active_count() == 2);
  CHECK(remote.on_new(1, 0, make_id(2), token, generous_limit) == cid_error_t::none);
  CHECK(remote.active_count() == 2);
}

TEST_CASE("a sequence number that changes its meaning is a protocol violation")
{
  remote_connection_ids_t remote;
  remote.install_initial(make_id(1));
  REQUIRE(remote.on_new(1, 0, make_id(2), make_token(5), generous_limit) == cid_error_t::none);

  SUBCASE("same sequence, different connection id")
  {
    CHECK(remote.on_new(1, 0, make_id(3), make_token(5), generous_limit) == cid_error_t::protocol_violation);
  }
  SUBCASE("same sequence, different reset token")
  {
    CHECK(remote.on_new(1, 0, make_id(2), make_token(6), generous_limit) == cid_error_t::protocol_violation);
  }
  SUBCASE("same connection id, different sequence")
  {
    CHECK(remote.on_new(2, 0, make_id(2), make_token(5), generous_limit) == cid_error_t::protocol_violation);
  }
}

TEST_CASE("retire prior to above the sequence number is a frame encoding error")
{
  // Section 19.15 names this one specifically, and it is FRAME_ENCODING_ERROR
  // rather than PROTOCOL_VIOLATION.
  remote_connection_ids_t remote;
  remote.install_initial(make_id(1));
  CHECK(remote.on_new(1, 2, make_id(2), make_token(5), generous_limit) == cid_error_t::frame_encoding);
}

TEST_CASE("retire prior to withdraws the older ids and owes a retire for each")
{
  remote_connection_ids_t remote;
  remote.install_initial(make_id(1));
  REQUIRE(remote.on_new(1, 0, make_id(2), make_token(1), generous_limit) == cid_error_t::none);
  REQUIRE(remote.on_new(2, 0, make_id(3), make_token(2), generous_limit) == cid_error_t::none);
  CHECK(remote.active_count() == 3);

  REQUIRE(remote.on_new(3, 2, make_id(4), make_token(3), generous_limit) == cid_error_t::none);
  // Sequences 0 and 1 are gone; 2 and 3 remain.
  CHECK(remote.active_count() == 2);
  const auto &owed = remote.pending_retires();
  CHECK(std::find(owed.begin(), owed.end(), std::uint64_t{0}) != owed.end());
  CHECK(std::find(owed.begin(), owed.end(), std::uint64_t{1}) != owed.end());
}

TEST_CASE("a smaller retire prior to arriving later is ignored")
{
  // Section 19.15. Frames reorder, and obeying a stale value would resurrect
  // connection IDs the peer has already stopped accepting.
  remote_connection_ids_t remote;
  remote.install_initial(make_id(1));
  REQUIRE(remote.on_new(2, 2, make_id(2), make_token(1), generous_limit) == cid_error_t::none);
  const auto after_first = remote.active_count();

  REQUIRE(remote.on_new(3, 1, make_id(3), make_token(2), generous_limit) == cid_error_t::none);
  CHECK(remote.active_count() == after_first + 1);
}

TEST_CASE("an id already covered by retire prior to is retired, not adopted")
{
  // Section 19.15 requires the retire to be sent even though the ID is never
  // used, so the peer stops counting it against its own limit.
  remote_connection_ids_t remote;
  remote.install_initial(make_id(1));
  REQUIRE(remote.on_new(4, 4, make_id(2), make_token(1), generous_limit) == cid_error_t::none);
  const auto before = remote.active_count();

  REQUIRE(remote.on_new(2, 0, make_id(3), make_token(2), generous_limit) == cid_error_t::none);
  CHECK(remote.active_count() == before);
  const auto &owed = remote.pending_retires();
  CHECK(std::find(owed.begin(), owed.end(), std::uint64_t{2}) != owed.end());
}

TEST_CASE("more active ids than advertised is a connection id limit error")
{
  remote_connection_ids_t remote;
  remote.install_initial(make_id(1));
  REQUIRE(remote.on_new(1, 0, make_id(2), make_token(1), 2) == cid_error_t::none);
  CHECK(remote.on_new(2, 0, make_id(3), make_token(2), 2) == cid_error_t::limit_exceeded);
}

TEST_CASE("a truncated reset token is a frame encoding error")
{
  remote_connection_ids_t remote;
  remote.install_initial(make_id(1));
  std::vector<std::uint8_t> short_token(stateless_reset_token_size - 1, 0x11);
  CHECK(remote.on_new(1, 0, make_id(2), short_token, generous_limit) == cid_error_t::frame_encoding);
}

TEST_CASE("switching to an unused id leaves the old one for the peer to retire")
{
  // Section 9.5: a new path must not reuse the connection ID the old one was
  // seen with, or an observer links the two.
  remote_connection_ids_t remote;
  remote.install_initial(make_id(1));
  CHECK_FALSE(remote.has_unused());
  CHECK_FALSE(remote.switch_to_unused());

  REQUIRE(remote.on_new(1, 0, make_id(2), make_token(1), generous_limit) == cid_error_t::none);
  CHECK(remote.has_unused());
  REQUIRE(remote.current() != nullptr);
  CHECK(*remote.current() == make_id(1));

  CHECK(remote.switch_to_unused());
  REQUIRE(remote.current() != nullptr);
  CHECK(*remote.current() == make_id(2));

  // Nothing is owed. The peer whose address moved under it -- a NAT rebinding
  // it never asked for -- still has the old ID bound to the path it is using,
  // and a RETIRE_CONNECTION_ID naming it is a protocol violation from there.
  // picoquic answers one with "cannot delete path through which packet
  // arrives"; retirement is the peer's call, via its own Retire Prior To.
  CHECK(remote.pending_retires().empty());

  // Only ids the peer has never seen on the old path qualify, so a second
  // switch with nothing fresh left stays put rather than going back.
  CHECK_FALSE(remote.has_unused());
  CHECK_FALSE(remote.switch_to_unused());
  REQUIRE(remote.current() != nullptr);
  CHECK(*remote.current() == make_id(2));
}

TEST_CASE("a Retire Prior To covering the id in use moves to a live one")
{
  // The peer is entitled to retire the ID this endpoint is addressing packets
  // to. Keeping it is wrong twice over: the peer has discarded it, and the
  // RETIRE_CONNECTION_ID owed for it would ride in a packet the frame names,
  // which section 5.1.2 makes a protocol violation.
  remote_connection_ids_t remote;
  remote.install_initial(make_id(1));
  REQUIRE(remote.current() != nullptr);
  CHECK(*remote.current() == make_id(1));

  REQUIRE(remote.on_new(1, 0, make_id(2), make_token(1), generous_limit) == cid_error_t::none);
  REQUIRE(remote.on_new(2, 2, make_id(3), make_token(2), generous_limit) == cid_error_t::none);

  // Sequences 0 and 1 are gone, so the id in use cannot still be sequence 0.
  REQUIRE(remote.current() != nullptr);
  CHECK(*remote.current() == make_id(3));

  const auto &owed = remote.pending_retires();
  CHECK(std::find(owed.begin(), owed.end(), std::uint64_t{0}) != owed.end());
  CHECK(std::find(owed.begin(), owed.end(), std::uint64_t{1}) != owed.end());
}

TEST_CASE("a Retire Prior To arriving with its own replacement lands on that one")
{
  // Section 19.15 allows retire_prior_to to equal the sequence it arrives on,
  // which retires everything older in the same breath as supplying the
  // replacement. The id in use has to end up being the one that survived.
  remote_connection_ids_t remote;
  remote.install_initial(make_id(1));
  REQUIRE(remote.on_new(1, 0, make_id(2), make_token(1), generous_limit) == cid_error_t::none);
  REQUIRE(remote.on_new(2, 2, make_id(3), make_token(2), generous_limit) == cid_error_t::none);
  REQUIRE(remote.current() != nullptr);
  CHECK(*remote.current() == make_id(3));
  CHECK(remote.active_count() == 1);
}

TEST_CASE("a retire stays owed until it is sent, and can be put back")
{
  remote_connection_ids_t remote;
  remote.install_initial(make_id(1));
  REQUIRE(remote.on_new(1, 1, make_id(2), make_token(1), generous_limit) == cid_error_t::none);
  REQUIRE(remote.pending_retires().size() == 1);

  remote.clear_pending_retire(0);
  CHECK(remote.pending_retires().empty());

  // Section 13.3 has RETIRE_CONNECTION_ID retransmitted on loss.
  remote.requeue_retire(0);
  CHECK(remote.pending_retires().size() == 1);
  remote.requeue_retire(0);
  CHECK(remote.pending_retires().size() == 1);
}
}
