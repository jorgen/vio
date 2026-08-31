#include <chrono>
#include <cstdint>
#include <set>
#include <vector>
#include <doctest/doctest.h>
#include <vio/quic/path.h>

// RFC 9000 section 8.2. These exercise the mechanism on its own, where the
// interesting cases -- a response that matches nothing, one that arrives after
// the attempt was abandoned, a peer that floods challenges -- can be produced
// directly instead of being coaxed out of two connections.

namespace
{
using namespace vio::quic;
using namespace std::chrono_literals;

vio::tick_t at(std::chrono::nanoseconds offset)
{
  return vio::tick_t::from_nanoseconds(offset);
}

constexpr auto abandon_after = 1s;
} // namespace

TEST_SUITE("quic path validation")
{
TEST_CASE("a challenge is answered by its own echo")
{
  path_validator_t validator;
  CHECK(validator.state() == path_state_t::unknown);

  validator.begin(at(0ns), abandon_after);
  CHECK(validator.state() == path_state_t::validating);
  CHECK(validator.challenge_due(at(0ns), 100ms));

  auto issued = validator.issue(at(0ns), abandon_after);
  REQUIRE(issued.has_value());
  CHECK(validator.on_response(*issued));
  CHECK(validator.state() == path_state_t::validated);
}

TEST_CASE("the data is unpredictable")
{
  // Section 8.2.1 requires it, because the echo is the only evidence that the
  // peer receives at the address it claims. A guessable payload lets an
  // off-path attacker answer a challenge it never saw.
  path_validator_t validator;
  std::set<path_challenge_data_t> seen;
  for (int i = 0; i < 64; ++i)
  {
    validator.begin(at(0ns), abandon_after);
    auto issued = validator.issue(at(0ns), abandon_after);
    REQUIRE(issued.has_value());
    seen.insert(*issued);
    validator.reset();
  }
  CHECK(seen.size() == 64);
}

TEST_CASE("a response that matches nothing outstanding is ignored")
{
  path_validator_t validator;
  validator.begin(at(0ns), abandon_after);
  auto issued = validator.issue(at(0ns), abandon_after);
  REQUIRE(issued.has_value());

  path_challenge_data_t forged = *issued;
  forged[0] ^= 0xff;
  CHECK_FALSE(validator.on_response(forged));
  CHECK(validator.state() == path_state_t::validating);

  // The genuine one still works afterwards: a wrong answer must not consume
  // the challenge, or an off-path attacker could deny validation by guessing.
  CHECK(validator.on_response(*issued));
  CHECK(validator.state() == path_state_t::validated);
}

TEST_CASE("a response of the wrong length is ignored")
{
  path_validator_t validator;
  validator.begin(at(0ns), abandon_after);
  auto issued = validator.issue(at(0ns), abandon_after);
  REQUIRE(issued.has_value());

  std::vector<std::uint8_t> truncated(issued->begin(), issued->end() - 1);
  CHECK_FALSE(validator.on_response(truncated));
  CHECK(validator.state() == path_state_t::validating);
}

TEST_CASE("any of several outstanding challenges validates the path")
{
  // Section 8.2.1 allows sending more than one to survive loss, and section
  // 13.3 requires different data each time, so the earlier ones must stay
  // eligible -- otherwise the response to a challenge that was retried once
  // would be discarded as stale.
  path_validator_t validator;
  validator.begin(at(0ns), abandon_after);

  std::vector<path_challenge_data_t> issued;
  for (int i = 0; i < 3; ++i)
  {
    auto data = validator.issue(at(std::chrono::milliseconds(i * 10)), abandon_after);
    REQUIRE(data.has_value());
    issued.push_back(*data);
  }
  CHECK(validator.on_response(issued.front()));
  CHECK(validator.state() == path_state_t::validated);
}

TEST_CASE("the set of eligible challenges is bounded")
{
  path_validator_t validator;
  validator.begin(at(0ns), abandon_after);

  std::vector<path_challenge_data_t> issued;
  for (std::size_t i = 0; i < max_outstanding_challenges + 2; ++i)
  {
    auto data = validator.issue(at(0ns), abandon_after);
    REQUIRE(data.has_value());
    issued.push_back(*data);
  }
  // The oldest fell out; the newest is still good. A peer that never answers
  // must not be able to grow this without limit.
  CHECK_FALSE(validator.on_response(issued.front()));
  CHECK(validator.on_response(issued.back()));
}

TEST_CASE("an attempt is abandoned on its deadline")
{
  path_validator_t validator;
  validator.begin(at(0ns), abandon_after);
  auto issued = validator.issue(at(0ns), abandon_after);
  REQUIRE(issued.has_value());

  validator.on_timeout(at(999ms));
  CHECK(validator.state() == path_state_t::validating);

  validator.on_timeout(at(1s));
  CHECK(validator.state() == path_state_t::failed);

  // Section 8.2.4: the attempt is over, so a late echo does not revive it.
  CHECK_FALSE(validator.on_response(*issued));
  CHECK(validator.state() == path_state_t::failed);
}

TEST_CASE("the deadline covers the attempt, not each challenge in it")
{
  path_validator_t validator;
  validator.begin(at(0ns), abandon_after);
  auto first = validator.issue(at(0ns), abandon_after);
  REQUIRE(first.has_value());
  // Re-probing later must not push the deadline out, or a validator that keeps
  // retrying would never abandon.
  auto second = validator.issue(at(900ms), abandon_after);
  REQUIRE(second.has_value());

  validator.on_timeout(at(1s));
  CHECK(validator.state() == path_state_t::failed);
}

TEST_CASE("probing is rate limited to the interval it is given")
{
  // Section 8.2.1: no more often than an Initial would be retried, so that
  // migrating costs a path no more than opening a connection would.
  path_validator_t validator;
  validator.begin(at(0ns), abandon_after);
  CHECK(validator.challenge_due(at(0ns), 100ms));

  auto issued = validator.issue(at(0ns), abandon_after);
  REQUIRE(issued.has_value());
  CHECK_FALSE(validator.challenge_due(at(50ms), 100ms));
  CHECK(validator.challenge_due(at(100ms), 100ms));
}

TEST_CASE("nothing is due when no attempt is running")
{
  path_validator_t validator;
  CHECK_FALSE(validator.challenge_due(at(0ns), 100ms));
  CHECK_FALSE(validator.deadline().has_value());

  validator.mark_validated();
  CHECK_FALSE(validator.challenge_due(at(1s), 100ms));
  CHECK_FALSE(validator.deadline().has_value());
}

TEST_CASE("the echo queue keeps the newest and is bounded")
{
  // Section 8.2.2 owes one response per challenge, but a peer can produce
  // challenges faster than this endpoint produces packets. Section 13.3 says
  // the peer re-challenges when no answer arrives, so dropping costs a round
  // trip -- which is why the queue may be bounded at all.
  path_response_queue_t queue;
  CHECK(queue.empty());

  std::vector<path_challenge_data_t> pushed;
  for (std::size_t i = 0; i < max_queued_path_responses + 2; ++i)
  {
    path_challenge_data_t data = {};
    data[0] = static_cast<std::uint8_t>(i);
    pushed.push_back(data);
    queue.push(data);
  }

  std::vector<path_challenge_data_t> drained;
  while (!queue.empty())
  {
    drained.push_back(queue.front().data);
    queue.pop();
  }
  REQUIRE(drained.size() == max_queued_path_responses);
  CHECK(drained.front() == pushed[2]);
  CHECK(drained.back() == pushed.back());
}

TEST_CASE("an echo of the wrong length is not queued")
{
  path_response_queue_t queue;
  std::vector<std::uint8_t> short_data(path_challenge_data_size - 1, 0x11);
  queue.push(short_data);
  CHECK(queue.empty());
}
}
