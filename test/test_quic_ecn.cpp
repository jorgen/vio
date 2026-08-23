#include <cstdint>
#include <doctest/doctest.h>
#include <vio/quic/ecn.h>

// RFC 9000 section 13.4.2.1. These counts arrive from the peer, and reacting to
// them means letting the peer influence how fast this endpoint sends. Every
// rule here exists to make that safe: a reported increase is only believed when
// it is consistent with the codepoints this endpoint actually applied to the
// packets being acknowledged.

namespace
{
using namespace vio::quic;

ecn_ack_report_t report_with(std::uint64_t ect0, std::uint64_t ect1, std::uint64_t ce, std::uint64_t newly_ect0, bool advanced = true)
{
  ecn_ack_report_t report;
  report.reported = ecn_counts_totals_t{.ect0 = ect0, .ect1 = ect1, .ce = ce};
  report.newly_acked_ect0 = newly_ect0;
  report.advanced_largest_acked = advanced;
  return report;
}
} // namespace

TEST_SUITE("quic ecn")
{
TEST_CASE("counts that account for what was sent are believed")
{
  ecn_validator_t validator;
  const auto result = validator.on_ack(report_with(10, 0, 0, 10));
  CHECK(result.outcome == ecn_outcome_t::validated);
  CHECK(result.ce_increase == 0);
  CHECK(validator.enabled());
}

TEST_CASE("a rise in the congestion count is reported once")
{
  ecn_validator_t validator;
  REQUIRE(validator.on_ack(report_with(10, 0, 0, 10)).outcome == ecn_outcome_t::validated);

  // Three of the next four arrived marked by a router on the way.
  const auto result = validator.on_ack(report_with(11, 0, 3, 4));
  CHECK(result.outcome == ecn_outcome_t::validated);
  CHECK(result.ce_increase == 3);

  // The same totals again say nothing new.
  const auto again = validator.on_ack(report_with(11, 0, 3, 0));
  CHECK(again.outcome == ecn_outcome_t::validated);
  CHECK(again.ce_increase == 0);
}

TEST_CASE("counts smaller than what was acknowledged mean the path is rewriting them")
{
  // Section 13.4.2.1: a packet sent ECT(0) must come back counted as ECT(0) or
  // as CE. If the two together do not cover everything newly acknowledged that
  // went out marked, something is clearing the field -- which would hide
  // congestion from this endpoint completely.
  ecn_validator_t validator;
  const auto result = validator.on_ack(report_with(3, 0, 0, 5));
  CHECK(result.outcome == ecn_outcome_t::failed);
  CHECK_FALSE(validator.enabled());
}

TEST_CASE("counts larger than what was acknowledged are ordinary")
{
  // ACK frames get lost, so the totals routinely cover packets whose
  // acknowledgements never arrived. Only a shortfall is evidence of anything.
  ecn_validator_t validator;
  const auto result = validator.on_ack(report_with(50, 0, 0, 2));
  CHECK(result.outcome == ecn_outcome_t::validated);
  CHECK(validator.enabled());
}

TEST_CASE("an absent ECN section fails only once something marked was acknowledged")
{
  SUBCASE("nothing marked was acknowledged")
  {
    ecn_validator_t validator;
    ecn_ack_report_t report;
    report.advanced_largest_acked = true;
    const auto result = validator.on_ack(report);
    CHECK(result.outcome == ecn_outcome_t::inert);
    CHECK(validator.enabled());
  }

  SUBCASE("marked packets were acknowledged with no counts at all")
  {
    // A middlebox clearing the field, or a peer that does not report. Either
    // way ECN is not working on this path.
    ecn_validator_t validator;
    ecn_ack_report_t report;
    report.newly_acked_ect0 = 4;
    report.advanced_largest_acked = true;
    const auto result = validator.on_ack(report);
    CHECK(result.outcome == ecn_outcome_t::failed);
    CHECK_FALSE(validator.enabled());
  }
}

TEST_CASE("counts that go backwards are the peer contradicting itself")
{
  ecn_validator_t validator;
  REQUIRE(validator.on_ack(report_with(10, 0, 5, 10)).outcome == ecn_outcome_t::validated);
  const auto result = validator.on_ack(report_with(9, 0, 5, 0));
  CHECK(result.outcome == ecn_outcome_t::failed);
}

TEST_CASE("a reordered acknowledgement can neither fail validation nor report congestion")
{
  // Section 13.4.2.1 says so explicitly, and the reason is symmetric: an ACK
  // that does not move the largest acknowledged forward may have overtaken a
  // newer one, so its totals are stale in both directions.
  ecn_validator_t validator;
  REQUIRE(validator.on_ack(report_with(10, 0, 0, 10)).outcome == ecn_outcome_t::validated);

  SUBCASE("a shortfall does not disable it")
  {
    const auto result = validator.on_ack(report_with(1, 0, 0, 9, false));
    CHECK(result.outcome != ecn_outcome_t::failed);
    CHECK(validator.enabled());
  }

  SUBCASE("a rise in the congestion count is not acted on")
  {
    const auto result = validator.on_ack(report_with(10, 0, 6, 0, false));
    CHECK(result.ce_increase == 0);
  }

  SUBCASE("counts going backwards does not disable it")
  {
    const auto result = validator.on_ack(report_with(2, 0, 0, 0, false));
    CHECK(validator.enabled());
  }
}

TEST_CASE("once it has failed nothing more is believed")
{
  ecn_validator_t validator;
  REQUIRE(validator.on_ack(report_with(1, 0, 0, 5)).outcome == ecn_outcome_t::failed);

  const auto result = validator.on_ack(report_with(100, 0, 100, 1));
  CHECK(result.outcome == ecn_outcome_t::inert);
  CHECK(result.ce_increase == 0);
}

TEST_CASE("a new path starts over")
{
  // Section 13.4.2: validation is per path, and migration produces a new one.
  ecn_validator_t validator;
  REQUIRE(validator.on_ack(report_with(1, 0, 0, 5)).outcome == ecn_outcome_t::failed);

  validator.reset();
  CHECK(validator.enabled());
  CHECK(validator.seen().ect0 == 0);
  CHECK(validator.on_ack(report_with(4, 0, 0, 4)).outcome == ecn_outcome_t::validated);
}

TEST_CASE("ECT(1) is held to the same accounting as ECT(0)")
{
  ecn_validator_t validator;
  ecn_ack_report_t report;
  report.reported = ecn_counts_totals_t{.ect0 = 0, .ect1 = 2, .ce = 0};
  report.newly_acked_ect1 = 5;
  report.advanced_largest_acked = true;
  CHECK(validator.on_ack(report).outcome == ecn_outcome_t::failed);
}
}
