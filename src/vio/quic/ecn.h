/*
  Copyright (c) 2025 Jørgen Lind

  Permission is hereby granted, free of charge, to any person obtaining a copy of
  this software and associated documentation files (the "Software"), to deal in
  the Software without restriction, including without limitation the rights to
  use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
  of the Software, and to permit persons to whom the Software is furnished to do
  so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
*/

#pragma once

// RFC 9000 section 13.4: explicit congestion notification, from the sending
// side.
//
// ECN lets a router say "I am close to dropping things" by setting two bits in
// the IP header instead of actually dropping. The receiver counts what arrives
// and echoes the totals back in ACK frames; the sender treats a rise in the
// congestion-experienced count as it would treat loss. The payoff is a
// congestion signal that costs no retransmission.
//
// The catch, and the reason this file is mostly validation: the counts arrive
// from the peer, and reacting to them means letting the peer set this
// endpoint's sending rate. Section 13.4.2.1 is what makes that safe. Every
// reported increase is checked against the codepoints this endpoint actually
// applied to the packets being acknowledged, so a peer that inflates the
// numbers -- or a middlebox that rewrites them -- fails validation and ECN is
// switched off for the path rather than obeyed.
//
// That is also why marking has to come first. Without it every packet leaves
// unmarked, an honest peer reports zero, and there is nothing to check a
// non-zero count against: believing it would hand any peer a throttle.

#include <cstdint>
#include <optional>

namespace vio::quic
{
// The two-bit field, in the values it takes on the wire (RFC 3168). It lives in
// the low bits of the IPv4 TOS byte and the IPv6 traffic class byte.
enum class ecn_codepoint_t : std::uint8_t
{
  not_ect = 0x00,
  ect1 = 0x01,
  ect0 = 0x02,
  ce = 0x03,
};

struct ecn_counts_totals_t
{
  std::uint64_t ect0 = 0;
  std::uint64_t ect1 = 0;
  std::uint64_t ce = 0;
};

// What an ACK frame said, and what this endpoint knows about the packets it
// covered.
struct ecn_ack_report_t
{
  // Absent when the ACK frame carried no ECN section at all.
  std::optional<ecn_counts_totals_t> reported;
  // Newly acknowledged packets, counted by the codepoint they were sent with.
  std::uint64_t newly_acked_ect0 = 0;
  std::uint64_t newly_acked_ect1 = 0;
  // Section 13.4.2.1: an ACK that does not move the largest acknowledged
  // forward may be reordered, and MUST NOT be allowed to fail validation.
  bool advanced_largest_acked = false;
};

enum class ecn_outcome_t : std::uint8_t
{
  // Nothing to say: no marked packets were acknowledged, or ECN is already off.
  inert,
  // The counts held up. ce_increase says whether to treat this as congestion.
  validated,
  // Section 13.4.2: the path does not carry ECN honestly. Marking stops.
  failed,
};

struct ecn_result_t
{
  ecn_outcome_t outcome = ecn_outcome_t::inert;
  std::uint64_t ce_increase = 0;
};

// One per packet number space, on the sending side.
class ecn_validator_t
{
public:
  [[nodiscard]] ecn_result_t on_ack(const ecn_ack_report_t &report)
  {
    if (!_enabled)
    {
      return {};
    }

    const bool acknowledged_marked = report.newly_acked_ect0 > 0 || report.newly_acked_ect1 > 0;

    if (!report.reported.has_value())
    {
      // Section 13.4.2.1: an ACK that newly acknowledges something this
      // endpoint marked, and carries no counts, means the marks are not
      // surviving the path -- a middlebox clearing the field, or a peer that
      // does not report. Either way ECN is not working here.
      if (acknowledged_marked && report.advanced_largest_acked)
      {
        return fail();
      }
      return {};
    }

    const auto &counts = *report.reported;

    // Counts are cumulative for the life of the connection, so they can only
    // ever go up. A decrease is the peer contradicting itself.
    if (counts.ect0 < _seen.ect0 || counts.ect1 < _seen.ect1 || counts.ce < _seen.ce)
    {
      if (report.advanced_largest_acked)
      {
        return fail();
      }
      return {};
    }

    const auto ect0_rise = counts.ect0 - _seen.ect0;
    const auto ect1_rise = counts.ect1 - _seen.ect1;
    const auto ce_rise = counts.ce - _seen.ce;

    // Section 13.4.2.1: a packet sent as ECT(0) must be counted either as
    // ECT(0) or, if a router marked it on the way, as CE. If the two together
    // do not account for everything newly acknowledged that was sent ECT(0),
    // something on the path is rewriting the field -- typically remarking CE
    // back down, which would hide congestion from this endpoint entirely.
    //
    // Only "less than" fails. More is expected and legal: ACK frames get lost,
    // so counts routinely cover packets whose acknowledgements never arrived.
    if (report.advanced_largest_acked)
    {
      if (ect0_rise + ce_rise < report.newly_acked_ect0)
      {
        return fail();
      }
      if (ect1_rise + ce_rise < report.newly_acked_ect1)
      {
        return fail();
      }
    }

    _seen = counts;
    if (!report.advanced_largest_acked)
    {
      // Believed, but not acted on: a reordered ACK would otherwise report the
      // same congestion twice.
      return {.outcome = ecn_outcome_t::validated, .ce_increase = 0};
    }
    return {.outcome = ecn_outcome_t::validated, .ce_increase = ce_rise};
  }

  [[nodiscard]] bool enabled() const
  {
    return _enabled;
  }

  // Section 13.4.2: once a path is shown not to carry ECN, this endpoint stops
  // marking on it rather than continuing to hope.
  void disable()
  {
    _enabled = false;
  }

  // Section 13.4.2: validation starts afresh for each new path, which is what
  // a migration produces.
  void reset()
  {
    _enabled = true;
    _seen = {};
  }

  [[nodiscard]] const ecn_counts_totals_t &seen() const
  {
    return _seen;
  }

private:
  [[nodiscard]] ecn_result_t fail()
  {
    _enabled = false;
    return {.outcome = ecn_outcome_t::failed, .ce_increase = 0};
  }

  bool _enabled = true;
  ecn_counts_totals_t _seen;
};
} // namespace vio::quic
