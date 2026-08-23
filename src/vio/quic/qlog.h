/*
  Copyright (c) 2024 Jorgen Lind

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
*/

#ifndef VIO_QUIC_QLOG_H
#define VIO_QUIC_QLOG_H

#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>

#include "vio/tick.h"

namespace vio::quic
{
// A qlog trace for one connection.
//
// The encoding is the draft-00 one, where an event is a four element array of
// [relative_time, category, event, data] described up front by event_fields.
// Later drafts spell each event out as an object, but this is what qvis reads
// most reliably and what picoquic writes, so a trace from each end of the same
// connection loads side by side.
//
// Events are written straight out rather than accumulated: a trace is most
// wanted when the thing being traced ended badly, and a log that only exists
// if the process exits cleanly is no use then. The cost is that the closing
// brackets are written by the destructor, so a hard kill leaves the JSON
// unterminated -- close_trace() early if that matters.
class qlog_writer_t
{
public:
  static std::unique_ptr<qlog_writer_t> create(const std::string &path, std::string_view vantage_point, std::span<const std::uint8_t> odcid, tick_t reference);

  ~qlog_writer_t();

  qlog_writer_t(const qlog_writer_t &) = delete;
  qlog_writer_t &operator=(const qlog_writer_t &) = delete;

  // An event's data object is open between these two, and the field and
  // nesting calls below go into it.
  void begin_event(tick_t now, std::string_view category, std::string_view name);
  void end_event();

  void field_string(std::string_view key, std::string_view value);
  void field_number(std::string_view key, std::uint64_t value);
  void field_signed(std::string_view key, std::int64_t value);
  void field_bool(std::string_view key, bool value);
  void field_hex(std::string_view key, std::span<const std::uint8_t> bytes);

  void begin_object(std::string_view key);
  void end_object();
  // An unkeyed object, for an element of an array.
  void begin_object();

  void begin_array(std::string_view key);
  void end_array();

  void close_trace();

private:
  qlog_writer_t() = default;

  struct state_t;
  std::unique_ptr<state_t> _state;
};
} // namespace vio::quic

#endif
