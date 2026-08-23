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

#include "vio/quic/qlog.h"

#include <cstdio>
#include <cstring>

namespace vio::quic
{
namespace
{
constexpr char hex_digits[] = "0123456789abcdef";

void append_hex(std::string &out, std::span<const std::uint8_t> bytes)
{
  for (const auto byte : bytes)
  {
    out.push_back(hex_digits[byte >> 4]);
    out.push_back(hex_digits[byte & 0x0f]);
  }
}

// Only what JSON actually requires. Everything written here is a protocol
// identifier or a number, so the escapes are a guard rather than a hot path.
void append_escaped(std::string &out, std::string_view value)
{
  for (const auto character : value)
  {
    switch (character)
    {
    case '"':
      out.append("\\\"");
      break;
    case '\\':
      out.append("\\\\");
      break;
    case '\n':
      out.append("\\n");
      break;
    case '\r':
      out.append("\\r");
      break;
    case '\t':
      out.append("\\t");
      break;
    default:
      if (static_cast<unsigned char>(character) < 0x20)
      {
        char escape[7] = {};
        std::snprintf(escape, sizeof(escape), "\\u%04x", static_cast<unsigned>(static_cast<unsigned char>(character)));
        out.append(escape);
      }
      else
      {
        out.push_back(character);
      }
      break;
    }
  }
}

void append_number(std::string &out, std::uint64_t value)
{
  char digits[24] = {};
  std::snprintf(digits, sizeof(digits), "%llu", static_cast<unsigned long long>(value));
  out.append(digits);
}

void append_signed(std::string &out, std::int64_t value)
{
  char digits[24] = {};
  std::snprintf(digits, sizeof(digits), "%lld", static_cast<long long>(value));
  out.append(digits);
}
} // namespace

// What closes the document. It is written after every flush and then seeked
// back over, so a trace on disk is a complete one at every point where nothing
// is part-written -- which is what makes it readable after the process is
// killed rather than only after it exits.
constexpr char trace_terminator[] = "]}]}\n";

// How much of a connection is written out one event at a time. Comfortably
// past a handshake and whatever follows it, and far short of a transfer.
constexpr std::uint64_t early_events = 256;

struct qlog_writer_t::state_t
{
  std::FILE *file = nullptr;
  std::string buffer;
  tick_t reference;
  bool wrote_event = false;
  // Whether the value about to be written is the first in its object or
  // array, which is the only thing that decides a separating comma.
  bool first_in_scope = true;
  bool closed = false;
  // An event opened while another is still open would nest inside whatever
  // object or array is current: valid JSON, in the wrong place, and silent.
  // The inner one is dropped whole -- refusing only its begin would leave its
  // fields landing in the outer event and its end closing that one early.
  bool in_event = false;
  int suppressed = 0;
  std::uint64_t events_written = 0;

  // A killed process never runs a destructor, and a trace is most wanted when
  // the run it describes ended badly. Everything buffered goes out followed by
  // the terminator, and unless this is the last flush the file position is put
  // back over it so the next write continues the events array.
  void flush(bool final)
  {
    if (file == nullptr)
    {
      return;
    }
    if (!buffer.empty())
    {
      std::fwrite(buffer.data(), 1, buffer.size(), file);
      buffer.clear();
    }
    const auto length = std::strlen(trace_terminator);
    std::fwrite(trace_terminator, 1, length, file);
    std::fflush(file);
    if (!final)
    {
      std::fseek(file, -static_cast<long>(length), SEEK_CUR);
    }
  }
};

std::unique_ptr<qlog_writer_t> qlog_writer_t::create(const std::string &path, std::string_view vantage_point, std::span<const std::uint8_t> odcid, tick_t reference)
{
  std::FILE *file = std::fopen(path.c_str(), "wb");
  if (file == nullptr)
  {
    return nullptr;
  }

  std::unique_ptr<qlog_writer_t> writer(new qlog_writer_t());
  writer->_state = std::make_unique<state_t>();
  writer->_state->file = file;
  writer->_state->reference = reference;
  writer->_state->buffer.reserve(64 * 1024);

  std::string &out = writer->_state->buffer;
  out.append("{\"qlog_version\":\"draft-00\",\"title\":\"vio\",\"traces\":[{\"vantage_point\":{\"name\":\"vio\",\"type\":\"");
  append_escaped(out, vantage_point);
  out.append("\"},\"title\":\"vio\",\"description\":\"");
  append_hex(out, odcid);
  out.append("\",\"event_fields\":[\"relative_time\",\"category\",\"event\",\"data\"],\"configuration\":{\"time_units\":\"us\"},\"common_fields\":{\"protocol_type\":\"QUIC_HTTP3\",\"reference_time\":\"");
  append_number(out, static_cast<std::uint64_t>(reference.since_origin().count() / 1000));
  out.append("\"},\"events\":[");
  writer->_state->flush(false);
  return writer;
}

qlog_writer_t::~qlog_writer_t()
{
  close_trace();
}

void qlog_writer_t::close_trace()
{
  if (_state == nullptr || _state->closed)
  {
    return;
  }
  _state->closed = true;
  _state->flush(true);
  if (_state->file != nullptr)
  {
    std::fclose(_state->file);
    _state->file = nullptr;
  }
}

void qlog_writer_t::begin_event(tick_t now, std::string_view category, std::string_view name)
{
  if (_state == nullptr || _state->closed)
  {
    return;
  }
  if (_state->in_event)
  {
    ++_state->suppressed;
    return;
  }
  _state->in_event = true;
  std::string &out = _state->buffer;
  if (_state->wrote_event)
  {
    out.push_back(',');
  }
  _state->wrote_event = true;

  const auto elapsed = now.since_origin() - _state->reference.since_origin();
  out.push_back('[');
  append_signed(out, static_cast<std::int64_t>(elapsed.count() / 1000));
  out.append(",\"");
  append_escaped(out, category);
  out.append("\",\"");
  append_escaped(out, name);
  out.append("\",{");
  _state->first_in_scope = true;
}

void qlog_writer_t::end_event()
{
  if (_state == nullptr || _state->closed)
  {
    return;
  }
  if (_state->suppressed > 0)
  {
    --_state->suppressed;
    return;
  }
  if (!_state->in_event)
  {
    return;
  }
  _state->in_event = false;
  _state->buffer.append("}]");
  _state->first_in_scope = false;

  // A connection is written out event by event until it is clearly not a short
  // one, and in blocks after that. Buffering loses whatever it holds when the
  // process is killed, and a handshake is a few hundred bytes -- the entire
  // trace of a short connection is exactly what would go missing. Paying that
  // per event for a bulk transfer instead costs several times the throughput,
  // which would distort the timing a trace exists to show.
  ++_state->events_written;
  if (_state->events_written <= early_events || _state->buffer.size() >= 8 * 1024)
  {
    _state->flush(false);
  }
}

namespace
{
void separate(std::string &out, bool &first)
{
  if (!first)
  {
    out.push_back(',');
  }
  first = false;
}
} // namespace

void qlog_writer_t::field_string(std::string_view key, std::string_view value)
{
  if (_state == nullptr || _state->closed || _state->suppressed > 0)
  {
    return;
  }
  std::string &out = _state->buffer;
  separate(out, _state->first_in_scope);
  out.push_back('"');
  append_escaped(out, key);
  out.append("\":\"");
  append_escaped(out, value);
  out.push_back('"');
}

void qlog_writer_t::field_number(std::string_view key, std::uint64_t value)
{
  if (_state == nullptr || _state->closed || _state->suppressed > 0)
  {
    return;
  }
  std::string &out = _state->buffer;
  separate(out, _state->first_in_scope);
  out.push_back('"');
  append_escaped(out, key);
  out.append("\":");
  append_number(out, value);
}

void qlog_writer_t::field_signed(std::string_view key, std::int64_t value)
{
  if (_state == nullptr || _state->closed || _state->suppressed > 0)
  {
    return;
  }
  std::string &out = _state->buffer;
  separate(out, _state->first_in_scope);
  out.push_back('"');
  append_escaped(out, key);
  out.append("\":");
  append_signed(out, value);
}

void qlog_writer_t::field_bool(std::string_view key, bool value)
{
  if (_state == nullptr || _state->closed || _state->suppressed > 0)
  {
    return;
  }
  std::string &out = _state->buffer;
  separate(out, _state->first_in_scope);
  out.push_back('"');
  append_escaped(out, key);
  out.append(value ? "\":true" : "\":false");
}

void qlog_writer_t::field_hex(std::string_view key, std::span<const std::uint8_t> bytes)
{
  if (_state == nullptr || _state->closed || _state->suppressed > 0)
  {
    return;
  }
  std::string &out = _state->buffer;
  separate(out, _state->first_in_scope);
  out.push_back('"');
  append_escaped(out, key);
  out.append("\":\"");
  append_hex(out, bytes);
  out.push_back('"');
}

void qlog_writer_t::begin_object(std::string_view key)
{
  if (_state == nullptr || _state->closed || _state->suppressed > 0)
  {
    return;
  }
  std::string &out = _state->buffer;
  separate(out, _state->first_in_scope);
  out.push_back('"');
  append_escaped(out, key);
  out.append("\":{");
  _state->first_in_scope = true;
}

void qlog_writer_t::begin_object()
{
  if (_state == nullptr || _state->closed || _state->suppressed > 0)
  {
    return;
  }
  std::string &out = _state->buffer;
  separate(out, _state->first_in_scope);
  out.push_back('{');
  _state->first_in_scope = true;
}

void qlog_writer_t::end_object()
{
  if (_state == nullptr || _state->closed || _state->suppressed > 0)
  {
    return;
  }
  _state->buffer.push_back('}');
  _state->first_in_scope = false;
}

void qlog_writer_t::begin_array(std::string_view key)
{
  if (_state == nullptr || _state->closed || _state->suppressed > 0)
  {
    return;
  }
  std::string &out = _state->buffer;
  separate(out, _state->first_in_scope);
  out.push_back('"');
  append_escaped(out, key);
  out.append("\":[");
  _state->first_in_scope = true;
}

void qlog_writer_t::begin_array()
{
  if (_state == nullptr || _state->closed || _state->suppressed > 0)
  {
    return;
  }
  std::string &out = _state->buffer;
  separate(out, _state->first_in_scope);
  out.push_back('[');
  _state->first_in_scope = true;
}

void qlog_writer_t::field_element(std::uint64_t value)
{
  if (_state == nullptr || _state->closed || _state->suppressed > 0)
  {
    return;
  }
  std::string &out = _state->buffer;
  separate(out, _state->first_in_scope);
  append_number(out, value);
}

void qlog_writer_t::end_array()
{
  if (_state == nullptr || _state->closed || _state->suppressed > 0)
  {
    return;
  }
  _state->buffer.push_back(']');
  _state->first_in_scope = false;
}
} // namespace vio::quic
