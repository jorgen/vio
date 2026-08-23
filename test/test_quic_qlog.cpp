#include <array>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include <doctest/doctest.h>
#include <vio/quic/qlog.h>

// A trace is only useful if a tool can load it, and the failure mode of a
// malformed one is silent: qvis simply refuses the file, long after the run
// that produced it is gone. These check the shape rather than the content.

namespace
{
using namespace vio;
using namespace vio::quic;

std::string read_back(const std::string &path)
{
  std::ifstream file(path, std::ios::binary);
  return std::string(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
}

// Enough of a check to catch an unbalanced object or array, which is what a
// missing end_object or a nested event would produce. String contents are
// skipped so a brace inside a value cannot confuse the count.
bool balanced(const std::string &text)
{
  int depth = 0;
  bool in_string = false;
  bool escaped = false;
  for (const auto character : text)
  {
    if (in_string)
    {
      if (escaped)
      {
        escaped = false;
      }
      else if (character == '\\')
      {
        escaped = true;
      }
      else if (character == '"')
      {
        in_string = false;
      }
      continue;
    }
    if (character == '"')
    {
      in_string = true;
    }
    else if (character == '{' || character == '[')
    {
      ++depth;
    }
    else if (character == '}' || character == ']')
    {
      --depth;
      if (depth < 0)
      {
        return false;
      }
    }
  }
  return depth == 0 && !in_string;
}

const std::array<std::uint8_t, 4> odcid = {0xde, 0xad, 0xbe, 0xef};
} // namespace

TEST_SUITE("quic qlog")
{
TEST_CASE("a trace with no events is still a loadable document")
{
  const std::string path = "vio_qlog_empty.qlog";
  {
    auto writer = qlog_writer_t::create(path, "server", odcid, tick_t::from_nanoseconds(std::chrono::nanoseconds(0)));
    REQUIRE(writer != nullptr);
  }
  const auto text = read_back(path);
  CHECK(balanced(text));
  CHECK(text.find("\"qlog_version\":\"draft-00\"") != std::string::npos);
  CHECK(text.find("\"vantage_point\":{\"name\":\"vio\",\"type\":\"server\"}") != std::string::npos);
  CHECK(text.find("\"description\":\"deadbeef\"") != std::string::npos);
  CHECK(text.find("\"events\":[]") != std::string::npos);
  std::remove(path.c_str());
}

TEST_CASE("events carry their fields and nested shapes")
{
  const std::string path = "vio_qlog_events.qlog";
  {
    auto writer = qlog_writer_t::create(path, "client", odcid, tick_t::from_nanoseconds(std::chrono::nanoseconds(0)));
    REQUIRE(writer != nullptr);

    writer->begin_event(tick_t::from_nanoseconds(std::chrono::milliseconds(1)), "transport", "packet_sent");
    writer->field_string("packet_type", "1RTT");
    writer->begin_object("header");
    writer->field_number("packet_number", 7);
    writer->end_object();
    writer->begin_array("frames");
    writer->begin_object();
    writer->field_string("frame_type", "stream");
    writer->field_number("stream_id", 4);
    writer->field_bool("fin", true);
    writer->end_object();
    writer->end_array();
    writer->end_event();

    writer->begin_event(tick_t::from_nanoseconds(std::chrono::milliseconds(2)), "recovery", "metrics_updated");
    writer->field_number("cwnd", 12000);
    writer->end_event();
  }

  const auto text = read_back(path);
  CHECK(balanced(text));
  // The time is relative to the reference and in microseconds.
  CHECK(text.find("[1000,\"transport\",\"packet_sent\"") != std::string::npos);
  CHECK(text.find("[2000,\"recovery\",\"metrics_updated\"") != std::string::npos);
  CHECK(text.find("\"header\":{\"packet_number\":7}") != std::string::npos);
  CHECK(text.find("\"frames\":[{\"frame_type\":\"stream\",\"stream_id\":4,\"fin\":true}]") != std::string::npos);
  // Two events, so exactly one separator between them.
  CHECK(text.find("}],[") != std::string::npos);
  std::remove(path.c_str());
}

TEST_CASE("an event opened inside another is refused rather than nested")
{
  // Recovery events are discovered while walking the frames of a packet that
  // is still being written. Nesting one there produces valid JSON in the
  // wrong place, which no tool reports and no reader notices.
  const std::string path = "vio_qlog_nested.qlog";
  {
    auto writer = qlog_writer_t::create(path, "server", odcid, tick_t::from_nanoseconds(std::chrono::nanoseconds(0)));
    REQUIRE(writer != nullptr);

    writer->begin_event(tick_t::from_nanoseconds(std::chrono::milliseconds(1)), "transport", "packet_received");
    writer->begin_array("frames");
    writer->begin_object();
    writer->field_string("frame_type", "ack");
    writer->end_object();

    writer->begin_event(tick_t::from_nanoseconds(std::chrono::milliseconds(1)), "recovery", "packet_lost");
    writer->field_number("ignored", 1);
    writer->end_event();

    writer->end_array();
    writer->end_event();

    writer->begin_event(tick_t::from_nanoseconds(std::chrono::milliseconds(2)), "recovery", "packet_lost");
    writer->field_number("packet_number", 3);
    writer->end_event();
  }

  const auto text = read_back(path);
  CHECK(balanced(text));
  CHECK(text.find("\"ignored\"") == std::string::npos);
  // The outer event closed properly and the one after it is intact.
  CHECK(text.find("\"frames\":[{\"frame_type\":\"ack\"}]") != std::string::npos);
  CHECK(text.find("[2000,\"recovery\",\"packet_lost\",{\"packet_number\":3}]") != std::string::npos);
  std::remove(path.c_str());
}

TEST_CASE("closing twice is harmless")
{
  const std::string path = "vio_qlog_twice.qlog";
  {
    auto writer = qlog_writer_t::create(path, "server", odcid, tick_t::from_nanoseconds(std::chrono::nanoseconds(0)));
    REQUIRE(writer != nullptr);
    writer->begin_event(tick_t::from_nanoseconds(std::chrono::milliseconds(1)), "transport", "packet_sent");
    writer->end_event();
    writer->close_trace();
    writer->close_trace();
    // Anything written afterwards is dropped rather than appended past the
    // closing bracket.
    writer->begin_event(tick_t::from_nanoseconds(std::chrono::milliseconds(2)), "transport", "packet_sent");
    writer->end_event();
  }
  const auto text = read_back(path);
  CHECK(balanced(text));
  CHECK(text.find("[2000,") == std::string::npos);
  std::remove(path.c_str());
}

TEST_CASE("a path that cannot be opened yields no writer rather than a crash")
{
  auto writer = qlog_writer_t::create("no_such_directory_here/trace.qlog", "server", odcid, tick_t::from_nanoseconds(std::chrono::nanoseconds(0)));
  CHECK(writer == nullptr);
}
}
