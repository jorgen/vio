// The endpoint the QUIC Interop Runner drives.
//
// The runner starts this image twice per test case -- once as a server, once
// as a client -- with a network simulator between them, and decides what it
// did by looking at the files that arrived, the packet capture, and the qlog.
// Everything it needs to say comes in through the environment, which is why
// there are no arguments here.
//
// A test case this endpoint cannot do MUST exit 127, which the runner reads as
// "unsupported" rather than "failed". Claiming one and failing it is worse
// than declining it.

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <vio/event_loop.h>
#include <vio/operation/dns.h>
#include <vio/operation/sleep.h>
#include <vio/operation/tcp.h>
#include <vio/quic/endpoint.h>
#include <vio/task.h>

namespace
{
using namespace vio;
using namespace vio::quic;
using namespace std::chrono_literals;

constexpr int unsupported_exit_code = 127;
constexpr std::uint16_t interop_port = 443;

std::string environment(const char *name, std::string fallback = {})
{
  const char *value = std::getenv(name);
  return value != nullptr ? std::string(value) : fallback;
}

// What this endpoint is prepared to be measured on.
//
// These are not the runner's test case names: it tells each side what it needs
// that side to do, so most of its cases arrive here as "transfer" and the
// endpoint never learns which test it is part of. What is left is a short list.
//
// Declined: resumption and zerortt need session tickets, which are deliberately
// compiled out; http3 needs a protocol that does not exist here yet; v2 needs a
// version this endpoint does not offer; chacha20 needs a client that can pin a
// ciphersuite; connectionmigration asks a server to advertise a preferred
// address, which this one has none to give.
bool supported(std::string_view, std::string_view testcase)
{
  static constexpr std::string_view known[] = {"handshake", "transfer", "multiconnect", "retry", "keyupdate", "ecn", "resumption", "zerortt"};
  return std::find(std::begin(known), std::end(known), testcase) != std::end(known);
}

std::vector<std::uint8_t> read_file(const std::string &path)
{
  std::FILE *file = std::fopen(path.c_str(), "rb");
  if (file == nullptr)
  {
    return {};
  }
  std::vector<std::uint8_t> out;
  std::uint8_t chunk[16384];
  for (;;)
  {
    const auto read = std::fread(chunk, 1, sizeof(chunk), file);
    if (read == 0)
    {
      break;
    }
    out.insert(out.end(), chunk, chunk + read);
  }
  std::fclose(file);
  return out;
}

bool write_file(const std::string &path, std::span<const std::uint8_t> bytes)
{
  std::FILE *file = std::fopen(path.c_str(), "wb");
  if (file == nullptr)
  {
    return false;
  }
  const auto written = bytes.empty() ? std::size_t{0} : std::fwrite(bytes.data(), 1, bytes.size(), file);
  std::fclose(file);
  return written == bytes.size();
}

// Whatever follows the last slash, with anything that could climb out of the
// directory refused rather than sanitised.
std::string base_name(std::string_view path)
{
  const auto slash = path.find_last_of('/');
  auto name = slash == std::string_view::npos ? path : path.substr(slash + 1);
  if (name.empty() || name == "." || name == ".." || name.find("..") != std::string_view::npos)
  {
    return {};
  }
  return std::string(name);
}

transport_parameters_t parameters()
{
  transport_parameters_t out;
  out.max_idle_timeout = 30000;
  out.initial_max_data = 64 * 1024 * 1024;
  out.initial_max_stream_data_bidi_local = 16 * 1024 * 1024;
  out.initial_max_stream_data_bidi_remote = 16 * 1024 * 1024;
  out.initial_max_stream_data_uni = 16 * 1024 * 1024;
  out.initial_max_streams_bidi = 200;
  out.initial_max_streams_uni = 200;
  out.active_connection_id_limit = 8;
  return out;
}

void apply_common(endpoint_config_t &config)
{
  config.connection.transport_parameters = parameters();
  config.ecn = true;
  config.qlog_directory = environment("QLOGDIR");
}

struct request_t
{
  std::string host;
  std::uint16_t port = interop_port;
  std::string path;
};

// The runner hands over "https://server:443/name" per file, space separated.
std::vector<request_t> parse_requests(const std::string &raw)
{
  std::vector<request_t> out;
  std::size_t position = 0;
  while (position < raw.size())
  {
    const auto end = raw.find_first_of(" \t\r\n", position);
    const auto token = raw.substr(position, end == std::string::npos ? std::string::npos : end - position);
    position = end == std::string::npos ? raw.size() : end + 1;
    if (token.empty())
    {
      continue;
    }
    auto rest = std::string_view(token);
    const auto scheme = rest.find("://");
    if (scheme != std::string_view::npos)
    {
      rest = rest.substr(scheme + 3);
    }
    const auto slash = rest.find('/');
    auto authority = slash == std::string_view::npos ? rest : rest.substr(0, slash);
    request_t parsed;
    parsed.path = slash == std::string_view::npos ? "/" : std::string(rest.substr(slash));
    const auto colon = authority.find(':');
    if (colon != std::string_view::npos)
    {
      parsed.port = static_cast<std::uint16_t>(std::strtoul(std::string(authority.substr(colon + 1)).c_str(), nullptr, 10));
      authority = authority.substr(0, colon);
    }
    parsed.host = std::string(authority);
    out.push_back(std::move(parsed));
  }
  return out;
}

// ---------------------------------------------------------------- server

struct server_state_t
{
  std::string www;
  std::size_t served = 0;
  // A request is small, but nothing says it arrives in one piece -- with
  // thousands of streams open at once some of them do not. Consuming the bytes
  // and then insisting on finding the newline among them loses the request.
  std::map<std::uint64_t, std::string> pending;
};

// HTTP/0.9 over the hq-interop ALPN: a request is "GET /name" and a newline,
// and the answer is the file followed by the end of the stream.
void answer_requests(server_state_t &state, connection_t &connection)
{
  for (const auto id : connection.readable_streams())
  {
    auto readable = connection.readable_stream(id);
    if (readable.empty())
    {
      continue;
    }
    auto &request = state.pending[id];
    request.append(reinterpret_cast<const char *>(readable.data()), readable.size());
    connection.consume_stream(id, readable.size());
    const auto newline = request.find('\n');
    if (newline == std::string::npos)
    {
      continue;
    }
    const auto slash = request.find('/');
    if (slash == std::string::npos || slash > newline)
    {
      continue;
    }
    auto name = request.substr(slash, newline - slash);
    while (!name.empty() && (name.back() == '\r' || name.back() == ' '))
    {
      name.pop_back();
    }
    const auto file = base_name(name);
    state.pending.erase(id);
    if (file.empty())
    {
      continue;
    }
    const auto body = read_file(state.www + "/" + file);
    (void)connection.write_stream(id, body, true);
    ++state.served;
    std::printf("served %s (%zu bytes)\n", file.c_str(), body.size());
    std::fflush(stdout);
  }
}

task_t<int> run_server(event_loop_t &loop, const std::string &testcase)
{
  const auto certificate = read_file(environment("CERTS", "/certs") + "/cert.pem");
  const auto key = read_file(environment("CERTS", "/certs") + "/priv.key");
  if (certificate.empty() || key.empty())
  {
    std::printf("no certificate or key under %s\n", environment("CERTS", "/certs").c_str());
    co_return 1;
  }

  tls_config_t tls;
  tls.role = tls_role_t::server;
  tls.certificate_chain_pem = certificate;
  tls.private_key_pem = key;
  tls.alpn = {"hq-interop"};
  tls.key_log_path = environment("SSLKEYLOGFILE");

  auto context = tls_context_t::create(tls);
  if (!context.has_value())
  {
    std::printf("could not build a TLS context\n");
    co_return 1;
  }

  endpoint_config_t config;
  config.connection.role = tls_role_t::server;
  apply_common(config);

  // Section 8.1.2: the retry test wants every client sent a Retry before any
  // handshake work happens.
  retry_token_key_t retry_key;
  if (testcase == "retry")
  {
    if (!retry_key.generate().has_value())
    {
      std::printf("could not generate a retry key\n");
      co_return 1;
    }
    config.retry_key = &retry_key;
  }

  auto made = endpoint_t::create(loop, *context, config);
  if (!made.has_value())
  {
    std::printf("could not build an endpoint\n");
    co_return 1;
  }
  endpoint_t server(std::move(*made));

  auto address = ip6_addr("::", interop_port);
  if (!address.has_value() || !server.bind(reinterpret_cast<const sockaddr *>(&*address)).has_value())
  {
    std::printf("could not bind port %u\n", static_cast<unsigned>(interop_port));
    co_return 1;
  }

  server_state_t state;
  state.www = environment("WWW", "/www");
  server.on_activity([&state](connection_t &connection) { answer_requests(state, connection); });

  std::printf("vio interop server listening on :%u testcase=%s\n", static_cast<unsigned>(interop_port), testcase.c_str());
  std::fflush(stdout);

  // The runner stops the container when the test is over, so this only ends
  // if the socket does.
  co_await server.run(nullptr);
  co_return 0;
}

// ---------------------------------------------------------------- client

struct download_t
{
  std::string name;
  std::uint64_t stream = 0;
  std::vector<std::uint8_t> body;
  bool complete = false;
};

struct client_state_t
{
  std::vector<download_t> downloads;
  std::string directory;
  bool key_update_wanted = false;
  bool key_update_done = false;
  bool failed = false;

  [[nodiscard]] bool finished() const
  {
    return std::all_of(downloads.begin(), downloads.end(), [](const download_t &entry) { return entry.complete; });
  }
};

void collect(client_state_t &state, connection_t &connection)
{
  for (const auto id : connection.readable_streams())
  {
    auto entry = std::find_if(state.downloads.begin(), state.downloads.end(), [id](const download_t &candidate) { return candidate.stream == id; });
    if (entry == state.downloads.end())
    {
      continue;
    }
    auto readable = connection.readable_stream(id);
    if (!readable.empty())
    {
      entry->body.insert(entry->body.end(), readable.begin(), readable.end());
      connection.consume_stream(id, readable.size());
    }

    // Section 6.1: a key update is only permitted once the handshake is
    // confirmed, so the first bytes of the response are the earliest point.
    if (state.key_update_wanted && !state.key_update_done && !entry->body.empty())
    {
      state.key_update_done = connection.initiate_key_update();
    }

    if (connection.stream_receive_finished(id))
    {
      entry->complete = true;
      if (!write_file(state.directory + "/" + entry->name, entry->body))
      {
        std::printf("could not write %s\n", entry->name.c_str());
        state.failed = true;
      }
      else
      {
        std::printf("downloaded %s (%zu bytes)\n", entry->name.c_str(), entry->body.size());
      }
      std::fflush(stdout);
    }
  }
}

// One connection carrying every request in the batch. multiconnect calls this
// once per request instead, which is the whole of that test.
task_t<bool> fetch(event_loop_t &loop, tls_context_t &context, const std::vector<request_t> &batch, const std::string &directory, bool key_update, std::vector<std::uint8_t> *ticket = nullptr, bool early_data = false)
{
  if (batch.empty())
  {
    co_return true;
  }

  address_info_t hints;
  hints.socktype = SOCK_DGRAM;
  auto resolved = co_await get_addrinfo(loop, batch.front().host, hints);
  if (!resolved.has_value() || resolved->empty())
  {
    std::printf("could not resolve %s\n", batch.front().host.c_str());
    co_return false;
  }
  sockaddr *target = resolved->front().get_sockaddr();
  if (target == nullptr)
  {
    co_return false;
  }
  if (target->sa_family == AF_INET)
  {
    reinterpret_cast<sockaddr_in *>(target)->sin_port = htons(batch.front().port);
  }
  else
  {
    reinterpret_cast<sockaddr_in6 *>(target)->sin6_port = htons(batch.front().port);
  }

  endpoint_config_t config;
  config.connection.role = tls_role_t::client;
  apply_common(config);

  auto made = endpoint_t::create(loop, context, config);
  if (!made.has_value())
  {
    co_return false;
  }
  endpoint_t client(std::move(*made));

  client_state_t state;
  state.directory = directory;
  state.key_update_wanted = key_update;
  for (const auto &entry : batch)
  {
    auto name = base_name(entry.path);
    if (name.empty())
    {
      co_return false;
    }
    state.downloads.push_back(download_t{.name = std::move(name)});
  }

  client.on_activity([&state](connection_t &connection) { collect(state, connection); });

  auto connected = client.connect(target, batch.front().host, ticket != nullptr ? std::span<const std::uint8_t>(*ticket) : std::span<const std::uint8_t>{});
  if (!connected.has_value())
  {
    std::printf("could not start a connection to %s\n", batch.front().host.c_str());
    co_return false;
  }

  cancellation_t cancel;
  auto serving = [](endpoint_t &endpoint, cancellation_t &token) -> detached_task_t { co_await endpoint.run(&token); }(client, cancel);
  (void)serving;

  // Asked for each time round the loop rather than kept: the endpoint collects
  // a connection once it has closed and drained, which is exactly what a
  // stalled handshake does while this is still running.
  const auto handle = *connected;
  std::size_t opened = 0;
  // 30 seconds is above every timeout the runner applies, so a hang here is
  // reported as a failed download rather than a killed container.
  for (int elapsed = 0; elapsed < 9000 && !state.finished() && !state.failed; ++elapsed)
  {
    connection_t *connection = client.connection(handle);
    if (connection == nullptr)
    {
      state.failed = true;
      break;
    }
    // A request per stream, opened as the peer's limit allows rather than all
    // at once: the multiplexing test asks for thousands of files, and the
    // credit for them arrives in MAX_STREAMS as earlier ones finish.
    const bool resuming = ticket != nullptr && !ticket->empty();
    if (connection->handshake_complete() || resuming)
    {
      while (opened < batch.size())
      {
        auto stream = connection->open_stream(stream_direction_t::bidirectional);
        if (!stream.has_value())
        {
          break;
        }
        state.downloads[opened].stream = *stream;
        const std::string line = "GET " + batch[opened].path + "\r\n";
        const auto bytes = std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(line.data()), line.size());
        if (connection->write_stream(*stream, bytes, true) != bytes.size())
        {
          state.failed = true;
          break;
        }
        ++opened;
      }
    }
    co_await sleep(loop, 10ms);
  }

  bool ok = state.finished() && !state.failed;
  if (ticket != nullptr && !ticket->empty())
  {
    // Resuming is not the same as 0-RTT: a ticket can be accepted while the
    // early data on it is refused, and only the second is what this tests.
    if (auto *connection = client.connection(handle); connection != nullptr)
    {
      const bool early = connection->early_data_accepted();
      std::printf("resumed, early data %s\n", early ? "accepted" : "refused");
      // Only the zerortt case fails for want of it; resumption is content to
      // have resumed, and offers no early data to be refused.
      ok = ok && (early || !early_data);
    }
  }
  // TLS 1.3 sends the ticket after the handshake, and often after the transfer
  // this connection existed for, so it is worth waiting a moment for.
  if (ticket != nullptr && ticket->empty())
  {
    for (int elapsed = 0; elapsed < 200 && ticket->empty(); ++elapsed)
    {
      connection_t *connection = client.connection(handle);
      if (connection == nullptr)
      {
        break;
      }
      *ticket = connection->resumption_ticket();
      if (!ticket->empty())
      {
        break;
      }
      co_await sleep(loop, 10ms);
    }
  }
  if (auto *connection = client.connection(handle); connection != nullptr)
  {
    connection->close(0, "done", true);
  }
  co_await sleep(loop, 50ms);
  cancel.cancel();
  co_await sleep(loop, 50ms);
  co_return std::move(ok);
}

task_t<int> run_client(event_loop_t &loop, const std::string &testcase)
{
  const auto requests = parse_requests(environment("REQUESTS"));
  if (requests.empty())
  {
    std::printf("no requests\n");
    co_return 1;
  }

  tls_config_t tls;
  tls.role = tls_role_t::client;
  tls.alpn = {"hq-interop"};
  tls.key_log_path = environment("SSLKEYLOGFILE");
  tls.ca_certificates_pem = read_file(environment("CERTS", "/certs") + "/ca.pem");
  // The runner inflates its certificate with twenty subject alternative names
  // of 250 random characters, to make the server's handshake flight large
  // enough for the amplification test. A DNS label may not exceed 63 octets
  // (RFC 1035 section 2.3.4), so those names are malformed, and LibreSSL
  // rejects the whole certificate for it rather than skipping the bad entries
  // and matching the valid "server" that sits alongside them -- which is what
  // OpenSSL does, and why every other endpoint verifies it happily.
  //
  // None of these test cases is about certificate validation, so the harness
  // stops checking rather than misreport a transport result. vio's own default
  // is unchanged and still verifies.
  tls.verify_peer = false;
  tls.session_resumption = testcase == "resumption" || testcase == "zerortt";
  tls.early_data = testcase == "zerortt";
  auto context = tls_context_t::create(tls);
  if (!context.has_value())
  {
    std::printf("could not build a TLS context\n");
    co_return 1;
  }

  const auto directory = environment("DOWNLOADS", "/downloads");
  const bool key_update = testcase == "keyupdate";
  bool ok = true;

  if (testcase == "zerortt" || testcase == "resumption")
  {
    // The runner's shape for both: one connection to be issued a ticket, then a
    // second that spends it. What is being tested is the second one, so the
    // first fetches nothing beyond what it takes to get a ticket. The two
    // differ only in what the second is required to achieve -- resumption asks
    // that the handshake be shorter, zerortt that data ride in the first
    // flight -- which is why early data is configured per test case above.
    std::vector<std::uint8_t> ticket;
    ok = co_await fetch(loop, *context, {requests.front()}, directory, false, &ticket);
    if (!ok || ticket.empty())
    {
      std::printf("no session ticket to resume with\n");
      co_return 1;
    }
    ok = co_await fetch(loop, *context, requests, directory, false, &ticket, testcase == "zerortt");
    co_return ok ? 0 : 1;
  }

  if (testcase == "multiconnect")
  {
    // The point of that test is many handshakes, so each file gets its own.
    for (const auto &single : requests)
    {
      ok = co_await fetch(loop, *context, {single}, directory, false) && ok;
    }
  }
  else
  {
    ok = co_await fetch(loop, *context, requests, directory, key_update);
  }

  co_return ok ? 0 : 1;
}
} // namespace

int main()
{
  const auto role = environment("ROLE", "server");
  const auto testcase = environment("TESTCASE", "handshake");

  if (!supported(role, testcase))
  {
    std::printf("vio does not implement the %s test case as a %s\n", testcase.c_str(), role.c_str());
    return unsupported_exit_code;
  }

  vio::event_loop_t loop;
  int result = 1;
  loop.run_in_loop(
    [&]
    {
      return [](vio::event_loop_t &event_loop, const std::string &which, const std::string &which_case, int &out) -> vio::task_t<void>
      {
        out = which == "client" ? co_await run_client(event_loop, which_case) : co_await run_server(event_loop, which_case);
        event_loop.stop();
      }(loop, role, testcase, result);
    });
  loop.run();
  return result;
}
