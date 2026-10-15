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

namespace vio::errc
{
inline constexpr int eof = -9001;
inline constexpr int canceled = -9002;
inline constexpr int again = -9003;
inline constexpr int interrupted = -9004;
inline constexpr int timed_out = -9005;
inline constexpr int connection_reset = -9006;
inline constexpr int connection_refused = -9007;
inline constexpr int connection_aborted = -9008;
inline constexpr int broken_pipe = -9009;
inline constexpr int address_in_use = -9010;
inline constexpr int address_not_available = -9011;
inline constexpr int not_connected = -9012;
inline constexpr int already_connected = -9013;
inline constexpr int network_unreachable = -9014;
inline constexpr int host_unreachable = -9015;
inline constexpr int network_down = -9016;
inline constexpr int no_buffer_space = -9017;
inline constexpr int message_too_long = -9018;
inline constexpr int invalid_argument = -9019;
inline constexpr int bad_descriptor = -9020;
inline constexpr int not_supported = -9021;
inline constexpr int permission_denied = -9022;
inline constexpr int operation_not_permitted = -9023;
inline constexpr int no_such_file = -9024;
inline constexpr int file_exists = -9025;
inline constexpr int not_a_directory = -9026;
inline constexpr int is_a_directory = -9027;
inline constexpr int directory_not_empty = -9028;
inline constexpr int no_space = -9029;
inline constexpr int too_many_open_files = -9030;
inline constexpr int out_of_memory = -9031;
inline constexpr int address_family_not_supported = -9032;
inline constexpr int already_in_progress = -9033;
inline constexpr int in_progress = -9034;
inline constexpr int name_too_long = -9035;
inline constexpr int read_only_file_system = -9036;
inline constexpr int cross_device_link = -9037;
inline constexpr int too_many_symbolic_links = -9038;
inline constexpr int file_too_large = -9039;
inline constexpr int io_error = -9040;
inline constexpr int invalid_seek = -9041;
inline constexpr int protocol_error = -9042;
inline constexpr int not_implemented = -9043;
inline constexpr int no_such_device = -9044;
inline constexpr int busy = -9045;
inline constexpr int bad_address = -9046;
inline constexpr int protocol_not_supported = -9047;
inline constexpr int socket_type_not_supported = -9048;
inline constexpr int text_file_busy = -9049;
inline constexpr int too_many_links = -9050;
inline constexpr int no_such_process = -9051;
inline constexpr int not_a_socket = -9052;
inline constexpr int destination_address_required = -9053;
inline constexpr int no_protocol_option = -9054;
inline constexpr int resource_busy_or_locked = -9055;
inline constexpr int dns_address_family = -9101;
inline constexpr int dns_again = -9102;
inline constexpr int dns_bad_flags = -9103;
inline constexpr int dns_fail = -9104;
inline constexpr int dns_family = -9105;
inline constexpr int dns_memory = -9106;
inline constexpr int dns_no_data = -9107;
inline constexpr int dns_no_name = -9108;
inline constexpr int dns_service = -9109;
inline constexpr int dns_socket_type = -9110;
inline constexpr int dns_overflow = -9111;
inline constexpr int dns_protocol = -9112;
inline constexpr int dns_canceled = -9113;
inline constexpr int dns_bad_hints = -9114;
inline constexpr int unknown = -9999;
} // namespace vio::errc
