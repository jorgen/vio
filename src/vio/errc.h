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
inline constexpr int eof = -3001;
inline constexpr int canceled = -3002;
inline constexpr int again = -3003;
inline constexpr int interrupted = -3004;
inline constexpr int timed_out = -3005;
inline constexpr int connection_reset = -3006;
inline constexpr int connection_refused = -3007;
inline constexpr int connection_aborted = -3008;
inline constexpr int broken_pipe = -3009;
inline constexpr int address_in_use = -3010;
inline constexpr int address_not_available = -3011;
inline constexpr int not_connected = -3012;
inline constexpr int already_connected = -3013;
inline constexpr int network_unreachable = -3014;
inline constexpr int host_unreachable = -3015;
inline constexpr int network_down = -3016;
inline constexpr int no_buffer_space = -3017;
inline constexpr int message_too_long = -3018;
inline constexpr int invalid_argument = -3019;
inline constexpr int bad_descriptor = -3020;
inline constexpr int not_supported = -3021;
inline constexpr int permission_denied = -3022;
inline constexpr int operation_not_permitted = -3023;
inline constexpr int no_such_file = -3024;
inline constexpr int file_exists = -3025;
inline constexpr int not_a_directory = -3026;
inline constexpr int is_a_directory = -3027;
inline constexpr int directory_not_empty = -3028;
inline constexpr int no_space = -3029;
inline constexpr int too_many_open_files = -3030;
inline constexpr int out_of_memory = -3031;
inline constexpr int address_family_not_supported = -3032;
inline constexpr int already_in_progress = -3033;
inline constexpr int in_progress = -3034;
inline constexpr int name_too_long = -3035;
inline constexpr int read_only_file_system = -3036;
inline constexpr int cross_device_link = -3037;
inline constexpr int too_many_symbolic_links = -3038;
inline constexpr int file_too_large = -3039;
inline constexpr int io_error = -3040;
inline constexpr int invalid_seek = -3041;
inline constexpr int protocol_error = -3042;
inline constexpr int not_implemented = -3043;
inline constexpr int no_such_device = -3044;
inline constexpr int busy = -3045;
inline constexpr int bad_address = -3046;
inline constexpr int protocol_not_supported = -3047;
inline constexpr int socket_type_not_supported = -3048;
inline constexpr int text_file_busy = -3049;
inline constexpr int too_many_links = -3050;
inline constexpr int no_such_process = -3051;
inline constexpr int not_a_socket = -3052;
inline constexpr int destination_address_required = -3053;
inline constexpr int no_protocol_option = -3054;
inline constexpr int resource_busy_or_locked = -3055;
inline constexpr int dns_address_family = -3101;
inline constexpr int dns_again = -3102;
inline constexpr int dns_bad_flags = -3103;
inline constexpr int dns_fail = -3104;
inline constexpr int dns_family = -3105;
inline constexpr int dns_memory = -3106;
inline constexpr int dns_no_data = -3107;
inline constexpr int dns_no_name = -3108;
inline constexpr int dns_service = -3109;
inline constexpr int dns_socket_type = -3110;
inline constexpr int dns_overflow = -3111;
inline constexpr int dns_protocol = -3112;
inline constexpr int dns_canceled = -3113;
inline constexpr int dns_bad_hints = -3114;
inline constexpr int unknown = -3999;
} // namespace vio::errc
