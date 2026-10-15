add_executable(vio_tests
    test_main.cpp
    test_basic.cpp
    test_crypto.cpp
    test_objstore.cpp
    test_credentials.cpp
    test_ssl_upgrade.cpp
    test_task_and_sleep.cpp
    test_timer.cpp
    test_crypto_aead.cpp
    test_udp_batch.cpp
    test_buffer_pool.cpp
    test_udp_send_async.cpp
    test_quic_vectors.cpp
    test_quic_frame_table.cpp
    test_quic_frame_codec.cpp
    test_quic_packet.cpp
    test_quic_protection.cpp
    test_quic_tls.cpp
    test_quic_reassembly.cpp
    test_quic_transport_parameters.cpp
    test_quic_connection.cpp
    test_quic_loss_recovery.cpp
    test_quic_path.cpp
    test_quic_connection_ids.cpp
    test_quic_stateless_reset.cpp
    test_quic_endpoint.cpp
    test_quic_ecn.cpp
    test_quic_congestion.cpp
    test_quic_qlog.cpp
    test_quic_streams.cpp
    test_quic_coroutine.cpp
    test_http_client.cpp
    test_http_cache.cpp
    test_file.cpp
    test_file_leak.cpp
    test_tcp.cpp
    test_tcp_read_cb.cpp
    test_tcp_read_into.cpp
    test_tcp_server_listen.cpp
    test_tcp_write_guard.cpp
    test_ssl.cpp
    test_ssl_alpn.cpp
    test_ssl_sni.cpp
    test_ssl_deep.cpp
    test_ssl_config.cpp
    test_ca_certificates.cpp
    test_dns.cpp
    test_dns_leak.cpp
    test_elastic_index_storage.cpp
    test_ring_buffer.cpp
    test_tls_server.cpp
    test_event_pipe.cpp
    test_event_pipe_drain.cpp
    test_ref_counted_wrapper.cpp
    test_handle_closer.cpp
    test_udp.cpp
    test_reader_cancel.cpp
    test_cancellation.cpp
    test_work.cpp
    test_thread_pool.cpp
    test_loop_core.cpp
)

CmDepTargetLinkLibrary(vio_tests PRIVATE vio vio_objstore BoringSSL::SSL BoringSSL::Crypto)

if(VIO_USE_SYSTEM_DOCTEST)
    target_link_libraries(vio_tests PRIVATE doctest::doctest)
else()
    target_include_directories(vio_tests PRIVATE ${doctest_SOURCE_DIR})
endif()

target_include_directories(vio_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)

add_test(NAME vio_tests COMMAND vio_tests)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    option(VIO_TEST_IO_URING "Also run vio_tests on the io_uring backend" ON)
    if(VIO_TEST_IO_URING)
        add_test(NAME vio_tests_io_uring COMMAND vio_tests)
        set_tests_properties(vio_tests_io_uring PROPERTIES ENVIRONMENT "VIO_BACKEND=io_uring")
    endif()
endif()

# A benchmark, not a test: it replaces global operator new to count
# allocations, so it must not share a binary with anything else. Excluded from
# the default build; configure and then "cmake --build . --target vio_bench".
add_executable(vio_bench EXCLUDE_FROM_ALL bench_quic.cpp)
CmDepTargetLinkLibrary(vio_bench PRIVATE vio BoringSSL::SSL BoringSSL::Crypto)
target_include_directories(vio_bench PRIVATE ${CMAKE_SOURCE_DIR}/src)

# A server for a foreign QUIC implementation to talk to. Needs a second
# process, so it is not part of the suite.
add_executable(vio_interop_server EXCLUDE_FROM_ALL interop_server.cpp)
CmDepTargetLinkLibrary(vio_interop_server PRIVATE vio BoringSSL::SSL BoringSSL::Crypto)
target_include_directories(vio_interop_server PRIVATE ${CMAKE_SOURCE_DIR}/src)

# A transfer with the network taken out of it: the one repeatable measurement
# of what the protocol costs, and what a profiler should be pointed at.
add_executable(vio_profile_quic EXCLUDE_FROM_ALL profile_quic.cpp)
CmDepTargetLinkLibrary(vio_profile_quic PRIVATE vio BoringSSL::SSL BoringSSL::Crypto)
target_include_directories(vio_profile_quic PRIVATE ${CMAKE_SOURCE_DIR}/src)

# Spawns threads and saturates a loopback port, so it is a tool rather than a
# test: "cmake --build . --target vio_udp_bench".
add_executable(vio_udp_bench EXCLUDE_FROM_ALL udp_bench.cpp)
CmDepTargetLinkLibrary(vio_udp_bench PRIVATE vio BoringSSL::SSL BoringSSL::Crypto)
target_include_directories(vio_udp_bench PRIVATE ${CMAKE_SOURCE_DIR}/src)

# What the AEAD costs per packet, for comparing against another stack's crypto.
add_executable(vio_crypto_bench EXCLUDE_FROM_ALL crypto_bench.cpp)
CmDepTargetLinkLibrary(vio_crypto_bench PRIVATE vio BoringSSL::SSL BoringSSL::Crypto)
target_include_directories(vio_crypto_bench PRIVATE ${CMAKE_SOURCE_DIR}/src)

# The endpoint the QUIC Interop Runner drives, as both client and server. Its
# whole interface is the environment, so it takes no arguments.
add_executable(vio_interop_endpoint EXCLUDE_FROM_ALL interop_endpoint.cpp)
CmDepTargetLinkLibrary(vio_interop_endpoint PRIVATE vio BoringSSL::SSL BoringSSL::Crypto)
target_include_directories(vio_interop_endpoint PRIVATE ${CMAKE_SOURCE_DIR}/src)
