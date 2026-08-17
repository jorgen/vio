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
)

CmDepTargetLinkLibrary(vio_tests PRIVATE vio vio_objstore LibreSSL::TLS LibreSSL::SSL LibreSSL::Crypto)

if(VIO_USE_SYSTEM_DOCTEST)
    target_link_libraries(vio_tests PRIVATE doctest::doctest)
else()
    target_include_directories(vio_tests PRIVATE ${doctest_SOURCE_DIR})
endif()

target_include_directories(vio_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)

add_test(NAME vio_tests COMMAND vio_tests)