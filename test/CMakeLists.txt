add_executable(vio_tests
    test_main.cpp
    test_basic.cpp
    test_task_and_sleep.cpp
    test_file.cpp
    test_tcp.cpp
    test_ssl.cpp
    test_dns.cpp
)

BuildExternalTargetLinkLibrary(vio_tests PRIVATE vio bcrypt LibreSSL::Crypto LibreSSL::SSL LibreSSL::TLS)
target_link_libraries(vio_tests PRIVATE bcrypt)


target_include_directories(vio_tests PRIVATE
    ${doctest_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/src
)

add_test(NAME vio_tests COMMAND vio_tests)