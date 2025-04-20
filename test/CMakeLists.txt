include(FetchContent)
FetchContent_Declare(
    doctest
    GIT_REPOSITORY https://github.com/doctest/doctest.git
    GIT_TAG        v2.4.11
)
FetchContent_MakeAvailable(doctest)

add_executable(vio_tests
    test_main.cpp
    test_basic.cpp
    test_task_and_sleep.cpp
    test_file.cpp
    test_tcp.cpp
)

target_link_libraries(vio_tests PRIVATE vio)


target_include_directories(vio_tests PRIVATE
    ${doctest_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/src
)

add_test(NAME vio_tests COMMAND vio_tests)