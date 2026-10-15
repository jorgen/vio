cmake_minimum_required(VERSION 3.30)
project(vio_install_consumer LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(vio CONFIG REQUIRED)

add_executable(vio_install_consumer main.cpp)
target_link_libraries(vio_install_consumer PRIVATE vio::vio)

enable_testing()
add_test(NAME vio_install_consumer COMMAND vio_install_consumer)
