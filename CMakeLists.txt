cmake_minimum_required(VERSION 3.30)
project(vio LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(VIO_BUILD_LIBUV "Download and build libuv as part of the build" OFF)

if(VIO_BUILD_LIBUV)
    include(FetchContent)
    FetchContent_Declare(
            libuv
            GIT_REPOSITORY https://github.com/libuv/libuv.git
            GIT_TAG        v1.50.0
    )
    FetchContent_MakeAvailable(libuv)
endif()

add_subdirectory(src)

enable_testing()
add_subdirectory(test)