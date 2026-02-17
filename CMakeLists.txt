cmake_minimum_required(VERSION 3.30)
project(vio LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/CMake")

option(VIO_USE_SYSTEM_LIBUV "Don't use the version specifed by vio cmake" OFF)
option(VIO_USE_SYSTEM_LIBRESSL "Use system-installed LibreSSL instead of bundled" OFF)
option(VIO_USE_SYSTEM_ADA "Use system-installed ada-url instead of bundled" OFF)
option(VIO_USE_SYSTEM_DOCTEST "Use system-installed doctest instead of bundled" OFF)
option(VIO_BUILD_SHARED "Build vio as a shared library" OFF)

if(VIO_BUILD_SHARED)
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
    # Place all executables and DLLs in the same directory so they can find each other
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
endif()

include(FetchContent)
FetchContent_Declare(cmake-dep
    SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../cmake-dep"
)
FetchContent_MakeAvailable(cmake-dep)
list(APPEND CMAKE_MODULE_PATH "${cmake-dep_SOURCE_DIR}/cmake")
include(CmDepMain)

set(CMDEP_3RD_PARTY_PACKAGES_FILE "${CMAKE_CURRENT_SOURCE_DIR}/CMake/3rdPartyPackages.cmake")
CmDepFetch3rdParty()

include(CMake/Build3rdParty.cmake)
Build3rdParty()

add_subdirectory(src)

enable_testing()
add_subdirectory(test)
add_subdirectory(examples)
