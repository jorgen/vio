cmake_minimum_required(VERSION 3.30)
project(vio LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/CMake")

option(VIO_USE_SYSTEM_LIBUV "Don't use the version specifed by vio cmake" OFF)

include(CMake/Fetch3rdParty.cmake)
Fetch3rdParty()
include(CMake/Build3rdParty.cmake)
Build3rdParty()
include(Cmake/BuildExternalTargetLinkLibrary.cmake)


add_subdirectory(src)

enable_testing()
add_subdirectory(test)