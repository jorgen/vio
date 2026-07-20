cmake_minimum_required(VERSION ${CMAKE_VERSION}) # this file comes with cmake

message(VERBOSE "Executing download step for libressl")

block(SCOPE_FOR VARIABLES)

include("/home/jlind/dev/vio/build-linux/CMakeFiles/fc-stamp/libressl/download-libressl.cmake")
include("/home/jlind/dev/vio/build-linux/CMakeFiles/fc-stamp/libressl/verify-libressl.cmake")
include("/home/jlind/dev/vio/build-linux/CMakeFiles/fc-stamp/libressl/extract-libressl.cmake")


endblock()
