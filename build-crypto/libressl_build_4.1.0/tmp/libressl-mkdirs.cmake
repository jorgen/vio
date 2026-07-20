# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file LICENSE.rst or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION ${CMAKE_VERSION}) # this file comes with cmake

# If CMAKE_DISABLE_SOURCE_CHANGES is set to true and the source directory is an
# existing directory in our source tree, calling file(MAKE_DIRECTORY) on it
# would cause a fatal error, even though it would be a no-op.
if(NOT EXISTS "/home/jlind/dev/vio/3rdparty/libressl-4.1.0")
  file(MAKE_DIRECTORY "/home/jlind/dev/vio/3rdparty/libressl-4.1.0")
endif()
file(MAKE_DIRECTORY
  "/home/jlind/dev/vio/build-crypto/libressl_build_4.1.0/src/libressl-build"
  "/home/jlind/dev/vio/build-crypto/libressl_build_4.1.0"
  "/home/jlind/dev/vio/build-crypto/libressl_build_4.1.0/tmp"
  "/home/jlind/dev/vio/build-crypto/libressl_build_4.1.0/src/libressl-stamp"
  "/home/jlind/dev/vio/build-crypto/libressl_build_4.1.0/src"
  "/home/jlind/dev/vio/build-crypto/libressl_build_4.1.0/src/libressl-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "/home/jlind/dev/vio/build-crypto/libressl_build_4.1.0/src/libressl-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "/home/jlind/dev/vio/build-crypto/libressl_build_4.1.0/src/libressl-stamp${cfgdir}") # cfgdir has leading slash
endif()
