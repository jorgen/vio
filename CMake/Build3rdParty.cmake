macro(Build3rdParty)
    if (cmakerc_USE_SYSTEM)
        find_package(CMakeRC CONFIG REQUIRED)
    else ()
        include(${cmakerc_SOURCE_DIR}/CMakeRC.cmake)
    endif ()

    if (libressl_USE_SYSTEM)
        find_package(LibreSSL REQUIRED)
    else ()
        CmDepInstallDir(LIBRESSL_INSTALL_DIR libressl ${libressl_VERSION})
        list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/CMake/FindPackage/libressl)
        Find_Package(libressl REQUIRED)
        # CMAKE_INSTALL_LIBDIR=lib: LibreSSL installs through GNUInstallDirs,
        # which defaults to lib64 on RedHat-family 64-bit distros (AlmaLinux,
        # Fedora, RHEL -- including the manylinux_2_28 images used to build
        # Python wheels). Findlibressl.cmake addresses the static libraries as
        # ${LIBRESSL_INSTALL_DIR}/lib/..., so without this the link fails with
        # "cannot find .../lib/libssl.a" on exactly those systems. Pin the
        # layout instead of guessing at it from the consumer side.
        CmDepBuildExternal(libressl ${libressl_VERSION} ${libressl_SOURCE_DIR} "-DLIBRESSL_APPS=OFF;-DLIBRESSL_TESTS=OFF;-DCMAKE_INSTALL_LIBDIR=lib" "LibreSSL::Crypto;LibreSSL::SSL;LibreSSL::TLS")
    endif ()

    CmDepAddPackage(libuv NO_SYSTEM_FIND OPTIONS LIBUV_BUILD_TESTS=OFF LIBUV_BUILD_BENCH=OFF LIBUV_BUILD_SHARED=OFF)
    CmDepAddPackage(ada OPTIONS ADA_TESTING=OFF ADA_BENCHMARKS=OFF ADA_TOOLS=OFF)

    if (VIO_BUILD_TESTS)
        CmDepAddPackage(doctest OPTIONS DOCTEST_WITH_TESTS=OFF DOCTEST_NO_INSTALL=ON)
    endif ()
endmacro()
