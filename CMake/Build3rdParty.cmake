macro(Build3rdParty)
    if (cmakerc_USE_SYSTEM)
        find_package(CMakeRC CONFIG REQUIRED)
    else ()
        include(${cmakerc_SOURCE_DIR}/CMakeRC.cmake)
    endif ()

    # BoringSSL builds in-tree like the other dependencies rather than as its own
    # external project. It publishes plain `crypto` and `ssl` targets carrying
    # their own include directories, and CmDepAddPackage adds it SYSTEM
    # EXCLUDE_FROM_ALL, so nothing of it is built beyond what vio links -- which
    # also keeps its install() rules from reaching this project.
    #
    # It is C++ rather than C, which is the one thing a consumer has to notice:
    # the archives carry C++ symbols and want the C++ runtime on the link line.
    CmDepAddPackage(boringssl PACKAGE OpenSSL CONFIG OPTIONS BUILD_TESTING=OFF)
    # Built in tree the targets are plain `crypto`/`ssl`; found on the system
    # they arrive under BoringSSL's OpenSSL-compatible config as OpenSSL::*.
    # vio links the BoringSSL:: names either way.
    if (NOT TARGET BoringSSL::Crypto)
        if (TARGET crypto)
            add_library(BoringSSL::Crypto ALIAS crypto)
        elseif (TARGET OpenSSL::Crypto)
            add_library(BoringSSL::Crypto INTERFACE IMPORTED)
            target_link_libraries(BoringSSL::Crypto INTERFACE OpenSSL::Crypto)
        endif ()
    endif ()
    if (NOT TARGET BoringSSL::SSL)
        if (TARGET ssl)
            add_library(BoringSSL::SSL ALIAS ssl)
        elseif (TARGET OpenSSL::SSL)
            add_library(BoringSSL::SSL INTERFACE IMPORTED)
            target_link_libraries(BoringSSL::SSL INTERFACE OpenSSL::SSL)
        endif ()
    endif ()

    CmDepAddPackage(ada OPTIONS ADA_TESTING=OFF ADA_BENCHMARKS=OFF ADA_TOOLS=OFF)

    if (VIO_BUILD_TESTS)
        CmDepAddPackage(doctest OPTIONS DOCTEST_WITH_TESTS=OFF DOCTEST_NO_INSTALL=ON)
    endif ()
endmacro()
