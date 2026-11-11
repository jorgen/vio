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

    # Text for the gui toolkit (gui/DECISIONS.md G27, G39). Both end up as the targets
    # vio::freetype and vio::harfbuzz whichever way they arrive.
    if (VIO_BUILD_GUI AND NOT EMSCRIPTEN)
        CmDepAddPackage(freetype PACKAGE Freetype OPTIONS
            FT_DISABLE_HARFBUZZ=ON FT_DISABLE_ZLIB=ON FT_DISABLE_BZIP2=ON
            FT_DISABLE_PNG=ON FT_DISABLE_BROTLI=ON)
        if (TARGET freetype)
            add_library(vio::freetype ALIAS freetype)
        else ()
            add_library(vio::freetype ALIAS Freetype::Freetype)
        endif ()

        if (harfbuzz_USE_SYSTEM)
            find_package(harfbuzz CONFIG REQUIRED)
            add_library(vio::harfbuzz ALIAS harfbuzz::harfbuzz)
        else ()
            # The amalgamation: one translation unit, HarfBuzz's own OpenType font functions and
            # Unicode data, no FreeType, no threads library, nothing installed.
            add_library(vio_harfbuzz STATIC "${harfbuzz_SOURCE_DIR}/src/harfbuzz.cc")
            target_include_directories(vio_harfbuzz SYSTEM PUBLIC "${harfbuzz_SOURCE_DIR}/src")
            set_target_properties(vio_harfbuzz PROPERTIES CXX_STANDARD 17 POSITION_INDEPENDENT_CODE ON)
            if (MSVC)
                target_compile_options(vio_harfbuzz PRIVATE /bigobj /w)
            else ()
                target_compile_options(vio_harfbuzz PRIVATE -w)
            endif ()
            add_library(vio::harfbuzz ALIAS vio_harfbuzz)
        endif ()
    endif ()

    if (VIO_BUILD_TESTS)
        CmDepAddPackage(doctest OPTIONS DOCTEST_WITH_TESTS=OFF DOCTEST_NO_INSTALL=ON)
    endif ()
endmacro()
