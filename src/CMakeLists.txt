if(EMSCRIPTEN)
    add_library(vio STATIC
        library_wasm.cpp
        crypto_encoding.cpp
        crypto_sha256.cpp
    )
    target_compile_definitions(vio PUBLIC VIO_STATIC_DEFINE)
    target_include_directories(vio PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
else()
    if(VIO_BUILD_SHARED)
        add_library(vio SHARED
            library.cpp
            crypto.cpp
            crypto_aead.cpp
            crypto_encoding.cpp
        )
    else()
        add_library(vio STATIC
            library.cpp
            crypto.cpp
            crypto_aead.cpp
            crypto_encoding.cpp
        )
        target_compile_definitions(vio PUBLIC VIO_STATIC_DEFINE)
    endif()

    set_target_properties(vio PROPERTIES
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN ON
        C_VISIBILITY_PRESET hidden
    )

    if(NOT VIO_USE_SYSTEM_LIBRESSL)
        configure_file(${libressl_SOURCE_DIR}/cert.pem ${CMAKE_CURRENT_SOURCE_DIR}/default_certs/cert.pem COPYONLY)
    endif()
    cmrc_add_resource_library(vio_default_certs ALIAS vio::default_certs NAMESPACE vio default_certs/cert.pem)

    if(VIO_BUILD_SHARED)
        set_target_properties(vio_default_certs PROPERTIES POSITION_INDEPENDENT_CODE ON)
    endif()

    # Select the SSL backend. PUBLIC so the define propagates to header-only
    # consumers (the seam #errors on a missing/ambiguous backend, catching a
    # header/library mismatch at compile time).
    if(VIO_SSL_BACKEND STREQUAL "libressl")
        target_compile_definitions(vio PUBLIC VIO_SSL_BACKEND_LIBRESSL)
    elseif(VIO_SSL_BACKEND STREQUAL "openssl")
        target_compile_definitions(vio PUBLIC VIO_SSL_BACKEND_OPENSSL)
    elseif(VIO_SSL_BACKEND STREQUAL "boringssl")
        target_compile_definitions(vio PUBLIC VIO_SSL_BACKEND_BORINGSSL)
    else()
        message(FATAL_ERROR "Unknown VIO_SSL_BACKEND '${VIO_SSL_BACKEND}' (expected libressl|openssl|boringssl)")
    endif()

    # Dependencies are PUBLIC because vio's inline header code calls libuv/libressl directly.
    # Phase 2 (PIMPL) will allow switching to PRIVATE for full symbol hiding.
    # vio now speaks only the OpenSSL SSL_*/BIO API (the memory-BIO engine), so libtls
    # (LibreSSL::TLS) is no longer linked -- only the SSL and Crypto libraries.
    CmDepTargetLinkLibrary(vio PUBLIC LibreSSL::SSL LibreSSL::Crypto ada::ada)
    if (WIN32)
        CmDepTargetLinkLibrary(vio PUBLIC crypt32 bcrypt)
    endif ()

    target_include_directories(vio PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    )

    target_link_libraries(vio PRIVATE vio::default_certs)

    if (VIO_USE_SYSTEM_LIBUV)
        find_package(libuv CONFIG REQUIRED)
        target_link_libraries(vio PUBLIC libuv::uv_a)
    else ()
        target_link_libraries(vio PUBLIC uv_a)
        target_include_directories(vio PUBLIC ${libuv_SOURCE_DIR}/include)
    endif ()

    if(VIO_BUILD_SHARED AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
        target_link_options(vio PRIVATE "-Wl,--exclude-libs,ALL")
    endif()
endif()

add_library(vio::vio ALIAS vio)

# ---------------------------------------------------------------------------
# vio_objstore: the object-store abstraction (io_manager backends + connection-string
# parsing + the native AWS credential provider chain) as a SEPARATE target layered on
# top of vio. Keeping it out of core libvio means base vio carries no AWS/JSON object
# code and no structify dependency; consumers that need cloud storage link
# vio::objstore, which brings vio (and its include dirs) transitively.
#
# Almost all of objstore is header-only -- its io_manager backends are instantiated in
# the consumer's translation units. Only the AWS credential parsers are compiled
# (aws_json.cpp + aws_config.cpp), and those are native-only, so under Emscripten the
# target is header-only (INTERFACE).
if(EMSCRIPTEN)
    add_library(vio_objstore INTERFACE)
    target_link_libraries(vio_objstore INTERFACE vio)
else()
    if(VIO_BUILD_SHARED)
        add_library(vio_objstore SHARED
            vio/objstore/aws_json.cpp
            vio/objstore/aws_config.cpp
        )
    else()
        add_library(vio_objstore STATIC
            vio/objstore/aws_json.cpp
            vio/objstore/aws_config.cpp
        )
    endif()

    set_target_properties(vio_objstore PROPERTIES
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN ON
        C_VISIBILITY_PRESET hidden
    )

    # PUBLIC: objstore's public headers use vio's public API (task_t, event_loop_t,
    # crypto, http::fetch), so consumers of vio_objstore need vio + its include dirs.
    # This also propagates VIO_STATIC_DEFINE in the static build, so the VIO_EXPORT
    # macros in the objstore sources resolve consistently with core vio.
    target_link_libraries(vio_objstore PUBLIC vio)

    # structify (header-only) is used only by aws_json.cpp. PRIVATE + SYSTEM: it must
    # not leak into objstore's public headers (which expose plain structs instead) and
    # its headers must not trip the -Wall -Werror build.
    target_include_directories(vio_objstore SYSTEM PRIVATE ${structify_SOURCE_DIR}/include)

    if(VIO_BUILD_SHARED AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
        target_link_options(vio_objstore PRIVATE "-Wl,--exclude-libs,ALL")
    endif()
endif()

add_library(vio::objstore ALIAS vio_objstore)

if(VIO_INSTALL AND NOT EMSCRIPTEN)
    include(CMakePackageConfigHelpers)

    install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/vio
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        FILES_MATCHING PATTERN "*.h")

    if(VIO_USE_SYSTEM_LIBUV AND VIO_USE_SYSTEM_LIBRESSL AND VIO_USE_SYSTEM_ADA)
        set(_vio_export_targets vio vio_objstore vio_default_certs)
        set(VIO_CONFIG_DEPS "")
        string(APPEND VIO_CONFIG_DEPS "find_dependency(libuv CONFIG)\n")
        string(APPEND VIO_CONFIG_DEPS "find_dependency(LibreSSL)\n")
        string(APPEND VIO_CONFIG_DEPS "find_dependency(ada CONFIG)\n")
        if(VIO_USE_SYSTEM_CMAKERC)
            string(APPEND VIO_CONFIG_DEPS "find_dependency(CMakeRC CONFIG)\n")
        else()
            list(APPEND _vio_export_targets cmrc-base)
        endif()

        install(TARGETS ${_vio_export_targets}
            EXPORT vioTargets
            ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
            LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
            INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
        install(EXPORT vioTargets
            NAMESPACE vio::
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/vio
            FILE vioTargets.cmake)
        configure_package_config_file(
            ${PROJECT_SOURCE_DIR}/CMake/vioConfig.cmake.in
            ${CMAKE_CURRENT_BINARY_DIR}/vioConfig.cmake
            INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/vio)
        write_basic_package_version_file(
            ${CMAKE_CURRENT_BINARY_DIR}/vioConfigVersion.cmake
            VERSION ${PROJECT_VERSION}
            COMPATIBILITY SameMajorVersion)
        install(FILES
            ${CMAKE_CURRENT_BINARY_DIR}/vioConfig.cmake
            ${CMAKE_CURRENT_BINARY_DIR}/vioConfigVersion.cmake
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/vio)
    else()
        install(TARGETS vio vio_objstore vio_default_certs
            ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
            LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
        message(STATUS "vio: VIO_INSTALL is on but vio is built with bundled dependencies; installing library + headers only (no find_package config). Configure with VIO_USE_SYSTEM_LIBUV/LIBRESSL/ADA=ON for a relocatable package config.")
    endif()
endif()
