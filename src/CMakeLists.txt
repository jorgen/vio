if(EMSCRIPTEN)
    add_library(vio STATIC
        library_wasm.cpp
    )
    target_compile_definitions(vio PUBLIC VIO_STATIC_DEFINE)
    target_include_directories(vio PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
else()
    if(VIO_BUILD_SHARED)
        add_library(vio SHARED
            library.cpp
        )
    else()
        add_library(vio STATIC
            library.cpp
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

    target_include_directories(vio PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

    target_link_libraries(vio PRIVATE vio::default_certs)

    if (VIO_USE_SYSTEM_LIBUV)
        find_package(libuv REQUIRED)
        target_link_libraries(vio PUBLIC uv_a)
    else ()
        target_link_libraries(vio PUBLIC uv_a)
        target_include_directories(vio PUBLIC ${libuv_SOURCE_DIR}/include)
    endif ()

    if(VIO_BUILD_SHARED AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
        target_link_options(vio PRIVATE "-Wl,--exclude-libs,ALL")
    endif()
endif()
