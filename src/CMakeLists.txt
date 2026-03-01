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

# Dependencies are PUBLIC because vio's inline header code calls libuv/libressl directly.
# Phase 2 (PIMPL) will allow switching to PRIVATE for full symbol hiding.
BuildExternalTargetLinkLibrary(vio PUBLIC LibreSSL::TLS LibreSSL::SSL LibreSSL::Crypto ada::ada)
if (WIN32)
    BuildExternalTargetLinkLibrary(vio PUBLIC crypt32 bcrypt)
endif ()

target_include_directories(vio PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

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
