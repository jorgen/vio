
add_library(vio STATIC
    library.cpp
    worker.cpp

)
configure_file(${libressl_SOURCE_DIR}/cert.pem ${CMAKE_CURRENT_SOURCE_DIR}/default_certs/cert.pem COPYONLY)
cmrc_add_resource_library(vio_default_certs ALIAS vio::default_certs NAMESPACE vio default_certs/cert.pem)

BuildExternalTargetLinkLibrary(vio PUBLIC LibreSSL::TLS ada)
if (WIN32)
    BuildExternalTargetLinkLibrary(vio PUBLIC crypt32)
endif ()

target_include_directories(vio PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(vio PRIVATE vio::default_certs)

if (VIO_USE_SYSTEM_LIBUV)
    find_package(libuv REQUIRED)
    target_link_libraries(vio PRIVATE uv_a)  # or uv::uv depending on how libuv is found
else ()
    target_link_libraries(vio PRIVATE uv_a)
    target_include_directories(vio PUBLIC ${libuv_SOURCE_DIR}/include)
endif ()

include(GenerateExportHeader)

# Generate an export header for the 'vio' library target
generate_export_header(vio
    BASE_NAME VIO
    EXPORT_FILE_NAME "${CMAKE_CURRENT_SOURCE_DIR}/vio/vio_export.h"
)

