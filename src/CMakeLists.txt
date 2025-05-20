
add_library(vio STATIC
    library.cpp
    worker.cpp

)

BuildExternalTargetLinkLibrary(vio PUBLIC LibreSSL::TLS ada)

target_include_directories(vio PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

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

