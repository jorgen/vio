add_library(vio STATIC
        library.cpp
        worker.cpp

)

target_include_directories(vio PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

if(TARGET uv_a)
    target_link_libraries(vio PRIVATE uv_a)
    target_include_directories(vio PUBLIC ${libuv_SOURCE_DIR}/include)
else()
    find_package(libuv REQUIRED)
    target_link_libraries(vio PRIVATE uv_a)  # or uv::uv depending on how libuv is found
endif()

include(GenerateExportHeader)

# Generate an export header for the 'vio' library target
generate_export_header(vio
        BASE_NAME VIO
        EXPORT_FILE_NAME "${CMAKE_CURRENT_SOURCE_DIR}/vio/vio_export.h"
)

