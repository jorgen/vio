set(VIO_GUI_SOURCES src/display.cpp src/context.cpp)
set(VIO_GUI_LIBRARIES vio)
set(VIO_GUI_DEFINITIONS)

if(WIN32)
    list(APPEND VIO_GUI_SOURCES src/backend_win32.cpp src/context_win32.cpp)
    list(APPEND VIO_GUI_LIBRARIES user32 gdi32)
elseif(APPLE)
    enable_language(OBJCXX)
    list(APPEND VIO_GUI_SOURCES src/backend_cocoa.mm)
    set_source_files_properties(src/backend_cocoa.mm PROPERTIES COMPILE_OPTIONS "-fobjc-arc")
    list(APPEND VIO_GUI_LIBRARIES "-framework Cocoa" "-framework QuartzCore" "-framework OpenGL")
else()
    find_package(X11)
    if(X11_FOUND)
        list(APPEND VIO_GUI_SOURCES src/backend_x11.cpp)
        list(APPEND VIO_GUI_LIBRARIES X11::X11)
        list(APPEND VIO_GUI_DEFINITIONS VIO_GUI_HAVE_X11)
    endif()
    find_package(PkgConfig)
    if(PkgConfig_FOUND)
        pkg_check_modules(VIO_WAYLAND IMPORTED_TARGET wayland-client wayland-cursor xkbcommon wayland-protocols)
        pkg_get_variable(VIO_WAYLAND_PROTOCOLS wayland-protocols pkgdatadir)
        pkg_get_variable(VIO_WAYLAND_SCANNER wayland-scanner wayland_scanner)
    endif()
    if(VIO_WAYLAND_FOUND AND VIO_WAYLAND_SCANNER AND VIO_WAYLAND_PROTOCOLS)
        set(protocol_dir ${CMAKE_CURRENT_BINARY_DIR}/protocols)
        file(MAKE_DIRECTORY ${protocol_dir})
        foreach(protocol
                stable/xdg-shell/xdg-shell.xml
                unstable/xdg-decoration/xdg-decoration-unstable-v1.xml)
            get_filename_component(name ${protocol} NAME_WE)
            add_custom_command(
                OUTPUT ${protocol_dir}/${name}.h ${protocol_dir}/${name}.c
                COMMAND ${VIO_WAYLAND_SCANNER} client-header ${VIO_WAYLAND_PROTOCOLS}/${protocol} ${protocol_dir}/${name}.h
                COMMAND ${VIO_WAYLAND_SCANNER} private-code ${VIO_WAYLAND_PROTOCOLS}/${protocol} ${protocol_dir}/${name}.c
                DEPENDS ${VIO_WAYLAND_PROTOCOLS}/${protocol})
            list(APPEND VIO_GUI_SOURCES ${protocol_dir}/${name}.c)
        endforeach()
        list(APPEND VIO_GUI_SOURCES src/backend_wayland.cpp)
        list(APPEND VIO_GUI_LIBRARIES PkgConfig::VIO_WAYLAND)
        list(APPEND VIO_GUI_DEFINITIONS VIO_GUI_HAVE_WAYLAND)
    endif()
    list(APPEND VIO_GUI_SOURCES src/context_egl.cpp)
    list(APPEND VIO_GUI_LIBRARIES ${CMAKE_DL_LIBS})
endif()

add_library(vio_gui STATIC ${VIO_GUI_SOURCES})
add_library(vio::gui ALIAS vio_gui)
target_include_directories(vio_gui PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/protocols)
target_link_libraries(vio_gui PUBLIC ${VIO_GUI_LIBRARIES})
target_compile_definitions(vio_gui PRIVATE ${VIO_GUI_DEFINITIONS})

# The declarative toolkit, on top of the window layer and kept out of it (PLAN.md, "UI toolkit").
add_library(vio_gui_ui STATIC src/ui.cpp src/ui_text.cpp src/ui_vulkan.cpp)
add_library(vio::gui_ui ALIAS vio_gui_ui)
# FreeType and HarfBuzz stay private: nothing in ui.h names them (G27).
target_link_libraries(vio_gui_ui PUBLIC vio_gui PRIVATE vio::freetype vio::harfbuzz)
# Vulkan declarations only: the loader is opened at run time (G6, G31), so nothing is linked.
if(vulkan_headers_USE_SYSTEM)
    find_package(VulkanHeaders CONFIG REQUIRED)
    target_link_libraries(vio_gui_ui PRIVATE Vulkan::Headers)
else()
    target_include_directories(vio_gui_ui SYSTEM PRIVATE ${vulkan_headers_SOURCE_DIR}/include)
endif()
if(NOT WIN32)
    target_link_libraries(vio_gui_ui PRIVATE ${CMAKE_DL_LIBS})
endif()

# Regenerates src/shaders/ui_spirv.h from ui.slang (G25). Not part of any build: the header is
# committed, and only someone changing a shader needs slangc. -DVIO_GUI_FETCH_SLANG=ON uses the
# prebuilt one cmake-dep fetched for this host; otherwise slangc is looked for on PATH.
foreach(_slang slang_windows_x86_64 slang_windows_aarch64 slang_macos_x86_64 slang_macos_aarch64
        slang_linux_x86_64 slang_linux_aarch64)
    if(VIO_GUI_FETCH_SLANG AND ${_slang}_SOURCE_DIR)
        find_program(VIO_SLANGC slangc PATHS ${${_slang}_SOURCE_DIR}/bin NO_DEFAULT_PATH REQUIRED)
    endif()
endforeach()
find_program(VIO_SLANGC slangc)
if(VIO_SLANGC)
    set(shader_dir ${CMAKE_CURRENT_BINARY_DIR}/shaders)
    add_custom_target(vio_gui_shaders
        COMMAND ${CMAKE_COMMAND} -E make_directory ${shader_dir}
        COMMAND ${VIO_SLANGC} ${CMAKE_CURRENT_SOURCE_DIR}/src/shaders/ui.slang -target spirv -profile spirv_1_0
                -entry vertexMain -stage vertex -o ${shader_dir}/ui.vert.spv
        COMMAND ${VIO_SLANGC} ${CMAKE_CURRENT_SOURCE_DIR}/src/shaders/ui.slang -target spirv -profile spirv_1_0
                -entry fragmentMain -stage fragment -o ${shader_dir}/ui.frag.spv
        COMMAND ${CMAKE_COMMAND} -DOUTPUT=${CMAKE_CURRENT_SOURCE_DIR}/src/shaders/ui_spirv.h
                "-DCOMPILER=slangc from ui.slang"
                "-DNAMES=ui_vertex$<SEMICOLON>ui_fragment"
                "-DFILES=${shader_dir}/ui.vert.spv$<SEMICOLON>${shader_dir}/ui.frag.spv"
                -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/embed_spirv.cmake
        COMMENT "Compiling the UI shaders with slangc"
        VERBATIM)
endif()

if(VIO_BUILD_TESTS)
    set(VIO_GUI_TEST_SOURCES test/test_main.cpp test/test_gui.cpp test/test_ui.cpp test/test_ui_render.cpp test/test_ui_text.cpp)
    if(WIN32)
        list(APPEND VIO_GUI_TEST_SOURCES test/test_win32.cpp)
    elseif(APPLE)
        list(APPEND VIO_GUI_TEST_SOURCES test/test_cocoa.mm)
        set_source_files_properties(test/test_cocoa.mm PROPERTIES COMPILE_OPTIONS "-fobjc-arc")
    else()
        list(APPEND VIO_GUI_TEST_SOURCES test/test_x11.cpp test/test_wayland.cpp test/test_context.cpp)
    endif()
    add_executable(vio_gui_tests ${VIO_GUI_TEST_SOURCES})
    target_compile_definitions(vio_gui_tests PRIVATE ${VIO_GUI_DEFINITIONS})
    target_link_libraries(vio_gui_tests PRIVATE vio_gui_ui)
    if(VIO_USE_SYSTEM_DOCTEST)
        target_link_libraries(vio_gui_tests PRIVATE doctest::doctest)
    else()
        target_include_directories(vio_gui_tests PRIVATE ${doctest_SOURCE_DIR})
    endif()
    # The text tests use fonts from HarfBuzz's own test suite, so they need its source tree.
    if(DEFINED harfbuzz_SOURCE_DIR AND NOT harfbuzz_USE_SYSTEM)
        target_compile_definitions(vio_gui_tests PRIVATE "VIO_GUI_TEST_FONTS=\"${harfbuzz_SOURCE_DIR}\"")
    endif()
    add_test(NAME vio_gui_tests COMMAND vio_gui_tests)
endif()

if(VIO_BUILD_EXAMPLES)
    function(add_vio_gui_example name source)
        add_executable(${name} examples/${source})
        target_link_libraries(${name} PRIVATE vio_gui ${ARGN})
    endfunction()
    add_vio_gui_example(vio_gui_hello hello_window.cpp)
    add_vio_gui_example(vio_gui_input_echo input_echo.cpp)
    add_vio_gui_example(vio_gui_windows_and_network windows_and_network.cpp)
    add_vio_gui_example(vio_gui_ui_counter ui_counter.cpp vio_gui_ui)
    find_package(Vulkan QUIET)
    if(Vulkan_FOUND AND NOT APPLE)
        add_vio_gui_example(vio_gui_vulkan_clear vulkan_clear.cpp Vulkan::Vulkan)
    endif()
    if(APPLE)
        add_vio_gui_example(vio_gui_metal_clear metal_clear.mm "-framework Metal" "-framework QuartzCore")
        set_source_files_properties(examples/metal_clear.mm PROPERTIES COMPILE_OPTIONS "-fobjc-arc")
    endif()
    if(WIN32)
        add_vio_gui_example(vio_gui_d3d12_clear d3d12_clear.cpp d3d12 dxgi)
        if(VIO_BUILD_TESTS)
            add_test(NAME vio_gui_hello COMMAND vio_gui_hello 20)
            add_test(NAME vio_gui_input_echo COMMAND vio_gui_input_echo 300)
            add_test(NAME vio_gui_windows_and_network COMMAND vio_gui_windows_and_network 1300)
            add_test(NAME vio_gui_ui_counter COMMAND vio_gui_ui_counter 300)
            add_test(NAME vio_gui_d3d12_clear COMMAND vio_gui_d3d12_clear 30)
        endif()
    endif()
endif()
