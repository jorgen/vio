include(BuildExternal)
include(GetPackageInstallDir)

macro(Build3rdParty)
    GetPackageInstallDir(LIBRESSL_INSTALL_DIR libressl ${libressl_VERSION})
    list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/CMake/FindPackage/libressl)
    Find_Package(libressl REQUIRED)
    BuildExternalCMake(libressl ${libressl_VERSION} ${libressl_SOURCE_DIR} "" "LibreSSL::TLS")
    if (NOT VIO_USE_SYSTEM_LIBUV)
        add_subdirectory(${libuv_SOURCE_DIR} "${CMAKE_CURRENT_BINARY_DIR}/libuv_build" SYSTEM)
    endif ()
    add_subdirectory(${doctest_SOURCE_DIR} "${CMAKE_CURRENT_BINARY_DIR}/doctest_build" SYSTEM)
endmacro()
