set(Fetch3rdPartyDirInternal "${CMAKE_CURRENT_LIST_DIR}")
macro(Fetch3rdParty_Package name version url url_hash)
    if (POINTS_3RD_PARTY_DIR)
        set(Fetch3rdPartyDir "${POINTS_3RD_PARTY_DIR}")
    else ()
        set(Fetch3rdPartyDir "${Fetch3rdPartyDirInternal}/../3rdparty")
    endif ()
    get_filename_component(thirdParty "${Fetch3rdPartyDir}" ABSOLUTE)
    set(SRC_DIR ${thirdParty}/${name}-${version})
    set(${name}_SOURCE_DIR ${SRC_DIR} PARENT_SCOPE)
    set(${name}_VERSION ${version} PARENT_SCOPE)
    if (NOT (EXISTS ${SRC_DIR}))
        FetchContent_Populate(${name}
            URL ${url}
            URL_HASH ${url_hash}
            SOURCE_DIR ${SRC_DIR}
            SUBBUILD_DIR ${thirdParty}/CMakeArtifacts/${name}-sub-${version}
            BINARY_DIR ${thirdParty}/CMakeArtifacts/${name}-${version})
    endif ()
endmacro()

macro(Fetch3rdParty_File name version url destination_name url_hash)
    if (POINTS_3RD_PARTY_DIR)
        set(Fetch3rdPartyDir "${POINTS_3RD_PARTY_DIR}")
    else ()
        set(Fetch3rdPartyDir "${Fetch3rdPartyDirInternal}/../3rdparty")
    endif ()
    get_filename_component(thirdParty "${Fetch3rdPartyDir}" ABSOLUTE)
    file(MAKE_DIRECTORY ${thirdParty})
    set(SRC_DIR ${thirdParty}/${name}-${version})
    set(${name}_SOURCE_DIR ${SRC_DIR} PARENT_SCOPE)
    set(${name}_VERSION ${version} PARENT_SCOPE)
    set(DESTINATION_FILE "${SRC_DIR}/${destination_name}")
    if (NOT (EXISTS ${DESTINATION_FILE}))
        file(DOWNLOAD ${url} ${DESTINATION_FILE}
            SHOW_PROGRESS
            EXPECTED_HASH ${url_hash}
        )
    endif ()
endmacro()

function(Fetch3rdParty)
    include(FetchContent)
    set(FETCHCONTENT_QUIET OFF)
    Fetch3rdParty_Package(cmakerc 952ff https://github.com/vector-of-bool/cmrc/archive/952ffddba731fc110bd50409e8d2b8a06abbd237.zip SHA256=b199e7481dda667cd1b1936c9acb64e496ebc3c5ad90b381ba8d0f361c80638d)
    Fetch3rdParty_Package(libuv v1.51.0 https://github.com/libuv/libuv/archive/refs/tags/v1.51.0.tar.gz SHA256=27e55cf7083913bfb6826ca78cde9de7647cded648d35f24163f2d31bb9f51cd)
    Fetch3rdParty_Package(doctest v2.4.11 https://github.com/doctest/doctest/archive/refs/tags/v2.4.12.tar.gz SHA256=73381c7aa4dee704bd935609668cf41880ea7f19fa0504a200e13b74999c2d70)
    Fetch3rdParty_Package(libressl 4.1.0 https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-4.1.0.tar.gz SHA256=0f71c16bd34bdaaccdcb96a5d94a4921bfb612ec6e0eba7a80d8854eefd8bb61)
    Fetch3rdParty_Package(ada 3.2.4 https://github.com/ada-url/ada/archive/refs/tags/v3.2.4.tar.gz SHA256=ce79b8fb0f6be6af3762a16c5488cbcd38c31d0655313a7030972a7eb2bda9e5)
endfunction()

