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
    include(${Fetch3rdPartyDirInternal}/3rdPartyPackages.cmake)
endfunction()

