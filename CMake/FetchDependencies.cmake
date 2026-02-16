# Standalone script to fetch all 3rdparty dependencies.
# Can be run independently of the build:
#   cmake -P CMake/FetchDependencies.cmake
#   cmake -DPOINTS_3RD_PARTY_DIR=/custom/path -P CMake/FetchDependencies.cmake
#
# Package list is shared with Fetch3rdParty.cmake via 3rdPartyPackages.cmake

cmake_minimum_required(VERSION 3.18)

# Determine the 3rdparty directory
get_filename_component(_script_dir "${CMAKE_CURRENT_LIST_DIR}" ABSOLUTE)
if(NOT POINTS_3RD_PARTY_DIR)
    set(_3rdparty_dir "${_script_dir}/../3rdparty")
else()
    set(_3rdparty_dir "${POINTS_3RD_PARTY_DIR}")
endif()
get_filename_component(_3rdparty_dir "${_3rdparty_dir}" ABSOLUTE)
file(MAKE_DIRECTORY "${_3rdparty_dir}")

message(STATUS "3rdparty directory: ${_3rdparty_dir}")

macro(Fetch3rdParty_Package name version url url_hash)
    set(_target_dir "${_3rdparty_dir}/${name}-${version}")
    if(EXISTS "${_target_dir}")
        message(STATUS "${name}-${version}: already exists, skipping")
    else()
        message(STATUS "${name}-${version}: downloading...")

        set(_tmp_dir "${_3rdparty_dir}/.fetch_tmp_${name}")
        file(REMOVE_RECURSE "${_tmp_dir}")
        file(MAKE_DIRECTORY "${_tmp_dir}")

        # Determine archive filename from URL
        string(REGEX MATCH "[^/]+$" _archive_name "${url}")
        set(_archive_path "${_tmp_dir}/${_archive_name}")

        file(DOWNLOAD "${url}" "${_archive_path}"
            SHOW_PROGRESS
            EXPECTED_HASH "${url_hash}"
            STATUS _download_status
        )
        list(GET _download_status 0 _status_code)
        if(NOT _status_code EQUAL 0)
            list(GET _download_status 1 _error_msg)
            file(REMOVE_RECURSE "${_tmp_dir}")
            message(FATAL_ERROR "Download failed for ${name}: ${_error_msg}")
        endif()

        # Extract to temp location
        set(_extract_dir "${_tmp_dir}/extracted")
        file(MAKE_DIRECTORY "${_extract_dir}")
        file(ARCHIVE_EXTRACT INPUT "${_archive_path}" DESTINATION "${_extract_dir}")

        # Find the single top-level directory in the extracted content
        file(GLOB _children "${_extract_dir}/*")
        list(LENGTH _children _num_children)
        if(_num_children EQUAL 1)
            list(GET _children 0 _single_child)
            if(IS_DIRECTORY "${_single_child}")
                file(RENAME "${_single_child}" "${_target_dir}")
            else()
                file(RENAME "${_extract_dir}" "${_target_dir}")
            endif()
        else()
            file(RENAME "${_extract_dir}" "${_target_dir}")
        endif()

        file(REMOVE_RECURSE "${_tmp_dir}")
        message(STATUS "${name}-${version}: done")
    endif()
endmacro()

include(${_script_dir}/3rdPartyPackages.cmake)

message(STATUS "All dependencies fetched to: ${_3rdparty_dir}")
