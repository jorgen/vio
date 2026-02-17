# Standalone script to fetch all 3rdparty dependencies.
# Can be run independently of the build:
#   cmake -P CMake/FetchDependencies.cmake
#   cmake -DPOINTS_3RD_PARTY_DIR=/custom/path -P CMake/FetchDependencies.cmake
#
# Requires cmake-dep to be available (either from a prior configure or checked out manually).

cmake_minimum_required(VERSION 3.18)

get_filename_component(_script_dir "${CMAKE_CURRENT_LIST_DIR}" ABSOLUTE)
get_filename_component(_project_root "${_script_dir}/.." ABSOLUTE)

# Look for cmake-dep: first as sibling directory, then in build/_deps
if(EXISTS "${_project_root}/../cmake-dep/cmake/CmDepFetchDependencies.cmake")
    set(_cmdep_dir "${_project_root}/../cmake-dep")
elseif(EXISTS "${_project_root}/build/_deps/cmake-dep-src/cmake/CmDepFetchDependencies.cmake")
    set(_cmdep_dir "${_project_root}/build/_deps/cmake-dep-src")
else()
    message(FATAL_ERROR
        "Cannot find cmake-dep. Either:\n"
        "  1. Place cmake-dep as a sibling directory (../cmake-dep), or\n"
        "  2. Run a CMake configure first to FetchContent cmake-dep into build/_deps/")
endif()

include("${_cmdep_dir}/cmake/CmDepFetchDependencies.cmake")
CmDepFetchDependenciesSetup("${_project_root}" "${_script_dir}/3rdPartyPackages.cmake")
