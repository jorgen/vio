# 3rdparty package definitions. Included by CmDepFetch (and CmDepFetchSetup in
# script mode). CmDepFetchPackage auto-declares, per dep: VIO_<DEP>_{VERSION,URL,SHA256}
# (CACHE STRING overrides, -D wins) and VIO_USE_SYSTEM_<DEP> (option; ON => skip the
# fetch). The VIO_ prefix is derived from the project() name (PROJECT_NAME).
#
# Override a version without editing this file, e.g.:
#   -DVIO_BORINGSSL_URL=https://.../<commit>.tar.gz -DVIO_BORINGSSL_SHA256=<hash>
# or consume a pre-installed copy: -DVIO_USE_SYSTEM_BORINGSSL=ON

CmDepFetchPackage(cmakerc 952ff
    https://github.com/vector-of-bool/cmrc/archive/952ffddba731fc110bd50409e8d2b8a06abbd237.zip
    SHA256=b199e7481dda667cd1b1936c9acb64e496ebc3c5ad90b381ba8d0f361c80638d)

if(VIO_BUILD_TESTS)
    CmDepFetchPackage(doctest v2.4.11
        https://github.com/doctest/doctest/archive/refs/tags/v2.4.12.tar.gz
        SHA256=73381c7aa4dee704bd935609668cf41880ea7f19fa0504a200e13b74999c2d70)
endif()

# BoringSSL has no releases and no stable ABI, so it is pinned by commit like
# any other source dependency and updated deliberately. Building it needs Go on
# PATH, and on Windows NASM as well -- without an assembler its configure step
# stops rather than quietly handing back a build with no AES-NI in it, which is
# what LibreSSL did and why this is BoringSSL now.
CmDepFetchPackage(boringssl 269525e
    https://github.com/google/boringssl/archive/269525eb7fcf610b8f9985f3de08d658bbd83f84.tar.gz
    SHA256=b9ae1852501d0d2e9c6b6047989fed9f0510087125c7113350116676436d54c8)

CmDepFetchPackage(ada 3.2.4
    https://github.com/ada-url/ada/archive/refs/tags/v3.2.4.tar.gz
    SHA256=ce79b8fb0f6be6af3762a16c5488cbcd38c31d0655313a7030972a7eb2bda9e5)

# structify: header-only JSON<->struct reflection, used by the native AWS credential provider chain to
# parse the ~/.aws login/SSO caches and the SSO/STS/IMDS responses. Consumed as includes only (no
# add_subdirectory, so structify's own catch2 / yaml-test-suite fetches never run) -- see src/CMakeLists.txt.
CmDepFetchPackage(structify b114582
    https://github.com/jorgen/structify/archive/b1145826ab4a06cbe32ae0c373a3161f74c48ac8.tar.gz
    SHA256=49f3af94194bd37aa76d99c1d3e351eb237b838ae75d21fecaf6ac4a806c7606)

# Vulkan-Headers: the declarations only. The gui toolkit's renderer loads the Vulkan loader at run
# time (gui/DECISIONS.md G6, G31), so nothing is linked and no Vulkan SDK is needed to build.
if(VIO_BUILD_GUI)
    CmDepFetchPackage(vulkan_headers 1.4.350.1
        https://github.com/KhronosGroup/Vulkan-Headers/archive/refs/tags/vulkan-sdk-1.4.350.1.tar.gz
        SHA256=6d1bb65e49520344cc0a48af3dc02e993781efff14c7ebdcb8ae9fa23ddf7e83)

    # Text (gui/DECISIONS.md G27, G39): HarfBuzz shapes, FreeType rasterizes. FreeType is built
    # without HarfBuzz, zlib, bzip2, PNG or Brotli, so the two never see each other. HarfBuzz is
    # compiled from its single-file amalgamation, and its test fonts are what the text tests use.
    CmDepFetchPackage(freetype 2.15.0
        https://github.com/freetype/freetype/archive/refs/tags/VER-2-15-0.tar.gz
        SHA256=87c7f1f8699b91e89f773f7dcfa505b044e1dae67f62a55d4e29c3afdcac4fb8)
    CmDepFetchPackage(harfbuzz 15.1.0
        https://github.com/harfbuzz/harfbuzz/releases/download/15.1.0/harfbuzz-15.1.0.tar.xz
        SHA256=0fc7c565443a5f4be7da65ac5ee5bd737d9b158dc908708b7689a0a5796b0c8d)

    # slangc, prebuilt, for the vio_gui_shaders target only (G33). Opt-in: the SPIR-V it produces
    # is committed, so only someone changing a shader needs it. A tool runs on the host, so the
    # archive is picked by the host's system and processor, never the target's.
    if(VIO_GUI_FETCH_SLANG)
        string(TOLOWER "${CMAKE_HOST_SYSTEM_PROCESSOR}" _vio_host_cpu)
        if(_vio_host_cpu MATCHES "^(arm64|aarch64)$")
            set(_vio_host_cpu aarch64)
        else()
            set(_vio_host_cpu x86_64)
        endif()
        set(_vio_slang_base https://github.com/shader-slang/slang/releases/download/v2026.21/slang-2026.21)
        if(CMAKE_HOST_WIN32 AND _vio_host_cpu STREQUAL aarch64)
            CmDepFetchPackage(slang_windows_aarch64 2026.21 ${_vio_slang_base}-windows-aarch64.tar.gz
                SHA256=b286783ed92d4e6ab22fc17e37ce39d7cac060f4e356fa10f1e2d67486fbb9c4)
        elseif(CMAKE_HOST_WIN32)
            CmDepFetchPackage(slang_windows_x86_64 2026.21 ${_vio_slang_base}-windows-x86_64.tar.gz
                SHA256=d2f4a1547f38d050aa87168bfd7379ad71aaa0a063c317ab6f727e9d8d901628)
        elseif(CMAKE_HOST_APPLE AND _vio_host_cpu STREQUAL aarch64)
            CmDepFetchPackage(slang_macos_aarch64 2026.21 ${_vio_slang_base}-macos-aarch64.tar.gz
                SHA256=c3d3c959ba3e0c8fdb6c2a5cf6a471ed097ed19c41820af9fb21625779794fb2)
        elseif(CMAKE_HOST_APPLE)
            CmDepFetchPackage(slang_macos_x86_64 2026.21 ${_vio_slang_base}-macos-x86_64.tar.gz
                SHA256=a6bc9ba38c5d3a092ae868595ba9c838663682b3e16de40d5786bd38964970ba)
        elseif(_vio_host_cpu STREQUAL aarch64)
            CmDepFetchPackage(slang_linux_aarch64 2026.21 ${_vio_slang_base}-linux-aarch64-glibc-2.28.tar.gz
                SHA256=c48f2c9a12f1a382a84a39f2b314b1cf3159c93136fbe8c4f377c87db4ef4dc8)
        else()
            CmDepFetchPackage(slang_linux_x86_64 2026.21 ${_vio_slang_base}-linux-x86_64-glibc-2.27.tar.gz
                SHA256=1b75315dabc97bab349449502c2e64faaa849360c17d9fdf709c0628ad5365ac)
        endif()
    endif()
endif()
