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

CmDepFetchPackage(libuv v1.51.0
    https://github.com/libuv/libuv/archive/refs/tags/v1.51.0.tar.gz
    SHA256=27e55cf7083913bfb6826ca78cde9de7647cded648d35f24163f2d31bb9f51cd)

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
