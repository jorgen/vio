# 3rdparty package definitions. Included by CmDepFetch (and CmDepFetchSetup in
# script mode). CmDepFetchPackage auto-declares, per dep: VIO_<DEP>_{VERSION,URL,SHA256}
# (CACHE STRING overrides, -D wins) and VIO_USE_SYSTEM_<DEP> (option; ON => skip the
# fetch). The VIO_ prefix is derived from the project() name (PROJECT_NAME).
#
# Override a version without editing this file, e.g.:
#   -DVIO_LIBRESSL_VERSION=4.0.0 -DVIO_LIBRESSL_URL=https://.../libressl-4.0.0.tar.gz -DVIO_LIBRESSL_SHA256=<hash>
# or consume a pre-installed copy: -DVIO_USE_SYSTEM_LIBRESSL=ON

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

CmDepFetchPackage(libressl 4.1.0
    https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-4.1.0.tar.gz
    SHA256=0f71c16bd34bdaaccdcb96a5d94a4921bfb612ec6e0eba7a80d8854eefd8bb61)

CmDepFetchPackage(ada 3.2.4
    https://github.com/ada-url/ada/archive/refs/tags/v3.2.4.tar.gz
    SHA256=ce79b8fb0f6be6af3762a16c5488cbcd38c31d0655313a7030972a7eb2bda9e5)
