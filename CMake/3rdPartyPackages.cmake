# 3rdparty package definitions.
# Included by CmDepFetch and CmDepFetchDependencies.
# Caller must define CmDepFetchPackage(name version url url_hash) before including this file.
#
# Each dependency's version, URL, and SHA256 are cache variables so a consumer
# can fetch a different version without editing this file, e.g.:
#   -DVIO_LIBRESSL_VERSION=4.0.0
#   -DVIO_LIBRESSL_URL=https://.../libressl-4.0.0.tar.gz
#   -DVIO_LIBRESSL_SHA256=<hash>
# Alternatively set VIO_USE_SYSTEM_<DEP>=ON to consume a pre-installed copy via
# find_package instead of fetching at all.

set(VIO_CMAKERC_VERSION "952ff" CACHE STRING "CMakeRC version tag")
set(VIO_CMAKERC_URL "https://github.com/vector-of-bool/cmrc/archive/952ffddba731fc110bd50409e8d2b8a06abbd237.zip" CACHE STRING "CMakeRC source archive URL")
set(VIO_CMAKERC_SHA256 "b199e7481dda667cd1b1936c9acb64e496ebc3c5ad90b381ba8d0f361c80638d" CACHE STRING "CMakeRC archive SHA256")
if(NOT VIO_USE_SYSTEM_CMAKERC)
    CmDepFetchPackage(cmakerc ${VIO_CMAKERC_VERSION} ${VIO_CMAKERC_URL} SHA256=${VIO_CMAKERC_SHA256})
endif()

set(VIO_LIBUV_VERSION "v1.51.0" CACHE STRING "libuv version to fetch")
set(VIO_LIBUV_URL "https://github.com/libuv/libuv/archive/refs/tags/v1.51.0.tar.gz" CACHE STRING "libuv source archive URL")
set(VIO_LIBUV_SHA256 "27e55cf7083913bfb6826ca78cde9de7647cded648d35f24163f2d31bb9f51cd" CACHE STRING "libuv archive SHA256")
if(NOT VIO_USE_SYSTEM_LIBUV)
    CmDepFetchPackage(libuv ${VIO_LIBUV_VERSION} ${VIO_LIBUV_URL} SHA256=${VIO_LIBUV_SHA256})
endif()

set(VIO_DOCTEST_VERSION "v2.4.11" CACHE STRING "doctest version to fetch")
set(VIO_DOCTEST_URL "https://github.com/doctest/doctest/archive/refs/tags/v2.4.12.tar.gz" CACHE STRING "doctest source archive URL")
set(VIO_DOCTEST_SHA256 "73381c7aa4dee704bd935609668cf41880ea7f19fa0504a200e13b74999c2d70" CACHE STRING "doctest archive SHA256")
if(VIO_BUILD_TESTS AND NOT VIO_USE_SYSTEM_DOCTEST)
    CmDepFetchPackage(doctest ${VIO_DOCTEST_VERSION} ${VIO_DOCTEST_URL} SHA256=${VIO_DOCTEST_SHA256})
endif()

set(VIO_LIBRESSL_VERSION "4.1.0" CACHE STRING "LibreSSL version to fetch")
set(VIO_LIBRESSL_URL "https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-4.1.0.tar.gz" CACHE STRING "LibreSSL source archive URL")
set(VIO_LIBRESSL_SHA256 "0f71c16bd34bdaaccdcb96a5d94a4921bfb612ec6e0eba7a80d8854eefd8bb61" CACHE STRING "LibreSSL archive SHA256")
if(NOT VIO_USE_SYSTEM_LIBRESSL)
    CmDepFetchPackage(libressl ${VIO_LIBRESSL_VERSION} ${VIO_LIBRESSL_URL} SHA256=${VIO_LIBRESSL_SHA256})
endif()

set(VIO_ADA_VERSION "3.2.4" CACHE STRING "ada-url version to fetch")
set(VIO_ADA_URL "https://github.com/ada-url/ada/archive/refs/tags/v3.2.4.tar.gz" CACHE STRING "ada-url source archive URL")
set(VIO_ADA_SHA256 "ce79b8fb0f6be6af3762a16c5488cbcd38c31d0655313a7030972a7eb2bda9e5" CACHE STRING "ada-url archive SHA256")
if(NOT VIO_USE_SYSTEM_ADA)
    CmDepFetchPackage(ada ${VIO_ADA_VERSION} ${VIO_ADA_URL} SHA256=${VIO_ADA_SHA256})
endif()
