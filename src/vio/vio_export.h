
#ifndef VIO_EXPORT_H
#define VIO_EXPORT_H

#ifdef VIO_STATIC_DEFINE
#  define VIO_EXPORT
#  define VIO_NO_EXPORT
#else
#  ifdef _WIN32
#    ifdef vio_EXPORTS
       /* We are building this library */
#      define VIO_EXPORT __declspec(dllexport)
#    else
       /* We are using this library */
#      define VIO_EXPORT __declspec(dllimport)
#    endif
#    define VIO_NO_EXPORT
#  else
#    define VIO_EXPORT __attribute__((visibility("default")))
#    define VIO_NO_EXPORT __attribute__((visibility("hidden")))
#  endif
#endif

#ifndef VIO_DEPRECATED
#  ifdef _MSC_VER
#    define VIO_DEPRECATED __declspec(deprecated)
#  else
#    define VIO_DEPRECATED __attribute__((deprecated))
#  endif
#endif

#ifndef VIO_DEPRECATED_EXPORT
#  define VIO_DEPRECATED_EXPORT VIO_EXPORT VIO_DEPRECATED
#endif

#ifndef VIO_DEPRECATED_NO_EXPORT
#  define VIO_DEPRECATED_NO_EXPORT VIO_NO_EXPORT VIO_DEPRECATED
#endif

#endif /* VIO_EXPORT_H */
