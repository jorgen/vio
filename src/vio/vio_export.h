
#ifndef VIO_EXPORT_H
#define VIO_EXPORT_H

#ifdef VIO_STATIC_DEFINE
#  define VIO_EXPORT
#  define VIO_NO_EXPORT
#else
#  ifndef VIO_EXPORT
#    ifdef vio_EXPORTS
        /* We are building this library */
#      define VIO_EXPORT 
#    else
        /* We are using this library */
#      define VIO_EXPORT 
#    endif
#  endif

#  ifndef VIO_NO_EXPORT
#    define VIO_NO_EXPORT 
#  endif
#endif

#ifndef VIO_DEPRECATED
#  define VIO_DEPRECATED __attribute__ ((__deprecated__))
#endif

#ifndef VIO_DEPRECATED_EXPORT
#  define VIO_DEPRECATED_EXPORT VIO_EXPORT VIO_DEPRECATED
#endif

#ifndef VIO_DEPRECATED_NO_EXPORT
#  define VIO_DEPRECATED_NO_EXPORT VIO_NO_EXPORT VIO_DEPRECATED
#endif

/* NOLINTNEXTLINE(readability-avoid-unconditional-preprocessor-if) */
#if 0 /* DEFINE_NO_DEPRECATED */
#  ifndef VIO_NO_DEPRECATED
#    define VIO_NO_DEPRECATED
#  endif
#endif

#endif /* VIO_EXPORT_H */
