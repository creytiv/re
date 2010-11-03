/**
 * @file re_types.h  Defines basic types
 *
 * Copyright (C) 2010 Creytiv.com
 */

#include <sys/types.h>

#ifdef _MSC_VER
#include <stdlib.h>
#endif

/*
 * Basic integral types from C99
 */

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#else

#ifndef __int8_t_defined
#define __int8_t_defined

/* Hack for OpenBSD */
#ifndef __BIT_TYPES_DEFINED__

#if defined(_CHAR_IS_SIGNED)
typedef char                    int8_t;
#elif defined(__STDC__)
typedef signed char             int8_t;
#else
typedef char                    int8_t;
#endif

typedef signed short int          int16_t;
typedef signed int                int32_t;
typedef signed long long int      int64_t;

#ifndef __uint32_t_defined
#define __uint32_t_defined
typedef unsigned char             uint8_t;
typedef unsigned short int        uint16_t;
typedef unsigned int              uint32_t;
typedef unsigned long long int    uint64_t;
#endif

#endif /* __BIT_TYPES_DEFINED__ */

#endif /* __int8_t_defined */
#ifndef __ssize_t_defined
typedef long     ssize_t;
#define __ssize_t_defined
#endif


#ifndef WIN32
typedef uint32_t socklen_t;
#endif
#endif


/*
 * Hack for Solaris which does not define int64_t/uint64_t for strict ANSI C
 */
#ifdef SOLARIS
#if !(__STDC__ - 0 == 0 && !defined(_NO_LONGLONG))
typedef signed long long int      int64_t;
typedef unsigned long long int    uint64_t;
#endif
#endif


/*
 * Boolean type
 * see http://www.opengroup.org/onlinepubs/000095399/basedefs/stdbool.h.html
 *     www.gnu.org/software/autoconf/manual/html_node/Particular-Headers.html
 */
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# ifndef HAVE__BOOL
#  ifdef __cplusplus
typedef bool _Bool;
#  else
#   define _Bool signed char
#  endif
# endif
# define bool _Bool
# define false 0
# define true 1
# define __bool_true_false_are_defined 1
#endif

/* Needed for MS compiler */
#ifdef _MSC_VER
#define inline _inline
#endif


/*
 * Misc macros
 */

/** Defines the NULL pointer */
#ifndef NULL
#define NULL ((void *)0)
#endif

/** Get number of elements in an array */
#undef ARRAY_SIZE
#define ARRAY_SIZE(a) ((sizeof(a))/(sizeof((a)[0])))

/** Align a value to the boundary of mask */
#define ALIGN_MASK(x, mask)    (((x)+(mask))&~(mask))


/** Get the minimal value */
#undef MIN
#define MIN(a,b) (((a)<(b)) ? (a) : (b))

/** Get the maximal value */
#undef MAX
#define MAX(a,b) (((a)>(b)) ? (a) : (b))

/** Get the minimal value */
#undef min
#define min(x,y) MIN(x, y)

/** Get the maximal value */
#undef max
#define max(x,y) MAX(x, y)

/** Defines a soft breakpoint */
#if (defined(__i386__) || defined(__x86_64__)) && !defined(__SYMBIAN32__)
#define BREAKPOINT __asm__("int $0x03")
#else
#define BREAKPOINT
#endif


/* Error codes */
#include <errno.h>

/* Duplication of error codes. Values are from linux asm-generic/errno.h */

/** No data available */
#ifndef ENODATA
#define ENODATA 61
#endif

/** Protocol error */
#ifndef EPROTO
#define EPROTO 71
#endif

/** Not a data message */
#ifndef EBADMSG
#define EBADMSG 74
#endif

/** Value too large for defined data type */
#ifndef EOVERFLOW
#define EOVERFLOW 75
#endif

/** Accessing a corrupted shared library */
#ifndef ELIBBAD
#define ELIBBAD 80
#endif

/** Destination address required */
#ifndef EDESTADDRREQ
#define EDESTADDRREQ 89
#endif

/** Protocol not supported */
#ifndef EPROTONOSUPPORT
#define EPROTONOSUPPORT 93
#endif

/** Operation not supported on transport endpoint */
#ifndef ENOTSUP
#define ENOTSUP 95
#endif

/** Address family not supported by protocol */
#ifndef EAFNOSUPPORT
#define EAFNOSUPPORT 97
#endif

/** Cannot assign requested address */
#ifndef EADDRNOTAVAIL
#define EADDRNOTAVAIL 99
#endif

/** Software caused connection abort */
#ifndef ECONNABORTED
#define ECONNABORTED 103
#endif

/** Connection reset by peer */
#ifndef ECONNRESET
#define ECONNRESET 104
#endif

/** Transport endpoint is not connected */
#ifndef ENOTCONN
#define ENOTCONN 107
#endif

/** Connection timed out */
#ifndef ETIMEDOUT
#define ETIMEDOUT 110
#endif

/** Connection refused */
#ifndef ECONNREFUSED
#define ECONNREFUSED 111
#endif

/** Operation already in progress */
#ifndef EALREADY
#define EALREADY 114
#endif

/** Operation now in progress */
#ifndef EINPROGRESS
#define EINPROGRESS 115
#endif

/** Authentication error */
#ifndef EAUTH
#define EAUTH 116
#endif
