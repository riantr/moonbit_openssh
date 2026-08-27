/* Minimal compat stub for Loop #9 harness (sshbuf.c / sshbuf-getput-basic.c).
 * Provides: BSD byte types, ssherr codes used, ROUNDUP from misc.h.
 * NOT production code. */
#ifndef KEX_C25519_COMPAT_H
#define KEX_C25519_COMPAT_H

#include <sys/types.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef uint8_t u_char;
typedef unsigned int u_int;
typedef uint8_t u_int8_t;
typedef uint16_t u_int16_t;
typedef uint32_t u_int32_t;
typedef uint64_t u_int64_t;

/* ssherr.h codes referenced by sshbuf sources */
#define SSH_ERR_INTERNAL_ERROR          (-1)
#define SSH_ERR_ALLOC_FAIL              (-2)
#define SSH_ERR_MESSAGE_INCOMPLETE      (-3)
#define SSH_ERR_INVALID_FORMAT          (-4)
#define SSH_ERR_NO_BUFFER_SPACE         (-5)
#define SSH_ERR_BIGNUM_IS_NEGATIVE      (-6)
#define SSH_ERR_STRING_TOO_LARGE        (-7)
#define SSH_ERR_KEY_INVALID_EC_VALUE    (-8)
#define SSH_ERR_SIGNATURE_INVALID       (-9)
#define SSH_ERR_MAC_INVALID             (-10)
#define SSH_ERR_BUFFER_READ_ONLY        (-11)
#define SSH_ERR_INVALID_ARGUMENT        (-12)
#define SSH_ERR_BIGNUM_TOO_LARGE        (-13)

/* openbsd-compat VA_COPY (va_list re-use) */
#include <stdarg.h>
#if defined(__GNUC__)
# define VA_COPY(ap2, ap) va_copy((ap2), (ap))
#else
# define VA_COPY(ap2, ap) ((ap2) = (ap))
#endif

/* openbsd-compat/recallocarray.c: grow/shrink with zeroing of new area */
static inline void *recallocarray(void *ptr, size_t oldnmemb, size_t newnmemb,
    size_t size)
{
    size_t oldsize = oldnmemb * size, newsize = newnmemb * size;
    void *np;
    if (newsize == 0) {
        free(ptr);
        return NULL;
    }
    np = realloc(ptr, newsize);
    if (np == NULL)
        return NULL;
    if (newsize > oldsize)
        memset((char *)np + oldsize, 0, newsize - oldsize);
    return np;
}

/* misc.h */
#define ROUNDUP(x, y)   ((((x)+((y)-1))/(y))*(y))

/* openbsd-compat freezero / explicit_bzero */
#define explicit_bzero(p, n) memset((p), 0, (n))
static inline void freezero(void *p, size_t n)
{
    if (p == NULL)
        return;
    explicit_bzero(p, n);
    free(p);
}

/* openbsd-compat/defines.h branch prediction hints */
#ifndef __predict_true
# define __predict_true(exp)    __builtin_expect(((exp) != 0), 1)
#endif
#ifndef __predict_false
# define __predict_false(exp)   __builtin_expect(((exp) != 0), 0)
#endif

/* misc.h ssh_signal: harness is single-threaded and never touches signals;
 * map to plain signal() */
#include <signal.h>
#define ssh_signal(sig, handler) signal((sig), (handler))

/* OpenSSH SSHBUF_SIZE_INC lives in sshbuf.h; nothing else needed here */

#endif /* KEX_C25519_COMPAT_H */
