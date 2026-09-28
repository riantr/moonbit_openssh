/* Minimal SSH-compat stub so OpenSSH's cipher-chachapoly.c compiles
 * standalone in the Loop #8 verification harness. NOT production code.
 * Provides exactly what cipher-chachapoly.c references:
 *   u_char/u_int types, ssherr codes, POKE_U64/PEEK_U32,
 *   timingsafe_bcmp, explicit_bzero, freezero.
 */
#ifndef AEAD_SSH_COMPAT_H
#define AEAD_SSH_COMPAT_H

#include <sys/types.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t u_char;
typedef unsigned int u_int;

/* ssherr.h codes used by cipher-chachapoly.c (values arbitrary, only
 * compared against themselves in this harness).
 * Guarded so we can coexist with kex_c25519_compat.h which already defines them. */
#ifndef SSH_ERR_INTERNAL_ERROR
#define SSH_ERR_INTERNAL_ERROR      (-1)
#endif
#ifndef SSH_ERR_MESSAGE_INCOMPLETE
#define SSH_ERR_MESSAGE_INCOMPLETE  (-2)
#endif
#ifndef SSH_ERR_MAC_INVALID
#define SSH_ERR_MAC_INVALID         (-3)
#endif

/* misc.h byte-poke/peek macros, big-endian, same semantics as OpenSSH.
 * POKE_U64 zero-extends its argument to 64 bit before storing - this is
 * exactly the behaviour MoonBit's seq_to_be64 must replicate. */
#define PEEK_U32(p) (((u_int)((const u_char *)(p))[0] << 24) | \
                     ((u_int)((const u_char *)(p))[1] << 16) | \
                     ((u_int)((const u_char *)(p))[2] << 8)  | \
                      (u_int)((const u_char *)(p))[3])

#define POKE_U64(p, v) do { \
    const uint64_t poke_u64_v_ = (uint64_t)(v); \
    ((u_char *)(p))[0] = (u_char)(poke_u64_v_ >> 56); \
    ((u_char *)(p))[1] = (u_char)(poke_u64_v_ >> 48); \
    ((u_char *)(p))[2] = (u_char)(poke_u64_v_ >> 40); \
    ((u_char *)(p))[3] = (u_char)(poke_u64_v_ >> 32); \
    ((u_char *)(p))[4] = (u_char)(poke_u64_v_ >> 24); \
    ((u_char *)(p))[5] = (u_char)(poke_u64_v_ >> 16); \
    ((u_char *)(p))[6] = (u_char)(poke_u64_v_ >> 8);  \
    ((u_char *)(p))[7] = (u_char)(poke_u64_v_);       \
} while (0)

static inline int timingsafe_bcmp(const void *b1, const void *b2, size_t n)
{
    const unsigned char *p1 = (const unsigned char *)b1;
    const unsigned char *p2 = (const unsigned char *)b2;
    int ret = 0;
    for (; n > 0; n--)
        ret |= *p1++ ^ *p2++;
    return ret != 0;
}

static inline void explicit_bzero(void *p, size_t n)
{
    if (p != NULL)
        memset(p, 0, n);
}

static inline void freezero(void *p, size_t n)
{
    if (p == NULL)
        return;
    explicit_bzero(p, n);
    free(p);
}

#endif /* AEAD_SSH_COMPAT_H */
