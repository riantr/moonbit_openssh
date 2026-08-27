/* Triple-check shim: minimal includes.h (no OpenSSH system headers) */
#ifndef INCLUDES_SHIM_H
#define INCLUDES_SHIM_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

typedef uint8_t u_char;
typedef unsigned int u_int;

/* ---- stubs for symbols referenced by ed25519.c but unused in standalone driver ---- */
static inline void explicit_bzero(void *p, size_t n) { memset(p, 0, n); }
static inline void randombytes(unsigned char *buf, unsigned long long n) {
    /* deterministic test fill: NOT cryptographic - this path is only for
     * ed25519_random_keypair_generate which is not exercised by KAT driver. */
    unsigned long long i;
    for (i = 0; i < n; i++) buf[i] = (unsigned char)(i & 0xff);
}

#endif /* INCLUDES_SHIM_H */
