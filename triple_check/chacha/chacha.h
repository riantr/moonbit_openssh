/* Triple-check shim for chacha.h (no OpenBSD sys/types.h, no __bounded__ attrs) */
#ifndef CHACHA_SHIM_H
#define CHACHA_SHIM_H

#include <stdint.h>
#include <stddef.h>

typedef uint8_t u_char;
typedef unsigned int u_int;

struct chacha_ctx {
	u_int input[16];
};

#define CHACHA_MINKEYLEN	16
#define CHACHA_NONCELEN		8
#define CHACHA_CTRLEN		8
#define CHACHA_STATELEN		(CHACHA_NONCELEN+CHACHA_CTRLEN)
#define CHACHA_BLOCKLEN		64

void chacha_keysetup(struct chacha_ctx *x, const u_char *k, u_int kbits);
void chacha_ivsetup(struct chacha_ctx *x, const u_char *iv, const u_char *ctr);
void chacha_encrypt_bytes(struct chacha_ctx *x, const u_char *m,
    u_char *c, u_int bytes);

#endif	/* CHACHA_SHIM_H */
