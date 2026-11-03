/*
 * blowfish_shim.h -- the three things OpenSSH's headers would have given us.
 *
 * This header stands in for OpenSSH's "includes.h" and "crypto_api.h" in
 * verify_c/blowfish_ref.c and verify_c/bcrypt_pbkdf_ref.c, which are
 * OpenSSH's own files with nothing but their include lines changed (see
 * host/blowfish_ref.py).
 *
 * Nothing here is a re-implementation of the algorithm.  It is:
 *
 *   1. the integer types OpenSSH's portability layer provides;
 *   2. the `blf_ctx` type and the Blowfish prototypes, copied verbatim
 *      out of OpenSSH's own openbsd-compat/blf.h;
 *   3. four small libc shims for the calls bcrypt_pbkdf.c makes that
 *      OpenSSH's portability layer normally hides.
 *
 * The SHA-512 is NOT shimmed: verify_c/sha2.c is OpenBSD's real SHA-2
 * implementation and is already in this repository, and the
 * `crypto_hash_sha512` below is a three-call wrapper over it.
 */

#ifndef BLOWFISH_SHIM_H
#define BLOWFISH_SHIM_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* OpenSSH's portability layer provides these; MinGW's sys/types.h may or
 * may not, and a repeated identical typedef is legal in C11. */
typedef uint8_t u_int8_t;
typedef uint16_t u_int16_t;
typedef uint32_t u_int32_t;
typedef uint64_t u_int64_t;

/* The SHA-2 prototypes.  bsd-sha2.h is OpenSSH's own header and is
 * already in this directory; sha2.c includes it too, and its include
 * guard makes the second inclusion a no-op. */
#include "bsd-sha2.h"

/* ------------------------------------------------------------------ */
/* From OpenSSH's openbsd-compat/blf.h, verbatim.                      */
/* ------------------------------------------------------------------ */

/* Schneier specifies a maximum key length of 56 bytes.
 * This ensures that every key bit affects every cipher
 * bit.  However, the subkeys can hold up to 72 bytes.
 * Warning: For normal blowfish encryption only 56 bytes
 * of the key affect all cipherbits.
 */

#define BLF_N	16			/* Number of Subkeys */
#define BLF_MAXKEYLEN ((BLF_N-2)*4)	/* 448 bits */
#define BLF_MAXUTILIZED ((BLF_N+2)*4)	/* 576 bits */

/* Blowfish context */
typedef struct BlowfishContext {
	u_int32_t S[4][256];	/* S-Boxes */
	u_int32_t P[BLF_N + 2];	/* Subkeys */
} blf_ctx;

/* Raw access to customized Blowfish
 *	blf_key is just:
 *	Blowfish_initstate( state )
 *	Blowfish_expand0state( state, key, keylen )
 */

void Blowfish_encipher(blf_ctx *, u_int32_t *, u_int32_t *);
void Blowfish_decipher(blf_ctx *, u_int32_t *, u_int32_t *);
void Blowfish_initstate(blf_ctx *);
void Blowfish_expand0state(blf_ctx *, const u_int8_t *, u_int16_t);
void Blowfish_expandstate
(blf_ctx *, const u_int8_t *, u_int16_t, const u_int8_t *, u_int16_t);

/* Standard Blowfish */

void blf_key(blf_ctx *, const u_int8_t *, u_int16_t);
void blf_enc(blf_ctx *, u_int32_t *, u_int16_t);
void blf_dec(blf_ctx *, u_int32_t *, u_int16_t);

void blf_ecb_encrypt(blf_ctx *, u_int8_t *, u_int32_t);
void blf_ecb_decrypt(blf_ctx *, u_int8_t *, u_int32_t);

void blf_cbc_encrypt(blf_ctx *, u_int8_t *, u_int8_t *, u_int32_t);
void blf_cbc_decrypt(blf_ctx *, u_int8_t *, u_int8_t *, u_int32_t);

/* Converts u_int8_t to u_int32_t */
u_int32_t Blowfish_stream2word(const u_int8_t *, u_int16_t , u_int16_t *);

/* ------------------------------------------------------------------ */
/* The libc shims.                                                     */
/* ------------------------------------------------------------------ */

/* The SHA-512, through OpenBSD's SHA-2 implementation.  This is the only
 * way bcrypt_pbkdf.c reaches a hash function, and it is what OpenSSH
 * itself reaches through crypto_api.h. */
#define crypto_hash_sha512_BYTES 64

static void
crypto_hash_sha512(uint8_t *out, const void *in, size_t len)
{
	SHA2_CTX ctx;

	SHA512Init(&ctx);
	SHA512Update(&ctx, in, len);
	SHA512Final(out, &ctx);
}

/* Only reached on the error path of bcrypt_pbkdf(), where the point is
 * to overwrite the key material with something unpredictable.  The value
 * does not matter, only that it is not the old key. */
static void
arc4random_buf(void *p, size_t n)
{
	memset(p, 0xA5, n);
}

static void
freezero(void *p, size_t n)
{
	if (p != NULL) {
		memset(p, 0, n);
		free(p);
	}
}

#ifndef explicit_bzero
#define explicit_bzero(p, n) memset((p), 0, (n))
#endif

#endif /* BLOWFISH_SHIM_H */
